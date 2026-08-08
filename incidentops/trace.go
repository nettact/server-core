package incidentops

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
)

// claimWindow is how far back a newly-confirmed fault looks for a traceroute
// report to claim as its evidence.
//
// It exists because the two sides of the story are produced by different parties
// on different clocks and neither waits for the other. The Agent traces when its
// own streak crosses the threshold; the server confirms when the same rounds
// have reached it, been ingested and been evaluated. Which lands first depends
// on the upload cadence and on how long the link was down — during the outages
// this feature exists for, the trace is written while nothing can be delivered
// and arrives in a burst minutes later, long after or well before the
// confirmation. A window rather than an exact pairing is the honest way to join
// them; fifteen minutes comfortably covers a slow drain without letting an
// unrelated outage half an hour ago be presented as this incident's evidence.
const claimWindow = 15 * time.Minute

// TraceEligibleMetric reports whether a firing condition — identified by its
// probe kind and breached metric — is a network-availability fault that an Agent
// would have traced. It is the server's half of the same eligibility rule the
// Agent's trigger applies: icmp/tcp/http/dns/nat probe metrics qualify; gateway,
// host, wireless and pure-resource metrics never do.
//
// The server no longer triggers anything, so this is used only to decide whether
// a confirmed fault should go looking for a report to claim — asking the
// question for a gateway fault would scan for evidence that by construction
// cannot exist.
func TraceEligibleMetric(probeKind, metricKind string) bool {
	switch probeKind {
	case "icmp":
		return strings.HasPrefix(metricKind, "probe.icmp.")
	case "tcp":
		return strings.HasPrefix(metricKind, "probe.tcp.")
	case "http":
		return strings.HasPrefix(metricKind, "probe.http.")
	case "dns":
		return strings.HasPrefix(metricKind, "probe.dns.")
	case "nat":
		return strings.HasPrefix(metricKind, "probe.nat.")
	}
	return false
}

// terminalTraceStatus reports whether a status is one of the Agent's terminal
// result values. A report arrives terminal or not at all — there are no
// pre-terminal server-side states any more — so anything else is a malformed
// payload and is stored as failed rather than as an invented status.
func terminalTraceStatus(status string) bool {
	switch status {
	case telemetry.TraceStatusSucceeded, telemetry.TraceStatusPartial, telemetry.TraceStatusTimedOut,
		telemetry.TraceStatusUnsupported, telemetry.TraceStatusFailed, telemetry.TraceStatusCanceled:
		return true
	}
	return false
}

// ---- ingest (inside the telemetry write transaction) ----

// TraceOutcome is the post-commit work one packet's traceroute reports left
// behind: the incidents whose attribution actually changed and now need the
// console told. Empty for the common case of a report that matched no open
// fault, which is not a failure — the report waits to be claimed.
type TraceOutcome struct {
	Attributed []eventbus.IncidentEvent
}

// IngestTracesTx persists the traceroute reports carried by one telemetry packet
// and attaches each to any fault it explains, inside the caller's write
// transaction.
//
// It runs in the SAME transaction as the samples and the fault evaluation
// deliberately. A report is evidence about the rounds arriving beside it, and
// committing the two separately would let the console observe an incident whose
// attribution was computed without the trace that was in the same packet — or,
// worse, leave a stored report attached to nothing after a mid-write failure
// while the Agent's ack said it had been received. Failing here withholds the
// ack and the Agent replays the packet, which the (agent, report id) idempotency
// makes harmless.
//
// Matching is by report id, which the Agent minted, with the authenticated agent
// id as the guard: a duplicate, replayed or foreign-agent report is a silent
// no-op and can never overwrite a stored execution.
func (s *Service) IngestTracesTx(ctx context.Context, tx *sql.Tx, agentID, siteID string, results []telemetry.TraceResult) (*TraceOutcome, error) {
	if len(results) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	agentName := s.agentName(ctx, agentID)
	out := &TraceOutcome{}
	changed := map[string]string{} // incident id → site id

	for _, res := range results {
		if res.ReportID == "" {
			continue
		}
		inserted, err := insertTraceReport(ctx, tx, agentID, siteID, agentName, res, now)
		if err != nil {
			return nil, err
		}
		if !inserted {
			continue // replay, or an id another agent already owns
		}
		if err := insertHops(ctx, tx, res.ReportID, res.Hops, clampBound(res.MaxHops, 64), clampBound(res.AttemptsPerHop, 5)); err != nil {
			return nil, err
		}
		// Attach to whatever this report explains. A report that matches no firing
		// fault is stored unattached on purpose: the Agent traced on its own
		// schedule and the fault may not be confirmed yet, so OnSignalConfirmed
		// claims it later (see claimTraces).
		incidents, err := attachTrace(ctx, tx, agentID, res, now)
		if err != nil {
			return nil, err
		}
		for _, id := range incidents {
			changed[id] = siteID
		}
	}

	// One attribution recompute per touched incident, not per report: a burst of
	// reports drained after an outage can name the same incident several times,
	// and the recompute reads the whole evidence set either way.
	for incidentID, site := range changed {
		didChange, siteFromRow, err := fault.RecomputeAttributionTx(ctx, tx, incidentID)
		if err != nil {
			return nil, err
		}
		if !didChange {
			continue
		}
		if siteFromRow != "" {
			site = siteFromRow
		}
		out.Attributed = append(out.Attributed, eventbus.IncidentEvent{IncidentID: incidentID, SiteID: site})
	}
	if len(out.Attributed) == 0 {
		return nil, nil
	}
	return out, nil
}

// PublishTraceOutcome lets the console converge after ingest committed. Called
// post-commit by the caller that ran IngestTracesTx, so nothing here can be
// observed before the evidence it describes is durable.
func (s *Service) PublishTraceOutcome(ctx context.Context, out *TraceOutcome) {
	if out == nil {
		return
	}
	for _, ev := range out.Attributed {
		s.publishAttributionRefresh(ctx, ev.SiteID, ev.IncidentID)
	}
}

// insertTraceReport stores one report, returning whether it was new. The id is
// the Agent's, so an INSERT OR IGNORE covers both idempotency cases at once: a
// replayed packet re-presents an id already stored, and an id claimed by a
// different agent collides with the row that agent owns. Either way the stored
// execution stands and nothing is overwritten.
func insertTraceReport(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string, res telemetry.TraceResult, now time.Time) (bool, error) {
	status := res.Status
	if !terminalTraceStatus(status) {
		status = telemetry.TraceStatusFailed
	}
	pathScope := res.PathScope
	if pathScope == "" {
		pathScope = telemetry.TracePathDirect
	}
	mode := res.Mode
	if mode != "icmp" && mode != "tcp" {
		// The column is CHECKed and the value is an Agent's; a malformed one must
		// not abort a whole telemetry packet, so it lands as the ICMP default with
		// its failed status telling the reader the execution was not trustworthy.
		mode = "icmp"
		status = telemetry.TraceStatusFailed
	}
	subject := res.SubjectKind
	switch subject {
	case telemetry.TraceSubjectTarget, telemetry.TraceSubjectResolver, telemetry.TraceSubjectProxy,
		telemetry.TraceSubjectWGEndpoint, telemetry.TraceSubjectSTUNServer:
	default:
		subject = telemetry.TraceSubjectTarget
	}

	r, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO trace_reports(id, site_id, agent_id, agent_name, dest_key, dest_host, dest_ip, mode, port,
			status, reason, max_hops, attempts, reached, reached_ttl,
			trigger_reason, trigger_streak, first_failed_at,
			started_at, completed_at, received_at,
			fallback_from, fallback_reason, subject_kind, subject_reason, path_scope, egress_id, egress_config_serial)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		res.ReportID, siteID, agentID, agentName, res.DestKey, res.DestHost, res.DestinationIP, mode, res.Port,
		status, res.Reason, clampBound(res.MaxHops, 64), clampBound(res.AttemptsPerHop, 5),
		boolInt(res.Reached), res.ReachedTTL,
		res.TriggerReason, res.TriggerStreak, nullTimeOf(res.FirstFailedAt),
		nullTimeOf(res.StartedAt), nullTimeOf(res.CompletedAt), now,
		res.FallbackFrom, res.FallbackReason, subject, res.SubjectReason,
		pathScope, res.EgressProxyID, res.EgressConfigSerial)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n > 0, nil
}

// clampBound bounds a reported hop/attempt count into [1, max] so a malformed
// oversized report cannot bloat the hop table, and a zero one still stores the
// hops it did collect.
func clampBound(v, max int) int {
	if v < 1 {
		return max
	}
	if v > max {
		return max
	}
	return v
}

func nullTimeOf(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

// attachTrace references a freshly stored report from every firing fault signal
// on the same agent and destination, and appends a timeline entry to each
// affected incident. It returns the distinct incident ids so the caller can
// recompute their attribution in the same transaction.
//
// The join is on the destination rather than on the monitor, because that is
// what the report is about: a proxied monitor's fault is traced to the proxy, a
// DNS monitor's to its resolver, and matching by monitor would attach a resolver
// trace to nothing while three monitors sharing one dead host each waited for a
// trace of their own.
func attachTrace(ctx context.Context, tx *sql.Tx, agentID string, res telemetry.TraceResult, now time.Time) ([]string, error) {
	if res.DestKey == "" {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, incident_id FROM fault_signals
		WHERE agent_id=? AND state='firing' AND incident_id IS NOT NULL AND incident_id<>''`,
		agentID)
	if err != nil {
		return nil, err
	}
	type ref struct{ signalID, incidentID string }
	var refs []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.signalID, &r.incidentID); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}

	// Narrow to the signals whose own diagnosable destination is this report's.
	matched := refs[:0]
	for _, r := range refs {
		ok, err := signalMatchesDest(ctx, tx, r.signalID, res.DestKey)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		return nil, nil
	}

	seen := map[string]bool{}
	var incidents []string
	for _, r := range matched {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO trace_report_refs(report_id, incident_id, signal_id, active, created_at)
			VALUES(?,?,?,1,?)
			ON CONFLICT(report_id, incident_id, signal_id) DO UPDATE SET active=1`,
			res.ReportID, r.incidentID, r.signalID, now); err != nil {
			return nil, err
		}
		if seen[r.incidentID] {
			continue
		}
		seen[r.incidentID] = true
		incidents = append(incidents, r.incidentID)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref) VALUES(?,?,?,?,?,?)`,
			"tl_"+uuid.NewString(), r.incidentID, now, "diag.completed", "", res.ReportID); err != nil {
			return nil, err
		}
	}
	return incidents, nil
}

// signalMatchesDest reports whether a firing signal's own diagnosable
// destination is destKey. It re-derives the destination from the signal's FROZEN
// trigger-time evidence with the same rules the Agent used, so a target edited
// after the fault cannot make an unrelated report look like its evidence.
func signalMatchesDest(ctx context.Context, tx *sql.Tx, signalID, destKey string) (bool, error) {
	evd, metricKind, err := readSignalEvidence(ctx, tx, signalID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !TraceEligibleMetric(evd.probeKind, metricKind) {
		return false, nil
	}
	key, ok := signalDestKey(evd)
	return ok && key == destKey, nil
}

// ---- claim-back (post-commit, on fault confirmation) ----

// OnSignalConfirmed reacts to one newly-confirmed fault signal by claiming the
// traceroute evidence the detecting Agent may already have produced for it.
//
// The Agent traced when its own failure streak crossed the threshold, which is
// not the instant this server finished confirming the same rounds: during the
// outages this feature exists for, the report is written while nothing can be
// uploaded and lands in a burst afterwards. So a report frequently arrives
// BEFORE its incident exists, ingest finds no firing fault to attach it to, and
// it sits unreferenced. This is the other half of that handshake — the same
// shape as the sub-threshold fluctuation claim in fault/fluctuation.go, which
// exists for the same reason: evidence recorded before a verdict is still that
// verdict's evidence.
//
// Reports the Agent has not sent yet are handled by the opposite path: ingest
// attaches them to this now-firing signal on arrival.
func (s *Service) OnSignalConfirmed(ctx context.Context, ev fault.SignalEvent) error {
	if !s.diagEnabled(ctx) {
		return nil
	}
	// A quality degradation is not a reachability fault: its target is answering,
	// just more slowly than usual, and an Agent never traces one. The eligibility
	// test below is by metric-kind PREFIX and probe.icmp.rtt_ms passes it, so this
	// has to be an explicit exclusion rather than a happy accident.
	if fault.IsDegradation(ev.DetectorKey) {
		return nil
	}
	evd, metricKind, err := readSignalEvidence(ctx, s.db.Read(), ev.SignalID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !TraceEligibleMetric(evd.probeKind, metricKind) {
		return nil
	}
	destKey, ok := signalDestKey(evd)
	if !ok {
		return nil
	}
	return s.claimTraces(ctx, ev, destKey)
}

// claimTraces attaches every recent unreferenced report for this agent and
// destination to the newly-confirmed signal, then recomputes the incident's
// attribution. Idempotent: re-running it re-selects nothing, because the reports
// it claimed now carry a reference.
func (s *Service) claimTraces(ctx context.Context, ev fault.SignalEvent, destKey string) error {
	cutoff := time.Now().UTC().Add(-claimWindow)
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id FROM trace_reports
		WHERE agent_id=? AND dest_key=? AND received_at >= ?
		  AND NOT EXISTS(SELECT 1 FROM trace_report_refs r WHERE r.report_id=trace_reports.id)
		ORDER BY received_at`, ev.AgentID, destKey, cutoff)
	if err != nil {
		return err
	}
	var reportIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		reportIDs = append(reportIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(reportIDs) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	now := time.Now().UTC()
	for _, reportID := range reportIDs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO trace_report_refs(report_id, incident_id, signal_id, active, created_at)
			VALUES(?,?,?,1,?)
			ON CONFLICT(report_id, incident_id, signal_id) DO UPDATE SET active=1`,
			reportID, ev.IncidentID, ev.SignalID, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref) VALUES(?,?,?,?,?,?)`,
			"tl_"+uuid.NewString(), ev.IncidentID, now, "diag.completed", "", reportID); err != nil {
			return err
		}
	}
	// The trace's reached-point is the strongest attribution evidence there is, so
	// claiming one has to re-answer "where did this break" rather than leaving the
	// incident on the guess it was confirmed with.
	changed, siteID, err := fault.RecomputeAttributionTx(ctx, tx, ev.IncidentID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if changed {
		if siteID == "" {
			siteID = ev.SiteID
		}
		s.publishAttributionRefresh(ctx, siteID, ev.IncidentID)
	}
	return nil
}

// publishAttributionRefresh lets the console converge after an incident's
// attribution changed. incident.changed refreshes the fault centre AND the open
// incident drawer; target.status.changed refreshes the target-status page, whose
// per-agent FaultRef now carries the same attribution. Both are needed because
// the target-status store only listens to the latter.
func (s *Service) publishAttributionRefresh(ctx context.Context, siteID, incidentID string) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(eventbus.TopicIncidentUpdated, eventbus.IncidentEvent{IncidentID: incidentID, SiteID: siteID})
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT DISTINCT target_id FROM fault_signals WHERE incident_id=? AND state='firing' AND target_id<>''`,
		incidentID)
	if err != nil {
		return
	}
	var targetIDs []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			targetIDs = append(targetIDs, id)
		}
	}
	rows.Close()
	if len(targetIDs) > 0 {
		s.bus.Publish(eventbus.TopicTargetStatusChanged, eventbus.TargetStatusChanged{SiteID: siteID, TargetIDs: targetIDs})
	}
}

// insertHops writes the per-attempt hop rows, clamped to the report's own
// bounds so a malformed oversized result cannot bloat storage. RTT is stored in
// microseconds; a timed-out attempt stores no address.
func insertHops(ctx context.Context, tx *sql.Tx, reportID string, hops []telemetry.TraceHop, maxHops, attempts int) error {
	for _, h := range hops {
		if h.TTL < 1 || h.TTL > maxHops {
			continue
		}
		for i, a := range h.Attempts {
			if i >= attempts {
				break
			}
			var rtt any
			if !a.Timeout && a.RTTMs > 0 {
				rtt = int64(a.RTTMs * 1000)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO trace_hops(report_id, ttl, attempt, addr, hostname, rtt_us, timed_out)
				VALUES(?,?,?,?,?,?,?)`,
				reportID, h.TTL, i, a.ResponderAddr, a.Hostname, rtt, boolInt(a.Timeout)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- reference deactivation (post-commit, on fault resolution) ----

// OnSignalResolved deactivates the trace references a fault signal held. It
// never deletes the execution: a resolved fault's report stays readable as the
// history of what was found, and only stops being counted as live evidence.
// Wired onto TopicFaultResolved, post-commit. Idempotent.
func (s *Service) OnSignalResolved(ctx context.Context, signalID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE trace_report_refs SET active=0 WHERE signal_id=? AND active=1`, signalID)
	return err
}
