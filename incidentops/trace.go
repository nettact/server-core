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

// attachSlack is the tolerance applied when a report's first-failure time is
// compared against a signal's first observed failing round. The two timestamps
// describe the same outage from two clocks: the Agent stamps its streak locally
// and the server stamps the round it ingested, so skew plus round phasing can
// legitimately put the Agent's mark a little before the server's. What the
// comparison must reject is a report from a PREVIOUS outage of the same
// destination — those are minutes-to-hours apart, not seconds — so a small
// fixed slack separates the two cases cleanly.
const attachSlack = 2 * time.Minute

// unreferencedTraceRetention is how long a report that never found its fault is
// kept. An Agent legitimately traces without a server-side verdict (its streak
// threshold crossed, but the rounds recovered before the server's profile
// confirmed), and after claimWindow nothing can ever reference such a report —
// it is invisible to every read path, which is incident-scoped. A day preserves
// it for hand debugging; past that it is dead weight.
const unreferencedTraceRetention = 24 * time.Hour

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
	// Touched names every incident that gained a reference or timeline entry.
	// It exists separately from Attributed because an attachment that does NOT
	// move the attribution — an unsupported report, or one that only confirms
	// the current answer — still changed what an open incident view shows, and
	// a console holding that view open has no other signal to refresh on.
	Touched []eventbus.IncidentEvent
	// Attributed is the subset whose attribution answer actually changed; these
	// additionally refresh the fault-centre target status.
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
		if siteFromRow != "" {
			site = siteFromRow
		}
		out.Touched = append(out.Touched, eventbus.IncidentEvent{IncidentID: incidentID, SiteID: site})
		if !didChange {
			continue
		}
		out.Attributed = append(out.Attributed, eventbus.IncidentEvent{IncidentID: incidentID, SiteID: site})
	}
	if len(out.Touched) == 0 {
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
	attributed := map[string]bool{}
	for _, ev := range out.Attributed {
		attributed[ev.IncidentID] = true
		s.publishAttributionRefresh(ctx, ev.SiteID, ev.IncidentID)
	}
	// The rest changed evidence without changing the answer: one incident event
	// keeps an open drawer honest, no target-status churn needed.
	for _, ev := range out.Touched {
		if attributed[ev.IncidentID] || s.bus == nil {
			continue
		}
		s.bus.Publish(eventbus.TopicIncidentUpdated, eventbus.IncidentEvent{IncidentID: ev.IncidentID, SiteID: ev.SiteID})
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
		SELECT id, incident_id, detector_key, observed_at FROM fault_signals
		WHERE agent_id=? AND state='firing' AND incident_id IS NOT NULL AND incident_id<>''`,
		agentID)
	if err != nil {
		return nil, err
	}
	type ref struct {
		signalID, incidentID string
		detectorKey          string
		observedAt           time.Time
	}
	var refs []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.signalID, &r.incidentID, &r.detectorKey, &r.observedAt); err != nil {
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
	// Two more guards mirror the claim-back path (OnSignalConfirmed), which
	// filters the same things before it goes looking for reports:
	//   - a degradation signal never attaches — its target is answering, just
	//     slowly, and the Agent never traced FOR it; sharing a destination with
	//     a hard-failure trace must not put that trace in its evidence;
	//   - a report whose streak began well before this signal's first failing
	//     round belongs to an earlier outage of the same destination. A
	//     reconnect drains both outages' records in one packet, and by the time
	//     traces are extracted only the later signal is still firing — the time
	//     comparison is what keeps the stale report out of it.
	matched := refs[:0]
	for _, r := range refs {
		if fault.IsDegradation(r.detectorKey) {
			continue
		}
		if !res.FirstFailedAt.IsZero() && !r.observedAt.IsZero() &&
			res.FirstFailedAt.Before(r.observedAt.Add(-attachSlack)) {
			continue
		}
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
// evidence the detecting Agent may already have produced for it — the scene it
// collected on its own fault edge, and the traceroute it ran.
//
// The Agent acts when its own failure streak crosses the threshold, which is not
// the instant this server finishes confirming the same rounds: during the
// outages this feature exists for, both records are written while nothing can be
// uploaded and land in a burst afterwards. So evidence frequently arrives BEFORE
// its incident exists, ingest finds no firing fault to attach it to, and it sits
// unreferenced. This is the other half of that handshake — the same shape as the
// sub-threshold fluctuation claim in fault/fluctuation.go, which exists for the
// same reason: evidence recorded before a verdict is still that verdict's
// evidence.
//
// Records the Agent has not sent yet are handled by the opposite path: ingest
// attaches them to this now-firing signal on arrival.
func (s *Service) OnSignalConfirmed(ctx context.Context, ev fault.SignalEvent) error {
	// A quality degradation is not a reachability fault: its target is answering,
	// just more slowly than usual, and an Agent neither traces nor collects a scene
	// for one. The trace eligibility test below is by metric-kind PREFIX and
	// probe.icmp.rtt_ms passes it, so this has to be an explicit exclusion rather
	// than a happy accident — and the scene claim, which keys on the monitor rather
	// than on the metric, has nothing else that would keep a hard failure's scene
	// out of a latency trend's evidence.
	if fault.IsDegradation(ev.DetectorKey) {
		return nil
	}
	// Scenes first, and deliberately outside the diagnostics gate below:
	// diag_enabled states whether the server asks agents to run PATH DIAGNOSTICS.
	// A scene is not one — it costs no probes, leaves the host's own network alone,
	// and an operator who turned traceroute off did not thereby say "and do not
	// tell me what the agent could see".
	//
	// Its error is carried, not returned. The two claims are independent bodies of
	// evidence and nothing retries this handler — the bus logs what comes back and
	// reconcileTraceRefs only deactivates references, it never claims — so
	// returning early on a transient scene failure would permanently lose the
	// trace evidence for this signal as collateral.
	sceneErr := s.claimScenes(ctx, ev)
	traceErr := s.claimTracesFor(ctx, ev)
	return errors.Join(sceneErr, traceErr)
}

// claimTracesFor is the traceroute half of OnSignalConfirmed: the diagnostics
// gate, the eligibility test, and the claim itself.
func (s *Service) claimTracesFor(ctx context.Context, ev fault.SignalEvent) error {
	if !s.diagEnabled(ctx) {
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

// claimTraces attaches every recent, temporally compatible report for this
// agent and destination to the newly-confirmed signal, then recomputes the
// incident's attribution.
//
// "Temporally compatible" replaces an earlier unreferenced-only rule, for both
// of that rule's failure modes. A report already claimed by one signal must
// still be claimable by a second signal of the SAME outage — the Agent dedupes
// by path cohort and will never send a second report, so refusing to share
// would leave the second incident permanently without evidence. And a report
// whose streak began before this signal's first failing round (minus clock
// slack) is a previous outage's evidence, which no window keyed on receipt
// time can distinguish — a reconnect delivers both outages' backlogs in one
// burst, stamping them with the same received_at. Idempotency comes from the
// reference upsert, not from claiming being one-shot.
func (s *Service) claimTraces(ctx context.Context, ev fault.SignalEvent, destKey string) error {
	var observedAt time.Time
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT observed_at FROM fault_signals WHERE id=?`, ev.SignalID).Scan(&observedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	cutoff := time.Now().UTC().Add(-claimWindow)
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id FROM trace_reports
		WHERE agent_id=? AND dest_key=? AND received_at >= ?
		  AND (first_failed_at IS NULL OR first_failed_at >= ?)
		ORDER BY received_at`, ev.AgentID, destKey, cutoff, observedAt.Add(-attachSlack).UTC())
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
	claimed := 0
	for _, reportID := range reportIDs {
		// The WHERE on the conflict arm makes RowsAffected the "was this new"
		// signal: a fresh reference or a reactivation counts, re-claiming an
		// already-active one does not. The timeline entry rides that signal —
		// without it, every re-confirmation of a signal would repeat the
		// "diagnostic completed" line for evidence the incident already shows.
		r, err := tx.ExecContext(ctx, `
			INSERT INTO trace_report_refs(report_id, incident_id, signal_id, active, created_at)
			VALUES(?,?,?,1,?)
			ON CONFLICT(report_id, incident_id, signal_id) DO UPDATE SET active=1 WHERE active=0`,
			reportID, ev.IncidentID, ev.SignalID, now)
		if err != nil {
			return err
		}
		if n, err := r.RowsAffected(); err != nil || n == 0 {
			if err != nil {
				return err
			}
			continue
		}
		claimed++
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref) VALUES(?,?,?,?,?,?)`,
			"tl_"+uuid.NewString(), ev.IncidentID, now, "diag.completed", "", reportID); err != nil {
			return err
		}
	}
	if claimed == 0 {
		return tx.Rollback()
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
	} else if s.bus != nil {
		// The claim added evidence without moving the attribution; an open
		// incident view still has to hear about it.
		s.bus.Publish(eventbus.TopicIncidentUpdated, eventbus.IncidentEvent{IncidentID: ev.IncidentID, SiteID: ev.SiteID})
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
