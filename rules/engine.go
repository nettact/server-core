package rules

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/metrics"
)

// evalRule is a live rule (in an agent's scope) plus its conditions, assembled
// for one EvaluateAgent pass.
type evalRule struct {
	id, op, layer, severity string
	name                    string
	channelIDs              []string
	groupIDCache            string
	conds                   []evalCond
}

// evalCond is one condition joined with its target's identity.
type evalCond struct {
	id, targetID, metricKind, comparator string
	threshold                            float64
	failThreshold, forSeconds            int
	kind, targetStr, targetName          string
	port                                 int // frozen trigger-time TCP port (from the target's probe params)
	configSerial                         int // target's current material generation (probe_tasks.config_serial)
}

// condResult is the outcome of looking up a condition's latest metric this pass.
type condResult struct {
	hasData   bool
	value     float64
	breach    bool
	satisfied bool // current satisfied verdict (after applying state)
	// reasonCode is the sibling probe.<kind>.error_class value this pass (a
	// telemetry.ProbeReason* code), frozen onto evidence when the alert fires so the
	// notice states WHY it failed. 0 (ProbeReasonNone) for host/nat or a clean probe.
	reasonCode int
}

// reasonMetricKind maps a probe kind to the metric that carries its failure-reason
// code, or ("", false) for a kind with no reason concept (host, nat). gateway pings
// emit through the shared ICMP metric set, so they read the ICMP reason.
func reasonMetricKind(probeKind string) (string, bool) {
	switch probeKind {
	case "icmp", "gateway":
		return string(telemetry.ICMPErrorClass), true
	case "dns":
		return string(telemetry.DNSErrorClass), true
	case "http":
		return string(telemetry.HTTPErrorClass), true
	case "tcp":
		return string(telemetry.TCPErrorClass), true
	default:
		return "", false
	}
}

// batchValue is one accepted-batch reading, keyed for an in-tx evaluation.
type batchValue struct {
	value float64
	ts    int64
}

// Overlay carries an accepted ingest batch's newest per-series readings so an
// in-tx evaluation observes the samples this commit is inserting — the metrics
// latest cache is only refreshed post-commit, so it still holds the previous
// cycle mid-tx. Probe metrics are keyed by (monitorID, kind); system/host
// metrics by (kind, target). Readings are already 5-minute-window filtered by
// BuildOverlay. A nil *Overlay (the standalone EvaluateAgent wrapper) contributes
// nothing, so evaluation falls back to the cache exactly as before.
type Overlay struct {
	probe map[string]batchValue // monitorID + "\x00" + kind
	host  map[string]batchValue // kind + "\x00" + target
}

// BuildOverlay indexes an accepted metric batch into an Overlay, keeping the
// newest reading per series within the 5-minute window (WAL-backfill packets
// carry old agent timestamps and must not flip a condition). The batch is
// current-generation by construction (ingest gated it), so no serial is keyed.
func BuildOverlay(ms []telemetry.Metric, sinceUnix int64) *Overlay {
	o := &Overlay{probe: map[string]batchValue{}, host: map[string]batchValue{}}
	for i := range ms {
		m := ms[i]
		ts := m.TS.Unix()
		if ts <= sinceUnix {
			continue
		}
		if m.MonitorID != "" {
			k := m.MonitorID + "\x00" + string(m.Kind)
			if ex, ok := o.probe[k]; !ok || ts > ex.ts {
				o.probe[k] = batchValue{value: m.Value, ts: ts}
			}
			continue
		}
		k := string(m.Kind) + "\x00" + m.Target
		if ex, ok := o.host[k]; !ok || ts > ex.ts {
			o.host[k] = batchValue{value: m.Value, ts: ts}
		}
	}
	return o
}

func (o *Overlay) probeValue(monitorID, kind string) (float64, int64, bool) {
	if o == nil {
		return 0, 0, false
	}
	v, ok := o.probe[monitorID+"\x00"+kind]
	return v.value, v.ts, ok
}

func (o *Overlay) hostValue(kind, target string) (float64, int64, bool) {
	if o == nil {
		return 0, 0, false
	}
	v, ok := o.host[kind+"\x00"+target]
	return v.value, v.ts, ok
}

// Outcome is one EvaluateAgentTx pass's post-commit work: the events and
// notifications the tx owner must publish after a successful commit (via
// PublishOutcome), and the target ids whose current rule state may have shifted
// this pass (for the caller's status event). It is discarded on rollback.
type Outcome struct {
	out              *txOut
	siteID           string
	ChangedTargetIDs []string
}

// EvaluateAgent evaluates every group rule in this agent's scope against the
// agent's latest metrics and drives the fault flow in one write transaction,
// publishing lifecycle events and dispatching notifications only after commit. It
// is the thin standalone wrapper around EvaluateAgentTx retained for the rules
// test suite (production telemetry runs the split path inside the ingest tx). A
// nil overlay means the evaluation reads purely from the metrics latest cache.
func (s *Service) EvaluateAgent(ctx context.Context, agentID, siteID string) error {
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
	out, err := s.EvaluateAgentTx(ctx, tx, agentID, siteID, nil)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	s.PublishOutcome(ctx, out)
	return nil
}

// EvaluateAgentTx runs one evaluation pass inside the caller's open write
// transaction: it loads the agent's scoped rules (in-tx, so definitions match
// what this commit is consistent with), reads each condition's latest value from
// the metrics cache merged newest-wins with the accepted-batch overlay, updates
// per-(condition, Agent) state, and fires/appends/closes alert instances with
// frozen evidence and group-aware incidents. All DB writes land in the caller's
// tx so samples, condition state, alerts, incidents and evidence commit
// atomically; the returned Outcome carries the post-commit publications for
// PublishOutcome. Generation-aware lookups (LatestByMonitor by config_serial, the
// current-generation overlay) keep an obsolete generation's sample from being
// read as current.
func (s *Service) EvaluateAgentTx(ctx context.Context, tx *sql.Tx, agentID, siteID string, overlay *Overlay) (*Outcome, error) {
	live, err := s.loadScopedRules(ctx, tx, agentID, siteID)
	if err != nil {
		return nil, err
	}
	if len(live) == 0 {
		return &Outcome{out: &txOut{}, siteID: siteID}, nil
	}

	// Metric lookups: cache (previous cycle mid-tx) merged newest-wins with the
	// accepted-batch overlay (this cycle). Both are already 5-minute-window bounded.
	sinceUnix := time.Now().Add(-5 * time.Minute).Unix()
	results := make(map[string]*condResult) // condition id → result
	targetSet := map[string]bool{}
	for _, r := range live {
		for _, c := range r.conds {
			targetSet[c.targetID] = true
			res := &condResult{}
			var found []metrics.TargetValue
			var lerr error
			if c.kind == "host" {
				found, lerr = s.metrics.LatestPerSeries(ctx, agentID, c.metricKind, c.targetStr, sinceUnix)
			} else {
				found, lerr = s.metrics.LatestByMonitor(ctx, agentID, c.metricKind, c.targetID, c.configSerial, sinceUnix)
			}
			if lerr != nil {
				return nil, lerr
			}
			var val float64
			var ts int64
			var have bool
			if len(found) > 0 {
				val, ts, have = found[0].Value, found[0].TS, true
			}
			var ov float64
			var ots int64
			var ook bool
			if c.kind == "host" {
				ov, ots, ook = overlay.hostValue(c.metricKind, c.targetStr)
			} else {
				ov, ots, ook = overlay.probeValue(c.targetID, c.metricKind)
			}
			if ook && (!have || ots >= ts) {
				val, ts, have = ov, ots, true
			}
			if have {
				res.hasData = true
				res.value = val
				res.breach = compare(val, c.comparator, c.threshold)
			}
			// Sibling failure-reason: the probe emits probe.<kind>.error_class in the
			// same cycle as the condition metric, sharing its TS. Merge overlay∪cache
			// newest-wins, keyed by the same monitor, then accept the reason ONLY when
			// its timestamp equals the chosen value's — a condition metric omitted on
			// failure (HTTP latency/status, TCP connect_ms) can be older than the
			// newest error_class, and pairing an old value with a newer unrelated
			// failure reason would misattribute the cause.
			if reasonKind, okKind := reasonMetricKind(c.kind); okKind && have {
				rfound, rerr := s.metrics.LatestByMonitor(ctx, agentID, reasonKind, c.targetID, c.configSerial, sinceUnix)
				if rerr != nil {
					return nil, rerr
				}
				var rval float64
				var rts int64
				var rhave bool
				if len(rfound) > 0 {
					rval, rts, rhave = rfound[0].Value, rfound[0].TS, true
				}
				if rov, rots, rook := overlay.probeValue(c.targetID, reasonKind); rook && (!rhave || rots >= rts) {
					rval, rts, rhave = rov, rots, true
				}
				if rhave && rts == ts {
					res.reasonCode = int(rval)
				}
			}
			results[c.id] = res
		}
	}

	now := time.Now().UTC()
	out := &txOut{}

	for _, r := range live {
		// Update per-condition state and compute the current satisfied verdict.
		satisfiedCount := 0
		for _, c := range r.conds {
			res := results[c.id]
			sat, err := s.applyConditionState(ctx, tx, c, agentID, res, now)
			if err != nil {
				return nil, err
			}
			res.satisfied = sat
			if sat {
				satisfiedCount++
			}
		}
		shouldFire := false
		switch r.op {
		case "and":
			shouldFire = satisfiedCount == len(r.conds) && len(r.conds) > 0
		case "or":
			shouldFire = satisfiedCount > 0
		}
		if err := s.applyRuleTransition(ctx, tx, r, agentID, siteID, results, shouldFire, now, out); err != nil {
			return nil, err
		}
	}

	changed := make([]string, 0, len(targetSet))
	for id := range targetSet {
		changed = append(changed, id)
	}
	return &Outcome{out: out, siteID: siteID, ChangedTargetIDs: changed}, nil
}

// PublishOutcome fans an Outcome's accumulated lifecycle events out on the bus
// and dispatches its notifications, off the write path. The tx owner calls it
// only after a successful commit; it is a no-op for a nil Outcome.
func (s *Service) PublishOutcome(ctx context.Context, out *Outcome) {
	if out == nil {
		return
	}
	s.publishAndNotify(ctx, out.out)
}

// applyConditionState updates rule_condition_state from this pass's metric and
// returns the current satisfied verdict. When there was no data this pass the
// stored state (and its satisfied flag) is left untouched.
func (s *Service) applyConditionState(ctx context.Context, tx *sql.Tx, c evalCond, agentID string, res *condResult, now time.Time) (bool, error) {
	var fails int
	var firstBreach sql.NullTime
	var satisfied int
	err := tx.QueryRowContext(ctx,
		`SELECT consecutive_fails, first_breach_at, satisfied FROM rule_condition_state WHERE condition_id=? AND agent_id=?`,
		c.id, agentID).Scan(&fails, &firstBreach, &satisfied)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if !res.hasData {
		// No fresh sample: preserve the stored verdict (and counters).
		return satisfied == 1, nil
	}

	fail := c.failThreshold
	if fail < 1 {
		fail = 1
	}
	var newFails int
	var newFirst sql.NullTime
	newSatisfied := false
	if res.breach {
		newFails = fails + 1
		if firstBreach.Valid {
			newFirst = firstBreach
		} else {
			newFirst = sql.NullTime{Time: now, Valid: true}
		}
		dwellMet := c.forSeconds <= 0 || now.Sub(newFirst.Time) >= time.Duration(c.forSeconds)*time.Second
		newSatisfied = newFails >= fail && dwellMet
	} else {
		newFails = 0
		newFirst = sql.NullTime{}
		newSatisfied = false
	}

	if exists {
		if _, err := tx.ExecContext(ctx,
			`UPDATE rule_condition_state SET consecutive_fails=?, first_breach_at=?, satisfied=?, last_value=?, last_eval_at=?
			 WHERE condition_id=? AND agent_id=?`,
			newFails, newFirst, boolInt(newSatisfied), res.value, now, c.id, agentID); err != nil {
			return false, err
		}
	} else {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO rule_condition_state(condition_id, agent_id, consecutive_fails, first_breach_at, satisfied, last_value, last_eval_at)
			 VALUES(?,?,?,?,?,?,?)`,
			c.id, agentID, newFails, newFirst, boolInt(newSatisfied), res.value, now); err != nil {
			return false, err
		}
	}
	return newSatisfied, nil
}

// applyRuleTransition materializes a rule's per-Agent alert instance from the
// firing decision: creating/appending-evidence when firing, resolving when not.
func (s *Service) applyRuleTransition(ctx context.Context, tx *sql.Tx, r evalRule, agentID, siteID string, results map[string]*condResult, shouldFire bool, now time.Time, out *txOut) error {
	var alertID string
	var incidentID sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT id, incident_id FROM alerts WHERE rule_id=? AND agent_id=? AND state='firing'`, r.id, agentID).
		Scan(&alertID, &incidentID)
	open := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	switch {
	case shouldFire && !open:
		return s.fireAlert(ctx, tx, r, agentID, siteID, results, now, out)
	case shouldFire && open:
		return s.appendEvidence(ctx, tx, r, alertID, incidentID.String, agentID, siteID, results, now, out)
	case !shouldFire && open:
		return s.closeAlert(ctx, tx, alertID, r.id, agentID, siteID, r.groupIDCache, r.layer, r.severity,
			incidentID.String, alert.ReasonRecovered, now, out)
	}
	return nil
}

// fireAlert opens a new alert instance, freezes evidence for every satisfied
// condition, and opens or attaches to the group's incident.
func (s *Service) fireAlert(ctx context.Context, tx *sql.Tx, r evalRule, agentID, siteID string, results map[string]*condResult, now time.Time, out *txOut) error {
	groupID, groupName, mergeEnabled, err := groupMeta(ctx, tx, r.id)
	if err != nil {
		return err
	}
	alertID := "alert_" + uuid.NewString()
	incidentID, opened, oldSeverity, err := findOrCreateIncident(ctx, tx, groupID, groupName, alertID, mergeEnabled, r.severity, r.layer, siteID, now)
	if err != nil {
		return err
	}
	// Freeze the rule's notification routing onto the alert so an incident's final
	// resolution/termination notices route to the configured channels even after
	// every member resolves or the rule is deleted (F-11).
	chans, _ := json.Marshal(normStrings(r.channelIDs))
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO alerts(id, rule_id, rule_name, agent_id, site_id, group_id, group_name, incident_id, state, severity, layer, channel_ids, started_at)
		 VALUES(?,?,?,?,?,?,?,?, 'firing', ?, ?, ?, ?)`,
		alertID, r.id, r.name, agentID, siteID, groupID, groupName, incidentID, r.severity, r.layer, string(chans), now); err != nil {
		return err
	}
	for _, c := range r.conds {
		if results[c.id].satisfied {
			if err := freezeEvidence(ctx, tx, alertID, incidentID, agentID, siteID, c, results[c.id].value, results[c.id].reasonCode, now, out); err != nil {
				return err
			}
		}
	}
	newSeverity, err := recomputeIncident(ctx, tx, incidentID, now)
	if err != nil {
		return err
	}
	addTimeline(ctx, tx, incidentID, "alert.raised", s.faultLine(ctx, tx, alertID), alertID, now)
	out.raised = append(out.raised, alert.Raised{
		ID: alertID, RuleID: r.id, AgentID: agentID, SiteID: siteID, GroupID: groupID,
		Layer: r.layer, Severity: r.severity, IncidentID: incidentID, At: now,
	})
	if opened {
		// Write the incident's one immutable base snapshot synchronously in this
		// transaction (INCIDENT-002). A failure is advisory: it records a failed/
		// partial snapshot but never blocks the incident from opening.
		if s.snap != nil {
			if err := s.snap.WriteIncidentBase(ctx, tx, incidentID, now); err != nil {
				log.Printf("rules: incident base snapshot for %s: %v", incidentID, err)
			}
		}
		addTimeline(ctx, tx, incidentID, "incident.opened", "", incidentID, now)
		out.incidentOpened = append(out.incidentOpened, eventbus.IncidentEvent{
			IncidentID: incidentID, SiteID: siteID, GroupID: groupID, Severity: newSeverity})
		out.notices = append(out.notices, notice{incidentID, siteID, "incident.opened", "open"})
	} else {
		escalated := severityRank[newSeverity] > severityRank[oldSeverity]
		out.incidentUpdated = append(out.incidentUpdated, eventbus.IncidentEvent{
			IncidentID: incidentID, SiteID: siteID, GroupID: groupID, Severity: newSeverity, Escalated: escalated})
		// Decided policy: membership growth notifies only on severity escalation.
		if escalated {
			out.notices = append(out.notices, notice{incidentID, siteID, "incident.updated", "open"})
		}
	}
	return nil
}

// appendEvidence freezes evidence for any newly-satisfied condition on an
// already-firing alert (idempotent via the (alert,condition) unique index).
func (s *Service) appendEvidence(ctx context.Context, tx *sql.Tx, r evalRule, alertID, incidentID, agentID, siteID string, results map[string]*condResult, now time.Time, out *txOut) error {
	for _, c := range r.conds {
		if !results[c.id].satisfied {
			continue
		}
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM alert_evidence WHERE alert_id=? AND condition_id=?`, alertID, c.id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		if err := freezeEvidence(ctx, tx, alertID, incidentID, agentID, siteID, c, results[c.id].value, results[c.id].reasonCode, now, out); err != nil {
			return err
		}
		addTimeline(ctx, tx, incidentID, "alert.evidence", s.evidenceLine(ctx, tx, alertID, c.id), alertID, now)
	}
	return nil
}

// closeAlert resolves a firing alert (reason recovered or configuration_changed)
// and updates or resolves its incident. Shared by the eval path and the
// configuration-change termination paths.
func (s *Service) closeAlert(ctx context.Context, tx *sql.Tx, alertID, ruleID, agentID, siteID, groupID, layer, severity, incidentID, reason string, now time.Time, out *txOut) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE alerts SET state='resolved', resolved_at=?, resolve_reason=? WHERE id=?`, now, reason, alertID); err != nil {
		return err
	}
	kind := "alert.resolved"
	if reason == alert.ReasonConfigChanged {
		kind = "alert.terminated"
	}
	addTimeline(ctx, tx, incidentID, kind, "", alertID, now)
	out.resolved = append(out.resolved, alert.Raised{
		ID: alertID, RuleID: ruleID, AgentID: agentID, SiteID: siteID, GroupID: groupID,
		Layer: layer, Severity: severity, IncidentID: incidentID, At: now, Reason: reason,
	})
	if incidentID == "" {
		return nil
	}
	var firing int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE incident_id=? AND state='firing'`, incidentID).Scan(&firing); err != nil {
		return err
	}
	if firing == 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE incidents SET state='resolved', resolved_at=?, resolve_reason=? WHERE id=? AND state='open'`,
			now, incidentReason(reason), incidentID); err != nil {
			return err
		}
		closeKind := "incident.resolved"
		state, event := "resolved", "incident.resolved"
		if reason == alert.ReasonConfigChanged {
			closeKind, state, event = "incident.terminated", "terminated", "incident.terminated"
		}
		addTimeline(ctx, tx, incidentID, closeKind, "", incidentID, now)
		var siteOf, groupOf string
		_ = tx.QueryRowContext(ctx, `SELECT site_id, group_id FROM incidents WHERE id=?`, incidentID).Scan(&siteOf, &groupOf)
		out.incidentResolved = append(out.incidentResolved, eventbus.IncidentEvent{
			IncidentID: incidentID, SiteID: siteOf, GroupID: groupOf})
		out.notices = append(out.notices, notice{incidentID, siteOf, event, state})
		return nil
	}
	// Partial recovery: recompute severity/summary; timeline only, no notification.
	if _, err := recomputeIncident(ctx, tx, incidentID, now); err != nil {
		return err
	}
	out.incidentUpdated = append(out.incidentUpdated, eventbus.IncidentEvent{IncidentID: incidentID, SiteID: siteID})
	return nil
}

// event for the post-commit diagnostic trigger.
func freezeEvidence(ctx context.Context, tx *sql.Tx, alertID, incidentID, agentID, siteID string, c evalCond, value float64, reasonCode int, now time.Time, out *txOut) error {
	evID := "evd_" + uuid.NewString()
	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO alert_evidence(id, alert_id, condition_id, target_id, target_name, target_addr, target_port,
		    probe_kind, metric_kind, comparator, threshold, value, reason_code, observed_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		evID, alertID, c.id, c.targetID, c.targetName, c.targetStr, c.port, c.kind, c.metricKind, c.comparator, c.threshold, value, reasonCode, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil // already frozen
	}
	out.evidence = append(out.evidence, eventbus.EvidenceAdded{
		EvidenceID: evID, AlertID: alertID, IncidentID: incidentID, AgentID: agentID, SiteID: siteID})
	return nil
}

// findOrCreateIncident returns the open incident for a group (merged) or alert
// (unmerged) by its open_key, creating one when none is open. The partial unique
// index on open_key (WHERE state='open') keeps concurrent/replayed raises from
// duplicating; a losing insert re-selects the winner. oldSeverity is the
// incident's severity before this attachment (empty for a freshly-opened one).
func findOrCreateIncident(ctx context.Context, tx *sql.Tx, groupID, groupName, alertID string, mergeEnabled bool, severity, layer, siteID string, now time.Time) (id string, opened bool, oldSeverity string, err error) {
	openKey := "alert:" + alertID
	if mergeEnabled {
		openKey = "grp:" + groupID
	}
	err = tx.QueryRowContext(ctx,
		`SELECT id, severity FROM incidents WHERE open_key=? AND state='open'`, openKey).Scan(&id, &oldSeverity)
	if err == nil {
		return id, false, oldSeverity, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, "", err
	}
	id = "inc_" + uuid.NewString()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO incidents(id, site_id, group_id, group_name, open_key, title, suspected_layer, state, severity, opened_at)
		 VALUES(?,?,?,?,?,?,?, 'open', ?, ?)`,
		id, siteID, groupID, groupName, openKey, groupName, layer, severity, now)
	if err != nil {
		// Lost the race for this open_key: re-select the winner and attach to it.
		var id2, sev2 string
		if e2 := tx.QueryRowContext(ctx,
			`SELECT id, severity FROM incidents WHERE open_key=? AND state='open'`, openKey).Scan(&id2, &sev2); e2 == nil {
			return id2, false, sev2, nil
		}
		return "", false, "", err
	}
	return id, true, "", nil
}

// recomputeIncident recomputes an incident's severity, suspected layer and
// summary from its currently-firing member alerts and their evidence, returning
// the new severity.
func recomputeIncident(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) (string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT severity, COALESCE(layer,'') FROM alerts WHERE incident_id=? AND state='firing'`, incidentID)
	if err != nil {
		return "", err
	}
	worst := "warn"
	layers := map[string]bool{}
	any := false
	for rows.Next() {
		var sev, l string
		if err := rows.Scan(&sev, &l); err != nil {
			rows.Close()
			return "", err
		}
		any = true
		if severityRank[sev] > severityRank[worst] {
			worst = sev
		}
		if l != "" {
			layers[l] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	if !any {
		return worst, nil
	}
	suspected := ""
	for _, l := range layerPriority {
		if layers[l] {
			suspected = l
			break
		}
	}
	summary := renderIncidentSummary(ctx, tx, incidentID)
	_, err = tx.ExecContext(ctx,
		`UPDATE incidents SET severity=?, suspected_layer=?, summary=? WHERE id=?`, worst, suspected, summary, incidentID)
	return worst, err
}

// incidentReason maps an alert resolve reason to the incident's resolve_reason so
// a configuration termination is never dressed up as a healthy recovery.
func incidentReason(alertReason string) string {
	if alertReason == alert.ReasonConfigChanged {
		return alert.ReasonConfigChanged
	}
	return alert.ReasonRecovered
}

// addTimeline appends a timeline entry with an entity ref.
func addTimeline(ctx context.Context, tx *sql.Tx, incidentID, kind, message, ref string, now time.Time) {
	if incidentID == "" {
		return
	}
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref) VALUES(?,?,?,?,?,?)`,
		"tl_"+uuid.NewString(), incidentID, now, kind, message, ref)
}

// groupMeta loads a rule's group id/name and merge flag inside the tx.
func groupMeta(ctx context.Context, tx *sql.Tx, ruleID string) (groupID, groupName string, mergeEnabled bool, err error) {
	var merge int
	err = tx.QueryRowContext(ctx, `
		SELECT mg.id, mg.name, mg.merge_enabled
		FROM group_rules gr JOIN monitor_groups mg ON mg.id = gr.group_id
		WHERE gr.id=?`, ruleID).Scan(&groupID, &groupName, &merge)
	return groupID, groupName, merge == 1, err
}

// rowQueryer is the read subset shared by the read pool and an open *sql.Tx, so
// loadScopedRules can read rule definitions inside the caller's write tx.
type rowQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// loadScopedRules assembles the enabled group rules in an agent's scope with
// their conditions and each condition's target identity, reading through q (the
// caller's tx during an in-tx evaluation) so definitions are consistent with the
// commit.
func (s *Service) loadScopedRules(ctx context.Context, q rowQueryer, agentID, siteID string) ([]evalRule, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT gr.id, gr.group_id, gr.op, COALESCE(gr.layer,''), gr.severity, COALESCE(gr.channel_ids,'[]'), gr.name,
		       c.id, c.target_id, c.metric_kind, c.comparator, c.threshold, c.fail_threshold, c.for_seconds,
		       pt.kind, COALESCE(pt.target,''), COALESCE(pt.name,''), COALESCE(pt.params,''), pt.config_serial
		FROM group_rules gr
		JOIN group_rule_conditions c ON c.rule_id = gr.id
		JOIN probe_tasks pt ON pt.id = c.target_id
		WHERE gr.site_id=? AND gr.enabled=1 AND `+config.AgentScopePredicate+`
		ORDER BY gr.id, c.position`, siteID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var order []string
	byID := map[string]*evalRule{}
	for rows.Next() {
		var rid, groupID, op, layer, sev, chans, name string
		var c evalCond
		var params string
		if err := rows.Scan(&rid, &groupID, &op, &layer, &sev, &chans, &name,
			&c.id, &c.targetID, &c.metricKind, &c.comparator, &c.threshold, &c.failThreshold, &c.forSeconds,
			&c.kind, &c.targetStr, &c.targetName, &params, &c.configSerial); err != nil {
			return nil, err
		}
		c.port = portFromParams(params)
		r := byID[rid]
		if r == nil {
			var ch []string
			if chans != "" {
				_ = json.Unmarshal([]byte(chans), &ch)
			}
			r = &evalRule{id: rid, op: op, layer: layer, severity: sev, name: name, channelIDs: ch, groupIDCache: groupID}
			byID[rid] = r
			order = append(order, rid)
		}
		r.conds = append(r.conds, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]evalRule, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}
