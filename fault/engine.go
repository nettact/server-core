package fault

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
)

// Outcome is one evaluation pass's post-commit work: the lifecycle events the tx
// owner must publish after a successful commit (via PublishOutcome) and the
// target ids whose current status may have shifted. Discarded on rollback.
type Outcome struct {
	out              *txOut
	siteID           string
	ChangedTargetIDs []string
}

// detectorState is one (target, agent, detector) row.
type detectorState struct {
	exists       bool
	configSerial int
	detectionRev int
	failRounds   int
	okRounds     int
	lastRoundTS  int64
	firstFailTS  sql.NullInt64
	signalID     sql.NullString
	lastValue    sql.NullFloat64
}

// EvaluateAgentTx advances every affected detector by the rounds this batch
// carries, inside the caller's open write transaction, so samples, detector
// state, fault signals, incidents and notification plans commit atomically. An
// error rolls the whole batch back and the agent's ack is withheld, so it
// retries the same sequence.
//
// Rounds are applied ONE AT A TIME in timestamp order. This is what makes the
// "N consecutive rounds" contract mean rounds rather than uploads: a WAL backfill
// delivering five failing cycles in one packet confirms exactly as if they had
// arrived separately, and a replayed packet — whose rounds are all at or below
// the detector's watermark — advances nothing.
func (s *Service) EvaluateAgentTx(ctx context.Context, tx *sql.Tx, agentID, siteID string, rounds []Round) (*Outcome, error) {
	out := &txOut{}
	if len(rounds) == 0 {
		return &Outcome{out: out, siteID: siteID}, nil
	}
	now := time.Now().UTC()
	agentName, err := agentDisplayName(ctx, tx, agentID)
	if err != nil {
		return nil, err
	}

	changed := make([]string, 0, 8)
	seen := map[string]bool{}
	// rounds are sorted by (target, ts), so one pass walks each detector's rounds
	// in order without regrouping.
	for i := 0; i < len(rounds); {
		targetID := rounds[i].TargetID
		j := i
		for j < len(rounds) && rounds[j].TargetID == targetID {
			j++
		}
		if err := s.advanceDetector(ctx, tx, agentID, siteID, agentName, rounds[i:j], now, out); err != nil {
			return nil, err
		}
		if !seen[targetID] {
			seen[targetID] = true
			changed = append(changed, targetID)
		}
		i = j
	}
	return &Outcome{out: out, siteID: siteID, ChangedTargetIDs: changed}, nil
}

// advanceDetector folds one target's rounds into its detector state and drives
// the confirm/resolve transitions.
func (s *Service) advanceDetector(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string, rounds []Round, now time.Time, out *txOut) error {
	targetID := rounds[0].TargetID
	st, err := loadDetectorState(ctx, tx, targetID, agentID, DetectorAvailability)
	if err != nil {
		return err
	}
	cur := rounds[len(rounds)-1]

	// Counters are pinned to the generation and sensitivity revision they were
	// accumulated under. When either advanced, a streak measured under the old
	// configuration says nothing about the new one, so counting restarts. The
	// active signal (if any) has already been terminated by the config path that
	// caused the advance, so there is nothing to carry over.
	if st.exists && (st.configSerial != cur.ConfigSerial || st.detectionRev != cur.Det.Revision) {
		st.failRounds, st.okRounds = 0, 0
		st.firstFailTS = sql.NullInt64{}
		st.lastRoundTS = 0
	}

	for _, r := range rounds {
		// Watermark: a round at or before the newest already-folded round is a
		// duplicate or an out-of-order straggler. Its sample is still stored (history
		// is complete) but it must not advance, rewind or re-decide current state.
		if r.TS <= st.lastRoundTS {
			continue
		}
		st.lastRoundTS = r.TS
		st.lastValue = sql.NullFloat64{Float64: r.Value, Valid: true}
		if r.Class == RoundFail {
			st.failRounds++
			st.okRounds = 0
			if !st.firstFailTS.Valid {
				st.firstFailTS = sql.NullInt64{Int64: r.TS, Valid: true}
			}
			if !st.signalID.Valid && st.failRounds >= r.Det.FailRounds {
				id, err := s.confirmSignal(ctx, tx, agentID, siteID, agentName, r, st, now, out)
				if err != nil {
					return err
				}
				st.signalID = sql.NullString{String: id, Valid: true}
			}
			continue
		}
		st.okRounds++
		st.failRounds = 0
		st.firstFailTS = sql.NullInt64{}
		if st.signalID.Valid && st.okRounds >= r.Det.RecoverRounds {
			if err := s.resolveSignal(ctx, tx, st.signalID.String, ReasonRecovered, timeFromUnix(r.TS), now, out); err != nil {
				return err
			}
			st.signalID = sql.NullString{}
		}
	}

	return saveDetectorState(ctx, tx, targetID, agentID, DetectorAvailability, cur.ConfigSerial, cur.Det.Revision, st, now)
}

// confirmSignal opens a fault signal with its evidence frozen from the confirming
// round, attaches it to an incident (merged per its group's policy) and plans the
// incident's open notification.
func (s *Service) confirmSignal(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string, r Round, st detectorState, now time.Time, out *txOut) (string, error) {
	groupName, mergeEnabled, err := groupMeta(ctx, tx, r.GroupID)
	if err != nil {
		return "", err
	}
	signalID := "sig_" + uuid.NewString()
	observed := timeFromUnix(r.TS)
	if st.firstFailTS.Valid {
		observed = timeFromUnix(st.firstFailTS.Int64)
	}
	confirmed := timeFromUnix(r.TS)

	sig := Signal{
		ID: signalID, SiteID: siteID, AgentID: agentID, AgentName: agentName,
		TargetID: r.TargetID, TargetName: r.Meta.Name, TargetAddr: r.Meta.Addr,
		DetectorKey: DetectorAvailability, ProbeKind: r.Kind,
		GroupID: r.GroupID, GroupName: groupName, Layer: r.Layer, Severity: SeverityWarn,
		FailThreshold: r.Det.FailRounds, RecoverThreshold: r.Det.RecoverRounds,
		MetricKind: r.MetricKind, Comparator: r.Comparator, Value: r.Value, Threshold: r.Threshold,
		ReasonCode: r.ReasonCode, ReasonDetail: r.ReasonDetail,
		ObservedAt: observed, ConfirmedAt: confirmed,
	}
	openKey := "sig:" + signalID
	if mergeEnabled && r.GroupID != "" {
		openKey = "grp:" + r.GroupID
	}
	title := SignalTitle(sig)
	if mergeEnabled && groupName != "" {
		title = groupName
	}
	incidentID, opened, oldSeverity, err := findOrCreateIncident(ctx, tx,
		openKey, siteID, r.GroupID, groupName, title, sig.Severity, sig.Layer, now)
	if err != nil {
		return "", err
	}
	sig.IncidentID = incidentID
	if err := insertSignal(ctx, tx, sig, r.Meta.Port); err != nil {
		return "", err
	}
	newSeverity, err := recomputeIncident(ctx, tx, incidentID)
	if err != nil {
		return "", err
	}
	addTimeline(ctx, tx, incidentID, "fault.confirmed", SignalTitle(sig), signalID, now)
	out.confirmed = append(out.confirmed, SignalEvent{
		SignalID: signalID, IncidentID: incidentID, SiteID: siteID,
		AgentID: agentID, TargetID: r.TargetID, Severity: sig.Severity,
	})

	scope := IncidentScope{
		IncidentID: incidentID, SiteID: siteID, GroupID: r.GroupID,
		Severity: newSeverity,
	}
	if opened {
		// One immutable base snapshot per incident, written synchronously in this
		// transaction. A failure is advisory and never blocks the incident.
		if s.snap != nil {
			if err := s.snap.WriteIncidentBase(ctx, tx, incidentID, now); err != nil {
				log.Printf("fault: incident base snapshot for %s: %v", incidentID, err)
			}
		}
		addTimeline(ctx, tx, incidentID, "incident.opened", "", incidentID, now)
		out.incidentOpened = append(out.incidentOpened, incidentEvent(incidentID, siteID, r.GroupID, newSeverity, false))
		if s.planner != nil {
			if err := s.planner.PlanOpenTx(ctx, tx, scope, now); err != nil {
				return "", err
			}
		}
		return signalID, nil
	}
	escalated := severityRank[newSeverity] > severityRank[oldSeverity]
	out.incidentUpdated = append(out.incidentUpdated, incidentEvent(incidentID, siteID, r.GroupID, newSeverity, escalated))
	if escalated {
		addTimeline(ctx, tx, incidentID, "severity.upgraded", newSeverity, incidentID, now)
		if s.planner != nil {
			if err := s.planner.EscalateTx(ctx, tx, scope, now); err != nil {
				return "", err
			}
		}
	}
	return signalID, nil
}

// resolveSignal ends a firing signal and, when it was its incident's last firing
// member, ends the incident too. resolvedAt is the moment the fault actually
// ended (the recovering round's timestamp, or the config change's wall time);
// now is the transaction's wall clock, used for the timeline and the delivery
// plan.
func (s *Service) resolveSignal(ctx context.Context, tx *sql.Tx, signalID, reason string, resolvedAt, now time.Time, out *txOut) error {
	var incidentID, siteID, groupID, targetID, agentID, severity, title string
	err := tx.QueryRowContext(ctx, `
		SELECT incident_id, site_id, group_id, target_id, agent_id, severity, target_name
		FROM fault_signals WHERE id=? AND state='firing'`, signalID).
		Scan(&incidentID, &siteID, &groupID, &targetID, &agentID, &severity, &title)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // already resolved; resolution is idempotent
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE fault_signals SET state='resolved', resolved_at=?, resolve_reason=? WHERE id=?`,
		resolvedAt, reason, signalID); err != nil {
		return err
	}
	kind := "fault.resolved"
	if !IsRecovery(reason) {
		kind = "fault.terminated"
	}
	addTimeline(ctx, tx, incidentID, kind, title, signalID, now)
	out.resolved = append(out.resolved, SignalEvent{
		SignalID: signalID, IncidentID: incidentID, SiteID: siteID,
		AgentID: agentID, TargetID: targetID, Severity: severity, Reason: reason,
	})

	var firing int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM fault_signals WHERE incident_id=? AND state='firing'`, incidentID).Scan(&firing); err != nil {
		return err
	}
	if firing > 0 {
		// Partial recovery: recompute severity/summary and update the timeline only.
		// The incident is still open, so no notification is due either way.
		if _, err := recomputeIncident(ctx, tx, incidentID); err != nil {
			return err
		}
		out.incidentUpdated = append(out.incidentUpdated, incidentEvent(incidentID, siteID, groupID, "", false))
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE incidents SET state='resolved', resolved_at=?, resolve_reason=? WHERE id=? AND state='open'`,
		resolvedAt, reason, incidentID); err != nil {
		return err
	}
	closeKind := "incident.resolved"
	if !IsRecovery(reason) {
		closeKind = "incident.terminated"
	}
	addTimeline(ctx, tx, incidentID, closeKind, "", incidentID, now)
	out.incidentResolved = append(out.incidentResolved, incidentEvent(incidentID, siteID, groupID, severity, false))
	if s.planner != nil {
		if err := s.planner.ResolveTx(ctx, tx, incidentID, reason, now); err != nil {
			return err
		}
	}
	return nil
}

// ---- persistence helpers ----

func loadDetectorState(ctx context.Context, tx *sql.Tx, targetID, agentID, detector string) (detectorState, error) {
	var st detectorState
	err := tx.QueryRowContext(ctx, `
		SELECT config_serial, detection_rev, fail_rounds, ok_rounds, last_round_ts,
		       first_fail_ts, active_signal_id, last_value
		FROM detector_state WHERE target_id=? AND agent_id=? AND detector_key=?`,
		targetID, agentID, detector).
		Scan(&st.configSerial, &st.detectionRev, &st.failRounds, &st.okRounds, &st.lastRoundTS,
			&st.firstFailTS, &st.signalID, &st.lastValue)
	if errors.Is(err, sql.ErrNoRows) {
		return detectorState{}, nil
	}
	if err != nil {
		return detectorState{}, err
	}
	st.exists = true
	// Defend against a signal that was terminated out of band (config change,
	// agent removal) without clearing this row: a resolved signal must never be
	// treated as the detector's active one.
	if st.signalID.Valid {
		var state string
		e := tx.QueryRowContext(ctx, `SELECT state FROM fault_signals WHERE id=?`, st.signalID.String).Scan(&state)
		if errors.Is(e, sql.ErrNoRows) || (e == nil && state != "firing") {
			st.signalID = sql.NullString{}
		} else if e != nil {
			return detectorState{}, e
		}
	}
	return st, nil
}

func saveDetectorState(ctx context.Context, tx *sql.Tx, targetID, agentID, detector string,
	configSerial, detectionRev int, st detectorState, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO detector_state(target_id, agent_id, detector_key, config_serial, detection_rev,
		    fail_rounds, ok_rounds, last_round_ts, first_fail_ts, active_signal_id, last_value, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, agent_id, detector_key) DO UPDATE SET
		    config_serial=excluded.config_serial, detection_rev=excluded.detection_rev,
		    fail_rounds=excluded.fail_rounds, ok_rounds=excluded.ok_rounds,
		    last_round_ts=excluded.last_round_ts, first_fail_ts=excluded.first_fail_ts,
		    active_signal_id=excluded.active_signal_id, last_value=excluded.last_value,
		    updated_at=excluded.updated_at`,
		targetID, agentID, detector, configSerial, detectionRev,
		st.failRounds, st.okRounds, st.lastRoundTS, st.firstFailTS, st.signalID, st.lastValue, now)
	return err
}

// insertSignal writes a confirmed signal with all its display facts frozen.
func insertSignal(ctx context.Context, tx *sql.Tx, sig Signal, port int) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO fault_signals(id, site_id, agent_id, target_id, detector_key, probe_kind,
		    group_id, group_name, target_name, target_addr, target_port, agent_name, layer, severity,
		    state, fail_threshold, recover_threshold, metric_kind, comparator, value, threshold,
		    reason_code, reason_detail, observed_at, confirmed_at, incident_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'firing', ?,?,?,?,?,?,?,?,?,?,?)`,
		sig.ID, sig.SiteID, sig.AgentID, sig.TargetID, sig.DetectorKey, sig.ProbeKind,
		sig.GroupID, sig.GroupName, sig.TargetName, sig.TargetAddr, port, sig.AgentName, sig.Layer, sig.Severity,
		sig.FailThreshold, sig.RecoverThreshold, sig.MetricKind, sig.Comparator, sig.Value, sig.Threshold,
		sig.ReasonCode, sig.ReasonDetail, sig.ObservedAt, sig.ConfirmedAt, sig.IncidentID)
	return err
}

// findOrCreateIncident returns the open incident for an open_key, creating one
// when none is open. The partial unique index on open_key (WHERE state='open')
// keeps concurrent or replayed confirmations from duplicating; a losing insert
// re-selects the winner. Ended incidents never reopen — a new fault under the
// same key opens a new incident. oldSeverity is the severity before this
// attachment (empty for a freshly opened incident).
func findOrCreateIncident(ctx context.Context, tx *sql.Tx, openKey, siteID, groupID, groupName, title, severity, layer string, now time.Time) (id string, opened bool, oldSeverity string, err error) {
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
		id, siteID, groupID, groupName, openKey, title, layer, severity, now)
	if err != nil {
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
// summary from its currently-firing members, returning the new severity.
func recomputeIncident(ctx context.Context, tx *sql.Tx, incidentID string) (string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT severity, COALESCE(layer,'') FROM fault_signals WHERE incident_id=? AND state='firing'`, incidentID)
	if err != nil {
		return "", err
	}
	worst := SeverityWarn
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
	summary, err := renderIncidentSummary(ctx, tx, incidentID)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE incidents SET severity=?, suspected_layer=?, summary=? WHERE id=?`, worst, suspected, summary, incidentID)
	return worst, err
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

// groupMeta loads a monitor group's display name and merge policy inside the tx.
// A missing group (agent-connectivity signals carry none) yields no merge.
func groupMeta(ctx context.Context, tx *sql.Tx, groupID string) (name string, mergeEnabled bool, err error) {
	if groupID == "" {
		return "", false, nil
	}
	var merge int
	err = tx.QueryRowContext(ctx, `SELECT name, merge_enabled FROM monitor_groups WHERE id=?`, groupID).Scan(&name, &merge)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return name, merge == 1, err
}

// agentDisplayName resolves an agent's display name for freezing onto signals.
func agentDisplayName(ctx context.Context, tx *sql.Tx, agentID string) (string, error) {
	var name string
	err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(NULLIF(display_name,''), hostname, id) FROM agents WHERE id=?`, agentID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return agentID, nil
	}
	return name, err
}
