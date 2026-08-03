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
	// pendingFails is the cause of each failing round of the streak in progress,
	// oldest first. It is staged in the row rather than held in memory because a
	// streak spans ingest batches — one transaction each — and it is needed because
	// the round that ENDS a streak carries no failure cause: without it a recovered
	// streak could only be recorded as "something failed twice". Accumulated only
	// while no signal is firing (a confirmed fault has already frozen its own copy),
	// so it is bounded by fail_threshold.
	pendingFails []FailEvidence
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
		// The discarded streak is not recorded as a fluctuation either. A streak cut
		// short by an operator editing the target is an artefact of that edit, not a
		// network event, and filing it as one would put noise in the very record whose
		// job is to explain real dips.
		st.pendingFails = nil
	}

	for _, r := range rounds {
		// Watermark: a round at or before the newest already-folded round is a
		// duplicate or an out-of-order straggler. Its sample is still stored (history
		// is complete) but it must not advance, rewind or re-decide current state.
		if r.TS <= st.lastRoundTS {
			continue
		}
		// A streak is N CONSECUTIVE rounds, and consecutive has to mean something in
		// wall-clock terms. Nothing else expires a streak — an Agent that dies
		// mid-streak leaves its counters untouched (its own connectivity fault covers
		// the outage), so without this an Agent failing twice and returning a day later
		// would either confirm a fault on "three consecutive rounds" spanning a day, or
		// file a fluctuation whose window is a day wide. Either one answers "why is
		// availability 99%?" with a fabrication, which is worse than not answering.
		//
		// Beyond the gap there is simply no evidence, so the streak is abandoned and
		// counting starts fresh rather than being stitched across the hole.
		if st.failRounds > 0 && st.lastRoundTS > 0 && r.TS-st.lastRoundTS > int64(r.Meta.maxRoundGap().Seconds()) {
			st.failRounds, st.okRounds = 0, 0
			st.firstFailTS = sql.NullInt64{}
			st.pendingFails = nil
		}
		st.lastRoundTS = r.TS
		st.lastValue = sql.NullFloat64{Float64: r.Value, Valid: true}
		if r.Class == RoundFail {
			st.failRounds++
			st.okRounds = 0
			if !st.firstFailTS.Valid {
				st.firstFailTS = sql.NullInt64{Int64: r.TS, Valid: true}
			}
			if !st.signalID.Valid {
				// Stage this round's cause while the streak is still unconfirmed. Once a
				// signal is firing it owns the frozen evidence, so accumulating past that
				// point would grow without bound through a long outage.
				st.pendingFails = append(st.pendingFails, FailEvidence{
					TS: r.TS, MetricKind: r.MetricKind, Value: r.Value,
					ReasonCode: r.ReasonCode, ReasonDetail: r.ReasonDetail,
				})
			}
			if !st.signalID.Valid && st.failRounds >= r.Det.FailRounds {
				id, err := s.confirmSignal(ctx, tx, agentID, siteID, agentName, r, st, now, out)
				if err != nil {
					return err
				}
				st.signalID = sql.NullString{String: id, Valid: true}
				st.pendingFails = nil // the signal froze its own copy
			}
			continue
		}
		// A streak that never confirmed is about to be erased by this success — its
		// counter and start time are cleared below and nothing else in the system
		// remembers it. Record it first: this is the dip behind a 99% availability
		// figure, and until now it left no explanation anywhere. A streak that DID
		// confirm is excluded (signalID set): that is a fault recovering, which the
		// fault centre already tells in full.
		if st.failRounds > 0 && !st.signalID.Valid {
			if err := insertFluctuation(ctx, tx, agentID, siteID, agentName, r, st); err != nil {
				return err
			}
		}
		st.okRounds++
		st.failRounds = 0
		st.firstFailTS = sql.NullInt64{}
		st.pendingFails = nil
		if st.signalID.Valid && st.okRounds >= r.Det.RecoverRounds {
			if err := s.resolveSignal(ctx, tx, st.signalID.String, ReasonRecovered, timeFromUnix(r.TS), now, out); err != nil {
				return err
			}
			st.signalID = sql.NullString{}
		}
	}

	// The row is written on every pass, including one where every round was green
	// and only last_round_ts moved. Skipping that write was tried and reverted:
	// last_round_ts is the watermark that rejects a round at or before the newest
	// already-folded one, so a watermark left behind re-opens the window it
	// closes — a packet carrying FAILING rounds inside the un-persisted lag would
	// be folded a second time and could confirm a fault the target has already
	// recovered from. Bounding the lag does not fix it either: a bound wide enough
	// to save writes still fits more than fail_threshold rounds.
	//
	// It is also not worth much. detector_state is a rowid table, so a row lives
	// where it was inserted, and one agent's targets are inserted together when it
	// first reports — its whole per-batch update lands in one or two pages, not one
	// page per target. The write this would have saved is a small fraction of
	// ingest's page traffic, against a defect class (fabricated incidents and the
	// notifications they send) that is expensive to even detect.
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
		// Where the probe actually went, from the confirming round's own samples and
		// the generation-matched proxy pin. Frozen so a later config edit cannot
		// redirect this fault's path diagnostic to a different endpoint.
		ResolverAddr: r.ResolverAddr, ResolverProtocol: r.ResolverProtocol,
		StunAddr: r.StunAddr, StunTransport: r.StunTransport,
		ProxyID: r.Meta.ProxyID, ProxyType: r.Meta.ProxyType, ProxyAddr: r.Meta.ProxyAddr,
		ProxyConfigSerial: r.Meta.ProxyConfigSerial,
		// Freeze the cause of every round of the streak, not just the confirming one.
		// The summary columns above answer "why is this firing"; these answer "what
		// actually happened" — a target that timed out twice and was then refused
		// points somewhere different from one refused three times, and the difference
		// is invisible if only the last round survives. pendingFails holds the earlier
		// rounds; this round is the last of them.
		Rounds:     st.pendingFails,
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
	// Claim the sub-threshold streaks that led up to this fault. They stop being
	// standalone curiosities and become this incident's precursor evidence, which is
	// often the most useful thing in it: "it had been flapping for half an hour" is
	// a different diagnosis from "it failed out of nowhere".
	linkPrecursors(ctx, tx, incidentID, r.TargetID, agentID, observed, now)
	out.confirmed = append(out.confirmed, SignalEvent{
		SignalID: signalID, IncidentID: incidentID, SiteID: siteID,
		AgentID: agentID, TargetID: r.TargetID, Severity: sig.Severity,
	})

	scope := IncidentScope{
		IncidentID: incidentID, SiteID: siteID, GroupID: r.GroupID,
		AgentID: agentID, Severity: newSeverity,
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
		// The incident plans nothing here, but its severity just changed downward.
		// Anything the policy layer aggregates over it has to hear about that, or a
		// notice still waiting out its delay will announce a severity that recovered
		// before it was ever sent.
		if s.planner != nil {
			return s.planner.RecomputeTx(ctx, tx, incidentID, now)
		}
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
	var pending string
	err := tx.QueryRowContext(ctx, `
		SELECT config_serial, detection_rev, fail_rounds, ok_rounds, last_round_ts,
		       first_fail_ts, active_signal_id, last_value, pending_fails
		FROM detector_state WHERE target_id=? AND agent_id=? AND detector_key=?`,
		targetID, agentID, detector).
		Scan(&st.configSerial, &st.detectionRev, &st.failRounds, &st.okRounds, &st.lastRoundTS,
			&st.firstFailTS, &st.signalID, &st.lastValue, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return detectorState{}, nil
	}
	if err != nil {
		return detectorState{}, err
	}
	st.exists = true
	st.pendingFails = decodeRounds(pending)
	// Defend against a signal that was terminated out of band (config change,
	// agent removal) without clearing this row: a resolved signal must never be
	// treated as the detector's active one.
	//
	// The failing streak goes with it. Those rounds were already recorded as a
	// confirmed fault, so carrying the counter forward would let the next
	// succeeding round file them a SECOND time as a fluctuation — the same failures
	// reported twice, once as an outage and once as a blip. Counting restarts
	// instead, which is the same thing every other termination path does by deleting
	// the row outright.
	if st.signalID.Valid {
		var state string
		e := tx.QueryRowContext(ctx, `SELECT state FROM fault_signals WHERE id=?`, st.signalID.String).Scan(&state)
		if errors.Is(e, sql.ErrNoRows) || (e == nil && state != "firing") {
			st.signalID = sql.NullString{}
			st.failRounds, st.okRounds = 0, 0
			st.firstFailTS = sql.NullInt64{}
			st.pendingFails = nil
		} else if e != nil {
			return detectorState{}, e
		}
	}
	return st, nil
}

func saveDetectorState(ctx context.Context, tx *sql.Tx, targetID, agentID, detector string,
	configSerial, detectionRev int, st detectorState, now time.Time) error {
	pending, err := encodeRounds(st.pendingFails)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO detector_state(target_id, agent_id, detector_key, config_serial, detection_rev,
		    fail_rounds, ok_rounds, last_round_ts, first_fail_ts, active_signal_id, last_value,
		    pending_fails, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, agent_id, detector_key) DO UPDATE SET
		    config_serial=excluded.config_serial, detection_rev=excluded.detection_rev,
		    fail_rounds=excluded.fail_rounds, ok_rounds=excluded.ok_rounds,
		    last_round_ts=excluded.last_round_ts, first_fail_ts=excluded.first_fail_ts,
		    active_signal_id=excluded.active_signal_id, last_value=excluded.last_value,
		    pending_fails=excluded.pending_fails, updated_at=excluded.updated_at`,
		targetID, agentID, detector, configSerial, detectionRev,
		st.failRounds, st.okRounds, st.lastRoundTS, st.firstFailTS, st.signalID, st.lastValue,
		pending, now)
	return err
}

// insertSignal writes a confirmed signal with all its display facts frozen.
func insertSignal(ctx context.Context, tx *sql.Tx, sig Signal, port int) error {
	roundsJSON, err := encodeRounds(sig.Rounds)
	if err != nil {
		return err
	}
	// The diagnosis-subject columns are empty for every detector that has no probe
	// behind it (agent connectivity), which the zero-valued Signal supplies.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO fault_signals(id, site_id, agent_id, target_id, detector_key, probe_kind,
		    group_id, group_name, target_name, target_addr, target_port, agent_name, layer, severity,
		    state, fail_threshold, recover_threshold, metric_kind, comparator, value, threshold,
		    reason_code, reason_detail,
		    resolver_addr, resolver_protocol, stun_addr, stun_transport,
		    proxy_id, proxy_type, proxy_addr, proxy_config_serial,
		    rounds_json, observed_at, confirmed_at, incident_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'firing', ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sig.ID, sig.SiteID, sig.AgentID, sig.TargetID, sig.DetectorKey, sig.ProbeKind,
		sig.GroupID, sig.GroupName, sig.TargetName, sig.TargetAddr, port, sig.AgentName, sig.Layer, sig.Severity,
		sig.FailThreshold, sig.RecoverThreshold, sig.MetricKind, sig.Comparator, sig.Value, sig.Threshold,
		sig.ReasonCode, sig.ReasonDetail,
		sig.ResolverAddr, sig.ResolverProtocol, sig.StunAddr, sig.StunTransport,
		sig.ProxyID, sig.ProxyType, sig.ProxyAddr, sig.ProxyConfigSerial,
		roundsJSON, sig.ObservedAt, sig.ConfirmedAt, sig.IncidentID)
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

// AddTimelineTx appends a timeline entry inside the caller's open write tx.
// Exported so the notification-policy layer can record on the incident's own
// timeline why its notice was suppressed in favour of a storm summary — the
// operator reads one timeline, not two.
func AddTimelineTx(ctx context.Context, tx *sql.Tx, incidentID, kind, message, ref string, now time.Time) {
	addTimeline(ctx, tx, incidentID, kind, message, ref, now)
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
