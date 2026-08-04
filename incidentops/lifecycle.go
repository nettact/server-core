package incidentops

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	pcfg "github.com/nettact/protocol/config"
)

// Recover restores in-flight state after a restart: it finalizes snapshots whose
// deadline elapsed while the server was down, times out queued/running traces
// past their deadline, reconciles active trace references against alert state,
// closes cohorts left orphaned, and re-dispatches the still-eligible trace queue.
// It spawns no goroutine — the server calls it once during startup.
func (s *Service) Recover(ctx context.Context) error {
	if err := s.finalizeExpiredSnapshots(ctx); err != nil {
		return err
	}
	if err := s.timeoutExpiredTraces(ctx); err != nil {
		return err
	}
	if err := s.reconcileTraceRefs(ctx); err != nil {
		return err
	}
	if err := s.closeOrphanCohorts(ctx); err != nil {
		return err
	}
	s.dispatchAll(ctx)
	return nil
}

// Tick is the callable periodic maintenance pass (the server drives it on a
// timer): finalize expired snapshots, time out expired traces, reconcile active
// trace references against alert state, close orphaned cohorts, and rehydrate the
// eligible trace queue. Idempotent and cheap when there is nothing to do.
func (s *Service) Tick(ctx context.Context) error {
	if err := s.finalizeExpiredSnapshots(ctx); err != nil {
		return err
	}
	if err := s.timeoutExpiredTraces(ctx); err != nil {
		return err
	}
	if err := s.reconcileTraceRefs(ctx); err != nil {
		return err
	}
	if err := s.closeOrphanCohorts(ctx); err != nil {
		return err
	}
	s.dispatchAll(ctx)
	return nil
}

// finalizeExpiredSnapshots finalizes every snapshot still collecting past its
// deadline, terminating any stragglers deterministically.
func (s *Service) finalizeExpiredSnapshots(ctx context.Context) error {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT id FROM incident_snapshots WHERE status='collecting' AND deadline_at <= ?`, time.Now().UTC())
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.finalizeSnapshot(ctx, id, true); err != nil {
			return err
		}
	}
	return nil
}

// timeoutExpiredTraces marks queued/running reports past their deadline as
// timed_out and emits a completion timeline entry for each referencing incident.
// The deadline (requested_at + diag_total_timeout_ms) is the only validity bound.
func (s *Service) timeoutExpiredTraces(ctx context.Context) error {
	now := time.Now().UTC()
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT id FROM trace_reports WHERE status IN('queued','running') AND deadline_at <= ?`, now)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		res, err := s.db.ExecContext(ctx,
			`UPDATE trace_reports SET status='timed_out', reason='deadline', completed_at=COALESCE(completed_at,?)
			 WHERE id=? AND status IN('queued','running')`, now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		if err := s.emitTraceCompletionWrite(ctx, id, now); err != nil {
			return err
		}
	}
	return nil
}

// emitTraceCompletionWrite is the non-transactional counterpart of
// emitTraceCompletion, used by the timeout sweep on the write handle.
func (s *Service) emitTraceCompletionWrite(ctx context.Context, reportID string, now time.Time) error {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT DISTINCT incident_id FROM trace_report_refs WHERE report_id=?`, reportID)
	if err != nil {
		return err
	}
	var incs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		incs = append(incs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, incidentID := range incs {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref) VALUES(?,?,?,?,?,?)`,
			"tl_"+uuid.NewString(), incidentID, now, "diag.completed", "", reportID); err != nil {
			return err
		}
	}
	return nil
}

// reconcileTraceRefs durably deactivates any trace reference whose alert is no
// longer firing. It is the crash/missed-callback safety net for the post-commit
// OnAlertResolved deactivation (which runs in a separate transaction and whose
// error the eventbus swallows): if that handler never ran, the reference would
// stay active=1 forever, keeping the report's cohort open so a later same-key
// fault attaches to the previous fault's report instead of starting a fresh one.
// Running this before closeOrphanCohorts on every Recover/Tick guarantees a
// resolved alert's references are cleared, so the cohort closes and cross-fault
// report reuse cannot happen. Idempotent.
func (s *Service) reconcileTraceRefs(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE trace_report_refs SET active=0
		WHERE active=1
		  AND signal_id NOT IN (SELECT id FROM fault_signals WHERE state='firing')`)
	return err
}

// closeOrphanCohorts closes any open cohort whose active reference count has
// fallen to zero (e.g. an alert-resolution callback the server missed while down).
// It never touches the execution.
func (s *Service) closeOrphanCohorts(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE trace_reports SET cohort_open=0
		WHERE cohort_open=1
		  AND NOT EXISTS(SELECT 1 FROM trace_report_refs r WHERE r.report_id=trace_reports.id AND r.active=1)`)
	return err
}

// dispatchAll re-dispatches the eligible (queued, in-deadline) trace queue for
// every agent that has pending work, bounded by the concurrency limits.
func (s *Service) dispatchAll(ctx context.Context) {
	if s.pusher == nil {
		return
	}
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT DISTINCT agent_id FROM trace_reports WHERE status='queued' AND deadline_at > ?`, time.Now().UTC())
	if err != nil {
		return
	}
	var agents []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return
		}
		agents = append(agents, id)
	}
	rows.Close()
	for _, id := range agents {
		s.dispatchAgent(ctx, id)
	}
}

// OnAgentConnected re-pushes an agent's still-outstanding, in-deadline work when
// its session (re)connects: collecting snapshot requests and running traces are
// re-sent (idempotent on the agent), and its queued traces are dispatched within
// the concurrency limits. Called by the hub from the connect path, after the
// session is registered, so the Pusher resolves to the live session.
func (s *Service) OnAgentConnected(ctx context.Context, agentID string) {
	if s.pusher == nil {
		return
	}
	now := time.Now().UTC()

	// Snapshot: re-push each still-collecting in-deadline request for this agent.
	// The target refs come from the entry, frozen when it was created — NOT from
	// probe_tasks. An agent can be offline for the whole collection window, and
	// re-deriving here would collect the scene against whatever the monitor was
	// edited into meanwhile (or, for a deleted one, against nothing at all).
	srows, err := s.db.Read().QueryContext(ctx, `
		SELECT e.request_id, e.targets, sn.incident_id, sn.deadline_at
		FROM incident_snapshot_entries e
		JOIN incident_snapshots sn ON sn.id = e.snapshot_id
		WHERE e.agent_id=? AND e.status='collecting' AND sn.deadline_at > ?`, agentID, now)
	if err == nil {
		type pend struct {
			reqID, incidentID string
			deadline          time.Time
			targets           []pcfg.SnapshotTargetRef
		}
		var pends []pend
		for srows.Next() {
			var p pend
			var targets string
			if err := srows.Scan(&p.reqID, &targets, &p.incidentID, &p.deadline); err != nil {
				break
			}
			// A malformed or empty blob yields no targets: the scene still collects
			// its network/agent/resource groups rather than the push being skipped.
			if targets != "" {
				_ = json.Unmarshal([]byte(targets), &p.targets)
			}
			pends = append(pends, p)
		}
		srows.Close()
		for _, p := range pends {
			s.dispatchSnapshot(agentID, p.incidentID, p.reqID, p.deadline, p.targets)
		}
	}

	// Trace: re-push in-deadline running reports, then dispatch queued ones.
	trows, err := s.db.Read().QueryContext(ctx,
		`SELECT id FROM trace_reports WHERE agent_id=? AND status='running' AND deadline_at > ?`, agentID, now)
	if err == nil {
		var ids []string
		for trows.Next() {
			var id string
			if err := trows.Scan(&id); err != nil {
				break
			}
			ids = append(ids, id)
		}
		trows.Close()
		for _, id := range ids {
			if req, ok := s.buildTraceRequest(ctx, id); ok {
				s.pusher.PushTraceRequest(agentID, req)
			}
		}
	}
	s.dispatchAgent(ctx, agentID)
}

// ---- retention ----

// Retention deletes agent-collected snapshot detail and trace hop detail for
// incidents resolved longer than the evidence-retention window, preserving the
// incident/alert/evidence summaries and marking the incident evidence_expired.
// Open incidents are never touched. Trace hops are deleted only when it is safe
// across all shared references — the report's cohort is closed and every incident
// still referencing it is itself resolved-and-expired — so a report shared with a
// still-live incident is preserved. Idempotent; the server drives it hourly.
func (s *Service) Retention(ctx context.Context) error {
	days := s.retentionDays(ctx)
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT id FROM incidents WHERE state='resolved' AND evidence_expired=0 AND resolved_at IS NOT NULL AND resolved_at < ?`,
		cutoff)
	if err != nil {
		return err
	}
	var due []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		due = append(due, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(due) == 0 {
		return nil
	}

	for _, incidentID := range due {
		// Drop the agent-collected scene entries; keep the incident_snapshots base
		// summary row.
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM incident_snapshot_entries
			 WHERE snapshot_id IN (SELECT id FROM incident_snapshots WHERE incident_id=?)`, incidentID); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE incidents SET evidence_expired=1 WHERE id=?`, incidentID); err != nil {
			return err
		}
	}

	// Delete trace hop detail only for closed-cohort reports whose every referencing
	// incident is now resolved-and-expired — never for a report still referenced by
	// a live incident.
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM trace_hops WHERE report_id IN (
			SELECT tr.id FROM trace_reports tr
			WHERE tr.cohort_open=0
			  AND EXISTS(SELECT 1 FROM trace_report_refs r WHERE r.report_id=tr.id)
			  AND NOT EXISTS(
				SELECT 1 FROM trace_report_refs r JOIN incidents i ON i.id=r.incident_id
				WHERE r.report_id=tr.id AND NOT (i.state='resolved' AND i.evidence_expired=1)))`); err != nil {
		return err
	}
	return nil
}
