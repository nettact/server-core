package incidentops

import (
	"context"
	"encoding/json"
	"time"

	pcfg "github.com/nettact/protocol/config"
)

// Recover restores in-flight state after a restart: it finalizes snapshots whose
// deadline elapsed while the server was down and reconciles active trace
// references against alert state. It spawns no goroutine — the server calls it
// once during startup.
//
// Traceroute needs no recovery any more. The Agent owns the execution and the
// outbox owns the delivery, so a server that was down while a trace ran finds
// the report waiting in the next packet rather than a half-finished lifecycle of
// its own.
func (s *Service) Recover(ctx context.Context) error {
	if err := s.finalizeExpiredSnapshots(ctx); err != nil {
		return err
	}
	return s.reconcileTraceRefs(ctx)
}

// Tick is the callable periodic maintenance pass (the server drives it on a
// timer): finalize expired snapshots and reconcile active trace references
// against alert state. Idempotent and cheap when there is nothing to do.
func (s *Service) Tick(ctx context.Context) error {
	if err := s.finalizeExpiredSnapshots(ctx); err != nil {
		return err
	}
	return s.reconcileTraceRefs(ctx)
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

// reconcileTraceRefs durably deactivates any trace reference whose alert is no
// longer firing. It is the crash/missed-callback safety net for the post-commit
// OnSignalResolved deactivation (which runs in a separate transaction and whose
// error the eventbus swallows): if that handler never ran, the reference would
// stay active=1 forever and a resolved fault would keep counting its old trace
// as live evidence. Idempotent.
func (s *Service) reconcileTraceRefs(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE trace_report_refs SET active=0
		WHERE active=1
		  AND signal_id NOT IN (SELECT id FROM fault_signals WHERE state='firing')`)
	return err
}

// OnAgentConnected re-pushes an agent's still-outstanding, in-deadline
// incident-snapshot work when its session (re)connects (idempotent on the
// agent). Called by the hub from the connect path, after the session is
// registered, so the Pusher resolves to the live session.
//
// Traceroute is deliberately absent: there is nothing to re-push, because the
// Agent decided and executed on its own and its result is already queued in the
// outbox the session is about to drain.
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

	// Delete trace hop detail only for reports whose every referencing incident is
	// now resolved-and-expired — never for one still referenced by a live incident,
	// since a report can be shared by several.
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM trace_hops WHERE report_id IN (
			SELECT tr.id FROM trace_reports tr
			WHERE EXISTS(SELECT 1 FROM trace_report_refs r WHERE r.report_id=tr.id)
			  AND NOT EXISTS(
				SELECT 1 FROM trace_report_refs r JOIN incidents i ON i.id=r.incident_id
				WHERE r.report_id=tr.id AND NOT (i.state='resolved' AND i.evidence_expired=1)))`); err != nil {
		return err
	}

	// A report that never found its fault — the Agent's streak crossed its
	// threshold but the rounds recovered before this server's profile confirmed
	// anything — can gain a reference only inside claimWindow. Past that it is
	// unreachable from every read path (all incident-scoped), so age it out
	// whole; the hops go with it via ON DELETE CASCADE.
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM trace_reports
		WHERE received_at < ?
		  AND NOT EXISTS(SELECT 1 FROM trace_report_refs r WHERE r.report_id=trace_reports.id)`,
		time.Now().UTC().Add(-unreferencedTraceRetention)); err != nil {
		return err
	}
	return nil
}
