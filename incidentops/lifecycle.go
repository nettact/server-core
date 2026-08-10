package incidentops

import (
	"context"
	"time"
)

// Recover restores in-flight state after a restart: it reconciles active trace
// references against alert state. It spawns no goroutine — the server calls it
// once during startup.
//
// Neither kind of agent evidence needs its COLLECTION recovered: the traceroute
// and the scene are decided, executed and delivered by the agent through its
// outbox, so a server that was down while one was produced finds it waiting in
// the next packet rather than a half-finished lifecycle of its own. What does
// need recovering is the bookkeeping — a reference left active by an alert that
// resolved unobserved, and a scene whose one post-commit chance to be claimed
// was missed.
func (s *Service) Recover(ctx context.Context) error {
	if err := s.reconcileTraceRefs(ctx); err != nil {
		return err
	}
	return s.ReconcileSceneClaims(ctx)
}

// Tick is the callable periodic maintenance pass (the server drives it on a
// timer): reconcile active trace references against alert state, and file any
// scene still waiting for the fault that owns it. Idempotent and cheap when
// there is nothing to do.
func (s *Service) Tick(ctx context.Context) error {
	if err := s.reconcileTraceRefs(ctx); err != nil {
		return err
	}
	return s.ReconcileSceneClaims(ctx)
}

// reconcileTraceRefs durably deactivates any trace reference whose alert is no
// longer firing. It is the crash/missed-callback safety net for the post-commit
// OnSignalResolved deactivation (which runs in a separate transaction and whose
// error the eventbus swallows): if that handler never ran, the reference would
// stay active=1 forever and a resolved fault would keep counting its old trace
// as live evidence. Idempotent.
//
// Scene references need no counterpart: they carry no active flag, because a
// scene feeds no attribution recompute and reads the same after resolution as it
// did before (see the scene_report_refs comment in the schema).
func (s *Service) reconcileTraceRefs(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE trace_report_refs SET active=0
		WHERE active=1
		  AND signal_id NOT IN (SELECT id FROM fault_signals WHERE state='firing')`)
	return err
}

// ---- retention ----

// Retention deletes agent-collected evidence detail for incidents resolved longer
// than the evidence-retention window, preserving the incident/alert/evidence
// summaries and marking the incident evidence_expired. Open incidents are never
// touched. Scene payloads and trace hops are deleted only when it is safe across
// all shared references — every incident still referencing the report is itself
// resolved-and-expired — so a report shared with a still-live incident is
// preserved. Idempotent; the server drives it hourly.
func (s *Service) Retention(ctx context.Context) error {
	days := s.retentionDays(ctx)
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	if _, err := s.db.ExecContext(ctx,
		`UPDATE incidents SET evidence_expired=1
		 WHERE state='resolved' AND evidence_expired=0 AND resolved_at IS NOT NULL AND resolved_at < ?`,
		cutoff); err != nil {
		return err
	}

	// Clear scene payloads whose every referencing incident is now
	// resolved-and-expired. The row itself stays: its triggers and timestamps are
	// what let a reader see that a scene WAS collected for this fault and has since
	// aged out, which an absent row cannot say. The truncated flag is deliberately
	// left alone — it means "shed to fit the size cap", and the incident's own
	// evidence_expired already says why this body is gone.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE scene_reports SET payload=''
		WHERE payload<>'' AND id IN (
			SELECT sr.id FROM scene_reports sr
			WHERE EXISTS(SELECT 1 FROM scene_report_refs r WHERE r.report_id=sr.id)
			  AND NOT EXISTS(
				SELECT 1 FROM scene_report_refs r JOIN incidents i ON i.id=r.incident_id
				WHERE r.report_id=sr.id AND NOT (i.state='resolved' AND i.evidence_expired=1)))`); err != nil {
		return err
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

	// A report that never found its fault — the agent's streak crossed its
	// threshold but the rounds recovered before this server's profile confirmed
	// anything, or its session blipped without the sweeper ever noticing — can gain
	// a reference only inside claimWindow. Past that it is unreachable from every
	// read path (all incident-scoped), so age it out whole; the hops and scene
	// triggers go with it via ON DELETE CASCADE.
	unreferenced := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM trace_reports
		WHERE received_at < ?
		  AND NOT EXISTS(SELECT 1 FROM trace_report_refs r WHERE r.report_id=trace_reports.id)`,
		unreferenced.Add(-unreferencedTraceRetention)); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM scene_reports
		WHERE received_at < ?
		  AND NOT EXISTS(SELECT 1 FROM scene_report_refs r WHERE r.report_id=scene_reports.id)`,
		unreferenced.Add(-unreferencedSceneRetention)); err != nil {
		return err
	}
	return nil
}
