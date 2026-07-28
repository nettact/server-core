package fault

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// postCommit is a publisher the transaction owner invokes after a successful
// commit and discards on rollback. It is an alias of the same underlying func
// type as config.PostCommit, which is how this package satisfies
// config.FaultTerminator without importing config (config imports fault for the
// detector-sensitivity type, so the dependency has to stay one-way).
type postCommit = func(ctx context.Context)

// The termination paths force-resolve firing signals whose subject stopped being
// what it was — the target was deleted, disabled, materially reconfigured, or
// moved out of an Agent's scope. Every one of them carries a reason distinct from
// "recovered", because a configuration change is not the fault going away: it is
// the fault becoming unobservable. The distinction is what stops the product from
// sending a false "recovered" notification when the operator deletes a monitor
// that was failing, and what keeps the recorded history honest about why a fault
// ended.
//
// Terminating also clears the detector counters for the affected pairs: a streak
// measured against the old configuration must not carry into the new one.

// TerminateForTargetsTx force-resolves the firing signals of the given targets
// inside the caller's open write transaction, with the given reason. It returns
// the distinct target ids whose signals closed (for the caller's status event)
// and a post-commit publisher the tx owner MUST invoke after a successful commit
// and discard on rollback. Implements config.FaultTerminator.
func (s *Service) TerminateForTargetsTx(ctx context.Context, tx *sql.Tx, targetIDs []string, reason string) ([]string, postCommit, error) {
	if len(targetIDs) == 0 {
		return nil, nil, nil
	}
	args := make([]any, len(targetIDs))
	for i, id := range targetIDs {
		args[i] = id
	}
	in := placeholders(len(targetIDs))
	ids, pub, err := s.terminateTx(ctx, tx, reason, `target_id IN (`+in+`)`, args...)
	if err != nil {
		return nil, nil, err
	}
	// Counters are per (target, agent): drop them all so the next round starts a
	// fresh streak under the new configuration.
	if _, err := tx.ExecContext(ctx, `DELETE FROM detector_state WHERE target_id IN (`+in+`)`, args...); err != nil {
		return nil, nil, err
	}
	return ids, pub, nil
}

// TerminateForGroupTx force-resolves the firing signals of every target in a
// monitor group (group deletion or merge-policy flip, which changes the incident
// grouping identity). Same contract as TerminateForTargetsTx.
func (s *Service) TerminateForGroupTx(ctx context.Context, tx *sql.Tx, groupID string) ([]string, postCommit, error) {
	ids, pub, err := s.terminateTx(ctx, tx, ReasonConfigChanged, `group_id = ?`, groupID)
	if err != nil {
		return nil, nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM detector_state WHERE target_id IN (SELECT id FROM probe_tasks WHERE group_id=?)`, groupID); err != nil {
		return nil, nil, err
	}
	return ids, pub, nil
}

// TerminateForAgent force-resolves every signal detected by one agent, in its own
// transaction. Used when the agent is deleted.
func (s *Service) TerminateForAgent(ctx context.Context, agentID string) error {
	return s.terminate(ctx, ReasonAgentDeleted, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM detector_state WHERE agent_id=?`, agentID)
		return err
	}, `agent_id = ?`, agentID)
}

// ResolveOutOfScope force-resolves firing signals whose detecting agent is no
// longer in their monitor group's Agent scope. It is the counterpart to the scope
// filter in evaluation: once an agent leaves scope its targets stop being
// evaluated for it, so a signal already open would otherwise never resolve.
// Idempotent; call after any scope change.
func (s *Service) ResolveOutOfScope(ctx context.Context, siteID string) error {
	where := `site_id = ? AND target_id <> '' AND NOT EXISTS(
		SELECT 1 FROM probe_tasks pt
		JOIN monitor_groups mg ON mg.id = pt.group_id
		WHERE pt.id = fault_signals.target_id AND (mg.all_agents=1 OR EXISTS(
			SELECT 1 FROM monitor_group_agent_groups mgag
			JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
			WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = fault_signals.agent_id)))`
	return s.terminate(ctx, ReasonAgentScopeChange, nil, where, siteID)
}

// terminate closes every firing signal matched by whereSQL in its OWN write
// transaction, runs the optional extra cleanup in that same transaction, then
// publishes post-commit. Callers must invoke it OUTSIDE any open write
// transaction (SQLite has a single writer).
func (s *Service) terminate(ctx context.Context, reason string, extra func(context.Context, *sql.Tx) error, whereSQL string, args ...any) error {
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
	_, pub, err := s.terminateTx(ctx, tx, reason, whereSQL, args...)
	if err != nil {
		return err
	}
	if extra != nil {
		if err := extra(ctx, tx); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if pub != nil {
		pub(ctx)
	}
	return nil
}

// terminateTx closes every firing signal matched by whereSQL (correlated to the
// fault_signals row) inside the caller's open write tx. Rows are collected before
// any write so no read cursor stays open across the closes.
func (s *Service) terminateTx(ctx context.Context, tx *sql.Tx, reason, whereSQL string, args ...any) ([]string, postCommit, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT id, site_id, target_id FROM fault_signals WHERE state='firing' AND (`+whereSQL+`)`, args...)
	if err != nil {
		return nil, nil, err
	}
	type row struct{ id, siteID, targetID string }
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.siteID, &r.targetID); err != nil {
			rows.Close()
			return nil, nil, err
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(list) == 0 {
		return nil, nil, nil
	}

	now := time.Now().UTC()
	out := &txOut{}
	targets := make([]string, 0, len(list))
	siteID := list[0].siteID
	for _, r := range list {
		if err := s.resolveSignal(ctx, tx, r.id, reason, now, now, out); err != nil {
			return nil, nil, err
		}
		if r.targetID != "" {
			targets = append(targets, r.targetID)
		}
	}
	targets = dedupeStrings(targets)
	captured := targets
	pub := postCommit(func(ctx context.Context) {
		s.publish(out)
		s.publishTargetStatus(siteID, captured)
	})
	return targets, pub, nil
}

// ClearDetectorStateTx drops the detector counters for the given targets inside
// the caller's tx, without touching signals. Used by config paths that reset a
// target's generation without having any firing signal to terminate.
func (s *Service) ClearDetectorStateTx(ctx context.Context, tx *sql.Tx, targetIDs []string) error {
	if len(targetIDs) == 0 {
		return nil
	}
	args := make([]any, len(targetIDs))
	for i, id := range targetIDs {
		args[i] = id
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM detector_state WHERE target_id IN (`+placeholders(len(targetIDs))+`)`, args...)
	return err
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
