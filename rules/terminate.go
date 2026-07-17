package rules

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/config"
)

// firingRow is one firing alert selected for configuration-change termination.
type firingRow struct {
	id, ruleID, agentID, siteID, groupID, layer, severity, incidentID string
}

// TerminateForTargetsTx force-resolves (configuration_changed) the firing alerts
// of every rule referencing one of the given targets, INSIDE the caller's open
// write transaction. It returns the distinct target ids whose alerts closed (for
// the caller's status event) and a post-commit publisher the tx owner MUST invoke
// after a successful commit and discard on rollback. Implements the config-defined
// config.AlertTerminator contract; cycle-free because config never imports rules.
func (s *Service) TerminateForTargetsTx(ctx context.Context, tx *sql.Tx, targetIDs []string) ([]string, config.PostCommit, error) {
	if len(targetIDs) == 0 {
		return nil, nil, nil
	}
	args := make([]any, len(targetIDs))
	for i, id := range targetIDs {
		args[i] = id
	}
	where := `a.rule_id IN (SELECT DISTINCT rule_id FROM group_rule_conditions WHERE target_id IN (` +
		placeholders(len(targetIDs)) + `))`
	return s.terminateTx(ctx, tx, alert.ReasonConfigChanged, where, args...)
}

// TerminateForGroupTx force-resolves the firing alerts of every rule in a monitor
// group inside the caller's open write transaction (used when a group is deleted
// or its merge policy flips). Same return contract as TerminateForTargetsTx.
func (s *Service) TerminateForGroupTx(ctx context.Context, tx *sql.Tx, groupID string) ([]string, config.PostCommit, error) {
	return s.terminateTx(ctx, tx, alert.ReasonConfigChanged, `a.group_id = ?`, groupID)
}

// terminateForRuleTx force-resolves one rule's firing alerts inside the caller's
// open write tx, returning only the post-commit publisher (the rule's own target
// ids are known to the rule-CRUD caller). Used by the in-package rule-CRUD
// consolidation so termination and the rule mutation share one commit.
func (s *Service) terminateForRuleTx(ctx context.Context, tx *sql.Tx, ruleID string) (config.PostCommit, error) {
	_, pub, err := s.terminateTx(ctx, tx, alert.ReasonConfigChanged, `a.rule_id = ?`, ruleID)
	return pub, err
}

// TerminateForAgent force-resolves the firing alerts detected by one agent (used
// when the agent is deleted).
func (s *Service) TerminateForAgent(ctx context.Context, agentID string) error {
	return s.terminate(ctx, alert.ReasonConfigChanged, `a.agent_id = ?`, agentID)
}

// ResolveOutOfScope force-resolves firing alerts whose detecting agent is no
// longer in their monitor group's Agent scope (all_agents=0 and the agent is in
// none of the group's referenced agent groups). It is the counterpart to the
// scope filter in evaluation: once an agent leaves scope its rules stop being
// evaluated for it, so an alert already open would otherwise never resolve. The
// termination reason is configuration_changed — a scope change, not a recovery.
// Idempotent. Call after any scope change (group scope edit, agent-group
// membership change, group deletion).
func (s *Service) ResolveOutOfScope(ctx context.Context, siteID string) error {
	where := `a.site_id = ? AND NOT EXISTS(
		SELECT 1 FROM monitor_groups mg
		WHERE mg.id = a.group_id AND (mg.all_agents=1 OR EXISTS(
			SELECT 1 FROM monitor_group_agent_groups mgag
			JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
			WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = a.agent_id)))`
	return s.terminate(ctx, alert.ReasonConfigChanged, where, siteID)
}

// terminate closes every firing alert matched by whereSQL (correlated to alerts
// alias "a") with the given resolve reason, in its OWN write transaction, then
// publishes the resulting lifecycle events and notifications post-commit. Callers
// must invoke it OUTSIDE any open write transaction (single-writer). Used by the
// autocommit termination paths (agent delete, out-of-scope resolution).
func (s *Service) terminate(ctx context.Context, reason, whereSQL string, args ...any) error {
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
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if pub != nil {
		pub(ctx)
	}
	return nil
}

// terminateTx closes every firing alert matched by whereSQL (correlated to alerts
// alias "a") with the given resolve reason, inside the caller's open write tx. It
// returns the distinct target ids whose alerts closed and a post-commit publisher
// (nil when nothing was terminated). Rows are collected before any write so no
// read cursor stays open across the closes.
func (s *Service) terminateTx(ctx context.Context, tx *sql.Tx, reason, whereSQL string, args ...any) ([]string, config.PostCommit, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, a.rule_id, a.agent_id, a.site_id, a.group_id, COALESCE(a.layer,''), a.severity, COALESCE(a.incident_id,'')
		FROM alerts a
		WHERE a.state='firing' AND (`+whereSQL+`)`, args...)
	if err != nil {
		return nil, nil, err
	}
	var list []firingRow
	for rows.Next() {
		var f firingRow
		if err := rows.Scan(&f.id, &f.ruleID, &f.agentID, &f.siteID, &f.groupID, &f.layer, &f.severity, &f.incidentID); err != nil {
			rows.Close()
			return nil, nil, err
		}
		list = append(list, f)
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
	ruleIDs := map[string]bool{}
	for _, f := range list {
		if err := s.closeAlert(ctx, tx, f.id, f.ruleID, f.agentID, f.siteID, f.groupID, f.layer, f.severity, f.incidentID, reason, now, out); err != nil {
			return nil, nil, err
		}
		if f.ruleID != "" {
			ruleIDs[f.ruleID] = true
		}
	}
	targetIDs, err := terminatedTargets(ctx, tx, ruleIDs)
	if err != nil {
		return nil, nil, err
	}
	pub := config.PostCommit(func(ctx context.Context) { s.publishAndNotify(ctx, out) })
	return targetIDs, pub, nil
}

// terminatedTargets returns the distinct target ids referenced by the conditions
// of the given (just-terminated) rules — the targets whose current rule state
// changed, for the caller's precise status event.
func terminatedTargets(ctx context.Context, tx *sql.Tx, ruleIDs map[string]bool) ([]string, error) {
	if len(ruleIDs) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(ruleIDs))
	for id := range ruleIDs {
		args = append(args, id)
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT target_id FROM group_rule_conditions WHERE rule_id IN (`+placeholders(len(args))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// placeholders returns "?,?,…" with n placeholders.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
