package rules

import (
	"context"
	"strings"
	"time"

	"github.com/nettact/server-core/alert"
)

// firingRow is one firing alert selected for configuration-change termination.
type firingRow struct {
	id, ruleID, agentID, siteID, groupID, layer, severity, incidentID string
}

// TerminateForRule force-resolves the firing alerts of one rule as a
// configuration change, closing their incidents through the shared close path.
func (s *Service) TerminateForRule(ctx context.Context, ruleID string) error {
	return s.terminate(ctx, alert.ReasonConfigChanged, `a.rule_id = ?`, ruleID)
}

// TerminateForGroup force-resolves the firing alerts of every rule in a monitor
// group (used when a custom group is deleted).
func (s *Service) TerminateForGroup(ctx context.Context, groupID string) error {
	return s.terminate(ctx, alert.ReasonConfigChanged, `a.group_id = ?`, groupID)
}

// TerminateForTargets force-resolves the firing alerts of every rule that
// references one of the given targets (used when a target is deleted or moved out
// of its group). Satisfies config.AlertTerminator.
func (s *Service) TerminateForTargets(ctx context.Context, targetIDs []string) error {
	if len(targetIDs) == 0 {
		return nil
	}
	args := make([]any, len(targetIDs))
	for i, id := range targetIDs {
		args[i] = id
	}
	where := `a.rule_id IN (SELECT DISTINCT rule_id FROM group_rule_conditions WHERE target_id IN (` +
		placeholders(len(targetIDs)) + `))`
	return s.terminate(ctx, alert.ReasonConfigChanged, where, args...)
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
// alias "a") with the given resolve reason, in one write transaction, then
// publishes the resulting lifecycle events and notifications post-commit. Rows
// are collected before any write so no read cursor stays open across the closes.
// Callers must invoke this OUTSIDE any open write transaction (single-writer).
func (s *Service) terminate(ctx context.Context, reason, whereSQL string, args ...any) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.rule_id, a.agent_id, a.site_id, a.group_id, COALESCE(a.layer,''), a.severity, COALESCE(a.incident_id,'')
		FROM alerts a
		WHERE a.state='firing' AND (`+whereSQL+`)`, args...)
	if err != nil {
		return err
	}
	var list []firingRow
	for rows.Next() {
		var f firingRow
		if err := rows.Scan(&f.id, &f.ruleID, &f.agentID, &f.siteID, &f.groupID, &f.layer, &f.severity, &f.incidentID); err != nil {
			rows.Close()
			return err
		}
		list = append(list, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(list) == 0 {
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
	out := &txOut{}
	for _, f := range list {
		if err := s.closeAlert(ctx, tx, f.id, f.ruleID, f.agentID, f.siteID, f.groupID, f.layer, f.severity, f.incidentID, reason, now, out); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	s.publishAndNotify(ctx, out)
	return nil
}

// placeholders returns "?,?,…" with n placeholders.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
