package config

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// ErrDefaultGroup is returned when a caller tries to delete a site's undeletable
// default monitor group.
var ErrDefaultGroup = errors.New("default monitor group cannot be deleted")

// txExec is the subset of *sql.Tx used by the shared rule-cascade helpers, so
// they can run inside any caller's write transaction.
type txExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// groupRuleIDs returns every group rule owned by a monitor group.
func groupRuleIDs(ctx context.Context, tx txExec, groupID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM group_rules WHERE group_id=?`, groupID)
	if err != nil {
		return nil, err
	}
	return scanIDs(rows)
}

// rulesReferencingTargets returns the distinct rule ids that have any condition
// referencing one of the given targets. These rules are removed whole when a
// target they reference is deleted or moved out of the group.
func rulesReferencingTargets(ctx context.Context, tx txExec, targetIDs []string) ([]string, error) {
	if len(targetIDs) == 0 {
		return nil, nil
	}
	args := make([]any, len(targetIDs))
	for i, id := range targetIDs {
		args[i] = id
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT rule_id FROM group_rule_conditions WHERE target_id IN (`+placeholders(len(targetIDs))+`)`, args...)
	if err != nil {
		return nil, err
	}
	return scanIDs(rows)
}

// deleteRulesCascade removes the given group rules and everything that hangs off
// them. group_rule_conditions (with their rule_condition_state) cascade on the
// rule delete; alerts.rule_id is ON DELETE SET NULL, so resolved alert rows and
// their alert_evidence are preserved structurally as immutable history (their
// frozen rule_name/group_name carry the display facts once the reference nulls
// out). The caller force-resolves the firing alerts (configuration_changed)
// beforehand, so no firing alert is ever left with a null rule_id. Incidents and
// their timelines are likewise left intact as history.
func deleteRulesCascade(ctx context.Context, tx txExec, ruleIDs []string) error {
	if len(ruleIDs) == 0 {
		return nil
	}
	args := make([]any, len(ruleIDs))
	for i, id := range ruleIDs {
		args[i] = id
	}
	in := placeholders(len(ruleIDs))
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_rules WHERE id IN (`+in+`)`, args...); err != nil {
		return err
	}
	return nil
}

func scanIDs(rows *sql.Rows) ([]string, error) {
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

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
