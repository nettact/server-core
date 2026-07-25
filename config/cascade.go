package config

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"

	"github.com/nettact/protocol/telemetry"
)

// ErrDefaultGroup is returned when a caller tries to delete a site's undeletable
// default monitor group.
var ErrDefaultGroup = errors.New("default monitor group cannot be deleted")

// ErrDuplicateTargetID reports a submitted target set that names one id twice.
// It is a malformed REQUEST, not a server fault, so the API layer matches it with
// errors.Is and answers 400 — a 500 would invite clients to retry a payload that
// can never succeed.
var ErrDuplicateTargetID = errors.New("duplicate target id in the submitted set")

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

// retypedTarget is a kept target whose probe kind changed in place, paired with
// the kind it used to be so the reconcile can report what was dropped and why.
type retypedTarget struct {
	target  ProbeTarget
	oldKind string
}

// RuleCleanup reports alert conditions removed because their target's probe kind
// changed and the new kind can never emit the metric they watch. It is surfaced
// on the save response so the console can tell the user which alarms they must
// reconfigure — a silently-dropped condition would leave a monitor that fails
// forever without ever raising an alert.
type RuleCleanup struct {
	MonitorID   string   `json:"monitor_id"`
	MonitorName string   `json:"monitor_name"`
	OldKind     string   `json:"old_kind"`
	NewKind     string   `json:"new_kind"`
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Metrics     []string `json:"metrics"`      // the dropped conditions' metric kinds
	RuleDeleted bool     `json:"rule_deleted"` // the rule lost its last condition and was removed whole
}

// cleanupKey identifies one (re-typed target, rule) pair: all of a rule's stale
// conditions for one target collapse into a single RuleCleanup entry.
type cleanupKey struct{ targetID, ruleID string }

// dropStaleConditions removes the alert conditions of re-typed targets that the
// target's NEW kind can no longer satisfy, and deletes whole any rule left with
// no conditions at all. Without this the condition survives pointing at a metric
// family that will never arrive again; the engine treats "no sample this pass" as
// "keep the stored verdict", so the rule freezes at not-satisfied and the monitor
// can fail indefinitely without alerting.
//
// Firing alerts need no handling here: a kind change is a material change, so the
// caller has already force-resolved them (configuration_changed) in this same tx.
func dropStaleConditions(ctx context.Context, tx txExec, changed map[string]retypedTarget) ([]RuleCleanup, error) {
	if len(changed) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(changed))
	for id := range changed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT c.id, c.rule_id, c.target_id, c.metric_kind, COALESCE(r.name,'')
		FROM group_rule_conditions c JOIN group_rules r ON r.id=c.rule_id
		WHERE c.target_id IN (`+placeholders(len(ids))+`)
		ORDER BY c.target_id, c.rule_id, c.position, c.id`, args...)
	if err != nil {
		return nil, err
	}
	var order []cleanupKey
	byKey := map[cleanupKey]*RuleCleanup{}
	var staleIDs []string
	err = func() error {
		defer rows.Close()
		for rows.Next() {
			var condID, ruleID, targetID, metricKind, ruleName string
			if err := rows.Scan(&condID, &ruleID, &targetID, &metricKind, &ruleName); err != nil {
				return err
			}
			rt := changed[targetID]
			if telemetry.MetricAllowedForProbeKind(rt.target.Kind, metricKind) {
				continue // the new kind still emits this metric — the condition stays live
			}
			staleIDs = append(staleIDs, condID)
			k := cleanupKey{targetID: targetID, ruleID: ruleID}
			cl, ok := byKey[k]
			if !ok {
				cl = &RuleCleanup{
					MonitorID: targetID, MonitorName: rt.target.Name,
					OldKind: rt.oldKind, NewKind: rt.target.Kind,
					RuleID: ruleID, RuleName: ruleName,
				}
				byKey[k] = cl
				order = append(order, k)
			}
			cl.Metrics = append(cl.Metrics, metricKind)
		}
		return rows.Err()
	}()
	if err != nil {
		return nil, err
	}
	if len(staleIDs) == 0 {
		return nil, nil
	}

	delArgs := make([]any, len(staleIDs))
	for i, id := range staleIDs {
		delArgs[i] = id
	}
	// rule_condition_state rows follow via ON DELETE CASCADE (migration 0013).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM group_rule_conditions WHERE id IN (`+placeholders(len(staleIDs))+`)`, delArgs...); err != nil {
		return nil, err
	}

	// A rule whose last condition was just dropped can never evaluate again; remove
	// it whole rather than leaving an empty rule that silently never fires.
	emptied, err := emptyRuleIDs(ctx, tx, byKey)
	if err != nil {
		return nil, err
	}
	if err := deleteRulesCascade(ctx, tx, emptied); err != nil {
		return nil, err
	}
	gone := map[string]bool{}
	for _, id := range emptied {
		gone[id] = true
	}
	out := make([]RuleCleanup, 0, len(order))
	for _, k := range order {
		cl := byKey[k]
		cl.RuleDeleted = gone[cl.RuleID]
		out = append(out, *cl)
	}
	return out, nil
}

// emptyRuleIDs returns, among the rules touched by a condition drop, those that
// have no conditions left.
func emptyRuleIDs(ctx context.Context, tx txExec, touched map[cleanupKey]*RuleCleanup) ([]string, error) {
	seen := map[string]bool{}
	var ruleIDs []string
	for k := range touched {
		if seen[k.ruleID] {
			continue
		}
		seen[k.ruleID] = true
		ruleIDs = append(ruleIDs, k.ruleID)
	}
	if len(ruleIDs) == 0 {
		return nil, nil
	}
	sort.Strings(ruleIDs)
	args := make([]any, len(ruleIDs))
	for i, id := range ruleIDs {
		args[i] = id
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT r.id FROM group_rules r
		WHERE r.id IN (`+placeholders(len(ruleIDs))+`)
		  AND NOT EXISTS (SELECT 1 FROM group_rule_conditions c WHERE c.rule_id=r.id)
		ORDER BY r.id`, args...)
	if err != nil {
		return nil, err
	}
	return scanIDs(rows)
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
