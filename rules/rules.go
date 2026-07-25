// Package rules is the deterministic threshold engine (architecture §9 layer 1)
// rebuilt for the group model: alerting is driven by group-level, one-layer
// AND/OR rules whose conditions each reference an in-group monitoring target.
// The package owns rule/condition CRUD and validation (this file), the
// transactional per-Agent fault engine (engine.go) that evaluates conditions,
// fires alert instances with frozen evidence and maintains group-aware
// incidents, and the configuration-change termination paths (terminate.go).
package rules

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// ErrNotFound is returned when a rule lookup misses.
var ErrNotFound = errors.New("rule not found")

// GroupRule is a group-level alert rule: a one-layer AND/OR list of conditions,
// each referencing an in-group target. It produces per-Agent alert instances.
type GroupRule struct {
	ID         string          `json:"id"`
	GroupID    string          `json:"group_id"`
	SiteID     string          `json:"site_id"`
	Name       string          `json:"name"`
	Op         string          `json:"op"` // "and" | "or"
	Layer      string          `json:"layer"`
	Severity   string          `json:"severity"`
	ChannelIDs []string        `json:"channel_ids"`
	Enabled    bool            `json:"enabled"`
	Conditions []RuleCondition `json:"conditions"`
}

// RuleCondition is one threshold test inside a group rule, bound to a target in
// the rule's group.
type RuleCondition struct {
	ID            string  `json:"id"`
	RuleID        string  `json:"rule_id"`
	TargetID      string  `json:"target_id"`
	MetricKind    string  `json:"metric_kind"`
	Comparator    string  `json:"comparator"` // gt|gte|lt|lte|eq
	Threshold     float64 `json:"threshold"`
	FailThreshold int     `json:"fail_threshold"` // consecutive breaching evaluations before satisfied
	ForSeconds    int     `json:"for_seconds"`    // additional dwell gate
	Position      int     `json:"position"`
}

type Service struct {
	db       *store.DB
	metrics  *metrics.Store
	notif    *notification.Service
	settings *settings.Service
	bus      *eventbus.Bus
	snap     SnapshotWriter
}

// SnapshotWriter writes an incident's immutable base snapshot synchronously inside
// the fault engine's incident-open transaction (INCIDENT-002). It is injected
// (satisfied by *incidentops.Service) so the fault engine does not import the
// orchestration package; nil-safe, so tests and the base-write-less path degrade
// to no snapshot. A returned error is advisory — the caller logs it and lets the
// incident open regardless (a snapshot failure never blocks alert/incident
// creation).
type SnapshotWriter interface {
	WriteIncidentBase(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) error
}

// New constructs the fault engine. notif/settings/bus/snap may be nil in tests
// (notifications, post-commit publications and incident snapshots are then simply
// skipped).
func New(db *store.DB, m *metrics.Store, notif *notification.Service, set *settings.Service, bus *eventbus.Bus, snap SnapshotWriter) *Service {
	return &Service{db: db, metrics: m, notif: notif, settings: set, bus: bus, snap: snap}
}

// ---- read ----

// ListForGroup returns a monitor group's rules with their conditions.
func (s *Service) ListForGroup(ctx context.Context, groupID string) ([]GroupRule, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT id, group_id, site_id, name, op, COALESCE(layer,''), severity, COALESCE(channel_ids,'[]'), enabled
		 FROM group_rules WHERE group_id=? ORDER BY name`, groupID)
	if err != nil {
		return nil, err
	}
	out, byID, err := scanRules(rows)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	return out, s.loadConditions(ctx, byID)
}

// GetRule returns one rule with its conditions, or ErrNotFound.
func (s *Service) GetRule(ctx context.Context, ruleID string) (GroupRule, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT id, group_id, site_id, name, op, COALESCE(layer,''), severity, COALESCE(channel_ids,'[]'), enabled
		 FROM group_rules WHERE id=?`, ruleID)
	if err != nil {
		return GroupRule{}, err
	}
	out, byID, err := scanRules(rows)
	if err != nil {
		return GroupRule{}, err
	}
	if len(out) == 0 {
		return GroupRule{}, ErrNotFound
	}
	if err := s.loadConditions(ctx, byID); err != nil {
		return GroupRule{}, err
	}
	return out[0], nil
}

func scanRules(rows *sql.Rows) ([]GroupRule, map[string]*GroupRule, error) {
	defer rows.Close()
	var out []GroupRule
	for rows.Next() {
		var r GroupRule
		var chans string
		var enabled int
		if err := rows.Scan(&r.ID, &r.GroupID, &r.SiteID, &r.Name, &r.Op, &r.Layer, &r.Severity, &chans, &enabled); err != nil {
			return nil, nil, err
		}
		r.Enabled = enabled == 1
		r.ChannelIDs = []string{}
		if chans != "" {
			_ = json.Unmarshal([]byte(chans), &r.ChannelIDs)
		}
		r.Conditions = []RuleCondition{}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	byID := make(map[string]*GroupRule, len(out))
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	return out, byID, nil
}

func (s *Service) loadConditions(ctx context.Context, byID map[string]*GroupRule) error {
	ids := make([]any, 0, len(byID))
	ph := make([]byte, 0, len(byID)*2)
	for id := range byID {
		if len(ph) > 0 {
			ph = append(ph, ',')
		}
		ph = append(ph, '?')
		ids = append(ids, id)
	}
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, rule_id, target_id, metric_kind, comparator, threshold, fail_threshold, for_seconds, position
		FROM group_rule_conditions WHERE rule_id IN (`+string(ph)+`) ORDER BY position, id`, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var c RuleCondition
		if err := rows.Scan(&c.ID, &c.RuleID, &c.TargetID, &c.MetricKind, &c.Comparator,
			&c.Threshold, &c.FailThreshold, &c.ForSeconds, &c.Position); err != nil {
			return err
		}
		if r := byID[c.RuleID]; r != nil {
			r.Conditions = append(r.Conditions, c)
		}
	}
	return rows.Err()
}

// ---- write (CRUD) ----

// Create validates and stores a new group rule with its conditions, enabled by
// default so it starts evaluating on the next telemetry ingest.
func (s *Service) Create(ctx context.Context, siteID, groupID string, r GroupRule) (string, error) {
	r.SiteID = siteID
	r.GroupID = groupID
	r.Enabled = true
	if err := s.validate(ctx, r); err != nil {
		return "", err
	}
	id := "rule_" + uuid.NewString()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	chans, _ := json.Marshal(normStrings(r.ChannelIDs))
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_rules(id, group_id, site_id, name, op, layer, severity, channel_ids, enabled)
		 VALUES(?,?,?,?,?,?,?,?,1)`,
		id, groupID, siteID, r.Name, r.Op, r.Layer, defSeverity(r.Severity), string(chans)); err != nil {
		return "", err
	}
	if err := insertConditions(ctx, tx, id, r.Conditions); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	// A new rule's conditions can become currently satisfied on the next ingest and
	// its rule_name feeds the status active-condition DTOs; publish so the batch
	// status refreshes for the referenced targets. Alert/incident lifecycle is not
	// disturbed (nothing is terminated by a create).
	s.publishTargetStatus(siteID, ruleTargetIDs(r))
	return id, nil
}

// Update replaces a rule's fields and conditions. It compares the incoming rule
// against the stored one and only disturbs live alert/incident state when a
// SEMANTIC field changes — enabled state, op, layer, severity, or the condition
// set. A pure name and/or notification-channel edit is non-semantic: it is applied
// in place, leaving the rule's firing alerts, their incidents and immutable
// snapshots untouched (no termination, no re-notification, no snapshot reset). A
// semantic edit force-resolves the rule's firing alerts as a configuration change
// (outside the write tx) and replaces its conditions, so the next telemetry ingest
// re-evaluates cleanly under the new definition.
func (s *Service) Update(ctx context.Context, r GroupRule) error {
	cur, err := s.GetRule(ctx, r.ID)
	if err != nil {
		return err
	}
	r.SiteID = cur.SiteID
	r.GroupID = cur.GroupID
	if err := s.validate(ctx, r); err != nil {
		return err
	}
	if !ruleSemanticChanged(cur, r) {
		// Non-semantic edit (name and/or channels only): apply in place. Conditions
		// are unchanged, so per-condition state and frozen evidence stay intact and no
		// active incident is disturbed.
		chans, _ := json.Marshal(normStrings(r.ChannelIDs))
		if _, err := s.db.ExecContext(ctx,
			`UPDATE group_rules SET name=?, channel_ids=? WHERE id=?`, r.Name, string(chans), r.ID); err != nil {
			return err
		}
		// A rename changes the rule_name surfaced in the status active-condition DTOs
		// for any currently-satisfied condition; publish so the batch status refreshes
		// the drill-down context. Lifecycle stays untouched (non-semantic edit).
		s.publishTargetStatus(cur.SiteID, ruleTargetIDs(cur))
		return nil
	}
	// Semantic change: terminate the rule's firing alerts (configuration_changed)
	// and replace its definition in ONE write transaction, so a status reader can
	// never observe a terminated alert alongside the old condition set. The next
	// telemetry ingest re-evaluates cleanly under the new definition.
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
	pub, err := s.terminateForRuleTx(ctx, tx, r.ID)
	if err != nil {
		return err
	}
	chans, _ := json.Marshal(normStrings(r.ChannelIDs))
	if _, err := tx.ExecContext(ctx,
		`UPDATE group_rules SET name=?, op=?, layer=?, severity=?, channel_ids=?, enabled=? WHERE id=?`,
		r.Name, r.Op, r.Layer, defSeverity(r.Severity), string(chans), boolInt(r.Enabled), r.ID); err != nil {
		return err
	}
	// Replace conditions wholesale; the delete cascades their per-Agent state.
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_rule_conditions WHERE rule_id=?`, r.ID); err != nil {
		return err
	}
	if err := insertConditions(ctx, tx, r.ID, r.Conditions); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if pub != nil {
		pub(ctx)
	}
	s.publishTargetStatus(cur.SiteID, ruleTargetIDs(cur, r))
	return nil
}

// ruleTargetIDs collects the distinct condition target ids of the given rules —
// the targets whose current rule state a lifecycle change may shift, for the
// precise status event.
func ruleTargetIDs(rs ...GroupRule) []string {
	var out []string
	for _, r := range rs {
		for _, c := range r.Conditions {
			out = append(out, c.TargetID)
		}
	}
	return out
}

// ruleSemanticChanged reports whether the edit from cur→next alters fault
// semantics — enablement, operator, suspected layer, severity, or the normalized
// condition set — as opposed to a purely cosmetic name/notification-channel change.
// Severity is compared through defSeverity so an empty severity and its default are
// equal, and conditions are compared as an order-independent multiset of their
// semantic fields so reordering or re-identifying conditions is not a change.
func ruleSemanticChanged(cur, next GroupRule) bool {
	if cur.Enabled != next.Enabled ||
		cur.Op != next.Op ||
		cur.Layer != next.Layer ||
		defSeverity(cur.Severity) != defSeverity(next.Severity) {
		return true
	}
	return !sameConditionSet(cur.Conditions, next.Conditions)
}

// sameConditionSet compares two condition lists by the multiset of their semantic
// content (target, metric, comparator, threshold, normalized fail_threshold,
// for_seconds), ignoring row ids and position.
func sameConditionSet(a, b []RuleCondition) bool {
	if len(a) != len(b) {
		return false
	}
	ka, kb := conditionKeys(a), conditionKeys(b)
	if len(ka) != len(kb) {
		return false
	}
	for k, n := range ka {
		if kb[k] != n {
			return false
		}
	}
	return true
}

// conditionKeys builds the multiset of canonical semantic keys for a condition
// list. fail_threshold is normalized to its stored floor (min 1) to match
// insertConditions, so an input 0 and the stored 1 compare equal.
func conditionKeys(cs []RuleCondition) map[string]int {
	m := make(map[string]int, len(cs))
	for _, c := range cs {
		fail := c.FailThreshold
		if fail < 1 {
			fail = 1
		}
		key := fmt.Sprintf("%s|%s|%s|%g|%d|%d", c.TargetID, c.MetricKind, c.Comparator, c.Threshold, fail, c.ForSeconds)
		m[key]++
	}
	return m
}

// SetEnabled toggles a rule. Disabling terminates its active alerts as a
// configuration change in the same transaction as the flip; enabling lets the
// next ingest re-evaluate. Either way one precise status event is published.
// AddChannelToAllRules adds channelID to every group rule's channel_ids that does
// not already include it, returning how many rules were changed. This is a
// channel-only (non-semantic) edit: it applies in place without terminating any
// firing alert. Open incidents keep their frozen routing, so only future firings
// pick up the added channel.
func (s *Service) AddChannelToAllRules(ctx context.Context, channelID string) (int, error) {
	if channelID == "" {
		return 0, fmt.Errorf("channel id is empty")
	}
	rows, err := s.db.Read().QueryContext(ctx, `SELECT id, COALESCE(channel_ids,'[]') FROM group_rules`)
	if err != nil {
		return 0, err
	}
	type pending struct {
		id    string
		chans []string
	}
	var todo []pending
	for rows.Next() {
		var id, chans string
		if err := rows.Scan(&id, &chans); err != nil {
			rows.Close()
			return 0, err
		}
		var ids []string
		_ = json.Unmarshal([]byte(chans), &ids)
		if containsString(ids, channelID) {
			continue
		}
		todo = append(todo, pending{id: id, chans: append(ids, channelID)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	if len(todo) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for _, p := range todo {
		b, _ := json.Marshal(p.chans)
		if _, err := tx.ExecContext(ctx, `UPDATE group_rules SET channel_ids=? WHERE id=?`, string(b), p.id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	committed = true
	return len(todo), nil
}

func (s *Service) SetEnabled(ctx context.Context, id string, enabled bool) error {
	cur, err := s.GetRule(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !enabled {
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
		pub, err := s.terminateForRuleTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE group_rules SET enabled=0 WHERE id=?`, id); err != nil {
			return err
		}
		// Clear the rule's per-Agent condition state in the same commit as the disable.
		// Otherwise a retained satisfied=1 row survives the disable and, on re-enable,
		// is immediately read by the status query as a current breach without any fresh
		// telemetry. Evidence on the (now-resolved) alerts is untouched — this is live
		// condition state, not immutable history.
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM rule_condition_state WHERE condition_id IN (
				SELECT id FROM group_rule_conditions WHERE rule_id=?)`, id); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		if pub != nil {
			pub(ctx)
		}
		s.publishTargetStatus(cur.SiteID, ruleTargetIDs(cur))
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE group_rules SET enabled=1 WHERE id=?`, id); err != nil {
		return err
	}
	s.publishTargetStatus(cur.SiteID, ruleTargetIDs(cur))
	return nil
}

// Delete removes a rule and everything hanging off it, terminating its firing
// alerts as a configuration change in the same transaction as the delete so their
// incidents close cleanly. The resolved alert rows and their frozen evidence are
// preserved as immutable history: alerts.rule_id is ON DELETE SET NULL, so the
// reference nulls out while the frozen rule_name/group_name keep the display
// facts. Idempotent — deleting an absent rule is a no-op.
func (s *Service) Delete(ctx context.Context, id string) error {
	cur, err := s.GetRule(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
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
	pub, err := s.terminateForRuleTx(ctx, tx, id)
	if err != nil {
		return err
	}
	// The rule delete cascades its conditions and their per-Agent state and nulls
	// the rule_id of the (now-resolved) alert rows that referenced it, leaving the
	// alerts and their alert_evidence intact.
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_rules WHERE id=?`, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if pub != nil {
		pub(ctx)
	}
	s.publishTargetStatus(cur.SiteID, ruleTargetIDs(cur))
	return nil
}

func insertConditions(ctx context.Context, tx *sql.Tx, ruleID string, conds []RuleCondition) error {
	for i, c := range conds {
		fail := c.FailThreshold
		if fail < 1 {
			fail = 1
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO group_rule_conditions(id, rule_id, target_id, metric_kind, comparator, threshold, fail_threshold, for_seconds, position)
			 VALUES(?,?,?,?,?,?,?,?,?)`,
			"cond_"+uuid.NewString(), ruleID, c.TargetID, c.MetricKind, c.Comparator, c.Threshold, fail, c.ForSeconds, i); err != nil {
			return err
		}
	}
	return nil
}

// ---- validation ----

var validComparators = map[string]bool{"gt": true, "gte": true, "lt": true, "lte": true, "eq": true}

// validSeverities is the frozen severity enum the status API and its worst-severity
// aggregation rank (rules/notify.go, targetstatus.severityRank). A rule whose
// severity escapes this set could be breaching/alerting while worst_severity is
// omitted (its rank is unknown), yielding an internally inconsistent status
// response — so validation rejects anything outside it.
var validSeverities = map[string]bool{"info": true, "warn": true, "error": true, "critical": true}

// validate enforces the group-rule contract: a valid op, a non-empty condition
// list, in-group target references, target-kind/metric compatibility, valid
// comparators/bounds, and no duplicate (target, metric, comparator, threshold)
// conditions.
func (s *Service) validate(ctx context.Context, r GroupRule) error {
	if r.Op != "and" && r.Op != "or" {
		return errors.New("rule op must be 'and' or 'or'")
	}
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("rule name is required")
	}
	if !validSeverities[defSeverity(r.Severity)] {
		return fmt.Errorf("invalid severity %q (must be info, warn, error or critical)", r.Severity)
	}
	if len(r.Conditions) == 0 {
		return errors.New("a rule needs at least one condition")
	}
	// In-group targets (id → kind) the conditions may reference.
	kinds, err := s.groupTargetKinds(ctx, r.GroupID)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, c := range r.Conditions {
		kind, ok := kinds[c.TargetID]
		if !ok {
			return fmt.Errorf("condition target %q is not in this monitor group", c.TargetID)
		}
		if strings.TrimSpace(c.MetricKind) == "" {
			return errors.New("condition metric_kind is required")
		}
		if !telemetry.MetricAllowedForProbeKind(kind, c.MetricKind) {
			return fmt.Errorf("metric %q is not valid for a %q target", c.MetricKind, kind)
		}
		if !validComparators[c.Comparator] {
			return fmt.Errorf("invalid comparator %q", c.Comparator)
		}
		if math.IsNaN(c.Threshold) || math.IsInf(c.Threshold, 0) {
			return errors.New("condition threshold must be a finite number")
		}
		if c.FailThreshold < 0 || c.FailThreshold > 100000 {
			return errors.New("condition fail_threshold out of range (0-100000)")
		}
		if c.ForSeconds < 0 || c.ForSeconds > 86400 {
			return errors.New("condition for_seconds out of range (0-86400)")
		}
		key := c.TargetID + "|" + c.MetricKind + "|" + c.Comparator + "|" + fmt.Sprintf("%g", c.Threshold)
		if seen[key] {
			return errors.New("duplicate condition (same target, metric, comparator and threshold)")
		}
		seen[key] = true
	}
	return nil
}

// groupTargetKinds maps a monitor group's target ids to their probe kinds.
func (s *Service) groupTargetKinds(ctx context.Context, groupID string) (map[string]string, error) {
	rows, err := s.db.Read().QueryContext(ctx, `SELECT id, kind FROM probe_tasks WHERE group_id=?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, kind string
		if err := rows.Scan(&id, &kind); err != nil {
			return nil, err
		}
		out[id] = kind
	}
	return out, rows.Err()
}

func defSeverity(s string) string {
	if s == "" {
		return "warn"
	}
	return s
}

func normStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

func containsString(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// portFromParams extracts the TCP/target port from a probe_tasks.params JSON blob,
// frozen onto alert_evidence at fire time so traceroute derivation never re-reads
// live (possibly-edited) probe config.
func portFromParams(params string) int {
	if params == "" {
		return 0
	}
	var p pcfg.ProbeParams
	if json.Unmarshal([]byte(params), &p) != nil {
		return 0
	}
	return p.Port
}

func compare(v float64, comparator string, threshold float64) bool {
	switch comparator {
	case "gt":
		return v > threshold
	case "gte":
		return v >= threshold
	case "lt":
		return v < threshold
	case "lte":
		return v <= threshold
	case "eq":
		return v == threshold
	}
	return false
}
