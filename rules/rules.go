// Package rules is the deterministic threshold engine (architecture §9 layer 1:
// rule-based diagnosis before any AI). Rules are now bound to a specific
// monitoring target (probe_task) rather than matched by glob, and trigger after
// a configurable number of CONSECUTIVE failures. A rule with is_template=1 is a
// reusable preset (not evaluated) that can be applied onto a target.
package rules

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
)

type Rule struct {
	ID            string   `json:"id"`
	ProbeTaskID   string   `json:"probe_task_id"` // bound target ("" for templates)
	Name          string   `json:"name"`
	MetricKind    string   `json:"metric_kind"`
	Comparator    string   `json:"comparator"` // gt|gte|lt|lte|eq
	Threshold     float64  `json:"threshold"`
	FailThreshold int      `json:"fail_threshold"` // consecutive failures before firing
	ForSeconds    int      `json:"for_seconds"`
	Layer         string   `json:"layer"`
	Severity      string   `json:"severity"`
	ChannelIDs    []string `json:"channel_ids"`
	IsTemplate    bool     `json:"is_template"`
	Enabled       bool     `json:"enabled"`
}

type Service struct {
	db      *store.DB
	alerts  *alert.Service
	metrics *metrics.Store
}

func New(db *store.DB, alerts *alert.Service, m *metrics.Store) *Service {
	return &Service{db: db, alerts: alerts, metrics: m}
}

// SeedDefaults installs the standard §4 layered rules as reusable TEMPLATES for
// a site if it has none, so operators can quickly apply them onto targets.
func (s *Service) SeedDefaults(ctx context.Context, siteID string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_rules WHERE is_template=1`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	defaults := []Rule{
		{Name: "网关不可达", MetricKind: "probe.icmp.loss_pct", Comparator: "gte", Threshold: 50, FailThreshold: 3, Layer: "lan", Severity: "error"},
		{Name: "公网目标不可达", MetricKind: "probe.icmp.loss_pct", Comparator: "gte", Threshold: 50, FailThreshold: 3, Layer: "internet", Severity: "error"},
		{Name: "DNS 解析失败", MetricKind: "probe.dns.ok", Comparator: "lt", Threshold: 1, FailThreshold: 2, Layer: "dns", Severity: "warn"},
		{Name: "HTTP 检测失败", MetricKind: "probe.http.ok", Comparator: "lt", Threshold: 1, FailThreshold: 2, Layer: "service", Severity: "warn"},
	}
	for _, r := range defaults {
		if _, err := s.insert(ctx, siteID, r, "", true); err != nil {
			return err
		}
	}
	return nil
}

// insert writes a rule row (template or live). probeTaskID is "" for templates.
func (s *Service) insert(ctx context.Context, siteID string, r Rule, probeTaskID string, isTemplate bool) (string, error) {
	id := "rule_" + uuid.NewString()
	if r.FailThreshold < 1 {
		r.FailThreshold = 1
	}
	chans, _ := json.Marshal(r.ChannelIDs)
	tmpl, pt := 0, any(nil)
	if isTemplate {
		tmpl = 1
	} else {
		pt = probeTaskID
	}
	en := 1
	if !r.Enabled && !isTemplate {
		en = 0
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_rules(id, site_id, probe_task_id, name, metric_kind, comparator, threshold,
		                        fail_threshold, for_seconds, layer, severity, channel_ids, is_template, enabled)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, siteID, pt, r.Name, r.MetricKind, r.Comparator, r.Threshold,
		r.FailThreshold, r.ForSeconds, r.Layer, r.Severity, string(chans), tmpl, en)
	return id, err
}

func scanRule(rows *sql.Rows) (Rule, error) {
	var r Rule
	var probeTask, chans string
	var isTemplate, enabled int
	if err := rows.Scan(&r.ID, &probeTask, &r.Name, &r.MetricKind, &r.Comparator, &r.Threshold,
		&r.FailThreshold, &r.ForSeconds, &r.Layer, &r.Severity, &chans, &isTemplate, &enabled); err != nil {
		return Rule{}, err
	}
	r.ProbeTaskID = probeTask
	if chans != "" {
		_ = json.Unmarshal([]byte(chans), &r.ChannelIDs)
	}
	r.IsTemplate = isTemplate == 1
	r.Enabled = enabled == 1
	return r, nil
}

const ruleCols = `id, COALESCE(probe_task_id,''), name, metric_kind, comparator, threshold,
	fail_threshold, for_seconds, COALESCE(layer,''), severity, COALESCE(channel_ids,''), is_template, enabled`

// ListTemplates returns the reusable rule presets.
func (s *Service) ListTemplates(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ruleCols+` FROM alert_rules WHERE is_template=1 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRules(rows)
}

// ListForTarget returns the live alarm rules bound to a probe_task.
func (s *Service) ListForTarget(ctx context.Context, probeTaskID string) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+ruleCols+` FROM alert_rules WHERE is_template=0 AND probe_task_id=? ORDER BY name`, probeTaskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRules(rows)
}

func collectRules(rows *sql.Rows) ([]Rule, error) {
	var out []Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateTemplate stores a new reusable preset.
func (s *Service) CreateTemplate(ctx context.Context, siteID string, r Rule) (string, error) {
	return s.insert(ctx, siteID, r, "", true)
}

// CreateForTarget stores a new live rule bound to a probe_task. New rules are
// enabled by default so they start evaluating immediately.
func (s *Service) CreateForTarget(ctx context.Context, siteID, probeTaskID string, r Rule) (string, error) {
	r.Enabled = true
	return s.insert(ctx, siteID, r, probeTaskID, false)
}

// ApplyTemplate copies a template's fields into a new live rule on a target.
func (s *Service) ApplyTemplate(ctx context.Context, templateID, probeTaskID string) (string, error) {
	var siteID string
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(site_id,''), `+ruleCols+` FROM alert_rules WHERE id=? AND is_template=1`, templateID)
	var r Rule
	var probeTask, chans string
	var isTemplate, enabled int
	if err := row.Scan(&siteID, &r.ID, &probeTask, &r.Name, &r.MetricKind, &r.Comparator, &r.Threshold,
		&r.FailThreshold, &r.ForSeconds, &r.Layer, &r.Severity, &chans, &isTemplate, &enabled); err != nil {
		return "", err
	}
	if chans != "" {
		_ = json.Unmarshal([]byte(chans), &r.ChannelIDs)
	}
	r.Enabled = true
	return s.insert(ctx, siteID, r, probeTaskID, false)
}

// Update edits a rule's fields (works for both templates and live rules).
func (s *Service) Update(ctx context.Context, r Rule) error {
	if r.FailThreshold < 1 {
		r.FailThreshold = 1
	}
	chans, _ := json.Marshal(r.ChannelIDs)
	en := 0
	if r.Enabled {
		en = 1
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE alert_rules SET name=?, metric_kind=?, comparator=?, threshold=?, fail_threshold=?,
		       for_seconds=?, layer=?, severity=?, channel_ids=?, enabled=? WHERE id=?`,
		r.Name, r.MetricKind, r.Comparator, r.Threshold, r.FailThreshold,
		r.ForSeconds, r.Layer, r.Severity, string(chans), en, r.ID)
	return err
}

// SetEnabled toggles a rule.
func (s *Service) SetEnabled(ctx context.Context, id string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE alert_rules SET enabled=? WHERE id=?`, v, id)
	return err
}

// Delete removes a rule (template or live). Any alerts it produced are cleared
// first — alerts.rule_id references alert_rules(id) with foreign keys ON, so a
// bare rule delete would fail once the rule has ever fired.
func (s *Service) Delete(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE rule_id=?`, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM alert_rules WHERE id=?`, id)
	return err
}

// liveRule is a live rule joined with its bound target string, for evaluation.
type liveRule struct {
	Rule
	Target string
}

// EvaluateAgent runs the site's live (per-target) rules against this agent's
// latest metric for the bound target and updates alert state. Called on each
// telemetry.ingested event.
func (s *Service) EvaluateAgent(ctx context.Context, agentID, siteID string) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.name, r.metric_kind, r.comparator, r.threshold, r.fail_threshold, r.for_seconds,
		       COALESCE(r.layer,''), r.severity, COALESCE(p.target,'')
		FROM alert_rules r JOIN probe_tasks p ON p.id = r.probe_task_id
		WHERE r.is_template=0 AND r.enabled=1 AND p.site_id=?`, siteID)
	if err != nil {
		return err
	}
	var live []liveRule
	for rows.Next() {
		var lr liveRule
		if err := rows.Scan(&lr.ID, &lr.Name, &lr.MetricKind, &lr.Comparator, &lr.Threshold,
			&lr.FailThreshold, &lr.ForSeconds, &lr.Layer, &lr.Severity, &lr.Target); err != nil {
			rows.Close()
			return err
		}
		live = append(live, lr)
	}
	rows.Close()

	sinceUnix := time.Now().Add(-5 * time.Minute).Unix()
	for _, r := range live {
		if r.Target == "" {
			continue
		}
		found, err := s.metrics.LatestPerSeries(ctx, agentID, r.MetricKind, r.Target, sinceUnix)
		if err != nil {
			return err
		}
		rv := alert.RuleView{ID: r.ID, Name: r.Name, Layer: r.Layer, Severity: r.Severity,
			ForSeconds: r.ForSeconds, FailThreshold: r.FailThreshold}
		for _, f := range found {
			if err := s.alerts.Update(ctx, rv, agentID, siteID, f.Target, compare(f.Value, r.Comparator, r.Threshold), f.Value); err != nil {
				return err
			}
		}
	}
	return nil
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

// ErrNotFound is returned when a rule/template lookup misses.
var ErrNotFound = errors.New("rule not found")
