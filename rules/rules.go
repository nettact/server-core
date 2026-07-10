// Package rules is the deterministic threshold engine (architecture §9 layer 1:
// rule-based diagnosis before any AI). On each telemetry ingest it evaluates the
// site's rules against the latest metric per matching target and drives the
// alert lifecycle. Rules carry a HealthLayer so the incident correlator can run
// the §4 layered diagnosis.
package rules

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/store"
)

type Rule struct {
	ID         string  `json:"id"`
	SiteID     string  `json:"site_id"`
	Name       string  `json:"name"`
	MetricKind string  `json:"metric_kind"`
	TargetGlob string  `json:"target_glob"`
	Comparator string  `json:"comparator"` // gt|gte|lt|lte|eq
	Threshold  float64 `json:"threshold"`
	ForSeconds int     `json:"for_seconds"`
	Layer      string  `json:"layer"`
	Severity   string  `json:"severity"`
	Enabled    bool    `json:"enabled"`
}

type Service struct {
	db     *store.DB
	alerts *alert.Service
}

func New(db *store.DB, alerts *alert.Service) *Service {
	return &Service{db: db, alerts: alerts}
}

// SeedDefaults installs the standard §4 layered rules for a site if it has none.
func (s *Service) SeedDefaults(ctx context.Context, siteID string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_rules WHERE site_id=?`, siteID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	defaults := []Rule{
		{Name: "网关不可达", MetricKind: "probe.icmp.loss_pct", TargetGlob: "gateway", Comparator: "gte", Threshold: 50, Layer: "lan", Severity: "error"},
		{Name: "公网目标不可达", MetricKind: "probe.icmp.loss_pct", TargetGlob: "*.*.*.*", Comparator: "gte", Threshold: 50, Layer: "internet", Severity: "error"},
		{Name: "DNS 解析失败", MetricKind: "probe.dns.ok", TargetGlob: "*", Comparator: "lt", Threshold: 1, Layer: "dns", Severity: "warn"},
		{Name: "HTTP 检测失败", MetricKind: "probe.http.ok", TargetGlob: "*", Comparator: "lt", Threshold: 1, Layer: "service", Severity: "warn"},
	}
	for _, r := range defaults {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO alert_rules(id, site_id, name, metric_kind, target_glob, comparator, threshold, for_seconds, layer, severity, enabled)
			VALUES(?,?,?,?,?,?,?,0,?,?,1)`,
			"rule_"+uuid.NewString(), siteID, r.Name, r.MetricKind, r.TargetGlob, r.Comparator, r.Threshold, r.Layer, r.Severity); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) List(ctx context.Context, siteID string) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(site_id,''), name, metric_kind, COALESCE(target_glob,''), comparator, threshold,
		       for_seconds, COALESCE(layer,''), severity, enabled
		FROM alert_rules WHERE site_id=? ORDER BY name`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var enabled int
		if err := rows.Scan(&r.ID, &r.SiteID, &r.Name, &r.MetricKind, &r.TargetGlob, &r.Comparator,
			&r.Threshold, &r.ForSeconds, &r.Layer, &r.Severity, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	return out, rows.Err()
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

// UpdateThreshold edits a rule's threshold/comparator/for_seconds.
func (s *Service) UpdateThreshold(ctx context.Context, id, comparator string, threshold float64, forSeconds int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE alert_rules SET comparator=?, threshold=?, for_seconds=? WHERE id=?`, comparator, threshold, forSeconds, id)
	return err
}

// EvaluateAgent runs all of the site's enabled rules against this agent's latest
// metrics and updates alert state. Called on each telemetry.ingested event.
func (s *Service) EvaluateAgent(ctx context.Context, agentID, siteID string) error {
	rs, err := s.List(ctx, siteID)
	if err != nil {
		return err
	}
	since := time.Now().UTC().Add(-5 * time.Minute)
	for _, r := range rs {
		if !r.Enabled {
			continue
		}
		// latest value per matching target (SQLite: bare columns follow MAX(ts))
		rows, err := s.db.QueryContext(ctx, `
			SELECT target, value, MAX(ts) FROM metrics
			WHERE agent_id=? AND kind=? AND target GLOB ? AND ts > ?
			GROUP BY target`, agentID, r.MetricKind, r.TargetGlob, since)
		if err != nil {
			return err
		}
		type tv struct {
			target string
			value  float64
		}
		var found []tv
		for rows.Next() {
			var target string
			var value float64
			var maxTS string // MAX(ts) returns a string from the driver; unused
			if err := rows.Scan(&target, &value, &maxTS); err != nil {
				rows.Close()
				return err
			}
			found = append(found, tv{target, value})
		}
		rows.Close()

		rv := alert.RuleView{ID: r.ID, Name: r.Name, Layer: r.Layer, Severity: r.Severity, ForSeconds: r.ForSeconds}
		for _, f := range found {
			if err := s.alerts.Update(ctx, rv, agentID, siteID, f.target, compare(f.value, r.Comparator, r.Threshold), f.value); err != nil {
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
