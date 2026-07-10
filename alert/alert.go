// Package alert tracks the lifecycle of threshold breaches: pending → firing →
// resolved, keyed by (rule, agent, target). Firing/resolved transitions are
// published on the bus for the incident correlator to consume.
package alert

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/store"
)

// RuleView is the rule context the alert service needs (avoids importing rules).
type RuleView struct {
	ID         string
	Name       string
	Layer      string
	Severity   string
	ForSeconds int
}

// Raised is the payload published on TopicAlertRaised / TopicAlertResolved.
type Raised struct {
	ID       string
	RuleID   string
	RuleName string
	AgentID  string
	SiteID   string
	Target   string
	Layer    string
	Severity string
	Value    float64
	At       time.Time
}

// Alert is a stored alert row joined with its rule (for the UI).
type Alert struct {
	ID         string     `json:"id"`
	RuleID     string     `json:"rule_id"`
	RuleName   string     `json:"rule_name"`
	AgentID    string     `json:"agent_id"`
	SiteID     string     `json:"site_id"`
	Target     string     `json:"target"`
	Layer      string     `json:"layer"`
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	Value      float64    `json:"value"`
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

type Service struct {
	db  *store.DB
	bus *eventbus.Bus
}

func New(db *store.DB, bus *eventbus.Bus) *Service { return &Service{db: db, bus: bus} }

// Update transitions the (rule, agent, target) alert given the latest breach state.
func (s *Service) Update(ctx context.Context, rule RuleView, agentID, siteID, target string, breach bool, value float64) error {
	now := time.Now().UTC()

	var id, state string
	var startedAt time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT id, state, started_at FROM alerts
		 WHERE rule_id=? AND agent_id=? AND target=? AND state IN ('pending','firing')
		 ORDER BY started_at DESC LIMIT 1`, rule.ID, agentID, target).Scan(&id, &state, &startedAt)
	open := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	switch {
	case breach && !open:
		id = "alert_" + uuid.NewString()
		st := "firing"
		if rule.ForSeconds > 0 {
			st = "pending"
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO alerts(id, rule_id, agent_id, site_id, target, state, value, started_at, last_eval_at)
			 VALUES(?,?,?,?,?,?,?,?,?)`, id, rule.ID, agentID, siteID, target, st, value, now, now); err != nil {
			return err
		}
		if st == "firing" {
			s.publish(eventbus.TopicAlertRaised, rule, id, agentID, siteID, target, value, now)
		}

	case breach && open:
		if state == "pending" && now.Sub(startedAt) >= time.Duration(rule.ForSeconds)*time.Second {
			if _, err := s.db.ExecContext(ctx,
				`UPDATE alerts SET state='firing', value=?, last_eval_at=? WHERE id=?`, value, now, id); err != nil {
				return err
			}
			s.publish(eventbus.TopicAlertRaised, rule, id, agentID, siteID, target, value, now)
		} else {
			if _, err := s.db.ExecContext(ctx, `UPDATE alerts SET value=?, last_eval_at=? WHERE id=?`, value, now, id); err != nil {
				return err
			}
		}

	case !breach && open:
		wasFiring := state == "firing"
		if _, err := s.db.ExecContext(ctx,
			`UPDATE alerts SET state='resolved', resolved_at=?, last_eval_at=? WHERE id=?`, now, now, id); err != nil {
			return err
		}
		if wasFiring {
			s.publish(eventbus.TopicAlertResolved, rule, id, agentID, siteID, target, value, now)
		}
	}
	return nil
}

func (s *Service) publish(topic string, rule RuleView, id, agentID, siteID, target string, value float64, at time.Time) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(topic, Raised{
		ID: id, RuleID: rule.ID, RuleName: rule.Name, AgentID: agentID, SiteID: siteID,
		Target: target, Layer: rule.Layer, Severity: rule.Severity, Value: value, At: at,
	})
}

// ListActive returns firing alerts for a site, joined with rule metadata.
func (s *Service) ListActive(ctx context.Context, siteID string) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.rule_id, COALESCE(r.name,''), a.agent_id, a.site_id, a.target,
		       COALESCE(r.layer,''), COALESCE(r.severity,''), a.state, a.value, a.started_at, a.resolved_at
		FROM alerts a LEFT JOIN alert_rules r ON r.id=a.rule_id
		WHERE a.site_id=? AND a.state='firing' ORDER BY a.started_at DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var resolved sql.NullTime
		if err := rows.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.AgentID, &a.SiteID, &a.Target,
			&a.Layer, &a.Severity, &a.State, &a.Value, &a.StartedAt, &resolved); err != nil {
			return nil, err
		}
		if resolved.Valid {
			t := resolved.Time
			a.ResolvedAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
