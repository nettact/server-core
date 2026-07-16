// Package alert holds the alert-instance domain: an alert is one firing of a
// group rule on one Agent, keyed (rule, agent), carrying immutable per-condition
// evidence. The lifecycle write path (evaluation, firing, evidence freezing,
// resolution, configuration termination) lives in the fault engine (package
// rules); this package owns the DTOs, the bus event payload, and the read
// queries the API renders.
package alert

import (
	"context"
	"database/sql"
	"time"

	"github.com/nettact/server-core/store"
)

// Resolve reasons carried on TopicAlertResolved and stored in alerts.resolve_reason
// so the incident/notification layers can tell a genuine recovery from a
// configuration-driven termination (target/rule/group/agent change).
const (
	ReasonRecovered     = "recovered"             // the rule recovered on its own
	ReasonConfigChanged = "configuration_changed" // an alert force-resolved by a config change
)

// Raised is the payload published on TopicAlertRaised / TopicAlertResolved by the
// fault engine, post-commit.
type Raised struct {
	ID         string
	RuleID     string
	RuleName   string
	AgentID    string
	SiteID     string
	GroupID    string
	Layer      string
	Severity   string
	IncidentID string
	At         time.Time
	// Reason is set only on TopicAlertResolved: ReasonRecovered for a normal
	// recovery, ReasonConfigChanged when force-resolved by a configuration change.
	Reason string
}

// Evidence is one immutable, frozen condition that contributed to a firing alert.
type Evidence struct {
	ID          string    `json:"id"`
	ConditionID string    `json:"condition_id"`
	TargetID    string    `json:"target_id"`
	TargetName  string    `json:"target_name"`
	TargetAddr  string    `json:"target_addr"`
	ProbeKind   string    `json:"probe_kind"`
	MetricKind  string    `json:"metric_kind"`
	Comparator  string    `json:"comparator"`
	Threshold   float64   `json:"threshold"`
	Value       float64   `json:"value"`
	ObservedAt  time.Time `json:"observed_at"`
}

// Alert is a stored alert instance joined with its rule/group/agent for the UI,
// plus the frozen evidence of every contributing condition.
type Alert struct {
	ID            string     `json:"id"`
	RuleID        string     `json:"rule_id"`
	RuleName      string     `json:"rule_name"`
	GroupID       string     `json:"group_id"`
	GroupName     string     `json:"group_name"`
	AgentID       string     `json:"agent_id"`
	AgentHost     string     `json:"agent_host"`
	SiteID        string     `json:"site_id"`
	Layer         string     `json:"layer"`
	Severity      string     `json:"severity"`
	State         string     `json:"state"`
	ResolveReason string     `json:"resolve_reason,omitempty"`
	IncidentID    string     `json:"incident_id,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	ResolvedAt    *time.Time `json:"resolved_at"`
	Evidence      []Evidence `json:"evidence"`
}

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

const alertCols = `a.id, COALESCE(a.rule_id,''), COALESCE(a.rule_name,''), a.group_id, COALESCE(a.group_name,''),
	a.agent_id, COALESCE(NULLIF(ag.display_name,''), ag.hostname, ''), a.site_id,
	COALESCE(a.layer,''), a.severity, a.state, COALESCE(a.resolve_reason,''), COALESCE(a.incident_id,''),
	a.started_at, a.resolved_at`

const alertFrom = `FROM alerts a
	LEFT JOIN agents ag ON ag.id=a.agent_id`

// ListActive returns the site's firing alert instances, newest first, each with
// its frozen condition evidence.
func (s *Service) ListActive(ctx context.Context, siteID string) ([]Alert, error) {
	return s.query(ctx, `SELECT `+alertCols+` `+alertFrom+`
		WHERE a.site_id=? AND a.state='firing' ORDER BY a.started_at DESC`, siteID)
}

// ListForAgent returns an agent's alert-instance history (firing + resolved),
// newest first and capped to limit, each with its frozen evidence.
func (s *Service) ListForAgent(ctx context.Context, agentID string, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	return s.query(ctx, `SELECT `+alertCols+` `+alertFrom+`
		WHERE a.agent_id=? ORDER BY a.started_at DESC LIMIT ?`, agentID, limit)
}

// ListForIncident returns the alert instances belonging to one incident (its
// members), firing first then by start time, each with evidence.
func (s *Service) ListForIncident(ctx context.Context, incidentID string) ([]Alert, error) {
	return s.query(ctx, `SELECT `+alertCols+` `+alertFrom+`
		WHERE a.incident_id=? ORDER BY CASE WHEN a.state='firing' THEN 0 ELSE 1 END, a.started_at DESC`, incidentID)
}

// query runs a read-only list on the read pool and backfills evidence in one
// extra pass.
func (s *Service) query(ctx context.Context, sqlStr string, args ...any) ([]Alert, error) {
	rows, err := s.db.Read().QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	byID := map[string]*Alert{}
	for rows.Next() {
		var a Alert
		var resolved sql.NullTime
		if err := rows.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.GroupID, &a.GroupName,
			&a.AgentID, &a.AgentHost, &a.SiteID, &a.Layer, &a.Severity, &a.State,
			&a.ResolveReason, &a.IncidentID, &a.StartedAt, &resolved); err != nil {
			return nil, err
		}
		if resolved.Valid {
			t := resolved.Time
			a.ResolvedAt = &t
		}
		a.Evidence = []Evidence{}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	if len(out) == 0 {
		return out, nil
	}
	if err := s.loadEvidence(ctx, byID); err != nil {
		return nil, err
	}
	return out, nil
}

// loadEvidence backfills each alert's frozen evidence rows in one query.
func (s *Service) loadEvidence(ctx context.Context, byID map[string]*Alert) error {
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
		SELECT alert_id, id, condition_id, target_id, target_name, target_addr, probe_kind,
		       metric_kind, comparator, threshold, value, observed_at
		FROM alert_evidence WHERE alert_id IN (`+string(ph)+`) ORDER BY observed_at`, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var alertID string
		var e Evidence
		if err := rows.Scan(&alertID, &e.ID, &e.ConditionID, &e.TargetID, &e.TargetName, &e.TargetAddr,
			&e.ProbeKind, &e.MetricKind, &e.Comparator, &e.Threshold, &e.Value, &e.ObservedAt); err != nil {
			return err
		}
		if a := byID[alertID]; a != nil {
			a.Evidence = append(a.Evidence, e)
		}
	}
	return rows.Err()
}
