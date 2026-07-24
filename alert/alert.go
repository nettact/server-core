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
// The evidence row itself never changes; CurrentlyAbnormal is a read-time overlay
// (STATUS-001) computed from CURRENT condition state, not from the frozen row: it
// is true only while the evidence's alert is still firing AND its (condition,
// agent) rule state is currently satisfied. False ⇒ recovered historical evidence.
type Evidence struct {
	ID                string    `json:"id"`
	ConditionID       string    `json:"condition_id"`
	TargetID          string    `json:"target_id"`
	TargetName        string    `json:"target_name"`
	TargetAddr        string    `json:"target_addr"`
	ProbeKind         string    `json:"probe_kind"`
	MetricKind        string    `json:"metric_kind"`
	Comparator        string    `json:"comparator"`
	Threshold         float64   `json:"threshold"`
	Value             float64   `json:"value"`
	ReasonCode        int       `json:"reason_code"`   // frozen probe failure reason (telemetry.ProbeReason*); 0 = none
	ReasonDetail      string    `json:"reason_detail"` // raw underlying cause frozen from the probe's detail label; '' when unavailable
	ObservedAt        time.Time `json:"observed_at"`
	CurrentlyAbnormal bool      `json:"currently_abnormal"`
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

// CountActive returns the number of firing alert instances for a site.
func (s *Service) CountActive(ctx context.Context, siteID string) (int, error) {
	var n int
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE site_id=? AND state='firing'`, siteID).Scan(&n)
	return n, err
}

// TargetScope identifies the one monitored entity whose alert history is being
// requested. User-created monitors use their stable monitor id; system/host
// series use the frozen target address carried by alert evidence.
type TargetScope struct {
	MonitorID string
	Address   string
}

// ListForAgent returns one target's alert-instance history for an Agent (firing
// + resolved), newest first and capped to limit. The EXISTS predicate is applied
// before ORDER/LIMIT so unrelated recent alerts cannot displace matching rows.
// Returned evidence is scoped too, keeping a multi-condition group alert focused
// on the target whose history page requested it.
func (s *Service) ListForAgent(ctx context.Context, agentID string, scope TargetScope, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	column, value := "e.target_id", scope.MonitorID
	if value == "" {
		column, value = "e.target_addr", scope.Address
	}
	alerts, err := s.query(ctx, `SELECT `+alertCols+` `+alertFrom+`
		WHERE a.agent_id=? AND EXISTS (
			SELECT 1 FROM alert_evidence e WHERE e.alert_id=a.id AND `+column+`=?
		) ORDER BY a.started_at DESC LIMIT ?`, agentID, value, limit)
	if err != nil {
		return nil, err
	}
	for i := range alerts {
		evidence := alerts[i].Evidence[:0]
		for _, item := range alerts[i].Evidence {
			if (scope.MonitorID != "" && item.TargetID == scope.MonitorID) ||
				(scope.MonitorID == "" && item.TargetAddr == scope.Address) {
				evidence = append(evidence, item)
			}
		}
		alerts[i].Evidence = evidence
	}
	return alerts, nil
}

// IncidentDetail returns one incident's member alerts (each with frozen evidence
// stamped with its read-time currently_abnormal overlay) and the incident's
// current abnormal-target count, all read in ONE read snapshot transaction so the
// evidence overlay and the count reflect the same committed condition/alert state.
//
// currently_abnormal per evidence = its alert is firing AND the (condition, agent)
// rule state is currently satisfied. abnormal_target_count = the number of
// distinct targets currently abnormal across the incident's firing alerts,
// computed from live rule_condition_state — deliberately decoupled from the
// immutable evidence count (recovered conditions keep their frozen evidence but
// do not count).
func (s *Service) IncidentDetail(ctx context.Context, incidentID string) ([]Alert, int, error) {
	tx, err := s.db.Read().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT `+alertCols+` `+alertFrom+`
		WHERE a.incident_id=? ORDER BY CASE WHEN a.state='firing' THEN 0 ELSE 1 END, a.started_at DESC`, incidentID)
	if err != nil {
		return nil, 0, err
	}
	var out []Alert
	for rows.Next() {
		var a Alert
		var resolved sql.NullTime
		if err := rows.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.GroupID, &a.GroupName,
			&a.AgentID, &a.AgentHost, &a.SiteID, &a.Layer, &a.Severity, &a.State,
			&a.ResolveReason, &a.IncidentID, &a.StartedAt, &resolved); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if resolved.Valid {
			t := resolved.Time
			a.ResolvedAt = &t
		}
		a.Evidence = []Evidence{}
		out = append(out, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	if len(out) > 0 {
		byID := make(map[string]*Alert, len(out))
		ids := make([]any, 0, len(out))
		ph := make([]byte, 0, len(out)*2)
		for i := range out {
			byID[out[i].ID] = &out[i]
			if len(ph) > 0 {
				ph = append(ph, ',')
			}
			ph = append(ph, '?')
			ids = append(ids, out[i].ID)
		}
		erows, err := tx.QueryContext(ctx, `
			SELECT e.alert_id, e.id, e.condition_id, e.target_id, e.target_name, e.target_addr, e.probe_kind,
			       e.metric_kind, e.comparator, e.threshold, e.value, e.reason_code, e.reason_detail, e.observed_at,
			       CASE WHEN a.state='firing' AND COALESCE(rcs.satisfied,0)=1 THEN 1 ELSE 0 END
			FROM alert_evidence e
			JOIN alerts a ON a.id = e.alert_id
			LEFT JOIN rule_condition_state rcs ON rcs.condition_id = e.condition_id AND rcs.agent_id = a.agent_id
			WHERE e.alert_id IN (`+string(ph)+`) ORDER BY e.observed_at`, ids...)
		if err != nil {
			return nil, 0, err
		}
		for erows.Next() {
			var alertID string
			var e Evidence
			var abnormal int
			if err := erows.Scan(&alertID, &e.ID, &e.ConditionID, &e.TargetID, &e.TargetName, &e.TargetAddr,
				&e.ProbeKind, &e.MetricKind, &e.Comparator, &e.Threshold, &e.Value, &e.ReasonCode, &e.ReasonDetail, &e.ObservedAt, &abnormal); err != nil {
				erows.Close()
				return nil, 0, err
			}
			e.CurrentlyAbnormal = abnormal == 1
			if a := byID[alertID]; a != nil {
				a.Evidence = append(a.Evidence, e)
			}
		}
		erows.Close()
		if err := erows.Err(); err != nil {
			return nil, 0, err
		}
	}

	var abnormalTargets int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT grc.target_id)
		FROM alerts a
		JOIN group_rule_conditions grc ON grc.rule_id = a.rule_id
		JOIN rule_condition_state rcs ON rcs.condition_id = grc.id AND rcs.agent_id = a.agent_id
		WHERE a.incident_id=? AND a.state='firing' AND rcs.satisfied=1`, incidentID).Scan(&abnormalTargets); err != nil {
		return nil, 0, err
	}

	if out == nil {
		out = []Alert{}
	}
	return out, abnormalTargets, nil
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
		       metric_kind, comparator, threshold, value, reason_code, reason_detail, observed_at
		FROM alert_evidence WHERE alert_id IN (`+string(ph)+`) ORDER BY observed_at`, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var alertID string
		var e Evidence
		if err := rows.Scan(&alertID, &e.ID, &e.ConditionID, &e.TargetID, &e.TargetName, &e.TargetAddr,
			&e.ProbeKind, &e.MetricKind, &e.Comparator, &e.Threshold, &e.Value, &e.ReasonCode, &e.ReasonDetail, &e.ObservedAt); err != nil {
			return err
		}
		if a := byID[alertID]; a != nil {
			a.Evidence = append(a.Evidence, e)
		}
	}
	return rows.Err()
}
