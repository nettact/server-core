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

// Resolve reasons carried on TopicAlertResolved so the incident correlator can
// tell a genuine probe recovery from an alert that was force-closed because its
// monitored object was deleted. The zero value ("") is a normal recovery, so
// existing publishers need no change.
const (
	ReasonRecovered = ""        // the probe recovered on its own
	ReasonDeleted   = "deleted" // the alert's target / rule / agent was removed while alerting
)

// RuleView is the rule context the alert service needs (avoids importing rules).
type RuleView struct {
	ID            string
	Name          string
	Layer         string
	Severity      string
	ForSeconds    int
	FailThreshold int // fire after this many CONSECUTIVE breaching evaluations (min 1)
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
	// Reason is set only on TopicAlertResolved: "" for a normal recovery,
	// ReasonDeleted when the alert was force-closed because its monitored object
	// (target, rule, or agent) was removed. Lets the incident correlator record a
	// termination rather than a false recovery.
	Reason string
}

// Alert is a stored alert row joined with its rule (for the UI). It carries the
// human-facing identifiers (agent hostname, target name) and the rule's metric
// condition (kind/comparator/threshold) so the API can render a description that
// says who fired and why.
type Alert struct {
	ID         string     `json:"id"`
	RuleID     string     `json:"rule_id"`
	RuleName   string     `json:"rule_name"`
	AgentID    string     `json:"agent_id"`
	AgentHost  string     `json:"agent_host"` // display name or hostname of the detecting agent
	SiteID     string     `json:"site_id"`
	Target     string     `json:"target"`
	TargetName string     `json:"target_name,omitempty"` // operator-set friendly name
	Layer      string     `json:"layer"`
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	Value      float64    `json:"value"`
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at"`

	// Rule condition + probe kind, used server-side to render a description.
	ProbeKind  string  `json:"-"`
	MetricKind string  `json:"-"`
	Comparator string  `json:"-"`
	Threshold  float64 `json:"-"`
}

type Service struct {
	db  *store.DB
	bus *eventbus.Bus
}

func New(db *store.DB, bus *eventbus.Bus) *Service { return &Service{db: db, bus: bus} }

// Update transitions the (rule, agent, target) alert given the latest breach
// state. Triggering is count-based: the alert fires after FailThreshold
// CONSECUTIVE breaching evaluations; a single non-breach resets the counter and
// resolves any open alert. (ForSeconds is retained as an additional gate: a
// pending alert only promotes once both the count and the duration are met.)
func (s *Service) Update(ctx context.Context, rule RuleView, agentID, siteID, target string, breach bool, value float64) error {
	now := time.Now().UTC()
	threshold := rule.FailThreshold
	if threshold < 1 {
		threshold = 1
	}

	var id, state string
	var startedAt time.Time
	var failCount int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, state, started_at, fail_count FROM alerts
		 WHERE rule_id=? AND agent_id=? AND target=? AND state IN ('pending','firing')
		 ORDER BY started_at DESC LIMIT 1`, rule.ID, agentID, target).Scan(&id, &state, &startedAt, &failCount)
	open := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	switch {
	case breach && !open:
		id = "alert_" + uuid.NewString()
		count := 1
		st := "pending"
		if count >= threshold && durationMet(rule, now, now) {
			st = "firing"
		}
		// fired_at is stamped only once the alert actually fires, so the history
		// view can tell real alarms from pending attempts that never fired.
		var firedAt any
		if st == "firing" {
			firedAt = now
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO alerts(id, rule_id, agent_id, site_id, target, state, value, fail_count, started_at, last_eval_at, fired_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, rule.ID, agentID, siteID, target, st, value, count, now, now, firedAt); err != nil {
			return err
		}
		if st == "firing" {
			s.publish(eventbus.TopicAlertRaised, rule, id, agentID, siteID, target, value, now)
		}

	case breach && open:
		failCount++
		if state == "pending" && failCount >= threshold && durationMet(rule, startedAt, now) {
			if _, err := s.db.ExecContext(ctx,
				`UPDATE alerts SET state='firing', value=?, fail_count=?, last_eval_at=?, fired_at=? WHERE id=?`, value, failCount, now, now, id); err != nil {
				return err
			}
			s.publish(eventbus.TopicAlertRaised, rule, id, agentID, siteID, target, value, now)
		} else {
			if _, err := s.db.ExecContext(ctx, `UPDATE alerts SET value=?, fail_count=?, last_eval_at=? WHERE id=?`, value, failCount, now, id); err != nil {
				return err
			}
		}

	case !breach && open:
		wasFiring := state == "firing"
		if _, err := s.db.ExecContext(ctx,
			`UPDATE alerts SET state='resolved', resolved_at=?, last_eval_at=?, fail_count=0 WHERE id=?`, now, now, id); err != nil {
			return err
		}
		if wasFiring {
			s.publish(eventbus.TopicAlertResolved, rule, id, agentID, siteID, target, value, now)
		}
	}
	return nil
}

// ResolveOutOfScope resolves any open (pending/firing) alert whose bound target
// is group-scoped (all_agents=0) and whose detecting agent is no longer in any of
// the target's groups. It is the counterpart to the scope filter in rule
// evaluation (config.AgentScopePredicate): once an agent leaves a target's scope
// its rules stop being evaluated for that agent, so an alert already open for it
// would otherwise never reach the resolve path and stay firing forever. Call after
// any scope change — a target's scope edit, group membership change, or group
// deletion. Firing alerts emit TopicAlertResolved so incidents close through the
// normal path. Idempotent: a second call resolves nothing.
//
// The WHERE clause is the negation of AgentScopePredicate correlated to each
// alert's own agent (all_agents=0 AND agent NOT in any bound group); keep the two
// in sync if the scoping model changes.
func (s *Service) ResolveOutOfScope(ctx context.Context, siteID string) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.rule_id, a.agent_id, a.target, a.value, a.state,
		       COALESCE(r.name,''), COALESCE(r.layer,''), COALESCE(r.severity,'')
		FROM alerts a
		JOIN alert_rules r ON r.id = a.rule_id
		JOIN probe_tasks pt ON pt.id = r.probe_task_id
		WHERE a.site_id=? AND a.state IN ('pending','firing') AND pt.all_agents=0
		  AND NOT EXISTS(
		    SELECT 1 FROM probe_task_groups ptg
		    JOIN agent_group_members agm ON agm.group_id = ptg.group_id
		    WHERE ptg.task_id = pt.id AND agm.agent_id = a.agent_id)`, siteID)
	if err != nil {
		return err
	}
	type stranded struct {
		id, ruleID, agentID, target, state, name, layer, severity string
		value                                                     float64
	}
	var list []stranded
	for rows.Next() {
		var st stranded
		if err := rows.Scan(&st.id, &st.ruleID, &st.agentID, &st.target, &st.value, &st.state,
			&st.name, &st.layer, &st.severity); err != nil {
			rows.Close()
			return err
		}
		list = append(list, st)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, st := range list {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE alerts SET state='resolved', resolved_at=?, last_eval_at=?, fail_count=0 WHERE id=?`,
			now, now, st.id); err != nil {
			return err
		}
		// Only firing alerts were correlated into an incident, so only they need a
		// resolve event to unwind it; pending ones just clear silently.
		if st.state == "firing" {
			s.publish(eventbus.TopicAlertResolved,
				RuleView{ID: st.ruleID, Name: st.name, Layer: st.layer, Severity: st.severity},
				st.id, st.agentID, siteID, st.target, st.value, now)
		}
	}
	return nil
}

// durationMet reports whether the rule's optional ForSeconds dwell has elapsed
// between the alert's start and now (always true when ForSeconds is 0).
func durationMet(rule RuleView, startedAt, now time.Time) bool {
	if rule.ForSeconds <= 0 {
		return true
	}
	return now.Sub(startedAt) >= time.Duration(rule.ForSeconds)*time.Second
}

// TerminateForRule force-resolves any open alert produced by a rule that is being
// deleted. See terminate for the lifecycle contract.
func (s *Service) TerminateForRule(ctx context.Context, ruleID string) error {
	return s.terminate(ctx, `a.rule_id = ?`, ruleID)
}

// TerminateForTask force-resolves any open alert produced by the rules bound to a
// monitor (probe_task) that is being deleted. See terminate for the contract.
func (s *Service) TerminateForTask(ctx context.Context, taskID string) error {
	return s.terminate(ctx, `a.rule_id IN (SELECT id FROM alert_rules WHERE probe_task_id = ?)`, taskID)
}

// TerminateForAgent force-resolves any open alert detected by an agent that is
// being deleted. See terminate for the contract.
func (s *Service) TerminateForAgent(ctx context.Context, agentID string) error {
	return s.terminate(ctx, `a.agent_id = ?`, agentID)
}

// terminate resolves every open (pending/firing) alert selected by whereSQL
// (correlated to alerts alias "a") because its owning object — target, rule, or
// agent — is being removed. Each row is stamped resolved and, if it was firing,
// TopicAlertResolved is published with ReasonDeleted so the incident correlator
// unwinds it through the normal path: it records a "监控终止（对象已删除）" entry
// and closes the incident as a termination rather than leaving it stranded open
// or letting an unrelated later recovery false-close it as a healthy recovery.
//
// Callers MUST invoke this BEFORE deleting the alert rows and OUTSIDE any open
// write transaction: the published event's incident handler writes to the DB, and
// SQLite allows a single writer. The rows are left in place (resolved) for the
// caller's own cascade to delete under its FK ordering. Idempotent — a second
// call finds nothing open and resolves/publishes nothing.
func (s *Service) terminate(ctx context.Context, whereSQL string, args ...any) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.rule_id, a.agent_id, a.site_id, a.target, a.value, a.state,
		       COALESCE(r.name,''), COALESCE(r.layer,''), COALESCE(r.severity,'')
		FROM alerts a
		LEFT JOIN alert_rules r ON r.id = a.rule_id
		WHERE a.state IN ('pending','firing') AND (`+whereSQL+`)`, args...)
	if err != nil {
		return err
	}
	type open struct {
		id, ruleID, agentID, siteID, target, state, name, layer, severity string
		value                                                             float64
	}
	var list []open
	for rows.Next() {
		var o open
		if err := rows.Scan(&o.id, &o.ruleID, &o.agentID, &o.siteID, &o.target, &o.value, &o.state,
			&o.name, &o.layer, &o.severity); err != nil {
			rows.Close()
			return err
		}
		list = append(list, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, o := range list {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE alerts SET state='resolved', resolved_at=?, last_eval_at=?, fail_count=0 WHERE id=?`,
			now, now, o.id); err != nil {
			return err
		}
		// Only firing alerts were correlated into an incident, so only they need a
		// resolve event to unwind it; pending ones just clear silently.
		if o.state == "firing" {
			s.publishReason(eventbus.TopicAlertResolved, ReasonDeleted,
				RuleView{ID: o.ruleID, Name: o.name, Layer: o.layer, Severity: o.severity},
				o.id, o.agentID, o.siteID, o.target, o.value, now)
		}
	}
	return nil
}

func (s *Service) publish(topic string, rule RuleView, id, agentID, siteID, target string, value float64, at time.Time) {
	s.publishReason(topic, ReasonRecovered, rule, id, agentID, siteID, target, value, at)
}

func (s *Service) publishReason(topic, reason string, rule RuleView, id, agentID, siteID, target string, value float64, at time.Time) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(topic, Raised{
		ID: id, RuleID: rule.ID, RuleName: rule.Name, AgentID: agentID, SiteID: siteID,
		Target: target, Layer: rule.Layer, Severity: rule.Severity, Value: value, At: at, Reason: reason,
	})
}

// alertCols / alertFrom are shared by ListActive and ListForTarget so both carry
// the same descriptive fields: the rule (name/layer/severity/metric condition),
// the bound probe task (kind + friendly name), and the detecting agent
// (display name / hostname). Column order must match query()'s scan.
const alertCols = `a.id, a.rule_id, COALESCE(r.name,''), a.agent_id,
	COALESCE(NULLIF(ag.display_name,''), ag.hostname, ''), a.site_id, a.target, COALESCE(p.name,''),
	COALESCE(r.layer,''), COALESCE(r.severity,''), a.state, a.value, a.started_at, a.resolved_at,
	COALESCE(p.kind,''), COALESCE(r.metric_kind,''), COALESCE(r.comparator,''), COALESCE(r.threshold,0)`

const alertFrom = `FROM alerts a
	LEFT JOIN alert_rules r ON r.id=a.rule_id
	LEFT JOIN probe_tasks p ON p.id=r.probe_task_id
	LEFT JOIN agents ag ON ag.id=a.agent_id`

// ListActive returns firing alerts for a site, joined with rule metadata.
func (s *Service) ListActive(ctx context.Context, siteID string) ([]Alert, error) {
	return s.query(ctx, `SELECT `+alertCols+` `+alertFrom+`
		WHERE a.site_id=? AND a.state='firing' ORDER BY a.started_at DESC`, siteID)
}

// ListForTarget returns the alarm history for a single agent+target, newest
// first and capped to limit — powers the history page's per-target 报警记录
// panel. Only alerts that actually fired are included (fired_at set), so pending
// attempts that resolved without firing are excluded. agent_id is a global
// primary key, so no site scoping is needed (and adding it would wrongly exclude
// agents outside the default site).
func (s *Service) ListForTarget(ctx context.Context, agentID, target string, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	return s.query(ctx, `SELECT `+alertCols+` `+alertFrom+`
		WHERE a.agent_id=? AND a.target=? AND a.fired_at IS NOT NULL
		ORDER BY a.started_at DESC LIMIT ?`, agentID, target, limit)
}

// ListForMonitor returns the alarm history for one agent + one user-created
// monitor (probe_task), newest first — the monitor-scoped variant of
// ListForTarget, so two monitors sharing a target string never see each
// other's alerts. Rules are bound to their monitor, so filtering on the rule's
// probe_task_id is exact.
func (s *Service) ListForMonitor(ctx context.Context, agentID, monitorID string, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	return s.query(ctx, `SELECT `+alertCols+` `+alertFrom+`
		WHERE a.agent_id=? AND r.probe_task_id=? AND a.fired_at IS NOT NULL
		ORDER BY a.started_at DESC LIMIT ?`, agentID, monitorID, limit)
}

// query serves the read-only list endpoints, so it runs on the read pool —
// alert-state writes (Update) stay on the single write connection.
func (s *Service) query(ctx context.Context, sqlStr string, args ...any) ([]Alert, error) {
	rows, err := s.db.Read().QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var resolved sql.NullTime
		if err := rows.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.AgentID, &a.AgentHost,
			&a.SiteID, &a.Target, &a.TargetName, &a.Layer, &a.Severity, &a.State, &a.Value,
			&a.StartedAt, &resolved,
			&a.ProbeKind, &a.MetricKind, &a.Comparator, &a.Threshold); err != nil {
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
