// Package targetstatus is the server-authoritative current-status domain service
// (STATUS-001). It answers "what is every monitoring target's current health,
// right now" for a whole site in one read-time aggregation, with no second
// persisted current-status table: every fact is derived at read time from the
// authoritative sources — site targets and their applicable Agents, reported vs
// predicted MonitorStatus (execution eligibility + Agent liveness), the latest
// EXACT-generation probe samples (probe result + freshness), the current
// rule_condition_state (rule breaching), and firing alerts/incidents (alerting).
//
// The three per-Agent dimensions are independent and all reported:
//
//   - execution_state — is the pair actually collecting, or why not
//     (disabled | agent_offline | pending | collecting | permission_blocked |
//     target_blocked | unsupported);
//   - probe_state — the freshness/result verdict of the latest current-generation
//     sample (no_data | healthy | failed | stale | not_applicable);
//   - rule_state — whether a current rule condition is breaching / firing
//     (normal | breaching | alerting).
//
// A target-level display_state rolls the per-Agent facts up through the fixed
// display-priority decision table. Reads run in one read-pool snapshot
// transaction so alerts and condition state — which the fault engine commits
// together — can never be observed inconsistently.
package targetstatus

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/store"
)

// ErrSiteNotFound is returned by SiteStatuses when the requested site does not
// exist, so the API can answer 404 (distinct from a dependency/query failure,
// which is a truthful 500).
var ErrSiteNotFound = errors.New("targetstatus: site not found")

// ---- stable enum values (machine values; only the frontend localizes them) ----

const (
	execDisabled          = "disabled"
	execUnassigned        = "unassigned" // target-only; never per-agent
	execPending           = "pending"
	execCollecting        = "collecting"
	execPermissionBlocked = "permission_blocked"
	execTargetBlocked     = "target_blocked"
	execUnsupported       = "unsupported"
	execAgentOffline      = "agent_offline"

	probeNoData        = "no_data"
	probeHealthy       = "healthy"
	probeFailed        = "failed"
	probeStale         = "stale"
	probeNotApplicable = "not_applicable"

	ruleNormal    = "normal"
	ruleBreaching = "breaching"
	ruleAlerting  = "alerting"

	displayDisabled       = "disabled"
	displayUnassigned     = "unassigned"
	displayAlerting       = "alerting"
	displayBreaching      = "breaching"
	displayPartialFailure = "partial_failure"
	displayProbeFailed    = "probe_failed"
	displayBlocked        = "blocked"
	displayAgentOffline   = "agent_offline"
	displayPending        = "pending"
	displayStale          = "stale"
	displayNoData         = "no_data"
	displayHealthy        = "healthy"

	reasonTargetDisabled    = "target_disabled"
	reasonNoApplicable      = "no_applicable_agents"
	reasonAgentOffline      = "agent_offline"
	reasonPermissionBlocked = "permission_blocked"
	reasonTargetBlocked     = "target_blocked"
	reasonUnsupported       = "unsupported"
	reasonAwaitingStatus    = "awaiting_status_report"
	reasonAlertFiring       = "alert_firing"
	reasonRuleBreaching     = "rule_breaching"
	reasonProbeFailed       = "probe_failed"
	reasonProbeStale        = "probe_stale"
	reasonProbeNoData       = "probe_no_data"
	reasonNotApplicable     = "not_applicable"
	reasonOK                = "ok"
)

// severityRank orders alert severities (mirrors rules/notify.go). Used to pick a
// target's worst current severity.
var severityRank = map[string]int{"info": 0, "warn": 1, "error": 2, "critical": 3}

// ---- API DTOs (frozen contract shared with the web-console types) ----

// SiteStatuses is one deterministic batch of every target's current status for a
// site, at a single generated_at snapshot.
type SiteStatuses struct {
	GeneratedAt time.Time      `json:"generated_at"`
	SiteID      string         `json:"site_id"`
	Targets     []TargetStatus `json:"targets"`
}

// TargetStatus is one target's aggregated current status across every applicable
// Agent. worst_severity is present only for alerting/breaching targets;
// last_observed_at is omitted when no current-generation sample exists anywhere.
type TargetStatus struct {
	TargetID             string        `json:"target_id"`
	GroupID              string        `json:"group_id"`
	Name                 string        `json:"name"`
	Kind                 string        `json:"kind"`
	Target               string        `json:"target"`
	Enabled              bool          `json:"enabled"`
	DisplayState         string        `json:"display_state"`
	ApplicableAgents     int           `json:"applicable_agents"`
	AffectedAgents       int           `json:"affected_agents"`
	WorstSeverity        string        `json:"worst_severity,omitempty"`
	LastObservedAt       *time.Time    `json:"last_observed_at,omitempty"`
	ActiveConditionCount int           `json:"active_condition_count"`
	RuleIDs              []string      `json:"rule_ids"`
	AlertIDs             []string      `json:"alert_ids"`
	IncidentIDs          []string      `json:"incident_ids"`
	Agents               []AgentStatus `json:"agents"`
}

// AgentStatus is one target's status as seen from one applicable Agent. The three
// dimensions are independent. stale_after_seconds is per-agent (the reported
// effective schedule when confirmed, else the desired-config fallback) and is
// omitted for host targets; pending_since is present iff execution_state=pending.
type AgentStatus struct {
	AgentID            string            `json:"agent_id"`
	AgentName          string            `json:"agent_name"`
	AgentOnline        bool              `json:"agent_online"`
	ExecutionState     string            `json:"execution_state"`
	ProbeState         string            `json:"probe_state"`
	RuleState          string            `json:"rule_state"`
	ReasonCode         string            `json:"reason_code"`
	StaleAfterSeconds  *int              `json:"stale_after_seconds,omitempty"`
	PendingSince       *time.Time        `json:"pending_since,omitempty"`
	MissingPermissions []string          `json:"missing_permissions"`
	MatchedSelector    string            `json:"matched_selector"`
	BlockReason        string            `json:"block_reason"`
	LastValue          *float64          `json:"last_value,omitempty"`
	LastMetricKind     string            `json:"last_metric_kind,omitempty"`
	LastUnit           string            `json:"last_unit,omitempty"`
	LastObservedAt     *time.Time        `json:"last_observed_at,omitempty"`
	ActiveConditions   []ActiveCondition `json:"active_conditions"`
}

// ActiveCondition is one currently-satisfied rule condition on a target×Agent
// pair. The display label is derived by the frontend from metric_kind +
// comparator; the server never invents display text. alert_id/incident_id are
// present only when the condition's rule has a firing alert for the agent.
type ActiveCondition struct {
	ConditionID   string     `json:"condition_id"`
	RuleID        string     `json:"rule_id"`
	RuleName      string     `json:"rule_name"`
	Severity      string     `json:"severity"`
	MetricKind    string     `json:"metric_kind"`
	Comparator    string     `json:"comparator"`
	Threshold     float64    `json:"threshold"`
	LastValue     *float64   `json:"last_value,omitempty"`
	Unit          string     `json:"unit,omitempty"`
	FirstBreachAt *time.Time `json:"first_breach_at,omitempty"`
	AlertID       string     `json:"alert_id,omitempty"`
	IncidentID    string     `json:"incident_id,omitempty"`
}

// Service reads the authoritative current status. It owns no persisted state.
type Service struct {
	db *store.DB
}

// New constructs the service over the shared store.
func New(db *store.DB) *Service { return &Service{db: db} }

// ---- internal read models ----

type targetRow struct {
	id, groupID, name, kind, target string
	enabled                         bool
	configSerial                    int
	configChangedAt                 sql.NullTime
	params                          pcfg.ProbeParams
	groupIsDefault                  bool
	groupName                       string
}

type applicablePair struct {
	agentID, agentName string
	online             bool
}

type msRow struct {
	status, source     string
	targetConfigSerial int
	assignedAt         sql.NullTime
	missing            []string
	matchedSelector    string
	reason             string
	effInterval        sql.NullInt64
	cycleDeadline      sql.NullInt64
}

type sampleVal struct {
	kind, unit string
	ts         int64
	value      float64
}

type condMeta struct {
	ruleID, targetID, metricKind, comparator string
	ruleName, severity                       string
	threshold                                float64
}

type condState struct {
	satisfied     bool
	lastValue     sql.NullFloat64
	firstBreachAt sql.NullTime
	lastEvalAt    sql.NullTime
}

type firingAlert struct {
	alertID, incidentID string
}

// agentAgg is the per-agent classification fed to the target-level decision table.
type agentAgg struct {
	exec, probe, rule string
	online            bool
	pendingExpired    bool
}

// SiteStatuses computes the whole site's current target status in one read-pool
// snapshot transaction. It returns ErrSiteNotFound for an unknown site; any
// dependency/query failure returns an error (the API answers a truthful 500 and
// never a partial/empty 200).
func (s *Service) SiteStatuses(ctx context.Context, siteID string) (SiteStatuses, error) {
	now := time.Now().UTC()
	// One read snapshot: WAL isolation holds for the life of a single read
	// transaction, so alerts and condition state (committed together by the fault
	// engine) can never be observed torn across the queries below. The read pool
	// is already query_only; ReadOnly is belt-and-braces.
	tx, err := s.db.Read().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SiteStatuses{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// Site existence (404 boundary).
	var siteSerial int
	if err := tx.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id=?`, siteID).Scan(&siteSerial); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SiteStatuses{}, ErrSiteNotFound
		}
		return SiteStatuses{}, err
	}

	targets, err := s.loadTargets(ctx, tx, siteID)
	if err != nil {
		return SiteStatuses{}, err
	}
	pairs, err := s.loadApplicablePairs(ctx, tx, siteID)
	if err != nil {
		return SiteStatuses{}, err
	}
	msByKey, err := s.loadMonitorStatus(ctx, tx, siteID)
	if err != nil {
		return SiteStatuses{}, err
	}
	samples, err := s.loadLatestSamples(ctx, tx, siteID)
	if err != nil {
		return SiteStatuses{}, err
	}
	condMetaByID, condStateByKey, condIDsByTarget, err := s.loadConditions(ctx, tx, siteID)
	if err != nil {
		return SiteStatuses{}, err
	}
	firing, err := s.loadFiringAlerts(ctx, tx, siteID)
	if err != nil {
		return SiteStatuses{}, err
	}

	out := SiteStatuses{GeneratedAt: now, SiteID: siteID, Targets: make([]TargetStatus, 0, len(targets))}
	for i := range targets {
		t := &targets[i]
		out.Targets = append(out.Targets, s.assembleTarget(t, pairs[t.id], now,
			msByKey, samples, condMetaByID, condStateByKey, condIDsByTarget[t.id], firing))
	}
	sortTargets(out.Targets, targets)
	return out, nil
}

// assembleTarget builds one target's status: derive each applicable Agent's three
// dimensions, then roll them up through the decision table and collect the
// target-level linkage (rules / alerts / incidents / worst severity).
func (s *Service) assembleTarget(t *targetRow, pairs []applicablePair, now time.Time,
	msByKey map[string]*msRow, samples map[string]*sampleVal,
	condMetaByID map[string]condMeta, condStateByKey map[string]condState,
	condIDs []string, firing map[string]firingAlert) TargetStatus {

	ts := TargetStatus{
		TargetID: t.id, GroupID: t.groupID, Name: t.name, Kind: t.kind, Target: t.target,
		Enabled: t.enabled, ApplicableAgents: len(pairs),
		RuleIDs: []string{}, AlertIDs: []string{}, IncidentIDs: []string{},
		Agents: make([]AgentStatus, 0, len(pairs)),
	}

	// Deterministic per-agent order: agent_name, agent_id.
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].agentName != pairs[j].agentName {
			return pairs[i].agentName < pairs[j].agentName
		}
		return pairs[i].agentID < pairs[j].agentID
	})

	aggs := make([]agentAgg, 0, len(pairs))
	ruleSet := map[string]bool{}
	alertSet := map[string]bool{}
	incidentSet := map[string]bool{}
	worstRank := -1
	var lastObserved *time.Time
	condCount := 0

	for _, p := range pairs {
		as, agg := s.deriveAgent(t, p, now, msByKey, samples, condIDs, condMetaByID, condStateByKey, firing)
		ts.Agents = append(ts.Agents, as)
		aggs = append(aggs, agg)

		condCount += len(as.ActiveConditions)
		for _, ac := range as.ActiveConditions {
			ruleSet[ac.RuleID] = true
			if ac.AlertID != "" {
				alertSet[ac.AlertID] = true
			}
			if ac.IncidentID != "" {
				incidentSet[ac.IncidentID] = true
			}
			if r, ok := severityRank[ac.Severity]; ok && r > worstRank {
				worstRank = r
			}
		}
		if as.LastObservedAt != nil && (lastObserved == nil || as.LastObservedAt.After(*lastObserved)) {
			lo := *as.LastObservedAt
			lastObserved = &lo
		}
	}

	display, affected := aggregate(t, aggs)
	ts.DisplayState = display
	ts.AffectedAgents = affected
	ts.ActiveConditionCount = condCount
	ts.RuleIDs = sortedKeys(ruleSet)
	ts.AlertIDs = sortedKeys(alertSet)
	ts.IncidentIDs = sortedKeys(incidentSet)
	ts.LastObservedAt = lastObserved
	if (display == displayAlerting || display == displayBreaching) && worstRank >= 0 {
		ts.WorstSeverity = severityName(worstRank)
	}
	return ts
}

// deriveAgent computes one (target, agent) pair's three independent dimensions,
// reason code, freshness window, pending clock and active conditions, plus the
// aggregation classification fed to the decision table.
func (s *Service) deriveAgent(t *targetRow, p applicablePair, now time.Time,
	msByKey map[string]*msRow, samples map[string]*sampleVal,
	condIDs []string, condMetaByID map[string]condMeta, condStateByKey map[string]condState,
	firing map[string]firingAlert) (AgentStatus, agentAgg) {

	as := AgentStatus{
		AgentID: p.agentID, AgentName: p.agentName, AgentOnline: p.online,
		MissingPermissions: []string{}, ActiveConditions: []ActiveCondition{},
	}

	pairKey := t.id + "\x00" + p.agentID
	ms := msByKey[pairKey]
	confirmed := ms != nil && ms.source == "reported" && ms.targetConfigSerial == t.configSerial

	// Assignment cutoff for current-state reads (SRV-007): the later of the target's
	// material-generation time and this pair's assigned_at. A pair that left a
	// target's scope and re-entered without a material edit keeps the same generation
	// (and thus its stored samples/series and any surviving condition state), so the
	// generation join alone cannot exclude pre-assignment facts. assigned_at is reset
	// to the re-entry time, so any sample or condition verdict observed before it is
	// pre-assignment history and must not surface as current. Historical storage is
	// untouched — only these reads exclude it.
	cutoff := pendingSince(t, ms)

	// Freshness window (per pair). Desired-config fallback is used until the agent
	// reports its actual effective schedule for the current generation.
	graceWindow := pcfg.StaleAfter(pcfg.EffectiveInterval(t.kind, t.params), pcfg.CycleDeadline(t.kind, t.params))
	staleAfter := graceWindow
	if confirmed && ms.effInterval.Valid && ms.effInterval.Int64 > 0 && ms.cycleDeadline.Valid && ms.cycleDeadline.Int64 > 0 {
		staleAfter = pcfg.StaleAfter(
			time.Duration(ms.effInterval.Int64)*time.Second,
			time.Duration(ms.cycleDeadline.Int64)*time.Millisecond)
	}
	if t.kind != "host" {
		secs := int(staleAfter / time.Second)
		as.StaleAfterSeconds = &secs
	}

	// execution_state (ordered: disabled → offline → pending → confirmed status).
	switch {
	case !t.enabled:
		as.ExecutionState = execDisabled
		as.ReasonCode = reasonTargetDisabled
	case !p.online:
		as.ExecutionState = execAgentOffline
		as.ReasonCode = reasonAgentOffline
	case !confirmed:
		as.ExecutionState = execPending
		as.ReasonCode = reasonAwaitingStatus
		as.PendingSince = pendingSince(t, ms)
	default:
		switch ms.status {
		case wire.MonitorStatusActive:
			as.ExecutionState = execCollecting
		case wire.MonitorStatusPermissionBlocked:
			as.ExecutionState = execPermissionBlocked
			as.ReasonCode = reasonPermissionBlocked
			as.MissingPermissions = nonNilStrings(ms.missing)
			as.MatchedSelector = ms.matchedSelector
			as.BlockReason = ms.reason
		case wire.MonitorStatusTargetBlocked:
			as.ExecutionState = execTargetBlocked
			as.ReasonCode = reasonTargetBlocked
			as.MatchedSelector = ms.matchedSelector
			as.BlockReason = ms.reason
		case wire.MonitorStatusUnsupported:
			as.ExecutionState = execUnsupported
			as.ReasonCode = reasonUnsupported
			as.BlockReason = ms.reason
		default:
			// Unknown reported status — treat as not yet confirmed rather than trust it.
			as.ExecutionState = execPending
			as.ReasonCode = reasonAwaitingStatus
			as.PendingSince = pendingSince(t, ms)
		}
	}

	// probe_state (independent of execution). host / disabled → not_applicable.
	if t.kind == "host" || !t.enabled {
		as.ProbeState = probeNotApplicable
	} else if sk := successKind(t.kind); sk == "" {
		as.ProbeState = probeNotApplicable
	} else if sv := samples[pairKey+"\x00"+sk]; sv == nil || sampleBeforeCutoff(sv.ts, cutoff) {
		// No current-generation sample, or the only one predates this pair's assignment
		// cutoff (pre-assignment history) → honest no_data.
		as.ProbeState = probeNoData
	} else {
		v := sv.value
		as.LastValue = &v
		as.LastMetricKind = sv.kind
		as.LastUnit = sv.unit
		lo := time.Unix(sv.ts, 0).UTC()
		as.LastObservedAt = &lo
		switch {
		case now.Sub(lo) > staleAfter:
			as.ProbeState = probeStale
		case t.kind == "icmp" || t.kind == "gateway":
			if sv.value >= 100 {
				as.ProbeState = probeFailed
			} else {
				as.ProbeState = probeHealthy
			}
		default:
			if sv.value >= 0.5 {
				as.ProbeState = probeHealthy
			} else {
				as.ProbeState = probeFailed
			}
		}
	}

	// rule_state + active conditions (from current condition state / firing alerts;
	// never from frozen evidence).
	anySatisfied, anyAlerting := false, false
	for _, cid := range condIDs {
		st, ok := condStateByKey[cid+"\x00"+p.agentID]
		if !ok || !st.satisfied {
			continue
		}
		// Ignore a satisfied verdict last evaluated before this pair's assignment
		// cutoff: it is pre-assignment condition state (SRV-007) and must not read as a
		// current breach after scope re-entry. Post-reassignment evaluations refresh
		// last_eval_at past the cutoff and are kept.
		if st.lastEvalAt.Valid && beforeCutoff(st.lastEvalAt.Time.UTC(), cutoff) {
			continue
		}
		anySatisfied = true
		meta := condMetaByID[cid]
		ac := ActiveCondition{
			ConditionID: cid, RuleID: meta.ruleID, RuleName: meta.ruleName,
			Severity: meta.severity, MetricKind: meta.metricKind,
			Comparator: meta.comparator, Threshold: meta.threshold,
		}
		if st.lastValue.Valid {
			lv := st.lastValue.Float64
			ac.LastValue = &lv
		}
		if u := samples[pairKey+"\x00"+meta.metricKind]; u != nil {
			ac.Unit = u.unit
		}
		if st.firstBreachAt.Valid {
			fb := st.firstBreachAt.Time.UTC()
			ac.FirstBreachAt = &fb
		}
		if al, ok := firing[meta.ruleID+"\x00"+p.agentID]; ok {
			ac.AlertID = al.alertID
			ac.IncidentID = al.incidentID
			anyAlerting = true
		}
		as.ActiveConditions = append(as.ActiveConditions, ac)
	}
	sort.Slice(as.ActiveConditions, func(i, j int) bool {
		a, b := as.ActiveConditions[i], as.ActiveConditions[j]
		if ra, rb := severityRank[a.Severity], severityRank[b.Severity]; ra != rb {
			return ra > rb // severity rank DESC
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.ConditionID < b.ConditionID
	})
	switch {
	case anyAlerting:
		as.RuleState = ruleAlerting
	case anySatisfied:
		as.RuleState = ruleBreaching
	default:
		as.RuleState = ruleNormal
	}

	// Reason code for a collecting pair reflects the most significant live signal.
	if as.ExecutionState == execCollecting {
		switch {
		case as.RuleState == ruleAlerting:
			as.ReasonCode = reasonAlertFiring
		case as.RuleState == ruleBreaching:
			as.ReasonCode = reasonRuleBreaching
		case as.ProbeState == probeFailed:
			as.ReasonCode = reasonProbeFailed
		case as.ProbeState == probeStale:
			as.ReasonCode = reasonProbeStale
		case as.ProbeState == probeNoData:
			as.ReasonCode = reasonProbeNoData
		case as.ProbeState == probeNotApplicable:
			as.ReasonCode = reasonNotApplicable
		default:
			as.ReasonCode = reasonOK
		}
	}

	agg := agentAgg{exec: as.ExecutionState, probe: as.ProbeState, rule: as.RuleState, online: p.online}
	if as.ExecutionState == execPending && as.PendingSince != nil {
		agg.pendingExpired = now.Sub(*as.PendingSince) > graceWindow
	}
	return as, agg
}

// aggregate applies the fixed display-priority decision table to a target's
// per-agent classifications, returning the target display_state and the
// affected_agents count — the number of agents in an abnormal state. A healthy
// display (including host targets and healthy-with-degraded-minority) is not a
// problem, so its affected count is 0. First matching rule wins.
func aggregate(t *targetRow, agents []agentAgg) (string, int) {
	if !t.enabled {
		return displayDisabled, 0
	}
	e := len(agents)
	if e == 0 {
		return displayUnassigned, 0
	}

	var collecting, healthy, failed, stale, nodata, notappl int
	var blocked, offline, pendingFresh, pendingExpired int
	var alerting, breaching int
	onlineAny := false
	for _, a := range agents {
		if a.online {
			onlineAny = true
		}
		switch a.rule {
		case ruleAlerting:
			alerting++
		case ruleBreaching:
			breaching++
		}
		switch a.exec {
		case execCollecting:
			collecting++
			switch a.probe {
			case probeHealthy:
				healthy++
			case probeFailed:
				failed++
			case probeStale:
				stale++
			case probeNoData:
				nodata++
			case probeNotApplicable:
				notappl++
			}
		case execPermissionBlocked, execTargetBlocked, execUnsupported:
			blocked++
		case execAgentOffline:
			offline++
		case execPending:
			if a.pendingExpired {
				pendingExpired++
			} else {
				pendingFresh++
			}
		}
	}
	x := collecting
	xMinusA := x - notappl // collecting, probe-applicable agents

	switch {
	case alerting > 0:
		return displayAlerting, alerting
	case breaching > 0:
		return displayBreaching, breaching
	case failed > 0 && failed == xMinusA && xMinusA > 0:
		return displayProbeFailed, failed
	case failed > 0:
		return displayPartialFailure, failed
	case x == 0 && blocked == e:
		return displayBlocked, e
	case x == 0 && !onlineAny:
		return displayAgentOffline, e
	case x == 0 && pendingFresh >= 1:
		return displayPending, pendingFresh
	case x == 0 && pendingExpired >= 1:
		return displayNoData, pendingExpired
	case x == 0:
		return displayBlocked, blocked
	case healthy > 0:
		return displayHealthy, 0
	case stale > 0:
		return displayStale, stale
	case nodata > 0:
		return displayNoData, nodata
	default:
		// X non-empty, all not_applicable (host targets collecting normally).
		return displayHealthy, 0
	}
}

// ---- queries (all inside the read snapshot tx; no per-target loop) ----

func (s *Service) loadTargets(ctx context.Context, tx *sql.Tx, siteID string) ([]targetRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT pt.id, pt.group_id, COALESCE(pt.name,''), pt.kind, COALESCE(pt.target,''),
		       pt.enabled, pt.config_serial, pt.config_changed_at, COALESCE(pt.params,''),
		       mg.is_default, mg.name
		FROM probe_tasks pt JOIN monitor_groups mg ON mg.id = pt.group_id
		WHERE pt.site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []targetRow
	for rows.Next() {
		var t targetRow
		var enabled, isDefault int
		var params string
		if err := rows.Scan(&t.id, &t.groupID, &t.name, &t.kind, &t.target,
			&enabled, &t.configSerial, &t.configChangedAt, &params, &isDefault, &t.groupName); err != nil {
			return nil, err
		}
		t.enabled = enabled == 1
		t.groupIsDefault = isDefault == 1
		if params != "" {
			_ = json.Unmarshal([]byte(params), &t.params)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// loadApplicablePairs returns, per target, the non-revoked Agents in the target's
// monitor-group scope (all_agents, or membership of one of the group's agent
// groups). The scope predicate is correlated on a.id (not the shared
// single-placeholder config.AgentScopePredicate).
func (s *Service) loadApplicablePairs(ctx context.Context, tx *sql.Tx, siteID string) (map[string][]applicablePair, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT pt.id, a.id,
		       COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), a.id), a.status
		FROM probe_tasks pt
		JOIN agents a ON a.site_id = pt.site_id AND a.revoked=0 AND EXISTS(
		    SELECT 1 FROM monitor_groups mg
		    WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
		        SELECT 1 FROM monitor_group_agent_groups mgag
		        JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
		        WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = a.id)))
		WHERE pt.site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]applicablePair{}
	for rows.Next() {
		var targetID, status string
		var p applicablePair
		if err := rows.Scan(&targetID, &p.agentID, &p.agentName, &status); err != nil {
			return nil, err
		}
		p.online = status == "online"
		out[targetID] = append(out[targetID], p)
	}
	return out, rows.Err()
}

func (s *Service) loadMonitorStatus(ctx context.Context, tx *sql.Tx, siteID string) (map[string]*msRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT ms.monitor_id, ms.agent_id, ms.status, ms.source, ms.target_config_serial,
		       ms.assigned_at, ms.missing_permissions, COALESCE(ms.matched_selector,''),
		       COALESCE(ms.reason,''), ms.effective_interval_seconds, ms.cycle_deadline_ms
		FROM monitor_status ms JOIN probe_tasks pt ON pt.id = ms.monitor_id
		WHERE pt.site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*msRow{}
	for rows.Next() {
		var monitorID, agentID, missing string
		m := &msRow{}
		if err := rows.Scan(&monitorID, &agentID, &m.status, &m.source, &m.targetConfigSerial,
			&m.assignedAt, &missing, &m.matchedSelector, &m.reason, &m.effInterval, &m.cycleDeadline); err != nil {
			return nil, err
		}
		m.missing = decodeStrings(missing)
		out[monitorID+"\x00"+agentID] = m
	}
	return out, rows.Err()
}

// loadLatestSamples returns the latest CURRENT-GENERATION sample per (monitor,
// agent, kind). The series↔probe_tasks join on config_serial structurally
// excludes every obsolete generation: a target's samples from before its last
// material change are simply not joined, so an old good sample can never surface
// as current (and a pending pair, whose new-generation series does not exist yet,
// yields no row → honest no_data).
func (s *Service) loadLatestSamples(ctx context.Context, tx *sql.Tx, siteID string) (map[string]*sampleVal, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT s.monitor_id, s.agent_id, s.kind, s.unit,
		       (SELECT ts    FROM samples WHERE series_id=s.id ORDER BY ts DESC LIMIT 1),
		       (SELECT value FROM samples WHERE series_id=s.id ORDER BY ts DESC LIMIT 1)
		FROM series s
		JOIN probe_tasks pt ON pt.id = s.monitor_id AND s.config_serial = pt.config_serial
		WHERE s.site_id=? AND s.monitor_id <> ''`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*sampleVal{}
	for rows.Next() {
		var monitorID, agentID string
		var ts sql.NullInt64
		var value sql.NullFloat64
		sv := &sampleVal{}
		if err := rows.Scan(&monitorID, &agentID, &sv.kind, &sv.unit, &ts, &value); err != nil {
			return nil, err
		}
		if !ts.Valid { // a series with no samples yet
			continue
		}
		sv.ts = ts.Int64
		sv.value = value.Float64
		out[monitorID+"\x00"+agentID+"\x00"+sv.kind] = sv
	}
	return out, rows.Err()
}

// loadConditions returns the site's enabled group-rule conditions (meta by id,
// per-(condition,agent) current state, and condition ids grouped by target). Rule
// state is derived from these, never from frozen alert_evidence.
func (s *Service) loadConditions(ctx context.Context, tx *sql.Tx, siteID string) (
	map[string]condMeta, map[string]condState, map[string][]string, error) {

	rows, err := tx.QueryContext(ctx, `
		SELECT c.id, c.rule_id, c.target_id, c.metric_kind, c.comparator, c.threshold,
		       gr.name, gr.severity,
		       rcs.agent_id, rcs.satisfied, rcs.last_value, rcs.first_breach_at, rcs.last_eval_at
		FROM group_rule_conditions c
		JOIN group_rules gr ON gr.id = c.rule_id
		LEFT JOIN rule_condition_state rcs ON rcs.condition_id = c.id
		WHERE gr.site_id=? AND gr.enabled=1`, siteID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	metaByID := map[string]condMeta{}
	stateByKey := map[string]condState{}
	for rows.Next() {
		var cid string
		var m condMeta
		var agentID sql.NullString
		var satisfied sql.NullInt64
		var lastValue sql.NullFloat64
		var firstBreach sql.NullTime
		var lastEval sql.NullTime
		if err := rows.Scan(&cid, &m.ruleID, &m.targetID, &m.metricKind, &m.comparator, &m.threshold,
			&m.ruleName, &m.severity, &agentID, &satisfied, &lastValue, &firstBreach, &lastEval); err != nil {
			return nil, nil, nil, err
		}
		metaByID[cid] = m
		if agentID.Valid {
			stateByKey[cid+"\x00"+agentID.String] = condState{
				satisfied:     satisfied.Valid && satisfied.Int64 == 1,
				lastValue:     lastValue,
				firstBreachAt: firstBreach,
				lastEvalAt:    lastEval,
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	idsByTarget := map[string][]string{}
	for cid, m := range metaByID {
		idsByTarget[m.targetID] = append(idsByTarget[m.targetID], cid)
	}
	return metaByID, stateByKey, idsByTarget, nil
}

func (s *Service) loadFiringAlerts(ctx context.Context, tx *sql.Tx, siteID string) (map[string]firingAlert, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT COALESCE(rule_id,''), agent_id, id, COALESCE(incident_id,'')
		FROM alerts WHERE site_id=? AND state='firing'`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]firingAlert{}
	for rows.Next() {
		var ruleID, agentID, alertID, incidentID string
		if err := rows.Scan(&ruleID, &agentID, &alertID, &incidentID); err != nil {
			return nil, err
		}
		if ruleID == "" {
			continue // a firing alert always has a live rule; defensive
		}
		out[ruleID+"\x00"+agentID] = firingAlert{alertID: alertID, incidentID: incidentID}
	}
	return out, rows.Err()
}

// ---- helpers ----

// successKind maps a probe target kind to the metric kind whose latest value
// decides probe success/failure. host (and any kind without a universal success
// metric) returns "" → not_applicable.
func successKind(kind string) string {
	switch kind {
	case "icmp", "gateway":
		return "probe.icmp.loss_pct"
	case "tcp":
		return "probe.tcp.ok"
	case "http":
		return "probe.http.ok"
	case "dns":
		return "probe.dns.ok"
	case "nat":
		return "probe.nat.ok"
	}
	return ""
}

// pendingSince is the per-pair pending clock: the later of the target's material// generation time (config_changed_at) and the row's assigned_at (present once a
// prediction/report exists for the pair). Nil only when neither is known.
func pendingSince(t *targetRow, ms *msRow) *time.Time {
	var best *time.Time
	if t.configChangedAt.Valid {
		v := t.configChangedAt.Time.UTC()
		best = &v
	}
	if ms != nil && ms.assignedAt.Valid {
		v := ms.assignedAt.Time.UTC()
		if best == nil || v.After(*best) {
			best = &v
		}
	}
	return best
}

// beforeCutoff reports whether a fact observed at ts predates the pair's assignment
// cutoff. A nil cutoff (neither config_changed_at nor assigned_at known) excludes
// nothing. Used by the current-state reads so pre-assignment samples/verdicts never
// surface as current (SRV-007).
func beforeCutoff(ts time.Time, cutoff *time.Time) bool {
	return cutoff != nil && ts.Before(*cutoff)
}

// sampleBeforeCutoff reports whether a probe sample predates the pair's assignment
// cutoff, compared at second granularity. samples.ts is stored as integer Unix
// seconds (metrics writes m.TS.Unix()), while the cutoff (config_changed_at /
// assigned_at) retains sub-second precision. Reconstructing the sample as
// time.Unix(ts, 0) floors it to the start of its second, so a genuinely
// post-assignment sample stored in the same Unix second as the cutoff would sort
// Before a fractional cutoff and be dropped as pre-assignment history — leaving the
// pair no_data for a full probe interval (up to ~30 min for NAT) (SRV-017).
// Comparing ts < cutoff.Unix() admits a same-second post-assignment sample while
// still rejecting genuinely earlier seconds; the config_serial join in
// loadLatestSamples already excludes true old-generation samples, so real
// pre-assignment history is not resurrected. This deliberately differs from the
// condition-state path, which keeps full-precision beforeCutoff: last_eval_at is a
// full-precision Go timestamp, not a truncated integer second, so it has no
// granularity mismatch to correct.
func sampleBeforeCutoff(ts int64, cutoff *time.Time) bool {
	return cutoff != nil && ts < cutoff.Unix()
}

func severityName(rank int) string {
	for name, r := range severityRank {
		if r == rank {
			return name
		}
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if out == nil {
		return []string{}
	}
	return out
}

func nonNilStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

func decodeStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// sortTargets orders the assembled targets deterministically: monitor group
// (default first, then group name), then target (kind, name, id). It sorts the
// output slice using the parallel targetRow group facts.
func sortTargets(out []TargetStatus, meta []targetRow) {
	facts := make(map[string]targetRow, len(meta))
	for _, t := range meta {
		facts[t.id] = t
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := facts[out[i].TargetID], facts[out[j].TargetID]
		if a.groupIsDefault != b.groupIsDefault {
			return a.groupIsDefault // default group first
		}
		if a.groupName != b.groupName {
			return a.groupName < b.groupName
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].TargetID < out[j].TargetID
	})
}
