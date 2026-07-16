// Package opissue is the operational-issue engine for the agent local-permission
// policy. It turns "a monitor is not running" into a deduplicated, operator-facing
// list (operational_issues) plus a per-(agent, monitor) status view
// (monitor_status). Inputs come from three places:
//
//   - the agent's wire.MonitorStatus frames (probe monitors), via ApplyMonitorStatus;
//   - server-side host-metric evaluation (host monitors), via ReevaluateHostMonitors;
//   - a save-time prediction of probe monitors, via PredictProbeMonitors.
//
// Scope narrowing / disabling is reconciled by ReconcileScope. Every mutation
// follows commit-then-publish: DB work in one transaction, then a single
// TopicIssueChanged per affected site so the SSE broker refreshes connected
// consoles. Issues are deliberately kept OUT of alert/incident evaluation — they
// describe why telemetry is absent, not a telemetry threshold breach.
package opissue

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/store"
)

const categoryMonitor = "monitor"

// Service owns the operational-issue tables and publishes change notifications.
type Service struct {
	db  *store.DB
	bus *eventbus.Bus
}

// New constructs the service. bus may be nil in tests (change notifications are
// then simply not published).
func New(db *store.DB, bus *eventbus.Bus) *Service {
	return &Service{db: db, bus: bus}
}

// Remediation is the actionable fix rendered next to an issue or a denied
// snapshot scope. permission_blocked yields a full NETTACT_AGENT_PERMISSIONS line
// (granted ∪ missing, closed over dependencies); unsupported yields no env line
// (the build/platform cannot do it); target_blocked yields only the matched
// selector (the resolved private address is never leaked — the agent decides what
// the selector reveals).
type Remediation struct {
	Reason          string `json:"reason"`
	PermissionsEnv  string `json:"permissions_env,omitempty"`
	MatchedSelector string `json:"matched_selector,omitempty"`
}

// Remediate builds the remediation object for a blocked reason. granted and
// missing are wire permission strings; matchedSelector is only used for
// target_blocked.
func Remediate(reason string, missing, granted []string, matchedSelector string) *Remediation {
	rem := &Remediation{Reason: reason}
	switch reason {
	case wire.MonitorStatusPermissionBlocked:
		set := permission.FromStrings(granted)
		for _, id := range permission.FromStrings(missing).Sorted() {
			set.Add(id)
		}
		rem.PermissionsEnv = "NETTACT_AGENT_PERMISSIONS=" + strings.Join(permission.Closure(set).Strings(), ",")
	case wire.MonitorStatusTargetBlocked:
		rem.MatchedSelector = matchedSelector
	case wire.MonitorStatusUnsupported:
		// No env line: the build/platform does not support it, so no policy change helps.
	}
	return rem
}

// Issue is one operational issue enriched with display + remediation fields.
type Issue struct {
	ID                 string       `json:"id"`
	SiteID             string       `json:"site_id"`
	AgentID            string       `json:"agent_id"`
	AgentName          string       `json:"agent_name"`
	Category           string       `json:"category"`
	RefID              string       `json:"ref_id"`
	MonitorName        string       `json:"monitor_name"`
	Reason             string       `json:"reason"`
	MissingPermissions []string     `json:"missing_permissions"`
	MatchedSelector    string       `json:"matched_selector"`
	PolicyHash         string       `json:"policy_hash"`
	State              string       `json:"state"`
	Read               bool         `json:"read"`
	Count              int          `json:"count"`
	FirstSeenAt        time.Time    `json:"first_seen_at"`
	LastSeenAt         time.Time    `json:"last_seen_at"`
	ResolvedAt         *time.Time   `json:"resolved_at"`
	Remediation        *Remediation `json:"remediation,omitempty"`
}

// MonitorStatusRow is one row of the per-(agent, monitor) status view.
type MonitorStatusRow struct {
	AgentID            string    `json:"agent_id"`
	AgentName          string    `json:"agent_name,omitempty"`
	MonitorID          string    `json:"monitor_id"`
	MonitorName        string    `json:"monitor_name,omitempty"`
	Kind               string    `json:"kind,omitempty"`
	Target             string    `json:"target,omitempty"`
	Status             string    `json:"status"`
	MissingPermissions []string  `json:"missing_permissions"`
	MatchedSelector    string    `json:"matched_selector,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	PolicyHash         string    `json:"policy_hash,omitempty"`
	ConfigVersion      int       `json:"config_version"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// SaveWarning is a monitor-save pre-check finding: a monitor that some (or all)
// in-scope agents cannot run under their current permission policy. It carries
// both the aggregate counts and the per-agent breakdown so the UI can name the
// capable and blocked agents independently (acceptance criterion 8).
type SaveWarning struct {
	MonitorID          string             `json:"monitor_id"`
	MonitorName        string             `json:"monitor_name"`
	Status             string             `json:"status"` // worst: permission_blocked | unsupported
	AffectedAgents     int                `json:"affected_agents"`
	CapableAgents      int                `json:"capable_agents"`
	MissingPermissions []string           `json:"missing_permissions"`
	BlockedAgents      []SaveWarningAgent `json:"blocked_agents"`
	// CapableAgentList names the in-scope agents that CAN run the monitor, so the UI
	// can present capable and blocked agents independently rather than only a count.
	CapableAgentList []SaveWarningAgent `json:"capable_agent_list"`
}

// SaveWarningAgent is one agent within a SaveWarning: its identity, its block
// status (active when capable), and the permissions it is missing (empty when
// capable).
type SaveWarningAgent struct {
	AgentID            string   `json:"agent_id"`
	AgentName          string   `json:"agent_name"`
	Status             string   `json:"status"` // active | permission_blocked | unsupported
	MissingPermissions []string `json:"missing_permissions"`
}

// ---- ingestion: agent-reported probe monitor status ----

// ApplyMonitorStatus ingests one MonitorStatus frame (the agent's full-state view
// of its probe monitors for a given config_version) and reconciles monitor_status
// rows + operational_issues. The monotonic guard drops a frame whose
// config_version is older than either the newest already accepted or the server's
// current desired config_version for the agent; equal versions are accepted so a
// runtime target-policy transition, or a policy-changing restart with unchanged
// DesiredState, is still recorded.
func (s *Service) ApplyMonitorStatus(ctx context.Context, agentID, siteID string, ms wire.MonitorStatus) error {
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

	var lastAccepted, desired int
	err = tx.QueryRowContext(ctx,
		`SELECT last_status_config_version, config_version FROM agents WHERE id=?`, agentID).
		Scan(&lastAccepted, &desired)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil // agent gone; nothing to reconcile
		}
		return err
	}
	// Monotonic guard: reject stale frames (older than what we accepted or than
	// the desired config we last pushed). Equal is valid.
	if ms.ConfigVersion < lastAccepted || ms.ConfigVersion < desired {
		return nil
	}

	// Only monitors that are enabled and in this agent's scope are valid targets; a
	// stale or misbehaving agent must not create status/issues for monitors it was
	// never assigned.
	valid, err := s.probeMonitorIDs(ctx, tx, siteID, agentID)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	changed := false
	current := make([]string, 0, len(ms.Statuses))
	blocked := map[string]bool{} // dedupe_keys reported blocked this frame
	seen := map[string]bool{}    // monitor ids already handled this frame (reject dupes)

	for _, e := range ms.Statuses {
		if !valid[e.MonitorID] || seen[e.MonitorID] || !validMonitorStatus(e.Status) {
			// Unknown/out-of-scope monitor, a duplicate id, or a non-enum status: ignore
			// rather than mutating status/issues on untrusted input.
			continue
		}
		seen[e.MonitorID] = true
		current = append(current, e.MonitorID)
		if err := upsertMonitorStatus(ctx, tx, agentID, e.MonitorID, e.Status,
			e.MissingPermissions, e.MatchedSelector, e.Reason, ms.PolicyHash, ms.ConfigVersion, now); err != nil {
			return err
		}
		if e.Status == wire.MonitorStatusActive {
			continue
		}
		key := dedupeKey(agentID, categoryMonitor, e.MonitorID, e.Status)
		blocked[key] = true
		wasTransition, err := s.upsertIssue(ctx, tx, issueUpsert{
			siteID: siteID, agentID: agentID, refID: e.MonitorID, reason: e.Status,
			dedupeKey: key, missing: e.MissingPermissions, matchedSelector: e.MatchedSelector,
			policyHash: ms.PolicyHash, now: now,
		})
		if err != nil {
			return err
		}
		changed = changed || wasTransition
	}

	// Delete this agent's PROBE monitor_status rows absent from the frame; host
	// rows are owned by ReevaluateHostMonitors and never touched here.
	if err := deleteAbsentProbeStatus(ctx, tx, agentID, current); err != nil {
		return err
	}

	// Resolve any active PROBE issue for this agent whose exact reason is no longer
	// reported (recovered, or transitioned to a different block reason).
	resolvedAny, err := s.resolveIssuesNotIn(ctx, tx,
		`SELECT oi.id, oi.dedupe_key FROM operational_issues oi
		   JOIN probe_tasks pt ON pt.id = oi.ref_id
		  WHERE oi.agent_id=? AND oi.category=? AND oi.state='active' AND pt.kind<>'host'`,
		[]any{agentID, categoryMonitor}, blocked, now)
	if err != nil {
		return err
	}
	changed = changed || resolvedAny

	if _, err := tx.ExecContext(ctx,
		`UPDATE agents SET last_status_config_version=? WHERE id=?`, ms.ConfigVersion, agentID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	s.publish(changed, siteID)
	return nil
}

// ---- server-side host monitor evaluation ----

// ReevaluateHostMonitors recomputes permission blocks for the agent's in-scope
// host monitors: for each host probe_task, the required host permissions are the
// union of permission.RequiredForHostMetric over its ENABLED bound alert rules,
// closed over dependencies, compared against the agent's stored effective set. A
// host monitor with no bound rules requires nothing and is active. Called after a
// Hello refreshes the agent's permission policy.
func (s *Service) ReevaluateHostMonitors(ctx context.Context, agentID string) error {
	var siteID, effStr, supStr, grantStr, policyHash string
	var configVersion int
	err := s.db.QueryRowContext(ctx,
		`SELECT site_id, config_version, COALESCE(perm_effective,'[]'), COALESCE(perm_supported,'[]'), COALESCE(perm_granted,'[]'), COALESCE(policy_hash,'') FROM agents WHERE id=?`, agentID).
		Scan(&siteID, &configVersion, &effStr, &supStr, &grantStr, &policyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	effective := permission.FromStrings(decodeStrings(effStr))
	supported := permission.FromStrings(decodeStrings(supStr))
	granted := permission.FromStrings(decodeStrings(grantStr))

	rows, err := s.db.QueryContext(ctx, `
		SELECT pt.id FROM probe_tasks pt
		 WHERE pt.site_id=? AND pt.enabled=1 AND pt.kind='host' AND `+config.AgentScopePredicate,
		siteID, agentID)
	if err != nil {
		return err
	}
	var hostIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		hostIDs = append(hostIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
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

	now := time.Now().UTC()
	changed := false
	for _, monitorID := range hostIDs {
		required, err := hostRequired(ctx, tx, monitorID)
		if err != nil {
			return err
		}
		// Classify like the agent (monitoreval.evaluate): a required permission that
		// is granted but not platform-supported is `unsupported`; one that is not
		// granted (or otherwise not effective) is `permission_blocked`. A locally
		// denied permission takes precedence over an unsupported one.
		var missing, unsupported []string
		for _, id := range diff(required, effective) {
			if granted.Has(id) && !supported.Has(id) {
				unsupported = append(unsupported, string(id))
			} else {
				missing = append(missing, string(id))
			}
		}

		status := wire.MonitorStatusActive
		var reasonList []string
		switch {
		case len(missing) > 0:
			status = wire.MonitorStatusPermissionBlocked
			reasonList = missing
		case len(unsupported) > 0:
			status = wire.MonitorStatusUnsupported
			reasonList = unsupported
		}

		if err := upsertMonitorStatus(ctx, tx, agentID, monitorID, status,
			reasonList, "", "", policyHash, configVersion, now); err != nil {
			return err
		}
		if status == wire.MonitorStatusActive {
			// Resolve any active issue for this pair regardless of prior reason.
			resolved, err := s.resolveMonitorIssuesExcept(ctx, tx, agentID, monitorID, "", now)
			if err != nil {
				return err
			}
			changed = changed || resolved
			continue
		}
		wasTransition, err := s.upsertIssue(ctx, tx, issueUpsert{
			siteID: siteID, agentID: agentID, refID: monitorID, reason: status,
			dedupeKey: dedupeKey(agentID, categoryMonitor, monitorID, status),
			missing:   reasonList, policyHash: policyHash, now: now,
		})
		if err != nil {
			return err
		}
		changed = changed || wasTransition
		// If the monitor flipped between block reasons (e.g. permission_blocked →
		// unsupported), resolve the stale issue of the other reason.
		resolved, err := s.resolveMonitorIssuesExcept(ctx, tx, agentID, monitorID, status, now)
		if err != nil {
			return err
		}
		changed = changed || resolved
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	s.publish(changed, siteID)
	return nil
}

// ReevaluateHostMonitorsForSite reevaluates host monitors for every non-revoked
// agent in the site. It is called wherever a host monitor, its bound rules, or an
// agent's group scope changes — none of which arrive via an agent frame, so the
// server must recompute the affected pairs immediately rather than wait for a
// reconnect.
func (s *Service) ReevaluateHostMonitorsForSite(ctx context.Context, siteID string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM agents WHERE site_id=? AND revoked=0`, siteID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.ReevaluateHostMonitors(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// hostRequired returns the closure of host permissions required by a host
// monitor's enabled group-rule conditions. No conditions ⇒ empty set (always
// active).
func hostRequired(ctx context.Context, tx *sql.Tx, monitorID string) (permission.Set, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.metric_kind FROM group_rule_conditions c
		JOIN group_rules gr ON gr.id = c.rule_id
		WHERE c.target_id=? AND gr.enabled=1`, monitorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	req := permission.Set{}
	for rows.Next() {
		var mk string
		if err := rows.Scan(&mk); err != nil {
			return nil, err
		}
		for _, id := range permission.RequiredForHostMetric(mk) {
			req.Add(id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return permission.Closure(req), nil
}

// ---- scope reconciliation ----

// ReconcileScope resolves issues and drops monitor_status rows for monitors that
// are now disabled or out of an agent's group/site scope, even while the agent is
// offline (deletion of a monitor is handled separately by FK ON DELETE CASCADE).
// Call it wherever monitoring scope mutates — the same sites that call
// alert.Service.ResolveOutOfScope.
func (s *Service) ReconcileScope(ctx context.Context, siteID string) error {
	// Correlated NOT-in-scope predicate: a monitor_status row is stranded when its
	// monitor is disabled, or the row's agent is not covered by the monitor group's
	// Agent scope (group broadcasts, or the agent is in one of its agent groups).
	// Correlated on ms.agent_id (so it is NOT the shared single-placeholder
	// config.AgentScopePredicate).
	rows, err := s.db.QueryContext(ctx, `
		SELECT ms.agent_id, ms.monitor_id FROM monitor_status ms
		  JOIN probe_tasks pt ON pt.id = ms.monitor_id
		 WHERE pt.site_id=? AND (pt.enabled=0 OR NOT EXISTS(
		    SELECT 1 FROM monitor_groups mg
		    WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
		        SELECT 1 FROM monitor_group_agent_groups mgag
		        JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
		        WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = ms.agent_id))))`, siteID)
	if err != nil {
		return err
	}
	type row struct{ agentID, monitorID string }
	var stranded []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.agentID, &r.monitorID); err != nil {
			rows.Close()
			return err
		}
		stranded = append(stranded, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(stranded) == 0 {
		return nil
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
	now := time.Now().UTC()
	changed := false
	for _, r := range stranded {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM monitor_status WHERE agent_id=? AND monitor_id=?`, r.agentID, r.monitorID); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE operational_issues SET state='resolved', resolved_at=?
			  WHERE agent_id=? AND category=? AND ref_id=? AND state='active'`,
			now, r.agentID, categoryMonitor, r.monitorID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			changed = true
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	s.publish(changed, siteID)
	return nil
}

// ---- monitor-save prediction ----

// PredictProbeMonitors upserts predicted monitor_status rows for every in-scope
// agent of every enabled probe monitor in the site, using each agent's stored
// permission policy, and returns per-monitor warnings for monitors that some or
// all in-scope agents cannot run. It is a save-and-warn pass: it never blocks the
// save, and the agent's real MonitorStatus frame later overwrites the prediction.
func (s *Service) PredictProbeMonitors(ctx context.Context, siteID string) ([]SaveWarning, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, COALESCE(name,''), COALESCE(target,''), COALESCE(params,'') FROM probe_tasks
		  WHERE site_id=? AND kind<>'host' AND enabled=1`, siteID)
	if err != nil {
		return nil, err
	}
	type predTarget struct {
		id string
		pt pcfg.ProbeTarget
	}
	var targets []predTarget
	for rows.Next() {
		var t predTarget
		var params string
		if err := rows.Scan(&t.id, &t.pt.Kind, &t.pt.Name, &t.pt.Target, &params); err != nil {
			rows.Close()
			return nil, err
		}
		if params != "" {
			_ = json.Unmarshal([]byte(params), &t.pt.Params)
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	now := time.Now().UTC()
	var warnings []SaveWarning
	for _, t := range targets {
		required := permission.Closure(permission.NewSet(permission.RequiredForTarget(t.pt)...))
		agents, err := scopedAgents(ctx, tx, siteID, t.id)
		if err != nil {
			return nil, err
		}
		capable, affected := 0, 0
		worst := ""
		missingUnion := permission.Set{}
		var blockedAgents, capableAgents []SaveWarningAgent
		for _, a := range agents {
			// Classify exactly like the agent (monitoreval / ReevaluateHostMonitors): a
			// required permission that is granted but not platform-supported is
			// `unsupported`; one that is not granted is `permission_blocked` and remedied
			// by an environment grant. A locally denied permission takes precedence over
			// an unsupported one. Using perm_granted here is what keeps prediction from
			// mislabeling an ungranted permission as unsupported.
			var missBlocked, missUnsupported []permission.ID
			for _, id := range diff(required, a.effective) {
				if a.granted.Has(id) && !a.supported.Has(id) {
					missUnsupported = append(missUnsupported, id)
				} else {
					missBlocked = append(missBlocked, id)
				}
			}
			status := wire.MonitorStatusActive
			var reasonList []permission.ID
			switch {
			case len(missBlocked) > 0:
				status = wire.MonitorStatusPermissionBlocked
				reasonList = missBlocked
			case len(missUnsupported) > 0:
				status = wire.MonitorStatusUnsupported
				reasonList = missUnsupported
			}
			if status == wire.MonitorStatusActive {
				capable++
				capableAgents = append(capableAgents, SaveWarningAgent{
					AgentID: a.id, AgentName: a.name, Status: status,
				})
			} else {
				affected++
				for _, id := range reasonList {
					missingUnion.Add(id)
				}
				if worst == "" || status == wire.MonitorStatusUnsupported {
					worst = status
				}
				blockedAgents = append(blockedAgents, SaveWarningAgent{
					AgentID: a.id, AgentName: a.name, Status: status,
					MissingPermissions: setStrings(reasonList),
				})
			}
			if err := upsertPredictedStatus(ctx, tx, a.id, t.id, status,
				setStrings(reasonList), a.policyHash, a.configVersion, now); err != nil {
				return nil, err
			}
		}
		if affected > 0 || len(agents) == 0 {
			if worst == "" {
				worst = wire.MonitorStatusPermissionBlocked
			}
			warnings = append(warnings, SaveWarning{
				MonitorID: t.id, MonitorName: monitorLabel(t.pt.Name, t.pt.Target),
				Status: worst, AffectedAgents: affected, CapableAgents: capable,
				MissingPermissions: missingUnion.Strings(),
				BlockedAgents:      blockedAgents,
				CapableAgentList:   capableAgents,
			})
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	committed = true
	return warnings, nil
}

type scopedAgent struct {
	id            string
	name          string
	configVersion int
	effective     permission.Set
	granted       permission.Set
	supported     permission.Set
	policyHash    string
}

// scopedAgents returns the non-revoked agents in a monitor's scope, with their
// stored permission policy, for prediction.
func scopedAgents(ctx context.Context, tx *sql.Tx, siteID, monitorID string) ([]scopedAgent, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), a.id),
		       a.config_version, COALESCE(a.perm_effective,'[]'), COALESCE(a.perm_granted,'[]'), COALESCE(a.perm_supported,'[]'), COALESCE(a.policy_hash,'')
		FROM agents a, probe_tasks pt
		WHERE pt.id=? AND a.site_id=? AND a.revoked=0 AND EXISTS(
		    SELECT 1 FROM monitor_groups mg
		    WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
		        SELECT 1 FROM monitor_group_agent_groups mgag
		        JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
		        WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = a.id)))`, monitorID, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scopedAgent
	for rows.Next() {
		var a scopedAgent
		var eff, grant, sup string
		if err := rows.Scan(&a.id, &a.name, &a.configVersion, &eff, &grant, &sup, &a.policyHash); err != nil {
			return nil, err
		}
		a.effective = permission.FromStrings(decodeStrings(eff))
		a.granted = permission.FromStrings(decodeStrings(grant))
		a.supported = permission.FromStrings(decodeStrings(sup))
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- read side ----

// List returns the site's active operational issues, newest first, each with a
// remediation object.
func (s *Service) List(ctx context.Context, siteID string) ([]Issue, error) {
	return s.queryIssues(ctx,
		`WHERE oi.site_id=? AND oi.state='active' ORDER BY oi.last_seen_at DESC`, siteID)
}

// ListForConsole returns the site's active issues plus the most recently resolved
// ones so a connected console can show a resolution (the requirement that
// resolution is also visible), not just have the row vanish. Active issues sort
// first (newest by last_seen), then resolved (newest by resolved_at), bounded so
// the history cannot grow without limit.
func (s *Service) ListForConsole(ctx context.Context, siteID string) ([]Issue, error) {
	return s.queryIssues(ctx,
		`WHERE oi.site_id=? AND (oi.state='active' OR oi.resolved_at IS NOT NULL)
		 ORDER BY CASE WHEN oi.state='active' THEN 0 ELSE 1 END,
		          COALESCE(oi.resolved_at, oi.last_seen_at) DESC
		 LIMIT 200`, siteID)
}

// ListForAgent returns an agent's active operational issues, newest first.
func (s *Service) ListForAgent(ctx context.Context, agentID string) ([]Issue, error) {
	return s.queryIssues(ctx,
		`WHERE oi.agent_id=? AND oi.state='active' ORDER BY oi.last_seen_at DESC`, agentID)
}

func (s *Service) queryIssues(ctx context.Context, where string, args ...any) ([]Issue, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT oi.id, oi.site_id, oi.agent_id,
		       COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), oi.agent_id),
		       oi.category, COALESCE(oi.ref_id,''),
		       COALESCE(NULLIF(pt.name,''), COALESCE(pt.target,''), ''),
		       oi.reason, oi.missing_permissions, oi.matched_selector, oi.policy_hash,
		       oi.state, oi.read, oi.count, oi.first_seen_at, oi.last_seen_at, oi.resolved_at,
		       COALESCE(a.perm_granted,'[]')
		FROM operational_issues oi
		LEFT JOIN agents a ON a.id = oi.agent_id
		LEFT JOIN probe_tasks pt ON pt.id = oi.ref_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Issue
	for rows.Next() {
		var i Issue
		var missing, granted string
		var read int
		var resolvedAt sql.NullTime
		if err := rows.Scan(&i.ID, &i.SiteID, &i.AgentID, &i.AgentName, &i.Category, &i.RefID,
			&i.MonitorName, &i.Reason, &missing, &i.MatchedSelector, &i.PolicyHash,
			&i.State, &read, &i.Count, &i.FirstSeenAt, &i.LastSeenAt, &resolvedAt, &granted); err != nil {
			return nil, err
		}
		i.MissingPermissions = decodeStrings(missing)
		i.Read = read == 1
		if resolvedAt.Valid {
			t := resolvedAt.Time
			i.ResolvedAt = &t
		}
		i.Remediation = Remediate(i.Reason, i.MissingPermissions, decodeStrings(granted), i.MatchedSelector)
		out = append(out, i)
	}
	return out, rows.Err()
}

// UnreadCount returns the number of active, unread issues for a site.
func (s *Service) UnreadCount(ctx context.Context, siteID string) (int, error) {
	var n int
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM operational_issues WHERE site_id=? AND state='active' AND read=0`, siteID).Scan(&n)
	return n, err
}

// MarkRead marks the given active issues read (all active issues of the site when
// ids is empty) and publishes a change so consoles refresh their unread badge.
func (s *Service) MarkRead(ctx context.Context, siteID string, ids []string) error {
	var res sql.Result
	var err error
	if len(ids) == 0 {
		res, err = s.db.ExecContext(ctx,
			`UPDATE operational_issues SET read=1 WHERE site_id=? AND state='active' AND read=0`, siteID)
	} else {
		q := `UPDATE operational_issues SET read=1 WHERE site_id=? AND state='active' AND read=0 AND id IN (` +
			placeholders(len(ids)) + `)`
		args := make([]any, 0, len(ids)+1)
		args = append(args, siteID)
		for _, id := range ids {
			args = append(args, id)
		}
		res, err = s.db.ExecContext(ctx, q, args...)
	}
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	s.publish(n > 0, siteID)
	return nil
}

// AgentStatuses returns the per-monitor status rows for one agent.
func (s *Service) AgentStatuses(ctx context.Context, agentID string) ([]MonitorStatusRow, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT ms.agent_id, ms.monitor_id, COALESCE(pt.name,''), COALESCE(pt.kind,''), COALESCE(pt.target,''),
		       ms.status, ms.missing_permissions, ms.matched_selector, ms.reason, ms.policy_hash, ms.config_version, ms.updated_at
		FROM monitor_status ms LEFT JOIN probe_tasks pt ON pt.id = ms.monitor_id
		WHERE ms.agent_id=? ORDER BY pt.kind, pt.target`, agentID)
	if err != nil {
		return nil, err
	}
	return scanMonitorRows(rows, false)
}

// MonitorStatuses returns the per-agent status rows for one monitor (target).
func (s *Service) MonitorStatuses(ctx context.Context, monitorID string) ([]MonitorStatusRow, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT ms.agent_id, COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), ms.agent_id),
		       ms.monitor_id, ms.status, ms.missing_permissions, ms.matched_selector, ms.reason,
		       ms.policy_hash, ms.config_version, ms.updated_at
		FROM monitor_status ms LEFT JOIN agents a ON a.id = ms.agent_id
		WHERE ms.monitor_id=? ORDER BY a.hostname`, monitorID)
	if err != nil {
		return nil, err
	}
	return scanMonitorRows(rows, true)
}

func scanMonitorRows(rows *sql.Rows, withAgentName bool) ([]MonitorStatusRow, error) {
	defer rows.Close()
	var out []MonitorStatusRow
	for rows.Next() {
		var m MonitorStatusRow
		var missing string
		var err error
		if withAgentName {
			err = rows.Scan(&m.AgentID, &m.AgentName, &m.MonitorID, &m.Status, &missing,
				&m.MatchedSelector, &m.Reason, &m.PolicyHash, &m.ConfigVersion, &m.UpdatedAt)
		} else {
			err = rows.Scan(&m.AgentID, &m.MonitorID, &m.MonitorName, &m.Kind, &m.Target, &m.Status,
				&missing, &m.MatchedSelector, &m.Reason, &m.PolicyHash, &m.ConfigVersion, &m.UpdatedAt)
		}
		if err != nil {
			return nil, err
		}
		m.MissingPermissions = decodeStrings(missing)
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- shared write helpers ----

type issueUpsert struct {
	siteID, agentID, refID, reason, dedupeKey string
	missing                                   []string
	matchedSelector, policyHash               string
	now                                       time.Time
}

// upsertIssue inserts or refreshes a blocked issue and reports whether this was a
// real transition (a newly created issue, or a resolved→active reactivation) — a
// pure repeat report of an already-active issue only bumps count/last_seen and is
// not treated as a change.
func (s *Service) upsertIssue(ctx context.Context, tx *sql.Tx, u issueUpsert) (bool, error) {
	var prevState string
	err := tx.QueryRowContext(ctx,
		`SELECT state FROM operational_issues WHERE dedupe_key=?`, u.dedupeKey).Scan(&prevState)
	transition := err == sql.ErrNoRows || prevState == "resolved"
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO operational_issues(id, site_id, agent_id, category, ref_id, reason, dedupe_key,
		                               missing_permissions, matched_selector, policy_hash,
		                               state, read, count, first_seen_at, last_seen_at, resolved_at)
		VALUES(?,?,?,?,?,?,?,?,?,?, 'active', 0, 1, ?, ?, NULL)
		ON CONFLICT(dedupe_key) DO UPDATE SET
		  count = count + 1,
		  last_seen_at = excluded.last_seen_at,
		  state = 'active',
		  read = CASE WHEN operational_issues.state='resolved' THEN 0 ELSE operational_issues.read END,
		  missing_permissions = excluded.missing_permissions,
		  matched_selector = excluded.matched_selector,
		  policy_hash = excluded.policy_hash,
		  resolved_at = NULL`,
		"issue_"+uuid.NewString(), u.siteID, u.agentID, categoryMonitor, u.refID, u.reason, u.dedupeKey,
		marshalStrings(u.missing), u.matchedSelector, u.policyHash, u.now, u.now)
	return transition, err
}

// resolveMonitorIssuesExcept resolves every active issue for (agent, monitor)
// whose reason differs from keepReason (pass "" to resolve all reasons, e.g. when
// the monitor is now active). Reports whether any row changed.
func (s *Service) resolveMonitorIssuesExcept(ctx context.Context, tx *sql.Tx, agentID, monitorID, keepReason string, now time.Time) (bool, error) {
	res, err := tx.ExecContext(ctx,
		`UPDATE operational_issues SET state='resolved', resolved_at=?
		  WHERE agent_id=? AND category=? AND ref_id=? AND state='active' AND reason<>?`,
		now, agentID, categoryMonitor, monitorID, keepReason)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// resolveIssuesNotIn resolves every active issue matched by selectSQL whose
// dedupe_key is not in keep, reporting whether any row changed.
func (s *Service) resolveIssuesNotIn(ctx context.Context, tx *sql.Tx, selectSQL string, args []any, keep map[string]bool, now time.Time) (bool, error) {
	rows, err := tx.QueryContext(ctx, selectSQL, args...)
	if err != nil {
		return false, err
	}
	type cand struct{ id, key string }
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.key); err != nil {
			rows.Close()
			return false, err
		}
		cands = append(cands, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	changed := false
	for _, c := range cands {
		if keep[c.key] {
			continue
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE operational_issues SET state='resolved', resolved_at=? WHERE id=? AND state='active'`, now, c.id)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			changed = true
		}
	}
	return changed, nil
}

func upsertMonitorStatus(ctx context.Context, tx *sql.Tx, agentID, monitorID, status string,
	missing []string, matchedSelector, reason, policyHash string, configVersion int, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id, monitor_id, status, missing_permissions, matched_selector,
		                           reason, policy_hash, config_version, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id, monitor_id) DO UPDATE SET
		  status=excluded.status, missing_permissions=excluded.missing_permissions,
		  matched_selector=excluded.matched_selector, reason=excluded.reason,
		  policy_hash=excluded.policy_hash, config_version=excluded.config_version, updated_at=excluded.updated_at`,
		agentID, monitorID, status, marshalStrings(missing), matchedSelector, reason, policyHash, configVersion, now)
	return err
}

// upsertPredictedStatus writes a save-time predicted status, but only when it is
// newer than any existing row (config_version strictly greater). This prevents a
// prediction from overwriting an agent's authoritative status already accepted at
// the same or newer config version — the agent may have applied the pushed
// DesiredState and reported its real status before this save-and-warn pass runs.
func upsertPredictedStatus(ctx context.Context, tx *sql.Tx, agentID, monitorID, status string,
	missing []string, policyHash string, configVersion int, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id, monitor_id, status, missing_permissions, matched_selector,
		                           reason, policy_hash, config_version, updated_at)
		VALUES(?,?,?,?,'','',?,?,?)
		ON CONFLICT(agent_id, monitor_id) DO UPDATE SET
		  status=excluded.status, missing_permissions=excluded.missing_permissions,
		  matched_selector=excluded.matched_selector, reason=excluded.reason,
		  policy_hash=excluded.policy_hash, config_version=excluded.config_version, updated_at=excluded.updated_at
		  WHERE monitor_status.config_version < excluded.config_version`,
		agentID, monitorID, status, marshalStrings(missing), policyHash, configVersion, now)
	return err
}

func deleteAbsentProbeStatus(ctx context.Context, tx *sql.Tx, agentID string, keep []string) error {
	q := `DELETE FROM monitor_status WHERE agent_id=?
		AND monitor_id IN (SELECT id FROM probe_tasks WHERE kind<>'host')`
	args := []any{agentID}
	if len(keep) > 0 {
		q += ` AND monitor_id NOT IN (` + placeholders(len(keep)) + `)`
		for _, id := range keep {
			args = append(args, id)
		}
	}
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}

func (s *Service) probeMonitorIDs(ctx context.Context, tx *sql.Tx, siteID, agentID string) (map[string]bool, error) {
	// Only enabled, non-host monitors currently in THIS agent's server-owned scope
	// are valid targets for an agent-reported status. An agent must not be able to
	// create status/issues for a monitor it was never assigned (or a disabled one).
	rows, err := tx.QueryContext(ctx,
		`SELECT pt.id FROM probe_tasks pt WHERE pt.site_id=? AND pt.kind<>'host' AND pt.enabled=1 AND `+config.AgentScopePredicate,
		siteID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (s *Service) publish(changed bool, siteID string) {
	if changed && s.bus != nil {
		s.bus.Publish(eventbus.TopicIssueChanged, eventbus.IssueChanged{SiteID: siteID})
	}
}

// ---- small utilities ----

func dedupeKey(agentID, category, refID, reason string) string {
	return agentID + "|" + category + "|" + refID + "|" + reason
}

// validMonitorStatus reports whether s is a known agent-reportable monitor status
// (agent_offline / probe_failed are server/console-derived and never agent-sent).
func validMonitorStatus(s string) bool {
	switch s {
	case wire.MonitorStatusActive, wire.MonitorStatusPermissionBlocked,
		wire.MonitorStatusTargetBlocked, wire.MonitorStatusUnsupported:
		return true
	}
	return false
}

func decodeStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func marshalStrings(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

// setStrings returns the wire strings for an ID slice in canonical order.
func setStrings(ids []permission.ID) []string {
	return permission.NewSet(ids...).Strings()
}

// diff returns required \ have as a sorted ID slice.
func diff(required, have permission.Set) []permission.ID {
	var out []permission.ID
	for _, id := range required.Sorted() {
		if !have.Has(id) {
			out = append(out, id)
		}
	}
	return out
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func monitorLabel(name, target string) string {
	if name != "" {
		return name
	}
	return target
}
