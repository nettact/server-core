// Package config manages monitor groups and their monitoring targets
// (probe_tasks) and builds the DesiredState the server pushes down to agents.
//
// Monitor groups (distinct from agent groups) own a static set of targets and
// the Agent execution scope shared by all of them: a group either broadcasts to
// every site agent (all_agents=1) or scopes to the union of referenced agent
// groups. Each site has one undeletable default group. Targets are configured
// centrally in Lite so agents stay near-zero-config; changing them bumps the
// per-agent config_version and publishes TopicConfigChanged so the WebSocket hub
// pushes the new state to connected agents immediately.
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

// Default scheduler intervals delivered to agents (seconds).
const (
	defaultBaseSeconds    = 10
	defaultRegularSeconds = 30
)

// defaultGroupName is the display name of every site's undeletable default
// monitor group. New/unclassified targets land here.
const defaultGroupName = "默认监控组"

// AgentScopePredicate is a SQL boolean fragment for a WHERE clause, true when the
// probe_tasks row aliased "pt" applies to a given agent: either the target's
// monitor group broadcasts to the whole site (all_agents=1) or the agent belongs
// to one of the group's referenced agent groups. The agent id must be bound to
// the single "?" placeholder it contains. It defines target→agent scoping in ONE
// place, shared by the config downlink (DesiredStateFor), the fault engine
// (rules.EvaluateAgent), and the operational-issue engine, so they can never
// drift. Any query using it must alias probe_tasks as "pt".
const AgentScopePredicate = `EXISTS(
	SELECT 1 FROM monitor_groups mg
	WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
		SELECT 1 FROM monitor_group_agent_groups mgag
		JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
		WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = ?)))`

// AlertTerminator is the fault-engine surface config needs to force-resolve
// alerts (and close their incidents) as `configuration_changed` before their
// owning targets/rules are removed. It is injected (satisfied by *rules.Service)
// so config does not import the fault engine — keeping the dependency one-way and
// avoiding an import cycle. Nil-safe callers guard for a nil terminator (tests).
type AlertTerminator interface {
	// TerminateForTargets force-resolves firing alerts whose rule references any of
	// the given targets, recording a configuration termination. Called BEFORE the
	// rows are deleted and OUTSIDE any open write transaction.
	TerminateForTargets(ctx context.Context, targetIDs []string) error
	// TerminateForGroup force-resolves firing alerts of every rule in a monitor
	// group. Used when a custom group is deleted.
	TerminateForGroup(ctx context.Context, groupID string) error
}

type Service struct {
	db   *store.DB
	reg  *registry.Service
	bus  *eventbus.Bus
	term AlertTerminator // force-resolves alerts of removed targets/rules (nil-safe)
}

func New(db *store.DB, reg *registry.Service, bus *eventbus.Bus, term AlertTerminator) *Service {
	return &Service{db: db, reg: reg, bus: bus, term: term}
}

// MonitorGroup is a site-scoped monitor group: a static owner of targets plus the
// Agent execution scope and incident-merge policy shared by all of them.
type MonitorGroup struct {
	ID            string   `json:"id"`
	SiteID        string   `json:"site_id"`
	Name          string   `json:"name"`
	IsDefault     bool     `json:"is_default"`
	MergeEnabled  bool     `json:"merge_enabled"`
	AllAgents     bool     `json:"all_agents"`
	AgentGroupIDs []string `json:"agent_group_ids"`
}

// ProbeTarget is a monitoring target managed via the UI. It belongs to exactly
// one monitor group (GroupID), which owns its Agent scope.
type ProbeTarget struct {
	ID      string           `json:"id"`
	GroupID string           `json:"group_id"` // owning monitor group (required)
	Kind    string           `json:"kind"`     // "icmp" | "dns" | "http" | "tcp" | "nat" | "gateway" | "host"
	Name    string           `json:"name,omitempty"`
	Target  string           `json:"target"`
	Params  pcfg.ProbeParams `json:"params"`
	Enabled bool             `json:"enabled"`
}

// ---- monitor groups ----

// EnsureDefaultGroup creates the site's undeletable default monitor group if it
// does not exist and returns its id. Idempotent (the partial unique index on
// is_default guards against a second default per site).
func (s *Service) EnsureDefaultGroup(ctx context.Context, siteID string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM monitor_groups WHERE site_id=? AND is_default=1`, siteID).Scan(&id)
	if err == nil {
		return id, nil
	}
	id = "mgrp_" + uuid.NewString()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO monitor_groups(id, site_id, name, is_default, merge_enabled, all_agents)
		 VALUES(?,?,?,1,1,1)`, id, siteID, defaultGroupName); err != nil {
		return "", err
	}
	return id, nil
}

// defaultGroupID returns the site's default monitor group id, creating it if
// missing.
func (s *Service) defaultGroupID(ctx context.Context, siteID string) (string, error) {
	return s.EnsureDefaultGroup(ctx, siteID)
}

// ListGroups returns the site's monitor groups, each with its bound agent-group
// scope, default group first then by name.
func (s *Service) ListGroups(ctx context.Context, siteID string) ([]MonitorGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, site_id, name, is_default, merge_enabled, all_agents
		 FROM monitor_groups WHERE site_id=? ORDER BY is_default DESC, name`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MonitorGroup
	byID := make(map[string]*MonitorGroup)
	for rows.Next() {
		var g MonitorGroup
		var isDefault, merge, all int
		if err := rows.Scan(&g.ID, &g.SiteID, &g.Name, &isDefault, &merge, &all); err != nil {
			return nil, err
		}
		g.IsDefault = isDefault == 1
		g.MergeEnabled = merge == 1
		g.AllAgents = all == 1
		g.AgentGroupIDs = []string{}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	grows, err := s.db.QueryContext(ctx,
		`SELECT mgag.monitor_group_id, mgag.agent_group_id
		 FROM monitor_group_agent_groups mgag
		 JOIN monitor_groups mg ON mg.id = mgag.monitor_group_id
		 WHERE mg.site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer grows.Close()
	for grows.Next() {
		var gid, agid string
		if err := grows.Scan(&gid, &agid); err != nil {
			return nil, err
		}
		if g := byID[gid]; g != nil {
			g.AgentGroupIDs = append(g.AgentGroupIDs, agid)
		}
	}
	return out, grows.Err()
}

// GetGroup returns one monitor group by id (with its agent-group scope), or
// sql.ErrNoRows when absent.
func (s *Service) GetGroup(ctx context.Context, groupID string) (MonitorGroup, error) {
	var g MonitorGroup
	var isDefault, merge, all int
	if err := s.db.QueryRowContext(ctx,
		`SELECT id, site_id, name, is_default, merge_enabled, all_agents FROM monitor_groups WHERE id=?`, groupID).
		Scan(&g.ID, &g.SiteID, &g.Name, &isDefault, &merge, &all); err != nil {
		return MonitorGroup{}, err
	}
	g.IsDefault = isDefault == 1
	g.MergeEnabled = merge == 1
	g.AllAgents = all == 1
	g.AgentGroupIDs = []string{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT agent_group_id FROM monitor_group_agent_groups WHERE monitor_group_id=?`, groupID)
	if err != nil {
		return MonitorGroup{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var agid string
		if err := rows.Scan(&agid); err != nil {
			return MonitorGroup{}, err
		}
		g.AgentGroupIDs = append(g.AgentGroupIDs, agid)
	}
	return g, rows.Err()
}

// CreateGroup creates a custom (non-default) monitor group and returns its id.
// A newly-created empty group scopes no targets yet, so no config bump is needed
// until targets are assigned to it.
func (s *Service) CreateGroup(ctx context.Context, siteID, name string, mergeEnabled, allAgents bool, agentGroupIDs []string) (string, error) {
	id := "mgrp_" + uuid.NewString()
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
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO monitor_groups(id, site_id, name, is_default, merge_enabled, all_agents)
		 VALUES(?,?,?,0,?,?)`, id, siteID, name, boolInt(mergeEnabled), boolInt(allAgents)); err != nil {
		return "", err
	}
	if err := reconcileGroupScope(ctx, tx, id, siteID, allAgents, agentGroupIDs); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	return id, nil
}

// UpdateGroup renames a monitor group and reconciles its merge flag and Agent
// scope, then bumps config_version for the site (the scope of every target in the
// group may have changed) and announces the change. The default group may be
// updated but not renamed to empty. Returns the group's site id. Callers must
// terminate active alerts of this group and re-evaluate around a scope/merge
// semantic change (orchestrated at the API layer). Returns sql.ErrNoRows when the
// group is gone.
func (s *Service) UpdateGroup(ctx context.Context, groupID, name string, mergeEnabled, allAgents bool, agentGroupIDs []string) (string, error) {
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
	var siteID string
	if err := tx.QueryRowContext(ctx, `SELECT site_id FROM monitor_groups WHERE id=?`, groupID).Scan(&siteID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE monitor_groups SET name=?, merge_enabled=?, all_agents=? WHERE id=?`,
		name, boolInt(mergeEnabled), boolInt(allAgents), groupID); err != nil {
		return "", err
	}
	if err := reconcileGroupScope(ctx, tx, groupID, siteID, allAgents, agentGroupIDs); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agents SET config_version=config_version+1 WHERE site_id=?`, siteID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	s.announce(siteID)
	return siteID, nil
}

// DeleteGroup removes a custom monitor group: it moves the group's targets into
// the site default group, deletes the group's rules (terminating their firing
// alerts as configuration_changed first), then removes the group and its scope
// bindings, and bumps config_version. Targets are never deleted. The default
// group cannot be deleted (returns ErrDefaultGroup). Returns the site id and
// sql.ErrNoRows when the group is gone.
func (s *Service) DeleteGroup(ctx context.Context, groupID string) (string, error) {
	var siteID string
	var isDefault int
	if err := s.db.QueryRowContext(ctx,
		`SELECT site_id, is_default FROM monitor_groups WHERE id=?`, groupID).Scan(&siteID, &isDefault); err != nil {
		return "", err
	}
	if isDefault == 1 {
		return "", ErrDefaultGroup
	}
	defaultID, err := s.defaultGroupID(ctx, siteID)
	if err != nil {
		return "", err
	}
	// Terminate the group's firing alerts (configuration_changed) BEFORE the write
	// transaction — the fault engine's termination writes to the DB and SQLite has a
	// single writer, so it must not run inside our open tx.
	if s.term != nil {
		if err := s.term.TerminateForGroup(ctx, groupID); err != nil {
			return "", err
		}
	}

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
	// Delete the group's rules (and their now-resolved alerts/evidence/conditions).
	ruleIDs, err := groupRuleIDs(ctx, tx, groupID)
	if err != nil {
		return "", err
	}
	if err := deleteRulesCascade(ctx, tx, ruleIDs); err != nil {
		return "", err
	}
	// Move the group's targets to the default group (never delete them).
	if _, err := tx.ExecContext(ctx,
		`UPDATE probe_tasks SET group_id=? WHERE group_id=?`, defaultID, groupID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM monitor_group_agent_groups WHERE monitor_group_id=?`, groupID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM monitor_groups WHERE id=?`, groupID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agents SET config_version=config_version+1 WHERE site_id=?`, siteID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	s.announce(siteID)
	return siteID, nil
}

// scopeQueryer is the read subset used to validate a monitor group's Agent
// scope, satisfied by both *store.DB and an open *sql.Tx (via txExec), so the
// same membership check runs standalone or inside a write transaction.
type scopeQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ValidateGroupScope reports whether a submitted monitor-group scope is
// acceptable: every referenced agent-group id must belong to siteID — the same
// membership rule reconcileGroupScope enforces when it rebuilds the bindings. It
// is read-only and has no alert/incident lifecycle side effects, so a handler can
// reject an invalid scope BEFORE taking any irreversible action (e.g. terminating
// a group's incidents on a merge-policy flip). When allAgents is set the group
// broadcasts and any agentGroupIDs are ignored.
func (s *Service) ValidateGroupScope(ctx context.Context, siteID string, allAgents bool, agentGroupIDs []string) error {
	return validateGroupScope(ctx, s.db, siteID, allAgents, agentGroupIDs)
}

// validateGroupScope is the single source of the "agent group belongs to site"
// rule. Empty ids and duplicates are skipped (matching reconcileGroupScope).
func validateGroupScope(ctx context.Context, q scopeQueryer, siteID string, allAgents bool, agentGroupIDs []string) error {
	if allAgents {
		return nil
	}
	seen := make(map[string]bool, len(agentGroupIDs))
	for _, agid := range agentGroupIDs {
		if agid == "" || seen[agid] {
			continue
		}
		seen[agid] = true
		rows, err := q.QueryContext(ctx,
			`SELECT 1 FROM agent_groups WHERE id=? AND site_id=?`, agid, siteID)
		if err != nil {
			return err
		}
		found := rows.Next()
		cerr := rows.Err()
		rows.Close()
		if cerr != nil {
			return cerr
		}
		if !found {
			return fmt.Errorf("agent group %q does not belong to site %s", agid, siteID)
		}
	}
	return nil
}

// reconcileGroupScope rebuilds a monitor group's agent-group bindings inside tx.
// When all_agents is true the bindings are cleared (the group broadcasts). A
// group may only reference agent groups in its own site; the submitted ids are
// validated up front by the shared validateGroupScope so a cross-site or unknown
// id is rejected before any binding is written.
func reconcileGroupScope(ctx context.Context, tx txExec, groupID, siteID string, allAgents bool, agentGroupIDs []string) error {
	if err := validateGroupScope(ctx, tx, siteID, allAgents, agentGroupIDs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM monitor_group_agent_groups WHERE monitor_group_id=?`, groupID); err != nil {
		return err
	}
	if allAgents {
		return nil
	}
	seen := make(map[string]bool, len(agentGroupIDs))
	for _, agid := range agentGroupIDs {
		if agid == "" || seen[agid] {
			continue
		}
		seen[agid] = true
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO monitor_group_agent_groups(monitor_group_id, agent_group_id) VALUES(?, ?)`,
			groupID, agid); err != nil {
			return err
		}
	}
	return nil
}

// ---- targets ----

// SeedDefaults inserts a few public ICMP targets plus a default-NIC gateway
// monitor for a site if it has none, all in the site's default monitor group, so
// agents get useful public-reachability and LAN-gateway monitoring out of the box.
func (s *Service) SeedDefaults(ctx context.Context, siteID string) error {
	defaultID, err := s.EnsureDefaultGroup(ctx, siteID)
	if err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM probe_tasks WHERE site_id=?`, siteID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	defaults := []ProbeTarget{
		{Kind: "icmp", Target: "1.1.1.1", Enabled: true, GroupID: defaultID},
		{Kind: "icmp", Target: "8.8.8.8", Enabled: true, GroupID: defaultID},
		{Kind: "icmp", Target: "223.5.5.5", Enabled: true, GroupID: defaultID},
		{Kind: "gateway", Target: "gateway", Enabled: true, GroupID: defaultID},
	}
	return s.SetSiteTargets(ctx, siteID, defaults)
}

// ListSiteTargets returns the site's monitoring targets (each with its owning
// monitor group id) for the management UI.
func (s *Service) ListSiteTargets(ctx context.Context, siteID string) ([]ProbeTarget, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, group_id, kind, COALESCE(name,''), COALESCE(target,''), COALESCE(params,''), enabled
		 FROM probe_tasks WHERE site_id=? ORDER BY kind, target`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeTarget
	for rows.Next() {
		var t ProbeTarget
		var params string
		var enabled int
		if err := rows.Scan(&t.ID, &t.GroupID, &t.Kind, &t.Name, &t.Target, &params, &enabled); err != nil {
			return nil, err
		}
		if params != "" {
			_ = json.Unmarshal([]byte(params), &t.Params)
		}
		t.Enabled = enabled == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetSiteTargets reconciles the site's targets to the given set. Each target must
// name an existing monitor group in the site. Targets removed from the set — or
// moved to a different group — have every group rule referencing them deleted
// (whole rule) and those rules' firing alerts terminated as configuration_changed,
// so a moved target can never leave a rule pointing outside its group. Existing
// target IDs are preserved (upsert) so a rule's conditions survive edits.
// config_version is bumped and TopicConfigChanged published so connected agents
// get fresh DesiredState immediately.
func (s *Service) SetSiteTargets(ctx context.Context, siteID string, targets []ProbeTarget) error {
	// Resolve/assign the default group so a target may omit group_id (it lands in
	// the default group) — used by SeedDefaults and lenient API callers.
	defaultID, err := s.defaultGroupID(ctx, siteID)
	if err != nil {
		return err
	}
	keep := make(map[string]bool, len(targets))
	for i := range targets {
		if targets[i].ID == "" {
			targets[i].ID = "probe_" + uuid.NewString()
		}
		if targets[i].GroupID == "" {
			targets[i].GroupID = defaultID
		}
		keep[targets[i].ID] = true
	}
	// Validate group ownership up front, before terminating anything, so a bad
	// group id cannot leave an alert force-resolved for an update that then rolls
	// back.
	if err := s.validateTargetGroups(ctx, siteID, targets); err != nil {
		return err
	}

	// Current targets and their groups, to find removed and moved targets.
	oldGroup, err := s.currentTargetGroups(ctx, siteID)
	if err != nil {
		return err
	}
	affected := map[string]bool{} // target ids whose rules must be dropped
	for id := range oldGroup {
		if !keep[id] {
			affected[id] = true // removed
		}
	}
	for _, t := range targets {
		if prev, ok := oldGroup[t.ID]; ok && prev != t.GroupID {
			affected[t.ID] = true // moved to another group
		}
	}
	affectedIDs := make([]string, 0, len(affected))
	for id := range affected {
		affectedIDs = append(affectedIDs, id)
	}

	// Force-resolve firing alerts of rules referencing an affected target BEFORE
	// the write transaction (single-writer discipline; the terminate path writes to
	// the DB). This closes those incidents as configuration terminations instead of
	// stranding them once the rules are deleted below.
	if s.term != nil && len(affectedIDs) > 0 {
		if err := s.term.TerminateForTargets(ctx, affectedIDs); err != nil {
			return err
		}
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

	// Delete rules referencing any affected target (and their now-resolved alerts).
	if len(affectedIDs) > 0 {
		ruleIDs, err := rulesReferencingTargets(ctx, tx, affectedIDs)
		if err != nil {
			return err
		}
		if err := deleteRulesCascade(ctx, tx, ruleIDs); err != nil {
			return err
		}
	}
	// Delete removed targets (their monitor_status/operational_issues cascade).
	for id := range oldGroup {
		if keep[id] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM probe_tasks WHERE id=?`, id); err != nil {
			return err
		}
	}

	for _, t := range targets {
		params, _ := json.Marshal(t.Params)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO probe_tasks(id, site_id, group_id, kind, name, target, params, enabled)
			 VALUES(?,?,?,?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET group_id=excluded.group_id, kind=excluded.kind, name=excluded.name,
			   target=excluded.target, params=excluded.params, enabled=excluded.enabled`,
			t.ID, siteID, t.GroupID, t.Kind, t.Name, t.Target, string(params), boolInt(t.Enabled)); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if err := s.reg.BumpConfigVersionForSite(ctx, siteID); err != nil {
		return err
	}
	s.announce(siteID)
	return nil
}

// currentTargetGroups maps the site's current target ids to their group ids.
func (s *Service) currentTargetGroups(ctx context.Context, siteID string) (map[string]string, error) {
	rows, err := s.db.Read().QueryContext(ctx, `SELECT id, group_id FROM probe_tasks WHERE site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, gid string
		if err := rows.Scan(&id, &gid); err != nil {
			return nil, err
		}
		out[id] = gid
	}
	return out, rows.Err()
}

// validateTargetGroups rejects the update if any target names a monitor group
// that does not belong to siteID. Read-only, run before termination and the tx.
func (s *Service) validateTargetGroups(ctx context.Context, siteID string, targets []ProbeTarget) error {
	want := map[string]bool{}
	for _, t := range targets {
		want[t.GroupID] = true
	}
	rows, err := s.db.Read().QueryContext(ctx, `SELECT id FROM monitor_groups WHERE site_id=?`, siteID)
	if err != nil {
		return err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		have[id] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for gid := range want {
		if !have[gid] {
			return fmt.Errorf("monitor group %q does not belong to site %s", gid, siteID)
		}
	}
	return nil
}

// DesiredStateFor builds the config to push to a specific agent. Targets are
// resolved per agent through the group scope predicate: a target reaches this
// agent when its monitor group broadcasts to the whole site or this agent belongs
// to one of the group's referenced agent groups. "host" targets are server-side
// alerting anchors and are never pushed down; disabled targets are skipped.
func (s *Service) DesiredStateFor(ctx context.Context, agentID string) (pcfg.DesiredState, error) {
	st, err := s.reg.ConfigStatus(ctx, agentID)
	if err != nil {
		return pcfg.DesiredState{}, err
	}
	ds := pcfg.DesiredState{
		ConfigVersion: st.ConfigVersion,
		Intervals:     pcfg.Intervals{BaseSeconds: defaultBaseSeconds, RegularSeconds: defaultRegularSeconds},
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT pt.id, kind, COALESCE(name,''), COALESCE(target,''), COALESCE(params,'')
		 FROM probe_tasks pt
		 WHERE pt.site_id=? AND pt.enabled=1 AND pt.kind<>'host'
		   AND `+AgentScopePredicate+`
		 ORDER BY kind, target`, st.SiteID, agentID)
	if err != nil {
		return pcfg.DesiredState{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var t pcfg.ProbeTarget
		var params string
		if err := rows.Scan(&t.MonitorID, &t.Kind, &t.Name, &t.Target, &params); err != nil {
			return pcfg.DesiredState{}, err
		}
		if params != "" {
			_ = json.Unmarshal([]byte(params), &t.Params)
		}
		ds.ProbeTargets = append(ds.ProbeTargets, t)
	}
	return ds, rows.Err()
}

// announce publishes TopicConfigChanged so the WebSocket hub pushes fresh
// DesiredState to the site's connected agents immediately.
func (s *Service) announce(siteID string) {
	if s.bus != nil {
		s.bus.Publish(eventbus.TopicConfigChanged, eventbus.ConfigChanged{SiteID: siteID})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
