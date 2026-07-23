// Package config manages monitor groups and their monitoring targets
// (probe_tasks) and builds the DesiredState the server pushes down to agents.
//
// Monitor groups (distinct from agent groups) own a static set of targets and
// the Agent execution scope shared by all of them: a group either broadcasts to
// every site agent (all_agents=1) or scopes to the union of referenced agent
// groups. Each site has one undeletable default group. Targets are configured
// centrally in Lite so agents stay near-zero-config; changing them bumps the
// site config serial (and stamps each materially-changed target's own
// config_serial) and publishes TopicConfigChanged so the WebSocket hub pushes the
// new state to connected agents immediately.
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

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

// PostCommit is a publisher the tx owner MUST invoke after a successful commit
// (and discard on rollback). The terminator returns one capturing its accumulated
// alert/incident lifecycle events, so config can close alerts inside its own write
// transaction yet still keep event publication off the write path — without
// importing the fault engine.
type PostCommit func(ctx context.Context)

// AlertTerminator is the fault-engine surface config needs to force-resolve
// alerts (and close their incidents) as `configuration_changed` INSIDE config's
// own write transaction, before its owning targets/rules are removed or changed.
// It is injected (satisfied by *rules.Service) so config does not import the fault
// engine — keeping the dependency one-way and cycle-free. Each method runs in the
// caller's open tx and returns the affected target ids (for the status event) plus
// a PostCommit publisher. Nil-safe callers guard for a nil terminator (tests).
type AlertTerminator interface {
	// TerminateForTargetsTx force-resolves, inside tx, the firing alerts of every
	// rule referencing any of the given targets.
	TerminateForTargetsTx(ctx context.Context, tx *sql.Tx, targetIDs []string) ([]string, PostCommit, error)
	// TerminateForGroupTx force-resolves, inside tx, the firing alerts of every rule
	// in a monitor group (group deletion or merge-policy flip).
	TerminateForGroupTx(ctx context.Context, tx *sql.Tx, groupID string) ([]string, PostCommit, error)
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
// scope, then bumps config_serial for the site (the scope of every target in the
// group may have changed) and announces the change. A merge-policy flip changes
// the incident-grouping identity for the whole group, so the group's firing alerts
// are terminated (configuration_changed) INSIDE this write tx before the flip
// commits — closing incidents under the old grouping identity atomically with it.
// The default group may be updated but not renamed to empty. Returns the group's
// site id, or sql.ErrNoRows when the group is gone.
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
	var oldMerge int
	if err := tx.QueryRowContext(ctx,
		`SELECT site_id, merge_enabled FROM monitor_groups WHERE id=?`, groupID).Scan(&siteID, &oldMerge); err != nil {
		return "", err
	}
	// Terminate the group's firing alerts in-tx only on a merge-policy flip (a pure
	// rename or agent-scope edit is not a grouping-identity change and must not
	// terminate incidents).
	var termPub PostCommit
	var termAffected []string
	if s.term != nil && (oldMerge == 1) != mergeEnabled {
		termAffected, termPub, err = s.term.TerminateForGroupTx(ctx, tx, groupID)
		if err != nil {
			return "", err
		}
	}
	targetIDs, err := groupTargetIDs(ctx, tx, groupID)
	if err != nil {
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
		`UPDATE sites SET config_serial=config_serial+1 WHERE id=?`, siteID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	if termPub != nil {
		termPub(ctx)
	}
	s.announce(siteID)
	s.publishTargetStatus(siteID, append(targetIDs, termAffected...))
	return siteID, nil
}

// DeleteGroup removes a custom monitor group: it moves the group's targets into
// the site default group, deletes the group's rules (terminating their firing
// alerts as configuration_changed first), then removes the group and its scope
// bindings, and bumps the site config serial. Targets are never deleted (a
// group-only move is not a material target change, so their per-target
// config_serial is preserved). The default group cannot be deleted (returns
// ErrDefaultGroup). Returns the site id and sql.ErrNoRows when the group is gone.
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
	// Terminate the group's firing alerts (configuration_changed) INSIDE this tx, so
	// their incidents close atomically with the group's removal.
	var termPub PostCommit
	var termAffected []string
	if s.term != nil {
		termAffected, termPub, err = s.term.TerminateForGroupTx(ctx, tx, groupID)
		if err != nil {
			return "", err
		}
	}
	// The group's targets move to the default group (never deleted); capture their
	// ids for the status event before the move.
	targetIDs, err := groupTargetIDs(ctx, tx, groupID)
	if err != nil {
		return "", err
	}
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
		`UPDATE sites SET config_serial=config_serial+1 WHERE id=?`, siteID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	if termPub != nil {
		termPub(ctx)
	}
	s.announce(siteID)
	s.publishTargetStatus(siteID, append(targetIDs, termAffected...))
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
// name an existing monitor group in the site, and no submitted id may belong to a
// different site. Targets removed from the set — or moved to a different group —
// have every group rule referencing them deleted (whole rule) and those rules'
// firing alerts terminated as configuration_changed, so a moved target can never
// leave a rule pointing outside its group. Existing target IDs are preserved
// (upsert) so a rule's conditions survive edits.
//
// All classification reads run INSIDE the write transaction (not the read pool):
// SQLite serializes writers, so a later complete-replacement request sees the
// earlier one's committed rows and cannot merge submitted sets or classify against
// a stale snapshot. The site config serial is bumped — and the DesiredState push
// (announce) fired — only when the desired generation actually changes (a new,
// removed, moved, or materially changed target). An identical resubmit is an
// idempotent no-op (no bump, no announce, no status event). A name-only edit keeps
// the target's generation and does NOT bump/announce either, but still publishes a
// precise target.status.changed so the batch exposes the new user-visible name.
func (s *Service) SetSiteTargets(ctx context.Context, siteID string, targets []ProbeTarget) error {
	// Resolve/assign the default group so a target may omit group_id (it lands in
	// the default group) — used by lenient API callers.
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

	// Validate group ownership and cross-site target-id ownership INSIDE the tx,
	// before any mutation, so a bad group id or a cross-site id rolls the whole
	// reconcile back with nothing terminated or written.
	if err := validateTargetGroups(ctx, tx, siteID, targets); err != nil {
		return err
	}
	if err := validateTargetOwnership(ctx, tx, siteID, targets); err != nil {
		return err
	}

	// Current targets and their facts, read in-tx to classify removed/moved/
	// materially-changed/name-only targets. Removed/moved targets have their
	// referencing rules deleted; materially changed targets keep their rules but
	// reset their current condition state and advance their generation; name-only
	// edits keep everything but still publish a status event.
	oldFacts, err := currentTargetFacts(ctx, tx, siteID)
	if err != nil {
		return err
	}
	removedOrMoved := map[string]bool{}
	material := map[string]bool{}
	newTargets := map[string]bool{}
	nameOnly := map[string]bool{}
	for id := range oldFacts {
		if !keep[id] {
			removedOrMoved[id] = true // removed
		}
	}
	for i := range targets {
		t := targets[i]
		of, ok := oldFacts[t.ID]
		if !ok {
			newTargets[t.ID] = true
			continue
		}
		moved := of.groupID != t.GroupID
		if moved {
			removedOrMoved[t.ID] = true // moved to another group
		}
		params, _ := json.Marshal(t.Params)
		mat := materialTargetChange(of, t, string(params))
		if mat {
			material[t.ID] = true
		}
		// A pure name edit (unchanged group + no material change) still alters a
		// user-visible batch field, so it must publish a status event — but it is
		// not a material generation change and must not bump/announce.
		if !moved && !mat && of.name != t.Name {
			nameOnly[t.ID] = true
		}
	}
	// terminateSet: every target whose firing alerts must close (removed ∪ moved ∪
	// materially changed). Deduped, deterministic order not required.
	terminateSet := make([]string, 0, len(removedOrMoved)+len(material))
	inTerm := map[string]bool{}
	for id := range removedOrMoved {
		inTerm[id] = true
		terminateSet = append(terminateSet, id)
	}
	for id := range material {
		if !inTerm[id] {
			inTerm[id] = true
			terminateSet = append(terminateSet, id)
		}
	}

	// hasGenerationChange: does anything alter the desired/probed generation? New,
	// removed, moved, or materially-changed targets all require a site serial bump
	// and a DesiredState re-announce. An identical or name-only save does not.
	hasGenerationChange := len(newTargets) > 0 || len(removedOrMoved) > 0 || len(material) > 0

	// Force-resolve firing alerts of rules referencing an affected target INSIDE the
	// write tx, so a status reader never sees a terminated alert alongside surviving
	// old-target condition state.
	var termPub PostCommit
	var termAffected []string
	if s.term != nil && len(terminateSet) > 0 {
		termAffected, termPub, err = s.term.TerminateForTargetsTx(ctx, tx, terminateSet)
		if err != nil {
			return err
		}
	}

	// Delete rules referencing any removed/moved target (and their now-resolved
	// alerts), so a moved target can never leave a rule pointing outside its group.
	rmList := keysOf(removedOrMoved)
	if len(rmList) > 0 {
		ruleIDs, err := rulesReferencingTargets(ctx, tx, rmList)
		if err != nil {
			return err
		}
		if err := deleteRulesCascade(ctx, tx, ruleIDs); err != nil {
			return err
		}
	}
	// Reset current condition state for materially-changed (kept) targets so an old
	// satisfied verdict never transfers to the new generation.
	matList := keysOf(material)
	if len(matList) > 0 {
		args := make([]any, len(matList))
		for i, id := range matList {
			args[i] = id
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM rule_condition_state WHERE condition_id IN (
				SELECT id FROM group_rule_conditions WHERE target_id IN (`+placeholders(len(matList))+`))`, args...); err != nil {
			return err
		}
	}
	// Delete removed targets (their monitor_status/operational_issues cascade).
	for id := range oldFacts {
		if keep[id] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM probe_tasks WHERE id=?`, id); err != nil {
			return err
		}
	}

	// Bump the site serial once (in-tx) ONLY when the desired generation changes —
	// it is the new per-target generation for every created/materially-changed
	// target, and the DesiredState version agents re-apply on. An identical/name-only
	// save leaves it untouched (idempotent). The current serial is always read (used
	// to stamp created/materially-changed targets below).
	if hasGenerationChange {
		if _, err := tx.ExecContext(ctx, `UPDATE sites SET config_serial=config_serial+1 WHERE id=?`, siteID); err != nil {
			return err
		}
	}
	var newSerial int
	if err := tx.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id=?`, siteID).Scan(&newSerial); err != nil {
		return err
	}
	now := time.Now().UTC()

	for _, t := range targets {
		params, _ := json.Marshal(t.Params)
		serial := newSerial
		changedAt := sql.NullTime{Time: now, Valid: true}
		if of, ok := oldFacts[t.ID]; ok && !material[t.ID] {
			// Non-material edit (name / group only): keep the target's generation.
			serial = of.configSerial
			changedAt = of.configChangedAt
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO probe_tasks(id, site_id, group_id, kind, name, target, params, enabled, config_serial, config_changed_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET group_id=excluded.group_id, kind=excluded.kind, name=excluded.name,
			   target=excluded.target, params=excluded.params, enabled=excluded.enabled,
			   config_serial=excluded.config_serial, config_changed_at=excluded.config_changed_at`,
			t.ID, siteID, t.GroupID, t.Kind, t.Name, t.Target, string(params), boolInt(t.Enabled), serial, changedAt); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	// Post-commit: publish the terminator's captured lifecycle events, push the new
	// DesiredState only when the generation changed, then one precise status event
	// over the affected targets (new ∪ removed/moved ∪ materially changed ∪
	// name-only ∪ terminator-affected).
	if termPub != nil {
		termPub(ctx)
	}
	if hasGenerationChange {
		s.announce(siteID)
	}
	eventTargets := make([]string, 0, len(newTargets)+len(terminateSet)+len(nameOnly)+len(termAffected))
	for id := range newTargets {
		eventTargets = append(eventTargets, id)
	}
	eventTargets = append(eventTargets, terminateSet...)
	for id := range nameOnly {
		eventTargets = append(eventTargets, id)
	}
	eventTargets = append(eventTargets, termAffected...)
	s.publishTargetStatus(siteID, eventTargets)
	return nil
}

// keysOf returns the keys of a string-set map.
func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// targetFacts is a target's current stored identity, used to detect removed/moved
// targets, per-target material change, and name-only edits during a reconcile.
type targetFacts struct {
	groupID, name, kind, target, params string
	enabled                             bool
	configSerial                        int
	configChangedAt                     sql.NullTime
}

// materialTargetChange reports whether the submitted target differs from its
// stored facts in a way that changes what the agent probes (kind / target /
// params / enabled). name and group_id are NOT material — they never change the
// probe, so the target keeps its generation. newParams is the canonical marshal
// of the submitted params.
func materialTargetChange(old targetFacts, t ProbeTarget, newParams string) bool {
	return old.kind != t.Kind || old.target != t.Target || old.enabled != t.Enabled ||
		canonParams(old.params) != newParams
}

// canonParams normalizes a stored params JSON string to the canonical marshal of
// pcfg.ProbeParams so a compare against a freshly-marshaled value is stable.
func canonParams(s string) string {
	if s == "" {
		s = "{}"
	}
	var p pcfg.ProbeParams
	_ = json.Unmarshal([]byte(s), &p)
	b, _ := json.Marshal(p)
	return string(b)
}

// currentTargetFacts maps the site's current target ids to their stored facts. It
// takes a queryer so it can read from the write transaction (authoritative,
// serialized) rather than the read pool — a concurrent complete-replacement must
// classify and delete against in-tx state, never a pre-transaction snapshot.
func currentTargetFacts(ctx context.Context, q scopeQueryer, siteID string) (map[string]targetFacts, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, group_id, COALESCE(name,''), kind, COALESCE(target,''), COALESCE(params,''), enabled, config_serial, config_changed_at
		 FROM probe_tasks WHERE site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]targetFacts{}
	for rows.Next() {
		var id string
		var f targetFacts
		var enabled int
		if err := rows.Scan(&id, &f.groupID, &f.name, &f.kind, &f.target, &f.params, &enabled, &f.configSerial, &f.configChangedAt); err != nil {
			return nil, err
		}
		f.enabled = enabled == 1
		out[id] = f
	}
	return out, rows.Err()
}

// validateTargetGroups rejects the update if any target names a monitor group
// that does not belong to siteID. Takes a queryer so it runs inside the write tx.
func validateTargetGroups(ctx context.Context, q scopeQueryer, siteID string, targets []ProbeTarget) error {
	want := map[string]bool{}
	for _, t := range targets {
		want[t.GroupID] = true
	}
	rows, err := q.QueryContext(ctx, `SELECT id FROM monitor_groups WHERE site_id=?`, siteID)
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

// validateTargetOwnership rejects the update if any submitted target id already
// belongs to a DIFFERENT site. The probe_tasks upsert keys on id globally
// (ON CONFLICT(id)), so without this an id owned by another site would be silently
// rewritten under this site's group/probe facts (cross-site corruption). Runs
// inside the write tx so the ownership fact it checks is the one the upsert mutates.
func validateTargetOwnership(ctx context.Context, q scopeQueryer, siteID string, targets []ProbeTarget) error {
	ids := make([]any, 0, len(targets))
	for _, t := range targets {
		if t.ID != "" {
			ids = append(ids, t.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := q.QueryContext(ctx,
		`SELECT id, site_id FROM probe_tasks WHERE id IN (`+placeholders(len(ids))+`)`, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, owner string
		if err := rows.Scan(&id, &owner); err != nil {
			return err
		}
		if owner != siteID {
			return fmt.Errorf("target %q belongs to another site", id)
		}
	}
	return rows.Err()
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
		`SELECT pt.id, kind, COALESCE(name,''), COALESCE(target,''), COALESCE(params,''), pt.config_serial
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
		if err := rows.Scan(&t.MonitorID, &t.Kind, &t.Name, &t.Target, &params, &t.ConfigSerial); err != nil {
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

// publishTargetStatus emits one precise TopicTargetStatusChanged for the affected
// targets after a committing config mutation. Empty sets publish nothing. This is
// distinct from announce (TopicConfigChanged drives the DesiredState push and is
// NOT bridged to status events — no duplicate safety-net event).
func (s *Service) publishTargetStatus(siteID string, targetIDs []string) {
	if s.bus == nil {
		return
	}
	seen := make(map[string]bool, len(targetIDs))
	ids := make([]string, 0, len(targetIDs))
	for _, id := range targetIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return
	}
	s.bus.Publish(eventbus.TopicTargetStatusChanged, eventbus.TargetStatusChanged{SiteID: siteID, TargetIDs: ids})
}

// groupTargetIDs returns the ids of the targets currently owned by a monitor
// group, inside tx — the targets a group-scope change affects.
func groupTargetIDs(ctx context.Context, tx txExec, groupID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM probe_tasks WHERE group_id=?`, groupID)
	if err != nil {
		return nil, err
	}
	return scanIDs(rows)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
