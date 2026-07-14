// Package config manages monitoring targets (probe_tasks) and builds the
// DesiredState the server pushes down to agents. Targets are configured
// centrally in Lite so agents stay near-zero-config; changing them bumps the
// per-agent config_version and publishes TopicConfigChanged so the WebSocket
// hub pushes the new state to connected agents immediately.
package config

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

// Default scheduler intervals delivered to agents (seconds).
const (
	defaultBaseSeconds    = 10
	defaultRegularSeconds = 30
)

// AgentScopePredicate is a SQL boolean fragment for a WHERE clause, true when the
// probe_tasks row aliased "pt" applies to a given agent: either the target is
// broadcast to the whole site (all_agents=1) or the agent belongs to one of the
// target's groups. The agent id must be bound to the single "?" placeholder it
// contains. It defines target→agent scoping in ONE place, shared by the config
// downlink (DesiredStateFor) and the alert engine (rules.EvaluateAgent), so the
// two can never drift. Any query using it must alias probe_tasks as "pt".
const AgentScopePredicate = `(pt.all_agents=1 OR EXISTS(
	SELECT 1 FROM probe_task_groups ptg
	JOIN agent_group_members agm ON agm.group_id = ptg.group_id
	WHERE ptg.task_id = pt.id AND agm.agent_id = ?))`

type Service struct {
	db     *store.DB
	reg    *registry.Service
	bus    *eventbus.Bus
	alerts *alert.Service // force-resolves alerts of deleted targets (nil-safe)
}

func New(db *store.DB, reg *registry.Service, bus *eventbus.Bus, alerts *alert.Service) *Service {
	return &Service{db: db, reg: reg, bus: bus, alerts: alerts}
}

// ProbeTarget is a site-scoped monitoring target managed via the UI.
type ProbeTarget struct {
	ID      string           `json:"id"`
	Kind    string           `json:"kind"`           // "icmp" | "dns" | "http" | "tcp" | "nat" | "host"
	Name    string           `json:"name,omitempty"` // human-friendly display name; optional
	Target  string           `json:"target"`         // "1.1.1.1", "example.com", …
	Params  pcfg.ProbeParams `json:"params"`         // per-protocol probe settings
	Enabled bool             `json:"enabled"`
	// Scope: AllAgents=true pushes this target to every agent in the site
	// (the default). When false, it is pushed only to agents that belong to one
	// of GroupIDs. These fields drive server-side per-agent resolution and are
	// not part of the wire DesiredState the agent receives.
	AllAgents bool     `json:"all_agents"`
	GroupIDs  []string `json:"group_ids"`
}

// SeedDefaults inserts a few public ICMP targets plus a default-NIC gateway
// monitor for a site if it has none, so agents get useful public-reachability
// and LAN-gateway monitoring out of the box.
func (s *Service) SeedDefaults(ctx context.Context, siteID string) error {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM probe_tasks WHERE site_id=?`, siteID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	defaults := []ProbeTarget{
		{Kind: "icmp", Target: "1.1.1.1", Enabled: true, AllAgents: true},
		{Kind: "icmp", Target: "8.8.8.8", Enabled: true, AllAgents: true},
		{Kind: "icmp", Target: "223.5.5.5", Enabled: true, AllAgents: true},
		// Empty Interface = each agent's default NIC gateway.
		{Kind: "gateway", Target: "gateway", Enabled: true, AllAgents: true},
	}
	return s.SetSiteTargets(ctx, siteID, defaults)
}

// ListSiteTargets returns the site-scoped monitoring targets, each with its scope
// (AllAgents flag + the agent-group IDs it is bound to) for the management UI.
func (s *Service) ListSiteTargets(ctx context.Context, siteID string) ([]ProbeTarget, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, COALESCE(name,''), COALESCE(target,''), COALESCE(params,''), enabled, all_agents
		 FROM probe_tasks WHERE site_id=? ORDER BY kind, target`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeTarget
	byID := make(map[string]*ProbeTarget)
	for rows.Next() {
		var t ProbeTarget
		var params string
		var enabled, allAgents int
		if err := rows.Scan(&t.ID, &t.Kind, &t.Name, &t.Target, &params, &enabled, &allAgents); err != nil {
			return nil, err
		}
		if params != "" {
			_ = json.Unmarshal([]byte(params), &t.Params)
		}
		t.Enabled = enabled == 1
		t.AllAgents = allAgents == 1
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	// Backfill each target's group bindings in one pass.
	grows, err := s.db.QueryContext(ctx,
		`SELECT ptg.task_id, ptg.group_id FROM probe_task_groups ptg
		 JOIN probe_tasks pt ON pt.id = ptg.task_id
		 WHERE pt.site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer grows.Close()
	for grows.Next() {
		var taskID, groupID string
		if err := grows.Scan(&taskID, &groupID); err != nil {
			return nil, err
		}
		if t := byID[taskID]; t != nil {
			t.GroupIDs = append(t.GroupIDs, groupID)
		}
	}
	return out, grows.Err()
}

// SetSiteTargets reconciles the site-scoped targets to the given set, bumps
// config_version for every agent in the site, and publishes TopicConfigChanged
// so connected agents get the new state pushed over their WebSocket right
// away. Existing target IDs are PRESERVED (upsert) so per-target alarm
// rules bound via probe_task_id survive edits; targets no longer present are
// deleted along with their bound rules.
func (s *Service) SetSiteTargets(ctx context.Context, siteID string, targets []ProbeTarget) error {
	// Assign IDs to new targets so the keep-set is complete, then diff against the
	// current targets to find which ones are being removed.
	keep := make(map[string]bool, len(targets))
	for i := range targets {
		if targets[i].ID == "" {
			targets[i].ID = "probe_" + uuid.NewString()
		}
		keep[targets[i].ID] = true
	}
	removed, err := s.removedTaskIDs(ctx, siteID, keep)
	if err != nil {
		return err
	}
	// Validate the incoming group bindings BEFORE terminating anything. Group
	// reconciliation inside the transaction below rejects group ids that don't
	// belong to this site; if that rejection fired after termination, we'd have
	// force-resolved a removed target's live alerts for an update that is then
	// rolled back — suppressing an active alarm the operator never actually
	// removed. Checking up front makes termination safe to run pre-transaction.
	if err := s.validateTargetGroups(ctx, siteID, targets); err != nil {
		return err
	}
	// Force-resolve any alert firing for a removed target BEFORE opening the write
	// transaction: TerminateForTask publishes resolve events whose incident handler
	// writes to the DB, and SQLite allows only one writer, so it must not run inside
	// our own open transaction. This closes the incident as a termination instead of
	// stranding it open (or letting an unrelated later recovery false-close it) once
	// the transaction below deletes the now-resolved alert rows.
	if s.alerts != nil {
		for _, id := range removed {
			if err := s.alerts.TerminateForTask(ctx, id); err != nil {
				return err
			}
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

	// Delete any existing target (and its bound rules) that is not in the incoming
	// set. Alert rows were already force-resolved above; here they are removed.
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM probe_tasks WHERE site_id=?`, siteID)
	if err != nil {
		return err
	}
	var existing []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, id)
	}
	rows.Close()
	for _, id := range existing {
		if keep[id] {
			continue
		}
		// Clear alerts before their rules (FKs ON: alerts.rule_id → alert_rules.id),
		// then the rules, its group bindings, then the target itself.
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM alerts WHERE rule_id IN (SELECT id FROM alert_rules WHERE probe_task_id=?)`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM alert_rules WHERE probe_task_id=?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM probe_task_groups WHERE task_id=?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM probe_tasks WHERE id=?`, id); err != nil {
			return err
		}
	}

	for _, t := range targets {
		enabled := 0
		if t.Enabled {
			enabled = 1
		}
		allAgents := 0
		if t.AllAgents {
			allAgents = 1
		}
		params, _ := json.Marshal(t.Params)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO probe_tasks(id, site_id, kind, name, target, params, enabled, all_agents)
			 VALUES(?,?,?,?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, name=excluded.name, target=excluded.target,
			   params=excluded.params, enabled=excluded.enabled, all_agents=excluded.all_agents`,
			t.ID, siteID, t.Kind, t.Name, t.Target, string(params), enabled, allAgents); err != nil {
			return err
		}
		// Reconcile the target's group bindings (rebuild: clear then insert).
		if _, err := tx.ExecContext(ctx, `DELETE FROM probe_task_groups WHERE task_id=?`, t.ID); err != nil {
			return err
		}
		if !t.AllAgents {
			// A target may only be scoped to groups in its own site: the INSERT..SELECT
			// filters by site_id so a cross-site (or unknown) group id inserts no row
			// and is rejected, preventing one site's config from reaching another
			// site's agents.
			seen := make(map[string]bool, len(t.GroupIDs))
			for _, gid := range t.GroupIDs {
				if seen[gid] {
					continue
				}
				seen[gid] = true
				res, err := tx.ExecContext(ctx,
					`INSERT INTO probe_task_groups(task_id, group_id)
					 SELECT ?, id FROM agent_groups WHERE id=? AND site_id=?`, t.ID, gid, siteID)
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n == 0 {
					return fmt.Errorf("agent group %q does not belong to site %s", gid, siteID)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if err := s.reg.BumpConfigVersionForSite(ctx, siteID); err != nil {
		return err
	}
	// Announce the change so the WebSocket hub pushes the new DesiredState to
	// the site's connected agents right away, instead of waiting for them to
	// notice the version bump on their own.
	if s.bus != nil {
		s.bus.Publish(eventbus.TopicConfigChanged, eventbus.ConfigChanged{SiteID: siteID})
	}
	return nil
}

// removedTaskIDs returns the site's current probe_task IDs that are absent from
// keep, i.e. the targets a SetSiteTargets call is about to delete. Read-only, run
// before the write transaction so their alerts can be force-resolved first.
func (s *Service) removedTaskIDs(ctx context.Context, siteID string, keep map[string]bool) ([]string, error) {
	rows, err := s.db.Read().QueryContext(ctx, `SELECT id FROM probe_tasks WHERE site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var removed []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if !keep[id] {
			removed = append(removed, id)
		}
	}
	return removed, rows.Err()
}

// validateTargetGroups rejects the update up front if any group-scoped target
// references a group that does not belong to siteID — the same rule the group
// reconcile enforces inside the transaction, checked early so termination and the
// transaction only run for an update that will actually commit. Read-only.
func (s *Service) validateTargetGroups(ctx context.Context, siteID string, targets []ProbeTarget) error {
	want := make(map[string]bool)
	for _, t := range targets {
		if t.AllAgents {
			continue
		}
		for _, gid := range t.GroupIDs {
			want[gid] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	rows, err := s.db.Read().QueryContext(ctx, `SELECT id FROM agent_groups WHERE site_id=?`, siteID)
	if err != nil {
		return err
	}
	defer rows.Close()
	have := make(map[string]bool)
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
			return fmt.Errorf("agent group %q does not belong to site %s", gid, siteID)
		}
	}
	return nil
}

// DesiredStateFor builds the config to push to a specific agent. Targets are
// resolved per agent: a target reaches this agent when it is broadcast to the
// whole site (all_agents=1) or when this agent belongs to one of the target's
// bound groups. "host" targets are server-side alerting anchors (the agent emits
// host.* metrics on its own) and are never pushed down; disabled targets are
// skipped in the query.
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
