// Package registry tracks agents: identity, local permission policy, status and
// last-seen. M1 provides dev auto-registration (agent appears on first
// telemetry). Real ed25519 enrollment, enrollment tokens and the max_agents
// quota land in M2.
package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/store"
)

type Agent struct {
	ID           string `json:"id"`
	SiteID       string `json:"site_id"`
	DisplayName  string `json:"display_name"` // operator-set friendly label, editable from the UI
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	AgentVersion string `json:"agent_version"`
	Status       string `json:"status"`
	// Local permission policy the agent reports on every (re)connect: supported =
	// what the build+platform can do, granted = the local policy, effective = the
	// usable intersection. These gate host/process/connection views and drive the
	// monitor pre-check + remediation surface.
	Supported    []string   `json:"supported"`
	Granted      []string   `json:"granted"`
	Effective    []string   `json:"effective"`
	PolicySource string     `json:"policy_source"`
	PolicyHash   string     `json:"policy_hash"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// StatusEvent is one online/offline transition in an agent's history.
type StatusEvent struct {
	Status    string    `json:"status"` // online | offline
	ChangedAt time.Time `json:"changed_at"`
}

const statusHistoryLimit = 20

type Service struct {
	db        *store.DB
	maxAgents int // 0 = unlimited
	bus       *eventbus.Bus
}

// New constructs the registry. maxAgents caps enrollment (0 = unlimited). bus may
// be nil in tests (agent-liveness events are then simply not published). The
// quota is a product requirement (default 50); note architecture §7/§15 advise
// against hard-limiting Lite — it is intentionally configurable.
func New(db *store.DB, maxAgents int, bus *eventbus.Bus) *Service {
	return &Service{db: db, maxAgents: maxAgents, bus: bus}
}

// publishLiveness emits a TopicAgentLivenessChanged so a bridge can fan an
// online↔offline flip out to a site-wide target-status refresh (liveness affects
// every target in the agent's scope).
func (s *Service) publishLiveness(siteID, agentID, status string) {
	if s.bus != nil && siteID != "" {
		s.bus.Publish(eventbus.TopicAgentLivenessChanged,
			eventbus.AgentLivenessChanged{SiteID: siteID, AgentID: agentID, Status: status})
	}
}

// publishSiteStatus emits a site-wide TopicTargetStatusChanged (empty TargetIDs =
// whole-site refresh) after a change whose scope is the entire site's target set,
// such as an agent being deleted — its removal changes applicable_agents and the
// aggregation of every target it was in scope for.
func (s *Service) publishSiteStatus(siteID string) {
	if s.bus != nil && siteID != "" {
		s.bus.Publish(eventbus.TopicTargetStatusChanged,
			eventbus.TargetStatusChanged{SiteID: siteID})
	}
}

// TouchLastSeen bumps an agent's last-seen timestamp and marks it online,
// recording an offline→online transition in the status history (and publishing a
// liveness event) when the agent was previously offline.
func (s *Service) TouchLastSeen(ctx context.Context, id string) error {
	now := time.Now().UTC()
	var prev, siteID string
	_ = s.db.QueryRowContext(ctx, `SELECT status, site_id FROM agents WHERE id=?`, id).Scan(&prev, &siteID)
	if _, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen_at=?, status='online' WHERE id=?`, now, id); err != nil {
		return err
	}
	if prev != "online" {
		s.recordStatus(ctx, id, "online", now)
		s.publishLiveness(siteID, id, "online")
	}
	return nil
}

// UpdatePermissions refreshes an agent's reported local permission policy
// (supported / granted / effective sets, source, hash) from its WebSocket Hello,
// so restarting an agent with a different NETTACT_AGENT_PERMISSIONS policy is
// reflected server-side (enrollment happens only once). The conditional WHERE
// makes it a no-op write when nothing changed.
func (s *Service) UpdatePermissions(ctx context.Context, id string, report permission.PermissionReport) error {
	sup := marshalStrings(report.Supported)
	gr := marshalStrings(report.Granted)
	eff := marshalStrings(report.Effective)
	_, err := s.db.ExecContext(ctx, `
		UPDATE agents SET perm_supported=?, perm_granted=?, perm_effective=?, policy_source=?, policy_hash=?
		WHERE id=? AND (perm_supported<>? OR perm_granted<>? OR perm_effective<>? OR policy_source<>? OR policy_hash<>?)`,
		sup, gr, eff, report.Source, report.PolicyHash,
		id, sup, gr, eff, report.Source, report.PolicyHash)
	return err
}

// marshalStrings encodes a string slice as a JSON array, normalizing nil to "[]"
// so a never-set column and an empty report compare equal (no spurious writes).
func marshalStrings(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

// UpdateReportedInfo refreshes the agent-reported identity fields (hostname,
// platform, agent version) from a WebSocket Hello, so a rename or agent upgrade
// is reflected server-side (enrollment happens only once). Empty values are
// written as-is: the agent owns these fields and reports them on every connect.
func (s *Service) UpdateReportedInfo(ctx context.Context, id, hostname, platform, agentVersion string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET hostname=?, platform=?, agent_version=? WHERE id=?`,
		hostname, platform, agentVersion, id)
	return err
}

// SweepStale marks any online agent whose last_seen_at is older than threshold
// as offline and records the transition. Runs on a periodic ticker; returns the
// number of agents flipped offline. exclude lists agent IDs that must never be
// swept regardless of last_seen_at — the caller passes the currently connected
// WebSocket sessions, so a live agent can't be flipped offline by a race
// between its keepalive touch and the sweep threshold.
func (s *Service) SweepStale(ctx context.Context, threshold time.Duration, exclude []string) (int, error) {
	now := time.Now().UTC()
	cutoff := now.Add(-threshold)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, site_id FROM agents WHERE revoked=0 AND status='online' AND last_seen_at IS NOT NULL AND last_seen_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	excluded := make(map[string]bool, len(exclude))
	for _, id := range exclude {
		excluded[id] = true
	}
	type staleAgent struct{ id, siteID string }
	var stale []staleAgent
	for rows.Next() {
		var a staleAgent
		if err := rows.Scan(&a.id, &a.siteID); err != nil {
			rows.Close()
			return 0, err
		}
		if excluded[a.id] {
			continue
		}
		stale = append(stale, a)
	}
	rows.Close()
	changed := 0
	for _, a := range stale {
		// Re-check the stale condition atomically in the UPDATE: if a keepalive
		// touch marked the agent online (bumping last_seen_at) between the SELECT
		// above and here, the WHERE fails and we neither flip it offline nor write
		// a bogus history row.
		res, err := s.db.ExecContext(ctx,
			`UPDATE agents SET status='offline' WHERE id=? AND status='online' AND last_seen_at < ?`, a.id, cutoff)
		if err != nil {
			return changed, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			s.recordStatus(ctx, a.id, "offline", now)
			s.publishLiveness(a.siteID, a.id, "offline")
			changed++
		}
	}
	return changed, nil
}

func (s *Service) recordStatus(ctx context.Context, agentID, status string, at time.Time) {
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO agent_status_history(id, agent_id, status, changed_at) VALUES(?,?,?,?)`,
		"ash_"+uuid.NewString(), agentID, status, at)
}

// StatusHistory returns at most 20 online/offline transitions, newest first.
func (s *Service) StatusHistory(ctx context.Context, agentID string) ([]StatusEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, changed_at FROM agent_status_history WHERE agent_id=? ORDER BY changed_at DESC LIMIT ?`,
		agentID, statusHistoryLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StatusEvent
	for rows.Next() {
		var e StatusEvent
		if err := rows.Scan(&e.Status, &e.ChangedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) List(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, site_id, COALESCE(display_name,''), COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,''),
		       status, COALESCE(perm_supported,'[]'), COALESCE(perm_granted,'[]'), COALESCE(perm_effective,'[]'),
		       COALESCE(policy_source,''), COALESCE(policy_hash,''), last_seen_at, created_at
		FROM agents WHERE revoked=0 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		var sup, gr, eff string
		var lastSeen sql.NullTime
		if err := rows.Scan(&a.ID, &a.SiteID, &a.DisplayName, &a.Hostname, &a.Platform, &a.AgentVersion,
			&a.Status, &sup, &gr, &eff, &a.PolicySource, &a.PolicyHash, &lastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		unmarshalStrings(sup, &a.Supported)
		unmarshalStrings(gr, &a.Granted)
		unmarshalStrings(eff, &a.Effective)
		if lastSeen.Valid {
			t := lastSeen.Time
			a.LastSeenAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, id string) (Agent, error) {
	var a Agent
	var lastSeen sql.NullTime
	var sup, gr, eff string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, site_id, COALESCE(display_name,''), COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,''),
		       status, COALESCE(perm_supported,'[]'), COALESCE(perm_granted,'[]'), COALESCE(perm_effective,'[]'),
		       COALESCE(policy_source,''), COALESCE(policy_hash,''), last_seen_at, created_at
		FROM agents WHERE id=? AND revoked=0`, id).
		Scan(&a.ID, &a.SiteID, &a.DisplayName, &a.Hostname, &a.Platform, &a.AgentVersion, &a.Status,
			&sup, &gr, &eff, &a.PolicySource, &a.PolicyHash, &lastSeen, &a.CreatedAt)
	if err != nil {
		return Agent{}, err
	}
	unmarshalStrings(sup, &a.Supported)
	unmarshalStrings(gr, &a.Granted)
	unmarshalStrings(eff, &a.Effective)
	if lastSeen.Valid {
		t := lastSeen.Time
		a.LastSeenAt = &t
	}
	return a, nil
}

// unmarshalStrings decodes a stored JSON array into dst, leaving it nil on empty.
func unmarshalStrings(s string, dst *[]string) {
	if s != "" {
		_ = json.Unmarshal([]byte(s), dst)
	}
}

// UpdateAgent sets an agent's operator-editable display name. Reported fields
// (hostname/platform/version/permissions) are owned by the agent and not touched
// here. Returns sql.ErrNoRows if no live agent has that id.
func (s *Service) UpdateAgent(ctx context.Context, id, displayName string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET display_name=? WHERE id=? AND revoked=0`, displayName, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteAgent hard-deletes an agent and the rows that belong to it. Foreign keys
// are enforced (store.Open sets foreign_keys=ON), so FK-constrained child rows
// (interfaces, agent_status_history, agent_group_members, monitor_status,
// operational_issues) must go before the agent row; the non-FK per-agent tables
// (agent_packets, events, alerts, rule_condition_state) are cleared too so no
// orphaned rows survive. rule_condition_state keys on agent_id with no FK cascade,
// so its per-agent live rows must be deleted explicitly here. All in one transaction.
// Time-series data (series/samples/rollups, plus the metrics store's in-memory
// cache) is NOT handled here — callers purge it via metrics.Store.PurgeAgent so
// the cache stays consistent. Returns sql.ErrNoRows if no agent has that id.
// After a successful commit it publishes a site-wide target-status refresh so
// batch-driven consoles drop the removed agent (and its per-target contribution)
// immediately instead of at the next unrelated event.
func (s *Service) DeleteAgent(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Capture the agent's site before its row is removed so the post-commit refresh
	// targets the right site. A missing row surfaces as sql.ErrNoRows (not-found).
	var siteID string
	if err := tx.QueryRowContext(ctx, `SELECT site_id FROM agents WHERE id=?`, id).Scan(&siteID); err != nil {
		return err
	}

	for _, stmt := range []string{
		`DELETE FROM interfaces WHERE agent_id=?`,
		`DELETE FROM agent_wifi WHERE agent_id=?`,
		`DELETE FROM agent_status_history WHERE agent_id=?`,
		`DELETE FROM agent_group_members WHERE agent_id=?`,
		`DELETE FROM monitor_status WHERE agent_id=?`,
		`DELETE FROM operational_issues WHERE agent_id=?`,
		`DELETE FROM agent_packets WHERE agent_id=?`,
		`DELETE FROM events WHERE agent_id=?`,
		`DELETE FROM alerts WHERE agent_id=?`,
		`DELETE FROM rule_condition_state WHERE agent_id=?`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
			return err
		}
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM agents WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.publishSiteStatus(siteID)
	return nil
}
