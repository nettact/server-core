// Package registry tracks agents: identity, capabilities, status and last-seen.
// M1 provides dev auto-registration (agent appears on first telemetry). Real
// ed25519 enrollment, enrollment tokens and the max_agents quota land in M2.
package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/store"
)

type Agent struct {
	ID           string     `json:"id"`
	SiteID       string     `json:"site_id"`
	DisplayName  string     `json:"display_name"` // operator-set friendly label, editable from the UI
	Hostname     string     `json:"hostname"`
	Platform     string     `json:"platform"`
	AgentVersion string     `json:"agent_version"`
	Status       string     `json:"status"`
	Capabilities []string   `json:"capabilities"` // advertised at enroll; gates host/process/connection views
	LastSeenAt   *time.Time `json:"last_seen_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// StatusEvent is one online/offline transition in an agent's history.
type StatusEvent struct {
	Status    string    `json:"status"` // online | offline
	ChangedAt time.Time `json:"changed_at"`
}

type Service struct {
	db        *store.DB
	maxAgents int // 0 = unlimited
}

// New constructs the registry. maxAgents caps enrollment (0 = unlimited). The
// quota is a product requirement (default 50); note architecture §7/§15 advise
// against hard-limiting Lite — it is intentionally configurable.
func New(db *store.DB, maxAgents int) *Service {
	return &Service{db: db, maxAgents: maxAgents}
}

// TouchLastSeen bumps an agent's last-seen timestamp and marks it online,
// recording an offline→online transition in the status history when the agent
// was previously offline.
func (s *Service) TouchLastSeen(ctx context.Context, id string) error {
	now := time.Now().UTC()
	var prev string
	_ = s.db.QueryRowContext(ctx, `SELECT status FROM agents WHERE id=?`, id).Scan(&prev)
	if _, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen_at=?, status='online' WHERE id=?`, now, id); err != nil {
		return err
	}
	if prev != "online" {
		s.recordStatus(ctx, id, "online", now)
	}
	return nil
}

// UpdateCapabilities refreshes an agent's advertised capabilities from its
// WebSocket Hello, so restarting an agent with different --report-* flags is
// reflected server-side (enrollment happens only once). The conditional WHERE
// makes it a no-op write when nothing changed.
func (s *Service) UpdateCapabilities(ctx context.Context, id string, caps []string) error {
	if caps == nil {
		caps = []string{}
	}
	b, err := json.Marshal(caps)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE agents SET capabilities=? WHERE id=? AND capabilities<>?`, string(b), id, string(b))
	return err
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
		`SELECT id FROM agents WHERE revoked=0 AND status='online' AND last_seen_at IS NOT NULL AND last_seen_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	excluded := make(map[string]bool, len(exclude))
	for _, id := range exclude {
		excluded[id] = true
	}
	var stale []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		if excluded[id] {
			continue
		}
		stale = append(stale, id)
	}
	rows.Close()
	changed := 0
	for _, id := range stale {
		// Re-check the stale condition atomically in the UPDATE: if a keepalive
		// touch marked the agent online (bumping last_seen_at) between the SELECT
		// above and here, the WHERE fails and we neither flip it offline nor write
		// a bogus history row.
		res, err := s.db.ExecContext(ctx,
			`UPDATE agents SET status='offline' WHERE id=? AND status='online' AND last_seen_at < ?`, id, cutoff)
		if err != nil {
			return changed, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			s.recordStatus(ctx, id, "offline", now)
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

// StatusHistory returns an agent's online/offline transitions, newest first.
func (s *Service) StatusHistory(ctx context.Context, agentID string) ([]StatusEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, changed_at FROM agent_status_history WHERE agent_id=? ORDER BY changed_at DESC LIMIT 500`, agentID)
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
		       status, COALESCE(capabilities,'[]'), last_seen_at, created_at
		FROM agents WHERE revoked=0 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		var caps string
		var lastSeen sql.NullTime
		if err := rows.Scan(&a.ID, &a.SiteID, &a.DisplayName, &a.Hostname, &a.Platform, &a.AgentVersion,
			&a.Status, &caps, &lastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		if caps != "" {
			_ = json.Unmarshal([]byte(caps), &a.Capabilities)
		}
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
	var caps string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, site_id, COALESCE(display_name,''), COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,''),
		       status, COALESCE(capabilities,'[]'), last_seen_at, created_at
		FROM agents WHERE id=? AND revoked=0`, id).
		Scan(&a.ID, &a.SiteID, &a.DisplayName, &a.Hostname, &a.Platform, &a.AgentVersion, &a.Status, &caps, &lastSeen, &a.CreatedAt)
	if err != nil {
		return Agent{}, err
	}
	if caps != "" {
		_ = json.Unmarshal([]byte(caps), &a.Capabilities)
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		a.LastSeenAt = &t
	}
	return a, nil
}

// UpdateAgent sets an agent's operator-editable display name. Reported fields
// (hostname/platform/version/capabilities) are owned by the agent and not
// touched here. Returns sql.ErrNoRows if no live agent has that id.
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
// (interfaces, config_versions, agent_status_history, agent_group_members) must
// go before the agent row; the non-FK per-agent tables (agent_packets, events,
// alerts) are cleared too so no orphaned rows survive. All in one transaction.
// Time-series data (series/samples/rollups, plus the metrics store's in-memory
// cache) is NOT handled here — callers purge it via metrics.Store.PurgeAgent so
// the cache stays consistent. Returns sql.ErrNoRows if no agent has that id.
func (s *Service) DeleteAgent(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, stmt := range []string{
		`DELETE FROM interfaces WHERE agent_id=?`,
		`DELETE FROM agent_wifi WHERE agent_id=?`,
		`DELETE FROM config_versions WHERE agent_id=?`,
		`DELETE FROM agent_status_history WHERE agent_id=?`,
		`DELETE FROM agent_group_members WHERE agent_id=?`,
		`DELETE FROM agent_packets WHERE agent_id=?`,
		`DELETE FROM events WHERE agent_id=?`,
		`DELETE FROM alerts WHERE agent_id=?`,
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
	return tx.Commit()
}
