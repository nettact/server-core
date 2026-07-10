// Package registry tracks agents: identity, capabilities, status and last-seen.
// M1 provides dev auto-registration (agent appears on first telemetry). Real
// ed25519 enrollment, enrollment tokens and the max_agents quota land in M2.
package registry

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nettact/server-core/store"
)

type Agent struct {
	ID           string     `json:"id"`
	SiteID       string     `json:"site_id"`
	Hostname     string     `json:"hostname"`
	Platform     string     `json:"platform"`
	AgentVersion string     `json:"agent_version"`
	Status       string     `json:"status"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

// EnsureDevAgent auto-registers (or refreshes) an agent seen via telemetry in
// dev mode. It stores an empty key/token — a placeholder replaced by real
// enrollment in M2.
func (s *Service) EnsureDevAgent(ctx context.Context, id, siteID, hostname, platform, version string) error {
	if id == "" {
		return errors.New("empty agent id")
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents(id, site_id, public_key, token_hash, hostname, platform, agent_version, status, last_seen_at, created_at)
		VALUES(?, ?, X'', '', ?, ?, ?, 'online', ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname=COALESCE(NULLIF(excluded.hostname,''), agents.hostname),
			platform=COALESCE(NULLIF(excluded.platform,''), agents.platform),
			agent_version=COALESCE(NULLIF(excluded.agent_version,''), agents.agent_version),
			status='online',
			last_seen_at=excluded.last_seen_at`,
		id, siteID, hostname, platform, version, now, now)
	return err
}

// TouchLastSeen bumps an agent's last-seen timestamp.
func (s *Service) TouchLastSeen(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen_at=?, status='online' WHERE id=?`, time.Now().UTC(), id)
	return err
}

func (s *Service) List(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, site_id, COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,''),
		       status, last_seen_at, created_at
		FROM agents WHERE revoked=0 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		var lastSeen sql.NullTime
		if err := rows.Scan(&a.ID, &a.SiteID, &a.Hostname, &a.Platform, &a.AgentVersion,
			&a.Status, &lastSeen, &a.CreatedAt); err != nil {
			return nil, err
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
	err := s.db.QueryRowContext(ctx, `
		SELECT id, site_id, COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,''),
		       status, last_seen_at, created_at
		FROM agents WHERE id=? AND revoked=0`, id).
		Scan(&a.ID, &a.SiteID, &a.Hostname, &a.Platform, &a.AgentVersion, &a.Status, &lastSeen, &a.CreatedAt)
	if err != nil {
		return Agent{}, err
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		a.LastSeenAt = &t
	}
	return a, nil
}
