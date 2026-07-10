// Package config manages monitoring targets (probe_tasks) and builds the
// DesiredState the server pushes down to agents. Targets are configured
// centrally in Lite so agents stay near-zero-config; changing them bumps the
// per-agent config_version so the next telemetry ack carries the new state.
package config

import (
	"context"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

// Default scheduler intervals delivered to agents (seconds).
const (
	defaultBaseSeconds    = 10
	defaultRegularSeconds = 30
)

type Service struct {
	db  *store.DB
	reg *registry.Service
}

func New(db *store.DB, reg *registry.Service) *Service {
	return &Service{db: db, reg: reg}
}

// ProbeTarget is a site-scoped monitoring target managed via the UI.
type ProbeTarget struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`   // "icmp" (M2)
	Target  string `json:"target"` // "1.1.1.1", "example.com", …
	Tier    string `json:"tier"`   // "base" | "regular"
	Enabled bool   `json:"enabled"`
}

// SeedDefaults inserts a few public ICMP targets for a site if it has none, so
// agents get useful public-reachability monitoring out of the box.
func (s *Service) SeedDefaults(ctx context.Context, siteID string) error {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM probe_tasks WHERE site_id=? AND agent_id IS NULL`, siteID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	defaults := []ProbeTarget{
		{Kind: "icmp", Target: "1.1.1.1", Tier: "base", Enabled: true},
		{Kind: "icmp", Target: "8.8.8.8", Tier: "base", Enabled: true},
		{Kind: "icmp", Target: "223.5.5.5", Tier: "base", Enabled: true},
	}
	return s.SetSiteTargets(ctx, siteID, defaults)
}

// ListSiteTargets returns the site-scoped monitoring targets.
func (s *Service) ListSiteTargets(ctx context.Context, siteID string) ([]ProbeTarget, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, COALESCE(target,''), tier, enabled
		 FROM probe_tasks WHERE site_id=? AND agent_id IS NULL ORDER BY kind, target`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeTarget
	for rows.Next() {
		var t ProbeTarget
		var enabled int
		if err := rows.Scan(&t.ID, &t.Kind, &t.Target, &t.Tier, &enabled); err != nil {
			return nil, err
		}
		t.Enabled = enabled == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetSiteTargets replaces all site-scoped targets and bumps config_version for
// every agent in the site so they pick up the change on next telemetry.
func (s *Service) SetSiteTargets(ctx context.Context, siteID string, targets []ProbeTarget) error {
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

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM probe_tasks WHERE site_id=? AND agent_id IS NULL`, siteID); err != nil {
		return err
	}
	for _, t := range targets {
		if t.Tier == "" {
			t.Tier = "base"
		}
		enabled := 0
		if t.Enabled {
			enabled = 1
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO probe_tasks(id, site_id, agent_id, kind, target, tier, enabled)
			 VALUES(?,?,NULL,?,?,?,?)`,
			"probe_"+uuid.NewString(), siteID, t.Kind, t.Target, t.Tier, enabled); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return s.reg.BumpConfigVersionForSite(ctx, siteID)
}

// DesiredStateFor builds the config to push to a specific agent.
func (s *Service) DesiredStateFor(ctx context.Context, agentID string) (pcfg.DesiredState, error) {
	st, err := s.reg.ConfigStatus(ctx, agentID)
	if err != nil {
		return pcfg.DesiredState{}, err
	}
	targets, err := s.ListSiteTargets(ctx, st.SiteID)
	if err != nil {
		return pcfg.DesiredState{}, err
	}
	ds := pcfg.DesiredState{
		ConfigVersion: st.ConfigVersion,
		Intervals:     pcfg.Intervals{BaseSeconds: defaultBaseSeconds, RegularSeconds: defaultRegularSeconds},
	}
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		ds.ProbeTargets = append(ds.ProbeTargets, pcfg.ProbeTarget{Kind: t.Kind, Target: t.Target, Tier: t.Tier})
	}
	return ds, nil
}
