package statuspage

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/nettact/server-core/agentstatus"
	"github.com/nettact/server-core/targetstatus"
)

// ---- public DTOs ----
//
// These are the anonymous wire contract. They are defined as their own structs
// rather than reusing the console's rows precisely so that adding a field to
// AgentStatusRow or TargetStatus can never publish it by accident: anything that
// reaches the outside has to be written down here on purpose.

// PublicPage is the page's own description — enough to render a header and decide
// which lists to request. It carries no ids and no site.
type PublicPage struct {
	Slug              string    `json:"slug"`
	Title             string    `json:"title"`
	Description       string    `json:"description,omitempty"`
	ShowAgentView     bool      `json:"show_agent_view"`
	ShowTargetView    bool      `json:"show_target_view"`
	ShowTargetAddress bool      `json:"show_target_address"`
	GeneratedAt       time.Time `json:"generated_at"`
}

// PublicAgentRow is one published agent. Name is the operator-set display name
// and is empty when unset — the hostname is NEVER substituted, because a hostname
// is exactly the kind of internal detail publishing an availability figure should
// not also disclose. An unnamed agent is rendered from Ordinal instead.
type PublicAgentRow struct {
	Name        string     `json:"name"`
	Ordinal     int        `json:"ordinal"`
	Online      bool       `json:"online"`
	StatusSince *time.Time `json:"status_since,omitempty"`
}

// PublicAgentStatuses is the agent view's payload.
type PublicAgentStatuses struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Agents      []PublicAgentRow `json:"agents"`
}

// PublicTargetRow is one published monitoring target. Address is present only
// when the page opted into showing addresses; Availability24h is nil when the
// window holds no verdict, because "unknown" and "0%" are different answers and
// must look it.
type PublicTargetRow struct {
	Name            string   `json:"name"`
	Ordinal         int      `json:"ordinal"`
	Kind            string   `json:"kind"`
	Address         string   `json:"address,omitempty"`
	Status          string   `json:"status"`
	Availability24h *float64 `json:"availability_24h,omitempty"`
}

// PublicTargetStatuses is the target view's payload.
type PublicTargetStatuses struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Targets     []PublicTargetRow `json:"targets"`
}

// The public status vocabulary. Four values, against the twelve display states
// the console renders: the internal set names internal causes (permission
// blocked, agent offline, awaiting first report), and those are operator
// diagnostics, not something an anonymous reader should be handed.
const (
	StatusUp       = "up"
	StatusDown     = "down"
	StatusDegraded = "degraded"
	StatusUnknown  = "unknown"
)

// publicStatus coarsens one display_state (targetstatus's twelve-value enum) into
// the public four. Anything unrecognized becomes "unknown" rather than defaulting
// to "up": a state this function has not been taught about must never be
// published as healthy.
func publicStatus(displayState string) string {
	switch displayState {
	case "healthy":
		return StatusUp
	case "faulted", "partial_failure", "probe_failed":
		return StatusDown
	case "confirming", "stale":
		return StatusDegraded
	default:
		// pending, no_data, blocked, agent_offline, disabled, unassigned — and
		// anything added later.
		return StatusUnknown
	}
}

// ---- public reads ----

// pageRow is the resolved public page, minus everything the outside never sees.
type pageRow struct {
	id                string
	siteID            string
	slug              string
	title             string
	description       string
	showTargetAddress bool
	showAgentView     bool
	showTargetView    bool
}

// PublicPage resolves a slug to its public description.
func (s *Service) PublicPage(ctx context.Context, slug string) (PublicPage, error) {
	p, err := s.resolve(ctx, slug)
	if err != nil {
		return PublicPage{}, err
	}
	return PublicPage{
		Slug:              p.slug,
		Title:             p.title,
		Description:       p.description,
		ShowAgentView:     p.showAgentView,
		ShowTargetView:    p.showTargetView,
		ShowTargetAddress: p.showTargetAddress,
		GeneratedAt:       s.now().UTC(),
	}, nil
}

// PublicAgentStatuses serves the agent view. A page with the agent view turned off
// answers ErrPageNotFound, identically to an unknown slug: the toggle is enforced
// here rather than by the frontend declining to ask, because this endpoint is
// directly reachable.
func (s *Service) PublicAgentStatuses(ctx context.Context, slug string) (PublicAgentStatuses, error) {
	p, err := s.resolve(ctx, slug)
	if err != nil {
		return PublicAgentStatuses{}, err
	}
	if !p.showAgentView {
		return PublicAgentStatuses{}, ErrPageNotFound
	}
	selected, err := s.selection(ctx, `SELECT agent_id FROM status_page_agents WHERE page_id=?`, p.id)
	if err != nil {
		return PublicAgentStatuses{}, err
	}
	snap, err := s.agentSnapshot(ctx, p.siteID)
	if err != nil {
		return PublicAgentStatuses{}, err
	}

	// Filtering against the live aggregation is also the backstop for stale
	// selections: an id that no longer resolves to a real agent simply has no row
	// to publish.
	rows := make([]agentstatus.AgentStatusRow, 0, len(selected))
	for _, row := range snap.Agents {
		if selected[row.ID] {
			rows = append(rows, row)
		}
	}
	// The aggregation orders by created_at, whose second-level precision leaves
	// same-second enrollments in an arbitrary order — fine for a console list,
	// not for ordinals that end up in a published label. Re-sort with the id as
	// the tiebreak so the numbering is stable across polls.
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if (a.DisplayName == "") != (b.DisplayName == "") {
			return a.DisplayName != "" // unnamed agents last
		}
		if a.DisplayName != b.DisplayName {
			return a.DisplayName < b.DisplayName
		}
		return a.ID < b.ID
	})

	out := make([]PublicAgentRow, 0, len(rows))
	for i, row := range rows {
		out = append(out, PublicAgentRow{
			Name:        row.DisplayName,
			Ordinal:     i + 1,
			Online:      row.Presence == "online",
			StatusSince: row.StatusSince,
		})
	}
	return PublicAgentStatuses{GeneratedAt: snap.GeneratedAt, Agents: out}, nil
}

// PublicTargetStatuses serves the target view, with the same server-side toggle
// enforcement as the agent view.
func (s *Service) PublicTargetStatuses(ctx context.Context, slug string) (PublicTargetStatuses, error) {
	p, err := s.resolve(ctx, slug)
	if err != nil {
		return PublicTargetStatuses{}, err
	}
	if !p.showTargetView {
		return PublicTargetStatuses{}, ErrPageNotFound
	}
	selected, err := s.selection(ctx, `SELECT target_id FROM status_page_targets WHERE page_id=?`, p.id)
	if err != nil {
		return PublicTargetStatuses{}, err
	}
	snap, err := s.targetSnapshot(ctx, p.siteID)
	if err != nil {
		return PublicTargetStatuses{}, err
	}

	rows := make([]targetstatus.TargetStatus, 0, len(selected))
	for _, row := range snap.Targets {
		if selected[row.TargetID] {
			rows = append(rows, row)
		}
	}
	// Group by kind, named before unnamed, id as the final tiebreak. Ordinals are
	// assigned within a kind in exactly this order, which is what makes the label
	// an unnamed target renders ("HTTP target 3") the same on every poll.
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if (a.Name == "") != (b.Name == "") {
			return a.Name != ""
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.TargetID < b.TargetID
	})

	perKind := map[string]int{}
	out := make([]PublicTargetRow, 0, len(rows))
	for _, row := range rows {
		perKind[row.Kind]++
		pub := PublicTargetRow{
			Name:            row.Name,
			Ordinal:         perKind[row.Kind],
			Kind:            row.Kind,
			Status:          publicStatus(row.DisplayState),
			Availability24h: row.Availability24h,
		}
		if p.showTargetAddress {
			pub.Address = row.Target
		}
		out = append(out, pub)
	}
	return PublicTargetStatuses{GeneratedAt: snap.GeneratedAt, Targets: out}, nil
}

// resolve looks up an enabled page by slug. A disabled page and an unknown slug
// return the same error on purpose — taking a page down must not confirm that it
// once existed.
func (s *Service) resolve(ctx context.Context, slug string) (pageRow, error) {
	var p pageRow
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT id, site_id, slug, title, description, show_target_address, show_agent_view, show_target_view
		FROM status_pages WHERE slug=? AND enabled=1`, slug).
		Scan(&p.id, &p.siteID, &p.slug, &p.title, &p.description,
			&p.showTargetAddress, &p.showAgentView, &p.showTargetView)
	if errors.Is(err, sql.ErrNoRows) {
		return pageRow{}, ErrPageNotFound
	}
	if err != nil {
		return pageRow{}, err
	}
	return p, nil
}

func (s *Service) selection(ctx context.Context, query, pageID string) (map[string]bool, error) {
	rows, err := s.db.Read().QueryContext(ctx, query, pageID)
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

// ---- snapshot cache ----
//
// Both helpers hold the mutex across the aggregation call. That collapses a burst
// of anonymous readers into one query instead of one query each, which is the
// whole reason the cache exists; the lock is per-service, and every caller here
// is a read that was going to wait on the same database anyway.

func (s *Service) targetSnapshot(ctx context.Context, siteID string) (targetstatus.SiteStatuses, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.targetCache[siteID]; ok && s.now().Sub(e.at) < s.ttl {
		return e.data, nil
	}
	data, err := s.targets.SiteStatuses(ctx, siteID)
	if err != nil {
		return targetstatus.SiteStatuses{}, err
	}
	s.targetCache[siteID] = targetSnapshot{at: s.now(), data: data}
	return data, nil
}

func (s *Service) agentSnapshot(ctx context.Context, siteID string) (agentstatus.SiteAgentStatuses, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.agentCache[siteID]; ok && s.now().Sub(e.at) < s.ttl {
		return e.data, nil
	}
	data, err := s.agents.SiteAgentStatuses(ctx, siteID)
	if err != nil {
		return agentstatus.SiteAgentStatuses{}, err
	}
	s.agentCache[siteID] = agentSnapshot{at: s.now(), data: data}
	return data, nil
}
