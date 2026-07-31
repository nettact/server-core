package notifypolicy

import (
	"context"
	"errors"
)

// Query is what needs a policy: the site it happened in, plus whichever specific
// scope the incident can be governed by. The two specific scopes are mutually
// exclusive by construction — an Agent-connectivity incident belongs to no
// monitor group, and a probe fault is never an Agent-liveness one — so a query
// carries at most one of them and the walk is always two steps at most.
type Query struct {
	SiteID string
	// GroupID is the monitor group a probe fault's incident belongs to; empty
	// when it has none.
	GroupID string
	// AgentConnectivity marks an Agent-liveness incident, which is routed by the
	// site's Agent-connectivity policy rather than by any group.
	AgentConnectivity bool
}

// Resolve returns the ONE policy that governs an incident, walking the fixed
// precedence for its kind:
//
//	probe fault    group > site
//	Agent offline  agent > site
//
// A DISABLED specific policy is skipped and the walk continues to the site
// default. That is the reading an operator expects: turning off a group's
// override — or the Agent-connectivity policy — means "fall back to the site
// default", not "silence this scope". Silencing is expressed by an ENABLED
// policy with no channels, which says so explicitly.
func (s *Service) Resolve(ctx context.Context, q Query) (Effective, error) {
	eff := Effective{Source: "none", Chain: []string{}}
	type step struct{ kind, id string }
	steps := make([]step, 0, 2)
	switch {
	case q.AgentConnectivity:
		steps = append(steps, step{ScopeAgent, ""})
	case q.GroupID != "":
		steps = append(steps, step{ScopeGroup, q.GroupID})
	}
	steps = append(steps, step{ScopeSite, ""})

	for _, st := range steps {
		eff.Chain = append(eff.Chain, st.kind)
		p, err := s.byScope(ctx, q.SiteID, st.kind, st.id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return Effective{}, err
		}
		if !p.Enabled {
			continue
		}
		found := p
		eff.Policy = &found
		eff.Source = st.kind
		return eff, nil
	}
	return eff, nil
}

// ResolveForTarget resolves the effective policy for a monitoring target by
// looking up its owning group itself, so an API caller only has to name the
// target. Returns the "none" effective value when the target does not exist.
func (s *Service) ResolveForTarget(ctx context.Context, targetID string) (Effective, error) {
	var siteID, groupID string
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT site_id, group_id FROM probe_tasks WHERE id=?`, targetID).Scan(&siteID, &groupID); err != nil {
		return Effective{}, err
	}
	return s.Resolve(ctx, Query{SiteID: siteID, GroupID: groupID})
}

// ResolveForAgentConnectivity resolves the effective policy for the site's
// Agent-offline faults, so the console can preview the same answer the delivery
// planner will use rather than restating the precedence rule in the UI.
func (s *Service) ResolveForAgentConnectivity(ctx context.Context, siteID string) (Effective, error) {
	return s.Resolve(ctx, Query{SiteID: siteID, AgentConnectivity: true})
}
