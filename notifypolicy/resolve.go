package notifypolicy

import (
	"context"
	"errors"
)

// Resolve returns the ONE policy that governs an incident in the given group,
// walking the fixed precedence group > site.
//
// A DISABLED override is skipped and the walk continues to the next scope. That
// is the reading an operator expects: turning off a group's override means "fall
// back to the site default", not "silence this group" — silencing is expressed
// by an enabled policy with no channels, which says so explicitly.
//
// groupID may be empty (Agent-connectivity incidents belong to no group), in
// which case the walk starts at the site default.
func (s *Service) Resolve(ctx context.Context, siteID, groupID string) (Effective, error) {
	eff := Effective{Source: "none", Chain: []string{}}
	type step struct{ kind, id string }
	steps := make([]step, 0, 2)
	if groupID != "" {
		steps = append(steps, step{ScopeGroup, groupID})
	}
	steps = append(steps, step{ScopeSite, ""})

	for _, st := range steps {
		eff.Chain = append(eff.Chain, st.kind)
		p, err := s.byScope(ctx, siteID, st.kind, st.id)
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
	return s.Resolve(ctx, siteID, groupID)
}
