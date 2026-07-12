package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AgentGroup is a named set of agents within a site. A target scoped to a group
// (config all_agents=0) is pushed only to that group's members; an agent may
// belong to several groups.
type AgentGroup struct {
	ID        string    `json:"id"`
	SiteID    string    `json:"site_id"`
	Name      string    `json:"name"`
	AgentIDs  []string  `json:"agent_ids"`
	CreatedAt time.Time `json:"created_at"`
}

// ListGroups returns a site's agent groups, each with its member agent IDs.
func (s *Service) ListGroups(ctx context.Context, siteID string) ([]AgentGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, site_id, name, created_at FROM agent_groups WHERE site_id=? ORDER BY name`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentGroup
	byID := make(map[string]*AgentGroup)
	for rows.Next() {
		var g AgentGroup
		if err := rows.Scan(&g.ID, &g.SiteID, &g.Name, &g.CreatedAt); err != nil {
			return nil, err
		}
		g.AgentIDs = []string{}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	mrows, err := s.db.QueryContext(ctx,
		`SELECT agm.group_id, agm.agent_id FROM agent_group_members agm
		 JOIN agent_groups g ON g.id = agm.group_id
		 WHERE g.site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var groupID, agentID string
		if err := mrows.Scan(&groupID, &agentID); err != nil {
			return nil, err
		}
		if g := byID[groupID]; g != nil {
			g.AgentIDs = append(g.AgentIDs, agentID)
		}
	}
	return out, mrows.Err()
}

// CreateGroup creates an empty agent group in a site and returns its ID. An empty
// group has no members yet, so it changes no agent's desired state; no config
// bump is needed until members are assigned.
func (s *Service) CreateGroup(ctx context.Context, siteID, name string) (string, error) {
	id := "grp_" + uuid.NewString()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_groups(id, site_id, name) VALUES(?,?,?)`, id, siteID, name)
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpdateGroup renames a group and reconciles its membership to exactly agentIDs,
// then bumps config_version for the site so affected agents pick up the change on
// their next telemetry ack. Returns the group's site id (so the caller can resolve
// alerts stranded by agents leaving the group's scope) and sql.ErrNoRows if no
// such group.
func (s *Service) UpdateGroup(ctx context.Context, groupID, name string, agentIDs []string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var siteID string
	if err := tx.QueryRowContext(ctx, `SELECT site_id FROM agent_groups WHERE id=?`, groupID).Scan(&siteID); err != nil {
		return "", err // sql.ErrNoRows when the group is gone
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_groups SET name=? WHERE id=?`, name, groupID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_group_members WHERE group_id=?`, groupID); err != nil {
		return "", err
	}
	// Only agents in this group's own site may be members: the INSERT..SELECT
	// filters by site_id so a cross-site (or unknown) agent id inserts no row and
	// is rejected. A group must not scope another site's targets onto an agent the
	// site-wide config bump below would never reach.
	seen := make(map[string]bool, len(agentIDs))
	for _, aid := range agentIDs {
		if seen[aid] {
			continue
		}
		seen[aid] = true
		res, err := tx.ExecContext(ctx,
			`INSERT INTO agent_group_members(group_id, agent_id)
			 SELECT ?, id FROM agents WHERE id=? AND site_id=?`, groupID, aid, siteID)
		if err != nil {
			return "", err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return "", fmt.Errorf("agent %q does not belong to site %s", aid, siteID)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agents SET config_version=config_version+1 WHERE site_id=?`, siteID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return siteID, nil
}

// DeleteGroup removes a group, its membership rows, and its target bindings
// (probe_task_groups), then bumps config_version for the site. Targets bound only
// to this group fall back to reaching no agents until re-scoped. Returns the
// group's site id (so the caller can resolve alerts stranded by the removed
// bindings) and sql.ErrNoRows if no such group.
func (s *Service) DeleteGroup(ctx context.Context, groupID string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var siteID string
	if err := tx.QueryRowContext(ctx, `SELECT site_id FROM agent_groups WHERE id=?`, groupID).Scan(&siteID); err != nil {
		return "", err
	}
	for _, stmt := range []string{
		`DELETE FROM agent_group_members WHERE group_id=?`,
		`DELETE FROM probe_task_groups WHERE group_id=?`,
		`DELETE FROM agent_groups WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, groupID); err != nil {
			return "", err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agents SET config_version=config_version+1 WHERE site_id=?`, siteID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return siteID, nil
}
