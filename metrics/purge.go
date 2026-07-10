package metrics

import "context"

// PurgeTarget deletes every series (with its samples and rollups) for a
// site+target, reclaiming its space immediately. Returns the series removed.
// This is the on-demand "per-target reclaim" — no per-target physical tables
// needed, since samples are already clustered by series.
func (s *Store) PurgeTarget(ctx context.Context, siteID, target string) (int, error) {
	return s.purge(ctx, `SELECT id, agent_id, kind, target FROM series WHERE site_id=? AND target=?`, siteID, target)
}

// PurgeAgent deletes all series for an agent (e.g. when the agent is removed).
func (s *Store) PurgeAgent(ctx context.Context, agentID string) (int, error) {
	return s.purge(ctx, `SELECT id, agent_id, kind, target FROM series WHERE agent_id=?`, agentID)
}

func (s *Store) purge(ctx context.Context, sel string, args ...any) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, sel, args...)
	if err != nil {
		return 0, err
	}
	type sk struct {
		id                   int64
		agent, kind, target  string
	}
	var list []sk
	for rows.Next() {
		var k sk
		if err := rows.Scan(&k.id, &k.agent, &k.kind, &k.target); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, k := range list {
		for _, t := range []string{"samples", "rollup_1m", "rollup_1h", "rollup_1d"} {
			if _, err := s.db.ExecContext(ctx, `DELETE FROM `+t+` WHERE series_id=?`, k.id); err != nil {
				return 0, err
			}
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM series WHERE id=?`, k.id); err != nil {
			return 0, err
		}
		delete(s.cache, seriesKey(k.agent, k.kind, k.target))
	}
	if len(list) > 0 {
		_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	}
	return len(list), nil
}
