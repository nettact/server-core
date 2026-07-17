package metrics

import "context"

// PurgeMonitor deletes every series (with its samples and rollups) recorded by
// one user-created monitor, across all agents and all its generations. Returns
// the series removed.
func (s *Store) PurgeMonitor(ctx context.Context, siteID, monitorID string) (int, error) {
	if monitorID == "" {
		return 0, nil // '' is the system-series marker, never a purgable monitor
	}
	return s.purge(ctx, `SELECT id, agent_id, monitor_id, kind, target, config_serial FROM series WHERE site_id=? AND monitor_id=?`,
		siteID, monitorID)
}

// PurgeTarget deletes SYSTEM series (monitor_id=”) for a site+target — e.g.
// a removed interface or a stale mount point. Monitor data is purged per
// monitor via PurgeMonitor, so a shared target string never collateral-damages
// another monitor's history.
func (s *Store) PurgeTarget(ctx context.Context, siteID, target string) (int, error) {
	return s.purge(ctx, `SELECT id, agent_id, monitor_id, kind, target, config_serial FROM series WHERE site_id=? AND target=? AND monitor_id=''`,
		siteID, target)
}

// PurgeAgent deletes all series for an agent (e.g. when the agent is removed).
func (s *Store) PurgeAgent(ctx context.Context, agentID string) (int, error) {
	return s.purge(ctx, `SELECT id, agent_id, monitor_id, kind, target, config_serial FROM series WHERE agent_id=?`, agentID)
}

func (s *Store) purge(ctx context.Context, sel string, args ...any) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, sel, args...)
	if err != nil {
		return 0, err
	}
	type sk struct {
		id                           int64
		agent, monitor, kind, target string
		configSerial                 int
	}
	var list []sk
	for rows.Next() {
		var k sk
		if err := rows.Scan(&k.id, &k.agent, &k.monitor, &k.kind, &k.target, &k.configSerial); err != nil {
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
		if _, err := s.db.ExecContext(ctx, `DELETE FROM rollup_state WHERE series_id=?`, k.id); err != nil {
			return 0, err
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM series WHERE id=?`, k.id); err != nil {
			return 0, err
		}
		delete(s.cache, seriesKey(k.agent, k.monitor, k.kind, k.target, k.configSerial))
		delete(s.latest, k.id)
		if ag := s.byAgent[k.agent]; ag != nil {
			delete(ag, k.id)
		}
	}
	if len(list) > 0 {
		_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(2000)`)
	}
	return len(list), nil
}
