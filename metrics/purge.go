package metrics

import (
	"context"
	"database/sql"
)

// PurgeCounts is the row tally of a delete, fed into cleanup-job progress.
type PurgeCounts struct {
	Samples int64 `json:"samples"`
	Rollups int64 `json:"rollups"`
	Series  int64 `json:"series"`
}

// PurgeAgent deletes all series for an agent (e.g. when the agent is removed).
func (s *Store) PurgeAgent(ctx context.Context, agentID string) (int, error) {
	ids, err := s.seriesIDsBy(ctx, `SELECT id FROM series WHERE agent_id=?`, agentID)
	if err != nil {
		return 0, err
	}
	c, err := s.PurgeSeriesIDs(ctx, ids)
	return int(c.Series), err
}

// seriesIDsBy runs a SELECT id query on the read pool and collects the ids.
func (s *Store) seriesIDsBy(ctx context.Context, sel string, args ...any) ([]int64, error) {
	rows, err := s.db.Read().QueryContext(ctx, sel, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ResolveSeriesIDs returns every series id (all generations) for one logical
// series key within a site. monitorID="" matches system series. Used by the
// cleanup runner to turn a frozen logical selection back into concrete ids at
// execution time, so a job is idempotent across restarts (an already-deleted key
// resolves to nothing). The site predicate keeps a job scoped to its own site: a
// key naming an agent in another site resolves to no ids here.
func (s *Store) ResolveSeriesIDs(ctx context.Context, siteID, agentID, monitorID, kind, target string) ([]int64, error) {
	return s.seriesIDsBy(ctx,
		`SELECT id FROM series WHERE site_id=? AND agent_id=? AND monitor_id=? AND kind=? AND target=?`,
		siteID, agentID, monitorID, kind, target)
}

// PurgeSeriesIDs fully removes the given series: every sample and rollup row, the
// rollup watermarks, and the series dictionary rows, evicting each from the
// in-memory caches. Returns the rows deleted per class. The shared full-delete
// core behind PurgeAgent and the cleanup runner's unbounded (whole-series) path.
func (s *Store) PurgeSeriesIDs(ctx context.Context, ids []int64) (PurgeCounts, error) {
	if len(ids) == 0 {
		return PurgeCounts{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// The identity tuple is needed to evict the caches keyed by seriesKey; read it
	// before the rows are deleted.
	type sk struct {
		id                           int64
		agent, monitor, kind, target string
		configSerial                 int
	}
	var list []sk
	for _, id := range ids {
		var k sk
		k.id = id
		err := s.db.QueryRowContext(ctx,
			`SELECT agent_id, COALESCE(monitor_id,''), kind, COALESCE(target,''), config_serial FROM series WHERE id=?`, id).
			Scan(&k.agent, &k.monitor, &k.kind, &k.target, &k.configSerial)
		if err == sql.ErrNoRows {
			continue // already gone (idempotent re-purge)
		}
		if err != nil {
			return PurgeCounts{}, err
		}
		list = append(list, k)
	}

	var counts PurgeCounts
	for _, k := range list {
		for _, t := range []string{"samples", "rollup_1m", "rollup_1h", "rollup_1d"} {
			res, err := s.db.ExecContext(ctx, `DELETE FROM `+t+` WHERE series_id=?`, k.id)
			if err != nil {
				return counts, err
			}
			n, _ := res.RowsAffected()
			if t == "samples" {
				counts.Samples += n
			} else {
				counts.Rollups += n
			}
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM rollup_state WHERE series_id=?`, k.id); err != nil {
			return counts, err
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM series WHERE id=?`, k.id); err != nil {
			return counts, err
		}
		counts.Series++
		s.evictLocked(k.agent, k.monitor, k.kind, k.target, k.configSerial, k.id)
	}
	if len(list) > 0 {
		_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(2000)`)
	}
	return counts, nil
}

// evictLocked drops a series from every in-memory cache. Caller holds s.mu.
func (s *Store) evictLocked(agent, monitor, kind, target string, configSerial int, id int64) {
	delete(s.cache, seriesKey(agent, monitor, kind, target, configSerial))
	delete(s.latest, id)
	if ag := s.byAgent[agent]; ag != nil {
		delete(ag, id)
	}
}
