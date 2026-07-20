package metrics

import (
	"context"
	"database/sql"
)

// rollupTiers pairs each rollup table with its bucket width (seconds). Buckets
// are aligned to their width (see alignDown in rollup.go), so a bucket row at ts
// covers [ts, ts+width).
var rollupTiers = []struct {
	table string
	width int64
}{
	{"rollup_1m", 60},
	{"rollup_1h", 3600},
	{"rollup_1d", 86400},
}

// PurgeRange deletes samples in [from, to) for the given series and the rollup
// buckets overlapping that window, then repairs the tiers so a subsequent query
// stays consistent. Semantics:
//
//   - Raw samples are deleted precisely on [from, to).
//   - Rollup buckets are whole-bucket units, so every bucket that OVERLAPS the
//     window (bucket start in [alignDown(from,w), to)) is deleted. This can
//     over-delete at the two edges (a boundary bucket straddling from/to loses
//     its surviving out-of-range portion).
//   - The rollup_state watermark for each tier is rewound to alignDown(from,w)
//     (never forward), so the next Rollup() pass recomputes [alignDown(from,w),
//     now) from the SURVIVING source data: interior buckets have no source and
//     stay deleted, while the straddling edge buckets are rebuilt from the raw /
//     lower-tier rows still outside the window — repairing the edge over-delete
//     as long as that source is within its own retention window.
//   - The in-memory latest cache is refreshed when the newest sample was in the
//     deleted window.
//
// The series dictionary row is deliberately KEPT even when the range empties every
// tier: a live series may have already obtained this id via EnsureSeries and be
// about to insert samples outside s.mu, so removing the row here would strand those
// samples under a deleted id. An emptied row is harmless (reachable, reused by the
// next ingest); a deleted-target series is reclaimed by the full orphan-cleanup
// path (PurgeSeriesIDs) instead.
//
// from/to are unix seconds and to must be > from. For a full (unbounded) delete
// callers use PurgeSeriesIDs instead.
func (s *Store) PurgeRange(ctx context.Context, ids []int64, from, to int64) (PurgeCounts, error) {
	if len(ids) == 0 || to <= from {
		return PurgeCounts{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var counts PurgeCounts
	for _, id := range ids {
		// Raw: precise range delete.
		res, err := s.db.ExecContext(ctx, `DELETE FROM samples WHERE series_id=? AND ts>=? AND ts<?`, id, from, to)
		if err != nil {
			return counts, err
		}
		n, _ := res.RowsAffected()
		counts.Samples += n

		// Rollups: whole-bucket delete of every overlapping bucket + watermark rewind.
		for _, t := range rollupTiers {
			lo := alignDown(from, t.width)
			res, err := s.db.ExecContext(ctx,
				`DELETE FROM `+t.table+` WHERE series_id=? AND ts>=? AND ts<?`, id, lo, to)
			if err != nil {
				return counts, err
			}
			rn, _ := res.RowsAffected()
			counts.Rollups += rn
			// Rewind the watermark so Rollup() revisits (and rebuilds edge buckets of)
			// this window; only when it currently sits past lo, never push it forward.
			resStr := t.table[len("rollup_"):]
			if _, err := s.db.ExecContext(ctx,
				`UPDATE rollup_state SET last_ts=? WHERE resolution=? AND series_id=? AND last_ts>?`,
				lo, resStr, id, lo); err != nil {
				return counts, err
			}
		}

		// Refresh the latest cache if the newest known sample was just deleted.
		if lv, ok := s.latest[id]; ok && lv.ts >= from && lv.ts < to {
			var ts int64
			var v float64
			err := s.db.Read().QueryRowContext(ctx,
				`SELECT ts, value FROM samples WHERE series_id=? ORDER BY ts DESC LIMIT 1`, id).Scan(&ts, &v)
			switch err {
			case nil:
				s.latest[id] = latestVal{ts: ts, value: v}
			case sql.ErrNoRows:
				delete(s.latest, id)
			default:
				return counts, err
			}
		}
	}
	_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(2000)`)
	return counts, nil
}

// InventoryEntry is one stored series row (a single generation) with its data
// extent and an approximate sample count. The cleanup service collapses
// generations of the same logical (agent, monitor, kind, target) key and joins
// human-readable names and live/deleted status.
type InventoryEntry struct {
	SeriesID   int64  `json:"series_id"`
	AgentID    string `json:"agent_id"`
	MonitorID  string `json:"monitor_id"`
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	Layer      string `json:"layer"`
	Unit       string `json:"unit"`
	Earliest   int64  `json:"earliest_ts"` // 0 = no data
	Latest     int64  `json:"latest_ts"`
	EstSamples int64  `json:"est_samples"` // approximate; from rollup counters
}

// CleanupInventory returns every series row for a site with its data extent and
// an approximate sample count, ordered for stable grouping. Reads run on the read
// pool. Counts are estimates from the rollup counters (never a COUNT(*) over the
// large samples table): SUM(cnt) of the 1d rollup, else the 1m rollup, else a
// bounded raw count for a series younger than one rollup bucket.
func (s *Store) CleanupInventory(ctx context.Context, siteID string) ([]InventoryEntry, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, agent_id, COALESCE(monitor_id,''), kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,'')
		FROM series WHERE site_id=? ORDER BY agent_id, monitor_id, kind, target, config_serial`, siteID)
	if err != nil {
		return nil, err
	}
	var out []InventoryEntry
	for rows.Next() {
		var e InventoryEntry
		if err := rows.Scan(&e.SeriesID, &e.AgentID, &e.MonitorID, &e.Kind, &e.Target, &e.Layer, &e.Unit); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.fillEntryStats(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// fillEntryStats populates one entry's earliest/latest/est from index-bounded
// per-series seeks (MIN/MAX use the (series_id, ts) PK; the rollup SUMs scan only
// that series' bucket rows).
func (s *Store) fillEntryStats(ctx context.Context, e *InventoryEntry) error {
	var sMin, sMax, dMin, dMax sql.NullInt64
	var d1, m1 int64
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT
			(SELECT MIN(ts) FROM samples   WHERE series_id=?),
			(SELECT MAX(ts) FROM samples   WHERE series_id=?),
			(SELECT MIN(ts) FROM rollup_1d WHERE series_id=?),
			(SELECT MAX(ts) FROM rollup_1d WHERE series_id=?),
			(SELECT COALESCE(SUM(cnt),0) FROM rollup_1d WHERE series_id=?),
			(SELECT COALESCE(SUM(cnt),0) FROM rollup_1m WHERE series_id=?)`,
		e.SeriesID, e.SeriesID, e.SeriesID, e.SeriesID, e.SeriesID, e.SeriesID).
		Scan(&sMin, &sMax, &dMin, &dMax, &d1, &m1)
	if err != nil {
		return err
	}
	e.Earliest = minNonZero(nullVal(sMin), nullVal(dMin))
	latest := nullVal(sMax)
	if dMax.Valid && dMax.Int64+86400 > latest {
		latest = dMax.Int64 + 86400
	}
	e.Latest = latest
	switch {
	case d1 > 0:
		e.EstSamples = d1
	case m1 > 0:
		e.EstSamples = m1
	case sMin.Valid:
		// Young series with only raw samples: a bounded count of its own rows.
		_ = s.db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE series_id=?`, e.SeriesID).Scan(&e.EstSamples)
	}
	return nil
}

func nullVal(n sql.NullInt64) int64 {
	if n.Valid {
		return n.Int64
	}
	return 0
}

func minNonZero(a, b int64) int64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}

// RangeCounts is the per-tier exact row count of a proposed delete, for the
// preview. It uses the same bucket-aligned bounds PurgeRange deletes with, so the
// preview total matches the actual deletion (modulo ingest still in flight).
type RangeCounts struct {
	Samples  int64 `json:"samples"`
	Rollup1m int64 `json:"rollup_1m"`
	Rollup1h int64 `json:"rollup_1h"`
	Rollup1d int64 `json:"rollup_1d"`
}

// Rollups returns the total rollup rows across tiers.
func (c RangeCounts) Rollups() int64 { return c.Rollup1m + c.Rollup1h + c.Rollup1d }

// CountRange counts the rows a delete of [from, to) over ids would remove. When
// from==0 && to==0 it counts every row for those series (the full-delete preview).
func (s *Store) CountRange(ctx context.Context, ids []int64, from, to int64) (RangeCounts, error) {
	var c RangeCounts
	full := from == 0 && to == 0
	for _, id := range ids {
		var n int64
		if full {
			if err := s.db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE series_id=?`, id).Scan(&n); err != nil {
				return c, err
			}
		} else {
			if err := s.db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE series_id=? AND ts>=? AND ts<?`, id, from, to).Scan(&n); err != nil {
				return c, err
			}
		}
		c.Samples += n
		for _, t := range rollupTiers {
			var rn int64
			if full {
				if err := s.db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+t.table+` WHERE series_id=?`, id).Scan(&rn); err != nil {
					return c, err
				}
			} else {
				lo := alignDown(from, t.width)
				if err := s.db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+t.table+` WHERE series_id=? AND ts>=? AND ts<?`, id, lo, to).Scan(&rn); err != nil {
					return c, err
				}
			}
			switch t.table {
			case "rollup_1m":
				c.Rollup1m += rn
			case "rollup_1h":
				c.Rollup1h += rn
			case "rollup_1d":
				c.Rollup1d += rn
			}
		}
	}
	return c, nil
}
