package metrics

import (
	"context"
	"strconv"
	"time"
)

// RetentionConfig is how long each tier is kept (seconds); 0 = keep forever.
type RetentionConfig struct {
	RawSeconds int64
	M1Seconds  int64
	H1Seconds  int64
	D1Seconds  int64
}

// DefaultRetention: raw 2d / 1m 30d / 1h 2y / 1d forever.
//
// Raw only serves reads of ranges ≤2h (pickTier), so it needs hours, not weeks;
// at 1-second probe intervals a fleet peaks at thousands of samples/sec and
// every extra raw day is GBs. The 1m tier carries the 2h–2d window plus the
// status pages' availability math and is kept a month.
func DefaultRetention() RetentionConfig {
	return RetentionConfig{
		RawSeconds: 2 * 86400,
		M1Seconds:  30 * 86400,
		H1Seconds:  2 * 365 * 86400,
		D1Seconds:  0,
	}
}

// Reprocess a trailing window each run so late samples (agent upload interval +
// retry, tens of seconds) are still captured. The window start is aligned DOWN
// to the destination bucket so every recomputed bucket is recomputed in full —
// an unaligned start would REPLACE a complete bucket with a partial aggregate.
const rollupOverlap = 120 // seconds

func alignDown(ts, bucket int64) int64 { return (ts / bucket) * bucket }

// Rollup performs incremental downsampling raw→1m→1h→1d. Each tier iterates
// the series dictionary and range-seeks one series' tail at a time (the
// samples/rollup PKs lead with series_id, so there is no ts index to scan);
// per-series watermarks live in rollup_state(resolution, series_id). Safe to
// call often; each run's work is bounded by the data that arrived since the
// last one.
func (s *Store) Rollup(ctx context.Context) error {
	now := time.Now().Unix()
	ids, err := s.allSeriesIDs(ctx)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if err := s.rollupTier(ctx, ids, "1m", "rollup_1m", "samples", true, 60, now); err != nil {
		return err
	}
	if err := s.rollupTier(ctx, ids, "1h", "rollup_1h", "rollup_1m", false, 3600, now); err != nil {
		return err
	}
	return s.rollupTier(ctx, ids, "1d", "rollup_1d", "rollup_1h", false, 86400, now)
}

func (s *Store) allSeriesIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.db.Read().QueryContext(ctx, `SELECT id FROM series ORDER BY id`)
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

// rollupTier downsamples src → dst for every series in chunks of series per
// transaction. One giant transaction would hold the single write connection for
// the whole catch-up after downtime — minutes of aggregation during which every
// write-handle query (and thus much of the HTTP API) stalls; chunking releases
// the writer between batches, exactly like Retention.
func (s *Store) rollupTier(ctx context.Context, ids []int64, res, dst, src string, srcRaw bool, bucket, now int64) error {
	upTo := alignDown(now, bucket)
	if upTo <= 0 {
		return nil
	}

	// Load this resolution's per-series watermarks in one read.
	states := make(map[int64]int64, len(ids))
	srows, err := s.db.Read().QueryContext(ctx, `SELECT series_id, last_ts FROM rollup_state WHERE resolution=?`, res)
	if err != nil {
		return err
	}
	for srows.Next() {
		var id, last int64
		if err := srows.Scan(&id, &last); err != nil {
			srows.Close()
			return err
		}
		states[id] = last
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return err
	}

	bkt := strconv.FormatInt(bucket, 10)
	expr := `(ts/` + bkt + `)*` + bkt
	var aggSQL string
	if srcRaw {
		aggSQL = `SELECT ` + expr + `, COUNT(*), SUM(value), MIN(value), MAX(value)
			FROM samples WHERE series_id=? AND ts>=? AND ts<? GROUP BY ` + expr
	} else {
		aggSQL = `SELECT ` + expr + `, SUM(cnt), SUM(total), MIN(vmin), MAX(vmax)
			FROM ` + src + ` WHERE series_id=? AND ts>=? AND ts<? GROUP BY ` + expr
	}

	const batch = 64 // series per transaction
	for start := 0; start < len(ids); start += batch {
		end := start + batch
		if end > len(ids) {
			end = len(ids)
		}
		if err := s.rollupBatch(ctx, ids[start:end], states, res, dst, aggSQL, bucket, upTo); err != nil {
			return err
		}
	}
	return nil
}

// rollupBatch downsamples one batch of series inside a single transaction with
// prepared statements reused across the batch.
func (s *Store) rollupBatch(ctx context.Context, ids []int64, states map[int64]int64, res, dst, aggSQL string, bucket, upTo int64) error {
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

	agg, err := tx.PrepareContext(ctx, aggSQL)
	if err != nil {
		return err
	}
	defer agg.Close()
	upsert, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO `+dst+`(series_id, ts, cnt, total, vmin, vmax) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer upsert.Close()
	setState, err := tx.PrepareContext(ctx, `
		INSERT INTO rollup_state(resolution, series_id, last_ts) VALUES(?,?,?)
		ON CONFLICT(resolution, series_id) DO UPDATE SET last_ts=excluded.last_ts`)
	if err != nil {
		return err
	}
	defer setState.Close()

	type bucketAgg struct {
		ts   int64
		cnt  int64
		tot  float64
		vmin float64
		vmax float64
	}
	for _, id := range ids {
		from := alignDown(states[id]-rollupOverlap, bucket)
		if from < 0 {
			from = 0
		}
		if upTo <= from {
			continue
		}
		rows, err := agg.QueryContext(ctx, id, from, upTo)
		if err != nil {
			return err
		}
		var buckets []bucketAgg
		for rows.Next() {
			var b bucketAgg
			if err := rows.Scan(&b.ts, &b.cnt, &b.tot, &b.vmin, &b.vmax); err != nil {
				rows.Close()
				return err
			}
			buckets = append(buckets, b)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, b := range buckets {
			if _, err := upsert.ExecContext(ctx, id, b.ts, b.cnt, b.tot, b.vmin, b.vmax); err != nil {
				return err
			}
		}
		// Advance the watermark even when the range was empty, so an idle series
		// costs one empty index probe per run instead of rescanning history.
		if _, err := setState.ExecContext(ctx, res, id, upTo); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// Retention prunes each tier past its window and reclaims space. Deletes are
// per-series ranged (the PK leads with series_id — a global ts DELETE would
// full-scan) and chunked into one transaction per series batch so the WAL
// never balloons and the writer is released between batches.
func (s *Store) Retention(ctx context.Context, cfg RetentionConfig) error {
	now := time.Now().Unix()
	ids, err := s.allSeriesIDs(ctx)
	if err != nil {
		return err
	}
	tiers := []struct {
		table string
		keep  int64
	}{
		{"samples", cfg.RawSeconds},
		{"rollup_1m", cfg.M1Seconds},
		{"rollup_1h", cfg.H1Seconds},
		{"rollup_1d", cfg.D1Seconds},
	}
	const batch = 64 // series per transaction
	for _, t := range tiers {
		if t.keep <= 0 {
			continue // keep forever
		}
		cutoff := now - t.keep
		for start := 0; start < len(ids); start += batch {
			end := start + batch
			if end > len(ids) {
				end = len(ids)
			}
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			del, err := tx.PrepareContext(ctx, `DELETE FROM `+t.table+` WHERE series_id=? AND ts<?`)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			for _, id := range ids[start:end] {
				if _, err := del.ExecContext(ctx, id, cutoff); err != nil {
					del.Close()
					_ = tx.Rollback()
					return err
				}
			}
			del.Close()
			if err := tx.Commit(); err != nil {
				return err
			}
		}
	}
	// Reclaim a bounded number of freed pages per run (auto_vacuum=incremental
	// is set at open); unbounded vacuums after a big prune stall the writer.
	_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(2000)`)
	return nil
}
