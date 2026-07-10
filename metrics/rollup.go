package metrics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RetentionConfig is how long each tier is kept (seconds); 0 = keep forever.
type RetentionConfig struct {
	RawSeconds int64
	M1Seconds  int64
	H1Seconds  int64
	D1Seconds  int64
}

// DefaultRetention: raw 14d / 1m 90d / 1h 2y / 1d forever.
func DefaultRetention() RetentionConfig {
	return RetentionConfig{
		RawSeconds: 14 * 86400,
		M1Seconds:  90 * 86400,
		H1Seconds:  2 * 365 * 86400,
		D1Seconds:  0,
	}
}

// reprocess a trailing window each run so late/backfilled samples are captured
// (INSERT OR REPLACE recomputes affected buckets from source).
const rollupOverlap = 900 // seconds

func alignDown(ts, bucket int64) int64 { return (ts / bucket) * bucket }

// Rollup performs incremental downsampling raw→1m→1h→1d. Safe to call often.
func (s *Store) Rollup(ctx context.Context) error {
	now := time.Now().Unix()
	if err := s.rollupFromRaw(ctx, now); err != nil {
		return err
	}
	if err := s.rollupFromRollup(ctx, "1h", "rollup_1h", "rollup_1m", 3600, now); err != nil {
		return err
	}
	return s.rollupFromRollup(ctx, "1d", "rollup_1d", "rollup_1h", 86400, now)
}

func (s *Store) rollupState(ctx context.Context, res string) (int64, error) {
	var last int64
	err := s.db.QueryRowContext(ctx, `SELECT last_ts FROM rollup_state WHERE resolution=?`, res).Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return last, err
}

func (s *Store) setRollupState(ctx context.Context, res string, last int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rollup_state(resolution, last_ts) VALUES(?,?)
		 ON CONFLICT(resolution) DO UPDATE SET last_ts=excluded.last_ts`, res, last)
	return err
}

// rollupFromRaw aggregates raw samples into rollup_1m (60s buckets).
func (s *Store) rollupFromRaw(ctx context.Context, now int64) error {
	last, err := s.rollupState(ctx, "1m")
	if err != nil {
		return err
	}
	from := last - rollupOverlap
	if from < 0 {
		from = 0
	}
	upTo := alignDown(now, 60)
	if upTo <= from {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO rollup_1m(series_id, ts, cnt, total, vmin, vmax)
		SELECT series_id, (ts/60)*60, COUNT(*), SUM(value), MIN(value), MAX(value)
		FROM samples WHERE ts >= ? AND ts < ?
		GROUP BY series_id, (ts/60)*60`, from, upTo); err != nil {
		return err
	}
	return s.setRollupState(ctx, "1m", upTo)
}

// rollupFromRollup aggregates a finer rollup into a coarser one.
func (s *Store) rollupFromRollup(ctx context.Context, res, dst, src string, bucket, now int64) error {
	last, err := s.rollupState(ctx, res)
	if err != nil {
		return err
	}
	from := last - rollupOverlap
	if from < 0 {
		from = 0
	}
	upTo := alignDown(now, bucket)
	if upTo <= from {
		return nil
	}
	q := fmt.Sprintf(`
		INSERT OR REPLACE INTO %s(series_id, ts, cnt, total, vmin, vmax)
		SELECT series_id, (ts/%d)*%d, SUM(cnt), SUM(total), MIN(vmin), MAX(vmax)
		FROM %s WHERE ts >= ? AND ts < ?
		GROUP BY series_id, (ts/%d)*%d`, dst, bucket, bucket, src, bucket, bucket)
	if _, err := s.db.ExecContext(ctx, q, from, upTo); err != nil {
		return err
	}
	return s.setRollupState(ctx, res, upTo)
}

// Retention prunes each tier past its window and reclaims space.
func (s *Store) Retention(ctx context.Context, cfg RetentionConfig) error {
	now := time.Now().Unix()
	prune := func(table string, keep int64) error {
		if keep <= 0 {
			return nil // keep forever
		}
		_, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE ts < ?`, now-keep)
		return err
	}
	if err := prune("samples", cfg.RawSeconds); err != nil {
		return err
	}
	if err := prune("rollup_1m", cfg.M1Seconds); err != nil {
		return err
	}
	if err := prune("rollup_1h", cfg.H1Seconds); err != nil {
		return err
	}
	if err := prune("rollup_1d", cfg.D1Seconds); err != nil {
		return err
	}
	// Reclaim freed pages (auto_vacuum=incremental is set at open).
	_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	return nil
}
