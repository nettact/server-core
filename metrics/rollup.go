package metrics

import (
	"context"
	"math"
	"time"

	"github.com/nettact/server-core/tsstore"
)

// RetentionConfig is how long each tier is kept (seconds); 0 = keep forever.
// The data plane enforces it by dropping whole blocks (each tsstore instance
// gets its window at Open); this struct's job on the read side is tier
// selection — covers() must agree with what the instances actually still hold.
type RetentionConfig struct {
	RawSeconds int64
	M1Seconds  int64
	H1Seconds  int64
	D1Seconds  int64
}

// DefaultRetention: raw 2d / 1m 30d / 1h 2y / 1d forever.
//
// Raw only serves reads of ranges ≤2h (pickTier), so it needs hours, not weeks.
// The 1m tier carries the 2h–2d window plus the status pages' availability math
// and is kept a month. NOTE the raw figure here is the LOGICAL window readers
// trust; the raw instance's PHYSICAL retention is wider (tsstore.Config) so a
// 72h backfill cannot be block-dropped before the rollup pass aggregates it.
func DefaultRetention() RetentionConfig {
	return RetentionConfig{
		RawSeconds: 2 * 86400,
		M1Seconds:  30 * 86400,
		H1Seconds:  2 * 365 * 86400,
		D1Seconds:  0,
	}
}

// TSStoreConfig derives the data plane's physical windows from the logical
// retention, in one place so the two can never drift apart: raw gets the
// logical window plus three days of backfill/rollup slack, the tiers map
// directly (their buckets are written once settled, no slack needed).
//
// Zero has OPPOSITE meanings on the two sides and must be translated, never
// passed through: here it means "keep forever", while tsstore.Config treats a
// nonpositive duration as "use this tier's default" (raw 5d, m1 30d, h1 2y).
// Forwarding a zero would quietly bound a tier the query planner still treats
// as unbounded — blocks dropped underneath reads that expect them. Every tier
// is therefore sent an explicit duration.
func (c RetentionConfig) TSStoreConfig() tsstore.Config {
	sec := func(s int64) time.Duration {
		if s <= 0 {
			return tsstore.Forever
		}
		return time.Duration(s) * time.Second
	}
	cfg := tsstore.Config{
		M1Retention:  sec(c.M1Seconds),
		H1Retention:  sec(c.H1Seconds),
		D1Retention:  sec(c.D1Seconds),
		RawRetention: tsstore.Forever,
	}
	if c.RawSeconds > 0 {
		cfg.RawRetention = sec(c.RawSeconds + 3*86400)
	}
	return cfg
}

// keepFor returns a tier's retention window in seconds; 0 = keep forever. It is
// the single mapping from tier name to configured window, shared by the reader's
// tier selection so it can never disagree with the data plane about which tier
// still holds a given moment. (The table names survive the SQLite tables they
// used to name; they are tier tags now — see tierOf.)
func (c RetentionConfig) keepFor(table string) int64 {
	switch table {
	case "samples":
		return c.RawSeconds
	case "rollup_1m":
		return c.M1Seconds
	case "rollup_1h":
		return c.H1Seconds
	default:
		return c.D1Seconds
	}
}

// covers reports whether a tier still holds data from ts, given the retention
// the data plane drops by. A disabled window (0) keeps forever.
//
// The margin is what keeps the answer stable: the cutoff advances continuously
// while block drops happen periodically, so data within a margin of the edge is
// about to disappear — possibly between two refreshes of the same chart. Reading
// one tier coarser slightly early costs resolution; trusting a tier that is
// about to drop the block costs the whole chart.
func (c RetentionConfig) covers(table string, ts, now int64) bool {
	keep := c.keepFor(table)
	if keep <= 0 {
		return true
	}
	return ts >= now-keep+retentionSafetyMargin
}

// retentionSafetyMargin is how far inside a tier's retention window a range must
// start before that tier is trusted to still hold it.
const retentionSafetyMargin = 3600

// Reprocess a trailing window each run so late samples (agent upload interval +
// retry, tens of seconds) are still captured. The window start is aligned DOWN
// to the destination bucket so every recomputed bucket is recomputed in full —
// an unaligned start would REPLACE a complete bucket with a partial aggregate.
const rollupOverlap = 120 // seconds

// idleWatermarkAdvance is how far a series with no new source data may fall
// behind before its rollup_state watermark is still written. Advancing the
// watermark on every empty run would rewrite one row per series per tier per
// run — pure page churn for an idle series; deferring costs only a wider
// (still empty) recompute range on subsequent runs.
const idleWatermarkAdvance = 3600 // seconds

func alignDown(ts, bucket int64) int64 { return (ts / bucket) * bucket }

// rollupSeries is one dictionary row the rollup pass works from.
type rollupSeries struct {
	id     int64
	cutoff int64 // series.purge_cutoff: recompute never reaches below it
}

// Rollup performs incremental downsampling raw→1m→1h→1d. Buckets live in the
// data plane as append-only (cnt, sum) pairs; watermarks stay in SQLite's
// rollup_state. Because the two stores cannot share a transaction, every
// repair follows a fixed order whose every crash point is benign:
//
//  1. diff — recompute [watermark−overlap, upTo) from the source and compare
//     against the existing buckets (Cnt and the exact Float64bits of Sum; the
//     ascending scan makes the float sum deterministic, so the comparison is
//     exact and a no-change pass writes NOTHING);
//  2. if anything changed, FIRST commit the parent tier's watermark rewind in
//     SQLite (guarded, never forward) — the durable intent that the tier above
//     must re-aggregate;
//  3. THEN append the changed buckets (k-repair: newest ms wins at read);
//  4. THEN CAS-advance this tier's own watermark.
//
// Die after 2: the parent recomputes, finds nothing changed, the guard writes
// nothing. Die after 3: this tier's watermark is behind, the next pass
// recomputes, the diff comes back empty. Reversing 2 and 3 would instead lose
// repairs: a parent pass running between them could aggregate the OLD child
// buckets and advance past them, and with the repair already written the next
// child pass sees no change and never rewinds the parent again.
//
// The whole pass holds rollupMu — see the field comment — and skips series
// whose ingest transaction committed a rewind whose raw samples are still in
// flight (pendingAppend).
func (s *Store) Rollup(ctx context.Context) error {
	s.rollupMu.Lock()
	defer s.rollupMu.Unlock()
	return s.rollupLocked(ctx)
}

func (s *Store) rollupLocked(ctx context.Context) error {
	now := time.Now().Unix()
	series, err := s.allRollupSeries(ctx)
	if err != nil {
		return err
	}
	if len(series) == 0 {
		return nil
	}
	if err := s.rollupTier(ctx, series, "1m", tsstore.TierM1, true, now, "1h", 3600); err != nil {
		return err
	}
	if err := s.rollupTier(ctx, series, "1h", tsstore.TierH1, false, now, "1d", 86400); err != nil {
		return err
	}
	return s.rollupTier(ctx, series, "1d", tsstore.TierD1, false, now, "", 0)
}

func (s *Store) allRollupSeries(ctx context.Context) ([]rollupSeries, error) {
	rows, err := s.db.Read().QueryContext(ctx, `SELECT id, purge_cutoff FROM series ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rollupSeries
	for rows.Next() {
		var rs rollupSeries
		if err := rows.Scan(&rs.id, &rs.cutoff); err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}

// rollupTier downsamples one tier for every series. srcRaw selects the source:
// raw samples for 1m, the child tier's buckets otherwise (1h reads 1m, 1d
// reads 1h — coarser tiers never touch raw).
func (s *Store) rollupTier(ctx context.Context, series []rollupSeries, res string, tier tsstore.Tier, srcRaw bool, now int64, parentRes string, parentBucket int64) error {
	bucket := tier.BucketSeconds()
	upTo := alignDown(now, bucket)
	if upTo <= 0 {
		return nil
	}

	// This resolution's per-series watermarks, in one read.
	states := make(map[int64]int64, len(series))
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

	// The pass runs in three phases per tier so the SQLite side stays a couple
	// of transactions instead of one autocommit per series (which measurably
	// rivaled the data-plane writes it was bookkeeping for): all parent
	// rewinds in one tx FIRST, then the data-plane appends, then all watermark
	// CASes in one tx. The per-series crash guarantees are unchanged — a
	// committed rewind without its append recomputes into the unchanged-guard,
	// an append without its CAS recomputes likewise (see the ordering comment
	// above); batching only widens how many series share each benign window.
	type pendingRepair struct {
		rs      rollupSeries
		changed []tsstore.Bucket
		oldest  int64
	}
	type pendingCAS struct {
		id   int64
		from int64
	}
	var repairs []pendingRepair
	var casses []pendingCAS

	for _, rs := range series {
		if srcRaw && s.isPendingAppend(rs.id) {
			continue // its rewind is durable but the samples are mid-flight; next pass
		}
		from := alignDown(states[rs.id]-rollupOverlap, bucket)
		if c := alignDown(rs.cutoff, bucket); c > from {
			from = c
		}
		if from < 0 {
			from = 0
		}
		if upTo <= from {
			continue
		}

		recomputed, err := s.recomputeBuckets(ctx, tier, srcRaw, rs, from, upTo)
		if err != nil {
			return err
		}
		var changed []tsstore.Bucket
		if len(recomputed) > 0 {
			existing, err := s.ts.ReadBuckets(ctx, tier, rs.id, from, upTo)
			if err != nil {
				return err
			}
			have := make(map[int64]tsstore.Bucket, len(existing))
			for _, b := range existing {
				have[b.TS] = b
			}
			for _, b := range recomputed {
				if e, ok := have[b.TS]; !ok || e.Cnt != b.Cnt || math.Float64bits(e.Sum) != math.Float64bits(b.Sum) {
					changed = append(changed, b)
				}
				// An existing bucket with no recomputed counterpart is left
				// alone: rollup never deletes buckets, only purge does.
			}
		}
		if len(changed) > 0 {
			oldest := changed[0].TS
			for _, b := range changed[1:] {
				if b.TS < oldest {
					oldest = b.TS
				}
			}
			repairs = append(repairs, pendingRepair{rs: rs, changed: changed, oldest: oldest})
		}
		// CAS-advance against the watermark this pass read — ingest may have
		// rewound the series mid-pass, and an unconditional write would erase
		// that rewind (the repair would then never happen). Losing the CAS
		// means someone moved the watermark backwards on purpose; leaving it
		// alone is exactly right, and the next pass picks it up.
		if len(recomputed) > 0 || upTo-states[rs.id] >= idleWatermarkAdvance {
			casses = append(casses, pendingCAS{id: rs.id, from: states[rs.id]})
		}
	}

	// Phase B: every changed series' parent rewind, one transaction, BEFORE any
	// append (the durable intent — see the ordering comment on Rollup).
	if parentRes != "" && len(repairs) > 0 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, r := range repairs {
			if _, err := tx.ExecContext(ctx,
				`UPDATE rollup_state SET last_ts=? WHERE resolution=? AND series_id=? AND last_ts>?`,
				alignDown(r.oldest, parentBucket), parentRes, r.rs.id, alignDown(r.oldest, parentBucket)); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	// Phase C: the repairs themselves.
	for _, r := range repairs {
		if err := s.ts.AppendBuckets(ctx, tier, r.rs.id, r.changed); err != nil {
			return err
		}
	}
	// Phase D: watermark advances, one transaction.
	if len(casses) > 0 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, c := range casses {
			// Re-check the in-flight mark here, not only at the top of the pass.
			// A series can be created (EnsureSeries commits it), picked up by
			// this pass, and only then marked pending by the ingest that is
			// about to append its first samples. That batch's rewind updates
			// zero rows — there is no rollup_state row yet — so the INSERT
			// below would be unconditional and would park the watermark at upTo
			// with the samples still in flight. Skipping the advance leaves the
			// series stateless, and the next pass aggregates it in full.
			if srcRaw && s.isPendingAppend(c.id) {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO rollup_state(resolution, series_id, last_ts) VALUES(?,?,?)
				ON CONFLICT(resolution, series_id) DO UPDATE SET last_ts=excluded.last_ts
				WHERE last_ts=?`, res, c.id, upTo, c.from); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// recomputeBuckets aggregates one series' source data in [from, upTo) into
// destination-width buckets. Sources are read ascending, so the float sums are
// bit-for-bit deterministic across passes — the foundation of the diff's
// exact unchanged-guard.
func (s *Store) recomputeBuckets(ctx context.Context, tier tsstore.Tier, srcRaw bool, rs rollupSeries, from, upTo int64) ([]tsstore.Bucket, error) {
	bucket := tier.BucketSeconds()
	var out []tsstore.Bucket
	add := func(ts int64, cnt int64, sum float64) {
		start := alignDown(ts, bucket)
		if n := len(out); n > 0 && out[n-1].TS == start {
			out[n-1].Cnt += cnt
			out[n-1].Sum += sum
			return
		}
		out = append(out, tsstore.Bucket{TS: start, Cnt: cnt, Sum: sum})
	}
	if srcRaw {
		samples, err := s.ts.RawRange(ctx, rs.id, from, upTo, 0)
		if err != nil {
			return nil, err
		}
		for _, smp := range samples {
			add(smp.TS, 1, smp.Value)
		}
		return out, nil
	}
	var child tsstore.Tier
	if tier == tsstore.TierH1 {
		child = tsstore.TierM1
	} else {
		child = tsstore.TierH1
	}
	buckets, err := s.ts.ReadBuckets(ctx, child, rs.id, from, upTo)
	if err != nil {
		return nil, err
	}
	for _, b := range buckets {
		add(b.TS, b.Cnt, b.Sum)
	}
	return out, nil
}
