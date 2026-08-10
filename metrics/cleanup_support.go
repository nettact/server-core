package metrics

import (
	"context"
	"errors"
	"time"

	"github.com/nettact/server-core/tsstore"
)

// rollupTiers pairs each tier tag with its bucket width (seconds). Buckets are
// aligned to their width (see alignDown in rollup.go), so a bucket at ts
// covers [ts, ts+width).
var rollupTiers = []struct {
	table string
	width int64
}{
	{"rollup_1m", 60},
	{"rollup_1h", 3600},
	{"rollup_1d", 86400},
}

// PurgeRange deletes samples in [from, to) for the given series and the
// bucket-tier windows overlapping it, then repairs the tiers so a subsequent
// query stays consistent. Semantics:
//
//   - Raw samples are tombstoned precisely on [from, to). A post-purge replay
//     that re-appends into the window is masked by the tombstone — consistent
//     with purge intent.
//   - Interior buckets (fully inside the window) are tombstoned: their source
//     is gone, so nothing will ever legitimately write them again.
//   - A straddling EDGE bucket is recomputed inline from its surviving source
//     and k-repaired on the spot — better than the old whole-bucket
//     over-delete, which left the edge missing until the next rollup pass.
//     When the edge is too old to append (beyond the OOO horizon,
//     tsstore.ErrBucketTooOld) it is tombstoned instead, which IS the old
//     over-delete semantics for ancient ranges.
//   - The rollup_state watermark for each tier is rewound to alignDown(from,w)
//     (never forward) as a belt: the next Rollup() pass re-verifies the window
//     and its unchanged-guard absorbs the already-done inline repairs.
//   - The in-memory latest cache is refreshed when the newest sample was in
//     the deleted window (tombstones apply at read time, so the refresh
//     already sees the post-purge truth).
//
// The series dictionary row is deliberately KEPT even when the range empties
// every tier: a live series may have already obtained this id via EnsureSeries
// and be about to append samples outside s.mu, so removing the row here would
// strand those samples under a deleted id. An emptied row is harmless; a
// deleted-target series is reclaimed by the full orphan-cleanup path
// (PurgeSeriesIDs) instead.
//
// from/to are unix seconds and to must be > from AND bounded (a real range).
// Clearing a live series' ENTIRE history is ClearSeriesHistory — a tombstone
// to "infinity" would mask the series' future appends forever, so an
// unbounded PurgeRange does not exist by design.
func (s *Store) PurgeRange(ctx context.Context, ids []int64, from, to int64) (PurgeCounts, error) {
	if len(ids) == 0 || to <= from {
		return PurgeCounts{}, nil
	}
	// Let already-issued appends land before any tombstone is computed: a
	// tombstone is clamped to what the series holds at Delete time, so a batch
	// that committed to SQLite before this purge but appends after it would
	// survive the delete outright (see Store.waitForPendingAppends).
	s.waitForPendingAppends()
	s.rollupMu.Lock()
	defer s.rollupMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	var counts PurgeCounts
	windows := make(map[int64]purgeWindow, len(ids))
	for _, id := range ids {
		// Raw: count, then precise tombstone.
		n, err := s.ts.RawCount(ctx, id, from, to)
		if err != nil {
			return counts, err
		}
		counts.Samples += n
		if err := s.ts.DeleteRawRange(ctx, id, from, to); err != nil {
			return counts, err
		}

		for _, t := range rollupTiers {
			tier := tierOf(t.table)
			lo := alignDown(from, t.width)
			affected, err := s.ts.ReadBuckets(ctx, tier, id, lo, to)
			if err != nil {
				return counts, err
			}
			counts.Rollups += int64(len(affected))

			// Interior: [first bucket fully >= from, last bucket fully < to).
			intLo := lo
			if from%t.width != 0 {
				intLo = lo + t.width
			}
			intHi := alignDown(to, t.width)
			if intHi > intLo {
				if err := s.ts.DeleteBucketRange(ctx, tier, id, intLo, intHi); err != nil {
					return counts, err
				}
			}
			// Straddling edges (at most two; one when the range sits inside a
			// single bucket): recompute from surviving source, k-repair or
			// tombstone. An aligned bound has no straddler on its side.
			edges := map[int64]bool{}
			if from%t.width != 0 {
				edges[lo] = true
			}
			if to%t.width != 0 {
				edges[alignDown(to, t.width)] = true
			}
			for edge := range edges {
				if err := s.repairEdgeBucketLocked(ctx, tier, t.width, id, edge); err != nil {
					return counts, err
				}
			}
			// Watermark rewind (belt; never forward).
			resStr := t.table[len("rollup_"):]
			if _, err := s.db.ExecContext(ctx,
				`UPDATE rollup_state SET last_ts=? WHERE resolution=? AND series_id=? AND last_ts>?`,
				lo, resStr, id, lo); err != nil {
				return counts, err
			}
		}

		windows[id] = purgeWindow{from: from, to: to} // until stamped below, at unlock time

		// Refresh the latest cache if the newest known sample was just deleted.
		if lv, ok := s.latest[id]; ok && lv.ts >= from && lv.ts < to {
			if err := s.refreshLatestLocked(ctx, id); err != nil {
				return counts, err
			}
		}
	}

	// Record the deleted windows so an in-flight ingest that committed BEFORE this
	// purge but folds its latest-cache update AFTER it (UpdateLatest runs post-
	// commit, outside this lock) re-verifies instead of resurrecting a just-deleted
	// sample. The expiry is stamped HERE — after all deletes, just before the lock
	// is released — so a fold that spent the whole purge blocked on s.mu still sees
	// a live guard no matter how long the purge took. Sweeping expired entries here
	// also bounds the map.
	now := time.Now().Unix()
	for id, w := range s.purged {
		if now > w.until {
			delete(s.purged, id)
		}
	}
	until := now + purgeGuardSeconds
	for id, w := range windows {
		if prev, ok := s.purged[id]; ok { // widen over a still-pending prior window
			if prev.from < w.from {
				w.from = prev.from
			}
			if prev.to > w.to {
				w.to = prev.to
			}
		}
		w.until = until
		s.purged[id] = w
	}
	return counts, nil
}

// repairEdgeBucketLocked rebuilds one straddling bucket from its surviving
// source (raw for m1, the child tier otherwise — the child's own edge was
// repaired earlier in the same tier loop). Empty source or an
// out-of-OOO-horizon window falls back to tombstoning the bucket.
func (s *Store) repairEdgeBucketLocked(ctx context.Context, tier tsstore.Tier, width, id, start int64) error {
	rs := rollupSeries{id: id}
	recomputed, err := s.recomputeBuckets(ctx, tier, tier == tsstore.TierM1, rs, start, start+width)
	if err != nil {
		return err
	}
	if len(recomputed) == 0 {
		return s.ts.DeleteBucketRange(ctx, tier, id, start, start+width)
	}
	// Skip the write when the surviving content matches what is already stored
	// (the edge did not actually intersect the purge).
	existing, err := s.ts.ReadBuckets(ctx, tier, id, start, start+width)
	if err != nil {
		return err
	}
	if len(existing) == 1 && existing[0].Cnt == recomputed[0].Cnt && existing[0].Sum == recomputed[0].Sum {
		return nil
	}
	err = s.ts.AppendBuckets(ctx, tier, id, recomputed)
	if errors.Is(err, tsstore.ErrBucketTooOld) {
		return s.ts.DeleteBucketRange(ctx, tier, id, start, start+width)
	}
	return err
}

// ClearSeriesHistory hides a live series' entire recorded history without a
// single tombstone: series.purge_cutoff is raised past everything stored and
// every read path clamps below it, while the old blocks age out through
// ordinary retention. This replaces "PurgeRange(0, maxTS)" — a tombstone over
// the future would mask the very samples the still-live series keeps
// appending, and compaction-time application would make the breakage permanent.
//
// purge_cutoff is the OLDEST SECOND STILL VISIBLE, so every reader can keep
// using it directly as an inclusive lower bound. It is set past the newest
// sample the series actually holds, not merely to now: ingest accepts
// timestamps up to two minutes ahead of the clock, so a cutoff of now would
// leave those future-stamped samples — and any sample landing exactly on the
// cutoff second — visible after a clear that claims to hide everything
// recorded.
func (s *Store) ClearSeriesHistory(ctx context.Context, ids []int64) (PurgeCounts, error) {
	if len(ids) == 0 {
		return PurgeCounts{}, nil
	}
	// As in PurgeRange: a batch that has committed but not yet appended is part
	// of "everything recorded", so let it land before reading the extent the
	// cutoff is derived from.
	s.waitForPendingAppends()
	s.rollupMu.Lock()
	defer s.rollupMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	var counts PurgeCounts
	windows := make(map[int64]purgeWindow, len(ids))
	for _, id := range ids {
		n, err := s.ts.RawCount(ctx, id, 0, 0)
		if err != nil {
			return counts, err
		}
		counts.Samples += n
		cutoff := now + 1
		if _, rawMax, ok, err := s.ts.RawExtent(ctx, id); err != nil {
			return counts, err
		} else if ok && rawMax >= cutoff {
			cutoff = rawMax + 1
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE series SET purge_cutoff=? WHERE id=? AND purge_cutoff<?`, cutoff, id, cutoff); err != nil {
			return counts, err
		}
		windows[id] = purgeWindow{from: 0, to: cutoff}
		// The cutoff hides everything below it; the latest cache must follow
		// immediately (refresh reads via the cutoff-clamped path).
		if err := s.refreshLatestLocked(ctx, id); err != nil {
			delete(s.latest, id)
		}
		// Rollup watermarks stay where they are: recompute clamps to the cutoff
		// (see rollupTier), so history below it is simply never revisited.
	}

	// Same fold guard PurgeRange installs, and for the same reason: an ingest
	// that committed before this clear folds its batch into the latest cache
	// after it, outside s.mu. Without a recorded window that fold walks straight
	// past the cutoff and republishes a sample the clear just hid.
	for id, w := range s.purged {
		if now > w.until {
			delete(s.purged, id)
		}
	}
	until := now + purgeGuardSeconds
	for id, w := range windows {
		if prev, ok := s.purged[id]; ok && prev.to > w.to {
			w.to = prev.to
		}
		w.until = until
		s.purged[id] = w
	}
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
	EstSamples int64  `json:"est_samples"` // approximate; from bucket counters
}

// CleanupInventory returns every series row for a site with its data extent and
// an approximate sample count, ordered for stable grouping. Counts are
// estimates from the bucket counters (never a full decompressing count over
// raw): Σcnt of the 1d tier, else the 1m tier, else a raw count for a series
// younger than one bucket.
func (s *Store) CleanupInventory(ctx context.Context, siteID string) ([]InventoryEntry, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, agent_id, COALESCE(monitor_id,''), kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,''), purge_cutoff
		FROM series WHERE site_id=? ORDER BY agent_id, monitor_id, kind, target, config_serial`, siteID)
	if err != nil {
		return nil, err
	}
	var out []InventoryEntry
	var cutoffs []int64
	for rows.Next() {
		var e InventoryEntry
		var cutoff int64
		if err := rows.Scan(&e.SeriesID, &e.AgentID, &e.MonitorID, &e.Kind, &e.Target, &e.Layer, &e.Unit, &cutoff); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
		cutoffs = append(cutoffs, cutoff)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.fillEntryStats(ctx, &out[i], cutoffs[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// fillEntryStats populates one entry's earliest/latest/est from the data
// plane's per-series extents, clamped to the purge cutoff.
func (s *Store) fillEntryStats(ctx context.Context, e *InventoryEntry, cutoff int64) error {
	rawMin, rawMax, rawOK, err := s.ts.RawExtent(ctx, e.SeriesID)
	if err != nil {
		return err
	}
	d1Min, d1Max, d1OK, err := s.ts.BucketExtent(ctx, tsstore.TierD1, e.SeriesID)
	if err != nil {
		return err
	}
	var earliest, latest int64
	if rawOK {
		earliest, latest = rawMin, rawMax
	}
	if d1OK {
		if earliest == 0 || d1Min < earliest {
			earliest = d1Min
		}
		if d1Max+86400 > latest {
			latest = d1Max + 86400
		}
	}
	if cutoff > 0 && earliest != 0 && earliest < cutoff {
		earliest = cutoff
	}
	// cutoff is the oldest visible second, so a series whose newest point sits
	// strictly below it has nothing left to show.
	if cutoff > 0 && latest != 0 && latest < cutoff {
		earliest, latest = 0, 0 // everything recorded is hidden
	}
	e.Earliest, e.Latest = earliest, latest

	sumCnt := func(tier tsstore.Tier) (int64, error) {
		buckets, err := s.ts.ReadBuckets(ctx, tier, e.SeriesID, cutoff, 0)
		if err != nil {
			return 0, err
		}
		var total int64
		for _, b := range buckets {
			total += b.Cnt
		}
		return total, nil
	}
	if n, err := sumCnt(tsstore.TierD1); err != nil {
		return err
	} else if n > 0 {
		e.EstSamples = n
		return nil
	}
	if n, err := sumCnt(tsstore.TierM1); err != nil {
		return err
	} else if n > 0 {
		e.EstSamples = n
		return nil
	}
	if rawOK {
		n, err := s.ts.RawCount(ctx, e.SeriesID, cutoff, 0)
		if err != nil {
			return err
		}
		e.EstSamples = n
	}
	return nil
}

// RangeCounts is the per-tier exact count of a proposed delete, for the
// preview. It uses the same bucket-aligned bounds PurgeRange deletes with, so
// the preview total matches the actual deletion (modulo ingest in flight).
type RangeCounts struct {
	Samples  int64 `json:"samples"`
	Rollup1m int64 `json:"rollup_1m"`
	Rollup1h int64 `json:"rollup_1h"`
	Rollup1d int64 `json:"rollup_1d"`
}

// Rollups returns the total affected buckets across tiers.
func (c RangeCounts) Rollups() int64 { return c.Rollup1m + c.Rollup1h + c.Rollup1d }

// CountRange counts what a delete of [from, to) over ids would remove. When
// from==0 && to==0 it counts every sample/bucket (the full-delete preview).
func (s *Store) CountRange(ctx context.Context, ids []int64, from, to int64) (RangeCounts, error) {
	var c RangeCounts
	full := from == 0 && to == 0
	for _, id := range ids {
		n, err := s.ts.RawCount(ctx, id, from, to)
		if err != nil {
			return c, err
		}
		c.Samples += n
		for _, t := range rollupTiers {
			lo, hi := alignDown(from, t.width), to
			if full {
				lo, hi = 0, 0
			}
			buckets, err := s.ts.ReadBuckets(ctx, tierOf(t.table), id, lo, hi)
			if err != nil {
				return c, err
			}
			switch t.table {
			case "rollup_1m":
				c.Rollup1m += int64(len(buckets))
			case "rollup_1h":
				c.Rollup1h += int64(len(buckets))
			case "rollup_1d":
				c.Rollup1d += int64(len(buckets))
			}
		}
	}
	return c, nil
}
