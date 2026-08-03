package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// TestOfflineBacklogStillReachesRollups pins the agent-WAL promise end to end:
// samples that arrive HOURS late — an offline agent draining its backlog — must
// still be downsampled, or the exact data the WAL existed to protect silently
// vanishes from every chart wider than the raw tier and from the availability
// math, and raw retention then deletes the only copy.
//
// The trap is the rollup watermark: it advances with wall time even while a
// series receives nothing (the overlap only re-reads 120s), so backlog inserted
// behind it was invisible to every subsequent pass. Ingest now rolls the
// watermark back to the oldest late sample it stores.
func TestOfflineBacklogStillReachesRollups(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)

	mk := func(ts time.Time, v float64) telemetry.Metric {
		return telemetry.Metric{
			TS: ts, Kind: telemetry.ICMPRTTms, Target: "10.0.0.1", Layer: "lan",
			Value: v, Unit: "ms", MonitorID: "probe_m1",
		}
	}

	// The agent was online six hours ago, then went dark. Rollup keeps running
	// while it is gone, advancing the series' watermarks to the present.
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{mk(now.Add(-6*time.Hour), 5)})
	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("rollup while agent online: %v", err)
	}
	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("rollup while agent offline: %v", err)
	}

	// The agent returns and drains its WAL: two hours of backlog, all timestamped
	// far behind the watermark (but inside raw retention).
	backlog := []telemetry.Metric{
		mk(now.Add(-2*time.Hour), 40),
		mk(now.Add(-2*time.Hour).Add(time.Minute), 41),
		mk(now.Add(-90*time.Minute), 42),
	}
	ingestBatch(t, db, s, "agent_a", backlog)
	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("rollup after backfill: %v", err)
	}

	// Every backlog minute must be in the 1m tier…
	var got int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM rollup_1m r
		JOIN series se ON se.id = r.series_id
		WHERE se.agent_id='agent_a' AND se.monitor_id='probe_m1'
		  AND r.ts >= ? AND r.ts < ?`,
		now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix()).Scan(&got)
	if err != nil {
		t.Fatalf("count 1m buckets: %v", err)
	}
	if got != 3 {
		t.Fatalf("1m buckets covering the backlog window = %d, want 3: late samples never reached the rollups", got)
	}

	// …and the hour tier must have re-aggregated on top of them in the same pass.
	var cnt int
	err = db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(cnt),0) FROM rollup_1h r
		JOIN series se ON se.id = r.series_id
		WHERE se.agent_id='agent_a' AND se.monitor_id='probe_m1'
		  AND r.ts >= ? AND r.ts < ?`,
		now.Add(-2*time.Hour).Truncate(time.Hour).Unix(), now.Unix()).Scan(&cnt)
	if err != nil {
		t.Fatalf("sum 1h cnt: %v", err)
	}
	if cnt != 3 {
		t.Fatalf("1h tier aggregated %d backlog samples, want 3", cnt)
	}
}

// TestRewindSurvivesAConcurrentRollupPass is the race the naive rewind loses.
//
// Rollup reads each tier's watermarks once, at the start of that tier. A backlog
// commit that lands mid-pass therefore rewinds watermarks the running pass has
// already snapshotted, and the pass then writes its own (advanced) values back
// on top — so the rewind is erased before anything acts on it, and the backlog
// is never aggregated by any later pass either, because every later pass sees
// only the advanced watermarks.
//
// The state below is that race's outcome made deterministic: the 1m tier still
// has to repair an old window, while 1h and 1d have already been advanced past
// it. Recovery must not depend on catching the race again.
func TestRewindSurvivesAConcurrentRollupPass(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Hour)
	old := now.Add(-5 * time.Hour)

	mk := func(ts time.Time, v float64) telemetry.Metric {
		return telemetry.Metric{
			TS: ts, Kind: telemetry.ICMPRTTms, Target: "10.0.0.1", Layer: "lan",
			Value: v, Unit: "ms", MonitorID: "probe_m1",
		}
	}

	// Establish the series and let every tier advance to the present.
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{mk(now.Add(-time.Minute), 1)})
	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("initial rollup: %v", err)
	}

	var seriesID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM series WHERE agent_id='agent_a' AND monitor_id='probe_m1'`).Scan(&seriesID); err != nil {
		t.Fatalf("series id: %v", err)
	}

	// Backlog lands, but the pass that was already running re-advanced 1h and 1d
	// after the rewind. Reproduce exactly that: raw rows present, 1m rewound,
	// coarser tiers left ahead of the backlog.
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{mk(old, 40), mk(old.Add(time.Minute), 41)})
	if _, err := db.ExecContext(ctx,
		`UPDATE rollup_state SET last_ts=? WHERE series_id=? AND resolution<>'1m'`,
		now.Unix(), seriesID); err != nil {
		t.Fatalf("simulate re-advanced coarse tiers: %v", err)
	}

	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("recovery rollup: %v", err)
	}

	// The 1m tier repairs itself from raw, and the hour tier must follow it down
	// rather than trusting its own watermark. The day tier is deliberately not
	// asserted on content: it only ever materializes COMPLETED days (upTo is
	// aligned down to midnight), so today's backlog is legitimately absent from it
	// — its watermark is checked below instead.
	for _, tc := range []struct{ table, label string }{
		{"rollup_1m", "minute"},
		{"rollup_1h", "hour"},
	} {
		var cnt int
		err := db.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(cnt),0) FROM `+tc.table+` WHERE series_id=? AND ts>=? AND ts<?`,
			seriesID, old.Add(-time.Hour).Unix(), old.Add(time.Hour).Unix()).Scan(&cnt)
		if err != nil {
			t.Fatalf("sum %s: %v", tc.table, err)
		}
		if cnt != 2 {
			t.Fatalf("%s tier aggregated %d backlog samples, want 2: a rewind erased by a "+
				"concurrent pass is never recovered", tc.label, cnt)
		}
	}

	// The cascade must have carried past the hour tier too, or the backlog would
	// be missing from the day tier the moment this day closes.
	var dayWatermark int64
	if err := db.QueryRowContext(ctx,
		`SELECT last_ts FROM rollup_state WHERE resolution='1d' AND series_id=?`, seriesID).Scan(&dayWatermark); err != nil {
		t.Fatalf("day watermark: %v", err)
	}
	if dayStart := alignDown(old.Unix(), 86400); dayWatermark > dayStart {
		t.Fatalf("day watermark %d is still past the backlog's day %d: the cascade stopped at the hour tier",
			dayWatermark, dayStart)
	}
}

// TestDuplicateSamplesDoNotRewind: a replayed packet under a fresh sequence, or
// an InsertSamples retry, changes no history — INSERT OR IGNORE stores nothing.
// Rewinding for it would drag the watermark back over everything still retained
// and make the next pass rescan it for no reason.
func TestDuplicateSamplesDoNotRewind(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	old := now.Add(-4 * time.Hour)

	m := telemetry.Metric{
		TS: old, Kind: telemetry.ICMPRTTms, Target: "10.0.0.1", Layer: "lan",
		Value: 7, Unit: "ms", MonitorID: "probe_m1",
	}
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{m})
	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("rollup: %v", err)
	}

	var seriesID, before int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM series WHERE agent_id='agent_a' AND monitor_id='probe_m1'`).Scan(&seriesID); err != nil {
		t.Fatalf("series id: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT last_ts FROM rollup_state WHERE resolution='1m' AND series_id=?`, seriesID).Scan(&before); err != nil {
		t.Fatalf("watermark: %v", err)
	}

	// The very same sample arrives again.
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{m})

	var after int64
	if err := db.QueryRowContext(ctx,
		`SELECT last_ts FROM rollup_state WHERE resolution='1m' AND series_id=?`, seriesID).Scan(&after); err != nil {
		t.Fatalf("watermark after: %v", err)
	}
	if after != before {
		t.Fatalf("a duplicate sample rewound the watermark %d -> %d; it changed no history", before, after)
	}
}
