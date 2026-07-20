package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// TestPurgeRangeRawAndBuckets deletes a middle time range and verifies raw
// samples in the window are gone precisely, overlapping rollup buckets are
// removed, and the surrounding data survives.
func TestPurgeRangeRawAndBuckets(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()

	// 30 minutes of 1-second samples ending on a minute boundary.
	end := alignDown(time.Now().Unix(), 60)
	start := end - 30*60
	var ms []telemetry.Metric
	for ts := start; ts < end; ts++ {
		ms = append(ms, telemetry.Metric{
			TS: time.Unix(ts, 0), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1",
			Value: 4, Unit: "ms", MonitorID: "probe_m1",
		})
	}
	ingestBatch(t, db, s, "agent_a", ms)
	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("Rollup: %v", err)
	}

	ids, err := s.ResolveSeriesIDs(ctx, "site_default", "agent_a", "probe_m1", string(telemetry.ICMPRTTms), "1.1.1.1")
	if err != nil || len(ids) != 1 {
		t.Fatalf("resolve: ids=%v err=%v", ids, err)
	}
	id := ids[0]

	// Delete a 10-minute window in the middle, aligned to minute boundaries.
	from := start + 10*60
	to := start + 20*60
	counts, err := s.PurgeRange(ctx, ids, from, to)
	if err != nil {
		t.Fatalf("PurgeRange: %v", err)
	}
	if counts.Samples != 600 {
		t.Errorf("deleted raw samples = %d, want 600", counts.Samples)
	}

	// Raw: no samples remain in [from,to); samples before and after survive.
	var inWindow, before, after int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE series_id=? AND ts>=? AND ts<?`, id, from, to).Scan(&inWindow)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE series_id=? AND ts<?`, id, from).Scan(&before)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE series_id=? AND ts>=?`, id, to).Scan(&after)
	if inWindow != 0 {
		t.Errorf("raw samples in window = %d, want 0", inWindow)
	}
	if before != 600 || after != 600 {
		t.Errorf("surrounding raw = before %d / after %d, want 600 / 600", before, after)
	}

	// Rollup 1m buckets in the window are gone (10 buckets), others remain.
	var m1InWindow int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rollup_1m WHERE series_id=? AND ts>=? AND ts<?`, id, from, to).Scan(&m1InWindow)
	if m1InWindow != 0 {
		t.Errorf("rollup_1m buckets in window = %d, want 0", m1InWindow)
	}
}

// TestPurgeRangeKeepsEmptiedSeries verifies a range delete that clears every tier
// removes the data but KEEPS the dictionary row (a live series must not lose its
// id out from under a concurrent ingest that already resolved it).
func TestPurgeRangeKeepsEmptiedSeries(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()

	base := alignDown(time.Now().Unix(), 60) - 3600
	var ms []telemetry.Metric
	for ts := base; ts < base+120; ts++ {
		ms = append(ms, telemetry.Metric{
			TS: time.Unix(ts, 0), Kind: telemetry.ICMPRTTms, Target: "2.2.2.2",
			Value: 1, Unit: "ms", MonitorID: "probe_m9",
		})
	}
	ingestBatch(t, db, s, "agent_a", ms)
	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("Rollup: %v", err)
	}
	ids, _ := s.ResolveSeriesIDs(ctx, "site_default", "agent_a", "probe_m9", string(telemetry.ICMPRTTms), "2.2.2.2")
	if len(ids) != 1 {
		t.Fatalf("want 1 series, got %d", len(ids))
	}

	// Cover the whole span (and beyond) so every tier empties.
	counts, err := s.PurgeRange(ctx, ids, base, base+7200)
	if err != nil {
		t.Fatalf("PurgeRange: %v", err)
	}
	if counts.Series != 0 {
		t.Errorf("range delete removed %d series rows, want 0 (row must be kept)", counts.Series)
	}
	// The dictionary row survives; its data is gone.
	left, _ := s.ResolveSeriesIDs(ctx, "site_default", "agent_a", "probe_m9", string(telemetry.ICMPRTTms), "2.2.2.2")
	if len(left) != 1 {
		t.Errorf("series row should survive an empty range delete, got %v", left)
	}
	var nSamples int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM samples WHERE series_id=?`, ids[0]).Scan(&nSamples)
	if nSamples != 0 {
		t.Errorf("samples remain after full-span range delete: %d", nSamples)
	}
}

// TestPurgeRangeIdempotent verifies re-deleting an already-cleared range is a
// safe no-op that reports zero.
func TestPurgeRangeIdempotent(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	base := alignDown(time.Now().Unix(), 60) - 3600
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{
		{TS: time.Unix(base, 0), Kind: telemetry.ICMPRTTms, Target: "3.3.3.3", Value: 1, Unit: "ms", MonitorID: "probe_i"},
	})
	ids, _ := s.ResolveSeriesIDs(ctx, "site_default", "agent_a", "probe_i", string(telemetry.ICMPRTTms), "3.3.3.3")
	if _, err := s.PurgeRange(ctx, ids, base-60, base+60); err != nil {
		t.Fatalf("first PurgeRange: %v", err)
	}
	// The dictionary row is kept, so it still resolves; the data is gone, so a
	// second delete over the same window removes nothing.
	again, _ := s.ResolveSeriesIDs(ctx, "site_default", "agent_a", "probe_i", string(telemetry.ICMPRTTms), "3.3.3.3")
	counts, err := s.PurgeRange(ctx, again, base-60, base+60)
	if err != nil {
		t.Fatalf("second PurgeRange: %v", err)
	}
	if counts.Samples != 0 || counts.Series != 0 {
		t.Errorf("idempotent re-delete removed %+v, want zero", counts)
	}
}
