package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/tsstore"
)

// TestClearSeriesHistoryHidesEverythingRecorded pins the contract the function
// name states: after it returns, nothing that was already stored is readable.
//
// Two samples make that non-trivial. One sits exactly on the second the clear
// runs, and purge_cutoff is an INCLUSIVE lower bound for every reader — a
// cutoff of "now" would leave it visible. The other is stamped ahead of the
// clock: ingest accepts up to two minutes of future slack, so a series can hold
// samples above now at the moment of the clear, and a cutoff derived from the
// clock alone would never cover them. The cutoff is therefore taken from the
// series' actual extent.
func TestClearSeriesHistoryHidesEverythingRecorded(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	mk := func(ts time.Time, v float64) telemetry.Metric {
		return telemetry.Metric{
			TS: ts, Kind: telemetry.ICMPRTTms, Target: "10.0.0.1", Layer: "lan",
			Value: v, Unit: "ms", MonitorID: "probe_m1",
		}
	}
	// Ordinary history, a sample landing on the clear second, and one inside the
	// future slack ingest allows.
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{
		mk(now.Add(-time.Hour), 1),
		mk(now, 2),
		mk(now.Add(90*time.Second), 3),
	})

	var seriesID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM series WHERE agent_id='agent_a' AND monitor_id='probe_m1'`).Scan(&seriesID); err != nil {
		t.Fatalf("series id: %v", err)
	}

	if _, err := s.ClearSeriesHistory(ctx, []int64{seriesID}); err != nil {
		t.Fatalf("ClearSeriesHistory: %v", err)
	}

	var cutoff int64
	if err := db.QueryRowContext(ctx, `SELECT purge_cutoff FROM series WHERE id=?`, seriesID).Scan(&cutoff); err != nil {
		t.Fatalf("read cutoff: %v", err)
	}
	if want := now.Add(90*time.Second).Unix() + 1; cutoff != want {
		t.Fatalf("purge_cutoff=%d, want %d (one past the newest stored sample)", cutoff, want)
	}

	// Every reader that honours the cutoff must now see nothing.
	pts, err := s.Query(ctx, Query{
		AgentID: "agent_a", MonitorID: "probe_m1", Kind: string(telemetry.ICMPRTTms),
		SinceUnix: now.Add(-2 * time.Hour).Unix(), UntilUnix: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(pts) != 0 {
		t.Fatalf("Query returned %d points after a full clear; the first is %+v", len(pts), pts[0])
	}
	live, err := s.LatestForSeries(ctx, []string{"agent_a"}, []int64{seriesID})
	if err != nil {
		t.Fatalf("LatestForSeries: %v", err)
	}
	if _, ok := live[seriesID]; ok {
		t.Fatalf("the latest cache still serves a value the clear was supposed to hide")
	}

	// A sample recorded AFTER the clear is new history and must appear.
	after := now.Add(3 * time.Minute)
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{mk(after, 42)})
	pts, err = s.Query(ctx, Query{
		AgentID: "agent_a", MonitorID: "probe_m1", Kind: string(telemetry.ICMPRTTms),
		SinceUnix: now.Add(-2 * time.Hour).Unix(), UntilUnix: after.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Query after: %v", err)
	}
	if len(pts) != 1 || pts[0].Value != 42 {
		t.Fatalf("post-clear sample not served back: %+v", pts)
	}
}

// TestTSStoreConfigTranslatesForever pins the zero-means-opposite-things hazard
// between the two configs: RetentionConfig spells "keep forever" as 0, while
// tsstore reads a nonpositive duration as "use my default" (raw 5d, m1 30d, h1
// 2y). Passing a zero through would bound a tier the query planner still treats
// as unbounded, dropping blocks under reads that expect them.
func TestTSStoreConfigTranslatesForever(t *testing.T) {
	got := RetentionConfig{}.TSStoreConfig()
	for _, tc := range []struct {
		name string
		have time.Duration
	}{
		{"raw", got.RawRetention},
		{"m1", got.M1Retention},
		{"h1", got.H1Retention},
		{"d1", got.D1Retention},
	} {
		if tc.have != tsstore.Forever {
			t.Errorf("%s retention = %v for an all-zero RetentionConfig, want tsstore.Forever: "+
				"a zero forwarded as-is becomes a FINITE tsstore default", tc.name, tc.have)
		}
	}

	// A configured tier still maps through, and raw still carries its backfill slack.
	cfg := RetentionConfig{RawSeconds: 2 * 86400, M1Seconds: 30 * 86400, H1Seconds: 0, D1Seconds: 0}.TSStoreConfig()
	if want := 5 * 24 * time.Hour; cfg.RawRetention != want {
		t.Errorf("raw retention = %v, want %v (logical 2d + 3d slack)", cfg.RawRetention, want)
	}
	if want := 30 * 24 * time.Hour; cfg.M1Retention != want {
		t.Errorf("m1 retention = %v, want %v", cfg.M1Retention, want)
	}
	if cfg.H1Retention != tsstore.Forever || cfg.D1Retention != tsstore.Forever {
		t.Errorf("zero tiers alongside configured ones must still be Forever: h1=%v d1=%v",
			cfg.H1Retention, cfg.D1Retention)
	}
}
