package metrics

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

func openStore(t testing.TB) (*store.DB, *Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, New(db)
}

// ingestBatch runs the real write path: EnsureSeries → tx InsertSamples → UpdateLatest.
func ingestBatch(t testing.TB, db *store.DB, s *Store, agentID string, ms []telemetry.Metric) {
	t.Helper()
	ctx := context.Background()
	ids, err := s.EnsureSeries(ctx, agentID, "site_default", ms)
	if err != nil {
		t.Fatalf("EnsureSeries: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := s.InsertSamples(ctx, tx, agentID, ids, ms); err != nil {
		t.Fatalf("InsertSamples: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.UpdateLatest(agentID, ids, ms)
}

// TestMonitorSeriesIsolation is the core guarantee of the monitor_id re-keying:
// two monitors probing the SAME target string keep fully separate series,
// latest values and query results.
func TestMonitorSeriesIsolation(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now()

	mk := func(mon string, v float64) telemetry.Metric {
		return telemetry.Metric{
			TS: now, Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet",
			Value: v, Unit: "ms", MonitorID: mon,
		}
	}
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{mk("probe_m1", 10), mk("probe_m2", 200)})

	// Two series rows, not one.
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM series WHERE agent_id='agent_a' AND target='1.1.1.1'`).Scan(&n); err != nil {
		t.Fatalf("count series: %v", err)
	}
	if n != 2 {
		t.Fatalf("series rows for same target = %d, want 2 (one per monitor)", n)
	}

	// Latest values resolve per monitor.
	for _, tc := range []struct {
		mon  string
		want float64
	}{{"probe_m1", 10}, {"probe_m2", 200}} {
		got, err := s.LatestByMonitor(ctx, "agent_a", string(telemetry.ICMPRTTms), tc.mon, 0, now.Unix()-60)
		if err != nil {
			t.Fatalf("LatestByMonitor(%s): %v", tc.mon, err)
		}
		if len(got) != 1 || got[0].Value != tc.want {
			t.Errorf("LatestByMonitor(%s) = %+v, want one value %v", tc.mon, got, tc.want)
		}
	}

	// System lookup (monitor_id='') must NOT see monitor series.
	sys, err := s.LatestPerSeries(ctx, "agent_a", string(telemetry.ICMPRTTms), "1.1.1.1", now.Unix()-60)
	if err != nil {
		t.Fatalf("LatestPerSeries: %v", err)
	}
	if len(sys) != 0 {
		t.Errorf("LatestPerSeries(system) sees monitor series: %+v", sys)
	}

	// Query filtered by monitor returns only that monitor's points.
	pts, err := s.Query(ctx, Query{AgentID: "agent_a", Kind: string(telemetry.ICMPRTTms), MonitorID: "probe_m2", SinceUnix: now.Unix() - 60})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(pts) != 1 || pts[0].Value != 200 || pts[0].MonitorID != "probe_m2" {
		t.Errorf("Query(monitor=probe_m2) = %+v, want single point value 200", pts)
	}

	// Purging one monitor leaves the sibling intact.
	removed, err := s.PurgeMonitor(ctx, "site_default", "probe_m1")
	if err != nil {
		t.Fatalf("PurgeMonitor: %v", err)
	}
	if removed != 1 {
		t.Errorf("PurgeMonitor removed %d series, want 1", removed)
	}
	left, err := s.LatestByMonitor(ctx, "agent_a", string(telemetry.ICMPRTTms), "probe_m2", 0, now.Unix()-60)
	if err != nil {
		t.Fatalf("LatestByMonitor after purge: %v", err)
	}
	if len(left) != 1 {
		t.Errorf("sibling monitor's series lost after purge: %+v", left)
	}
}

// TestLatestWarmFromDB verifies a fresh Store (process restart) serves latest
// values seeded only in the DB.
func TestLatestWarmFromDB(t *testing.T) {
	db, s := openStore(t)
	now := time.Now()
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{
		{TS: now, Kind: telemetry.HostCPUPct, Target: "host", Value: 42, Unit: "pct"},
	})

	fresh := New(db) // same DB, empty caches — like a restart
	got, err := fresh.LatestPerSeries(context.Background(), "agent_a", string(telemetry.HostCPUPct), "host", now.Unix()-60)
	if err != nil {
		t.Fatalf("LatestPerSeries: %v", err)
	}
	if len(got) != 1 || got[0].Value != 42 {
		t.Errorf("warm-from-DB latest = %+v, want value 42", got)
	}
}

// TestRollupTiersAndQuery seeds raw samples, runs Rollup, and reads a >2h range
// so Query serves 1m-bucket averages.
func TestRollupTiersAndQuery(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()

	// 10 minutes of 1-second samples ending "now", value == constant 4 with one
	// spike, so bucket averages are easy to assert.
	end := alignDown(time.Now().Unix(), 60)
	start := end - 600
	var ms []telemetry.Metric
	for ts := start; ts < end; ts++ {
		v := 4.0
		if ts == start { // one spike in the first bucket
			v = 64.0
		}
		ms = append(ms, telemetry.Metric{
			TS: time.Unix(ts, 0), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1",
			Value: v, Unit: "ms", MonitorID: "probe_m1",
		})
	}
	ingestBatch(t, db, s, "agent_a", ms)

	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("Rollup: %v", err)
	}

	var buckets int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rollup_1m`).Scan(&buckets); err != nil {
		t.Fatalf("count rollup_1m: %v", err)
	}
	if buckets != 10 {
		t.Fatalf("rollup_1m buckets = %d, want 10", buckets)
	}

	// First bucket: 59×4 + 1×64 → avg 5.0. Query over a 3h range hits rollup_1m.
	pts, err := s.Query(ctx, Query{AgentID: "agent_a", Kind: string(telemetry.ICMPRTTms), MonitorID: "probe_m1", SinceUnix: time.Now().Unix() - 3*3600})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(pts) != 10 {
		t.Fatalf("rollup query points = %d, want 10", len(pts))
	}
	if pts[0].Value != 5.0 {
		t.Errorf("first bucket avg = %v, want 5.0", pts[0].Value)
	}
	if pts[1].Value != 4.0 {
		t.Errorf("second bucket avg = %v, want 4.0", pts[1].Value)
	}

	// A second Rollup run (overlap window) must not corrupt existing buckets.
	if err := s.Rollup(ctx); err != nil {
		t.Fatalf("Rollup again: %v", err)
	}
	pts2, err := s.Query(ctx, Query{AgentID: "agent_a", Kind: string(telemetry.ICMPRTTms), MonitorID: "probe_m1", SinceUnix: time.Now().Unix() - 3*3600})
	if err != nil {
		t.Fatalf("Query after re-rollup: %v", err)
	}
	if len(pts2) != 10 || pts2[0].Value != 5.0 {
		t.Errorf("re-rollup changed buckets: n=%d first=%v (want 10, 5.0)", len(pts2), pts2[0].Value)
	}
}

// TestRetentionPrunes verifies old raw samples are pruned while rollups stay.
func TestRetentionPrunes(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	old := time.Now().Add(-72 * time.Hour)
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{
		{TS: old, Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Value: 1, Unit: "ms", MonitorID: "probe_m1"},
		{TS: time.Now(), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Value: 2, Unit: "ms", MonitorID: "probe_m1"},
	})
	if err := s.Retention(ctx, RetentionConfig{RawSeconds: 2 * 86400}); err != nil {
		t.Fatalf("Retention: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM samples`).Scan(&n); err != nil {
		t.Fatalf("count samples: %v", err)
	}
	if n != 1 {
		t.Errorf("samples after retention = %d, want 1 (old sample pruned)", n)
	}
}

func TestCurrentSnapshotUsesOnlyAuthoritativeGeneration(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES('site_default','Default')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('group','site_default','All',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,config_serial,config_changed_at)
		VALUES('monitor','site_default','group','http','https://example.test','{}',1,2,?)`, now); err != nil {
		t.Fatal(err)
	}
	old := telemetry.Metric{
		TS: now, Kind: telemetry.HTTPOK, Target: "https://example.test", Layer: telemetry.LayerService,
		Value: 0, Unit: telemetry.UnitBool, MonitorID: "monitor", ConfigSerial: 1,
	}
	ingestBatch(t, db, s, "agent", []telemetry.Metric{old})
	got, err := s.LatestSnapshot(ctx, "agent", now.Add(-time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("old generation surfaced before current sample: %+v", got)
	}

	current := old
	current.TS = now.Add(time.Second)
	current.Value = 1
	current.ConfigSerial = 2
	ingestBatch(t, db, s, "agent", []telemetry.Metric{current})
	got, err = s.LatestSnapshot(ctx, "agent", now.Add(-time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Value != 1 {
		t.Fatalf("current snapshot = %+v, want generation-2 value 1", got)
	}
	series, err := s.ListSeries(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 || series[0].MonitorID != "monitor" {
		t.Fatalf("logical selectors = %+v, want one generation-neutral row", series)
	}
	history, err := s.Query(ctx, Query{AgentID: "agent", MonitorID: "monitor", Kind: string(telemetry.HTTPOK), SinceUnix: now.Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].Value != 0 || history[1].Value != 1 {
		t.Fatalf("history = %+v, want both generations", history)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"host", "host", true},
		{"host", "host2", false},
		{"C:", "C:", true},
		{"*", "anything", true},
		{"probe*", "probe_x", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*tail", "long-tail", true},
		{"*tail", "long-tails", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}

// BenchmarkIngestBatch measures the full write path for one agent packet of 100
// samples across 20 series — the shape of a 20-monitor agent uploading 5s of
// 1-second data.
func BenchmarkIngestBatch(b *testing.B) {
	db, s := openStore(b)
	ctx := context.Background()

	base := time.Now().Add(-time.Duration(b.N+10) * time.Second)
	var ms []telemetry.Metric
	for i := 0; i < 100; i++ {
		ms = append(ms, telemetry.Metric{
			Kind: telemetry.ICMPRTTms, Target: fmt.Sprintf("10.0.0.%d", i%20),
			Value: float64(i), Unit: "ms", MonitorID: fmt.Sprintf("probe_m%d", i%20),
		})
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for i := range ms {
			ms[i].TS = base.Add(time.Duration(n*5+i/20) * time.Second) // advance so PK never collides
		}
		ids, err := s.EnsureSeries(ctx, "agent_bench", "site_default", ms)
		if err != nil {
			b.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err := s.InsertSamples(ctx, tx, "agent_bench", ids, ms); err != nil {
			b.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			b.Fatal(err)
		}
		s.UpdateLatest("agent_bench", ids, ms)
	}
}
