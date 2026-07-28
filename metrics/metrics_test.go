package metrics

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func openStore(t testing.TB) (*store.DB, *Store) {
	t.Helper()
	db := storetest.Open(t)
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
	ids, err := s.ResolveSeriesIDs(ctx, "site_default", "agent_a", "probe_m1", string(telemetry.ICMPRTTms), "1.1.1.1")
	if err != nil {
		t.Fatalf("ResolveSeriesIDs: %v", err)
	}
	removed, err := s.PurgeSeriesIDs(ctx, ids)
	if err != nil {
		t.Fatalf("PurgeSeriesIDs: %v", err)
	}
	if removed.Series != 1 {
		t.Errorf("PurgeSeriesIDs removed %d series, want 1", removed.Series)
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

// A monitor re-typed in place (dns → http) keeps its old kind's series in the
// dictionary forever. ListSeries must not offer them: a consumer picking the dead
// probe.dns.ok as the monitor's availability band would report a healthy 100% for
// a target whose HTTP probe fails every cycle.
func TestListSeriesHidesSeriesTheCurrentKindCannotEmit(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES('site_default','Default')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('group','site_default','All',1)`); err != nil {
		t.Fatal(err)
	}
	// The monitor was a DNS probe first, then re-typed to HTTP.
	if _, err := db.ExecContext(ctx, `INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,config_serial,config_changed_at)
		VALUES('monitor','site_default','group','dns','www.yahoo.co.jp','{}',1,1,?)`, now); err != nil {
		t.Fatal(err)
	}
	ingestBatch(t, db, s, "agent", []telemetry.Metric{
		{TS: now, Kind: telemetry.DNSOK, Target: "www.yahoo.co.jp", Layer: telemetry.LayerService,
			Value: 1, Unit: telemetry.UnitBool, MonitorID: "monitor", ConfigSerial: 1},
		// A system series has no owning monitor and must always survive.
		{TS: now, Kind: telemetry.HostCPUPct, Target: "host", Layer: telemetry.LayerLocal, Value: 12, Unit: telemetry.UnitPct},
	})
	if _, err := db.ExecContext(ctx, `UPDATE probe_tasks SET kind='http', target='https://www.yahoo.co.jp', config_serial=2 WHERE id='monitor'`); err != nil {
		t.Fatal(err)
	}
	ingestBatch(t, db, s, "agent", []telemetry.Metric{
		{TS: now.Add(time.Second), Kind: telemetry.HTTPOK, Target: "https://www.yahoo.co.jp", Layer: telemetry.LayerService,
			Value: 0, Unit: telemetry.UnitBool, MonitorID: "monitor", ConfigSerial: 2},
	})

	series, err := s.ListSeries(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, si := range series {
		kinds[si.Kind] = true
	}
	if kinds[string(telemetry.DNSOK)] {
		t.Fatalf("stale dns series still listed for an http monitor: %+v", series)
	}
	if !kinds[string(telemetry.HTTPOK)] || !kinds[string(telemetry.HostCPUPct)] {
		t.Fatalf("series = %+v, want the current http series and the system series", series)
	}
}

// TestSummarize pins the server aggregates to what the status page's browser
// code computed from Query results before PERF-001: latest = strictly-newest
// sample, P95 = nearest-rank over the merged raw window, matched across all
// generations.
func TestSummarize(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	kind := string(telemetry.ICMPRTTms)

	mk := func(ts int64, mon string, v float64, serial int) telemetry.Metric {
		return telemetry.Metric{
			TS: time.Unix(ts, 0), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet",
			Value: v, Unit: "ms", MonitorID: mon, ConfigSerial: serial,
		}
	}

	t.Run("small sample parity and missing kind", func(t *testing.T) {
		// Mirrors the frontend test fixture: [10, 20, 35] → latest 35, P95 35
		// (nearest rank: ceil(3*0.95)-1 = index 2).
		ingestBatch(t, db, s, "agent_small", []telemetry.Metric{
			mk(now-30, "probe_m1", 10, 1), mk(now-20, "probe_m1", 20, 1), mk(now-10, "probe_m1", 35, 1),
		})
		got, err := s.Summarize(ctx, SummaryQuery{
			AgentID: "agent_small", Kinds: []string{kind, "probe.never.reported"}, MonitorID: "probe_m1",
		})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		ks := got[kind]
		if ks.Count != 3 || ks.Latest == nil || ks.Latest.Value != 35 || ks.Latest.TS.Unix() != now-10 {
			t.Errorf("summary = %+v, want count 3 latest 35 @ now-10", ks)
		}
		if ks.P95 == nil || *ks.P95 != 35 {
			t.Errorf("p95 = %v, want 35", ks.P95)
		}
		missing, ok := got["probe.never.reported"]
		if !ok || missing.Count != 0 || missing.Latest != nil || missing.P95 != nil {
			t.Errorf("missing kind entry = %+v ok=%v, want present zero summary", missing, ok)
		}
	})

	t.Run("7201-sample window", func(t *testing.T) {
		// Full 2h window at 1s interval: values 0..7200 by ts, plus one
		// out-of-window sample that must not leak into the aggregates. The run
		// is shifted 60s forward of `now` so the oldest sample sits safely above
		// Summarize's live cutoff (its own time.Now minus 2h) even if the wall
		// clock advances a few seconds while the 7202 rows are inserted; the
		// out-of-window sample stays below any possible cutoff.
		const slack = 60
		ms := make([]telemetry.Metric, 0, 7202)
		ms = append(ms, mk(now-7300, "probe_m1", 9999, 1))
		for i := int64(0); i <= 7200; i++ {
			ms = append(ms, mk(now-7200+slack+i, "probe_m1", float64(i), 1))
		}
		ingestBatch(t, db, s, "agent_full", ms)
		got, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_full", Kinds: []string{kind}, MonitorID: "probe_m1"})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		ks := got[kind]
		if ks.Count != 7201 {
			t.Fatalf("count = %d, want 7201", ks.Count)
		}
		if ks.Latest == nil || ks.Latest.Value != 7200 {
			t.Errorf("latest = %+v, want 7200", ks.Latest)
		}
		// ceil(7201*0.95)-1 = 6840 → value 6840 in the sorted 0..7200 run.
		if ks.P95 == nil || *ks.P95 != 6840 {
			t.Errorf("p95 = %v, want 6840", ks.P95)
		}
	})

	t.Run("merges generations like Query", func(t *testing.T) {
		ingestBatch(t, db, s, "agent_gen", []telemetry.Metric{
			mk(now-20, "probe_m1", 100, 1), // old generation
			mk(now-10, "probe_m1", 50, 2),  // current generation
		})
		got, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_gen", Kinds: []string{kind}, MonitorID: "probe_m1"})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		ks := got[kind]
		// Both generations count; latest comes from the newer one, P95 from the
		// merged set (ceil(2*0.95)-1 = index 1 of [50,100] → 100).
		if ks.Count != 2 || ks.Latest == nil || ks.Latest.Value != 50 || ks.P95 == nil || *ks.P95 != 100 {
			t.Errorf("summary = %+v, want count 2 latest 50 p95 100", ks)
		}
	})

	t.Run("monitor filter isolation", func(t *testing.T) {
		ingestBatch(t, db, s, "agent_mon", []telemetry.Metric{
			mk(now-20, "probe_m1", 10, 1), mk(now-10, "probe_m2", 200, 1),
		})
		got, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_mon", Kinds: []string{kind}, MonitorID: "probe_m2"})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		if ks := got[kind]; ks.Count != 1 || ks.Latest == nil || ks.Latest.Value != 200 {
			t.Errorf("filtered summary = %+v, want only probe_m2's sample", ks)
		}
		all, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_mon", Kinds: []string{kind}})
		if err != nil {
			t.Fatalf("Summarize all: %v", err)
		}
		if ks := all[kind]; ks.Count != 2 {
			t.Errorf("unfiltered summary = %+v, want both monitors", ks)
		}
	})

	t.Run("tied timestamps keep merge-order winner", func(t *testing.T) {
		// Same ts across two monitors: the strictly-greater scan keeps the first
		// entry in (target, monitor, ts) order — probe_m1 — matching the JS reduce
		// over Query output.
		ingestBatch(t, db, s, "agent_tie", []telemetry.Metric{
			mk(now-10, "probe_m1", 1, 1), mk(now-10, "probe_m2", 2, 1),
		})
		got, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_tie", Kinds: []string{kind}})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		if ks := got[kind]; ks.Latest == nil || ks.Latest.Value != 1 {
			t.Errorf("tied-ts latest = %+v, want probe_m1's value 1", ks.Latest)
		}
	})

	t.Run("worst reduce with target exclusion", func(t *testing.T) {
		// Dashboard quality semantics: drop the gateway leg, collapse to the
		// per-timestamp worst across the remaining targets, then aggregate.
		mkT := func(ts int64, target string, v float64) telemetry.Metric {
			return telemetry.Metric{
				TS: time.Unix(ts, 0), Kind: telemetry.ICMPRTTms, Target: target, Layer: "internet",
				Value: v, Unit: "ms", MonitorID: "probe_" + target,
			}
		}
		ingestBatch(t, db, s, "agent_worst", []telemetry.Metric{
			mkT(now-20, "1.1.1.1", 10), mkT(now-20, "8.8.8.8", 30), mkT(now-20, "gateway", 500),
			mkT(now-10, "1.1.1.1", 40), mkT(now-10, "8.8.8.8", 20), mkT(now-10, "gateway", 500),
		})
		got, err := s.Summarize(ctx, SummaryQuery{
			AgentID: "agent_worst", Kinds: []string{kind},
			Reduce: ReduceWorstByTS, ExcludeTargets: []string{"gateway"},
		})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		ks := got[kind]
		// Worst-by-ts series is [30 @ now-20, 40 @ now-10]: count 2, latest 40,
		// p95 = 40 (index 1), avg = 35. Gateway's 500s must not leak in.
		if ks.Count != 2 || ks.Latest == nil || ks.Latest.Value != 40 {
			t.Errorf("summary = %+v, want count 2 latest 40", ks)
		}
		if ks.P95 == nil || *ks.P95 != 40 || ks.Avg == nil || *ks.Avg != 35 {
			t.Errorf("p95/avg = %v/%v, want 40/35", ks.P95, ks.Avg)
		}
	})

	t.Run("target filter", func(t *testing.T) {
		got, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_worst", Kinds: []string{kind}, Target: "8.8.8.8"})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		if ks := got[kind]; ks.Count != 2 || ks.Latest == nil || ks.Latest.Value != 20 {
			t.Errorf("target-filtered summary = %+v, want only 8.8.8.8's two samples, latest 20", ks)
		}
	})

	t.Run("latest nonzero fallback for code kinds", func(t *testing.T) {
		// NAT-style series: a determinate result followed by a transient
		// "unknown" (code 0). latest = 0, latest_nonzero = the code-5 sample.
		natKind := string(telemetry.MetricKind("probe.nat.type"))
		ingestBatch(t, db, s, "agent_nat", []telemetry.Metric{
			{TS: time.Unix(now-20, 0), Kind: telemetry.MetricKind(natKind), Target: "stun", Layer: "internet", Value: 5, Unit: "code", MonitorID: "probe_nat"},
			{TS: time.Unix(now-10, 0), Kind: telemetry.MetricKind(natKind), Target: "stun", Layer: "internet", Value: 0, Unit: "code", MonitorID: "probe_nat"},
		})
		got, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_nat", Kinds: []string{natKind}, MonitorID: "probe_nat"})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		ks := got[natKind]
		if ks.Latest == nil || ks.Latest.Value != 0 {
			t.Errorf("latest = %+v, want the transient 0", ks.Latest)
		}
		if ks.LatestNonzero == nil || ks.LatestNonzero.Value != 5 || ks.LatestNonzero.TS.Unix() != now-20 {
			t.Errorf("latest_nonzero = %+v, want the code-5 sample @ now-20", ks.LatestNonzero)
		}
	})

	t.Run("24h window reads raw", func(t *testing.T) {
		// Beyond the 2h Query tier but within raw retention: aggregates still
		// come from raw samples.
		ingestBatch(t, db, s, "agent_day", []telemetry.Metric{
			mk(now-20*3600, "probe_m1", 100, 1), mk(now-10, "probe_m1", 10, 1),
		})
		got, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_day", Kinds: []string{kind}, WindowSeconds: 24 * 3600})
		if err != nil {
			t.Fatalf("Summarize: %v", err)
		}
		if ks := got[kind]; ks.Count != 2 || ks.Latest == nil || ks.Latest.Value != 10 || ks.P95 == nil || *ks.P95 != 100 {
			t.Errorf("24h summary = %+v, want count 2 latest 10 p95 100", ks)
		}
	})

	t.Run("window beyond raw retention is rejected", func(t *testing.T) {
		_, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_small", Kinds: []string{kind}, WindowSeconds: 7 * 86400})
		if !errors.Is(err, ErrSummaryWindow) {
			t.Errorf("err = %v, want ErrSummaryWindow", err)
		}
	})

	t.Run("unknown reduce mode is rejected", func(t *testing.T) {
		_, err := s.Summarize(ctx, SummaryQuery{AgentID: "agent_small", Kinds: []string{kind}, Reduce: "median"})
		if !errors.Is(err, ErrSummaryReduce) {
			t.Errorf("err = %v, want ErrSummaryReduce", err)
		}
	})
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
