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
	"github.com/nettact/server-core/tsstore"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

func openStore(t testing.TB) (*store.DB, *Store) {
	t.Helper()
	db := storetest.Open(t)
	return db, New(db, tsstoretest.Open(t))
}

// ingestBatch runs the real write path in ingest's ordering: EnsureSeries (pre-tx)
// → in-tx RewindForBatch → BeginPendingAppend → commit → post-commit
// AppendRawSamples → UpdateLatest.
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
	if err := s.RewindForBatch(ctx, tx, agentID, ids, ms); err != nil {
		t.Fatalf("RewindForBatch: %v", err)
	}
	pendingDone := s.BeginPendingAppend(ids)
	defer func() {
		if pendingDone != nil {
			pendingDone()
		}
	}()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := s.AppendRawSamples(ctx, agentID, ids, ms); err != nil {
		t.Fatalf("AppendRawSamples: %v", err)
	}
	pendingDone()
	pendingDone = nil
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

	fresh := New(db, s.ts) // same DB and data plane, empty caches — like a restart
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

	ids, err := s.ResolveSeriesIDs(ctx, "site_default", "agent_a", "probe_m1", string(telemetry.ICMPRTTms), "1.1.1.1")
	if err != nil || len(ids) != 1 {
		t.Fatalf("resolve: ids=%v err=%v", ids, err)
	}
	buckets, err := s.ts.ReadBuckets(ctx, tsstore.TierM1, ids[0], start, end)
	if err != nil {
		t.Fatalf("ReadBuckets: %v", err)
	}
	if len(buckets) != 10 {
		t.Fatalf("rollup_1m buckets = %d, want 10", len(buckets))
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

// seedHistoricalRun ingests ten minutes of 1-second samples ending `age` before
// now and builds every rollup tier over them. The stretch is hour-aligned so the
// hourly bucket covering it is stamped at the window's own start — rollup rows
// carry the BUCKET's timestamp, which can otherwise precede the range asking for
// them. One spike survives only at raw resolution; the minute bucket containing
// it averages to exactly 5.0, which is how a test tells the tiers apart.
func seedHistoricalRun(t *testing.T, db *store.DB, s *Store, age time.Duration) (start, end int64) {
	t.Helper()
	const span = 600
	start = alignDown(time.Now().Unix()-int64(age.Seconds()), 3600)
	end = start + span
	var ms []telemetry.Metric
	for ts := start; ts < end; ts++ {
		v := 4.0
		if ts == start+30 {
			v = 64.0
		}
		ms = append(ms, telemetry.Metric{
			TS: time.Unix(ts, 0), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1",
			Value: v, Unit: "ms", MonitorID: "probe_m1",
		})
	}
	ingestBatch(t, db, s, "agent_a", ms)
	if err := s.Rollup(context.Background()); err != nil {
		t.Fatalf("Rollup: %v", err)
	}
	return start, end
}

// TestQueryUntilBoundsTheWindow covers what the upper bound does to the SET of
// points, at one fixed resolution. Tier selection is TestTierSelectionByWidthAndAge.
func TestQueryUntilBoundsTheWindow(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()

	// Ten minutes of 1-second samples ending now: recent and narrow, so every query
	// below reads raw samples and the counts are exact.
	const span = 600
	end := time.Now().Unix()
	start := end - span
	var ms []telemetry.Metric
	for ts := start; ts < end; ts++ {
		ms = append(ms, telemetry.Metric{
			TS: time.Unix(ts, 0), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1",
			Value: 4, Unit: "ms", MonitorID: "probe_m1",
		})
	}
	ingestBatch(t, db, s, "agent_a", ms)

	base := Query{AgentID: "agent_a", Kind: string(telemetry.ICMPRTTms), MonitorID: "probe_m1", SinceUnix: start}
	all, err := s.Query(ctx, base)
	if err != nil {
		t.Fatalf("unbounded Query: %v", err)
	}
	if len(all) != span {
		t.Fatalf("unbounded window = %d points, want %d", len(all), span)
	}

	// Both ends are inclusive, so half the window is half the points plus the
	// boundary second itself.
	q := base
	q.UntilUnix = start + span/2
	half, err := s.Query(ctx, q)
	if err != nil {
		t.Fatalf("half-window Query: %v", err)
	}
	if len(half) != span/2+1 {
		t.Fatalf("half window = %d points, want %d", len(half), span/2+1)
	}
	for _, p := range half {
		if p.TS.Unix() < start || p.TS.Unix() > q.UntilUnix {
			t.Fatalf("point at %d escapes the window [%d,%d]", p.TS.Unix(), start, q.UntilUnix)
		}
	}

	// The limit counts WITHIN the bounded window, still taking its earliest points.
	q.Limit = 10
	if capped, err := s.Query(ctx, q); err != nil || len(capped) != 10 {
		t.Fatalf("limited window = %d points (%v), want 10", len(capped), err)
	}

	// An inverted window is empty, not an error: it is a range containing no
	// seconds, which is a legitimate thing for a caller to ask about.
	q = base
	q.UntilUnix = start - 3600
	if empty, err := s.Query(ctx, q); err != nil || len(empty) != 0 {
		t.Fatalf("inverted window = %d points (%v), want none", len(empty), err)
	}

	// Agent device clocks run ahead of the server's, so a sample can legitimately
	// be stamped in the future — and this store keeps it as history. An unbounded
	// read must still return it, which is why an absent (or future) bound applies
	// NO upper bound rather than clamping the window to now.
	ahead := time.Now().Unix() + 600
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{{
		TS: time.Unix(ahead, 0), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1",
		Value: 99, Unit: "ms", MonitorID: "probe_m1",
	}})
	q = base
	q.SinceUnix = time.Now().Unix() - 60
	skewed, err := s.Query(ctx, q)
	if err != nil {
		t.Fatalf("unbounded Query over skewed sample: %v", err)
	}
	if len(skewed) == 0 || skewed[len(skewed)-1].Value != 99 {
		t.Fatalf("unbounded read = %+v, want the clock-skewed sample", skewed)
	}
	q.UntilUnix = time.Now().Unix() + 3600
	if bounded, err := s.Query(ctx, q); err != nil || len(bounded) != len(skewed) {
		t.Fatalf("future bound = %d points (%v), want the unbounded %d", len(bounded), err, len(skewed))
	}
	// A bound in the past, however, is applied — and excludes it.
	q.UntilUnix = time.Now().Unix() - 1
	past, err := s.Query(ctx, q)
	if err != nil {
		t.Fatalf("past bound: %v", err)
	}
	for _, p := range past {
		if p.Value == 99 {
			t.Fatal("a past bound returned the future-stamped sample")
		}
	}
}

// TestTierSelectionByWidthAndAge is the rule bounded historical reads depend on:
// the finest tier that suits the window's width AND is still retained at the
// window's start.
//
// Width alone is a trap once an upper bound exists. A one-hour window three days
// old is narrow enough for raw samples and older than the two days raw is kept,
// so a width-only answer reads an already-pruned table and returns nothing —
// while the minute rollups covering that same hour sit right there.
func TestTierSelectionByWidthAndAge(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	start, end := seedHistoricalRun(t, db, s, 3*24*time.Hour)

	base := Query{AgentID: "agent_a", Kind: string(telemetry.ICMPRTTms), MonitorID: "probe_m1", SinceUnix: start}

	// Unbounded: three days of width, answered hourly — one bucket for the lot.
	coarse, err := s.Query(ctx, base)
	if err != nil {
		t.Fatalf("unbounded Query: %v", err)
	}
	if len(coarse) != 1 {
		t.Fatalf("unbounded query = %d points, want the single hourly bucket", len(coarse))
	}

	// Bounded to the ten minutes recorded: narrow enough for raw, but three days
	// past raw retention, so the minute tier answers — ten buckets, the first
	// carrying the spike as an average (59×4 + 64)/60 = 5.0.
	q := base
	q.UntilUnix = end
	fine, err := s.Query(ctx, q)
	if err != nil {
		t.Fatalf("bounded Query: %v", err)
	}
	if len(fine) != 10 {
		t.Fatalf("bounded query = %d points, want 10 minute buckets", len(fine))
	}
	if fine[0].Value != 5.0 || fine[1].Value != 4.0 {
		t.Fatalf("bucket values = %v/%v, want the minute tier's 5.0/4.0", fine[0].Value, fine[1].Value)
	}

	// Retention disabled everywhere means nothing has been pruned, so width alone
	// decides again and the same window reads raw — spike intact.
	s.SetRetention(RetentionConfig{})
	raw, err := s.Query(ctx, q)
	if err != nil {
		t.Fatalf("no-retention Query: %v", err)
	}
	if len(raw) != 600 {
		t.Fatalf("no-retention query = %d points, want 600 raw samples", len(raw))
	}
	sawSpike := false
	for _, p := range raw {
		if p.Value == 64 {
			sawSpike = true
		}
	}
	if !sawSpike {
		t.Fatal("no-retention query lost the spike; it did not read the raw tier")
	}

	// A minute tier that no longer reaches back this far pushes the same window one
	// rung further down, to the hourly bucket.
	s.SetRetention(RetentionConfig{RawSeconds: 2 * 86400, M1Seconds: 86400, H1Seconds: 2 * 365 * 86400})
	hourly, err := s.Query(ctx, q)
	if err != nil {
		t.Fatalf("short-1m-retention Query: %v", err)
	}
	if len(hourly) != 1 {
		t.Fatalf("short 1m retention = %d points, want the hourly bucket", len(hourly))
	}

	// A RECENT window of the same width is unaffected: age is what disqualified the
	// raw tier, not width.
	s.SetRetention(DefaultRetention())
	recentStart := time.Now().Unix() - 300
	ingestBatch(t, db, s, "agent_a", []telemetry.Metric{{
		TS: time.Unix(recentStart+10, 0), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1",
		Value: 7, Unit: "ms", MonitorID: "probe_m1",
	}})
	q = base
	q.SinceUnix = recentStart
	q.UntilUnix = time.Now().Unix()
	recent, err := s.Query(ctx, q)
	if err != nil {
		t.Fatalf("recent Query: %v", err)
	}
	if len(recent) != 1 || recent[0].Value != 7 {
		t.Fatalf("recent window = %+v, want the raw sample", recent)
	}
}

// TestPickTierForLadder pins the selection rule directly, including the ends of
// the ladder that are awkward to reach through stored data.
func TestPickTierForLadder(t *testing.T) {
	now := time.Now().Unix()
	def := DefaultRetention()
	hour := int64(3600)

	cases := []struct {
		name  string
		width int64
		start int64
		ret   RetentionConfig
		want  string
	}{
		{"narrow and recent reads raw", hour, now - 2*hour, def, "samples"},
		{"narrow but past raw retention falls to 1m", hour, now - 3*86400, def, "rollup_1m"},
		{"narrow but past 1m retention falls to 1h", hour, now - 60*86400, def, "rollup_1h"},
		{"narrow but past 1h retention falls to 1d", hour, now - 3*365*86400, def, "rollup_1d"},
		{"retention disabled keeps the width answer", hour, now - 3*365*86400, RetentionConfig{}, "samples"},
		{"width still coarsens a recent range", 30 * 86400, now - 30*86400, def, "rollup_1h"},
		// The margin makes a range starting just inside the raw window read one tier
		// coarser, so a chart does not flap as the cutoff creeps past it.
		{"just inside raw retention is not trusted", hour, now - def.RawSeconds + 60, def, "rollup_1m"},
		{"comfortably inside raw retention is", hour, now - def.RawSeconds + 4*hour, def, "samples"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, raw := pickTierFor(c.width, c.start, now, c.ret)
			if got != c.want {
				t.Fatalf("pickTierFor = %q, want %q", got, c.want)
			}
			if raw != (got == "samples") {
				t.Fatalf("raw flag = %v for table %q", raw, got)
			}
		})
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
		if err := s.RewindForBatch(ctx, tx, "agent_bench", ids, ms); err != nil {
			b.Fatal(err)
		}
		pendingDone := s.BeginPendingAppend(ids)
		if err := tx.Commit(); err != nil {
			b.Fatal(err)
		}
		if _, err := s.AppendRawSamples(ctx, "agent_bench", ids, ms); err != nil {
			b.Fatal(err)
		}
		pendingDone()
		s.UpdateLatest("agent_bench", ids, ms)
	}
}

func TestAvailabilityForSiteWithAgents(t *testing.T) {
	db, s := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(ts time.Time, monitor string, value float64) telemetry.Metric {
		return telemetry.Metric{
			TS: ts, Kind: telemetry.MetricKind(RoundOKKind), Target: monitor,
			MonitorID: monitor, Value: value, Unit: telemetry.UnitBool,
		}
	}
	ingestBatch(t, db, s, "agent-a", []telemetry.Metric{
		mk(now.Add(-4*time.Second), "target-1", 1),
		mk(now.Add(-3*time.Second), "target-1", 0),
	})
	ingestBatch(t, db, s, "agent-b", []telemetry.Metric{
		mk(now.Add(-2*time.Second), "target-1", 1),
		mk(now.Add(-time.Second), "target-1", 1),
	})

	totals, agents, err := s.AvailabilityForSiteWithAgents(ctx, "site_default", now.Add(-time.Minute).Unix(), now.Add(time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if got := totals["target-1"]; got.Rounds != 4 || got.OKRounds != 3 || got.Ratio != 0.75 {
		t.Fatalf("target total = %+v, want 3/4 (0.75)", got)
	}
	if got := agents["target-1"]["agent-a"]; got.Rounds != 2 || got.OKRounds != 1 || got.Ratio != 0.5 {
		t.Fatalf("agent-a = %+v, want 1/2 (0.5)", got)
	}
	if got := agents["target-1"]["agent-b"]; got.Rounds != 2 || got.OKRounds != 2 || got.Ratio != 1 {
		t.Fatalf("agent-b = %+v, want 2/2 (1)", got)
	}
}
