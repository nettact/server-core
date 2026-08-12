package gamedata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// openGameDB seeds a site and one agent holding every game permission, which is
// the ordinary case; the denial tests seed agents with narrower sets.
func openGameDB(t *testing.T) (*store.DB, *Service) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	seedAgent(t, db, "agent_game", `["game.process.detect","game.performance.read","game.gpu.read"]`)
	return db, New(db, settings.New(db))
}

func seedAgent(t *testing.T, db *store.DB, id, effective string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO agents(id,site_id,public_key,token_hash,status,perm_effective)
		 VALUES(?,'site_default',x'00','h','online',?)`, id, effective); err != nil {
		t.Fatalf("seed agent %s: %v", id, err)
	}
}

// apply runs one payload through the ingest write path in its own transaction,
// the way a packet does. Most tests carry no gaps and no machine seconds, so
// they go through this rather than restating two empty slices apiece.
func apply(t *testing.T, db *store.DB, agentID string, runs []gamesense.Run, buckets []gamesense.Bucket) Result {
	t.Helper()
	return applyAll(t, db, agentID, runs, buckets, nil, nil)
}

func applyAll(t *testing.T, db *store.DB, agentID string, runs []gamesense.Run, buckets []gamesense.Bucket, gaps []gamesense.Gap, hosts []gamesense.HostSecond) Result {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	res, err := Apply(ctx, store.AdaptTx(tx, store.Standalone()), agentID, "site_default", runs, buckets, gaps, hosts)
	if err != nil {
		tx.Rollback()
		t.Fatalf("apply: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return res
}

func intp(v int) *int       { return &v }
func boolp(v bool) *bool    { return &v }
func u64p(v uint64) *uint64 { return &v }

// hist builds a log24_v1 histogram from (frame time, count) pairs.
func hist(pairs ...[2]float64) gamesense.Histogram {
	counts := make([]uint32, gamesense.HistBins)
	for _, p := range pairs {
		bin, _ := gamesense.HistBucket(p[0])
		counts[bin] += uint32(p[1])
	}
	return gamesense.Histogram{Layout: gamesense.HistLayoutLog24V1, Counts: counts}
}

func run(id string, started time.Time, seconds int) gamesense.Run {
	return gamesense.Run{
		ID: id, Proc: "game.exe", Title: "A Game",
		StartedAt:  started,
		LastSeenAt: started.Add(time.Duration(seconds) * time.Second),
		Source:     gamesense.SourcePresentMonService,
		Caps:       []string{gamesense.CapDisplayed, gamesense.CapPresentMeta},
	}
}

func bucket(runID string, ts time.Time, presented int, h gamesense.Histogram) gamesense.Bucket {
	return gamesense.Bucket{
		RunID: runID, TS: ts,
		Sample: gamesense.Sample{
			Frames: gamesense.Frames{Presented: presented},
			FT:     gamesense.FrameTimes{Avg: 5.77, P50: 5.7, P95: 6.1, P99: 6.4, Max: 7, SD: 0.3},
			Hist:   h,
		},
	}
}

// TestApplyIsIdempotent pins the property an at-least-once uploader depends on:
// re-sending the same seconds must not duplicate them, and re-sending a run must
// update it in place rather than fork it.
func TestApplyIsIdempotent(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	h := hist([2]float64{5, 100})
	runs := []gamesense.Run{run("run_1", start, 2)}
	buckets := []gamesense.Bucket{
		bucket("run_1", start, 100, h),
		bucket("run_1", start.Add(time.Second), 100, h),
	}

	first := apply(t, db, "agent_game", runs, buckets)
	if first.Runs != 1 || first.Buckets != 2 || first.Rejected != 0 {
		t.Fatalf("first apply = %+v, want 1 run / 2 buckets", first)
	}
	stored, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}

	second := apply(t, db, "agent_game", runs, buckets)
	if second.Runs != 1 || second.Buckets != 0 {
		t.Fatalf("replay = %+v, want the run upserted and no new buckets", second)
	}

	// The run's totals are the part a replay can corrupt without a trace. They are
	// accumulated as seconds land rather than recomputed, and the seconds are
	// deleted long before the run is, so a second folded in twice is wrong forever
	// with nothing left to check it against.
	replayed, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun after replay: %v", err)
	}
	if !reflect.DeepEqual(stored.Summary, replayed.Summary) {
		t.Fatalf("summary after replay = %+v, want %+v", replayed.Summary, stored.Summary)
	}
	if replayed.Summary.Presented != 200 {
		t.Fatalf("presented = %d after a replay, want the 200 frames actually recorded",
			replayed.Summary.Presented)
	}
	// Checked as a frame count rather than through the FPS figures, which are means
	// and come out identical whether or not every bin was doubled.
	var blob []byte
	if err := db.QueryRowContext(ctx, `SELECT hist FROM game_runs WHERE id='run_1'`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if total := gamesense.HistTotal(decodeHist(blob)); total != 200 {
		t.Fatalf("the run's merged histogram counts %d frames after a replay, want 200", total)
	}

	var runRows, bucketRows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_runs`).Scan(&runRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_buckets`).Scan(&bucketRows); err != nil {
		t.Fatal(err)
	}
	if runRows != 1 || bucketRows != 2 {
		t.Fatalf("rows after replay: runs=%d buckets=%d, want 1 and 2", runRows, bucketRows)
	}

	got, err := svc.ListBuckets(ctx, "run_1", BucketFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("ListBuckets = %d buckets err=%v, want 2", len(got), err)
	}
}

// TestNullMeansNotMeasured is the load-bearing test of this package. A source
// that cannot see dropped frames and a game that dropped none produce the same
// zero if the storage conflates them, and every chart downstream then reports a
// blind spot as a flawless result.
func TestNullMeansNotMeasured(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})

	blind := bucket("run_1", start, 100, h) // a source that sees nothing but presents

	measured := bucket("run_1", start.Add(time.Second), 100, h)
	measured.Frames.Displayed = intp(100)
	measured.Frames.Dropped = intp(0) // really zero: this second dropped nothing
	measured.Frames.App = intp(50)
	measured.Frames.Generated = intp(50)
	measured.DispFT = &gamesense.DispFT{Avg: 5.8, P95: 6.2}
	measured.Present = &gamesense.Present{
		Mode:    gamesense.PresentModeHardwareIndependentFlip,
		Sync:    intp(0),      // vsync off, not "unknown"
		Tearing: boolp(false), // observed absent, not "unknown"
		API:     gamesense.APIDXGI,
	}
	measured.Quality = []string{gamesense.QualityHistClipped}

	apply(t, db, "agent_game", []gamesense.Run{run("run_1", start, 2)},
		[]gamesense.Bucket{blind, measured})

	got, err := svc.ListBuckets(ctx, "run_1", BucketFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("ListBuckets = %d err=%v", len(got), err)
	}

	b := got[0]
	if b.Frames.Displayed != nil || b.Frames.Dropped != nil || b.Frames.App != nil || b.Frames.Generated != nil {
		t.Fatalf("unmeasured counts came back as values: %+v", b.Frames)
	}
	if b.DispFT != nil {
		t.Fatalf("unmeasured displayed intervals came back as %+v", b.DispFT)
	}
	if b.Present != nil {
		t.Fatalf("absent presentation metadata came back as %+v", b.Present)
	}
	if b.Quality != nil {
		t.Fatalf("absent quality flags came back as %+v", b.Quality)
	}

	m := got[1]
	if m.Frames.Dropped == nil || *m.Frames.Dropped != 0 {
		t.Fatalf("a measured zero must survive as a pointer to 0, got %v", m.Frames.Dropped)
	}
	if m.Frames.Displayed == nil || *m.Frames.Displayed != 100 {
		t.Fatalf("displayed = %v, want 100", m.Frames.Displayed)
	}
	if m.Present == nil || m.Present.Sync == nil || *m.Present.Sync != 0 {
		t.Fatalf("sync interval 0 (vsync off) must survive, got %+v", m.Present)
	}
	if m.Present.Tearing == nil || *m.Present.Tearing {
		t.Fatalf("tearing=false must survive as an observation, got %v", m.Present.Tearing)
	}
	if m.Present.Mode != gamesense.PresentModeHardwareIndependentFlip || m.Present.API != gamesense.APIDXGI {
		t.Fatalf("present metadata = %+v", m.Present)
	}
	if m.DispFT == nil || m.DispFT.P95 != 6.2 {
		t.Fatalf("disp_ft = %+v", m.DispFT)
	}
	if len(m.Quality) != 1 || m.Quality[0] != gamesense.QualityHistClipped {
		t.Fatalf("quality = %+v", m.Quality)
	}

	// A run in which no second could see drops must not report a zero total either.
	page, err := svc.ListRuns(ctx, RunFilter{AgentID: "agent_game"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("ListRuns = %+v err=%v", page, err)
	}
	if page.Items[0].Summary.Dropped == nil || *page.Items[0].Summary.Dropped != 0 {
		t.Fatalf("dropped total = %v, want the one measured second's 0", page.Items[0].Summary.Dropped)
	}

	apply(t, db, "agent_game", []gamesense.Run{run("run_blind", start, 1)},
		[]gamesense.Bucket{bucket("run_blind", start, 100, h)})
	blindRun, err := svc.GetRun(ctx, "run_blind")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if blindRun.Summary.Dropped != nil || blindRun.Summary.Displayed != nil {
		t.Fatalf("a run nothing could measure reported totals: %+v", blindRun.Summary)
	}
	if blindRun.Summary.Presented != 100 {
		t.Fatalf("presented total = %d, want 100", blindRun.Summary.Presented)
	}

	// The run's own columns must draw the same distinction, because they are what
	// outlives the buckets: once retention has taken the seconds, a zero written
	// here is indistinguishable from a measurement and there is nothing left to
	// correct it from.
	var displayed, dropped sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT displayed, dropped FROM game_runs WHERE id='run_blind'`).Scan(&displayed, &dropped); err != nil {
		t.Fatal(err)
	}
	if displayed.Valid || dropped.Valid {
		t.Fatalf("a run nothing could measure stored displayed=%v dropped=%v, want NULL", displayed, dropped)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT displayed, dropped FROM game_runs WHERE id='run_1'`).Scan(&displayed, &dropped); err != nil {
		t.Fatal(err)
	}
	if !displayed.Valid || displayed.Int64 != 100 {
		t.Fatalf("displayed total = %v, want the one measured second's 100", displayed)
	}
	if !dropped.Valid || dropped.Int64 != 0 {
		t.Fatalf("dropped total = %v, want a measured 0 rather than NULL", dropped)
	}
}

// TestBucketStutterAndProcRes covers the two blocks a second can carry beyond its
// frame statistics. Both are optional in a way a plain column cannot express: a
// second that was watched and held no hitch is a real zero, and a process whose
// CPU could not be sampled yet may still have reported its memory.
func TestBucketStutterAndProcRes(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})

	both := bucket("run_1", start, 100, h)
	both.Stutter = &gamesense.Stutter{Count: 2, ExcessMs: 118.4}
	both.ProcRes = &gamesense.ProcRes{
		CPUPct: floatPtr(14.5), WSBytes: u64p(3 << 30), PrivBytes: u64p(4 << 30),
	}

	// Watched, and nothing hitched — the observation a smooth run is made of.
	quiet := bucket("run_1", start.Add(time.Second), 100, h)
	quiet.Stutter = &gamesense.Stutter{}

	// The first observed second of a run has no CPU delta yet; memory is a level
	// and is readable at once. The reverse happens when the memory query fails.
	cpuOnly := bucket("run_1", start.Add(2*time.Second), 100, h)
	cpuOnly.ProcRes = &gamesense.ProcRes{CPUPct: floatPtr(0)} // an idle 0, not "unknown"
	memOnly := bucket("run_1", start.Add(3*time.Second), 100, h)
	memOnly.ProcRes = &gamesense.ProcRes{WSBytes: u64p(2 << 30)}

	bare := bucket("run_1", start.Add(4*time.Second), 100, h) // neither block

	apply(t, db, "agent_game", []gamesense.Run{run("run_1", start, 4)},
		[]gamesense.Bucket{both, quiet, cpuOnly, memOnly, bare})

	got, err := svc.ListBuckets(ctx, "run_1", BucketFilter{})
	if err != nil || len(got) != 5 {
		t.Fatalf("ListBuckets = %d err=%v, want 5", len(got), err)
	}

	if got[0].Stutter == nil || *got[0].Stutter != *both.Stutter {
		t.Fatalf("stutter = %+v, want %+v", got[0].Stutter, both.Stutter)
	}
	p := got[0].ProcRes
	if p == nil || p.CPUPct == nil || *p.CPUPct != 14.5 ||
		p.WSBytes == nil || *p.WSBytes != 3<<30 || p.PrivBytes == nil || *p.PrivBytes != 4<<30 {
		t.Fatalf("proc_res = %+v, want all three readings back", p)
	}

	if got[1].Stutter == nil || *got[1].Stutter != (gamesense.Stutter{}) {
		t.Fatalf("a watched second with no hitch came back as %+v, want a zeroed block",
			got[1].Stutter)
	}
	if got[1].ProcRes != nil {
		t.Fatalf("an unsampled process acquired a resource block: %+v", got[1].ProcRes)
	}

	// Half a block must stay half a block. Filling the missing reading in with a 0
	// would report a game using no CPU or no memory at all.
	if p = got[2].ProcRes; p == nil || p.CPUPct == nil || *p.CPUPct != 0 {
		t.Fatalf("cpu-only proc_res = %+v, want a measured 0%%", p)
	}
	if p.WSBytes != nil || p.PrivBytes != nil {
		t.Fatalf("cpu-only proc_res invented memory readings: %+v", p)
	}
	if got[2].Stutter != nil {
		t.Fatalf("an unwatched second acquired a stutter block: %+v", got[2].Stutter)
	}
	if p = got[3].ProcRes; p == nil || p.WSBytes == nil || *p.WSBytes != 2<<30 {
		t.Fatalf("mem-only proc_res = %+v", p)
	}
	if p.CPUPct != nil || p.PrivBytes != nil {
		t.Fatalf("mem-only proc_res invented readings: %+v", p)
	}

	if got[4].Stutter != nil || got[4].ProcRes != nil {
		t.Fatalf("a second carrying neither block came back with %+v / %+v",
			got[4].Stutter, got[4].ProcRes)
	}

	// The columns must draw the same distinction the structs do, since they are
	// what a later reader actually sees.
	var count sql.NullInt64
	var excess sql.NullFloat64
	if err := db.QueryRowContext(ctx,
		`SELECT stutter_count, stutter_excess_ms FROM game_buckets WHERE run_id='run_1' AND ts=?`,
		quiet.TS.Unix()).Scan(&count, &excess); err != nil {
		t.Fatal(err)
	}
	if !count.Valid || count.Int64 != 0 || !excess.Valid || excess.Float64 != 0 {
		t.Fatalf("a watched, hitch-free second stored count=%v excess=%v, want a measured 0/0",
			count, excess)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT stutter_count, stutter_excess_ms FROM game_buckets WHERE run_id='run_1' AND ts=?`,
		bare.TS.Unix()).Scan(&count, &excess); err != nil {
		t.Fatal(err)
	}
	if count.Valid || excess.Valid {
		t.Fatalf("an unwatched second stored count=%v excess=%v, want NULL", count, excess)
	}
	var ws, priv sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT proc_ws_bytes, proc_priv_bytes FROM game_buckets WHERE run_id='run_1' AND ts=?`,
		cpuOnly.TS.Unix()).Scan(&ws, &priv); err != nil {
		t.Fatal(err)
	}
	if ws.Valid || priv.Valid {
		t.Fatalf("a cpu-only sample stored ws=%v priv=%v, want NULL", ws, priv)
	}
}

// diagSample fills a bucket with one of everything a diag-tier second carries, so
// the tests below can take it apart rather than each rebuilding it.
func diagSample(b *gamesense.Bucket) {
	b.CPUSplit = &gamesense.CPUSplit{BusyAvg: 4.1, BusyP95: 5.9, WaitAvg: 2.8, WaitP95: 3.4}
	b.GPUSplit = &gamesense.GPUSplit{
		LatencyAvg: 1.2, TimeAvg: 6.1, TimeP95: 7.7,
		BusyAvg: 5.8, BusyP95: 7.2, WaitAvg: 0.3,
		InPresentAvg: 0.9, RenderLatencyAvg: 5.2,
	}
	b.Latency = &gamesense.Latency{DisplayAvg: 12.5, AnimErrAvg: 0.8, AnimErrP95: 2.1}
	b.ProcVRAM = &gamesense.ProcVRAM{Used: 5 << 30, Budget: u64p(7 << 30)}
}

// TestBucketDiagBlocksRoundTrip covers the deeper breakdowns a diag-tier profile
// buys. They come in two kinds and the storage has to keep them apart: the
// frame-derived groups are written whole, so a block of measured zeros — the
// second that waited on nothing, which is precisely the "not GPU-bound" verdict —
// must survive as a block; the polled adapter readings are independent, because a
// driver publishing utilization and no memory is an ordinary card and not a
// failed read.
func TestBucketDiagBlocksRoundTrip(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})

	full := bucket("run_1", start, 100, h)
	diagSample(&full)

	// A second in which nothing waited on anything. Every figure is a measured 0,
	// and dropping the blocks over it would erase the finding.
	zeroed := bucket("run_1", start.Add(time.Second), 100, h)
	zeroed.CPUSplit = &gamesense.CPUSplit{}
	zeroed.GPUSplit = &gamesense.GPUSplit{}
	zeroed.Latency = &gamesense.Latency{}

	// An OS that publishes no per-process budget. The level is still the reading.
	noBudget := bucket("run_1", start.Add(4*time.Second), 100, h)
	noBudget.ProcVRAM = &gamesense.ProcVRAM{Used: 1 << 30}

	// A diag second whose polled sources fell over: the flag rides the existing
	// quality array, and the blocks are simply absent.
	degraded := bucket("run_1", start.Add(5*time.Second), 100, h)
	degraded.CPUSplit = &gamesense.CPUSplit{BusyAvg: 3, BusyP95: 4, WaitAvg: 1, WaitP95: 2}
	degraded.Quality = []string{gamesense.QualityDiagDegraded}

	bare := bucket("run_1", start.Add(6*time.Second), 100, h) // a base-tier second

	apply(t, db, "agent_game", []gamesense.Run{run("run_1", start, 6)},
		[]gamesense.Bucket{full, zeroed, noBudget, degraded, bare})

	got, err := svc.ListBuckets(ctx, "run_1", BucketFilter{})
	if err != nil || len(got) != 5 {
		t.Fatalf("ListBuckets = %d err=%v, want 5", len(got), err)
	}

	// Everything present comes back byte for byte. The group-atomic blocks are
	// compared by value: a field silently dropped or reordered in the column list
	// would otherwise pass every spot check.
	g := got[0]
	if g.CPUSplit == nil || *g.CPUSplit != *full.CPUSplit {
		t.Fatalf("cpu_split = %+v, want %+v", g.CPUSplit, full.CPUSplit)
	}
	if g.GPUSplit == nil || *g.GPUSplit != *full.GPUSplit {
		t.Fatalf("gpu_split = %+v, want %+v", g.GPUSplit, full.GPUSplit)
	}
	if g.Latency == nil || *g.Latency != *full.Latency {
		t.Fatalf("lat = %+v, want %+v", g.Latency, full.Latency)
	}
	if g.ProcVRAM == nil || g.ProcVRAM.Used != 5<<30 ||
		g.ProcVRAM.Budget == nil || *g.ProcVRAM.Budget != 7<<30 {
		t.Fatalf("proc_vram = %+v", g.ProcVRAM)
	}

	z := got[1]
	if z.CPUSplit == nil || *z.CPUSplit != (gamesense.CPUSplit{}) {
		t.Fatalf("a measured all-zero cpu split came back as %+v, want a zeroed block", z.CPUSplit)
	}
	if z.GPUSplit == nil || *z.GPUSplit != (gamesense.GPUSplit{}) {
		t.Fatalf("a measured all-zero gpu split came back as %+v", z.GPUSplit)
	}
	if z.Latency == nil || *z.Latency != (gamesense.Latency{}) {
		t.Fatalf("a measured all-zero latency block came back as %+v", z.Latency)
	}
	if z.ProcVRAM != nil {
		t.Fatalf("an unpolled second acquired %+v", z.ProcVRAM)
	}

	v := got[2].ProcVRAM
	if v == nil || v.Used != 1<<30 {
		t.Fatalf("budget-less proc_vram = %+v, want the level kept", v)
	}
	if v.Budget != nil {
		t.Fatalf("proc_vram invented a budget: %v", *v.Budget)
	}

	d := got[3]
	if d.CPUSplit == nil || d.ProcVRAM != nil {
		t.Fatalf("degraded second = cpu:%+v vram:%+v, want only the frame-derived block",
			d.CPUSplit, d.ProcVRAM)
	}
	if len(d.Quality) != 1 || d.Quality[0] != gamesense.QualityDiagDegraded {
		t.Fatalf("quality = %+v, want the degradation flag on the existing array", d.Quality)
	}

	b := got[4]
	if b.CPUSplit != nil || b.GPUSplit != nil || b.Latency != nil || b.ProcVRAM != nil {
		t.Fatalf("a base-tier second came back carrying diag blocks: %+v", b)
	}

	// And the columns must say the same, since they are what a later reader sees:
	// a base-tier second leaves every diag column NULL rather than storing the
	// zeros its struct fields hold.
	var (
		cpuBusy, gpuLatency, latDisplay sql.NullFloat64
		vramUsed                        sql.NullInt64
	)
	scanDiag := func(ts time.Time) {
		t.Helper()
		if err := db.QueryRowContext(ctx, `
			SELECT cpu_busy_avg, gpu_latency_avg, lat_display_avg, proc_vram_used
			  FROM game_buckets WHERE run_id='run_1' AND ts=?`, ts.Unix()).
			Scan(&cpuBusy, &gpuLatency, &latDisplay, &vramUsed); err != nil {
			t.Fatal(err)
		}
	}
	scanDiag(bare.TS)
	if cpuBusy.Valid || gpuLatency.Valid || latDisplay.Valid || vramUsed.Valid {
		t.Fatalf("a base-tier second stored diag values instead of NULL: %v %v %v %v",
			cpuBusy, gpuLatency, latDisplay, vramUsed)
	}
	scanDiag(zeroed.TS)
	if !cpuBusy.Valid || cpuBusy.Float64 != 0 || !gpuLatency.Valid || !latDisplay.Valid {
		t.Fatalf("a measured-zero second stored %v / %v / %v, want real 0s",
			cpuBusy, gpuLatency, latDisplay)
	}
	if vramUsed.Valid {
		t.Fatalf("an unpolled second stored a vram reading: %v", vramUsed)
	}
	scanDiag(noBudget.TS)
	var budget sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT proc_vram_budget FROM game_buckets WHERE run_id='run_1' AND ts=?`,
		noBudget.TS.Unix()).Scan(&budget); err != nil {
		t.Fatal(err)
	}
	if !vramUsed.Valid || budget.Valid {
		t.Fatalf("budget-less vram stored used=%v budget=%v, want a level and a NULL budget",
			vramUsed, budget)
	}
}

// hostSecond builds one machine second with every block filled.
func hostSecond(ts time.Time) gamesense.HostSecond {
	return gamesense.HostSecond{
		TS: ts,
		HostSample: gamesense.HostSample{
			CPU:      &gamesense.HostCPU{TotalPct: 41.5, BusiestPct: 99.25},
			CPUClock: &gamesense.HostCPUClock{CurrentMHz: 4900, MaxMHz: 3600},
			Mem:      &gamesense.HostMem{Used: 12 << 30, Total: 32 << 30},
			GPU: &gamesense.GPUTel{
				UtilPct: floatPtr(87.5), MemUsed: u64p(6 << 30), MemSize: u64p(8 << 30),
				CoreMHz: floatPtr(2610.5), MemMHz: floatPtr(1313.3),
			},
		},
	}
}

// TestGPUTelemetryNeedsItsOwnPermission is the second half of the ingest gate.
// game.performance.read buys the game's own frame stream; the adapter's
// utilization and its video memory describe the card and every process sharing
// it, which is a different read an operator can withhold on its own. A WAL that
// drained after that narrowing must not smuggle it in — and must not take the
// frame-derived breakdowns, or the machine's CPU and memory, down with it. None
// of those is the graphics device.
func TestGPUTelemetryNeedsItsOwnPermission(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	seedAgent(t, db, "agent_nogpu", `["game.process.detect","game.performance.read"]`)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})

	gated := bucket("run_nogpu", start, 100, h)
	diagSample(&gated)
	res := applyAll(t, db, "agent_nogpu", []gamesense.Run{run("run_nogpu", start, 0)},
		[]gamesense.Bucket{gated}, nil, []gamesense.HostSecond{hostSecond(start)})
	// The records themselves are permitted: only the withheld part goes missing,
	// and both are stored rather than refused.
	if res.Denied || res.Buckets != 1 || res.HostSeconds != 1 || res.Rejected != 0 {
		t.Fatalf("apply = %+v, want both stored with their GPU readings dropped", res)
	}

	allowed := bucket("run_gpu", start, 100, h)
	diagSample(&allowed)
	applyAll(t, db, "agent_game", []gamesense.Run{run("run_gpu", start, 0)},
		[]gamesense.Bucket{allowed}, nil, []gamesense.HostSecond{hostSecond(start)})

	stripped, err := svc.ListBuckets(ctx, "run_nogpu", BucketFilter{})
	if err != nil || len(stripped) != 1 {
		t.Fatalf("ListBuckets run_nogpu = %d err=%v", len(stripped), err)
	}
	s := stripped[0]
	if s.ProcVRAM != nil {
		t.Fatalf("proc_vram=%+v landed for an agent without game.gpu.read", s.ProcVRAM)
	}
	// Everything derived from the frame stream rides the permission the agent does
	// hold, including the GPU-side frame breakdown — it comes from the game's own
	// presentation, not from the adapter.
	if s.CPUSplit == nil || *s.CPUSplit != *gated.CPUSplit {
		t.Fatalf("cpu_split = %+v, want the frame-derived block kept", s.CPUSplit)
	}
	if s.GPUSplit == nil || *s.GPUSplit != *gated.GPUSplit {
		t.Fatalf("gpu_split = %+v, want the frame-derived block kept", s.GPUSplit)
	}
	if s.Latency == nil || *s.Latency != *gated.Latency {
		t.Fatalf("lat = %+v, want the frame-derived block kept", s.Latency)
	}

	// The machine second loses its adapter block and keeps the rest. This is the
	// part most easily broken by "strip the GPU stuff": the processor and the RAM
	// are not the graphics device, and withholding them would remove the readings
	// that explain a stutter for a reason that has nothing to do with them.
	host, err := svc.ListHostSeconds(ctx, "agent_nogpu", HostFilter{SiteID: "site_default"})
	if err != nil || len(host) != 1 {
		t.Fatalf("ListHostSeconds agent_nogpu = %d err=%v", len(host), err)
	}
	if host[0].GPU != nil {
		t.Fatalf("adapter telemetry = %+v for an agent without game.gpu.read", host[0].GPU)
	}
	if host[0].CPU == nil || host[0].CPU.BusiestPct != 99.25 {
		t.Fatalf("machine cpu = %+v, want it kept", host[0].CPU)
	}
	if host[0].Mem == nil || host[0].Mem.Total != 32<<30 {
		t.Fatalf("machine memory = %+v, want it kept", host[0].Mem)
	}

	// The columns, not just the structs: this is what a later reader sees.
	var vramUsed, vramBudget sql.NullInt64
	if err := db.QueryRowContext(ctx, `
		SELECT proc_vram_used, proc_vram_budget FROM game_buckets WHERE run_id='run_nogpu'`).
		Scan(&vramUsed, &vramBudget); err != nil {
		t.Fatal(err)
	}
	if vramUsed.Valid || vramBudget.Valid {
		t.Fatalf("gated vram columns stored %v %v, want NULL", vramUsed, vramBudget)
	}
	var util sql.NullFloat64
	var memUsed, cpuTotal sql.NullFloat64
	if err := db.QueryRowContext(ctx, `
		SELECT gpu_util_pct, cpu_total_pct, mem_used FROM game_host_seconds WHERE agent_id='agent_nogpu'`).
		Scan(&util, &cpuTotal, &memUsed); err != nil {
		t.Fatal(err)
	}
	if util.Valid {
		t.Fatalf("gated adapter column stored %v, want NULL", util)
	}
	if !cpuTotal.Valid || !memUsed.Valid {
		t.Fatalf("the machine's own readings were stripped with the adapter's: cpu=%v mem=%v", cpuTotal, memUsed)
	}

	// The agent holding both keeps everything, which is what makes the difference
	// above a policy decision rather than a lost write path.
	kept, err := svc.ListBuckets(ctx, "run_gpu", BucketFilter{})
	if err != nil || len(kept) != 1 {
		t.Fatalf("ListBuckets run_gpu = %d err=%v", len(kept), err)
	}
	if k := kept[0]; k.ProcVRAM == nil || k.ProcVRAM.Used != 5<<30 {
		t.Fatalf("proc_vram = %+v for an agent holding game.gpu.read", k.ProcVRAM)
	}
	keptHost, err := svc.ListHostSeconds(ctx, "agent_game", HostFilter{SiteID: "site_default"})
	if err != nil || len(keptHost) != 1 {
		t.Fatalf("ListHostSeconds agent_game = %d err=%v", len(keptHost), err)
	}
	if g := keptHost[0].GPU; g == nil || g.UtilPct == nil || *g.UtilPct != 87.5 {
		t.Fatalf("adapter telemetry = %+v for an agent holding game.gpu.read", g)
	}
}

// A machine second that carried nothing but an adapter block is dropped when the
// permission strips it, rather than stored as an all-NULL row.
//
// An all-NULL row asserts "this second was covered and nothing was readable",
// which a reader has to interpret as evidence of something — a card that stopped
// reporting, most likely. It would be evidence of a setting.
func TestStrippedHostSecondWithNothingLeftIsNotStored(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	seedAgent(t, db, "agent_nogpu", `["game.process.detect","game.performance.read"]`)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	gpuOnly := gamesense.HostSecond{
		TS:         start,
		HostSample: gamesense.HostSample{GPU: &gamesense.GPUTel{UtilPct: floatPtr(80)}},
	}
	// One that also carries a flag survives: the flag is the explanation the empty
	// row was missing.
	flagged := gamesense.HostSecond{
		TS: start.Add(time.Second),
		HostSample: gamesense.HostSample{
			GPU:     &gamesense.GPUTel{UtilPct: floatPtr(80)},
			Quality: []string{gamesense.QualityHostDegraded},
		},
	}

	res := applyAll(t, db, "agent_nogpu", nil, nil, nil,
		[]gamesense.HostSecond{gpuOnly, flagged})
	if res.HostSeconds != 1 {
		t.Fatalf("stored %d machine second(s), want only the one with an explanation", res.HostSeconds)
	}
	got, err := svc.ListHostSeconds(ctx, "agent_nogpu", HostFilter{SiteID: "site_default"})
	if err != nil || len(got) != 1 {
		t.Fatalf("ListHostSeconds = %d err=%v, want 1", len(got), err)
	}
	if !got[0].TS.Equal(flagged.TS) {
		t.Fatalf("kept the second at %s, want the flagged one at %s", got[0].TS, flagged.TS)
	}
	if got[0].GPU != nil {
		t.Fatalf("adapter block survived the strip: %+v", got[0].GPU)
	}
}

// The machine stream is keyed by (agent, second) and belongs to the machine, so
// two runs overlapping a second read the same rows — and deleting one run must
// not blank the other's curves. The surrounding DeleteRun deletes the run's own
// rows one statement at a time, which is exactly what invites adding a fourth.
func TestDeleteRunLeavesTheMachineStreamAlone(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})

	applyAll(t, db, "agent_game",
		[]gamesense.Run{run("run_a", start, 1), run("run_b", start, 1)},
		[]gamesense.Bucket{bucket("run_a", start, 100, h), bucket("run_b", start, 100, h)},
		[]gamesense.Gap{{
			ID: "gap_a", RunID: "run_a", Reason: gamesense.GapBackground,
			StartedAt: start.Add(time.Second), EndedAt: start.Add(5 * time.Second),
		}},
		[]gamesense.HostSecond{hostSecond(start), hostSecond(start.Add(time.Second))})

	if err := svc.DeleteRun(ctx, "run_a"); err != nil {
		t.Fatalf("DeleteRun: %v", err)
	}

	host, err := svc.ListHostSeconds(ctx, "agent_game", HostFilter{SiteID: "site_default"})
	if err != nil || len(host) != 2 {
		t.Fatalf("ListHostSeconds = %d err=%v, want both machine seconds intact", len(host), err)
	}
	// The run's own records do go, gaps included.
	gaps, err := svc.ListGaps(ctx, "run_a")
	if err != nil || len(gaps) != 0 {
		t.Fatalf("ListGaps(run_a) = %d err=%v, want the deleted run's gaps gone", len(gaps), err)
	}
	if _, err := svc.GetRun(ctx, "run_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRun(run_a) err = %v, want ErrNotFound", err)
	}
	if _, err := svc.GetRun(ctx, "run_b"); err != nil {
		t.Fatalf("the surviving run went with it: %v", err)
	}
}

// Gaps are re-sent as they grow, and a retried batch can carry a stale copy. The
// stored end therefore takes max() rather than last-writer-wins: a redelivered
// older copy must not rewind a stretch that has since grown.
func TestGapUpsertKeepsTheLaterEnd(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	short := gamesense.Gap{
		ID: "gap_1", RunID: "run_1", Reason: gamesense.GapBackground,
		StartedAt: start.Add(time.Second), EndedAt: start.Add(10 * time.Second),
	}
	grown := short
	grown.EndedAt = start.Add(90 * time.Second)

	applyAll(t, db, "agent_game", []gamesense.Run{run("run_1", start, 1)}, nil,
		[]gamesense.Gap{short}, nil)
	applyAll(t, db, "agent_game", nil, nil, []gamesense.Gap{grown}, nil)
	// The stale copy arrives last, as a retried batch would.
	applyAll(t, db, "agent_game", nil, nil, []gamesense.Gap{short}, nil)

	got, err := svc.ListGaps(ctx, "run_1")
	if err != nil || len(got) != 1 {
		t.Fatalf("ListGaps = %d err=%v, want one interval", len(got), err)
	}
	if !got[0].EndedAt.Equal(grown.EndedAt) {
		t.Fatalf("gap ends at %s, want %s — a stale redelivery rewound it", got[0].EndedAt, grown.EndedAt)
	}
	if !got[0].StartedAt.Equal(short.StartedAt) {
		t.Fatalf("gap starts at %s, want %s", got[0].StartedAt, short.StartedAt)
	}
	if got[0].Reason != gamesense.GapBackground {
		t.Fatalf("gap reason = %q", got[0].Reason)
	}
}

// A gap can outlive its run: a player who minimizes a game and never comes back
// leaves a stretch of silence after the last frame. Clamping it to the run's end
// would erase the difference between that and quitting, which is the question
// the record answers.
func TestGapMayOutliveItsRun(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})

	r := run("run_1", start, 10)
	ended := start.Add(10 * time.Second)
	r.EndedAt = &ended
	applyAll(t, db, "agent_game", []gamesense.Run{r},
		[]gamesense.Bucket{bucket("run_1", start, 100, h)},
		[]gamesense.Gap{{
			ID: "gap_1", RunID: "run_1", Reason: gamesense.GapBackground,
			StartedAt: start.Add(11 * time.Second), EndedAt: start.Add(time.Hour),
		}}, nil)

	got, err := svc.ListGaps(ctx, "run_1")
	if err != nil || len(got) != 1 {
		t.Fatalf("ListGaps = %d err=%v", len(got), err)
	}
	if !got[0].EndedAt.After(ended) {
		t.Fatalf("gap ends at %s, want it kept past the run's end at %s", got[0].EndedAt, ended)
	}

	// And the run itself is untouched by it: a minimized game is not a game still
	// being played, so the gap must not have advanced last_seen_at or reopened it.
	stored, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.EndedAt == nil || !stored.EndedAt.Equal(ended) {
		t.Fatalf("run ended_at = %v, want %s — the gap rewrote the run", stored.EndedAt, ended)
	}
	if stored.LastSeenAt.After(ended) {
		t.Fatalf("run last_seen_at = %s, want no later than %s — the gap advanced it",
			stored.LastSeenAt, ended)
	}
}

// A gap naming a run this agent does not own is refused, the way a bucket is.
// Ids are minted by agents, so without the check one agent could attach a
// fabricated silence to another's session.
func TestGapForAnUnknownRunIsRejected(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	seedAgent(t, db, "agent_other", `["game.process.detect","game.performance.read","game.gpu.read"]`)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	applyAll(t, db, "agent_game", []gamesense.Run{run("run_1", start, 1)}, nil, nil, nil)
	res := applyAll(t, db, "agent_other", nil, nil, []gamesense.Gap{{
		ID: "gap_x", RunID: "run_1", Reason: gamesense.GapNoFrames,
		StartedAt: start, EndedAt: start.Add(time.Minute),
	}}, nil)
	if res.Gaps != 0 || res.Rejected != 1 {
		t.Fatalf("apply = %+v, want the gap refused", res)
	}
	got, err := svc.ListGaps(ctx, "run_1")
	if err != nil || len(got) != 0 {
		t.Fatalf("ListGaps = %d err=%v, want none", len(got), err)
	}
}

// Machine seconds round-trip with each block's presence intact, are keyed by
// (agent, second) so a replay stores nothing new, and are bounded by the window
// a run detail asks with.
func TestHostSecondsRoundTripAndWindow(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	idle := gamesense.HostSecond{
		TS: start.Add(time.Second),
		HostSample: gamesense.HostSample{
			CPU: &gamesense.HostCPU{},
			Mem: &gamesense.HostMem{Used: 4 << 30, Total: 32 << 30},
		},
	}
	utilOnly := gamesense.HostSecond{
		TS:         start.Add(2 * time.Second),
		HostSample: gamesense.HostSample{GPU: &gamesense.GPUTel{UtilPct: floatPtr(41)}},
	}
	res := applyAll(t, db, "agent_game", nil, nil, nil,
		[]gamesense.HostSecond{hostSecond(start), idle, utilOnly})
	if res.HostSeconds != 3 {
		t.Fatalf("stored %d machine second(s), want 3", res.HostSeconds)
	}
	// A replayed batch stores nothing new, the way a replayed bucket does.
	if again := applyAll(t, db, "agent_game", nil, nil, nil,
		[]gamesense.HostSecond{hostSecond(start), idle, utilOnly}); again.HostSeconds != 0 {
		t.Fatalf("a replay stored %d machine second(s), want 0", again.HostSeconds)
	}

	got, err := svc.ListHostSeconds(ctx, "agent_game", HostFilter{SiteID: "site_default"})
	if err != nil || len(got) != 3 {
		t.Fatalf("ListHostSeconds = %d err=%v, want 3", len(got), err)
	}
	full := got[0]
	if full.CPU == nil || *full.CPU != (gamesense.HostCPU{TotalPct: 41.5, BusiestPct: 99.25}) {
		t.Fatalf("cpu = %+v", full.CPU)
	}
	if full.Mem == nil || *full.Mem != (gamesense.HostMem{Used: 12 << 30, Total: 32 << 30}) {
		t.Fatalf("mem = %+v", full.Mem)
	}
	if full.GPU == nil || full.GPU.MemSize == nil || *full.GPU.MemSize != 8<<30 {
		t.Fatalf("gpu = %+v", full.GPU)
	}
	// The clocks, which throttle independently of everything above them.
	if full.GPU.CoreMHz == nil || *full.GPU.CoreMHz != 2610.5 || full.GPU.MemMHz == nil || *full.GPU.MemMHz != 1313.3 {
		t.Errorf("adapter clocks = %v / %v, want 2610.5 / 1313.3", full.GPU.CoreMHz, full.GPU.MemMHz)
	}
	// A boost clock ABOVE the nominal maximum is ordinary rather than wrong, and
	// must survive as read: clamping it to the maximum would erase the thing a
	// reader is looking for.
	if full.CPUClock == nil || *full.CPUClock != (gamesense.HostCPUClock{CurrentMHz: 4900, MaxMHz: 3600}) {
		t.Errorf("cpu clock = %+v, want the boost kept above the nominal maximum", full.CPUClock)
	}

	// An idle machine is two measured zeros, not an unread one. Dropping the block
	// over it would erase the finding "the box was not the problem".
	if got[1].CPU == nil || *got[1].CPU != (gamesense.HostCPU{}) {
		t.Fatalf("an idle machine came back as %+v, want a zeroed block", got[1].CPU)
	}
	if got[1].GPU != nil {
		t.Fatalf("a second with no adapter reading acquired one: %+v", got[1].GPU)
	}

	// Half a card's telemetry stays half. Filling the rest in with zeros would
	// report a card at no load or with no memory installed.
	u := got[2].GPU
	if u == nil || u.UtilPct == nil || *u.UtilPct != 41 {
		t.Fatalf("util-only telemetry = %+v", u)
	}
	if u.MemUsed != nil || u.MemSize != nil {
		t.Fatalf("util-only telemetry invented memory readings: %+v", u)
	}
	if got[2].CPU != nil || got[2].Mem != nil {
		t.Fatalf("an adapter-only second acquired machine readings: %+v / %+v", got[2].CPU, got[2].Mem)
	}

	// The window a run detail asks with. Until is exclusive, matching ListBuckets.
	win, err := svc.ListHostSeconds(ctx, "agent_game", HostFilter{
		SiteID: "site_default",
		Since:  start.Add(time.Second).Unix(),
		Until:  start.Add(2 * time.Second).Unix(),
	})
	if err != nil || len(win) != 1 || !win[0].TS.Equal(idle.TS) {
		t.Fatalf("windowed ListHostSeconds = %d %v err=%v, want only the second at %s",
			len(win), win, err, idle.TS)
	}

	// Another site sees nothing, even naming the right agent.
	none, err := svc.ListHostSeconds(ctx, "agent_game", HostFilter{SiteID: "site_other"})
	if err != nil || len(none) != 0 {
		t.Fatalf("cross-site ListHostSeconds = %d err=%v, want none", len(none), err)
	}
}

// TestRunStutterTotals pins the whole-run fold. The totals accumulate across
// packets and outlive the seconds behind them, so a replayed second folded twice
// is wrong forever with nothing left to check it against — and a run nothing
// watched must stay NULL rather than claim it never hitched, which is the single
// most misleading zero this package could produce.
func TestRunStutterTotals(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})

	hitched := bucket("run_1", start, 100, h)
	hitched.Stutter = &gamesense.Stutter{Count: 2, ExcessMs: 100}
	unwatched := bucket("run_1", start.Add(time.Second), 100, h) // no block at all
	first := []gamesense.Bucket{hitched, unwatched}

	again := bucket("run_1", start.Add(2*time.Second), 100, h)
	again.Stutter = &gamesense.Stutter{Count: 1, ExcessMs: 60.5}
	smooth := bucket("run_1", start.Add(3*time.Second), 100, h)
	smooth.Stutter = &gamesense.Stutter{} // contributes nothing but the fact it looked
	second := []gamesense.Bucket{again, smooth}

	runs := []gamesense.Run{run("run_1", start, 3)}
	apply(t, db, "agent_game", runs, first)
	apply(t, db, "agent_game", runs, second)

	got, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.StutterCount == nil || *got.StutterCount != 3 {
		t.Fatalf("stutter_count = %v, want the 3 events across both packets", got.StutterCount)
	}
	if got.StutterExcessMs == nil || *got.StutterExcessMs != 160.5 {
		t.Fatalf("stutter_excess_ms = %v, want 160.5", got.StutterExcessMs)
	}

	// The WAL redelivers both packets. Every second is already recorded, so none of
	// them may reach the totals a second time.
	apply(t, db, "agent_game", runs, first)
	apply(t, db, "agent_game", runs, second)
	replayed, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun after replay: %v", err)
	}
	if *replayed.StutterCount != 3 || *replayed.StutterExcessMs != 160.5 {
		t.Fatalf("totals after a replay = %d / %.1f, want 3 / 160.5",
			*replayed.StutterCount, *replayed.StutterExcessMs)
	}

	// A run whose every watched second was smooth reports a measured zero, which is
	// the whole point of watching.
	quiet := bucket("run_quiet", start, 100, h)
	quiet.Stutter = &gamesense.Stutter{}
	apply(t, db, "agent_game", []gamesense.Run{run("run_quiet", start, 0)},
		[]gamesense.Bucket{quiet})
	quietRun, err := svc.GetRun(ctx, "run_quiet")
	if err != nil {
		t.Fatalf("GetRun run_quiet: %v", err)
	}
	if quietRun.StutterCount == nil || *quietRun.StutterCount != 0 {
		t.Fatalf("a watched, hitch-free run = %v, want a measured 0", quietRun.StutterCount)
	}
	if quietRun.StutterExcessMs == nil || *quietRun.StutterExcessMs != 0 {
		t.Fatalf("excess = %v, want a measured 0", quietRun.StutterExcessMs)
	}

	// ...and a run nothing ever watched reports nothing. This is what outlives the
	// buckets: once retention has taken the seconds, a zero written here is
	// indistinguishable from a measurement and nothing is left to correct it from.
	apply(t, db, "agent_game", []gamesense.Run{run("run_blind", start, 0)},
		[]gamesense.Bucket{bucket("run_blind", start, 100, h)})
	blind, err := svc.GetRun(ctx, "run_blind")
	if err != nil {
		t.Fatalf("GetRun run_blind: %v", err)
	}
	if blind.StutterCount != nil || blind.StutterExcessMs != nil {
		t.Fatalf("a run nothing watched reported %v / %v, want both null",
			blind.StutterCount, blind.StutterExcessMs)
	}
	var count sql.NullInt64
	var excess sql.NullFloat64
	if err := db.QueryRowContext(ctx,
		`SELECT stutter_count, stutter_excess_ms FROM game_runs WHERE id='run_blind'`).
		Scan(&count, &excess); err != nil {
		t.Fatal(err)
	}
	if count.Valid || excess.Valid {
		t.Fatalf("a run nothing watched stored count=%v excess=%v, want NULL", count, excess)
	}

	// On the wire the absence has to be an explicit null rather than a missing key:
	// a console that reads the field as undefined and one that reads it as 0 must
	// not be able to disagree about whether the run hitched.
	raw := map[string]any{}
	body, err := json.Marshal(blind)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"stutter_count", "stutter_excess_ms"} {
		v, present := raw[key]
		if !present {
			t.Fatalf("run JSON is missing %q entirely; it must be present as null (%s)", key, body)
		}
		if v != nil {
			t.Fatalf("%s = %v on a run nothing watched, want null", key, v)
		}
	}
}

// TestPermissionDenied covers a policy narrowed while the agent still had the
// data queued: the WAL drains after the revocation, and none of it may land.
func TestPermissionDenied(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	seedAgent(t, db, "agent_nogame", `["host.cpu.read"]`)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	res := apply(t, db, "agent_nogame",
		[]gamesense.Run{run("run_denied", start, 1)},
		[]gamesense.Bucket{bucket("run_denied", start, 100, hist([2]float64{5, 100}))})
	if !res.Denied || res.Runs != 0 || res.Buckets != 0 {
		t.Fatalf("apply without %s = %+v, want everything dropped", permission.GamePerformanceRead, res)
	}
	if _, err := svc.GetRun(ctx, "run_denied"); err != ErrNotFound {
		t.Fatalf("GetRun after denial: %v, want ErrNotFound", err)
	}
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_buckets`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("game_buckets = %d rows after denial", rows)
	}
}

// TestRejectsUnknownLayoutAndPhantomRuns pins the two refusals. An unrecognized
// layout name cannot be stored, because a later reader would apply this build's
// edges to counts that were binned by someone else's; a bucket naming no run
// cannot conjure one, because the invented run would say nothing about what its
// capture could see.
func TestRejectsUnknownLayoutAndPhantomRuns(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	good := hist([2]float64{5, 100})

	future := bucket("run_1", start, 100, good)
	future.Hist.Layout = "log32_v2"

	truncated := bucket("run_1", start.Add(time.Second), 100, good)
	truncated.Hist.Counts = truncated.Hist.Counts[:12]

	orphan := bucket("run_missing", start, 100, good)

	res := apply(t, db, "agent_game", []gamesense.Run{run("run_1", start, 3)},
		[]gamesense.Bucket{future, truncated, orphan})
	if res.Buckets != 0 || res.Rejected != 3 {
		t.Fatalf("apply = %+v, want all three rejected", res)
	}

	got, err := svc.ListBuckets(ctx, "run_1", BucketFilter{})
	if err != nil || len(got) != 0 {
		t.Fatalf("ListBuckets = %d err=%v, want none stored", len(got), err)
	}
	var phantom int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_runs WHERE id='run_missing'`).Scan(&phantom); err != nil {
		t.Fatal(err)
	}
	if phantom != 0 {
		t.Fatalf("an orphan bucket created a phantom run")
	}
}

// TestRunUpsertKeepsTheEnding covers the two ways a re-sent run could corrupt the
// stored one: a stale copy overwriting the current title, and a stale copy
// reopening a run that has already been observed to end.
func TestRunUpsertKeepsTheEnding(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	early := run("run_1", start, 10)
	early.Title = "Main Menu"
	apply(t, db, "agent_game", []gamesense.Run{early}, nil)

	ended := run("run_1", start, 600)
	ended.Title = "Round 3"
	end := start.Add(600 * time.Second)
	ended.EndedAt = &end
	apply(t, db, "agent_game", []gamesense.Run{ended}, nil)

	// The WAL redelivers the early copy after the final one has already landed.
	apply(t, db, "agent_game", []gamesense.Run{early}, nil)

	got, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.Title != "Round 3" {
		t.Fatalf("title = %q, want the newest report to win", got.Title)
	}
	if got.EndedAt == nil || !got.EndedAt.Equal(end) {
		t.Fatalf("ended_at = %v, want a replay not to reopen a finished run", got.EndedAt)
	}
	if !got.LastSeenAt.Equal(end) {
		t.Fatalf("last_seen_at = %v, want %v", got.LastSeenAt, end)
	}
	if got.Summary.DurationSeconds != 600 {
		t.Fatalf("duration = %ds, want 600", got.Summary.DurationSeconds)
	}
}

// A person who moves to another window and comes back is in the same session,
// and the agent reopens the run it had parked. An ending is therefore
// provisional, and a report that has seen more of the run than the stored one
// must be able to clear it — otherwise the second half of that session is
// stranded in a row marked finished.
//
// The counterpart is TestRunUpsertKeepsTheEnding: what separates a reopening
// from a replayed old packet is which report has seen more, not which arrived
// later.
func TestRunUpsertReopensAParkedRun(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	parked := run("run_1", start, 300)
	end := start.Add(300 * time.Second)
	parked.EndedAt = &end
	apply(t, db, "agent_game", []gamesense.Run{parked}, nil)

	if got, err := svc.GetRun(ctx, "run_1"); err != nil || got.EndedAt == nil {
		t.Fatalf("GetRun = %+v, %v; want a finished run to start from", got, err)
	}

	// The player comes back; the agent reopens the run and reports it as live.
	resumed := run("run_1", start, 420)
	apply(t, db, "agent_game", []gamesense.Run{resumed}, nil)

	got, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.EndedAt != nil {
		t.Fatalf("ended_at = %v, want the run reopened", got.EndedAt)
	}
	if !got.LastSeenAt.Equal(start.Add(420 * time.Second)) {
		t.Fatalf("last_seen_at = %v, want the resumed extent", got.LastSeenAt)
	}
	// And it can finish again afterwards.
	finalEnd := start.Add(500 * time.Second)
	final := run("run_1", start, 500)
	final.EndedAt = &finalEnd
	apply(t, db, "agent_game", []gamesense.Run{final}, nil)
	got, err = svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.EndedAt == nil || !got.EndedAt.Equal(finalEnd) {
		t.Fatalf("ended_at = %v, want %v", got.EndedAt, finalEnd)
	}
}

// TestRunUpsertRejectsForeignAgent: run ids are agent-generated, so a collision
// must not reattribute one machine's session to another's.
func TestRunUpsertRejectsForeignAgent(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	seedAgent(t, db, "agent_other", `["game.process.detect","game.performance.read"]`)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	apply(t, db, "agent_game", []gamesense.Run{run("run_1", start, 10)}, nil)
	theft := run("run_1", start, 20)
	theft.Title = "Stolen"
	apply(t, db, "agent_other", []gamesense.Run{theft}, nil)

	got, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.AgentID != "agent_game" || got.Title == "Stolen" {
		t.Fatalf("run = %+v, want the original agent's record untouched", got)
	}
}

// TestSummaryLowsFromMergedHistograms is why buckets store distributions at all:
// a run that is mostly fast with a rare stutter must report a 1% low far below
// its mean, which no average of per-second summaries produces.
func TestSummaryLowsFromMergedHistograms(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)

	// 100 seconds, each 99 frames at ~173 FPS and one at ~10 FPS.
	runs := []gamesense.Run{run("run_stutter", start, 100)}
	var buckets []gamesense.Bucket
	for i := 0; i < 100; i++ {
		buckets = append(buckets, bucket("run_stutter", start.Add(time.Duration(i)*time.Second), 100,
			hist([2]float64{5, 99}, [2]float64{100, 1})))
	}
	apply(t, db, "agent_game", runs, buckets)

	got, err := svc.GetRun(ctx, "run_stutter")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	s := got.Summary
	if s.MeanFPS == nil || s.Low1PctFPS == nil || s.Low01PctFPS == nil {
		t.Fatalf("summary = %+v, want all three figures over 10000 frames", s)
	}
	if *s.MeanFPS < 100 {
		t.Fatalf("mean = %.1f FPS, want the fast majority to dominate it", *s.MeanFPS)
	}
	if *s.Low1PctFPS > *s.MeanFPS/4 {
		t.Fatalf("1%% low = %.1f FPS against a mean of %.1f: the stutter did not surface",
			*s.Low1PctFPS, *s.MeanFPS)
	}
	if s.Presented != 10000 {
		t.Fatalf("presented = %d, want 10000", s.Presented)
	}
}

// TestSummaryOmitsUnsupportedLows: a fraction covering only a handful of frames
// is one slow frame, not a statistic. Reporting 0 there would read as a run that
// stuttered to a standstill — the opposite of what a short, smooth clip means.
func TestSummaryOmitsUnsupportedLows(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	var buckets []gamesense.Bucket
	for i := 0; i < 3; i++ {
		buckets = append(buckets, bucket("run_short", start.Add(time.Duration(i)*time.Second), 100,
			hist([2]float64{5, 100})))
	}
	apply(t, db, "agent_game", []gamesense.Run{run("run_short", start, 3)}, buckets)

	got, err := svc.GetRun(ctx, "run_short")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.Summary.MeanFPS == nil {
		t.Fatalf("mean FPS is computable from 300 frames and must be reported")
	}
	if got.Summary.Low1PctFPS != nil || got.Summary.Low01PctFPS != nil {
		t.Fatalf("low figures = %v / %v, want them omitted rather than zeroed",
			got.Summary.Low1PctFPS, got.Summary.Low01PctFPS)
	}
}

// TestDeleteRunCascades: deleting a run takes its seconds with it, or the buckets
// become unreachable rows that only retention would ever find.
func TestDeleteRunCascades(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})
	apply(t, db, "agent_game", []gamesense.Run{run("run_1", start, 2)}, []gamesense.Bucket{
		bucket("run_1", start, 100, h),
		bucket("run_1", start.Add(time.Second), 100, h),
	})

	if err := svc.DeleteRun(ctx, "run_1"); err != nil {
		t.Fatalf("DeleteRun: %v", err)
	}
	if err := svc.DeleteRun(ctx, "run_1"); err != ErrNotFound {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_buckets`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("game_buckets = %d rows after the run was deleted", rows)
	}
}

// TestRetentionWindows: buckets age out on the short window while their run
// survives on the long one, so a summary outlives the seconds behind it.
func TestRetentionWindows(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	h := hist([2]float64{5, 100})

	old := now.AddDate(0, 0, -120)
	mid := now.AddDate(0, 0, -30)
	apply(t, db, "agent_game", []gamesense.Run{run("run_old", old, 1), run("run_mid", mid, 1)},
		[]gamesense.Bucket{bucket("run_old", old, 100, h), bucket("run_mid", mid, 100, h)})

	buckets, runs, err := svc.Retention(ctx)
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if buckets != 2 || runs != 1 {
		t.Fatalf("retention removed %d bucket(s) / %d run(s), want 2 and 1", buckets, runs)
	}
	if _, err := svc.GetRun(ctx, "run_old"); err != ErrNotFound {
		t.Fatalf("a 120-day-old run survived the 90-day window: %v", err)
	}
	got, err := svc.GetRun(ctx, "run_mid")
	if err != nil {
		t.Fatalf("GetRun run_mid: %v", err)
	}
	if got.Summary.MeanFPS == nil || got.Summary.Presented != 100 {
		t.Fatalf("a run outliving its buckets lost its figures: %+v", got.Summary)
	}
}

// TestSummarySurvivesItsBuckets is why the totals live on the run row. Buckets age
// out in a week and runs in three months, so every run old enough to be worth
// comparing has lost its seconds — and a summary derived from whatever buckets
// remain reports those runs as zero frames at null FPS, which is the whole reason
// the long window exists undone.
func TestSummarySurvivesItsBuckets(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Second).AddDate(0, 0, -30)

	// 100 seconds of 99 fast frames and one stutter: 10000 frames, enough that even
	// the 0.1% low covers the ten frames it takes to be a statistic.
	var buckets []gamesense.Bucket
	for i := 0; i < 100; i++ {
		b := bucket("run_mid", start.Add(time.Duration(i)*time.Second), 100,
			hist([2]float64{5, 99}, [2]float64{100, 1}))
		b.Frames.Displayed = intp(98)
		b.Frames.Dropped = intp(2)
		buckets = append(buckets, b)
	}
	apply(t, db, "agent_game", []gamesense.Run{run("run_mid", start, 99)}, buckets)

	before, err := svc.GetRun(ctx, "run_mid")
	if err != nil {
		t.Fatalf("GetRun before retention: %v", err)
	}
	if before.Summary.Low01PctFPS == nil {
		t.Fatalf("summary = %+v, want all three figures over 10000 frames", before.Summary)
	}

	if _, _, err := svc.Retention(ctx); err != nil {
		t.Fatalf("Retention: %v", err)
	}
	var left int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM game_buckets WHERE run_id='run_mid'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d second(s) survived the 7-day window, so this proves nothing", left)
	}

	after, err := svc.GetRun(ctx, "run_mid")
	if err != nil {
		t.Fatalf("GetRun after retention: %v", err)
	}
	if !reflect.DeepEqual(before.Summary, after.Summary) {
		t.Fatalf("summary after its buckets aged out = %+v, want %+v", after.Summary, before.Summary)
	}
	s := after.Summary
	if s.Presented != 10000 {
		t.Fatalf("presented = %d, want 10000", s.Presented)
	}
	if s.Displayed == nil || *s.Displayed != 9800 || s.Dropped == nil || *s.Dropped != 200 {
		t.Fatalf("totals = %+v, want 9800 displayed / 200 dropped", s)
	}
	if s.MeanFPS == nil || s.Low1PctFPS == nil || s.Low01PctFPS == nil {
		t.Fatalf("frame figures = %+v, want all three to outlive the histograms", s)
	}
	if *s.Low1PctFPS >= *s.MeanFPS {
		t.Fatalf("1%% low %.1f is not below the mean %.1f", *s.Low1PctFPS, *s.MeanFPS)
	}
}

// TestRetentionCountsRunChildBuckets: with the bucket window disabled or set wider
// than the run window, expiring runs is the only thing deleting seconds. Reporting
// zero there would have the sweep log claim it found nothing to do in the same
// breath as it emptied the table.
func TestRetentionCountsRunChildBuckets(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	st := settings.New(db)
	if err := st.Set(ctx, settings.KeyGameBucketRetentionDays, "0"); err != nil {
		t.Fatalf("disable bucket retention: %v", err)
	}
	old := time.Now().UTC().Truncate(time.Second).AddDate(0, 0, -120)
	h := hist([2]float64{5, 100})

	var buckets []gamesense.Bucket
	for i := 0; i < 3; i++ {
		buckets = append(buckets, bucket("run_old", old.Add(time.Duration(i)*time.Second), 100, h))
	}
	apply(t, db, "agent_game", []gamesense.Run{run("run_old", old, 2)}, buckets)

	gotBuckets, gotRuns, err := svc.Retention(ctx)
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if gotBuckets != 3 || gotRuns != 1 {
		t.Fatalf("retention reported %d bucket(s) / %d run(s), want 3 and 1", gotBuckets, gotRuns)
	}
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_buckets`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("game_buckets = %d rows, want the expired run's seconds gone", rows)
	}
}

// TestRunDurationCountsItsLastSecond: the agent opens a bucket-started run at its
// first second and always ends it at its last, so both stamps name a second that
// was captured. Timing the gap between them reports a run that plainly happened as
// zero seconds long, and an N-second run as N-1.
func TestRunDurationCountsItsLastSecond(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	h := hist([2]float64{5, 100})

	apply(t, db, "agent_game", []gamesense.Run{run("run_one", start, 0)},
		[]gamesense.Bucket{bucket("run_one", start, 100, h)})

	var buckets []gamesense.Bucket
	for i := 0; i < 10; i++ {
		buckets = append(buckets, bucket("run_ten", start.Add(time.Duration(i)*time.Second), 100, h))
	}
	apply(t, db, "agent_game", []gamesense.Run{run("run_ten", start, 9)}, buckets)

	// A run tracked from a status and ended without ever seeing a second is stamped
	// from the agent's clock instead, which is already an elapsed time.
	tracked := run("run_tracked", start, 30)
	end := start.Add(30 * time.Second)
	tracked.EndedAt = &end
	apply(t, db, "agent_game", []gamesense.Run{tracked}, nil)

	for _, tc := range []struct {
		id   string
		want int64
	}{{"run_one", 1}, {"run_ten", 10}, {"run_tracked", 30}} {
		got, err := svc.GetRun(ctx, tc.id)
		if err != nil {
			t.Fatalf("GetRun %s: %v", tc.id, err)
		}
		if got.Summary.DurationSeconds != tc.want {
			t.Fatalf("%s duration = %ds, want %d", tc.id, got.Summary.DurationSeconds, tc.want)
		}
	}
}

// TestListRunsWindowIncludesOverlaps: an operator looking at "the last hour" is
// asking about play that happened in it, which includes a session that started
// before the window opened.
func TestListRunsWindowIncludesOverlaps(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	apply(t, db, "agent_game", []gamesense.Run{
		run("run_spanning", now.Add(-3*time.Hour), 3*3600), // started before, still running
		run("run_ancient", now.Add(-9*time.Hour), 60),      // finished long before
	}, nil)

	page, err := svc.ListRuns(ctx, RunFilter{AgentID: "agent_game", Since: now.Add(-time.Hour).Unix()})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "run_spanning" {
		t.Fatalf("window listing = %+v, want only the overlapping run", page)
	}
}

// TestHistogramBlobRoundTrip pins the stored encoding: bin counts must come back
// in their own bins, since a shift by one would silently report frame times that
// were never measured.
func TestHistogramBlobRoundTrip(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	h := hist([2]float64{5, 7}, [2]float64{100, 3}, [2]float64{20, 11})
	apply(t, db, "agent_game", []gamesense.Run{run("run_1", start, 1)},
		[]gamesense.Bucket{bucket("run_1", start, 21, h)})

	got, err := svc.ListBuckets(ctx, "run_1", BucketFilter{})
	if err != nil || len(got) != 1 {
		t.Fatalf("ListBuckets err=%v n=%d", err, len(got))
	}
	if got[0].Hist.Layout != gamesense.HistLayoutLog24V1 {
		t.Fatalf("layout = %q", got[0].Hist.Layout)
	}
	if len(got[0].Hist.Counts) != gamesense.HistBins {
		t.Fatalf("counts = %d bins, want %d", len(got[0].Hist.Counts), gamesense.HistBins)
	}
	for i, want := range h.Counts {
		if got[0].Hist.Counts[i] != want {
			t.Fatalf("bin %d = %d, want %d", i, got[0].Hist.Counts[i], want)
		}
	}

	var blob []byte
	if err := db.QueryRowContext(ctx, `SELECT hist FROM game_buckets WHERE run_id='run_1'`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if len(blob) != histBytes {
		t.Fatalf("stored blob = %d bytes, want %d", len(blob), histBytes)
	}
}

// TestApplyWithoutAgentRowStoresNothing: an agent deleted mid-batch has no
// permission record left, and data attributed to nobody must not be kept.
func TestApplyWithoutAgentRowStoresNothing(t *testing.T) {
	db, _ := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	res := apply(t, db, "agent_gone", []gamesense.Run{run("run_x", start, 1)}, nil)
	if !res.Denied || res.Runs != 0 {
		t.Fatalf("apply for an unknown agent = %+v", res)
	}
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_runs`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("game_runs = %d rows", rows)
	}
}
