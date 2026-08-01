package gamedata

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// openGameDB seeds a site and one agent holding the game permissions, which is
// the ordinary case; the denial test overrides the agent's effective set.
func openGameDB(t *testing.T) (*store.DB, *Service) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	seedAgent(t, db, "agent_game", `["game.process.detect","game.performance.read"]`)
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
// the way a packet does.
func apply(t *testing.T, db *store.DB, agentID string, runs []gamesense.Run, buckets []gamesense.Bucket) Result {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	res, err := Apply(ctx, tx, agentID, "site_default", runs, buckets)
	if err != nil {
		tx.Rollback()
		t.Fatalf("apply: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return res
}

func intp(v int) *int    { return &v }
func boolp(v bool) *bool { return &v }

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
