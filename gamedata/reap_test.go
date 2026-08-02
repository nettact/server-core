package gamedata

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/server-core/store"
)

// reportUploadInterval records an agent's reported WAL batch-upload cadence where
// the server actually keeps it: on the agent's monitor_status rows, one per probe
// target, each carrying the same agent-global value. The group and target exist
// only because the foreign keys demand them.
func reportUploadInterval(t *testing.T, db *store.DB, agentID string, seconds int) {
	t.Helper()
	ctx := context.Background()
	id := agentID + "_mon"
	if _, err := db.ExecContext(ctx,
		`INSERT OR IGNORE INTO monitor_groups(id,site_id,name) VALUES('grp_reap','site_default','reap')`); err != nil {
		t.Fatalf("seed monitor group: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,target) VALUES(?,'site_default','grp_reap','icmp','127.0.0.1')`,
		id); err != nil {
		t.Fatalf("seed probe task: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO monitor_status(agent_id,monitor_id,status,config_version,updated_at,upload_interval_seconds)
		 VALUES(?,?,'active',1,?,?)`, agentID, id, time.Now().UTC(), seconds); err != nil {
		t.Fatalf("seed monitor status: %v", err)
	}
}

// TestCloseAbandonedRunEndsAtLastSeen is the reported bug: an agent killed
// mid-session leaves its run with no ending, and nothing on that machine can ever
// write one — after a restart the recorder has forgotten the run entirely. The
// sweep closes it, and closes it at the second it actually stopped rather than at
// the time of the sweep, so the duration stays the length of the session instead
// of the length of the outage.
func TestCloseAbandonedRunEndsAtLastSeen(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)
	h := hist([2]float64{5, 100})

	apply(t, db, "agent_game", []gamesense.Run{run("run_killed", start, 1)}, []gamesense.Bucket{
		bucket("run_killed", start, 100, h),
		bucket("run_killed", start.Add(time.Second), 100, h),
	})

	n, err := svc.CloseAbandonedRuns(ctx)
	if err != nil {
		t.Fatalf("CloseAbandonedRuns: %v", err)
	}
	if n != 1 {
		t.Fatalf("closed %d run(s), want the one abandoned run", n)
	}

	got, err := svc.GetRun(ctx, "run_killed")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.EndedAt == nil {
		t.Fatal("run still reads as in progress after the sweep")
	}
	if !got.EndedAt.Equal(got.LastSeenAt) {
		t.Fatalf("ended at %s, want the run's last seen second %s — stamping the sweep's own clock invents session that never happened",
			got.EndedAt, got.LastSeenAt)
	}
	// Two seconds recorded, both ends inclusive. Had the sweep stamped "now" this
	// would report the whole thirty minutes since the crash as play time.
	if got.Summary.DurationSeconds != 2 {
		t.Fatalf("duration = %ds, want 2s", got.Summary.DurationSeconds)
	}
}

// TestCloseAbandonedLeavesFreshRun: a session in progress is exactly what
// ended_at NULL is for, and the sweep must never touch one. The margin is what
// makes that safe — the server hears from a live run every upload, so a run seen
// a minute ago is nowhere near the bound.
func TestCloseAbandonedLeavesFreshRun(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	h := hist([2]float64{5, 100})

	apply(t, db, "agent_game", []gamesense.Run{run("run_live", start, 1)},
		[]gamesense.Bucket{bucket("run_live", start, 100, h)})

	n, err := svc.CloseAbandonedRuns(ctx)
	if err != nil {
		t.Fatalf("CloseAbandonedRuns: %v", err)
	}
	if n != 0 {
		t.Fatalf("closed %d run(s), want none — the session is still running", n)
	}
	got, err := svc.GetRun(ctx, "run_live")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.EndedAt != nil {
		t.Fatalf("a live run was ended at %s", got.EndedAt)
	}
}

// TestCloseAbandonedLeavesEndedRun: a run the agent already ended is finished
// business. The sweep must not count it, and must not restamp it — its ending was
// observed, and last_seen_at is not necessarily the same second.
func TestCloseAbandonedLeavesEndedRun(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)
	h := hist([2]float64{5, 100})

	done := run("run_done", start, 1)
	ended := start.Add(30 * time.Second)
	done.EndedAt = &ended
	apply(t, db, "agent_game", []gamesense.Run{done},
		[]gamesense.Bucket{bucket("run_done", start, 100, h)})

	n, err := svc.CloseAbandonedRuns(ctx)
	if err != nil {
		t.Fatalf("CloseAbandonedRuns: %v", err)
	}
	if n != 0 {
		t.Fatalf("closed %d run(s), want none — the run was already ended", n)
	}
	got, err := svc.GetRun(ctx, "run_done")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.EndedAt == nil || !got.EndedAt.Equal(ended) {
		t.Fatalf("ended_at = %v, want the agent's own ending %s untouched", got.EndedAt, ended)
	}
}

// TestCloseAbandonedIsIdempotent: the sweep runs every minute forever, so a second
// pass over the same data must find nothing to do. A sweep that kept re-closing
// what it closed would report a count every minute and, worse, would be rewriting
// rows the console is reading.
func TestCloseAbandonedIsIdempotent(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)
	h := hist([2]float64{5, 100})

	apply(t, db, "agent_game", []gamesense.Run{run("run_killed", start, 1)},
		[]gamesense.Bucket{bucket("run_killed", start, 100, h)})

	first, err := svc.CloseAbandonedRuns(ctx)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	before, err := svc.GetRun(ctx, "run_killed")
	if err != nil {
		t.Fatalf("GetRun after first sweep: %v", err)
	}

	second, err := svc.CloseAbandonedRuns(ctx)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if first != 1 || second != 0 {
		t.Fatalf("sweeps closed %d then %d run(s), want 1 then 0", first, second)
	}
	after, err := svc.GetRun(ctx, "run_killed")
	if err != nil {
		t.Fatalf("GetRun after second sweep: %v", err)
	}
	if after.EndedAt == nil || !after.EndedAt.Equal(*before.EndedAt) {
		t.Fatalf("ended_at moved between sweeps: %v -> %v", before.EndedAt, after.EndedAt)
	}
}

// TestCloseAbandonedOnDisconnectedAgent: while the owning agent has no socket,
// nothing for that run can arrive at all, so the wait drops from the connected
// bound to the short grace that absorbs a reconnect. The control run belongs to a
// connected agent at the same staleness and must survive — otherwise the sweep is
// just a shorter timeout wearing a liveness check.
func TestCloseAbandonedOnDisconnectedAgent(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	seedAgent(t, db, "agent_gone", `["game.performance.read"]`)
	// Offline, and last heard from well past the grace — the machine is gone, not
	// blinking.
	if _, err := db.ExecContext(ctx, `UPDATE agents SET status='offline', last_seen_at=? WHERE id='agent_gone'`,
		time.Now().UTC().Add(-10*time.Minute)); err != nil {
		t.Fatalf("mark agent offline: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE agents SET last_seen_at=? WHERE id='agent_game'`,
		time.Now().UTC()); err != nil {
		t.Fatalf("touch online agent: %v", err)
	}

	start := time.Now().UTC().Truncate(time.Second).Add(-5 * time.Minute)
	h := hist([2]float64{5, 100})
	apply(t, db, "agent_gone", []gamesense.Run{run("run_gone", start, 1)},
		[]gamesense.Bucket{bucket("run_gone", start, 100, h)})
	apply(t, db, "agent_game", []gamesense.Run{run("run_here", start, 1)},
		[]gamesense.Bucket{bucket("run_here", start, 100, h)})

	n, err := svc.CloseAbandonedRuns(ctx)
	if err != nil {
		t.Fatalf("CloseAbandonedRuns: %v", err)
	}
	if n != 1 {
		t.Fatalf("closed %d run(s), want only the disconnected agent's", n)
	}
	gone, err := svc.GetRun(ctx, "run_gone")
	if err != nil {
		t.Fatalf("GetRun run_gone: %v", err)
	}
	if gone.EndedAt == nil {
		t.Fatal("a run whose agent is disconnected still reads as in progress")
	}
	here, err := svc.GetRun(ctx, "run_here")
	if err != nil {
		t.Fatalf("GetRun run_here: %v", err)
	}
	if here.EndedAt != nil {
		t.Fatalf("a connected agent's run was ended at %s after only five minutes", here.EndedAt)
	}
}

// TestCloseAbandonedRespectsReportedUploadInterval: the agent's WAL batch-upload
// cadence is configurable, and the server hears nothing about a run between
// uploads however often the agent drains into its WAL — the WAL is on the agent's
// disk. A deployment uploading every half hour is healthy, and a bound fixed
// against the 5s default would close every live run on it, over and over, for most
// of each upload cycle. The bound therefore scales with what the agent reported.
func TestCloseAbandonedRespectsReportedUploadInterval(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	reportUploadInterval(t, db, "agent_game", 1800) // 30 minutes
	h := hist([2]float64{5, 100})

	// Stale by 40 minutes: four times the floor, but barely one upload cycle on
	// this deployment, so the run is very plausibly still being played.
	recent := time.Now().UTC().Truncate(time.Second).Add(-40 * time.Minute)
	apply(t, db, "agent_game", []gamesense.Run{run("run_slow_upload", recent, 1)},
		[]gamesense.Bucket{bucket("run_slow_upload", recent, 100, h)})

	if n, err := svc.CloseAbandonedRuns(ctx); err != nil || n != 0 {
		t.Fatalf("sweep closed %d run(s) (err %v), want 0 — 40 minutes is inside a 30-minute upload cycle's allowance", n, err)
	}
	got, err := svc.GetRun(ctx, "run_slow_upload")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.EndedAt != nil {
		t.Fatalf("a live run on a slow-uploading agent was ended at %s", got.EndedAt)
	}

	// The bound scales, it does not vanish: past four upload cycles the run is
	// abandoned on any reading.
	dead := time.Now().UTC().Truncate(time.Second).Add(-3 * time.Hour)
	apply(t, db, "agent_game", []gamesense.Run{run("run_really_dead", dead, 1)},
		[]gamesense.Bucket{bucket("run_really_dead", dead, 100, h)})
	if n, err := svc.CloseAbandonedRuns(ctx); err != nil || n != 1 {
		t.Fatalf("sweep closed %d run(s) (err %v), want 1 — three hours is past even a 30-minute cadence", n, err)
	}
	if still, err := svc.GetRun(ctx, "run_slow_upload"); err != nil || still.EndedAt != nil {
		t.Fatalf("the run inside the allowance was closed too (err %v): %+v", err, still.EndedAt)
	}
}

// TestCloseAbandonedGraceRunsFromDisconnect: the offline grace exists to absorb a
// blip, and it can only do that if it is measured from the DISCONNECT. Measuring
// it from the run's own staleness would defeat it entirely — a run already stale
// when its agent drops (a server restart, an upload backlog: exactly when a live
// agent looks stale) would be closed on the first tick, with no grace at all.
func TestCloseAbandonedGraceRunsFromDisconnect(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	seedAgent(t, db, "agent_blip", `["game.performance.read"]`)

	// The socket dropped seconds ago; the run was already five minutes stale when
	// it did. Well inside the connected bound, so only the liveness arm can fire.
	if _, err := db.ExecContext(ctx, `UPDATE agents SET status='offline', last_seen_at=? WHERE id='agent_blip'`,
		time.Now().UTC().Add(-10*time.Second)); err != nil {
		t.Fatalf("mark agent offline: %v", err)
	}
	start := time.Now().UTC().Truncate(time.Second).Add(-5 * time.Minute)
	h := hist([2]float64{5, 100})
	apply(t, db, "agent_blip", []gamesense.Run{run("run_blip", start, 1)},
		[]gamesense.Bucket{bucket("run_blip", start, 100, h)})

	if n, err := svc.CloseAbandonedRuns(ctx); err != nil || n != 0 {
		t.Fatalf("sweep closed %d run(s) (err %v), want 0 — the agent dropped ten seconds ago and the grace has not run", n, err)
	}
	got, err := svc.GetRun(ctx, "run_blip")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.EndedAt != nil {
		t.Fatalf("a reconnect blip ended a live run at %s", got.EndedAt)
	}

	// Same run, same staleness; only the disconnect has aged past the grace.
	if _, err := db.ExecContext(ctx, `UPDATE agents SET last_seen_at=? WHERE id='agent_blip'`,
		time.Now().UTC().Add(-3*time.Minute)); err != nil {
		t.Fatalf("age the disconnect: %v", err)
	}
	if n, err := svc.CloseAbandonedRuns(ctx); err != nil || n != 1 {
		t.Fatalf("sweep closed %d run(s) (err %v), want 1 once the grace has passed", n, err)
	}
}

// TestReapSweepsOnlyOpenRuns pins the cost of the sweep, which runs every minute
// for the life of the process. The partial index holds one entry per session in
// progress — usually none — so the tick must walk that and not the run table,
// which keeps ninety days of history the sweep has no question about. A plan that
// stopped naming the index would mean the minute tick had quietly become a scan
// proportional to everything ever recorded.
func TestReapSweepsOnlyOpenRuns(t *testing.T) {
	db, _ := openGameDB(t)
	rows, err := db.Read().QueryContext(context.Background(), `EXPLAIN QUERY PLAN `+reapSQL,
		0, 0, 0, 0, time.Time{})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	for _, step := range plan {
		if strings.Contains(step, "idx_game_runs_open") {
			return
		}
	}
	t.Fatalf("plan does not use the open-run index, so the sweep scans every run: %v", plan)
}

// TestAbandonedRunReopensOnLateBatch is the property the whole design rests on.
//
// Reaping is a guess: the server cannot tell a crashed agent from one whose
// packets are merely late. It is allowed to guess because upsertRun resolves
// ended_at in favour of the report with the newer last_seen_at, so a batch from a
// session that was alive all along carries a NULL ending that WINS and reopens the
// run. Without that, a premature close would be permanent and the bound would have
// to be set defensively long — which is the difference between a stale "in
// progress" clearing in minutes and clearing in hours.
func TestAbandonedRunReopensOnLateBatch(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Add(-30 * time.Minute)
	h := hist([2]float64{5, 100})

	apply(t, db, "agent_game", []gamesense.Run{run("run_slow", start, 1)},
		[]gamesense.Bucket{bucket("run_slow", start, 100, h)})

	if n, err := svc.CloseAbandonedRuns(ctx); err != nil || n != 1 {
		t.Fatalf("sweep closed %d run(s) (err %v), want 1", n, err)
	}
	closed, err := svc.GetRun(ctx, "run_slow")
	if err != nil {
		t.Fatalf("GetRun after sweep: %v", err)
	}
	if closed.EndedAt == nil {
		t.Fatal("sweep did not close the run, so this test proves nothing")
	}

	// The session was never over: the agent was backlogged, and its next batch
	// carries newer seconds and still no ending.
	late := run("run_slow", start, 1)
	late.LastSeenAt = now.Add(-10 * time.Second)
	apply(t, db, "agent_game", []gamesense.Run{late},
		[]gamesense.Bucket{bucket("run_slow", late.LastSeenAt, 100, h)})

	got, err := svc.GetRun(ctx, "run_slow")
	if err != nil {
		t.Fatalf("GetRun after late batch: %v", err)
	}
	if got.EndedAt != nil {
		t.Fatalf("late batch left the run ended at %s: a premature close is permanent, and the reaper is unsafe", got.EndedAt)
	}
	if !got.LastSeenAt.Equal(late.LastSeenAt) {
		t.Fatalf("last_seen_at = %s, want the late batch's %s", got.LastSeenAt, late.LastSeenAt)
	}
	// And having recovered, it stays recovered: the run is fresh again, so the next
	// sweep leaves it alone rather than re-closing it every minute.
	if n, err := svc.CloseAbandonedRuns(ctx); err != nil || n != 0 {
		t.Fatalf("sweep after recovery closed %d run(s) (err %v), want 0", n, err)
	}
}
