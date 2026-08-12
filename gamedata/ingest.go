package gamedata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/store"
)

// Result reports what one packet's game payload did, for the ingest log. A packet
// whose data was refused wholesale (Denied) is a different event from one whose
// individual buckets were rejected, and the two must not read alike when someone
// is working out why a run has no frames.
type Result struct {
	Runs        int  // runs upserted
	Buckets     int  // buckets stored (a replayed second stores nothing)
	Gaps        int  // frameless stretches upserted
	HostSeconds int  // machine-level seconds stored (a replayed second stores nothing)
	Rejected    int  // buckets or gaps refused: unknown run, or unrecognized histogram layout
	Denied      bool // the agent does not hold game.performance.read
}

// Apply stores a packet's runs, buckets, gaps and machine-level seconds inside
// the caller's ingest transaction, so game data and the telemetry it arrived
// with reach one committed state together.
//
// Runs are upserted: the agent re-sends a run whenever its mutable fields change
// (title, last seen, ending), which is what completes a run that outlived a
// disconnect. Gaps are upserted by id for the same reason — a silence has to be
// visible before it ends, so it is re-sent as it grows. Buckets and host seconds
// are INSERT OR IGNORE on their identity like every other replay-safe write here
// — an at-least-once uploader must be able to retry a batch without duplicating
// or rewriting a second that is already recorded.
func Apply(ctx context.Context, tx store.WriteTx, agentID, siteID string, runs []gamesense.Run, buckets []gamesense.Bucket, gaps []gamesense.Gap, hosts []gamesense.HostSecond) (Result, error) {
	var res Result
	if len(runs) == 0 && len(buckets) == 0 && len(gaps) == 0 && len(hosts) == 0 {
		return res, nil
	}

	// Permission gate. Game data is not a metric, so the metric-kind mapping does
	// not cover it and the permission is checked directly. The agent enforces its
	// own policy, but a policy that was narrowed while a batch sat in the agent's
	// WAL would otherwise still land here — storing frame data the operator has
	// since revoked. The effective set is the intersection the agent reported, so a
	// build or platform that cannot capture frames also fails this test.
	//
	// Read once for the whole packet rather than per bucket: it is the same row for
	// every second in the batch, and a batch commonly carries a minute of them.
	perms, err := agentPermissions(ctx, tx, agentID)
	if err != nil {
		return res, err
	}
	if !perms.Has(permission.GamePerformanceRead) {
		res.Denied = true
		log.Printf("gamedata: dropped %d run(s), %d bucket(s), %d gap(s) and %d machine second(s) from agent %s without %s",
			len(runs), len(buckets), len(gaps), len(hosts), agentID, permission.GamePerformanceRead)
		return res, nil
	}
	// The adapter telemetry is a second, narrower read. Frame timings come from the
	// game's own presentation, while GPU utilization and VRAM describe the card and
	// every process sharing it — so an operator can grant the first and withhold the
	// second, and a WAL that drained after that narrowing must not smuggle the
	// difference in.
	//
	// It strips exactly two things: a bucket's process VRAM, and a machine
	// second's adapter block. Everything else survives, including the machine's
	// CPU and memory — the processor and the RAM are not the graphics device, and
	// gating them on a graphics permission would withhold the readings that
	// explain a stutter for a reason that has nothing to do with them.
	gpuOK := perms.Has(permission.GameGPURead)

	for _, run := range runs {
		if run.ID == "" {
			continue
		}
		if err := upsertRun(ctx, tx, agentID, siteID, run); err != nil {
			return res, err
		}
		res.Runs++
	}

	// Buckets are only stored under a run this agent already owns. Creating a run
	// from a bucket would invent a session with no start, no source and no
	// capability list — a phantom whose frames could never be interpreted, since
	// nothing would say what the capture could see.
	known, err := ownedRuns(ctx, tx, agentID, buckets)
	if err != nil {
		return res, err
	}
	deltas := map[string]*runDelta{}
	stripped := 0
	for _, b := range buckets {
		if !known[b.RunID] || !knownLayout(b.Hist) {
			res.Rejected++
			continue
		}
		// b is a copy, so clearing the blocks here affects what this packet stores and
		// nothing the caller still holds. The bucket is not rejected over it: the
		// second's frame data is permitted and worth keeping — only the part the
		// policy withholds goes missing, which is exactly the NULL that means "not
		// measured" everywhere else in this table.
		if !gpuOK && b.ProcVRAM != nil {
			b.ProcVRAM = nil
			stripped++
		}
		stored, err := insertBucket(ctx, tx, b)
		if err != nil {
			return res, err
		}
		// Only a second the insert actually took is folded into the run's totals. A
		// replayed batch re-reports every second it carries, and a second counted
		// twice can never be caught: the totals outlive the rows they came from, so
		// nothing downstream could ever recompute them and notice.
		if stored {
			res.Buckets++
			fold(deltas, b)
		}
	}
	if err := writeAggregates(ctx, tx, deltas); err != nil {
		return res, err
	}

	// Gaps hang off a run, so they are filtered through the same ownership test
	// buckets are. `known` was built from the buckets' run ids, which are not the
	// gaps' — a stretch with no frames in it has no bucket to have been named by —
	// so the gaps get their own lookup.
	//
	// Deliberately NOT folded into the run: a gap must not advance last_seen_at,
	// must not clear ended_at, and must not touch the summary. A game sitting
	// minimized is not a game still being played, and advancing the run over it
	// would make it look alive to the abandoned-run reaper and stretch
	// duration_seconds across time no frame covered.
	knownGapRuns, err := ownedGapRuns(ctx, tx, agentID, gaps)
	if err != nil {
		return res, err
	}
	for _, g := range gaps {
		if g.ID == "" || !knownGapRuns[g.RunID] {
			res.Rejected++
			continue
		}
		if err := upsertGap(ctx, tx, g); err != nil {
			return res, err
		}
		res.Gaps++
	}

	// Machine seconds are keyed by (agent, second) and hang off no run, so they
	// need no ownership test — the agent id IS the ownership. They are also
	// stored for agents with no open run at all, which is the point: the seconds
	// a game drew nothing in are exactly the ones a reader wants the machine's
	// side of.
	for _, h := range hosts {
		if !gpuOK && h.GPU != nil {
			h.GPU = nil
			stripped++
		}
		// Re-checked after the strip, not before. Removing the only block a second
		// carried leaves an all-NULL row, which asserts "covered and nothing
		// readable" — a claim this agent has not earned, and one a reader would
		// mistake for a card that stopped reporting rather than a permission that
		// was withheld.
		if h.Empty() {
			continue
		}
		stored, err := insertHostSecond(ctx, tx, agentID, siteID, h)
		if err != nil {
			return res, err
		}
		if stored {
			res.HostSeconds++
		}
	}

	if res.Rejected > 0 {
		log.Printf("gamedata: rejected %d record(s) from agent %s (unknown run or histogram layout)", res.Rejected, agentID)
	}
	if stripped > 0 {
		log.Printf("gamedata: stripped GPU readings from %d record(s) of agent %s without %s",
			stripped, agentID, permission.GameGPURead)
	}
	return res, nil
}

// agentPermissions returns the agent's reported effective set. An agent row that
// has vanished mid-batch yields the empty set rather than an error: there is
// nothing left to attribute the data to, so it fails every test below on its own.
func agentPermissions(ctx context.Context, tx store.Executor, agentID string) (permission.Set, error) {
	var effective string
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(perm_effective,'[]') FROM agents WHERE id=?`, agentID).Scan(&effective)
	if errors.Is(err, sql.ErrNoRows) {
		return permission.Set{}, nil
	}
	if err != nil {
		return permission.Set{}, err
	}
	return permission.FromStrings(decodeStrings(effective)), nil
}

// knownLayout reports whether this histogram is one this build can interpret.
// Storing counts under an unrecognized layout name would let a later reader apply
// the wrong bin edges to them and report frame times that were never measured —
// the layout name is the whole compatibility contract, so a mismatch is refused
// rather than kept "just in case".
func knownLayout(h gamesense.Histogram) bool {
	return h.Layout == gamesense.HistLayoutLog24V1 && len(h.Counts) == gamesense.HistBins
}

// upsertRun writes a run, letting the newer report win on the mutable fields.
//
// Newer is decided by last_seen_at rather than by arrival order, because an
// at-least-once uploader can redeliver an early copy of a run after a later one
// has already landed; taking arrival order would then reinstate a stale window
// title and rewind the run's extent. ended_at is COALESCEd instead: once a run is
// known to be over, no replay may reopen it.
//
// Identity columns (agent, site, start, source, caps) are never updated. They
// describe the session and how it was measured, and a run whose measurement basis
// changed under it is a different run.
func upsertRun(ctx context.Context, tx store.Executor, agentID, siteID string, run gamesense.Run) error {
	var ended sql.NullInt64
	if run.EndedAt != nil {
		ended = sql.NullInt64{Int64: run.EndedAt.Unix(), Valid: true}
	}
	// The agent_id guard on the update is what stops one agent's run id from
	// overwriting another's. Ids are agent-generated, so collision is the caller's
	// mistake to make; the write silently does nothing rather than reattributing a
	// session to the wrong machine.
	//
	// Every mutable field, the ending included, follows the same rule: the report
	// that has seen the most of the run wins. An ending is provisional — a person
	// who alt-tabs away and comes back within the hour is in the same session, and
	// the agent reopens it — so a rule that made an end permanent would leave the
	// second half of that session stranded in a run marked finished. Ordering on
	// last_seen_at is what keeps that from also letting a replayed old packet
	// reopen a run that genuinely finished: a stale report has, by definition,
	// seen less.
	// The profile stamp is mutable under the same guard as proc and title: a
	// profile created while a session is already running re-classifies it on the
	// agent's next report, and an empty id is a session that matches none — stored
	// as NULL, never as the empty string, so "other process" is one value rather
	// than two that readers would have to test for separately.
	_, err := tx.ExecContext(ctx, `
		INSERT INTO game_runs(id, agent_id, site_id, proc, title, profile_id, started_at, last_seen_at, ended_at, source, caps)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			proc = CASE WHEN excluded.last_seen_at >= game_runs.last_seen_at THEN excluded.proc ELSE game_runs.proc END,
			title = CASE WHEN excluded.last_seen_at >= game_runs.last_seen_at THEN excluded.title ELSE game_runs.title END,
			profile_id = CASE WHEN excluded.last_seen_at >= game_runs.last_seen_at
			                  THEN excluded.profile_id ELSE game_runs.profile_id END,
			last_seen_at = max(game_runs.last_seen_at, excluded.last_seen_at),
			ended_at = CASE WHEN excluded.last_seen_at >= game_runs.last_seen_at
			                THEN excluded.ended_at ELSE game_runs.ended_at END
		WHERE game_runs.agent_id = excluded.agent_id`,
		run.ID, agentID, siteID, run.Proc, run.Title, nullStr(run.ProfileID),
		run.StartedAt.Unix(), run.LastSeenAt.Unix(), ended, run.Source,
		string(mustJSON(run.Caps)))
	return err
}

// ownedRuns returns which of the referenced run ids exist and belong to this
// agent. Read after the upserts so a run arriving in the same packet as its first
// buckets is already there.
func ownedRuns(ctx context.Context, tx store.Executor, agentID string, buckets []gamesense.Bucket) (map[string]bool, error) {
	want := map[string]bool{}
	args := []any{agentID}
	for _, b := range buckets {
		if b.RunID == "" {
			continue
		}
		if _, seen := want[b.RunID]; !seen {
			want[b.RunID] = false
			args = append(args, b.RunID)
		}
	}
	if len(want) == 0 {
		return want, nil
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM game_runs WHERE agent_id=? AND id IN (`+placeholders(len(want))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if _, referenced := want[id]; referenced {
			want[id] = true
		}
	}
	return want, rows.Err()
}

func insertBucket(ctx context.Context, tx store.Executor, b gamesense.Bucket) (bool, error) {
	var (
		dispAvg, dispP95              sql.NullFloat64
		mode, api                     sql.NullString
		sync, tearing, presentChanged sql.NullInt64
		stutterCount                  sql.NullInt64
		stutterExcess, procCPU        sql.NullFloat64
		procWS, procPriv              sql.NullInt64
	)
	if b.DispFT != nil {
		dispAvg = nullFloat(b.DispFT.Avg, true)
		dispP95 = nullFloat(b.DispFT.P95, true)
	}
	if b.Present != nil {
		mode = nullStr(b.Present.Mode)
		api = nullStr(b.Present.API)
		sync = nullInt(b.Present.Sync)
		tearing = nullBool(b.Present.Tearing)
		// Written unconditionally for a present block, including false: it is the
		// column that says the block was observed at all.
		presentChanged = nullBool(&b.Present.Changed)
	}
	if b.Stutter != nil {
		// Both columns unconditionally, the zero included: the pair IS the record
		// that the second was watched, and a watched second holding no long frame is
		// the observation every smooth stretch of a run is made of.
		stutterCount = nullInt(&b.Stutter.Count)
		stutterExcess = nullFloat(b.Stutter.ExcessMs, true)
	}
	if b.ProcRes != nil {
		// Each reading stands alone here, unlike the stutter pair. The CPU delta and
		// the memory level come from different queries and fail separately — the
		// first second of a run has no CPU delta to report — so an absent one leaves
		// its own column NULL instead of taking the others down with it.
		if b.ProcRes.CPUPct != nil {
			procCPU = nullFloat(*b.ProcRes.CPUPct, true)
		}
		procWS = nullUint64(b.ProcRes.WSBytes)
		procPriv = nullUint64(b.ProcRes.PrivBytes)
	}

	// The diag blocks. The three frame-derived ones are written whole or not at
	// all, matching how the sensor acquires them — a group is registered when the
	// session opens and either produces every figure in it or none — so each
	// group's columns share one presence and the group's first column is what a
	// reader tests. Zeros inside a present block are measurements: a second in
	// which the game waited on nothing really did wait zero milliseconds.
	var (
		cpuBusyAvg, cpuBusyP95, cpuWaitAvg, cpuWaitP95 sql.NullFloat64
		gpuLatencyAvg, gpuTimeAvg, gpuTimeP95          sql.NullFloat64
		gpuBusyAvg, gpuBusyP95, gpuWaitAvg             sql.NullFloat64
		gpuInPresentAvg, gpuRenderLatencyAvg           sql.NullFloat64
		latDisplayAvg, latAnimErrAvg, latAnimErrP95    sql.NullFloat64
		vramUsed, vramBudget                           sql.NullInt64
	)
	if c := b.CPUSplit; c != nil {
		cpuBusyAvg = nullFloat(c.BusyAvg, true)
		cpuBusyP95 = nullFloat(c.BusyP95, true)
		cpuWaitAvg = nullFloat(c.WaitAvg, true)
		cpuWaitP95 = nullFloat(c.WaitP95, true)
	}
	if g := b.GPUSplit; g != nil {
		gpuLatencyAvg = nullFloat(g.LatencyAvg, true)
		gpuTimeAvg = nullFloat(g.TimeAvg, true)
		gpuTimeP95 = nullFloat(g.TimeP95, true)
		gpuBusyAvg = nullFloat(g.BusyAvg, true)
		gpuBusyP95 = nullFloat(g.BusyP95, true)
		gpuWaitAvg = nullFloat(g.WaitAvg, true)
		gpuInPresentAvg = nullFloat(g.InPresentAvg, true)
		gpuRenderLatencyAvg = nullFloat(g.RenderLatencyAvg, true)
	}
	if l := b.Latency; l != nil {
		latDisplayAvg = nullFloat(l.DisplayAvg, true)
		latAnimErrAvg = nullFloat(l.AnimErrAvg, true)
		latAnimErrP95 = nullFloat(l.AnimErrP95, true)
	}
	// Used is unconditional for a present block — it is what says the read
	// happened — while the budget stays optional, since an OS that does not
	// publish one still leaves the level worth recording.
	if v := b.ProcVRAM; v != nil {
		vramUsed = nullUint64(&v.Used)
		vramBudget = nullUint64(v.Budget)
	}

	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO game_buckets(
			run_id, ts, presented, displayed, dropped, app_frames, generated_frames,
			ft_avg, ft_p50, ft_p95, ft_p99, ft_max, ft_sd,
			hist_layout, hist, disp_ft_avg, disp_ft_p95,
			present_mode, sync_interval, tearing, api, present_changed,
			stutter_count, stutter_excess_ms,
			proc_cpu_pct, proc_ws_bytes, proc_priv_bytes,
			cpu_busy_avg, cpu_busy_p95, cpu_wait_avg, cpu_wait_p95,
			gpu_latency_avg, gpu_time_avg, gpu_time_p95, gpu_busy_avg, gpu_busy_p95,
			gpu_wait_avg, gpu_in_present_avg, gpu_render_latency_avg,
			lat_display_avg, lat_anim_err_avg, lat_anim_err_p95,
			proc_vram_used, proc_vram_budget, quality)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
		       ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		b.RunID, b.TS.Unix(), b.Frames.Presented,
		nullInt(b.Frames.Displayed), nullInt(b.Frames.Dropped),
		nullInt(b.Frames.App), nullInt(b.Frames.Generated),
		b.FT.Avg, b.FT.P50, b.FT.P95, b.FT.P99, b.FT.Max, b.FT.SD,
		b.Hist.Layout, encodeHist(b.Hist.Counts), dispAvg, dispP95,
		mode, sync, tearing, api, presentChanged,
		stutterCount, stutterExcess,
		procCPU, procWS, procPriv,
		cpuBusyAvg, cpuBusyP95, cpuWaitAvg, cpuWaitP95,
		gpuLatencyAvg, gpuTimeAvg, gpuTimeP95, gpuBusyAvg, gpuBusyP95,
		gpuWaitAvg, gpuInPresentAvg, gpuRenderLatencyAvg,
		latDisplayAvg, latAnimErrAvg, latAnimErrP95,
		vramUsed, vramBudget, encodeStrings(b.Quality))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ownedGapRuns is ownedRuns for the run ids gaps name. Separate rather than
// generic over both because a gap's run and a bucket's run are different sets:
// the whole point of a gap is a stretch that produced no bucket, so a packet can
// easily carry a gap whose run no bucket in it mentions.
func ownedGapRuns(ctx context.Context, tx store.Executor, agentID string, gaps []gamesense.Gap) (map[string]bool, error) {
	want := map[string]bool{}
	args := []any{agentID}
	for _, g := range gaps {
		if g.RunID == "" {
			continue
		}
		if _, seen := want[g.RunID]; !seen {
			want[g.RunID] = false
			args = append(args, g.RunID)
		}
	}
	if len(want) == 0 {
		return want, nil
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM game_runs WHERE agent_id=? AND id IN (`+placeholders(len(want))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if _, referenced := want[id]; referenced {
			want[id] = true
		}
	}
	return want, rows.Err()
}

// upsertGap stores one frameless stretch, extending it if a later report has
// seen it grow.
//
// The end takes max() rather than "newest report wins", and the difference is
// what makes an at-least-once uploader safe: a retried batch can carry a copy of
// this interval from before it grew, and last-writer-wins would rewind it. A
// stretch only ever gets longer, so max is also the whole of the merge rule.
//
// The run_id guard mirrors upsertRun's agent_id guard one level down. Ids are
// minted by the agent, and one agent must not be able to re-point another's gap
// at a run of its own by reusing the id.
//
// Nothing here touches game_runs. A gap is evidence the game was NOT presenting,
// so advancing last_seen_at or clearing ended_at over it would make a minimized
// game look alive to the reaper and stretch the run's duration across time no
// frame covered.
func upsertGap(ctx context.Context, tx store.Executor, g gamesense.Gap) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO game_run_gaps(id, run_id, reason, started_at, ended_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			ended_at = max(game_run_gaps.ended_at, excluded.ended_at)
		WHERE game_run_gaps.run_id = excluded.run_id`,
		g.ID, g.RunID, g.Reason, g.StartedAt.Unix(), g.EndedAt.Unix())
	return err
}

// insertHostSecond stores one machine second, reporting whether it was new.
//
// INSERT OR IGNORE on (agent_id, ts) for the reason buckets use it: a replayed
// batch must neither duplicate a second nor rewrite one. It also handles the
// clock stepping backwards, which re-offers a second already stored — the first
// reading wins, which is the one taken while the clock was still monotonic.
//
// Each block's columns are written and left NULL together, and each block's
// first column is what read-back tests. Zeros inside a present block are
// measurements: an idle machine really was at 0%.
func insertHostSecond(ctx context.Context, tx store.Executor, agentID, siteID string, h gamesense.HostSecond) (bool, error) {
	var (
		cpuTotal, cpuBusiest sql.NullFloat64
		cpuMHz, cpuMaxMHz    sql.NullFloat64
		memUsed, memTotal    sql.NullInt64
		gpuUtil              sql.NullFloat64
		gpuMemUsed, gpuMemSz sql.NullInt64
		gpuCoreMHz, gpuMemHz sql.NullFloat64
	)
	if c := h.CPU; c != nil {
		cpuTotal = nullFloat(c.TotalPct, true)
		cpuBusiest = nullFloat(c.BusiestPct, true)
	}
	if c := h.CPUClock; c != nil {
		cpuMHz = nullFloat(c.CurrentMHz, true)
		cpuMaxMHz = nullFloat(c.MaxMHz, true)
	}
	if m := h.Mem; m != nil {
		memUsed = nullUint64(&m.Used)
		memTotal = nullUint64(&m.Total)
	}
	// The adapter block breaks the pairing rule on purpose: which figures a driver
	// publishes varies by vendor and by metric, so each column carries its own
	// presence the way the proc_res readings on a bucket do.
	if g := h.GPU; g != nil {
		if g.UtilPct != nil {
			gpuUtil = nullFloat(*g.UtilPct, true)
		}
		gpuMemUsed = nullUint64(g.MemUsed)
		gpuMemSz = nullUint64(g.MemSize)
		if g.CoreMHz != nil {
			gpuCoreMHz = nullFloat(*g.CoreMHz, true)
		}
		if g.MemMHz != nil {
			gpuMemHz = nullFloat(*g.MemMHz, true)
		}
	}

	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO game_host_seconds(
			agent_id, site_id, ts,
			cpu_total_pct, cpu_busiest_pct, cpu_mhz, cpu_max_mhz,
			mem_used, mem_total,
			gpu_util_pct, gpu_mem_used, gpu_mem_size, gpu_core_mhz, gpu_mem_mhz, quality)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		agentID, siteID, h.TS.Unix(),
		cpuTotal, cpuBusiest, cpuMHz, cpuMaxMHz,
		memUsed, memTotal,
		gpuUtil, gpuMemUsed, gpuMemSz, gpuCoreMHz, gpuMemHz, encodeStrings(h.Quality))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// runDelta is one packet's contribution to a run's stored totals.
type runDelta struct {
	hist               []uint32
	presented          int64
	displayed, dropped int64
	stutterCount       int64
	stutterExcess      float64
	sawDisplayed       bool
	sawDropped         bool
	sawStutter         bool
}

// fold adds one newly stored second to its run's delta.
func fold(deltas map[string]*runDelta, b gamesense.Bucket) {
	d := deltas[b.RunID]
	if d == nil {
		d = &runDelta{hist: make([]uint32, gamesense.HistBins)}
		deltas[b.RunID] = d
	}
	d.presented += int64(b.Frames.Presented)
	// A count this second could not see is a blind spot in the source, not a zero:
	// it contributes nothing AND leaves the run's total absent unless some second
	// could see it. A source that never can must keep NULL, because a zero there
	// reads as a run that dropped no frames.
	if b.Frames.Displayed != nil {
		d.displayed += int64(*b.Frames.Displayed)
		d.sawDisplayed = true
	}
	if b.Frames.Dropped != nil {
		d.dropped += int64(*b.Frames.Dropped)
		d.sawDropped = true
	}
	// The same rule one measurement further out: a second nothing watched for long
	// frames contributes nothing AND leaves the run's totals absent, while a second
	// that watched and saw none contributes its zero and establishes them. Only the
	// second kind can support the sentence "this session never hitched".
	if b.Stutter != nil {
		d.stutterCount += int64(b.Stutter.Count)
		d.stutterExcess += b.Stutter.ExcessMs
		d.sawStutter = true
	}
	// ProcRes is deliberately not folded. CPU is a rate and memory is a level, and
	// neither has a whole-run sum; the run-level questions about them are a peak or
	// an average, which are different figures and are asked of the seconds
	// themselves while those are still there.
	gamesense.HistAdd(d.hist, b.Hist.Counts)
}

// writeAggregates merges each run's delta into the totals stored on its row.
//
// One read-modify-write per run per packet rather than per second, because a
// batch commonly carries a minute of them and the histogram merge cannot be
// expressed in SQL. It runs in the caller's transaction, so a second's row and
// its contribution to the run reach one committed state together — the two can
// never disagree about what has been counted.
func writeAggregates(ctx context.Context, tx store.Executor, deltas map[string]*runDelta) error {
	for id, d := range deltas {
		var (
			presented          int64
			displayed, dropped sql.NullInt64
			stutterCount       sql.NullInt64
			stutterExcess      sql.NullFloat64
			layout             sql.NullString
			blob               []byte
		)
		if err := tx.QueryRowContext(ctx, `
			SELECT presented, displayed, dropped, stutter_count, stutter_excess_ms, hist_layout, hist
			  FROM game_runs WHERE id=?`, id).
			Scan(&presented, &displayed, &dropped, &stutterCount, &stutterExcess, &layout, &blob); err != nil {
			return err
		}
		a := newRunAggregate(presented, displayed, dropped, layout, blob)

		merged := make([]uint32, gamesense.HistBins)
		gamesense.HistAdd(merged, a.hist)
		gamesense.HistAdd(merged, d.hist)

		// An absent total takes the delta as-is: NULL is "nothing has ever counted
		// this", so the first second that can count it establishes the total rather
		// than adding to a zero that was never measured.
		if d.sawDisplayed {
			a.displayed = sql.NullInt64{Int64: a.displayed.Int64 + d.displayed, Valid: true}
		}
		if d.sawDropped {
			a.dropped = sql.NullInt64{Int64: a.dropped.Int64 + d.dropped, Valid: true}
		}
		// The stutter pair moves together for the same reason it is stored together:
		// the count and the time it cost are one measurement, and a total that had
		// only one of them could not be read as either.
		if d.sawStutter {
			stutterCount = sql.NullInt64{Int64: stutterCount.Int64 + d.stutterCount, Valid: true}
			stutterExcess = sql.NullFloat64{Float64: stutterExcess.Float64 + d.stutterExcess, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE game_runs SET presented=?, displayed=?, dropped=?,
			                     stutter_count=?, stutter_excess_ms=?, hist_layout=?, hist=?
			 WHERE id=?`,
			a.presented+d.presented, a.displayed, a.dropped,
			stutterCount, stutterExcess,
			gamesense.HistLayoutLog24V1, encodeHist(merged), id); err != nil {
			return err
		}
	}
	return nil
}

// mustJSON encodes a capability list, falling back to an empty array. A list that
// cannot be marshalled is not a reason to lose the run.
func mustJSON(ss []string) []byte {
	if len(ss) == 0 {
		return []byte("[]")
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return []byte("[]")
	}
	return b
}
