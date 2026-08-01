package gamedata

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/nettact/protocol/gamesense"
)

// ErrNotFound is returned for a run id that does not exist, so callers can map it
// to a 404 without inspecting driver errors.
var ErrNotFound = errors.New("game run not found")

// RunFilter narrows a run listing. Zero values mean "no constraint".
//
// Since/Until are unix seconds and select runs that OVERLAP the window rather than
// runs that started inside it: a session already in progress when the window opens
// is exactly the one an operator looking at "the last hour" wants to see, and
// bounding started_at alone would hide it.
type RunFilter struct {
	AgentID string
	SiteID  string
	Since   int64
	Until   int64
	// Runs selects by profile stamp: "" / RunsAll for everything, RunsProfiled for
	// sessions that matched a game profile, RunsOther for the ones that matched
	// none. The split exists because the two are different questions — "how did my
	// games run" and "what else was presenting frames on this machine" — and a
	// single list mixing them buries the first under browsers and video players.
	Runs  string
	Limit int // default 50, max 200
}

// RunFilter.Runs values.
const (
	RunsAll      = "all"
	RunsProfiled = "profiled"
	RunsOther    = "other"
)

// RunPage is a listing plus the filter's total match count, which is not
// len(Items) once the limit bites.
type RunPage struct {
	Items []Run `json:"items"`
	Total int   `json:"total"`
}

// ListRuns returns the matching runs newest first, each with its whole-run
// summary.
func (s *Service) ListRuns(ctx context.Context, f RunFilter) (RunPage, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where, args := f.where()
	page := RunPage{Items: []Run{}}

	q := `SELECT COUNT(*) FROM game_runs r`
	if where != "" {
		q += ` WHERE ` + where
	}
	if err := s.db.Read().QueryRowContext(ctx, q, args...).Scan(&page.Total); err != nil {
		return page, err
	}

	q = `SELECT ` + runCols + runFrom
	if where != "" {
		q += ` WHERE ` + where
	}
	q += ` ORDER BY r.started_at DESC, r.id DESC LIMIT ?`
	runs, err := s.queryRuns(ctx, q, append(args, limit)...)
	if err != nil {
		return page, err
	}
	page.Items = runs
	return page, nil
}

// GetRun returns one run and its summary. ErrNotFound when the id is unknown.
func (s *Service) GetRun(ctx context.Context, id string) (Run, error) {
	runs, err := s.queryRuns(ctx, `SELECT `+runCols+runFrom+` WHERE r.id=?`, id)
	if err != nil {
		return Run{}, err
	}
	if len(runs) == 0 {
		return Run{}, ErrNotFound
	}
	return runs[0], nil
}

// DeleteRun removes a run and every bucket under it. The buckets go first and
// explicitly rather than by relying on the cascade, so the delete does not depend
// on a connection-level pragma being set.
func (s *Service) DeleteRun(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM game_buckets WHERE run_id=?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM game_runs WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

const runCols = `r.id, r.agent_id, r.site_id, r.proc, r.title, r.profile_id, gp.name,
	r.started_at, r.last_seen_at, r.ended_at, r.source, r.caps,
	r.presented, r.displayed, r.dropped, r.hist_layout, r.hist,
	r.stutter_count, r.stutter_excess_ms`

// runFrom joins the profile a run was stamped with, when it still exists. The
// join is LEFT and same-site: a deleted profile must leave the run readable with
// its id intact and no name, which is exactly what a stamp outliving its
// configuration looks like.
const runFrom = ` FROM game_runs r LEFT JOIN game_profiles gp ON gp.id = r.profile_id AND gp.site_id = r.site_id`

func (f RunFilter) where() (string, []any) {
	var where []string
	var args []any
	if f.AgentID != "" {
		where = append(where, "r.agent_id=?")
		args = append(args, f.AgentID)
	}
	if f.SiteID != "" {
		where = append(where, "r.site_id=?")
		args = append(args, f.SiteID)
	}
	if f.Since > 0 {
		where = append(where, "r.last_seen_at >= ?")
		args = append(args, f.Since)
	}
	if f.Until > 0 {
		where = append(where, "r.started_at < ?")
		args = append(args, f.Until)
	}
	switch f.Runs {
	case RunsProfiled:
		where = append(where, "r.profile_id IS NOT NULL")
	case RunsOther:
		where = append(where, "r.profile_id IS NULL")
	}
	return strings.Join(where, " AND "), args
}

func (s *Service) queryRuns(ctx context.Context, q string, args ...any) ([]Run, error) {
	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var (
			r                      Run
			profileID, profileName sql.NullString
			started, lastSeen      int64
			ended                  sql.NullInt64
			caps                   string
			presented              int64
			displayed, dropped     sql.NullInt64
			layout                 sql.NullString
			blob                   []byte
			stutterCount           sql.NullInt64
			stutterExcess          sql.NullFloat64
		)
		if err := rows.Scan(&r.ID, &r.AgentID, &r.SiteID, &r.Proc, &r.Title, &profileID, &profileName,
			&started, &lastSeen, &ended, &r.Source, &caps,
			&presented, &displayed, &dropped, &layout, &blob,
			&stutterCount, &stutterExcess); err != nil {
			return nil, err
		}
		r.ProfileID = strPtr(profileID)
		r.ProfileName = strPtr(profileName)
		r.StartedAt = unixTime(started)
		r.LastSeenAt = unixTime(lastSeen)
		if ended.Valid {
			t := unixTime(ended.Int64)
			r.EndedAt = &t
		}
		r.Caps = decodeStrings(caps)
		if r.Caps == nil {
			r.Caps = []string{}
		}
		// Straight off the run row rather than through runAggregate: the aggregate
		// exists to turn the merged histogram into the FPS figures, and these two are
		// already the answer, folded at ingest and stored as they will be reported.
		r.StutterCount = int64Ptr(stutterCount)
		r.StutterExcessMs = float64Ptr(stutterExcess)
		r.Summary = newRunAggregate(presented, displayed, dropped, layout, blob).summary(r)
		out = append(out, r)
	}
	return out, rows.Err()
}

// runAggregate is a run's whole-run totals as stored on the run row, where ingest
// folds each second in as it lands.
//
// The histograms are merged rather than the per-second percentiles averaged,
// because a mean of per-second p95s is not the run's p95 — it is not any number.
// The merge happens once per second on the way in instead of on every read: the
// seconds are deleted months before the run row is, so a total recomputed from
// whatever buckets survive would empty itself out from under a run that is still
// there, and listing a page of runs would cost a scan of every second beneath
// them.
type runAggregate struct {
	presented          int64
	displayed, dropped sql.NullInt64
	layout             string
	hist               []uint32
}

func newRunAggregate(presented int64, displayed, dropped sql.NullInt64, layout sql.NullString, blob []byte) runAggregate {
	a := runAggregate{presented: presented, displayed: displayed, dropped: dropped, layout: layout.String}
	// Counts recorded under a layout this build does not know are left out of every
	// figure derived from them: their bin edges mean something else, and applying
	// this build's would report frame times nobody measured.
	if a.layout == gamesense.HistLayoutLog24V1 {
		a.hist = decodeHist(blob)
	}
	return a
}

// recorded reports whether any second of frames was ever folded in. The layout is
// the discriminator — it is written with the first fold and never cleared —
// because presented is a count, and a count of zero cannot tell a run that
// recorded nothing apart from one whose seconds presented nothing.
func (a runAggregate) recorded() bool { return a.layout != "" }

// summary renders the stored totals. Every figure the histogram cannot support is
// omitted rather than defaulted — see the Summary doc for why a zero here would be
// a lie rather than an approximation.
func (a runAggregate) summary(r Run) Summary {
	s := Summary{
		DurationSeconds: a.duration(r),
		Presented:       a.presented,
		Displayed:       int64Ptr(a.displayed),
		Dropped:         int64Ptr(a.dropped),
	}
	if v, ok := gamesense.HistMeanFPS(a.hist); ok {
		s.MeanFPS = floatPtr(v)
	}
	if v, ok := gamesense.HistLowFPS(a.hist, 0.01); ok {
		s.Low1PctFPS = floatPtr(v)
	}
	if v, ok := gamesense.HistLowFPS(a.hist, 0.001); ok {
		s.Low01PctFPS = floatPtr(v)
	}
	return s
}

// duration counts both end seconds rather than the interval between them.
//
// A run that recorded frames is stamped from the seconds themselves: the agent
// opens a run at its first bucket when frames arrive before a status, and always
// ends it at the last bucket's timestamp. Both name a second that was captured, so
// the run spans them inclusive — measuring end minus start alone reports a
// one-second run as zero and N consecutive seconds as N-1.
//
// A run that recorded no seconds has no such second to include. Its stamps come
// from the agent's clock when tracking started and stopped, which is already an
// elapsed time and must not be widened.
func (a runAggregate) duration(r Run) int64 {
	end := r.LastSeenAt
	if r.EndedAt != nil {
		end = *r.EndedAt
	}
	d := int64(end.Sub(r.StartedAt).Seconds())
	if d < 0 {
		d = 0
	}
	if a.recorded() {
		d++
	}
	return d
}

// BucketFilter bounds a run's per-second buckets for charting. Since/Until are
// unix seconds over the bucket timestamps.
type BucketFilter struct {
	Since int64
	Until int64
	Limit int // default 3600 (an hour of seconds), max 86400
}

// ListBuckets returns a run's seconds in time order, in the same shape the agent
// uploaded them. Reusing gamesense.Bucket rather than restating its fields is what
// guarantees a nil measurement stays nil across the round trip: there is only one
// definition of which fields are optional.
func (s *Service) ListBuckets(ctx context.Context, runID string, f BucketFilter) ([]gamesense.Bucket, error) {
	limit := f.Limit
	if limit <= 0 || limit > 86400 {
		limit = 3600
	}
	q := `SELECT ts, presented, displayed, dropped, app_frames, generated_frames,
		         ft_avg, ft_p50, ft_p95, ft_p99, ft_max, ft_sd,
		         hist_layout, hist, disp_ft_avg, disp_ft_p95,
		         present_mode, sync_interval, tearing, api, present_changed,
		         stutter_count, stutter_excess_ms,
		         proc_cpu_pct, proc_ws_bytes, proc_priv_bytes,
		         cpu_busy_avg, cpu_busy_p95, cpu_wait_avg, cpu_wait_p95,
		         gpu_latency_avg, gpu_time_avg, gpu_time_p95, gpu_busy_avg, gpu_busy_p95,
		         gpu_wait_avg, gpu_in_present_avg, gpu_render_latency_avg,
		         lat_display_avg, lat_anim_err_avg, lat_anim_err_p95,
		         gpu_util_pct, gpu_mem_used, gpu_mem_size,
		         proc_vram_used, proc_vram_budget, busiest_core_pct, quality
		    FROM game_buckets WHERE run_id=?`
	args := []any{runID}
	if f.Since > 0 {
		q += ` AND ts >= ?`
		args = append(args, f.Since)
	}
	if f.Until > 0 {
		q += ` AND ts < ?`
		args = append(args, f.Until)
	}
	q += ` ORDER BY ts LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gamesense.Bucket{}
	for rows.Next() {
		var (
			b                             gamesense.Bucket
			ts                            int64
			displayed, dropped, app, gen  sql.NullInt64
			blob                          []byte
			dispAvg, dispP95              sql.NullFloat64
			mode, api, quality            sql.NullString
			sync, tearing, presentChanged sql.NullInt64
			stutterCount                  sql.NullInt64
			stutterExcess, procCPU        sql.NullFloat64
			procWS, procPriv              sql.NullInt64

			cpuBusyAvg, cpuBusyP95, cpuWaitAvg, cpuWaitP95 sql.NullFloat64
			gpuLatencyAvg, gpuTimeAvg, gpuTimeP95          sql.NullFloat64
			gpuBusyAvg, gpuBusyP95, gpuWaitAvg             sql.NullFloat64
			gpuInPresentAvg, gpuRenderLatencyAvg           sql.NullFloat64
			latDisplayAvg, latAnimErrAvg, latAnimErrP95    sql.NullFloat64
			gpuUtilPct                                     sql.NullFloat64
			gpuMemUsed, gpuMemSize                         sql.NullInt64
			vramUsed, vramBudget                           sql.NullInt64
			busiestCore                                    sql.NullFloat64
		)
		if err := rows.Scan(&ts, &b.Frames.Presented, &displayed, &dropped, &app, &gen,
			&b.FT.Avg, &b.FT.P50, &b.FT.P95, &b.FT.P99, &b.FT.Max, &b.FT.SD,
			&b.Hist.Layout, &blob, &dispAvg, &dispP95,
			&mode, &sync, &tearing, &api, &presentChanged,
			&stutterCount, &stutterExcess,
			&procCPU, &procWS, &procPriv,
			&cpuBusyAvg, &cpuBusyP95, &cpuWaitAvg, &cpuWaitP95,
			&gpuLatencyAvg, &gpuTimeAvg, &gpuTimeP95, &gpuBusyAvg, &gpuBusyP95,
			&gpuWaitAvg, &gpuInPresentAvg, &gpuRenderLatencyAvg,
			&latDisplayAvg, &latAnimErrAvg, &latAnimErrP95,
			&gpuUtilPct, &gpuMemUsed, &gpuMemSize,
			&vramUsed, &vramBudget, &busiestCore, &quality); err != nil {
			return nil, err
		}
		b.RunID = runID
		b.TS = unixTime(ts)
		b.Frames.Displayed = intPtr(displayed)
		b.Frames.Dropped = intPtr(dropped)
		b.Frames.App = intPtr(app)
		b.Frames.Generated = intPtr(gen)
		b.Hist.Counts = decodeHist(blob)
		if dispAvg.Valid || dispP95.Valid {
			b.DispFT = &gamesense.DispFT{Avg: dispAvg.Float64, P95: dispP95.Float64}
		}
		// present_changed is the discriminator: it is non-NULL exactly when a
		// presentation block was recorded, so an absent one stays absent even though
		// every field inside it may legitimately be empty.
		if presentChanged.Valid {
			b.Present = &gamesense.Present{
				Mode:    mode.String,
				Sync:    intPtr(sync),
				Tearing: boolPtr(tearing),
				API:     api.String,
				Changed: presentChanged.Int64 != 0,
			}
		}
		// stutter_count is the discriminator for its own block, the way
		// present_changed is for the presentation one: the pair is written together,
		// so a NULL count means nothing watched rather than nothing happened.
		if stutterCount.Valid {
			b.Stutter = &gamesense.Stutter{
				Count:    int(stutterCount.Int64),
				ExcessMs: stutterExcess.Float64,
			}
		}
		// The resource block has no such column, and needs none: its three readings
		// are independent, so ANY of them being present is what says the block was
		// there. One that carried no reading at all said nothing, and comes back as
		// the absence it was.
		if procCPU.Valid || procWS.Valid || procPriv.Valid {
			b.ProcRes = &gamesense.ProcRes{
				CPUPct:    float64Ptr(procCPU),
				WSBytes:   uint64Ptr(procWS),
				PrivBytes: uint64Ptr(procPriv),
			}
		}
		// The diag blocks, each rebuilt on its own discriminator. The three
		// frame-derived ones were written whole, so their first column answers for the
		// group — and every figure inside comes back as stored, zeros included: a
		// second whose frames waited on nothing measured a real zero, and dropping the
		// block over it would erase the very finding "this second was not GPU-bound".
		if cpuBusyAvg.Valid {
			b.CPUSplit = &gamesense.CPUSplit{
				BusyAvg: cpuBusyAvg.Float64, BusyP95: cpuBusyP95.Float64,
				WaitAvg: cpuWaitAvg.Float64, WaitP95: cpuWaitP95.Float64,
			}
		}
		if gpuLatencyAvg.Valid {
			b.GPUSplit = &gamesense.GPUSplit{
				LatencyAvg: gpuLatencyAvg.Float64,
				TimeAvg:    gpuTimeAvg.Float64, TimeP95: gpuTimeP95.Float64,
				BusyAvg: gpuBusyAvg.Float64, BusyP95: gpuBusyP95.Float64,
				WaitAvg:          gpuWaitAvg.Float64,
				InPresentAvg:     gpuInPresentAvg.Float64,
				RenderLatencyAvg: gpuRenderLatencyAvg.Float64,
			}
		}
		if latDisplayAvg.Valid {
			b.Latency = &gamesense.Latency{
				DisplayAvg: latDisplayAvg.Float64,
				AnimErrAvg: latAnimErrAvg.Float64,
				AnimErrP95: latAnimErrP95.Float64,
			}
		}
		// Adapter telemetry has no discriminator column and needs none, exactly like
		// the resource block above: its three readings are independent, so ANY of them
		// says the poll happened. A poll that returned nothing at all told us nothing
		// and comes back as the absence it was — which is also what an agent without
		// game.gpu.read stores.
		if gpuUtilPct.Valid || gpuMemUsed.Valid || gpuMemSize.Valid {
			b.GPUTel = &gamesense.GPUTel{
				UtilPct: float64Ptr(gpuUtilPct),
				MemUsed: uint64Ptr(gpuMemUsed),
				MemSize: uint64Ptr(gpuMemSize),
			}
		}
		// The used level is the block: a budget alone would describe headroom against
		// an unknown occupancy, which is not a reading of anything.
		if vramUsed.Valid {
			b.ProcVRAM = &gamesense.ProcVRAM{
				Used:   uint64(vramUsed.Int64),
				Budget: uint64Ptr(vramBudget),
			}
		}
		b.BusiestCorePct = float64Ptr(busiestCore)
		b.Quality = decodeStrings(quality.String)
		out = append(out, b)
	}
	return out, rows.Err()
}

// placeholders returns "?,?,…" with n placeholders for an IN clause.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
