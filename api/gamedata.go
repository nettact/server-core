package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/gamedata"
)

// ---- game presentation history ----
//
// Runs and their per-second buckets are read separately: a run list is a page of
// summaries an operator scans, while a bucket range is chart data for exactly one
// of them. Serving both from one endpoint would mean either sending hours of
// seconds nobody asked for, or making the summary optional on the surface that
// exists to show it.

// handleListGameRuns lists an agent's game runs newest first. The optional
// since/until pair (unix seconds) selects runs OVERLAPPING that window, so a
// session still in progress when the window opened is included.
//
// runs=all|profiled|other splits the list by whether the session matched a game
// profile. An unrecognized value is refused rather than silently treated as
// "all": a console asking for one half of the data and being handed both would
// present other processes as games without anything saying so.
func (d Deps) handleListGameRuns(w http.ResponseWriter, r *http.Request) {
	if d.GameData == nil {
		writeError(w, http.StatusServiceUnavailable, "game data not available")
		return
	}
	q := r.URL.Query()
	f := gamedata.RunFilter{
		AgentID: chi.URLParam(r, "id"),
		SiteID:  siteParam(r),
	}
	switch runs := q.Get("runs"); runs {
	case "", gamedata.RunsAll:
	case gamedata.RunsProfiled, gamedata.RunsOther:
		f.Runs = runs
	default:
		writeError(w, http.StatusBadRequest, "runs must be all, profiled or other")
		return
	}
	if n, err := strconv.ParseInt(q.Get("since"), 10, 64); err == nil && n > 0 {
		f.Since = n
	}
	if n, err := strconv.ParseInt(q.Get("until"), 10, 64); err == nil && n > 0 {
		f.Until = n
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		f.Limit = n
	}
	page, err := d.GameData.ListRuns(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (d Deps) handleGetGameRun(w http.ResponseWriter, r *http.Request) {
	run, ok := d.gameRun(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// handleGameRunBuckets returns one run's seconds in time order for charting, in
// the same shape the agent uploaded them — including which measurements the
// source could not make, which stay null rather than becoming zero.
func (d Deps) handleGameRunBuckets(w http.ResponseWriter, r *http.Request) {
	run, ok := d.gameRun(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var f gamedata.BucketFilter
	if n, err := strconv.ParseInt(q.Get("since"), 10, 64); err == nil && n > 0 {
		f.Since = n
	}
	if n, err := strconv.ParseInt(q.Get("until"), 10, 64); err == nil && n > 0 {
		f.Until = n
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		f.Limit = n
	}
	buckets, err := d.GameData.ListBuckets(r.Context(), run.ID, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, buckets)
}

func (d Deps) handleDeleteGameRun(w http.ResponseWriter, r *http.Request) {
	run, ok := d.gameRun(w, r)
	if !ok {
		return
	}
	if err := d.GameData.DeleteRun(r.Context(), run.ID); err != nil {
		if errors.Is(err, gamedata.ErrNotFound) {
			writeError(w, http.StatusNotFound, "game run not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "game_run.delete", run.ID, run.Proc+" · "+run.Title)
	w.WriteHeader(http.StatusNoContent)
}

// gameRun loads the addressed run and enforces site ownership, writing the
// response and returning false when it cannot. Every run-scoped handler goes
// through it so the ownership check cannot be forgotten on one of them.
func (d Deps) gameRun(w http.ResponseWriter, r *http.Request) (gamedata.Run, bool) {
	if d.GameData == nil {
		writeError(w, http.StatusServiceUnavailable, "game data not available")
		return gamedata.Run{}, false
	}
	run, err := d.GameData.GetRun(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, gamedata.ErrNotFound) {
			writeError(w, http.StatusNotFound, "game run not found")
			return gamedata.Run{}, false
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return gamedata.Run{}, false
	}
	if run.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "game run not found")
		return gamedata.Run{}, false
	}
	return run, true
}
