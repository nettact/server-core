package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/routehist"
)

// Route-monitor history. All four reads answer 404 for a target that does not
// exist and 400 for one that is not a route monitor, so the console can tell
// "gone" from "wrong page"; an existing monitor with no history yet answers
// empty arrays and current:null rather than an error.

func (d Deps) handleTargetRoute(w http.ResponseWriter, r *http.Request) {
	if d.Routes == nil {
		writeError(w, http.StatusNotFound, "route history unavailable")
		return
	}
	out, err := d.Routes.TargetRoute(r.Context(), chi.URLParam(r, "id"))
	if writeRouteErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (d Deps) handleRouteEpochs(w http.ResponseWriter, r *http.Request) {
	if d.Routes == nil {
		writeError(w, http.StatusNotFound, "route history unavailable")
		return
	}
	qv := r.URL.Query()
	q := routehist.EpochQuery{AgentID: qv.Get("agent_id")}
	var ok bool
	if q.From, ok = parseRouteTime(w, qv.Get("from"), "from"); !ok {
		return
	}
	if q.To, ok = parseRouteTime(w, qv.Get("to"), "to"); !ok {
		return
	}
	if q.Limit, ok = parseRouteLimit(w, qv.Get("limit")); !ok {
		return
	}
	eps, err := d.Routes.Epochs(r.Context(), chi.URLParam(r, "id"), q)
	if writeRouteErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"epochs": eps})
}

func (d Deps) handleRouteChanges(w http.ResponseWriter, r *http.Request) {
	if d.Routes == nil {
		writeError(w, http.StatusNotFound, "route history unavailable")
		return
	}
	qv := r.URL.Query()
	q := routehist.ChangeQuery{AgentID: qv.Get("agent_id")}
	var ok bool
	if q.Before, ok = parseRouteTime(w, qv.Get("before"), "before"); !ok {
		return
	}
	if q.Limit, ok = parseRouteLimit(w, qv.Get("limit")); !ok {
		return
	}
	cs, err := d.Routes.Changes(r.Context(), chi.URLParam(r, "id"), q)
	if writeRouteErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": cs})
}

func (d Deps) handleRouteChange(w http.ResponseWriter, r *http.Request) {
	if d.Routes == nil {
		writeError(w, http.StatusNotFound, "route history unavailable")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "route change not found")
		return
	}
	out, err := d.Routes.ChangeDetail(r.Context(), id)
	if writeRouteErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRouteSummaries serves every enabled route monitor of a site in one
// batch, for a status page that classifies all of them at once. An unknown
// site is 404, like the other site-scoped status reads; a site without route
// monitors answers an empty targets array.
func (d Deps) handleRouteSummaries(w http.ResponseWriter, r *http.Request) {
	if d.Routes == nil {
		writeError(w, http.StatusNotFound, "route history unavailable")
		return
	}
	out, err := d.Routes.SiteSummaries(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, routehist.ErrSiteNotFound) {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	if writeRouteErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// writeRouteErr maps a route-history read error to its status; it reports
// whether it wrote a response.
func writeRouteErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, routehist.ErrTargetNotFound):
		writeError(w, http.StatusNotFound, "target not found")
	case errors.Is(err, routehist.ErrChangeNotFound):
		writeError(w, http.StatusNotFound, "route change not found")
	case errors.Is(err, routehist.ErrNotTraceTarget):
		writeError(w, http.StatusBadRequest, "target is not a route monitor")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
	return true
}

// parseRouteTime parses an optional RFC3339 bound; empty is "unbounded".
func parseRouteTime(w http.ResponseWriter, v, name string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		writeError(w, http.StatusBadRequest, name+" must be an RFC3339 time")
		return time.Time{}, false
	}
	return t, true
}

// parseRouteLimit parses an optional positive limit (0 = the default; values
// above routehist.MaxLimit are clamped by the service).
func parseRouteLimit(w http.ResponseWriter, v string) (int, bool) {
	if v == "" {
		return 0, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		writeError(w, http.StatusBadRequest, "limit must be a positive integer")
		return 0, false
	}
	return n, true
}
