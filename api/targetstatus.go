// Authoritative current target-status HTTP handler (STATUS-001): one session-
// protected batch of every target's current health for a site. It is the single
// source of current target health in the console — the browser never re-infers
// up/down from metric samples.
package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/targetstatus"
)

// handleTargetStatuses returns the whole site's authoritative current target
// status in one deterministic batch. Availability and fluctuation evidence use
// the page-wide time range. An unknown site is a 404; any dependency or query
// failure is a truthful 500 (never a partial or empty 200).
func (d Deps) handleTargetStatuses(w http.ResponseWriter, r *http.Request) {
	if d.TargetStatus == nil {
		writeError(w, http.StatusServiceUnavailable, "target status not available")
		return
	}
	win, ok := timeRange(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "window must be 3h, 24h, 7d, 30d or 90d")
		return
	}
	res, err := d.TargetStatus.SiteStatuses(r.Context(), chi.URLParam(r, "id"), win)
	if errors.Is(err, targetstatus.ErrSiteNotFound) {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
