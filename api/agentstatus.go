// Agent status list + connectivity-alert HTTP handlers (AGENT-001 / AGENT-002).
// handleAgentStatuses returns one batch of every agent's health + resources for a
// site; handleListConnAlerts returns the connectivity-alert history for the site
// or a single agent. Both are read-only and follow the same 503-on-missing-dep /
// truthful-500 conventions as the target-status handler.
package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// handleAgentStatuses returns the whole site's per-agent health + resource
// rollup in one deterministic batch.
func (d Deps) handleAgentStatuses(w http.ResponseWriter, r *http.Request) {
	if d.AgentStatus == nil {
		writeError(w, http.StatusServiceUnavailable, "agent status not available")
		return
	}
	res, err := d.AgentStatus.SiteAgentStatuses(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleListConnAlerts returns connectivity alerts. Query params: status
// (firing|resolved|all, default firing), agent (single-agent scope), limit
// (<=500, default 50). Without an agent it scopes to the default site.
func (d Deps) handleListConnAlerts(w http.ResponseWriter, r *http.Request) {
	if d.AgentAlert == nil {
		writeError(w, http.StatusServiceUnavailable, "agent alerts not available")
		return
	}
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	alerts, err := d.AgentAlert.ListAlerts(r.Context(), siteParam(r), q.Get("status"), q.Get("agent"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}
