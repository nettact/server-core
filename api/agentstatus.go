// Agent status list HTTP handler (AGENT-001). handleAgentStatuses returns one
// batch of every agent's health + resources for a site. It is read-only and
// follows the same 503-on-missing-dep / truthful-500 conventions as the
// target-status handler.
//
// Agent connectivity history has no handler of its own any more: an offline
// Agent produces an ordinary fault signal, so it is served by /fault-signals
// with ?detector=agent_connectivity.
package api

import (
	"net/http"

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
