// Operational-issue and live-update HTTP handlers: the deduplicated list of
// monitors that are not running (operational_issues), the per-(agent, monitor)
// status views, and the Server-Sent Events stream that pushes fresh issue state
// to connected consoles. All are session-protected and read from the opissue
// engine; issues never enter alert/incident evaluation.
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/opissue"
	"github.com/nettact/server-core/sse"
)

// pingInterval is how often the SSE stream emits a comment ping so idle
// connections (and intermediary proxies) stay open.
const ssePingInterval = 25 * time.Second

func (d Deps) handleListIssues(w http.ResponseWriter, r *http.Request) {
	if d.OpIssue == nil {
		writeError(w, http.StatusServiceUnavailable, "issues not available")
		return
	}
	siteID := siteParam(r)
	issues, err := d.OpIssue.ListForConsole(r.Context(), siteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	unread, err := d.OpIssue.UnreadCount(r.Context(), siteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if issues == nil {
		issues = []opissue.Issue{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": issues, "unread_count": unread})
}

func (d Deps) handleMarkIssuesRead(w http.ResponseWriter, r *http.Request) {
	if d.OpIssue == nil {
		writeError(w, http.StatusServiceUnavailable, "issues not available")
		return
	}
	var body struct {
		IDs []string `json:"ids"` // empty = mark all active issues of the site read
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if err := d.OpIssue.MarkRead(r.Context(), siteParam(r), body.IDs); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleIssuesUnreadCount(w http.ResponseWriter, r *http.Request) {
	if d.OpIssue == nil {
		writeError(w, http.StatusServiceUnavailable, "issues not available")
		return
	}
	n, err := d.OpIssue.UnreadCount(r.Context(), siteParam(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"unread_count": n})
}

func (d Deps) handleAgentIssues(w http.ResponseWriter, r *http.Request) {
	if d.OpIssue == nil {
		writeError(w, http.StatusServiceUnavailable, "issues not available")
		return
	}
	issues, err := d.OpIssue.ListForAgent(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if issues == nil {
		issues = []opissue.Issue{}
	}
	writeJSON(w, http.StatusOK, issues)
}

func (d Deps) handleAgentMonitorStatus(w http.ResponseWriter, r *http.Request) {
	if d.OpIssue == nil {
		writeError(w, http.StatusServiceUnavailable, "issues not available")
		return
	}
	rows, err := d.OpIssue.AgentStatuses(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []opissue.MonitorStatusRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleEvents is the Server-Sent Events stream. It multiplexes two live streams
// for the site on one connection: authoritative "issues" snapshots (emitted on
// connect and re-queried on every issue change) and precise
// "target.status.changed" events (written verbatim so the client coalesces a
// batch status refresh). A comment ping every 25s keeps idle connections open. A
// slow client is dropped by the broker (its channel closes) and this handler
// returns, letting the browser's EventSource reconnect.
func (d Deps) handleEvents(w http.ResponseWriter, r *http.Request) {
	if d.SSE == nil || d.OpIssue == nil {
		writeError(w, http.StatusServiceUnavailable, "events not available")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	siteID := siteParam(r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	id, ch := d.SSE.Subscribe(siteID)
	defer d.SSE.Unsubscribe(id)

	// On connect emit only the issues snapshot; the target-status client performs
	// its own initial full fetch over the batch API.
	d.writeIssueSnapshot(w, flusher, r, siteID)

	ping := time.NewTicker(ssePingInterval)
	defer ping.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			_, _ = io.WriteString(w, ": ping\n\n")
			flusher.Flush()
		case ev, open := <-ch:
			if !open {
				return // dropped by the broker (slow consumer)
			}
			switch ev.Name {
			case sse.EventTargetStatusChanged, sse.EventAgentStatusChanged, sse.EventIncidentChanged:
				// Precise payload written verbatim; the client coalesces a batch refresh.
				// Incident events carry {"site_id","incident_id"} so the fault centre and
				// an open incident drawer can refetch the specific incident.
				_, _ = io.WriteString(w, "event: "+ev.Name+"\ndata: ")
				_, _ = w.Write(ev.Data)
				_, _ = io.WriteString(w, "\n\n")
				flusher.Flush()
			default:
				// "issues" (Data nil): re-query and write an authoritative snapshot.
				d.writeIssueSnapshot(w, flusher, r, siteID)
			}
		}
	}
}

// writeIssueSnapshot writes one full-state "issues" event: the site's active
// issues plus the unread count. Idempotent — a client can replace its state
// wholesale on each event.
func (d Deps) writeIssueSnapshot(w http.ResponseWriter, flusher http.Flusher, r *http.Request, siteID string) {
	issues, err := d.OpIssue.ListForConsole(r.Context(), siteID)
	if err != nil {
		return
	}
	if issues == nil {
		issues = []opissue.Issue{}
	}
	unread, _ := d.OpIssue.UnreadCount(r.Context(), siteID)
	b, err := json.Marshal(map[string]any{"issues": issues, "unread_count": unread})
	if err != nil {
		return
	}
	_, _ = io.WriteString(w, "event: issues\ndata: ")
	_, _ = w.Write(b)
	_, _ = io.WriteString(w, "\n\n")
	flusher.Flush()
}
