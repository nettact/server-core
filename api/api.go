// Package api exposes the HTTP surface (chi router + handlers), reusable by the
// future cloud server. M2 adds real auth: a single-user session (HttpOnly
// cookie) for the UI and ed25519 enrollment for agents. Telemetry and the
// config downlink ride the persistent agent WebSocket (package agentws),
// mounted here at /agent/ws.
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/agentws"
	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/hostlive"
	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/incident"
	"github.com/nettact/server-core/inventory"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/opissue"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/rules"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/site"
	"github.com/nettact/server-core/sse"

	neturl "net/url"
)

const sessionCookie = "nettact_session"

// Deps are the services the HTTP layer needs.
type Deps struct {
	Identity     *identity.Service
	Registry     *registry.Service
	Metrics      *metrics.Store
	Config       *config.Service
	Site         *site.Service
	Inventory    *inventory.Service
	Rules        *rules.Service
	Alert        *alert.Service
	Incident     *incident.Service
	Notification *notification.Service
	Settings     *settings.Service
	Audit        *audit.Service
	HostLive     *hostlive.Store  // in-memory live process/connection snapshots (never persisted)
	OpIssue      *opissue.Service // operational-issue engine (monitor status + issues)
	SSE          *sse.Broker      // Server-Sent Events fan-out for live issue updates
	AgentWS      *agentws.Hub     // persistent agent WebSocket channel (telemetry + config downlink)
	Bus          *eventbus.Bus    // TopicConfigChanged for config mutations outside config.Service (group scope edits)
	SPA          http.Handler     // optional embedded web UI (served for non-/api routes)
	Dev          bool             // relax CORS for the Vite origin
	SecureCookie bool             // set Secure on the session cookie (production/HTTPS)
}

func Router(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	if d.Dev {
		r.Use(devCORS)
	}

	r.Route("/api/v1", func(r chi.Router) {
		// public / agent-facing
		r.Get("/healthz", d.handleHealthz)
		r.Post("/auth/login", d.handleLogin)
		r.Post("/enroll", d.handleEnroll)
		r.Get("/agent/ws", d.AgentWS.HandleUpgrade)

		// session-protected UI
		r.Group(func(r chi.Router) {
			r.Use(d.requireSession)
			r.Post("/auth/logout", d.handleLogout)
			r.Get("/auth/me", d.handleMe)
			r.Get("/server-info", d.handleServerInfo)
			r.Get("/quota", d.handleQuota)
			r.Get("/stats", d.handleStats)
			r.Get("/sites", d.handleListSites)
			r.Get("/agents", d.handleListAgents)
			r.Get("/agents/{id}", d.handleGetAgent)
			r.Put("/agents/{id}", d.handleUpdateAgent)
			r.Delete("/agents/{id}", d.handleDeleteAgent)
			r.Get("/agents/{id}/metrics", d.handleAgentMetrics)
			r.Get("/agents/{id}/latest", d.handleAgentLatest)
			r.Get("/agents/{id}/interfaces", d.handleAgentInterfaces)
			r.Get("/agents/{id}/series", d.handleAgentSeries)
			r.Get("/agents/{id}/status-history", d.handleAgentStatusHistory)
			r.Get("/agents/{id}/alerts", d.handleAgentAlerts)
			r.Get("/agents/{id}/issues", d.handleAgentIssues)
			r.Get("/agents/{id}/monitor-status", d.handleAgentMonitorStatus)
			// Live host snapshot (ephemeral process/connection lists): POST asks the
			// agent, GET polls for the result. Never stored.
			r.Post("/agents/{id}/snapshot", d.handleRequestSnapshot)
			r.Get("/agents/{id}/snapshot", d.handleGetSnapshot)
			r.Get("/enrollment-tokens", d.handleListTokens)
			r.Post("/enrollment-tokens", d.handleCreateToken)
			r.Get("/sites/{id}/targets", d.handleListTargets)
			r.Put("/sites/{id}/targets", d.handleSetTargets)
			r.Post("/sites/{id}/purge-target", d.handlePurgeTarget)
			r.Get("/sites/{id}/devices", d.handleListDevices)
			// Operational issues (monitors not running under the agent's permission
			// policy). Kept separate from alerts/incidents (never alerted on).
			r.Get("/issues", d.handleListIssues)
			r.Post("/issues/mark-read", d.handleMarkIssuesRead)
			r.Get("/issues/unread-count", d.handleIssuesUnreadCount)
			r.Get("/targets/{id}/agent-status", d.handleTargetAgentStatus)
			// Server-Sent Events stream for live issue updates.
			r.Get("/events", d.handleEvents)
			// Agent groups: named sets of agents that scope monitoring targets.
			r.Get("/sites/{id}/agent-groups", d.handleListAgentGroups)
			r.Post("/sites/{id}/agent-groups", d.handleCreateAgentGroup)
			r.Put("/agent-groups/{id}", d.handleUpdateAgentGroup)
			r.Delete("/agent-groups/{id}", d.handleDeleteAgentGroup)
			r.Get("/incidents", d.handleListIncidents)
			r.Get("/incidents/{id}/timeline", d.handleTimeline)
			r.Get("/alerts", d.handleListAlerts)
			// Alarm rules are configured per monitoring target.
			r.Get("/targets/{id}/rules", d.handleListTargetRules)
			r.Post("/targets/{id}/rules", d.handleCreateTargetRule)
			r.Put("/rules/{id}", d.handleUpdateRule)
			r.Delete("/rules/{id}", d.handleDeleteRule)
			r.Get("/channels", d.handleListChannels)
			r.Post("/channels", d.handleCreateChannel)
			r.Put("/channels/{id}", d.handleUpdateChannel)
			r.Delete("/channels/{id}", d.handleDeleteChannel)
			// Global server settings (e.g. console_base_url for notification links).
			r.Get("/settings", d.handleGetSettings)
			r.Put("/settings", d.handleUpdateSettings)
			r.Get("/dashboard-layout", d.handleGetDashboardLayout)
			r.Put("/dashboard-layout", d.handleUpdateDashboardLayout)
		})
	})

	// Embedded SPA (served for any non-/api path) when provided.
	if d.SPA != nil {
		r.Handle("/*", d.SPA)
	}
	return r
}

func siteParam(r *http.Request) string {
	if s := r.URL.Query().Get("site"); s != "" {
		return s
	}
	return site.DefaultSiteID
}

// ---- auth (UI session) ----

func (d Deps) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, err := d.Identity.Authenticate(r.Context(), body.Username, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	sid, exp, err := d.Identity.CreateSession(r.Context(), u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	SetSessionCookie(w, sid, exp, d.SecureCookie)
	d.Audit.Log(r.Context(), u.Username, "auth.login", "", "")
	writeJSON(w, http.StatusOK, u)
}

// SetSessionCookie writes the canonical session cookie. It is the single source
// of truth for the cookie's attributes (name, Path, HttpOnly, SameSite, Secure,
// Expires): any handler that establishes a session — the password login here or
// a host-driven one-time-token login — must set it through this helper so the
// attributes can never drift apart (a Path/SameSite/HttpOnly mismatch silently
// breaks session reuse).
func SetSessionCookie(w http.ResponseWriter, sid string, exp time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sid, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure, Expires: exp,
	})
}

func (d Deps) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = d.Identity.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleMe(w http.ResponseWriter, r *http.Request) {
	u, _ := d.Identity.ValidateSession(r.Context(), cookieVal(r, sessionCookie))
	writeJSON(w, http.StatusOK, u)
}

// handleServerInfo reports the host OS and whether native desktop notifications
// are available on this build, so the UI can conditionally offer the "system"
// notification channel.
func (d Deps) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"os":            runtime.GOOS,
		"native_notify": notification.NativeSupported(),
	})
}

func (d Deps) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := d.Identity.ValidateSession(r.Context(), cookieVal(r, sessionCookie)); err != nil {
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- enrollment (agent-facing) ----

func (d Deps) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enroll.EnrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid enroll request")
		return
	}
	resp, err := d.Registry.Enroll(r.Context(), req)
	switch {
	case errors.Is(err, registry.ErrQuota):
		writeError(w, http.StatusForbidden, "agent quota reached (max_agents)")
		return
	case errors.Is(err, registry.ErrEnrollToken):
		writeError(w, http.StatusUnauthorized, "invalid or expired enrollment token")
		return
	case errors.Is(err, registry.ErrSignature):
		writeError(w, http.StatusBadRequest, "invalid signature")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), resp.AgentID, "agent.enroll", resp.SiteID, req.Hostname)
	writeJSON(w, http.StatusOK, resp)
}

// ---- live host snapshot (ephemeral, never stored) ----

// handleRequestSnapshot registers a pending live-snapshot request for an agent
// and pushes it down the agent's WebSocket. The scopes are process/connection
// permission IDs; unknown ones are a 400. A disconnected agent is a 409 up front.
// A permission pre-check runs before anything is pushed: if NONE of the requested
// scopes is in the agent's effective policy the request is answered inline (200)
// with per-scope denials + a remediation object and nothing is pushed; otherwise
// the full scope list is pushed and the agent evaluates each scope itself.
func (d Deps) handleRequestSnapshot(w http.ResponseWriter, r *http.Request) {
	if d.HostLive == nil {
		writeError(w, http.StatusServiceUnavailable, "live snapshots not available")
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		Scopes []string `json:"scopes"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	if len(body.Scopes) == 0 {
		writeError(w, http.StatusBadRequest, "scopes required")
		return
	}
	reqSet := permission.FromStrings(body.Scopes)
	for _, sc := range reqSet.Sorted() {
		if !snapshotScopes.Has(sc) {
			writeError(w, http.StatusBadRequest, "unknown snapshot scope: "+string(sc))
			return
		}
	}
	if !d.AgentWS.IsConnected(id) {
		writeError(w, http.StatusConflict, "agent offline")
		return
	}
	a, err := d.Registry.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	effective := permission.FromStrings(a.Effective)
	supported := permission.FromStrings(a.Supported)

	scopes := reqSet.Sorted() // deterministic order
	var precheck []telemetry.SnapshotScopeResult
	var deniedSupported []string // requested, supported, but not granted → env remediation
	anyUnsupported := false
	anyEffective := false
	for _, sc := range scopes {
		if effective.Has(sc) {
			anyEffective = true
			precheck = append(precheck, telemetry.SnapshotScopeResult{Scope: string(sc), Status: telemetry.ScopeCollected})
			continue
		}
		reason := "permission_denied"
		status := telemetry.ScopeDenied
		if supported.Has(sc) {
			deniedSupported = append(deniedSupported, string(sc))
		} else {
			reason = "unsupported"
			status = telemetry.ScopeUnsupported
			anyUnsupported = true
		}
		precheck = append(precheck, telemetry.SnapshotScopeResult{Scope: string(sc), Status: status, Reason: reason})
	}

	// No requested scope is usable: answer inline, record via audit only, push nothing.
	if !anyEffective {
		reason := wire.MonitorStatusUnsupported
		var missing []string
		if len(deniedSupported) > 0 {
			reason = wire.MonitorStatusPermissionBlocked
			missing = deniedSupported
		} else if !anyUnsupported {
			reason = wire.MonitorStatusPermissionBlocked
		}
		rem := opissue.Remediate(reason, missing, a.Granted, "")
		d.Audit.Log(r.Context(), "admin", "snapshot.denied", id, strings.Join(body.Scopes, ","))
		writeJSON(w, http.StatusOK, map[string]any{
			"request_id":  nil,
			"scopes":      precheck,
			"remediation": rem,
		})
		return
	}

	req := d.HostLive.Request(id, body.Scopes)
	// Push directly; a race where the agent dropped between the check above and
	// here is fine — the request is re-pushed if it reconnects while pending,
	// and expires via TTL otherwise.
	d.AgentWS.PushSnapshotRequest(id, req)
	writeJSON(w, http.StatusOK, map[string]any{"request_id": req.RequestID, "precheck": precheck})
}

// snapshotScopes is the allow-list of process/connection permission IDs a live
// snapshot may request. Anything else is a 400.
var snapshotScopes = permission.NewSet(
	permission.HostProcessBasicRead, permission.HostProcessOwnerRead,
	permission.HostProcessResourceRead, permission.HostProcessIORead,
	permission.HostConnectionSummaryRead, permission.HostConnectionLocalRead,
	permission.HostConnectionRemoteRead, permission.HostConnectionOwnerRead,
)

// handleGetSnapshot returns the latest in-memory snapshot for an agent (if fresh)
// and whether a request is still pending, so the console can poll after asking.
func (d Deps) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	if d.HostLive == nil {
		writeError(w, http.StatusServiceUnavailable, "live snapshots not available")
		return
	}
	id := chi.URLParam(r, "id")
	snap, ok, pending := d.HostLive.Latest(id)
	resp := struct {
		Snapshot    *telemetry.HostSnapshot `json:"snapshot"`
		Pending     bool                    `json:"pending"`
		Remediation *opissue.Remediation    `json:"remediation,omitempty"`
	}{Pending: pending}
	if ok {
		resp.Snapshot = &snap
		// Attach a permission remediation for any permission-denied scope in the
		// delivered snapshot, so the console shows the full replacement
		// NETTACT_AGENT_PERMISSIONS line at the exact failure point (not only in the
		// POST all-denied path). Unsupported/failed scopes carry no env line; the
		// console explains those from their scope status.
		var deniedPerms []string
		for _, sr := range snap.Scopes {
			if sr.Status == telemetry.ScopeDenied {
				deniedPerms = append(deniedPerms, sr.Scope)
			}
		}
		if len(deniedPerms) > 0 {
			var granted []string
			if a, err := d.Registry.Get(r.Context(), id); err == nil {
				granted = a.Granted
			}
			resp.Remediation = opissue.Remediate(wire.MonitorStatusPermissionBlocked, deniedPerms, granted, "")
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- UI resources ----

func (d Deps) handleQuota(w http.ResponseWriter, r *http.Request) {
	used, _ := d.Registry.AgentCount(r.Context())
	writeJSON(w, http.StatusOK, map[string]int{"used": used, "max": d.Registry.MaxAgents()})
}

func (d Deps) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := d.Metrics.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (d Deps) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := d.Registry.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if agents == nil {
		agents = []registry.Agent{}
	}
	writeJSON(w, http.StatusOK, agents)
}

func (d Deps) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	a, err := d.Registry.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (d Deps) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := d.Registry.UpdateAgent(r.Context(), id, body.DisplayName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "agent.update", id, body.DisplayName)
	a, err := d.Registry.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (d Deps) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// Evict any live WebSocket session FIRST: it authenticated at upgrade time,
	// so left open it would keep ingesting under the captured identity and could
	// recreate series after the purge below. Disconnect completes the close
	// handshake before returning, so no further packet from this agent lands.
	if d.AgentWS != nil {
		d.AgentWS.Disconnect(id, wire.CloseRevoked, "agent deleted")
	}
	// Purge the agent's time-series (series/samples/rollups + metrics-store cache)
	// BEFORE removing the agent row. If the purge fails we return 500 with the
	// agent still present, so a retry re-purges and then deletes — otherwise the
	// agent row would be gone, the retry would 404, and the series would be
	// orphaned forever, contrary to the endpoint's hard-delete semantics. Purging
	// a non-existent agent is a harmless no-op, so ordering it first is safe.
	if _, err := d.Metrics.PurgeAgent(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Force-resolve any alert this agent has firing BEFORE its rows are purged, so
	// deleting an agent mid-alarm closes the incident as a termination rather than
	// stranding it open or letting an unrelated later recovery false-close it. Runs
	// outside DeleteAgent's transaction (the resolve event's incident handler writes
	// to the DB and SQLite has a single writer); DeleteAgent then removes the rows.
	if d.Alert != nil {
		if err := d.Alert.TerminateForAgent(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := d.Registry.DeleteAgent(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "agent.delete", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) handleAgentMetrics(w http.ResponseWriter, r *http.Request) {
	q := metrics.Query{
		AgentID:   chi.URLParam(r, "id"),
		Kind:      r.URL.Query().Get("kind"),
		Target:    r.URL.Query().Get("target"),
		MonitorID: r.URL.Query().Get("monitor"),
	}
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			q.Limit = n
		}
	}
	if s := r.URL.Query().Get("since_seconds"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			q.SinceUnix = time.Now().Unix() - int64(n)
		}
	}
	points, err := d.Metrics.Query(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if points == nil {
		points = []metrics.Point{}
	}
	writeJSON(w, http.StatusOK, points)
}

// handleAgentLatest returns the newest value per series (one point per target)
// so the dashboard can render current status without pulling full ranges.
// The lookback window defaults to 2h and is overridable via ?since_seconds.
func (d Deps) handleAgentLatest(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Unix() - 2*3600
	if s := r.URL.Query().Get("since_seconds"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			since = time.Now().Unix() - int64(n)
		}
	}
	points, err := d.Metrics.LatestSnapshot(r.Context(), chi.URLParam(r, "id"), since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if points == nil {
		points = []metrics.Point{}
	}
	writeJSON(w, http.StatusOK, points)
}

// handleAgentInterfaces returns the agent's current interface set plus its
// collection-level Wi-Fi verdict and a server-computed freshness flag. Same
// authorization boundary as /latest (session cookie, agent-scoped). stale =
// now − sampled_at > max(3 × effective RegularSeconds, 90s), so pre-disconnect
// SSIDs/numerics can never pose as current.
func (d Deps) handleAgentInterfaces(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	col, ifaces, err := d.Inventory.ListInterfaces(r.Context(), agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	regular := 30 // default regular tier interval (seconds)
	if ds, derr := d.Config.DesiredStateFor(r.Context(), agentID); derr == nil && ds.Intervals.RegularSeconds > 0 {
		regular = ds.Intervals.RegularSeconds
	}
	window := time.Duration(3*regular) * time.Second
	if window < 90*time.Second {
		window = 90 * time.Second
	}
	if col.SampledAt != nil {
		// age > window ⇒ too old; age < -window ⇒ sampled farther in the future
		// than the freshness window (clock skew ahead) ⇒ suspect, treat as stale.
		// Small positive skew within the window stays fresh.
		age := time.Since(*col.SampledAt)
		col.Stale = age > window || age < -window
	} else {
		col.Stale = true // never reported ⇒ not current
	}

	if ifaces == nil {
		ifaces = []inventory.Interface{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"wifi": col, "interfaces": ifaces})
}

// handleAgentSeries lists every series recorded for an agent, so the history
// browser can offer a target selector regardless of recent activity.
func (d Deps) handleAgentSeries(w http.ResponseWriter, r *http.Request) {
	series, err := d.Metrics.ListSeries(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if series == nil {
		series = []metrics.SeriesInfo{}
	}
	writeJSON(w, http.StatusOK, series)
}

func (d Deps) handleListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := d.Site.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sites == nil {
		sites = []site.Site{}
	}
	writeJSON(w, http.StatusOK, sites)
}

func (d Deps) handleListTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := d.Registry.ListEnrollmentTokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if toks == nil {
		toks = []registry.EnrollmentToken{}
	}
	writeJSON(w, http.StatusOK, toks)
}

func (d Deps) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SiteID     string `json:"site_id"`
		Note       string `json:"note"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	if body.SiteID == "" {
		body.SiteID = site.DefaultSiteID
	}
	ttl := time.Duration(body.TTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 60 * time.Minute
	}
	token, err := d.Registry.CreateEnrollmentToken(r.Context(), body.SiteID, body.Note, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "enroll_token.create", body.SiteID, body.Note)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_in_minutes": int(ttl.Minutes())})
}

func (d Deps) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := d.Config.ListSiteTargets(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if targets == nil {
		targets = []config.ProbeTarget{}
	}
	writeJSON(w, http.StatusOK, targets)
}

func (d Deps) handleSetTargets(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Targets []config.ProbeTarget `json:"targets"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	for i := range body.Targets {
		if err := validateTarget(&body.Targets[i]); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	siteID := chi.URLParam(r, "id")
	if err := d.Config.SetSiteTargets(r.Context(), siteID, body.Targets); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Narrowing a target's scope can strand alerts already firing for agents that
	// just left it; resolve them so they don't stay firing forever.
	if err := d.Alert.ResolveOutOfScope(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Same scope narrowing strands operational issues + monitor_status rows for
	// disabled/out-of-scope monitors; reconcile them (offline agents included).
	var warnings []opissue.SaveWarning
	if d.OpIssue != nil {
		if err := d.OpIssue.ReconcileScope(r.Context(), siteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Save-and-warn pre-check: predict which in-scope agents can run each monitor
		// under their current permission policy, upserting predicted monitor_status
		// rows and returning warnings for the ones some/all agents cannot run.
		var perr error
		warnings, perr = d.OpIssue.PredictProbeMonitors(r.Context(), siteID)
		if perr != nil {
			writeError(w, http.StatusInternalServerError, perr.Error())
			return
		}
		// Host monitors are server-authored (never pushed to agents), so a target set
		// that adds/removes/rescopes a host monitor must be reevaluated here.
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), siteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "monitoring.set_targets", siteID, strconv.Itoa(len(body.Targets))+" targets")
	if warnings == nil {
		warnings = []opissue.SaveWarning{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "warnings": warnings})
}

func (d Deps) handleListAgentGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := d.Registry.ListGroups(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if groups == nil {
		groups = []registry.AgentGroup{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (d Deps) handleCreateAgentGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || utf8.RuneCountInString(name) > 128 {
		writeError(w, http.StatusBadRequest, "group name is required (max 128)")
		return
	}
	siteID := chi.URLParam(r, "id")
	id, err := d.Registry.CreateGroup(r.Context(), siteID, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "agent_group.create", siteID, name)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (d Deps) handleUpdateAgentGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Name     string   `json:"name"`
		AgentIDs []string `json:"agent_ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || utf8.RuneCountInString(name) > 128 {
		writeError(w, http.StatusBadRequest, "group name is required (max 128)")
		return
	}
	siteID, err := d.Registry.UpdateGroup(r.Context(), id, name, body.AgentIDs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Agents removed from the group may have alerts still firing for targets scoped
	// to it; resolve any that just went out of scope.
	if err := d.Alert.ResolveOutOfScope(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d.OpIssue != nil {
		if err := d.OpIssue.ReconcileScope(r.Context(), siteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// A membership change can bring a newly in-scope agent (including an offline
		// one) under an existing probe monitor. Predict its status now from the stored
		// permission report so its monitor_status row exists immediately instead of
		// only after the agent reconnects or an unrelated target save runs.
		if _, err := d.OpIssue.PredictProbeMonitors(r.Context(), siteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Group membership changes which agents fall in a host monitor's scope.
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), siteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	// UpdateGroup bumped config_version (membership changes which targets reach
	// which agents); publish so the WS hub pushes the recomputed DesiredState to
	// connected agents now instead of on their next reconnect.
	if d.Bus != nil {
		d.Bus.Publish(eventbus.TopicConfigChanged, eventbus.ConfigChanged{SiteID: siteID})
	}
	d.Audit.Log(r.Context(), "admin", "agent_group.update", id, name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleDeleteAgentGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	siteID, err := d.Registry.DeleteGroup(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Deleting the group drops its target bindings, so targets scoped only to it now
	// reach nobody; resolve any alerts left firing for those targets.
	if err := d.Alert.ResolveOutOfScope(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d.OpIssue != nil {
		if err := d.OpIssue.ReconcileScope(r.Context(), siteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Deleting the group re-scopes its former members; recompute predicted probe
		// status for every still-in-scope agent (offline included) so rows stay
		// consistent without waiting on a reconnect.
		if _, err := d.OpIssue.PredictProbeMonitors(r.Context(), siteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Deleting the group changes host-monitor scope for its former members.
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), siteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	// DeleteGroup bumped config_version (its target bindings are gone); publish
	// so connected agents drop the now-unscoped targets immediately.
	if d.Bus != nil {
		d.Bus.Publish(eventbus.TopicConfigChanged, eventbus.ConfigChanged{SiteID: siteID})
	}
	d.Audit.Log(r.Context(), "admin", "agent_group.delete", id, "")
	w.WriteHeader(http.StatusNoContent)
}

// validKinds is the whitelist of monitoring-target kinds the server accepts.
var validKinds = map[string]bool{"icmp": true, "dns": true, "http": true, "tcp": true, "nat": true, "gateway": true, "host": true}

// validateTarget checks a single monitoring target before it is persisted and
// pushed to agents. It normalizes trivial fields and rejects malformed configs
// with a user-facing message (mirrors the decodeRule validation style).
func validateTarget(t *config.ProbeTarget) error {
	t.Kind = strings.TrimSpace(t.Kind)
	t.Name = strings.TrimSpace(t.Name)
	t.Target = strings.TrimSpace(t.Target)
	if !validKinds[t.Kind] {
		return errors.New("invalid monitor kind: " + t.Kind)
	}
	if utf8.RuneCountInString(t.Name) > 128 {
		return errors.New("name too long (max 128)")
	}
	// Gateway monitors probe the agent's own gateway (resolved from the chosen
	// NIC, or the default NIC when none is given), so there is no user-entered
	// target. Normalize the empty target to a stable "gateway" so the
	// required-target check below passes and the monitor list shows a consistent
	// value; the NIC selection lives in Params.Interface.
	if t.Kind == "gateway" {
		if t.Target == "" {
			t.Target = "gateway"
		}
		// The agent matches Interface exactly against a NIC ID/name, so trim
		// surrounding whitespace ("Wi-Fi " → "Wi-Fi") before it is stored and
		// pushed — otherwise the lookup fails and the probe reports a false 100%
		// loss / gateway-unreachable.
		t.Params.Interface = strings.TrimSpace(t.Params.Interface)
		if utf8.RuneCountInString(t.Params.Interface) > 128 {
			return errors.New("interface name too long (max 128)")
		}
	}
	// Every kind needs a target: probes need something to hit, and a host anchor
	// needs its metric-series target (e.g. "host", "core0", a mount) or the rule
	// engine — which skips rules bound to an empty target — can never match it.
	if t.Target == "" {
		return errors.New("target is required")
	}
	if t.Kind == "tcp" {
		if t.Params.Port < 1 || t.Params.Port > 65535 {
			return errors.New("tcp monitor requires a port in 1-65535")
		}
	}
	if t.Kind == "nat" {
		switch t.Params.NATTransport {
		case "", "udp", "tcp", "tls", "dtls":
		default:
			return errors.New("invalid nat_transport: " + t.Params.NATTransport)
		}
		if t.Params.Port < 0 || t.Params.Port > 65535 {
			return errors.New("nat monitor port out of range (0-65535)")
		}
		// stun_server2 is host[:port] (the agent applies the default STUN port when
		// none is given, like the primary target), so a bare host is valid. A value
		// containing a colon must parse cleanly as host:port with an in-range port —
		// this rejects malformed forms like "host:3478:extra" or "host:abc" rather than
		// silently accepting them as a bare host.
		if s := t.Params.STUNServer2; s != "" && strings.ContainsRune(s, ':') {
			host, port, err := net.SplitHostPort(s)
			if err != nil || host == "" {
				return errors.New("stun_server2 must be host or host:port")
			}
			if p, perr := strconv.Atoi(port); perr != nil || p < 1 || p > 65535 {
				return errors.New("stun_server2 port out of range (1-65535)")
			}
		}
	}
	if t.Params.IntervalSeconds < 0 || t.Params.IntervalSeconds > 86400 {
		return errors.New("interval_seconds out of range (0-86400)")
	}
	if t.Params.TimeoutMs < 0 || t.Params.TimeoutMs > 300000 {
		return errors.New("timeout_ms out of range (0-300000)")
	}
	if t.Params.ResolverPort < 0 || t.Params.ResolverPort > 65535 {
		return errors.New("resolver_port out of range (0-65535)")
	}
	switch t.Params.ResolverProtocol {
	case "", "udp", "tcp":
	case "dot", "doh":
		// DoT/DoH have no system default, so a resolver server/URL is required.
		if t.Params.ResolverServer == "" {
			return errors.New(t.Params.ResolverProtocol + " requires a resolver server")
		}
	default:
		return errors.New("invalid resolver_protocol: " + t.Params.ResolverProtocol)
	}
	if t.Params.AcceptedStatuses != "" {
		if err := validateAcceptedStatuses(t.Params.AcceptedStatuses); err != nil {
			return err
		}
	}
	return nil
}

// validateAcceptedStatuses parses a CSV of HTTP status codes / ranges
// (e.g. "200-299,301,404") and ensures every code sits in 100-599. A non-empty
// expression that yields no codes (e.g. "," or "  ") is rejected, since it would
// otherwise persist and make an HTTP probe reject every response.
func validateAcceptedStatuses(s string) error {
	n := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, ok := strings.Cut(part, "-")
		if !ok {
			hi = lo
		}
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || a < 100 || b > 599 || a > b {
			return errors.New("invalid accepted_statuses: " + s)
		}
		n++
	}
	if n == 0 {
		return errors.New("invalid accepted_statuses: " + s)
	}
	return nil
}

// handlePurgeTarget clears history for exactly one of: a user-created monitor
// (monitor_id — that monitor's series across all agents), or a system-series
// target string (target — e.g. a removed interface; monitor data is never
// touched via the string form, so a shared target can't collateral-damage
// another monitor).
func (d Deps) handlePurgeTarget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MonitorID string `json:"monitor_id"`
		Target    string `json:"target"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil ||
		(body.MonitorID == "") == (body.Target == "") {
		writeError(w, http.StatusBadRequest, "exactly one of monitor_id or target required")
		return
	}
	siteID := chi.URLParam(r, "id")
	var n int
	var err error
	var subject string
	if body.MonitorID != "" {
		subject = body.MonitorID
		n, err = d.Metrics.PurgeMonitor(r.Context(), siteID, body.MonitorID)
	} else {
		subject = body.Target
		n, err = d.Metrics.PurgeTarget(r.Context(), siteID, body.Target)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "metrics.purge_target", subject, strconv.Itoa(n)+" series")
	writeJSON(w, http.StatusOK, map[string]int{"purged_series": n})
}

func (d Deps) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := d.Inventory.ListDevices(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if devices == nil {
		devices = []inventory.Device{}
	}
	writeJSON(w, http.StatusOK, devices)
}

func (d Deps) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := siteParam(r)
	page, pageSize := pageParams(r, 15, 100)
	total, err := d.Incident.Count(ctx, siteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	incs, err := d.Incident.List(ctx, siteID, pageSize, (page-1)*pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if incs == nil {
		incs = []incident.Incident{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": incs, "total": total, "page": page, "page_size": pageSize,
	})
}

// pageParams parses ?page and ?page_size, applying a default size and a hard cap.
func pageParams(r *http.Request, defSize, maxSize int) (page, size int) {
	page = 1
	if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 1 {
		page = v
	}
	size = defSize
	if v, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && v > 0 {
		size = v
	}
	if size > maxSize {
		size = maxSize
	}
	return page, size
}

func (d Deps) handleTimeline(w http.ResponseWriter, r *http.Request) {
	tl, err := d.Incident.Timeline(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tl == nil {
		tl = []incident.TimelineEntry{}
	}
	writeJSON(w, http.StatusOK, tl)
}

// alertView is an active alert plus a human description of the fault, rendered
// in both languages so the console can show "who fired and why" without
// re-implementing the wording client-side.
type alertView struct {
	alert.Alert
	DescZh string `json:"desc_zh"`
	DescEn string `json:"desc_en"`
}

func (d Deps) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := d.Alert.ListActive(r.Context(), siteParam(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]alertView, 0, len(alerts))
	for _, a := range alerts {
		// AgentHost is left off the detail so the description doesn't repeat the
		// host — the console shows it in its own column.
		det := notification.AlertDetail{
			ProbeKind: a.ProbeKind, MetricKind: a.MetricKind, Comparator: a.Comparator,
			Threshold: a.Threshold, Value: a.Value, TargetName: a.TargetName, Target: a.Target,
			Layer: a.Layer, Severity: a.Severity,
		}
		views = append(views, alertView{
			Alert:  a,
			DescZh: notification.DescribeDetail(det, "zh"),
			DescEn: notification.DescribeDetail(det, "en"),
		})
	}
	writeJSON(w, http.StatusOK, views)
}

// handleAgentAlerts returns the alarm history (firing + resolved) for one
// agent, newest first — scoped to a user-created monitor via ?monitor=, or to
// a target string via ?target= (host alerts, whose metrics carry no monitor).
func (d Deps) handleAgentAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	var alerts []alert.Alert
	var err error
	if mon := r.URL.Query().Get("monitor"); mon != "" {
		alerts, err = d.Alert.ListForMonitor(r.Context(), chi.URLParam(r, "id"), mon, limit)
	} else {
		alerts, err = d.Alert.ListForTarget(r.Context(), chi.URLParam(r, "id"), r.URL.Query().Get("target"), limit)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if alerts == nil {
		alerts = []alert.Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

// ---- alarm rules (per monitoring target) ----

func (d Deps) handleListTargetRules(w http.ResponseWriter, r *http.Request) {
	rs, err := d.Rules.ListForTarget(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rs == nil {
		rs = []rules.Rule{}
	}
	writeJSON(w, http.StatusOK, rs)
}

func (d Deps) handleCreateTargetRule(w http.ResponseWriter, r *http.Request) {
	rule, ok := decodeRule(w, r)
	if !ok {
		return
	}
	probeTaskID := chi.URLParam(r, "id")
	id, err := d.Rules.CreateForTarget(r.Context(), siteParam(r), probeTaskID, rule)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// A bound rule defines a host monitor's required host permissions, so its
	// creation can change a host monitor's status; reevaluate the site.
	if d.OpIssue != nil {
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), siteParam(r)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "rule.create", id, probeTaskID)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (d Deps) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	rule, ok := decodeRule(w, r)
	if !ok {
		return
	}
	rule.ID = chi.URLParam(r, "id")
	if err := d.Rules.Update(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d.OpIssue != nil {
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), siteParam(r)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "rule.update", rule.ID, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := d.Rules.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d.OpIssue != nil {
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), siteParam(r)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "rule.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// decodeRule parses a rules.Rule from the request body, applying light defaults.
func decodeRule(w http.ResponseWriter, r *http.Request) (rules.Rule, bool) {
	var rule rules.Rule
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule body")
		return rules.Rule{}, false
	}
	if rule.Name == "" || rule.MetricKind == "" || rule.Comparator == "" {
		writeError(w, http.StatusBadRequest, "name, metric_kind and comparator are required")
		return rules.Rule{}, false
	}
	if rule.Severity == "" {
		rule.Severity = "warn"
	}
	return rule, true
}

// ---- notification channels ----

func (d Deps) handleListChannels(w http.ResponseWriter, r *http.Request) {
	chans, err := d.Notification.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if chans == nil {
		chans = []notification.Channel{}
	}
	writeJSON(w, http.StatusOK, chans)
}

func (d Deps) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string            `json:"name"`
		Type   string            `json:"type"`
		Config map[string]string `json:"config"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil || (body.Type != "webhook" && body.Type != "email" && body.Type != "system") {
		writeError(w, http.StatusBadRequest, "type must be webhook, email or system")
		return
	}
	id, err := d.Notification.Create(r.Context(), body.Name, body.Type, body.Config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "channel.create", body.Type, body.Name)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

// handleGetSettings returns public UI settings as a flat map (e.g.
// {"console_base_url": "http://localhost:8080"}).
func (d Deps) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	all, err := d.Settings.All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for key := range all {
		if !knownSettingKeys[key] {
			delete(all, key)
		}
	}
	writeJSON(w, http.StatusOK, all)
}

// knownSettingKeys is the allow-list of settings the generic settings API may
// expose or write. Internal values such as dashboard layout use dedicated APIs.
var knownSettingKeys = map[string]bool{settings.KeyConsoleBaseURL: true}

// handleUpdateSettings merges the posted keys. Only known keys are accepted;
// console_base_url is validated to be an absolute http(s) origin without a query
// or fragment (or empty to clear it), since a deep-link path is appended to it.
func (d Deps) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	for k := range body {
		if !knownSettingKeys[k] {
			writeError(w, http.StatusBadRequest, "unknown setting: "+k)
			return
		}
	}
	if v, ok := body[settings.KeyConsoleBaseURL]; ok {
		v = strings.TrimSpace(v)
		if v != "" {
			u, err := neturl.Parse(v)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
				writeError(w, http.StatusBadRequest, "console_base_url must be an http(s) URL without a query or fragment")
				return
			}
		}
		body[settings.KeyConsoleBaseURL] = v
	}
	for k, v := range body {
		if err := d.Settings.Set(r.Context(), k, v); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "settings.update", "", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string            `json:"name"`
		Enabled bool              `json:"enabled"`
		Config  map[string]string `json:"config"` // nil/omitted = keep existing
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	id := chi.URLParam(r, "id")
	if err := d.Notification.Update(r.Context(), id, body.Name, body.Enabled, body.Config); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "channel.update", id, body.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	if err := d.Notification.Delete(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleAgentStatusHistory(w http.ResponseWriter, r *http.Request) {
	hist, err := d.Registry.StatusHistory(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hist == nil {
		hist = []registry.StatusEvent{}
	}
	writeJSON(w, http.StatusOK, hist)
}

func (d Deps) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- helpers ----

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

func cookieVal(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func devCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
