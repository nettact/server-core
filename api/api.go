// Package api exposes the HTTP surface (chi router + handlers), reusable by the
// future cloud server. M2 adds real auth: a single-user session (HttpOnly
// cookie) for the UI and ed25519 enrollment for agents. Telemetry and the
// config downlink ride the persistent agent WebSocket (package agentws),
// mounted here at /agent/ws.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
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
	"github.com/nettact/server-core/agentalert"
	"github.com/nettact/server-core/agentstatus"
	"github.com/nettact/server-core/agentws"
	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/cleanup"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/hostlive"
	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/incident"
	"github.com/nettact/server-core/incidentops"
	"github.com/nettact/server-core/inventory"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/opissue"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/rules"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/site"
	"github.com/nettact/server-core/sse"
	"github.com/nettact/server-core/targetstatus"

	neturl "net/url"
)

const sessionCookie = "nettact_session"

// Deps are the services the HTTP layer needs.
type Deps struct {
	Identity     *identity.Service
	Registry     *registry.Service
	Metrics      *metrics.Store
	Cleanup      *cleanup.Service
	Config       *config.Service
	Site         *site.Service
	Inventory    *inventory.Service
	Rules        *rules.Service
	Alert        *alert.Service
	Incident     *incident.Service
	IncidentOps  *incidentops.Service // incident snapshot + traceroute orchestration reads
	Notification *notification.Service
	Settings     *settings.Service
	Audit        *audit.Service
	HostLive     *hostlive.Store       // in-memory live process/connection snapshots (never persisted)
	OpIssue      *opissue.Service      // operational-issue engine (monitor status + issues)
	TargetStatus *targetstatus.Service // authoritative current target-status aggregation (read-time)
	AgentStatus  *agentstatus.Service  // per-agent health/resource rollup for the Agent status list (read-time)
	AgentAlert   *agentalert.Engine    // agent offline/recovery connectivity-alert engine
	SSE          *sse.Broker           // Server-Sent Events fan-out for live issue + target-status updates
	AgentWS      *agentws.Hub          // persistent agent WebSocket channel (telemetry + config downlink)
	Bus          *eventbus.Bus         // TopicConfigChanged for config mutations outside config.Service (group scope edits)
	SPA          http.Handler          // optional embedded web UI (served for non-/api routes)
	Dev          bool                  // relax CORS for the Vite origin
	SecureCookie bool                  // set Secure on the session cookie (production/HTTPS)

	// ListenStatus reports how the running server is actually bound (nil when the
	// host doesn't provide one, e.g. bare server-core tests).
	ListenStatus func(ctx context.Context) *ListenStatus
	// ApplyListenAddr is non-nil only in desktop mode: it triggers an embedded
	// server restart onto the newly saved listen address (asynchronously, after
	// the settings PUT response is written).
	ApplyListenAddr func(ctx context.Context, addr string) error
}

// ListenStatus describes the server's actual listen binding for server-info.
type ListenStatus struct {
	EffectiveAddr string `json:"effective_addr"`
	Source        string `json:"source"` // "default" | "flag" | "db"
	Desktop       bool   `json:"desktop"`
	PendingAddr   string `json:"pending_addr,omitempty"`  // stored setting differing from the effective bind
	FallbackFrom  string `json:"fallback_from,omitempty"` // configured addr that failed to bind at startup
	OverridesFlag bool   `json:"overrides_flag"`          // Source=="db" while an explicit -addr flag was passed
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
			r.Post("/auth/password", d.handleChangePassword)
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
			r.Get("/agents/{id}/metrics/summary", d.handleAgentMetricsSummary)
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
			// History data cleanup: controlled series inventory, dry-run preview, and
			// async delete jobs (whole series or a time range; one-click orphan cleanup).
			r.Get("/sites/{id}/cleanup/series", d.handleCleanupSeries)
			r.Post("/sites/{id}/cleanup/preview", d.handleCleanupPreview)
			r.Post("/sites/{id}/cleanup/jobs", d.handleCreateCleanupJob)
			r.Get("/sites/{id}/cleanup/jobs", d.handleListCleanupJobs)
			r.Get("/cleanup/jobs/{id}", d.handleGetCleanupJob)
			// Monitor groups own targets, their Agent execution scope and the
			// incident-merge policy shared by all of them.
			r.Get("/sites/{id}/monitor-groups", d.handleListMonitorGroups)
			r.Post("/sites/{id}/monitor-groups", d.handleCreateMonitorGroup)
			r.Put("/monitor-groups/{id}", d.handleUpdateMonitorGroup)
			r.Delete("/monitor-groups/{id}", d.handleDeleteMonitorGroup)
			r.Get("/sites/{id}/devices", d.handleListDevices)
			// Operational issues (monitors not running under the agent's permission
			// policy). Kept separate from alerts/incidents (never alerted on).
			r.Get("/issues", d.handleListIssues)
			r.Post("/issues/mark-read", d.handleMarkIssuesRead)
			r.Get("/issues/unread-count", d.handleIssuesUnreadCount)
			// Authoritative current status for every target of a site, in one batch.
			r.Get("/sites/{id}/target-statuses", d.handleTargetStatuses)
			// Per-agent health + resource rollup for the Agent status list (AGENT-001),
			// and the agent connectivity alert history (AGENT-002).
			r.Get("/sites/{id}/agent-statuses", d.handleAgentStatuses)
			r.Get("/agent-alerts", d.handleListConnAlerts)
			// Server-Sent Events stream for live issue + target-status updates.
			r.Get("/events", d.handleEvents)
			// Agent groups: named sets of agents that scope monitoring targets.
			r.Get("/sites/{id}/agent-groups", d.handleListAgentGroups)
			r.Post("/sites/{id}/agent-groups", d.handleCreateAgentGroup)
			r.Put("/agent-groups/{id}", d.handleUpdateAgentGroup)
			r.Delete("/agent-groups/{id}", d.handleDeleteAgentGroup)
			r.Get("/incidents", d.handleListIncidents)
			r.Get("/incidents/{id}", d.handleGetIncident)
			r.Get("/incidents/{id}/timeline", d.handleTimeline)
			// Incident immutable snapshot, its referenced traceroute reports, and the
			// full shared trace report hops (site-owned, session-protected).
			r.Get("/incidents/{id}/snapshot", d.handleIncidentSnapshot)
			r.Get("/incidents/{id}/traces", d.handleIncidentTraces)
			r.Get("/trace-reports/{id}", d.handleTraceReport)
			r.Get("/alerts", d.handleListAlerts)
			// Group-level one-layer AND/OR alert rules (configured on a monitor group).
			r.Get("/monitor-groups/{id}/rules", d.handleListGroupRules)
			r.Post("/monitor-groups/{id}/rules", d.handleCreateGroupRule)
			r.Put("/group-rules/{id}", d.handleUpdateGroupRule)
			r.Delete("/group-rules/{id}", d.handleDeleteGroupRule)
			r.Get("/channels", d.handleListChannels)
			r.Post("/channels", d.handleCreateChannel)
			r.Post("/channels/test", d.handleTestChannel)
			r.Put("/channels/{id}", d.handleUpdateChannel)
			r.Delete("/channels/{id}", d.handleDeleteChannel)
			r.Post("/channels/{id}/apply-to-all", d.handleApplyChannelToAllRules)
			// Global server settings (e.g. console_base_url for notification links).
			r.Get("/settings", d.handleGetSettings)
			r.Put("/settings", d.handleUpdateSettings)
			r.Get("/dashboard-layout", d.handleGetDashboardLayout)
			r.Put("/dashboard-layout", d.handleUpdateDashboardLayout)
			r.Get("/onboarding", d.handleGetOnboardingState)
			r.Put("/onboarding", d.handleUpdateOnboardingState)
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
	// LoginSession verifies the password and mints the session atomically, so a
	// password change racing this login can't hand out a session for the old
	// password. A bad credential (or a password rotated mid-login) is ErrAuth →
	// 401; anything else is a real server error.
	u, sid, exp, err := d.Identity.LoginSession(r.Context(), body.Username, body.Password)
	if err != nil {
		if errors.Is(err, identity.ErrAuth) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
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

// handleChangePassword rotates the logged-in admin's password. UpdatePassword
// verifies the current password, applies the policy to the new one, swaps the
// hash and revokes every OTHER session — all in one transaction — so any other
// logged-in client is forced to re-authenticate while this session survives.
// Runs under requireSession, so a valid session is guaranteed; the session id is
// re-read here to identify the user and to mark which session to keep.
//
// A wrong old password is 403 "invalid old password" — deliberately distinct
// from requireSession's 401 "login required" so the console can tell "your
// session lapsed, log in again" apart from "that current-password field is
// wrong" and route the user accordingly.
func (d Deps) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	sid := cookieVal(r, sessionCookie)
	u, err := d.Identity.ValidateSession(r.Context(), sid)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "login required")
		return
	}
	switch err := d.Identity.UpdatePassword(r.Context(), u.ID, body.OldPassword, body.NewPassword, sid); {
	case errors.Is(err, identity.ErrAuth):
		writeError(w, http.StatusForbidden, "invalid old password")
		return
	case errors.Is(err, identity.ErrPasswordPolicy):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), u.Username, "auth.password_changed", "", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleMe(w http.ResponseWriter, r *http.Request) {
	u, _ := d.Identity.ValidateSession(r.Context(), cookieVal(r, sessionCookie))
	writeJSON(w, http.StatusOK, u)
}

// handleServerInfo reports the host OS, whether native desktop notifications
// are available on this build, and (when the host provides it) the listen
// binding status so the UI can show effective vs pending listen settings.
func (d Deps) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"os":            runtime.GOOS,
		"native_notify": notification.NativeSupported(),
	}
	if d.ListenStatus != nil {
		ls := d.ListenStatus(r.Context())
		if v, _ := d.Settings.Get(r.Context(), settings.KeyListenAddr); v != "" && v != ls.EffectiveAddr {
			ls.PendingAddr = v
		}
		out["listen"] = ls
	}
	writeJSON(w, http.StatusOK, out)
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
	// Pointer fields distinguish "omitted" from a zero value, so a mute-only
	// patch never clears the display name and vice versa.
	var body struct {
		DisplayName             *string `json:"display_name"`
		ConnectivityAlertsMuted *bool   `json:"connectivity_alerts_muted"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.DisplayName != nil {
		if err := d.Registry.UpdateAgent(r.Context(), id, *body.DisplayName); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusNotFound, "agent not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		d.Audit.Log(r.Context(), "admin", "agent.update", id, *body.DisplayName)
	}
	if body.ConnectivityAlertsMuted != nil {
		if err := d.Registry.SetConnectivityMuted(r.Context(), id, *body.ConnectivityAlertsMuted); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusNotFound, "agent not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Muting closes any firing connectivity alert immediately (no notification);
		// unmuting lets the next engine tick reopen if still offline past grace.
		if d.AgentAlert != nil {
			d.AgentAlert.OnMuteChanged(r.Context(), id, *body.ConnectivityAlertsMuted)
		}
		d.Audit.Log(r.Context(), "admin", "agent.mute", id, strconv.FormatBool(*body.ConnectivityAlertsMuted))
	}
	a, err := d.Registry.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
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
		if err := d.Rules.TerminateForAgent(r.Context(), id); err != nil {
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

// metricsSummaryResponse is the /metrics/summary payload: per-kind aggregates
// plus the window they were computed over.
type metricsSummaryResponse struct {
	WindowSeconds int64                          `json:"window_seconds"`
	Kinds         map[string]metrics.KindSummary `json:"kinds"`
}

// handleAgentMetricsSummary serves latest/P95/avg per kind so stat cards get
// one small response instead of a raw sample window (PERF-001). Aggregates are
// always computed from raw samples (percentiles of rollup bucket averages
// would be wrong), so the window is capped at raw retention — wider requests
// are a client bug and get a 400. Optional `reduce=worst` collapses to the
// per-timestamp worst value across series (dashboard quality cards), and
// `exclude_targets` drops series by target string (e.g. the gateway leg).
func (d Deps) handleAgentMetricsSummary(w http.ResponseWriter, r *http.Request) {
	var kinds []string
	for _, k := range strings.Split(r.URL.Query().Get("kinds"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			kinds = append(kinds, k)
		}
	}
	if len(kinds) == 0 {
		writeError(w, http.StatusBadRequest, "kinds required")
		return
	}
	var exclude []string
	for _, target := range strings.Split(r.URL.Query().Get("exclude_targets"), ",") {
		if target = strings.TrimSpace(target); target != "" {
			exclude = append(exclude, target)
		}
	}
	q := metrics.SummaryQuery{
		AgentID:        chi.URLParam(r, "id"),
		Kinds:          kinds,
		MonitorID:      r.URL.Query().Get("monitor"),
		Target:         r.URL.Query().Get("target"),
		ExcludeTargets: exclude,
		Reduce:         r.URL.Query().Get("reduce"),
		WindowSeconds:  2 * 3600,
	}
	if s := r.URL.Query().Get("since_seconds"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			q.WindowSeconds = int64(n)
		}
	}
	summary, err := d.Metrics.Summarize(r.Context(), q)
	if err != nil {
		if errors.Is(err, metrics.ErrSummaryWindow) || errors.Is(err, metrics.ErrSummaryReduce) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, metricsSummaryResponse{WindowSeconds: q.WindowSeconds, Kinds: summary})
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
			// This endpoint reconciles the WHOLE set, so a rejection can come from a
			// monitor the user is not editing (e.g. one saved before a rule tightened).
			// Name it, or the console reports an error the user cannot locate.
			name := body.Targets[i].Name
			if name == "" {
				name = body.Targets[i].Target
			}
			writeError(w, http.StatusBadRequest, "monitor "+strconv.Quote(name)+": "+err.Error())
			return
		}
	}
	siteID := chi.URLParam(r, "id")
	// ruleCleanups: alert conditions dropped because a kept monitor's kind changed
	// and its new kind can never emit the metric they watched. Surfaced on the
	// response so the console can tell the user which alarms to reconfigure.
	ruleCleanups, err := d.Config.SetSiteTargets(r.Context(), siteID, body.Targets)
	if err != nil {
		// A repeated target id is a malformed payload, not a server fault: answering
		// 500 would tell the client to retry something that can never succeed.
		if errors.Is(err, config.ErrDuplicateTargetID) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The save has COMMITTED — those alarm deletions are permanent. Every step
	// below can still fail with a 500 that carries no body of ours, and the cleanup
	// report exists only in this variable, so record it durably HERE. Otherwise a
	// failing reconcile would silently swallow the one notice telling the user
	// which alarms they must rebuild (a re-save reports nothing: the conditions are
	// already gone).
	for _, c := range ruleCleanups {
		detail := c.MonitorName + " (" + c.OldKind + "→" + c.NewKind + "): rule " + c.RuleName +
			" lost " + strings.Join(c.Metrics, ", ")
		if c.RuleDeleted {
			detail += "; rule deleted (no conditions left)"
		}
		d.Audit.Log(r.Context(), "admin", "monitoring.rule_cleanup", c.MonitorID, detail)
	}
	// Narrowing a target's scope can strand alerts already firing for agents that
	// just left it; resolve them so they don't stay firing forever.
	if err := d.Rules.ResolveOutOfScope(r.Context(), siteID); err != nil {
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
	audited := strconv.Itoa(len(body.Targets)) + " targets"
	if len(ruleCleanups) > 0 {
		audited += "; " + strconv.Itoa(len(ruleCleanups)) + " rule(s) pruned after a monitor kind change"
	}
	d.Audit.Log(r.Context(), "admin", "monitoring.set_targets", siteID, audited)
	if warnings == nil {
		warnings = []opissue.SaveWarning{}
	}
	if ruleCleanups == nil {
		ruleCleanups = []config.RuleCleanup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "warnings": warnings, "rule_cleanups": ruleCleanups})
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
	if err := d.Rules.ResolveOutOfScope(r.Context(), siteID); err != nil {
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
	if err := d.Rules.ResolveOutOfScope(r.Context(), siteID); err != nil {
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

// leadingSchemeRE matches a URL that OPENS with a scheme (RFC 3986 §3.1). It is
// deliberately anchored: a "://" anywhere else belongs to the path or query
// ("example.com/login?next=https://idp"), and treating that as "already schemed"
// would leave the URL scheme-less for the agent.
var leadingSchemeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// opaqueSchemeRE matches a leading scheme whose delimiter is a bare ":" instead
// of "://" — "mailto:user@example.com", "ssh:user@host". These must be rejected
// explicitly: prefixing one with "https://" yields a URL that PARSES, with the
// original scheme swallowed as userinfo ("https://mailto:user@example.com" has
// host "example.com"), so the save would succeed and silently probe a host the
// user never named.
//
// The class after the colon is what keeps a scheme-less authority out: a digit
// means "host:port", and an empty remainder ("host:") is left to the clearer
// trailing-colon check downstream.
var opaqueSchemeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:[^0-9/?#]`)

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
	if t.Kind == "http" {
		// A scheme-less address ("www.example.com") is what a browser address bar
		// accepts, but Go's HTTP client refuses it outright ("unsupported protocol
		// scheme"), so the probe would fail every single cycle and classify as a
		// generic "other" error with nothing pointing at the real cause. Normalize
		// to https:// — the same default a browser applies — and store the
		// normalized form, so the console, the agent, and the alert notice all name
		// the exact URL that is probed.
		lower := strings.ToLower(t.Target)
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			// Any OTHER explicit scheme is a real mistake, not an omission — the agent
			// can only speak http/https, so never paper over it with a prefix. Only a
			// LEADING scheme counts: "example.com/login?next=https://idp" is a
			// scheme-less URL that happens to carry one in its query. Both delimiter
			// forms are checked: "ftp://x" and the opaque "mailto:x".
			if leadingSchemeRE.MatchString(t.Target) || opaqueSchemeRE.MatchString(t.Target) {
				return errors.New("http monitor url must start with http:// or https://")
			}
			t.Target = "https://" + t.Target
		}
		u, err := url.Parse(t.Target)
		if err != nil {
			return errors.New("invalid http monitor url: " + t.Target)
		}
		if u.Hostname() == "" {
			return errors.New("http monitor url must include a host")
		}
		if err := validateURLPort(u, "http monitor url", t.Target); err != nil {
			return err
		}
	}
	// Every dialing/querying kind takes a BARE host — a URL or "host:port" pasted
	// here can never succeed, and the agent can only report it as a generic probe
	// failure, so reject the shape now instead of letting it fail forever. gateway
	// (server-normalized to "gateway") and host (a metric-series anchor such as
	// "host", "*" or a mount point like "C:") are not addresses and are exempt.
	switch t.Kind {
	case "dns":
		// The port belongs to resolver_port, so a colon here is a mistake.
		if err := validateBareHost("dns monitor target", t.Target, hostRule{}); err != nil {
			return err
		}
	case "icmp":
		if err := validateBareHost("icmp monitor target", t.Target, hostRule{}); err != nil {
			return err
		}
	case "tcp":
		if err := validateBareHost("tcp monitor target", t.Target, hostRule{}); err != nil {
			return err
		}
	case "nat":
		// STUN endpoints are host[:port] — the agent applies the per-transport
		// default port when none is given.
		if err := validateBareHost("nat monitor target", t.Target, hostRule{allowPort: true}); err != nil {
			return err
		}
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
		// none is given, like the primary target). Optional, but once given it must
		// be a real endpoint — the same shape rules as the primary target. The
		// trimmed value is stored: the agent passes it straight to net.JoinHostPort,
		// where surrounding whitespace fails every probe.
		if s := strings.TrimSpace(t.Params.STUNServer2); s != "" {
			if err := validateBareHost("stun_server2", s, hostRule{allowPort: true}); err != nil {
				return err
			}
			t.Params.STUNServer2 = s
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
	// Remaining per-kind param bounds (ICMP cycle shape, DNS record type/resolver
	// endpoint, HTTP method/status/keyword/headers/body/redirect/read caps). Each is
	// checked only for the kind that consumes it, so a param left over from a
	// previous kind — which that kind's collector ignores — never blocks a save.
	return validateProbeParams(t.Kind, &t.Params)
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
	stats, err := d.Incident.OverviewStats(ctx, siteID, time.Now().Add(-24*time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": incs, "total": total, "page": page, "page_size": pageSize, "summary": stats,
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

// handleGetIncident returns one incident with its member alert instances (each
// carrying frozen per-condition evidence). Snapshot and trace detail are served
// by later endpoints. Enforces site ownership.
func (d Deps) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	inc, err := d.Incident.Get(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if inc.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	members, abnormalTargetCount, err := d.Alert.IncidentDetail(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if members == nil {
		members = []alert.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incident":              inc,
		"members":               members,
		"abnormal_target_count": abnormalTargetCount,
	})
}

// incidentOwned resolves an incident and enforces site ownership, writing the 404
// itself and returning ok=false when the incident is missing or not in this site.
func (d Deps) incidentOwned(w http.ResponseWriter, r *http.Request, id string) bool {
	inc, err := d.Incident.Get(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "incident not found")
		return false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if inc.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "incident not found")
		return false
	}
	return true
}

// handleIncidentSnapshot returns an incident's immutable snapshot (server base +
// per-Agent scene entries). Site-owned.
func (d Deps) handleIncidentSnapshot(w http.ResponseWriter, r *http.Request) {
	if d.IncidentOps == nil {
		writeError(w, http.StatusServiceUnavailable, "incident snapshots not available")
		return
	}
	id := chi.URLParam(r, "id")
	if !d.incidentOwned(w, r, id) {
		return
	}
	view, ok, err := d.IncidentOps.Snapshot(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleIncidentTraces returns the traceroute reports referenced by an incident,
// each summarized with this incident's active-reference count. Site-owned.
func (d Deps) handleIncidentTraces(w http.ResponseWriter, r *http.Request) {
	if d.IncidentOps == nil {
		writeError(w, http.StatusServiceUnavailable, "diagnostics not available")
		return
	}
	id := chi.URLParam(r, "id")
	if !d.incidentOwned(w, r, id) {
		return
	}
	traces, err := d.IncidentOps.TracesForIncident(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, traces)
}

// handleTraceReport returns one full shared traceroute report with all its hops,
// read by report id so every referencing incident sees the same execution.
// Site-owned via the report's own site id.
func (d Deps) handleTraceReport(w http.ResponseWriter, r *http.Request) {
	if d.IncidentOps == nil {
		writeError(w, http.StatusServiceUnavailable, "diagnostics not available")
		return
	}
	view, siteID, ok, err := d.IncidentOps.TraceReport(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok || siteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "trace report not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// alertView is an active alert instance plus a human description of its top
// fault, rendered in both languages so the console can show "who fired and why"
// without re-implementing the wording client-side.
type alertView struct {
	alert.Alert
	DescZh string `json:"desc_zh"`
	DescEn string `json:"desc_en"`
}

// detailFromAlert builds a notification.AlertDetail from an alert instance's
// first (worst) frozen evidence row, used only to render its description.
func detailFromAlert(a alert.Alert) notification.AlertDetail {
	det := notification.AlertDetail{Layer: a.Layer, Severity: a.Severity}
	if len(a.Evidence) > 0 {
		e := a.Evidence[0]
		det.ProbeKind = e.ProbeKind
		det.MetricKind = e.MetricKind
		det.Comparator = e.Comparator
		det.Threshold = e.Threshold
		det.Value = e.Value
		det.TargetName = e.TargetName
		det.Target = e.TargetAddr
		det.ReasonCode = e.ReasonCode
		det.ReasonDetail = e.ReasonDetail
	}
	return det
}

func (d Deps) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := d.Alert.ListActive(r.Context(), siteParam(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]alertView, 0, len(alerts))
	for _, a := range alerts {
		det := detailFromAlert(a)
		views = append(views, alertView{
			Alert:  a,
			DescZh: notification.DescribeDetail(det, "zh"),
			DescEn: notification.DescribeDetail(det, "en"),
		})
	}
	writeJSON(w, http.StatusOK, views)
}

// handleAgentAlerts returns one target's alert-instance history (firing +
// resolved) for one Agent, newest first. Exactly one stable monitor id or system
// target address is required; an unscoped Agent-wide history is not exposed.
func (d Deps) handleAgentAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	monitorID := r.URL.Query().Get("monitor")
	targetAddr := r.URL.Query().Get("target")
	if (monitorID == "") == (targetAddr == "") {
		writeError(w, http.StatusBadRequest, "exactly one of monitor or target is required")
		return
	}
	alerts, err := d.Alert.ListForAgent(r.Context(), chi.URLParam(r, "id"), alert.TargetScope{
		MonitorID: monitorID,
		Address:   targetAddr,
	}, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if alerts == nil {
		alerts = []alert.Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

// ---- monitor groups ----

func (d Deps) handleListMonitorGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := d.Config.ListGroups(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if groups == nil {
		groups = []config.MonitorGroup{}
	}
	writeJSON(w, http.StatusOK, groups)
}

// monitorGroupBody is the create/update payload for a monitor group.
type monitorGroupBody struct {
	Name          string   `json:"name"`
	MergeEnabled  bool     `json:"merge_enabled"`
	AllAgents     bool     `json:"all_agents"`
	AgentGroupIDs []string `json:"agent_group_ids"`
}

func (d Deps) handleCreateMonitorGroup(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	var body monitorGroupBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || utf8.RuneCountInString(name) > 128 {
		writeError(w, http.StatusBadRequest, "group name is required (max 128)")
		return
	}
	id, err := d.Config.CreateGroup(r.Context(), siteID, name, body.MergeEnabled, body.AllAgents, body.AgentGroupIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "monitor_group.create", siteID, name)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (d Deps) handleUpdateMonitorGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	g, err := d.Config.GetGroup(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "monitor group not found")
		return
	}
	if g.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "monitor group not found")
		return
	}
	var body monitorGroupBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || utf8.RuneCountInString(name) > 128 {
		writeError(w, http.StatusBadRequest, "group name is required (max 128)")
		return
	}
	// Validate the whole submitted scope BEFORE any lifecycle mutation. The
	// merge-flip termination below commits its own transaction and dispatches
	// resolution notifications — irreversible. UpdateGroup would otherwise reject
	// an unknown/cross-site agent_group_id only AFTER termination, so a failed
	// request would still have force-resolved incidents. Validating the scope up
	// front (the same rule UpdateGroup enforces) guarantees a rejected request has
	// zero alert/incident lifecycle side effects.
	if err := d.Config.ValidateGroupScope(r.Context(), g.SiteID, body.AllAgents, body.AgentGroupIDs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The whole submitted scope is validated read-only above so a rejected request
	// has zero lifecycle side effects. A merge-policy flip terminates the group's
	// active alerts (configuration_changed) inside UpdateGroup's own transaction, so
	// no incident lingers under a stale grouping identity.
	siteID, err := d.Config.UpdateGroup(r.Context(), id, name, body.MergeEnabled, body.AllAgents, body.AgentGroupIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A scope narrowing can strand alerts for agents that just left scope.
	if err := d.Rules.ResolveOutOfScope(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := d.reconcileScope(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "monitor_group.update", id, name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleDeleteMonitorGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	g, err := d.Config.GetGroup(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "monitor group not found")
		return
	}
	if g.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "monitor group not found")
		return
	}
	siteID, err := d.Config.DeleteGroup(r.Context(), id)
	if errors.Is(err, config.ErrDefaultGroup) {
		writeError(w, http.StatusBadRequest, "the default monitor group cannot be deleted")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := d.Rules.ResolveOutOfScope(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := d.reconcileScope(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "monitor_group.delete", id, "")
	w.WriteHeader(http.StatusNoContent)
}

// reconcileScope runs the operational-issue reconciliation that must follow any
// monitor-group scope change (targets moving in/out of an agent's scope), and
// re-predicts probe/host monitor status for the site. It returns the first failure
// so the mutating handler can answer a truthful 500 instead of a 2xx that leaves
// authoritative current state obsolete or immediately expired (SRV-008).
func (d Deps) reconcileScope(ctx context.Context, siteID string) error {
	if d.OpIssue == nil {
		return nil
	}
	if err := d.OpIssue.ReconcileScope(ctx, siteID); err != nil {
		return err
	}
	if _, err := d.OpIssue.PredictProbeMonitors(ctx, siteID); err != nil {
		return err
	}
	return d.OpIssue.ReevaluateHostMonitorsForSite(ctx, siteID)
}

// ---- group rules (one-layer AND/OR, configured on a monitor group) ----

func (d Deps) handleListGroupRules(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	g, err := d.Config.GetGroup(r.Context(), groupID)
	if err != nil || g.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "monitor group not found")
		return
	}
	rs, err := d.Rules.ListForGroup(r.Context(), groupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rs == nil {
		rs = []rules.GroupRule{}
	}
	writeJSON(w, http.StatusOK, rs)
}

func (d Deps) handleCreateGroupRule(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	g, err := d.Config.GetGroup(r.Context(), groupID)
	if err != nil || g.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "monitor group not found")
		return
	}
	rule, ok := decodeGroupRule(w, r)
	if !ok {
		return
	}
	id, err := d.Rules.Create(r.Context(), g.SiteID, groupID, rule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A host-target condition defines a host monitor's required permissions.
	if d.OpIssue != nil {
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), g.SiteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "group_rule.create", id, groupID)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (d Deps) handleUpdateGroupRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cur, err := d.Rules.GetRule(r.Context(), id)
	if errors.Is(err, rules.ErrNotFound) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cur.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	rule, ok := decodeGroupRule(w, r)
	if !ok {
		return
	}
	rule.ID = id
	if err := d.Rules.Update(r.Context(), rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if d.OpIssue != nil {
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), cur.SiteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "group_rule.update", id, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleDeleteGroupRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cur, err := d.Rules.GetRule(r.Context(), id)
	if errors.Is(err, rules.ErrNotFound) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cur.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err := d.Rules.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d.OpIssue != nil {
		if err := d.OpIssue.ReevaluateHostMonitorsForSite(r.Context(), cur.SiteID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "group_rule.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// decodeGroupRule parses a rules.GroupRule from the request body with light
// structural checks; the full condition validation runs in rules.Create/Update.
func decodeGroupRule(w http.ResponseWriter, r *http.Request) (rules.GroupRule, bool) {
	var rule rules.GroupRule
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule body")
		return rules.GroupRule{}, false
	}
	if strings.TrimSpace(rule.Name) == "" || (rule.Op != "and" && rule.Op != "or") {
		writeError(w, http.StatusBadRequest, "name and op ('and'|'or') are required")
		return rules.GroupRule{}, false
	}
	if rule.Severity == "" {
		rule.Severity = "warn"
	}
	return rule, true
}

// ---- notification channels ----

// maxChannelBodyBytes bounds channel create/update/test request bodies. Webhook
// channels can carry a custom header set and a body template, so the limit sits
// well above the few-hundred-byte email/system configs.
const maxChannelBodyBytes = 32 << 10

// methodPattern / headerNamePattern validate a webhook's custom HTTP method and
// header names (RFC 7230 token charset for names).
var (
	methodPattern     = regexp.MustCompile(`^[A-Z]{1,16}$`)
	headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// validateWebhookConfig checks a webhook channel's config and returns a
// user-facing error message, or "" when valid. The url may embed {{variables}},
// so it is prefix-checked rather than fully parsed.
func validateWebhookConfig(cfg map[string]string) string {
	u := strings.TrimSpace(cfg["url"])
	if u == "" {
		return "webhook url is required"
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "webhook url must start with http:// or https://"
	}
	if m := strings.TrimSpace(cfg["method"]); m != "" && !methodPattern.MatchString(m) {
		return "method must be 1-16 uppercase letters"
	}
	if raw := strings.TrimSpace(cfg["headers"]); raw != "" {
		var hdrs map[string]string
		if json.Unmarshal([]byte(raw), &hdrs) != nil {
			return "headers must be a JSON object of string values"
		}
		for k, v := range hdrs {
			if !headerNamePattern.MatchString(k) {
				return "invalid header name: " + k
			}
			if strings.ContainsAny(v, "\r\n") {
				return "header value must not contain CR or LF"
			}
		}
	}
	return ""
}

// webhookAuditDetail reduces a webhook URL to a non-secret identifier for the
// audit log: scheme://host only. Many providers (Slack, DingTalk) carry an
// access token in the URL path/query, which must not be persisted to the
// append-only audit trail. Falls back to "webhook" when the URL can't be parsed.
func webhookAuditDetail(rawURL string) string {
	if u, err := neturl.Parse(rawURL); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "webhook"
}

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
	if err := json.NewDecoder(io.LimitReader(r.Body, maxChannelBodyBytes)).Decode(&body); err != nil || (body.Type != "webhook" && body.Type != "email" && body.Type != "system") {
		writeError(w, http.StatusBadRequest, "type must be webhook, email or system")
		return
	}
	if body.Type == "webhook" {
		if msg := validateWebhookConfig(body.Config); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
	}
	id, err := d.Notification.Create(r.Context(), body.Name, body.Type, body.Config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "channel.create", body.Type, body.Name)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

// handleTestChannel sends a sample incident to a webhook config WITHOUT saving a
// channel, so an operator can validate a custom method / headers / body template
// from the add or edit form. Only webhook channels are testable. The request
// always returns 200 with the delivery outcome — a delivery failure is a result,
// not an API error.
func (d Deps) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type   string            `json:"type"`
		Config map[string]string `json:"config"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxChannelBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Type != "webhook" {
		writeError(w, http.StatusBadRequest, "only webhook channels can be tested")
		return
	}
	if msg := validateWebhookConfig(body.Config); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	p := notification.SampleWebhookPayload(d.Settings.ConsoleBaseURL(r.Context()))
	status, snippet, err := d.Notification.TestWebhook(r.Context(), body.Config, p)
	d.Audit.Log(r.Context(), "admin", "channel.test", body.Type, webhookAuditDetail(body.Config["url"]))
	resp := map[string]any{"ok": err == nil && status < 300, "status_code": status, "body": snippet}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleGetSettings returns public UI settings as a flat map (e.g.
// {"console_base_url": "http://localhost:12450"}).
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
// expose or write: the console base URL, the listen address, plus every
// incident-snapshot / diagnostic integer knob (settings.IntKeys). Internal
// values such as the dashboard layout and onboarding state use dedicated APIs.
var knownSettingKeys = buildKnownSettingKeys()

func buildKnownSettingKeys() map[string]bool {
	m := map[string]bool{
		settings.KeyConsoleBaseURL:       true,
		settings.KeyListenAddr:           true,
		settings.KeyAgentAlertSeverity:   true, // string; validated explicitly below
		settings.KeyAgentAlertChannelIDs: true, // string (JSON array); validated explicitly below
	}
	for k := range settings.IntKeys {
		m[k] = true
	}
	return m
}

// handleUpdateSettings merges the posted keys. Only known keys are accepted;
// console_base_url is validated to be an absolute http(s) origin without a query
// or fragment (or empty to clear it), listen_addr is validated (host allow-list,
// port range, bind probe) and reports its effect timing in the response, and
// every integer knob is range-checked against its registered bounds.
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
	listenChanged := false
	var listenNew string
	if v, ok := body[settings.KeyListenAddr]; ok {
		v = strings.TrimSpace(v)
		if v != "" {
			var effective string
			if d.ListenStatus != nil {
				effective = d.ListenStatus(r.Context()).EffectiveAddr
			}
			if msg := validateListenAddr(v, effective); msg != "" {
				writeError(w, http.StatusBadRequest, msg)
				return
			}
		}
		body[settings.KeyListenAddr] = v
		cur, err := d.Settings.Get(r.Context(), settings.KeyListenAddr)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		listenChanged = v != cur
		listenNew = v
	}
	// Agent connectivity-alert severity: a fixed enum, or "" to clear (= warn).
	if v, ok := body[settings.KeyAgentAlertSeverity]; ok {
		v = strings.TrimSpace(v)
		switch v {
		case "", "info", "warn", "error", "critical":
		default:
			writeError(w, http.StatusBadRequest, "agent_alert_severity must be one of info|warn|error|critical")
			return
		}
		body[settings.KeyAgentAlertSeverity] = v
	}
	// Agent connectivity-alert channel IDs: a JSON array of non-empty strings, or
	// "" to clear (= all enabled channels).
	if v, ok := body[settings.KeyAgentAlertChannelIDs]; ok {
		v = strings.TrimSpace(v)
		if v != "" {
			var ids []string
			if json.Unmarshal([]byte(v), &ids) != nil || len(ids) > 64 {
				writeError(w, http.StatusBadRequest, "agent_alert_channel_ids must be a JSON array of up to 64 channel ids")
				return
			}
			for _, id := range ids {
				if strings.TrimSpace(id) == "" {
					writeError(w, http.StatusBadRequest, "agent_alert_channel_ids must not contain empty ids")
					return
				}
			}
		}
		body[settings.KeyAgentAlertChannelIDs] = v
	}
	// Range-check the integer knobs against their registered bounds; normalize the
	// stored form to the parsed integer.
	for k, v := range body {
		b, ok := settings.IntKeys[k]
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < b.Min || n > b.Max {
			writeError(w, http.StatusBadRequest, "setting "+k+" must be an integer in "+
				strconv.Itoa(b.Min)+"-"+strconv.Itoa(b.Max))
			return
		}
		body[k] = strconv.Itoa(n)
	}
	for k, v := range body {
		if err := d.Settings.Set(r.Context(), k, v); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	d.Audit.Log(r.Context(), "admin", "settings.update", "", "")
	if listenChanged {
		if d.ApplyListenAddr != nil {
			if err := d.ApplyListenAddr(r.Context(), listenNew); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "listen_effect": "restarting"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "listen_effect": "pending"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// validateListenAddr checks a listen_addr setting value: "host:port" with host
// restricted to 127.0.0.1 (loopback) or 0.0.0.0 (all interfaces) and a port in
// 1-65535. When the requested port differs from the currently bound one it also
// probes with a real bind so "port in use" and "permission denied" fail at save
// time (best-effort: the port can still be taken before the restart — the
// startup fallback in liteserver covers that). Returns "" when valid, else a
// user-facing error message.
func validateListenAddr(v, effectiveAddr string) string {
	host, portStr, err := net.SplitHostPort(v)
	if err != nil {
		return "listen_addr must be host:port, e.g. 127.0.0.1:12450"
	}
	if host != "127.0.0.1" && host != "0.0.0.0" {
		return "listen_addr host must be 127.0.0.1 (local only) or 0.0.0.0 (all interfaces)"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "listen_addr port must be an integer in 1-65535"
	}
	// Same port as the current bind: the server itself holds it, so a probe would
	// false-positive; a pure mode flip (127.0.0.1 <-> 0.0.0.0) needs no probe.
	if _, curPort, err := net.SplitHostPort(effectiveAddr); err == nil && curPort == portStr {
		return ""
	}
	ln, err := net.Listen("tcp", v)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "address already in use") || strings.Contains(msg, "Only one usage of each socket address"):
			return "port " + portStr + " is already in use by another program"
		case strings.Contains(msg, "permission denied") || strings.Contains(msg, "access permissions"):
			return "binding port " + portStr + " was denied (insufficient permission)"
		default:
			return "cannot listen on " + v + ": " + msg
		}
	}
	_ = ln.Close()
	return ""
}

func (d Deps) handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string            `json:"name"`
		Enabled bool              `json:"enabled"`
		Config  map[string]string `json:"config"` // nil/omitted = keep existing
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxChannelBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	id := chi.URLParam(r, "id")
	// When config is supplied for a webhook channel, validate it. The update body
	// carries no type, so look it up (also gives a clean 404 for a bad id).
	if body.Config != nil {
		ch, err := d.Notification.Get(r.Context(), id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeError(w, http.StatusNotFound, "channel not found")
			return
		case err != nil:
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ch.Type == "webhook" {
			if msg := validateWebhookConfig(body.Config); msg != "" {
				writeError(w, http.StatusBadRequest, msg)
				return
			}
		}
	}
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

// handleApplyChannelToAllRules adds this channel to every alert rule's channel
// set — a convenience so an operator doesn't have to tick it on each rule. Only
// future firings pick it up; open incidents keep their frozen routing. Returns
// the number of rules changed.
func (d Deps) handleApplyChannelToAllRules(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	switch _, err := d.Notification.Get(r.Context(), id); {
	case errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, "channel not found")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	n, err := d.Rules.AddChannelToAllRules(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "channel.apply_all", id, strconv.Itoa(n))
	writeJSON(w, http.StatusOK, map[string]int{"updated": n})
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
