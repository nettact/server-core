// Package api exposes the HTTP surface (chi router + handlers), reusable by the
// future cloud server. M2 adds real auth: a single-user session (HttpOnly
// cookie) for the UI, ed25519 enrollment for agents, and bearer-token auth on
// telemetry. Monitoring targets are edited here and pushed to agents via the
// telemetry ack (config downlink).
package api

import (
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/hostlive"
	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/incident"
	"github.com/nettact/server-core/ingest"
	"github.com/nettact/server-core/inventory"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/rules"
	"github.com/nettact/server-core/site"
)

const sessionCookie = "nettact_session"

// Deps are the services the HTTP layer needs.
type Deps struct {
	Identity     *identity.Service
	Registry     *registry.Service
	Ingest       *ingest.Service
	Metrics      *metrics.Store
	Config       *config.Service
	Site         *site.Service
	Inventory    *inventory.Service
	Rules        *rules.Service
	Alert        *alert.Service
	Incident     *incident.Service
	Notification *notification.Service
	Audit        *audit.Service
	HostLive     *hostlive.Store // in-memory live process/connection snapshots (never persisted)
	SPA          http.Handler    // optional embedded web UI (served for non-/api routes)
	Dev          bool            // relax CORS for the Vite origin
	SecureCookie bool            // set Secure on the session cookie (production/HTTPS)
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
		r.Post("/telemetry", d.handleTelemetry)

		// session-protected UI
		r.Group(func(r chi.Router) {
			r.Use(d.requireSession)
			r.Post("/auth/logout", d.handleLogout)
			r.Get("/auth/me", d.handleMe)
			r.Get("/quota", d.handleQuota)
			r.Get("/stats", d.handleStats)
			r.Get("/sites", d.handleListSites)
			r.Get("/agents", d.handleListAgents)
			r.Get("/agents/{id}", d.handleGetAgent)
			r.Put("/agents/{id}", d.handleUpdateAgent)
			r.Delete("/agents/{id}", d.handleDeleteAgent)
			r.Get("/agents/{id}/metrics", d.handleAgentMetrics)
			r.Get("/agents/{id}/latest", d.handleAgentLatest)
			r.Get("/agents/{id}/series", d.handleAgentSeries)
			r.Get("/agents/{id}/status-history", d.handleAgentStatusHistory)
			r.Get("/agents/{id}/alerts", d.handleAgentAlerts)
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
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sid, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: d.SecureCookie, Expires: exp,
	})
	d.Audit.Log(r.Context(), u.Username, "auth.login", "", "")
	writeJSON(w, http.StatusOK, u)
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

// ---- telemetry (agent-facing, bearer auth) ----

const maxPacketBytes = 8 << 20

type telemetryResponse struct {
	HighestSequence uint64             `json:"highest_sequence"`
	ServerTime      time.Time          `json:"server_time"`
	ConfigVersion   int                `json:"config_version"`
	DesiredState    *pcfg.DesiredState `json:"desired_state,omitempty"`
}

func (d Deps) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	agentID, siteID, err := d.Registry.AuthenticateAgent(r.Context(), bearer(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid agent token")
		return
	}

	var body io.Reader = http.MaxBytesReader(w, r.Body, maxPacketBytes)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid gzip body")
			return
		}
		defer gz.Close()
		body = gz
	}
	// Decode by Content-Type: protobuf when advertised, JSON otherwise (default),
	// so pre-protobuf agents keep working. Protobuf needs the whole buffer.
	// MaxBytesReader bounds only the compressed bytes, so bound the decompressed
	// read as well (one extra byte detects overflow) — otherwise a small gzip
	// bomb from an authenticated agent could allocate unbounded memory.
	raw, err := io.ReadAll(io.LimitReader(body, maxPacketBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(raw) > maxPacketBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "telemetry packet exceeds size limit")
		return
	}
	pkt, err := wire.UnmarshalPacket(raw, r.Header.Get("Content-Type"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid packet: "+err.Error())
		return
	}

	ctx := r.Context()
	ack, err := d.Ingest.Ingest(ctx, agentID, siteID, pkt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ingest: "+err.Error())
		return
	}
	// A live host snapshot is stored in memory only and handled outside ingest's
	// sequence dedup (it is idempotent, latest-wins), so a snapshot-only packet
	// with a reused sequence is still processed.
	if pkt.HostSnapshot != nil && d.HostLive != nil {
		d.HostLive.Store(agentID, *pkt.HostSnapshot)
	}
	_ = d.Registry.TouchLastSeen(ctx, agentID)
	_ = d.Registry.SetReportedConfigVersion(ctx, agentID, pkt.ReportedConfigVersion)
	// Refresh advertised capabilities from the header so a restart with changed
	// --report-* flags is reflected (enrollment runs only once). No-op when equal.
	if h := r.Header.Get("X-Agent-Capabilities"); h != "" {
		_ = d.Registry.UpdateCapabilities(ctx, agentID, splitCaps(h))
	}

	resp := telemetryResponse{HighestSequence: ack.HighestSequence, ServerTime: ack.ServerTime}
	if st, err := d.Registry.ConfigStatus(ctx, agentID); err == nil {
		resp.ConfigVersion = st.ConfigVersion
		// A pending live-snapshot request must reach the agent even when its config
		// version is current, so attach DesiredState if config lags OR one is pending.
		var pendingSnap *pcfg.SnapshotRequest
		if d.HostLive != nil {
			pendingSnap = d.HostLive.PendingFor(agentID)
		}
		if pkt.ReportedConfigVersion < st.ConfigVersion || pendingSnap != nil {
			if ds, err := d.Config.DesiredStateFor(ctx, agentID); err == nil {
				ds.SnapshotRequest = pendingSnap
				resp.DesiredState = &ds
			}
		}
	}
	// Reply in the format the agent accepts (protobuf preferred), falling back to
	// JSON. telemetryResponse and wire.Ack are field-identical, so convert directly.
	writeAck(w, r, wire.Ack(resp))
}

// ---- live host snapshot (ephemeral, never stored) ----

// handleRequestSnapshot registers a pending live-snapshot request for an agent.
// The agent honors it only for the caps it was started with, so a request for a
// non-opted-in agent simply comes back with empty lists.
func (d Deps) handleRequestSnapshot(w http.ResponseWriter, r *http.Request) {
	if d.HostLive == nil {
		writeError(w, http.StatusServiceUnavailable, "live snapshots not available")
		return
	}
	var body struct {
		WantProcesses   *bool `json:"want_processes"`
		WantConnections *bool `json:"want_connections"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	// Default to requesting both lists when the client omits the fields.
	wantProcs := body.WantProcesses == nil || *body.WantProcesses
	wantConns := body.WantConnections == nil || *body.WantConnections
	id := d.HostLive.Request(chi.URLParam(r, "id"), wantProcs, wantConns)
	writeJSON(w, http.StatusOK, map[string]string{"request_id": id})
}

// handleGetSnapshot returns the latest in-memory snapshot for an agent (if fresh)
// and whether a request is still pending, so the console can poll after asking.
func (d Deps) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	if d.HostLive == nil {
		writeError(w, http.StatusServiceUnavailable, "live snapshots not available")
		return
	}
	snap, ok, pending := d.HostLive.Latest(chi.URLParam(r, "id"))
	resp := struct {
		Snapshot *telemetry.HostSnapshot `json:"snapshot"`
		Pending  bool                    `json:"pending"`
	}{Pending: pending}
	if ok {
		resp.Snapshot = &snap
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
		AgentID: chi.URLParam(r, "id"),
		Kind:    r.URL.Query().Get("kind"),
		Target:  r.URL.Query().Get("target"),
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
	d.Audit.Log(r.Context(), "admin", "monitoring.set_targets", siteID, strconv.Itoa(len(body.Targets))+" targets")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// validKinds is the whitelist of monitoring-target kinds the server accepts.
var validKinds = map[string]bool{"icmp": true, "dns": true, "http": true, "tcp": true, "host": true}

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

func (d Deps) handlePurgeTarget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || body.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}
	siteID := chi.URLParam(r, "id")
	n, err := d.Metrics.PurgeTarget(r.Context(), siteID, body.Target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "metrics.purge_target", body.Target, strconv.Itoa(n)+" series")
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
	incs, err := d.Incident.List(r.Context(), siteParam(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if incs == nil {
		incs = []incident.Incident{}
	}
	writeJSON(w, http.StatusOK, incs)
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

func (d Deps) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := d.Alert.ListActive(r.Context(), siteParam(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if alerts == nil {
		alerts = []alert.Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

// handleAgentAlerts returns the alarm history (firing + resolved) for one
// agent+target, newest first, for the history page's 报警记录 panel.
func (d Deps) handleAgentAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	alerts, err := d.Alert.ListForTarget(r.Context(), chi.URLParam(r, "id"), r.URL.Query().Get("target"), limit)
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
	d.Audit.Log(r.Context(), "admin", "rule.update", rule.ID, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := d.Rules.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
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
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil || (body.Type != "webhook" && body.Type != "email") {
		writeError(w, http.StatusBadRequest, "type must be webhook or email")
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

// splitCaps parses the comma-separated X-Agent-Capabilities header, trimming
// blanks so an empty or padded value yields a clean slice.
func splitCaps(h string) []string {
	var out []string
	for _, p := range strings.Split(h, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

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

// writeAck encodes the telemetry ack in the format the agent advertised via
// Accept (protobuf preferred; JSON when absent/unknown), matching the request's
// negotiated format so old JSON agents receive JSON acks.
func writeAck(w http.ResponseWriter, r *http.Request, ack wire.Ack) {
	ct := wire.Negotiate(r.Header.Get("Accept"))
	data, err := wire.MarshalAck(ack, ct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode ack: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
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
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, Content-Encoding, X-Agent-Hostname, X-Agent-Platform, X-Agent-Version")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
