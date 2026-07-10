// Package api exposes the HTTP surface (chi router + handlers). It lives in
// server-core so the future cloud server can reuse the same handlers. Auth is
// dev-open in M1 (any Bearer token accepted, agents auto-register); real
// bearer-token verification and session login land in M2.
package api

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/ingest"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/site"
)

// Deps are the services the HTTP layer needs.
type Deps struct {
	Ingest   *ingest.Service
	Registry *registry.Service
	Site     *site.Service
	Dev      bool
}

// Router builds the HTTP handler.
func Router(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	if d.Dev {
		r.Use(devCORS)
	}

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/healthz", d.handleHealthz)
		r.Post("/telemetry", d.handleTelemetry)
		r.Get("/sites", d.handleListSites)
		r.Get("/agents", d.handleListAgents)
		r.Get("/agents/{id}", d.handleGetAgent)
		r.Get("/agents/{id}/metrics", d.handleAgentMetrics)
	})
	return r
}

const maxPacketBytes = 8 << 20 // 8 MiB decompressed cap

func (d Deps) handleTelemetry(w http.ResponseWriter, r *http.Request) {
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

	var pkt telemetry.Packet
	if err := json.NewDecoder(body).Decode(&pkt); err != nil {
		writeError(w, http.StatusBadRequest, "invalid packet json: "+err.Error())
		return
	}
	if pkt.AgentID == "" {
		writeError(w, http.StatusBadRequest, "missing agent_id")
		return
	}

	ctx := r.Context()
	siteID := pkt.SiteID
	if siteID == "" {
		siteID = site.DefaultSiteID
	}
	if ok, _ := d.Site.Exists(ctx, siteID); !ok {
		siteID = site.DefaultSiteID
	}

	// Dev auto-registration; hostname/platform/version passed via headers.
	if err := d.Registry.EnsureDevAgent(ctx, pkt.AgentID, siteID,
		r.Header.Get("X-Agent-Hostname"),
		r.Header.Get("X-Agent-Platform"),
		r.Header.Get("X-Agent-Version")); err != nil {
		writeError(w, http.StatusInternalServerError, "register: "+err.Error())
		return
	}

	ack, err := d.Ingest.Ingest(ctx, pkt.AgentID, siteID, pkt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ingest: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ack)
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

func (d Deps) handleAgentMetrics(w http.ResponseWriter, r *http.Request) {
	q := ingest.MetricQuery{
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
			q.Since = time.Now().UTC().Add(-time.Duration(n) * time.Second)
		}
	}
	samples, err := d.Ingest.QueryMetrics(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if samples == nil {
		samples = []ingest.Sample{}
	}
	writeJSON(w, http.StatusOK, samples)
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

func (d Deps) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// devCORS allows the Vite dev origin to call the API during development.
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
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Content-Encoding, X-Agent-Hostname, X-Agent-Platform, X-Agent-Version")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
