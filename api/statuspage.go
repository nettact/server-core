package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/statuspage"
)

// Public status pages: the admin CRUD, and the anonymous read surface.
//
// Everything under /api/v1/public is reachable with no session, which makes it
// the one place in this router where "what does the response contain" is a
// security question rather than a formatting one. Two rules hold it together:
//
//   - The DTOs come from statuspage, which builds them field by field. This file
//     adds nothing to them and never falls back to a console DTO.
//   - Every miss — unknown slug, disabled page, disabled view — is the same 404
//     with the same body. Nothing here may distinguish them, or a reader could
//     enumerate which pages exist by their error responses.

const maxStatusPageBodyBytes = 1 << 20

// statusPageBody is the create/update payload. Enabled and the two view toggles
// are pointers so an omitted field takes the sensible default (published, both
// views shown) instead of silently creating an invisible page; show_target_address
// defaults to false, which is the safe direction and so needs no pointer.
type statusPageBody struct {
	Slug              string   `json:"slug"`
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	Enabled           *bool    `json:"enabled"`
	ShowTargetAddress bool     `json:"show_target_address"`
	ShowAgentView     *bool    `json:"show_agent_view"`
	ShowTargetView    *bool    `json:"show_target_view"`
	AgentGroupIDs     []string `json:"agent_group_ids"`
	TargetIDs         []string `json:"target_ids"`
}

func (b statusPageBody) toSpec() statuspage.Spec {
	boolOr := func(p *bool, def bool) bool {
		if p != nil {
			return *p
		}
		return def
	}
	return statuspage.Spec{
		Slug:              b.Slug,
		Title:             b.Title,
		Description:       b.Description,
		Enabled:           boolOr(b.Enabled, true),
		ShowTargetAddress: b.ShowTargetAddress,
		ShowAgentView:     boolOr(b.ShowAgentView, true),
		ShowTargetView:    boolOr(b.ShowTargetView, true),
		AgentGroupIDs:     b.AgentGroupIDs,
		TargetIDs:         b.TargetIDs,
	}
}

// writeStatusPageError maps the service's sentinels onto status codes. A bad slug
// or an unpublishable selection is the operator's mistake (400), a taken slug is a
// conflict (409), and a missing page is 404 — anything else is genuinely ours.
func writeStatusPageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, statuspage.ErrBadSpec), errors.Is(err, statuspage.ErrBadSelection):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, statuspage.ErrSlugTaken):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, statuspage.ErrNotFound):
		writeError(w, http.StatusNotFound, "status page not found")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func (d Deps) handleListStatusPages(w http.ResponseWriter, r *http.Request) {
	pages, err := d.StatusPage.List(r.Context(), siteParam(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pages)
}

func (d Deps) handleGetStatusPage(w http.ResponseWriter, r *http.Request) {
	page, err := d.statusPageInSite(r)
	if err != nil {
		writeStatusPageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (d Deps) handleCreateStatusPage(w http.ResponseWriter, r *http.Request) {
	var body statusPageBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxStatusPageBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	siteID := siteParam(r)
	page, err := d.StatusPage.Create(r.Context(), siteID, body.toSpec())
	if err != nil {
		writeStatusPageError(w, err)
		return
	}
	d.Audit.Log(r.Context(), "admin", "status_page.create", page.ID, page.Slug+" · "+page.Title)
	writeJSON(w, http.StatusOK, page)
}

func (d Deps) handleUpdateStatusPage(w http.ResponseWriter, r *http.Request) {
	stored, err := d.statusPageInSite(r)
	if err != nil {
		writeStatusPageError(w, err)
		return
	}
	var body statusPageBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxStatusPageBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	page, err := d.StatusPage.Update(r.Context(), stored.ID, body.toSpec())
	if err != nil {
		writeStatusPageError(w, err)
		return
	}
	d.Audit.Log(r.Context(), "admin", "status_page.update", page.ID, page.Slug+" · "+page.Title)
	writeJSON(w, http.StatusOK, page)
}

func (d Deps) handleDeleteStatusPage(w http.ResponseWriter, r *http.Request) {
	stored, err := d.statusPageInSite(r)
	if err != nil {
		writeStatusPageError(w, err)
		return
	}
	if err := d.StatusPage.Delete(r.Context(), stored.ID); err != nil {
		writeStatusPageError(w, err)
		return
	}
	d.Audit.Log(r.Context(), "admin", "status_page.delete", stored.ID, stored.Slug+" · "+stored.Title)
	w.WriteHeader(http.StatusNoContent)
}

// statusPageInSite loads the addressed page and rejects one owned by a different
// site, exactly as the other site-scoped id routes do (see proxies.go). A page
// from another site reads as absent rather than forbidden.
func (d Deps) statusPageInSite(r *http.Request) (statuspage.Page, error) {
	page, err := d.StatusPage.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		return statuspage.Page{}, err
	}
	if page.SiteID != siteParam(r) {
		return statuspage.Page{}, statuspage.ErrNotFound
	}
	return page, nil
}

// ---- anonymous surface ----

// publicCORS opens the public status endpoints to any origin, because a deployer
// may host the status frontend anywhere — a static bucket, a different domain, a
// CDN — while this server keeps serving the API.
//
// The wildcard is safe precisely because this surface is credential-free: it
// carries no session, reads no cookie, and mutates nothing, so there is no
// ambient authority for a cross-origin caller to borrow. That is also why
// Allow-Credentials is actively removed rather than merely not set: in --dev the
// root devCORS middleware sets it (with a reflected origin) for the console's
// Vite server, and a wildcard origin combined with credentials is rejected
// outright by browsers.
//
// One asymmetry worth knowing: in --dev, devCORS answers OPTIONS itself and
// returns before this middleware runs, so a preflight there gets devCORS's
// reflected-origin response. It costs nothing — these are GETs with no custom
// headers, which browsers treat as simple requests and never preflight — and
// production builds have no devCORS at all.
func publicCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Del("Access-Control-Allow-Credentials")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// servePublic runs one public read and funnels every miss into one
// indistinguishable 404.
func (d Deps) servePublic(w http.ResponseWriter, r *http.Request, load func(slug string) (any, error)) {
	if d.StatusPage == nil {
		writeError(w, http.StatusServiceUnavailable, "status pages unavailable")
		return
	}
	// Set before the read, so a MISS carries it too. A 404 without cache headers
	// is heuristically cacheable, and a browser or CDN that retains one keeps
	// answering 404 for a slug the operator has since created or re-enabled —
	// with nothing in the console to explain why the page is still "missing".
	w.Header().Set("Cache-Control", "no-store")

	out, err := load(chi.URLParam(r, "slug"))
	if err != nil {
		if errors.Is(err, statuspage.ErrPageNotFound) {
			writeError(w, http.StatusNotFound, "page not found")
			return
		}
		// Anonymous caller: the error text stays server-side. A driver error names
		// tables, columns and file paths, and this is the one endpoint in the router
		// where the reader is a stranger.
		log.Printf("statuspage: public read %q: %v", chi.URLParam(r, "slug"), err)
		writeError(w, http.StatusInternalServerError, "status page unavailable")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (d Deps) handlePublicStatusPage(w http.ResponseWriter, r *http.Request) {
	d.servePublic(w, r, func(slug string) (any, error) {
		return d.StatusPage.PublicPage(r.Context(), slug)
	})
}

func (d Deps) handlePublicStatusPageAgents(w http.ResponseWriter, r *http.Request) {
	d.servePublic(w, r, func(slug string) (any, error) {
		return d.StatusPage.PublicAgentStatuses(r.Context(), slug)
	})
}

func (d Deps) handlePublicStatusPageTargets(w http.ResponseWriter, r *http.Request) {
	d.servePublic(w, r, func(slug string) (any, error) {
		return d.StatusPage.PublicTargetStatuses(r.Context(), slug)
	})
}
