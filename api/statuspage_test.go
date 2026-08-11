package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nettact/server-core/agentstatus"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/statuspage"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/targetstatus"
)

// statusPageFixture builds a router over a seeded site with one agent and one
// target, plus a logged-in session for the admin routes. dev controls whether
// devCORS is installed: the public CORS assertions run with it OFF, because that
// is what a production build looks like.
func statusPageFixture(t *testing.T, dev bool) (http.Handler, *store.DB, *http.Cookie) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	exec(`INSERT INTO monitor_groups(id,site_id,name,is_default) VALUES('mg','site_default','Default',1)`)
	exec(`INSERT INTO agents(id, site_id, public_key, token_hash, hostname, display_name, status,
		first_connected_at, last_seen_at, created_at)
		VALUES('agent_a','site_default',x'00','h','secret-hostname','Alpha','online',?,?,?)`, now, now, now)
	exec(`INSERT INTO probe_tasks(id, site_id, group_id, kind, target, name, enabled)
		VALUES('probe_1','site_default','mg','http','https://internal.example','Website',1)`)
	// Pages publish agent GROUPS, so the fixture needs one holding the agent.
	exec(`INSERT INTO agent_groups(id,site_id,name) VALUES('ag_1','site_default','Rack A')`)
	exec(`INSERT INTO agent_group_members(group_id,agent_id) VALUES('ag_1','agent_a')`)

	id := identity.New(db)
	admin, _, err := id.EnsureAdmin(ctx, "admin", "correct-horse-battery")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	session, _, err := id.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	d := Deps{
		Identity:   id,
		Audit:      audit.New(db),
		StatusPage: statuspage.New(db, targetstatus.New(db, nil), agentstatus.New(db, nil, settings.New(db)), nil),
		Dev:        dev,
	}
	return Router(d), db, &http.Cookie{Name: sessionCookie, Value: session}
}

func doJSON(t *testing.T, h http.Handler, method, url, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, url, nil)
	} else {
		r = httptest.NewRequest(method, url, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const statusPagePayload = `{"slug":"home","title":"Home lab","description":"hi",
	"enabled":true,"show_target_address":false,"show_agent_view":true,"show_target_view":true,"show_incidents":true,
	"agent_group_ids":["ag_1"],"target_ids":["probe_1"]}`

func createStatusPage(t *testing.T, h http.Handler, cookie *http.Cookie, payload string) statuspage.Page {
	t.Helper()
	w := doJSON(t, h, http.MethodPost, "/api/v1/status-pages", payload, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var page statuspage.Page
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return page
}

func TestStatusPageAdminCRUDRoundTrip(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)

	page := createStatusPage(t, h, cookie, statusPagePayload)
	if page.ID == "" || page.Slug != "home" || !page.ShowIncidents || len(page.AgentGroupIDs) != 1 || len(page.TargetIDs) != 1 {
		t.Fatalf("created page = %+v", page)
	}

	list := doJSON(t, h, http.MethodGet, "/api/v1/status-pages", "", cookie)
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	var pages []statuspage.Page
	if err := json.Unmarshal(list.Body.Bytes(), &pages); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("list = %+v, want one page", pages)
	}

	updated := doJSON(t, h, http.MethodPut, "/api/v1/status-pages/"+page.ID,
		`{"slug":"home","title":"Renamed","enabled":true,"show_agent_view":true,"show_target_view":true,
		  "agent_group_ids":[],"target_ids":["probe_1"]}`, cookie)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}

	got := doJSON(t, h, http.MethodGet, "/api/v1/status-pages/"+page.ID, "", cookie)
	if got.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", got.Code, got.Body.String())
	}
	var one statuspage.Page
	if err := json.Unmarshal(got.Body.Bytes(), &one); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if one.Title != "Renamed" || len(one.AgentGroupIDs) != 0 {
		t.Fatalf("after update = %+v, want the renamed page with an empty agent selection", one)
	}

	del := doJSON(t, h, http.MethodDelete, "/api/v1/status-pages/"+page.ID, "", cookie)
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", del.Code, del.Body.String())
	}
	if again := doJSON(t, h, http.MethodGet, "/api/v1/status-pages/"+page.ID, "", cookie); again.Code != http.StatusNotFound {
		t.Fatalf("get after delete status=%d, want 404", again.Code)
	}
}

// Operator mistakes must not read as server faults: each of these is a 4xx with a
// message naming what to fix.
func TestStatusPageAdminRejectsBadRequests(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)
	createStatusPage(t, h, cookie, statusPagePayload)

	cases := []struct {
		name    string
		payload string
		want    int
	}{
		{"bad slug", `{"slug":"Not A Slug","title":"x"}`, http.StatusBadRequest},
		{"empty title", `{"slug":"ok","title":"  "}`, http.StatusBadRequest},
		{"all views hidden", `{"slug":"ok","title":"x","show_agent_view":false,"show_target_view":false,"show_incidents":false}`, http.StatusBadRequest},
		{"unknown agent group", `{"slug":"ok","title":"x","agent_group_ids":["ag_nope"]}`, http.StatusBadRequest},
		{"unknown target", `{"slug":"ok","title":"x","target_ids":["probe_nope"]}`, http.StatusBadRequest},
		{"duplicate slug", `{"slug":"home","title":"x"}`, http.StatusConflict},
		{"malformed json", `{"slug":`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, h, http.MethodPost, "/api/v1/status-pages", tc.payload, cookie)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

// A page belonging to another site is not this site's to read or edit, and says
// so as 404 rather than confirming it exists.
func TestStatusPageAdminRoutesAreSiteScoped(t *testing.T) {
	h, db, cookie := statusPageFixture(t, false)
	page := createStatusPage(t, h, cookie, statusPagePayload)
	if _, err := db.Exec(`INSERT INTO sites(id,name,created_at) VALUES('site_other','other',?)`, time.Now().UTC()); err != nil {
		t.Fatalf("seed other site: %v", err)
	}

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		w := doJSON(t, h, method, "/api/v1/status-pages/"+page.ID+"?site=site_other", "", cookie)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s cross-site status=%d, want 404", method, w.Code)
		}
	}
	w := doJSON(t, h, http.MethodPut, "/api/v1/status-pages/"+page.ID+"?site=site_other", statusPagePayload, cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("PUT cross-site status=%d, want 404", w.Code)
	}
}

func TestStatusPageAdminRoutesRequireSession(t *testing.T) {
	h, _, _ := statusPageFixture(t, false)
	for _, path := range []string{"/api/v1/status-pages", "/api/v1/status-pages/spg_whatever"} {
		w := doJSON(t, h, http.MethodGet, path, "", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s without a session = %d, want 401", path, w.Code)
		}
	}
	if w := doJSON(t, h, http.MethodPost, "/api/v1/status-pages", statusPagePayload, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("POST without a session = %d, want 401", w.Code)
	}
}

// A 404 without cache headers is heuristically cacheable, so a browser or CDN
// can keep answering "no such page" for a slug the operator has since created or
// re-enabled — with nothing in the console to explain why.
func TestPublicStatusPageMissesAreNotCacheable(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)
	createStatusPage(t, h, cookie,
		`{"slug":"down","title":"Taken down","enabled":false,"target_ids":["probe_1"]}`)

	for _, path := range []string{
		"/api/v1/public/pages/never-existed",
		"/api/v1/public/pages/down",
		"/api/v1/public/pages/down/target-statuses",
	} {
		w := doJSON(t, h, http.MethodGet, path, "", nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d, want 404", path, w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s Cache-Control = %q on a miss, want no-store", path, cc)
		}
	}
}

// ---- the anonymous surface ----

func TestPublicStatusPageServesWithoutASession(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)
	createStatusPage(t, h, cookie, statusPagePayload)

	for _, path := range []string{
		"/api/v1/public/pages/home",
		"/api/v1/public/pages/home/agent-statuses",
		"/api/v1/public/pages/home/target-statuses",
		"/api/v1/public/pages/home/incidents",
	} {
		w := doJSON(t, h, http.MethodGet, path, "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("%s Allow-Origin = %q, want the wildcard a separately hosted frontend needs", path, got)
		}
		// A wildcard origin plus credentials is rejected by every browser, and this
		// surface has no credentials to send in the first place.
		if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("%s Allow-Credentials = %q, want it absent", path, got)
		}
	}
}

func TestPublicStatusPagePreflightIsAnswered(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)
	createStatusPage(t, h, cookie, statusPagePayload)

	r := httptest.NewRequest(http.MethodOptions, "/api/v1/public/pages/home", nil)
	r.Header.Set("Origin", "https://status.example.com")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status=%d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("preflight Allow-Origin = %q, want *", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") {
		t.Errorf("preflight Allow-Methods = %q, want GET", got)
	}
}

// The public payloads are the reason this feature needed a separate DTO layer:
// nothing the console shows about a target or agent may ride along by accident.
func TestPublicStatusPageWithholdsInternalDetail(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)
	createStatusPage(t, h, cookie, statusPagePayload)

	for _, path := range []string{
		"/api/v1/public/pages/home/agent-statuses",
		"/api/v1/public/pages/home/target-statuses",
		"/api/v1/public/pages/home/incidents",
	} {
		body := doJSON(t, h, http.MethodGet, path, "", nil).Body.String()
		for _, leak := range []string{
			"secret-hostname",                    // the agent's hostname
			"https://internal.example",           // the target address, not opted into
			"agent_a", "probe_1", "site_default", // internal ids
			"params", "proxy", "incident_id", "signal_ids",
			// Node resources publish at the DEFAULT level here, so the figures
			// that describe the machine rather than its health must still be
			// absent: those need agent_metrics=full, which nobody asked for.
			"mem_used", "mem_total", "disk_used", "disk_total", "disk_mount",
		} {
			if strings.Contains(body, leak) {
				t.Errorf("%s leaked %q: %s", path, leak, body)
			}
		}
	}
}

func TestPublicStatusPageShowsAddressOnlyWhenOptedIn(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)
	createStatusPage(t, h, cookie,
		`{"slug":"home","title":"Home","show_target_address":true,"target_ids":["probe_1"]}`)

	body := doJSON(t, h, http.MethodGet, "/api/v1/public/pages/home/target-statuses", "", nil).Body.String()
	if !strings.Contains(body, "https://internal.example") {
		t.Fatalf("address missing after opting in: %s", body)
	}
}

// Unknown slug, disabled page, and disabled view must be byte-identical from
// outside — otherwise the error itself tells a stranger which pages exist.
func TestEveryPublicMissIsTheSameResponse(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)
	createStatusPage(t, h, cookie,
		`{"slug":"down","title":"Taken down","enabled":false,"target_ids":["probe_1"]}`)
	createStatusPage(t, h, cookie,
		`{"slug":"agents-only","title":"Agents","show_target_view":false,"agent_group_ids":["ag_1"]}`)
	createStatusPage(t, h, cookie,
		`{"slug":"no-history","title":"No history","show_incidents":false,"target_ids":["probe_1"]}`)

	paths := []string{
		"/api/v1/public/pages/never-existed",
		"/api/v1/public/pages/down",
		"/api/v1/public/pages/down/target-statuses",
		"/api/v1/public/pages/agents-only/target-statuses",
		"/api/v1/public/pages/no-history/incidents",
	}
	var first string
	for i, path := range paths {
		w := doJSON(t, h, http.MethodGet, path, "", nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d, want 404", path, w.Code)
		}
		if i == 0 {
			first = w.Body.String()
			continue
		}
		if w.Body.String() != first {
			t.Errorf("%s body=%q, want it identical to the unknown-slug body %q", path, w.Body.String(), first)
		}
	}

	// The view that is enabled still answers — the toggle hides a list, not the page.
	if w := doJSON(t, h, http.MethodGet, "/api/v1/public/pages/agents-only/agent-statuses", "", nil); w.Code != http.StatusOK {
		t.Fatalf("enabled view status=%d body=%s", w.Code, w.Body.String())
	}
}

// In --dev the root devCORS middleware runs first and reflects the caller's
// origin with credentials for the Vite console. The public routes must still end
// up wildcard and credential-free for ordinary GETs.
func TestPublicStatusPageOverridesDevCORS(t *testing.T) {
	h, _, cookie := statusPageFixture(t, true)
	createStatusPage(t, h, cookie, statusPagePayload)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/public/pages/home", nil)
	r.Header.Set("Origin", "https://status.example.com")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want publicCORS to have overridden devCORS", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials = %q, want publicCORS to have removed devCORS's", got)
	}
}

// ---- the root URL ----

// stubSPA stands in for the console shell. The real one is a built dist supplied
// by the host binary; all this test needs is something distinguishable from a
// redirect.
const stubSPABody = "console shell"

// rootFixture is statusPageFixture plus an SPA, because homeGate only exists when
// one is mounted. Kept separate rather than adding a parameter to the shared
// helper: every other status-page test asserts on the API surface, and giving
// them a root handler they never call would only invite confusion about which
// handler answered.
func rootFixture(t *testing.T) (http.Handler, *http.Cookie) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	exec(`INSERT INTO monitor_groups(id,site_id,name,is_default) VALUES('mg','site_default','Default',1)`)
	exec(`INSERT INTO probe_tasks(id, site_id, group_id, kind, target, name, enabled)
		VALUES('probe_1','site_default','mg','http','https://internal.example','Website',1)`)

	id := identity.New(db)
	admin, _, err := id.EnsureAdmin(ctx, "admin", "correct-horse-battery")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	session, _, err := id.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	d := Deps{
		Identity:   id,
		Audit:      audit.New(db),
		StatusPage: statuspage.New(db, targetstatus.New(db, nil), agentstatus.New(db, nil, settings.New(db)), nil),
		SPA: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(stubSPABody))
		}),
	}
	return Router(d), &http.Cookie{Name: sessionCookie, Value: session}
}

const homePagePayload = `{"slug":"home","title":"Home lab","enabled":true,
	"show_agent_view":false,"show_target_view":true,"is_home":true,
	"agent_group_ids":[],"target_ids":["probe_1"]}`

func TestRootRedirectsToHomeStatusPage(t *testing.T) {
	h, cookie := rootFixture(t)

	// No home page yet: the root is the console, exactly as before this feature.
	if w := doJSON(t, h, http.MethodGet, "/", "", nil); w.Code != http.StatusOK ||
		w.Body.String() != stubSPABody {
		t.Fatalf("root with no home page: status=%d body=%q; want 200 + the SPA", w.Code, w.Body.String())
	}

	page := createStatusPage(t, h, cookie, homePagePayload)
	if !page.IsHome {
		t.Fatalf("created page did not take the home flag: %+v", page)
	}

	// GET and HEAD must behave identically. HEAD is the reason homeGate wraps the
	// SPA instead of registering its own "/" route: a static route would match the
	// path, miss the method, and answer 405.
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := doJSON(t, h, method, "/", "", nil)
		if w.Code != http.StatusFound {
			t.Errorf("anonymous %s /: status=%d; want 302", method, w.Code)
			continue
		}
		if got, want := w.Header().Get("Location"), "/status/#/home"; got != want {
			t.Errorf("anonymous %s / Location=%q; want %q", method, got, want)
		}
		// Without no-store a cached redirect outlives the setting that caused it,
		// and even signing in would not get the admin back to the console.
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("anonymous %s / Cache-Control=%q; want no-store", method, got)
		}
	}

	// A signed-in admin asked for the console and gets the console.
	if w := doJSON(t, h, http.MethodGet, "/", "", cookie); w.Code != http.StatusOK ||
		w.Body.String() != stubSPABody {
		t.Errorf("authenticated GET /: status=%d body=%q; want 200 + the SPA", w.Code, w.Body.String())
	}

	// Only the root is diverted. A bookmarked console deep link must still reach
	// the SPA, whose own guard sends it to /login.
	if w := doJSON(t, h, http.MethodGet, "/monitoring", "", nil); w.Code != http.StatusOK ||
		w.Body.String() != stubSPABody {
		t.Errorf("anonymous GET /monitoring: status=%d body=%q; want 200 + the SPA", w.Code, w.Body.String())
	}

	// Unpublishing the home page reads as "no such page" here too.
	unpublished := strings.Replace(homePagePayload, `"enabled":true`, `"enabled":false`, 1)
	if w := doJSON(t, h, http.MethodPut, "/api/v1/status-pages/"+page.ID, unpublished, cookie); w.Code != http.StatusOK {
		t.Fatalf("unpublish: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := doJSON(t, h, http.MethodGet, "/", "", nil); w.Code != http.StatusOK ||
		w.Body.String() != stubSPABody {
		t.Errorf("root with an unpublished home page: status=%d; want 200 + the SPA", w.Code)
	}
}

// The anonymous DTO carries is_home so the board can decide whether to offer a
// way back to the console.
func TestPublicPageWireCarriesIsHome(t *testing.T) {
	h, cookie := rootFixture(t)
	createStatusPage(t, h, cookie, homePagePayload)

	w := doJSON(t, h, http.MethodGet, "/api/v1/public/pages/home", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("public page: status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, ok := body["is_home"]; !ok || got != true {
		t.Errorf("public page is_home = %v (present=%v); want true", got, ok)
	}
}
