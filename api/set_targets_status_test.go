package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/rules"
	"github.com/nettact/server-core/store"
)

// setTargets invokes handleSetTargets with an injected chi "id" (site) param.
func setTargets(t *testing.T, d Deps, siteID, body string) *httptest.ResponseRecorder {
	t.Helper()
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", siteID)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sites/"+siteID+"/targets", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	d.handleSetTargets(w, req)
	return w
}

func targetsTestDeps(t *testing.T) (Deps, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "targets.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES('site_default','Default')`); err != nil {
		t.Fatal(err)
	}
	bus := eventbus.New()
	reg := registry.New(db, 0, nil)
	cfg := config.New(db, reg, bus, nil)
	groupID, err := cfg.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return Deps{
		Config: cfg,
		Rules:  rules.New(db, nil, nil, nil, bus, nil),
		Audit:  audit.New(db),
	}, groupID
}

// A malformed payload must not be reported as a server fault: a 500 tells the
// client the request might succeed on retry, and this one never can.
func TestSetTargetsRejectsDuplicateIDsWith400(t *testing.T) {
	d, groupID := targetsTestDeps(t)
	body := `{"targets":[
		{"id":"dup","group_id":"` + groupID + `","kind":"dns","name":"A","target":"a.example.com","enabled":true},
		{"id":"dup","group_id":"` + groupID + `","kind":"dns","name":"B","target":"b.example.com","enabled":true}
	]}`
	w := setTargets(t, d, "site_default", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "duplicate target id") {
		t.Fatalf("body = %s, want it to name the duplicate id problem", w.Body.String())
	}
}

// A rejected target must be identifiable: this endpoint reconciles the WHOLE set,
// so the offender can be a monitor the user is not editing.
func TestSetTargetsNamesTheRejectedMonitor(t *testing.T) {
	d, groupID := targetsTestDeps(t)
	body := `{"targets":[
		{"id":"ok","group_id":"` + groupID + `","kind":"icmp","name":"Good","target":"1.1.1.1","enabled":true},
		{"id":"bad","group_id":"` + groupID + `","kind":"dns","name":"域名解析（雅虎日本）","target":"https://www.yahoo.co.jp","enabled":true}
	]}`
	w := setTargets(t, d, "site_default", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	body = w.Body.String()
	if !strings.Contains(body, "域名解析（雅虎日本）") {
		t.Fatalf("body = %s, want it to name the offending monitor", body)
	}
	if !strings.Contains(body, "not a URL") {
		t.Fatalf("body = %s, want it to state the shape problem", body)
	}
}

// The happy path still saves and reports no cleanup, so the checks above are
// rejecting the payload rather than the endpoint being broken.
func TestSetTargetsAcceptsAValidSet(t *testing.T) {
	d, groupID := targetsTestDeps(t)
	body := `{"targets":[
		{"id":"m1","group_id":"` + groupID + `","kind":"dns","name":"Yahoo","target":"www.yahoo.co.jp","enabled":true},
		{"id":"m2","group_id":"` + groupID + `","kind":"http","name":"Site","target":"example.com","enabled":true}
	]}`
	w := setTargets(t, d, "site_default", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	// The scheme-less http target was normalized on the way in.
	stored, err := d.Config.ListSiteTargets(context.Background(), "site_default")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stored {
		if s.ID == "m2" && s.Target != "https://example.com" {
			t.Fatalf("http target stored as %q, want the normalized https:// form", s.Target)
		}
	}
}
