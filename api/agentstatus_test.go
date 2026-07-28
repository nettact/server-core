package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/agentalert"
	"github.com/nettact/server-core/agentstatus"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func openStatusDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.Open(t)
	now := time.Now().UTC()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatal(err)
	}
	return db
}

// TestUpdateSettingsAgentConnectivityValidation pins the connectivity detector's
// settable surface: the int knobs are bounds-checked, and the alert-era routing
// keys are gone for good. Routing lives in notification policies now, so an
// accepted write to agent_alert_severity/channel_ids would be a value nothing
// reads — config that looks applied and silently does nothing.
func TestUpdateSettingsAgentConnectivityValidation(t *testing.T) {
	db := openStatusDB(t)
	d := Deps{Settings: settings.New(db), Audit: audit.New(db)}

	put := func(bodyJSON string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPut, "/api/v1/settings", strings.NewReader(bodyJSON))
		w := httptest.NewRecorder()
		d.handleUpdateSettings(w, r)
		return w
	}

	for _, gone := range []string{
		`{"agent_alert_severity":"critical"}`,
		`{"agent_alert_channel_ids":"[\"chan_1\"]"}`,
		`{"agent_alert_enabled":"1"}`,
		`{"agent_alert_grace_seconds":"90"}`,
	} {
		if w := put(gone); w.Code != http.StatusBadRequest {
			t.Fatalf("alert-era key must be rejected outright: body=%s status=%d resp=%s",
				gone, w.Code, w.Body.String())
		}
	}

	if w := put(`{"agent_connectivity_grace_seconds":"5"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("grace below min should fail: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := put(`{"agent_connectivity_grace_seconds":"90"}`); w.Code != http.StatusOK {
		t.Fatalf("valid grace: status=%d body=%s", w.Code, w.Body.String())
	}
	if got, _ := settings.New(db).Get(context.Background(), settings.KeyAgentConnectivityGraceSeconds); got != "90" {
		t.Fatalf("grace not persisted, got %q", got)
	}
	if w := put(`{"agent_connectivity_enabled":"0"}`); w.Code != http.StatusOK {
		t.Fatalf("disabling detection: status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestUpdateAgentMuteOnly verifies a mute-only PATCH does not clear the display
// name (pointer-field semantics).
func TestUpdateAgentMuteOnly(t *testing.T) {
	db := openStatusDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO agents(id,site_id,public_key,token_hash,status,display_name,first_connected_at)
		 VALUES('agent-1','site_default',x'00','h','online','Living Room',?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	d := Deps{
		Registry:   registry.New(db, 0, eventbus.New()),
		Audit:      audit.New(db),
		AgentAlert: agentalert.New(db, settings.New(db), nil, eventbus.New()),
	}

	body := `{"connectivity_alerts_muted":true}`
	r := httptest.NewRequest(http.MethodPut, "/api/v1/agents/agent-1", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "agent-1")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	d.handleUpdateAgent(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("mute patch status=%d body=%s", w.Code, w.Body.String())
	}

	a, err := registry.New(db, 0, nil).Get(ctx, "agent-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !a.ConnectivityAlertsMuted {
		t.Fatalf("expected muted=true")
	}
	if a.DisplayName != "Living Room" {
		t.Fatalf("mute-only patch must not clear display_name, got %q", a.DisplayName)
	}
}

// TestHandleAgentStatusesOK is a smoke test that the endpoint returns a batch.
func TestHandleAgentStatusesOK(t *testing.T) {
	db := openStatusDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO agents(id,site_id,public_key,token_hash,status,first_connected_at)
		 VALUES('agent-1','site_default',x'00','h','online',?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	d := Deps{AgentStatus: agentstatus.New(db, nil, settings.New(db))}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sites/site_default/agent-statuses", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "site_default")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	d.handleAgentStatuses(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"agent-1"`) || !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}
