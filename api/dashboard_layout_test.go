package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store/storetest"
)

func TestDashboardLayoutRoundTrip(t *testing.T) {
	db := storetest.Open(t)
	d := Deps{Settings: settings.New(db)}

	get := httptest.NewRecorder()
	d.handleGetDashboardLayout(get, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard-layout", nil))
	if get.Code != http.StatusOK || strings.TrimSpace(get.Body.String()) != "null" {
		t.Fatalf("unset GET status=%d body=%q", get.Code, get.Body.String())
	}

	payload := `{"version":2,"cards":[{"id":"overall","type":"overall","visible":true,"size":"wide"},{"id":"monitor-target-cloudflare","type":"monitor-target","visible":true,"size":"medium","target_id":"target_cloudflare"}]}`
	put := httptest.NewRecorder()
	d.handleUpdateDashboardLayout(put, httptest.NewRequest(http.MethodPut, "/api/v1/dashboard-layout", strings.NewReader(payload)))
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", put.Code, put.Body.String())
	}

	get = httptest.NewRecorder()
	d.handleGetDashboardLayout(get, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard-layout", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", get.Code, get.Body.String())
	}
	var got dashboardLayout
	if err := json.Unmarshal(get.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got.Version != 2 || len(got.Cards) != 2 || got.Cards[1].Type != "monitor-target" || got.Cards[1].TargetID != "target_cloudflare" {
		t.Fatalf("GET layout=%+v", got)
	}
	raw, err := d.Settings.Get(context.Background(), settings.KeyDashboardLayout)
	if err != nil || raw == "" {
		t.Fatalf("stored layout=%q err=%v", raw, err)
	}

	publicSettings := httptest.NewRecorder()
	d.handleGetSettings(publicSettings, httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil))
	var settingsBody map[string]string
	if err := json.Unmarshal(publicSettings.Body.Bytes(), &settingsBody); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if _, exposed := settingsBody[settings.KeyDashboardLayout]; exposed {
		t.Fatal("dashboard layout leaked through generic settings API")
	}
}

func TestDashboardLayoutAcceptsTallSize(t *testing.T) {
	db := storetest.Open(t)
	d := Deps{Settings: settings.New(db)}

	payload := `{"version":2,"cards":[{"id":"network-quality","type":"network-quality","visible":true,"size":"tall"}]}`
	w := httptest.NewRecorder()
	d.handleUpdateDashboardLayout(w, httptest.NewRequest(http.MethodPut, "/api/v1/dashboard-layout", strings.NewReader(payload)))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT tall size status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDashboardLayoutRouteRequiresSession(t *testing.T) {
	db := storetest.Open(t)
	d := Deps{Identity: identity.New(db), Settings: settings.New(db)}

	w := httptest.NewRecorder()
	Router(d).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard-layout", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateDashboardLayoutRejectsInvalidPayloads(t *testing.T) {
	db := storetest.Open(t)
	d := Deps{Settings: settings.New(db)}

	cases := map[string]string{
		"malformed":           `{"version":`,
		"wrong version":       `{"version":1,"cards":[]}`,
		"missing cards":       `{"version":2}`,
		"missing type":        `{"version":2,"cards":[{"id":"a","visible":true,"size":"wide"}]}`,
		"duplicate id":        `{"version":2,"cards":[{"id":"a","type":"a","visible":true,"size":"wide"},{"id":"a","type":"a","visible":false,"size":"compact"}]}`,
		"invalid size":        `{"version":2,"cards":[{"id":"a","type":"a","visible":true,"size":"giant"}]}`,
		"missing target id":   `{"version":2,"cards":[{"id":"a","type":"monitor-target","visible":true,"size":"medium"}]}`,
		"target id on static": `{"version":2,"cards":[{"id":"a","type":"a","visible":true,"size":"wide","target_id":"target"}]}`,
		"static id mismatch":  `{"version":2,"cards":[{"id":"overall","type":"monitor-target-lookalike","visible":true,"size":"wide"}]}`,
		"unknown field":       `{"version":2,"cards":[],"extra":true}`,
		"multiple values":     `{"version":2,"cards":[]} {}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			d.handleUpdateDashboardLayout(w, httptest.NewRequest(http.MethodPut, "/api/v1/dashboard-layout", strings.NewReader(payload)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	w := httptest.NewRecorder()
	oversized := strings.Repeat(" ", maxDashboardLayoutBodySize) + `{"version":2,"cards":[]}`
	d.handleUpdateDashboardLayout(w, httptest.NewRequest(http.MethodPut, "/api/v1/dashboard-layout", strings.NewReader(oversized)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d body=%s", w.Code, w.Body.String())
	}
}
