package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

func channelTestDeps(t *testing.T) Deps {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "channels.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return Deps{Notification: notification.New(db), Settings: settings.New(db), Audit: audit.New(db)}
}

// putChannel invokes handleUpdateChannel with an injected chi "id" URL param.
func putChannel(d Deps, id, body string) *httptest.ResponseRecorder {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/channels/"+id, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	d.handleUpdateChannel(w, req)
	return w
}

func TestCreateChannelValidatesWebhook(t *testing.T) {
	d := channelTestDeps(t)
	bad := map[string]string{
		"missing url": `{"type":"webhook","config":{}}`,
		"bad scheme":  `{"type":"webhook","config":{"url":"ftp://x"}}`,
		"bad method":  `{"type":"webhook","config":{"url":"https://x","method":"get"}}`,
		"bad headers": `{"type":"webhook","config":{"url":"https://x","headers":"not json"}}`,
	}
	for name, payload := range bad {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			d.handleCreateChannel(w, httptest.NewRequest(http.MethodPost, "/api/v1/channels", strings.NewReader(payload)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	w := httptest.NewRecorder()
	d.handleCreateChannel(w, httptest.NewRequest(http.MethodPost, "/api/v1/channels",
		strings.NewReader(`{"type":"webhook","name":"WH","config":{"url":"https://x/y","method":"POST","headers":"{\"Authorization\":\"Bearer z\"}"}}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("valid create status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateChannelValidation(t *testing.T) {
	d := channelTestDeps(t)

	// Updating a non-existent channel's config is a 404.
	w := putChannel(d, "chan_missing", `{"name":"x","enabled":true,"config":{"url":"https://y"}}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing channel status=%d body=%s", w.Code, w.Body.String())
	}

	// Create a webhook to edit.
	id, err := d.Notification.Create(context.Background(), "WH", "webhook", map[string]string{"url": "https://x", "lang": "zh"})
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}

	// Invalid config on an existing webhook is a 400.
	w = putChannel(d, id, `{"name":"WH","enabled":true,"config":{"url":""}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid update status=%d body=%s", w.Code, w.Body.String())
	}

	// Valid config change succeeds.
	w = putChannel(d, id, `{"name":"WH","enabled":true,"config":{"url":"https://x/v2","method":"PUT"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("valid update status=%d body=%s", w.Code, w.Body.String())
	}

	// Name/enabled-only update (no config) must not require a valid config.
	w = putChannel(d, id, `{"name":"Renamed","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("metadata-only update status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTestChannelEndpoint(t *testing.T) {
	d := channelTestDeps(t)

	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		d.handleTestChannel(w, httptest.NewRequest(http.MethodPost, "/api/v1/channels/test", strings.NewReader(body)))
		return w
	}

	if w := post(`{"type":"email","config":{}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("non-webhook status=%d", w.Code)
	}
	if w := post(`{"type":"webhook","config":{}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid config status=%d", w.Code)
	}

	// Valid webhook against a live server: 200 with the delivery outcome, and the
	// sample payload must actually reach the server.
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "okey")
	}))
	defer srv.Close()

	w := post(`{"type":"webhook","config":{"url":"` + srv.URL + `","lang":"en"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("test status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		OK         bool   `json:"ok"`
		StatusCode int    `json:"status_code"`
		Body       string `json:"body"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.StatusCode != http.StatusOK || resp.Body != "okey" || resp.Error != "" {
		t.Fatalf("resp=%+v", resp)
	}
	if !strings.Contains(string(gotBody), `"event":"test"`) {
		t.Fatalf("sample payload not marked as a test: %s", gotBody)
	}
}

func TestApplyChannelToAllRulesNotFound(t *testing.T) {
	d := channelTestDeps(t)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "chan_missing")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/chan_missing/apply-to-all", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	d.handleApplyChannelToAllRules(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookAuditDetail(t *testing.T) {
	cases := map[string]string{
		"https://oapi.dingtalk.com/robot/send?access_token=SECRET": "https://oapi.dingtalk.com",
		"https://hooks.slack.com/services/T00/B00/XXXXSECRET":      "https://hooks.slack.com",
		"http://192.168.1.5:9000/notify?key=abc":                   "http://192.168.1.5:9000",
		"not a url":                                                "webhook",
		"":                                                         "webhook",
	}
	for in, want := range cases {
		if got := webhookAuditDetail(in); got != want {
			t.Errorf("webhookAuditDetail(%q)=%q want %q", in, got, want)
		}
	}
}
