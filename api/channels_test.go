package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/notifypolicy"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store/storetest"
)

func channelTestDeps(t *testing.T) Deps {
	t.Helper()
	db := storetest.Open(t)
	// The site row is not optional scenery: creating a channel checks it into that
	// site's two built-in policies, so without it every create would fail.
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default Site',?)`,
		time.Now().UTC()); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	notif := notification.New(db, false)
	set := settings.New(db)
	return Deps{
		Notification: notif,
		NotifyPolicy: notifypolicy.New(db, notif, set, eventbus.New()),
		Settings:     set,
		Audit:        audit.New(db),
	}
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
		"missing url": `{"type":"webhook","storm_merge":true,"config":{}}`,
		"bad scheme":  `{"type":"webhook","storm_merge":true,"config":{"url":"ftp://x"}}`,
		"bad method":  `{"type":"webhook","storm_merge":true,"config":{"url":"https://x","method":"get"}}`,
		"bad headers": `{"type":"webhook","storm_merge":true,"config":{"url":"https://x","headers":"not json"}}`,
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
		strings.NewReader(`{"type":"webhook","name":"WH","storm_merge":true,"config":{"url":"https://x/y","method":"POST","headers":"{\"Authorization\":\"Bearer z\"}"}}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("valid create status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCreateChannelRequiresStormMergeChoice(t *testing.T) {
	d := channelTestDeps(t)
	w := postChannel(d, `{"type":"system","name":"Desktop","config":{"lang":"zh"}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing storm_merge status=%d body=%s", w.Code, w.Body.String())
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
	id, err := d.Notification.Create(context.Background(), "WH", "webhook", map[string]string{"url": "https://x", "lang": "zh"}, true)
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

// postChannel invokes handleCreateChannel with a raw JSON body.
func postChannel(d Deps, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	d.handleCreateChannel(w, httptest.NewRequest(http.MethodPost, "/api/v1/channels", strings.NewReader(body)))
	return w
}

// TestCreateChannelTypeAllowList: the allow-list is the three built-ins plus the
// notification package's provider registry — an unregistered type is rejected,
// a registered push type is created.
//
// The telegram config here is deliberately valid under the FINAL provider
// validation rules (a real-shaped bot token and chat id), not merely under the
// phase-A stub that accepts everything, so this fixture keeps passing when the
// real ValidateConfig lands.
func TestCreateChannelTypeAllowList(t *testing.T) {
	d := channelTestDeps(t)

	if w := postChannel(d, `{"type":"pigeon","name":"P","config":{}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown type status=%d body=%s", w.Code, w.Body.String())
	}
	if w := postChannel(d, `{"type":"","config":{}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("empty type status=%d body=%s", w.Code, w.Body.String())
	}

	w := postChannel(d, `{"type":"telegram","name":"TG","storm_merge":false,"config":{"bot_token":"123456:AAAA","chat_id":"-100123","lang":"zh"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("telegram create status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("create response=%s err=%v", w.Body.String(), err)
	}
	ch, err := d.Notification.Get(context.Background(), created.ID)
	if err != nil || ch.Type != "telegram" || ch.Config["bot_token"] != "123456:AAAA" || ch.StormMerge {
		t.Fatalf("stored channel=%+v err=%v", ch, err)
	}
}

// TestUpdateChannelMergesMaskedSecrets: the console only ever sees a masked
// credential, so saving an edit form that did not retype the token must keep the
// stored token and still apply the other field's change.
func TestUpdateChannelMergesMaskedSecrets(t *testing.T) {
	d := channelTestDeps(t)
	id, err := d.Notification.Create(context.Background(), "TG", "telegram", map[string]string{
		"bot_token": "123456:AAAAreal", "chat_id": "-100123", "lang": "zh",
	}, true)
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}

	w := putChannel(d, id, `{"name":"TG","enabled":true,"config":{"bot_token":"`+notification.MaskedSecret+`","chat_id":"-100999","lang":"zh"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("masked update status=%d body=%s", w.Code, w.Body.String())
	}
	ch, err := d.Notification.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if ch.Config["bot_token"] != "123456:AAAAreal" {
		t.Fatalf("masked token overwrote the stored one: %q", ch.Config["bot_token"])
	}
	if ch.Config["chat_id"] != "-100999" {
		t.Fatalf("non-secret change lost: %q", ch.Config["chat_id"])
	}

	// A genuine rotation still replaces the stored token.
	w = putChannel(d, id, `{"name":"TG","enabled":true,"config":{"bot_token":"654321:BBBBnew","chat_id":"-100999","lang":"zh"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("rotation status=%d body=%s", w.Code, w.Body.String())
	}
	if ch, _ = d.Notification.Get(context.Background(), id); ch.Config["bot_token"] != "654321:BBBBnew" {
		t.Fatalf("rotation lost: %q", ch.Config["bot_token"])
	}
}

// TestTestChannelProvider covers the generalized test endpoint: push types are
// testable, channel_id merges stored secrets behind the mask, and a bad
// channel_id is a 404 / type mismatch a 400.
//
// The masked case must NOT be a 400: the merge happens before validation, so the
// bullets never reach it. Delivery itself may fail (the phase-A provider stubs
// do not build a request at all) — that is still a 200 with ok:false, because a
// delivery failure is a result, not an API error.
func TestTestChannelProvider(t *testing.T) {
	d := channelTestDeps(t)

	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		d.handleTestChannel(w, httptest.NewRequest(http.MethodPost, "/api/v1/channels/test", strings.NewReader(body)))
		return w
	}
	decode := func(t *testing.T, w *httptest.ResponseRecorder) struct {
		OK         bool   `json:"ok"`
		StatusCode int    `json:"status_code"`
		Body       string `json:"body"`
		Error      string `json:"error"`
	} {
		t.Helper()
		var resp struct {
			OK         bool   `json:"ok"`
			StatusCode int    `json:"status_code"`
			Body       string `json:"body"`
			Error      string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %s: %v", w.Body.String(), err)
		}
		return resp
	}

	tgID, err := d.Notification.Create(context.Background(), "TG", "telegram", map[string]string{
		"bot_token": "123456:AAAAreal", "chat_id": "-100123", "lang": "zh",
	}, true)
	if err != nil {
		t.Fatalf("seed telegram: %v", err)
	}
	whID, err := d.Notification.Create(context.Background(), "WH", "webhook", map[string]string{"url": "https://x"}, true)
	if err != nil {
		t.Fatalf("seed webhook: %v", err)
	}

	// Masked secret + channel_id: accepted, delivered (unsuccessfully, since the
	// provider is still a stub), reported as a result.
	w := post(`{"type":"telegram","channel_id":"` + tgID + `","config":{"bot_token":"` + notification.MaskedSecret + `","chat_id":"-100123","lang":"zh"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("masked test status=%d body=%s", w.Code, w.Body.String())
	}
	if resp := decode(t, w); resp.OK {
		t.Fatalf("stub provider reported a successful send: %+v", resp)
	}

	// Without channel_id the endpoint still accepts a fully-typed config.
	if w := post(`{"type":"telegram","config":{"bot_token":"123456:AAAA","chat_id":"-100123"}}`); w.Code != http.StatusOK {
		t.Fatalf("unsaved telegram test status=%d body=%s", w.Code, w.Body.String())
	}

	// channel_id naming a channel of a different type: refuse rather than merge
	// one channel's secrets into another's form.
	if w := post(`{"type":"telegram","channel_id":"` + whID + `","config":{}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("type mismatch status=%d body=%s", w.Code, w.Body.String())
	}
	if w := post(`{"type":"telegram","channel_id":"chan_missing","config":{}}`); w.Code != http.StatusNotFound {
		t.Fatalf("missing channel status=%d body=%s", w.Code, w.Body.String())
	}
	// system/email remain untestable.
	if w := post(`{"type":"system","config":{}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("system test status=%d", w.Code)
	}
}

// TestCreateChannelChecksItIntoBuiltinPolicies: a channel is created in order to
// be notified through, so the create wires it into the site default AND the
// Agent-connectivity policy. The built-ins are materialized lazily by the
// notifications page, and this test deliberately never calls it — that is the
// onboarding path, where the first channel exists long before anyone opens the
// policy UI.
func TestCreateChannelChecksItIntoBuiltinPolicies(t *testing.T) {
	d := channelTestDeps(t)
	ctx := context.Background()

	w := postChannel(d, `{"name":"tg","type":"telegram","storm_merge":true,
		"config":{"bot_token":"123456:ABCDEF","chat_id":"-100123","lang":"zh"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("create = %d, body %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	policies, err := d.NotifyPolicy.List(ctx, "site_default")
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected the two built-in policies, got %d", len(policies))
	}
	for _, p := range policies {
		if !slices.Contains(p.ChannelIDs, created.ID) {
			t.Errorf("%s policy channels = %v, want the new channel %s", p.ScopeKind, p.ChannelIDs, created.ID)
		}
	}

	// A second channel joins the first rather than replacing it.
	w2 := postChannel(d, `{"name":"dd","type":"dingtalk","storm_merge":true,
		"config":{"access_token":"abc","lang":"zh"}}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("second create = %d, body %s", w2.Code, w2.Body.String())
	}
	policies, err = d.NotifyPolicy.List(ctx, "site_default")
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	for _, p := range policies {
		if len(p.ChannelIDs) != 2 {
			t.Errorf("%s policy channels = %v, want both channels", p.ScopeKind, p.ChannelIDs)
		}
	}
}
