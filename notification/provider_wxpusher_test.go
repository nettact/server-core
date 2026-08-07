package notification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func wxPusherPayload() Payload {
	return Payload{
		Event:          "incident.opened",
		IncidentID:     "inc_1",
		SiteID:         "site_1",
		State:          "open",
		Severity:       "critical",
		Scope:          "single",
		AgentCount:     1,
		SuspectedLayer: "service",
		Details: []FaultDetail{{
			ProbeKind: "http", MetricKind: "probe.http.status", Comparator: "eq",
			Threshold: 200, Value: 503, TargetName: "Shop", Target: "https://shop.example.com",
			Layer: "service", Severity: "critical", AgentHost: "living-room",
		}},
		URL: "https://console.example.com/incidents/inc_1",
		At:  time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC),
	}
}

// wxPusherBuild is the shared decode step: Build must always produce the fixed
// endpoint and a JSON object, so every test below starts from the decoded body
// rather than repeating the marshal/error dance.
func wxPusherBuild(t *testing.T, cfg map[string]string, p Payload) map[string]json.RawMessage {
	t.Helper()
	url, body, err := wxPusherProvider{}.Build(cfg, p, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if url != "https://wxpusher.zjiecode.com/api/send/message" {
		t.Fatalf("endpoint = %q", url)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body not valid JSON: %v (%s)", err, body)
	}
	return got
}

func wxPusherStr(t *testing.T, raw map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw[key], &s); err != nil {
		t.Fatalf("%s not a string: %v (%s)", key, err, raw[key])
	}
	return s
}

// TestWxPusherBuildUIDsOnly locks the exact wire shape of a uids-only channel:
// every documented field present with the right value, and no topicIds key at
// all (omitempty), since a null/[] there is noise the platform never asked for.
func TestWxPusherBuildUIDsOnly(t *testing.T) {
	p := wxPusherPayload()
	cfg := map[string]string{
		"app_token": "AT_secret",
		"uids":      "UID_a, UID_b\nUID_c",
		"lang":      "en",
	}
	got := wxPusherBuild(t, cfg, p)

	wantKeys := map[string]bool{"appToken": true, "content": true, "summary": true, "contentType": true, "uids": true, "url": true}
	for k := range got {
		if !wantKeys[k] {
			t.Fatalf("unexpected key %q in body", k)
		}
	}
	for k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing key %q in body", k)
		}
	}
	if _, ok := got["topicIds"]; ok {
		t.Fatal("topicIds must be omitted when no topics are configured")
	}

	if v := wxPusherStr(t, got, "appToken"); v != "AT_secret" {
		t.Fatalf("appToken = %q", v)
	}
	wantContent := RenderTitle(p, "en") + "\n" + pushText(p, "en")
	if v := wxPusherStr(t, got, "content"); v != wantContent {
		t.Fatalf("content = %q want %q", v, wantContent)
	}
	if v := wxPusherStr(t, got, "summary"); v != truncateRunes(RenderTitle(p, "en"), 20) {
		t.Fatalf("summary = %q", v)
	}
	if v := wxPusherStr(t, got, "url"); v != p.URL {
		t.Fatalf("url = %q want %q", v, p.URL)
	}
	if string(got["contentType"]) != "1" {
		t.Fatalf("contentType = %s, want 1 (plain text)", got["contentType"])
	}
	var uids []string
	if err := json.Unmarshal(got["uids"], &uids); err != nil {
		t.Fatalf("uids: %v", err)
	}
	if len(uids) != 3 || uids[0] != "UID_a" || uids[1] != "UID_b" || uids[2] != "UID_c" {
		t.Fatalf("uids = %v (comma + newline separators must both split)", uids)
	}
}

// TestWxPusherBuildTopicsOnly: a topics-only channel sends numeric topicIds and
// omits uids. Mixed comma/newline/space separators and a trailing comma are all
// accepted, because the console field is a free-form textarea.
func TestWxPusherBuildTopicsOnly(t *testing.T) {
	cfg := map[string]string{
		"app_token": "AT_secret",
		"topic_ids": "123,456\n789 1011,",
		"lang":      "en",
	}
	got := wxPusherBuild(t, cfg, wxPusherPayload())
	if _, ok := got["uids"]; ok {
		t.Fatal("uids must be omitted when no uids are configured")
	}
	var topics []int
	if err := json.Unmarshal(got["topicIds"], &topics); err != nil {
		t.Fatalf("topicIds: %v (%s)", err, got["topicIds"])
	}
	want := []int{123, 456, 789, 1011}
	if len(topics) != len(want) {
		t.Fatalf("topicIds = %v want %v", topics, want)
	}
	for i := range want {
		if topics[i] != want[i] {
			t.Fatalf("topicIds = %v want %v", topics, want)
		}
	}
}

// TestWxPusherBuildNoConsoleURL: an incident with no console link omits url
// rather than sending an empty string WeChat would render as a dead button.
func TestWxPusherBuildNoConsoleURL(t *testing.T) {
	p := wxPusherPayload()
	p.URL = ""
	got := wxPusherBuild(t, map[string]string{"app_token": "AT_x", "uids": "UID_a"}, p)
	if _, ok := got["url"]; ok {
		t.Fatalf("url present for a payload with no console link: %s", got["url"])
	}
}

func TestWxPusherValidateConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  map[string]string
		want string // "" = valid; otherwise a substring the message must contain
	}{
		{"missing token", map[string]string{"uids": "UID_a"}, "app token"},
		{"blank token", map[string]string{"app_token": "   ", "uids": "UID_a"}, "app token"},
		{"no recipients", map[string]string{"app_token": "AT_x"}, "uid or topic"},
		{"recipients only whitespace", map[string]string{"app_token": "AT_x", "uids": " ,\n ,"}, "uid or topic"},
		{"non-numeric topic", map[string]string{"app_token": "AT_x", "topic_ids": "123,abc"}, "abc"},
		{"valid uids only", map[string]string{"app_token": "AT_x", "uids": "UID_a\nUID_b"}, ""},
		{"valid topics only", map[string]string{"app_token": "AT_x", "topic_ids": "123"}, ""},
		{"valid both", map[string]string{"app_token": "AT_x", "uids": "UID_a", "topic_ids": "123, 456"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wxPusherProvider{}.ValidateConfig(tt.cfg)
			if tt.want == "" {
				if got != "" {
					t.Fatalf("want valid, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("got %q, want it to mention %q", got, tt.want)
			}
		})
	}
}

// TestWxPusherCheckResponse pins the 1000-means-success convention, which is the
// whole reason this provider cannot be a webhook preset.
func TestWxPusherCheckResponse(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string // "" = nil error
	}{
		{"success code 1000", 200, `{"code":1000,"msg":"处理成功"}`, ""},
		{"soft failure 1001", 200, `{"code":1001,"msg":"appToken 校验失败"}`, "1001"},
		{"zero is NOT success", 200, `{"code":0,"msg":"x"}`, "0"},
		{"server error", 500, `{"code":1000}`, "http 500"},
		{"bad gateway", 502, ``, "http 502"},
		{"garbage body", 200, `<html>proxy interstitial</html>`, ""},
		{"truncated json", 200, `{"code":1000,"data":[{"uid":"UID_a"`, ""},
		{"empty body", 200, ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wxPusherProvider{}.CheckResponse(tt.status, []byte(tt.body))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
	// The 1001 error must carry the platform's own message: "code 1001" alone
	// leaves the operator nothing to act on.
	err := wxPusherProvider{}.CheckResponse(200, []byte(`{"code":1001,"msg":"appToken 校验失败"}`))
	if err == nil || !strings.Contains(err.Error(), "appToken 校验失败") {
		t.Fatalf("error dropped the platform msg: %v", err)
	}
}

// TestWxPusherSummaryTruncation: the banner cap counts RUNES, not bytes — a
// 20-character Chinese title is 60 bytes and must survive intact.
func TestWxPusherSummaryTruncation(t *testing.T) {
	p := wxPusherPayload()
	p.Event = "incident.resolved"
	p.State = "resolved"
	p.GroupMerged = true
	p.GroupName = strings.Repeat("长", 40)
	cfg := map[string]string{"app_token": "AT_x", "uids": "UID_a"} // zh (default)

	got := wxPusherBuild(t, cfg, p)
	summary := wxPusherStr(t, got, "summary")
	if n := utf8.RuneCountInString(summary); n != 20 {
		t.Fatalf("summary is %d runes, want exactly 20: %q", n, summary)
	}
	if !strings.HasSuffix(summary, ellipsis) {
		t.Fatalf("truncated summary must end with an ellipsis: %q", summary)
	}
	if len(summary) <= 20 {
		t.Fatalf("summary should be multi-byte here (%d bytes) — test lost its point", len(summary))
	}
	// A short title is passed through untouched, ellipsis and all.
	short := wxPusherPayload()
	shortSummary := wxPusherStr(t, wxPusherBuild(t, cfg, short), "summary")
	if shortSummary != RenderTitle(short, "") || strings.HasSuffix(shortSummary, ellipsis) {
		t.Fatalf("short title was altered: %q", shortSummary)
	}
}

// TestWxPusherContentCap: an absurd target name cannot push the body past
// WxPusher's 40000-character content ceiling.
func TestWxPusherContentCap(t *testing.T) {
	p := wxPusherPayload()
	p.Details[0].TargetName = strings.Repeat("超", 60000)
	got := wxPusherBuild(t, map[string]string{"app_token": "AT_x", "uids": "UID_a", "lang": "en"}, p)
	content := wxPusherStr(t, got, "content")
	if n := utf8.RuneCountInString(content); n != 40000 {
		t.Fatalf("content is %d runes, want the 40000 cap", n)
	}
	if !strings.HasSuffix(content, ellipsis) {
		t.Fatalf("truncated content must end with an ellipsis")
	}
	// A normal payload is far under the cap and must not be touched.
	normal := wxPusherStr(t, wxPusherBuild(t, map[string]string{"app_token": "AT_x", "uids": "UID_a", "lang": "en"}, wxPusherPayload()), "content")
	if strings.HasSuffix(normal, ellipsis) {
		t.Fatalf("normal content was truncated: %q", normal)
	}
}

// TestWxPusherDeliverSoftFailure is the end-to-end path: deliverProvider must
// POST JSON and then report an HTTP 200 carrying code 1001 as a FAILURE, with
// the platform's reply available as the snippet.
func TestWxPusherDeliverSoftFailure(t *testing.T) {
	var gotMethod, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotCT = r.Method, r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"code":1001,"msg":"appToken 校验失败"}`)
	}))
	defer srv.Close()

	// deliverProvider posts to Build's fixed endpoint, so the test server is
	// reached through a provider whose only difference is the target URL.
	svc := &Service{client: &http.Client{Timeout: 10 * time.Second}}
	status, snippet, err := svc.deliverProvider(context.Background(),
		wxPusherTestEndpoint{srv.URL},
		map[string]string{"app_token": "AT_x", "uids": "UID_a", "lang": "en"},
		wxPusherPayload())

	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if err == nil || !strings.Contains(err.Error(), "1001") {
		t.Fatalf("code 1001 must be an error, got %v", err)
	}
	if !strings.Contains(snippet, "appToken") {
		t.Fatalf("snippet lost the platform reply: %q", snippet)
	}
	if gotMethod != http.MethodPost || gotCT != "application/json" {
		t.Fatalf("method=%s content-type=%s", gotMethod, gotCT)
	}
	var parsed map[string]any
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("posted body not valid JSON: %v (%s)", err, gotBody)
	}
	if parsed["appToken"] != "AT_x" || parsed["contentType"] != float64(1) {
		t.Fatalf("posted body = %v", parsed)
	}
}

// wxPusherTestEndpoint is the real provider with Build's fixed hosted endpoint
// swapped for a local test server. Everything else — body, classification,
// secrets — is the production implementation, so the end-to-end test exercises
// the shipped code rather than a re-implementation of it.
type wxPusherTestEndpoint struct{ url string }

func (e wxPusherTestEndpoint) ValidateConfig(cfg map[string]string) string {
	return wxPusherProvider{}.ValidateConfig(cfg)
}

func (e wxPusherTestEndpoint) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	_, body, err := wxPusherProvider{}.Build(cfg, p, now)
	return e.url, body, err
}

func (e wxPusherTestEndpoint) CheckResponse(status int, body []byte) error {
	return wxPusherProvider{}.CheckResponse(status, body)
}

func (e wxPusherTestEndpoint) SecretKeys() []string { return wxPusherProvider{}.SecretKeys() }
