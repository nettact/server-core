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

// weComTestPayload is the minimal fully-deterministic payload: a test event with
// no details renders to a title, the fixed test-notification line and the link
// line, so the expected request body can be written out literally.
func weComTestPayload() Payload {
	return Payload{
		Event: "test",
		URL:   "https://console.example.com/i/inc_1",
		At:    time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC),
	}
}

func weComFaultPayload() Payload {
	return Payload{
		Event:          "incident.opened",
		IncidentID:     "inc_2",
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
		URL: "https://console.example.com/i/inc_2",
		At:  time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC),
	}
}

// TestWeComBuild locks the wire contract: the group-robot endpoint with the key
// URL-escaped into the query, and a msgtype "text" envelope whose content is the
// headline plus the shared push text — with no platform prefix, since a WeCom
// robot has no keyword security mode to satisfy.
func TestWeComBuild(t *testing.T) {
	cfg := map[string]string{"key": "a+b/c=d", "lang": "en"}
	gotURL, gotBody, err := weComProvider{}.Build(cfg, weComTestPayload(), time.Time{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	wantURL := "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=a%2Bb%2Fc%3Dd"
	if gotURL != wantURL {
		t.Fatalf("url=%q want %q", gotURL, wantURL)
	}
	wantBody := `{"msgtype":"text","text":{"content":"NetTact test notification\nThis is a test notification from NetTact.\nView details: https://console.example.com/i/inc_1"}}`
	if string(gotBody) != wantBody {
		t.Fatalf("body=%s\nwant %s", gotBody, wantBody)
	}

	// The same composition rule on a real fault payload, where the detail lines
	// are the renderers' business rather than this provider's.
	_, gotBody, err = weComProvider{}.Build(cfg, weComFaultPayload(), time.Time{})
	if err != nil {
		t.Fatalf("build fault: %v", err)
	}
	var env struct {
		MsgType string `json:"msgtype"`
		Text    struct {
			Content string `json:"content"`
		} `json:"text"`
	}
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("decode: %v (%s)", err, gotBody)
	}
	want := RenderTitle(weComFaultPayload(), "en") + "\n" + pushText(weComFaultPayload(), "en")
	if env.MsgType != "text" || env.Text.Content != want {
		t.Fatalf("msgtype=%q content=%q want %q", env.MsgType, env.Text.Content, want)
	}
}

func TestWeComValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr bool
	}{
		{"missing key", map[string]string{"lang": "en"}, true},
		{"blank key", map[string]string{"key": "   "}, true},
		{"key with space", map[string]string{"key": "693a91f6 7d0e"}, true},
		{"key with newline", map[string]string{"key": "693a91f6\n"}, true},
		{"valid", map[string]string{"key": "693a91f6-7d0e-4bc4-97a0-0ec2sifa5aaa", "lang": "en"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := weComProvider{}.ValidateConfig(tc.cfg)
			if (msg != "") != tc.wantErr {
				t.Fatalf("ValidateConfig=%q wantErr=%v", msg, tc.wantErr)
			}
		})
	}
}

func TestWeComCheckResponse(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr bool
		contain string
	}{
		{"ok", 200, `{"errcode":0,"errmsg":"ok"}`, false, ""},
		{"soft failure", 200, `{"errcode":93000,"errmsg":"invalid webhook url"}`, true, "93000"},
		{"http error", 500, `oops`, true, "500"},
		{"garbage body", 200, `<html>gateway</html>`, false, ""},
		{"empty body", 200, ``, false, ""},
		{"truncated json", 200, `{"errcode":0,"errmsg":"o`, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := weComProvider{}.CheckResponse(tc.status, []byte(tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckResponse=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.contain != "" && !strings.Contains(err.Error(), tc.contain) {
				t.Fatalf("error %v does not mention %q", err, tc.contain)
			}
		})
	}
}

// TestWeComTruncation: an over-long message is cut to WeCom's documented byte
// cap, on a rune boundary, with the ellipsis counted against the limit. Chinese
// text is the case that matters — three bytes per character means the naive cut
// lands mid-sequence and the platform rejects the whole message.
func TestWeComTruncation(t *testing.T) {
	p := weComTestPayload()
	p.URL = "https://console.example.com/i/" + strings.Repeat("测", 900)
	_, body, err := weComProvider{}.Build(map[string]string{"key": "k", "lang": "en"}, p, time.Time{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var env struct {
		Text struct {
			Content string `json:"content"`
		} `json:"text"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	content := env.Text.Content
	if len(content) > weComContentBytes {
		t.Fatalf("content is %d bytes, over the %d-byte cap", len(content), weComContentBytes)
	}
	if len(content) >= weComContentBytes {
		t.Fatalf("content lands exactly on the cap (%d): the cut did not back up to a rune boundary", len(content))
	}
	if !strings.HasSuffix(content, ellipsis) {
		t.Fatalf("truncated content lost its ellipsis: %q", content[len(content)-16:])
	}
	if !utf8.ValidString(content) {
		t.Fatal("truncation produced invalid UTF-8")
	}
	if !strings.HasSuffix(strings.TrimSuffix(content, ellipsis), "测") {
		t.Fatalf("cut did not land on a whole rune: %q", content[len(content)-16:])
	}
}

// weComRoutedProvider is the real provider with its endpoint pointed at a test
// server: everything else — body, Content-Type, response classification — is the
// production path.
type weComRoutedProvider struct {
	weComProvider
	base string
}

func (w weComRoutedProvider) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	_, body, err := w.weComProvider.Build(cfg, p, now)
	return w.base, body, err
}

// TestWeComDeliverSoftFailure is the end-to-end case that justifies the whole
// Provider interface: HTTP 200 with a non-zero errcode must come back as an
// error, with the platform's own errmsg in the snippet.
func TestWeComDeliverSoftFailure(t *testing.T) {
	var gotMethod, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotCT = r.Method, r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"errcode":93000,"errmsg":"invalid webhook url"}`)
	}))
	defer srv.Close()

	prov := weComRoutedProvider{base: srv.URL}
	svc := &Service{client: &http.Client{Timeout: 10 * time.Second}}
	status, snippet, err := svc.deliverProvider(context.Background(),
		prov, map[string]string{"key": "k", "lang": "en"}, weComTestPayload())

	if gotMethod != http.MethodPost || gotCT != "application/json" {
		t.Fatalf("method=%s content-type=%s", gotMethod, gotCT)
	}
	wantBody := `{"msgtype":"text","text":{"content":"NetTact test notification\nThis is a test notification from NetTact.\nView details: https://console.example.com/i/inc_1"}}`
	if string(gotBody) != wantBody {
		t.Fatalf("request body=%s\nwant %s", gotBody, wantBody)
	}
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if err == nil {
		t.Fatal("errcode 93000 was classified as a success")
	}
	if !strings.Contains(snippet, "invalid webhook url") {
		t.Fatalf("snippet lost the platform errmsg: %q", snippet)
	}
}
