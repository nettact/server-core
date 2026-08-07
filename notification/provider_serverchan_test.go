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

func serverChanSamplePayload() Payload {
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

// serverChanBody decodes a built body, asserting it carries exactly the two
// documented fields.
func serverChanBody(t *testing.T, raw []byte) (title, desp string) {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("body is not a JSON object of strings: %v (%s)", err, raw)
	}
	if len(m) != 2 {
		t.Fatalf("body has %d fields, want title+desp only: %s", len(m), raw)
	}
	return m["title"], m["desp"]
}

// TestServerChanBuildTurboKey locks the Turbo endpoint and the exact body: a
// title/desp pair whose desp is pushText with every newline doubled, because a
// single newline is not a line break in ServerChan's markdown.
func TestServerChanBuildTurboKey(t *testing.T) {
	p := serverChanSamplePayload()
	cfg := map[string]string{"sendkey": "SCTxxxx", "lang": "en"}

	url, body, err := serverChanProvider{}.Build(cfg, p, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if url != "https://sctapi.ftqq.com/SCTxxxx.send" {
		t.Fatalf("url=%s", url)
	}

	wantTitle := RenderTitle(p, "en")
	wantDesp := strings.ReplaceAll(pushText(p, "en"), "\n", "\n\n")
	want, err := json.Marshal(struct {
		Title string `json:"title"`
		Desp  string `json:"desp"`
	}{Title: wantTitle, Desp: wantDesp})
	if err != nil {
		t.Fatalf("marshal expected: %v", err)
	}
	if string(body) != string(want) {
		t.Fatalf("body mismatch:\n got %s\nwant %s", body, want)
	}

	title, desp := serverChanBody(t, body)
	if title != "Network fault" {
		t.Fatalf("title=%q", title)
	}
	if !strings.Contains(desp, "\n\n") {
		t.Fatalf("desp has no blank-line separators: %q", desp)
	}
	// Every newline must be part of a doubled pair — a lone one would collapse.
	if strings.Contains(strings.ReplaceAll(desp, "\n\n", ""), "\n") {
		t.Fatalf("desp carries a lone newline: %q", desp)
	}
	if !strings.Contains(desp, "https://console.example.com/incidents/inc_1") {
		t.Fatalf("desp lost the console link: %q", desp)
	}
}

// TestServerChanBuildSCTPKey: a Server酱³ key routes to its account's shard, with
// the numeric id lifted out of the key itself.
func TestServerChanBuildSCTPKey(t *testing.T) {
	url, body, err := serverChanProvider{}.Build(
		map[string]string{"sendkey": "sctp12345tabcdef", "lang": "en"},
		serverChanSamplePayload(), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if want := "https://12345.push.ft07.com/send/sctp12345tabcdef.send"; url != want {
		t.Fatalf("url=%s want=%s", url, want)
	}
	if title, desp := serverChanBody(t, body); title == "" || desp == "" {
		t.Fatalf("empty title/desp: %s", body)
	}
}

func TestServerChanValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr bool
	}{
		{"missing", map[string]string{"lang": "en"}, true},
		{"blank", map[string]string{"sendkey": "   "}, true},
		{"inner whitespace", map[string]string{"sendkey": "SCT123 456"}, true},
		{"trailing newline", map[string]string{"sendkey": "SCT123456\n"}, true},
		{"valid turbo", map[string]string{"sendkey": "SCT123456abcdef"}, false},
		{"valid sctp", map[string]string{"sendkey": "sctp12345tabcdef"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := serverChanProvider{}.ValidateConfig(tt.cfg)
			if (msg != "") != tt.wantErr {
				t.Fatalf("ValidateConfig=%q wantErr=%v", msg, tt.wantErr)
			}
		})
	}
}

func TestServerChanCheckResponse(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantErr  bool
		contains string
	}{
		{"ok", 200, `{"code":0,"message":"","data":{"pushid":"1"}}`, false, ""},
		{"in-band failure", 200, `{"code":40001,"message":"bad key"}`, true, "40001"},
		{"in-band failure no message", 200, `{"code":40001}`, true, "40001"},
		{"server error", 500, `nginx`, true, "500"},
		{"garbage body", 200, `<html>gateway</html>`, false, ""},
		{"truncated json", 200, `{"code":0,"message":"","data":{"pu`, false, ""},
		{"empty body", 200, ``, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := serverChanProvider{}.CheckResponse(tt.status, []byte(tt.body))
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckResponse=%v wantErr=%v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("error %q does not contain %q", err, tt.contains)
			}
		})
	}
}

// TestServerChanTitleTruncation uses a Chinese headline so the 32-RUNE cap is
// distinguishable from a byte cap (which would cut it at 10 characters).
func TestServerChanTitleTruncation(t *testing.T) {
	p := serverChanSamplePayload()
	p.Event = "incident.resolved"
	p.State = "resolved"
	p.GroupMerged = true
	p.GroupName = strings.Repeat("网", 60)

	_, body, err := serverChanProvider{}.Build(map[string]string{"sendkey": "SCT1", "lang": "zh"}, p, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	title, _ := serverChanBody(t, body)
	if n := utf8.RuneCountInString(title); n != serverChanTitleRunes {
		t.Fatalf("title is %d runes, want %d: %q", n, serverChanTitleRunes, title)
	}
	if !strings.HasSuffix(title, ellipsis) {
		t.Fatalf("truncated title not marked: %q", title)
	}
	if len(title) <= serverChanTitleRunes {
		t.Fatalf("multi-byte title collapsed to a byte cap: %q", title)
	}
}

func TestServerChanDespCap(t *testing.T) {
	p := serverChanSamplePayload()
	p.URL = "https://console.example.com/" + strings.Repeat("a", 40000)

	_, body, err := serverChanProvider{}.Build(map[string]string{"sendkey": "SCT1", "lang": "en"}, p, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, desp := serverChanBody(t, body)
	if len(desp) != serverChanDespBytes {
		t.Fatalf("desp is %d bytes, want the %d cap", len(desp), serverChanDespBytes)
	}
	if !strings.HasSuffix(desp, ellipsis) {
		t.Fatalf("truncated desp not marked")
	}
}

// TestServerChanDeliverInBandFailure is the end-to-end path: POST + JSON body to
// the built URL, and an HTTP 200 carrying code!=0 reported as a failure with the
// platform's own text in the snippet.
func TestServerChanDeliverInBandFailure(t *testing.T) {
	var gotMethod, gotCT, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotCT, gotPath = r.Method, r.Header.Get("Content-Type"), r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"code":40001,"message":"bad pushkey"}`)
	}))
	defer srv.Close()

	// deliverProvider posts to whatever Build returns, so the test server is
	// reached by overriding the built URL through a stub around the real provider.
	svc := &Service{client: &http.Client{Timeout: 10 * time.Second}}
	prov := serverChanRedirect{base: srv.URL}
	status, snippet, err := svc.deliverProvider(context.Background(), prov,
		map[string]string{"sendkey": "SCTxxxx", "lang": "en"}, serverChanSamplePayload())

	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if err == nil || !strings.Contains(err.Error(), "40001") {
		t.Fatalf("err=%v, want a 40001 classification error", err)
	}
	if !strings.Contains(snippet, "bad pushkey") {
		t.Fatalf("snippet=%q", snippet)
	}
	if gotMethod != http.MethodPost || gotCT != "application/json" {
		t.Fatalf("method=%s content-type=%s", gotMethod, gotCT)
	}
	if gotPath != "/SCTxxxx.send" {
		t.Fatalf("path=%s, want the Turbo send path", gotPath)
	}
	title, desp := serverChanBody(t, gotBody)
	if title != "Network fault" || !strings.Contains(desp, "\n\n") {
		t.Fatalf("delivered body title=%q desp=%q", title, desp)
	}
}

// serverChanRedirect is the real provider with only the host swapped for a test
// server: the URL derivation is asserted directly in the Build tests, and this
// keeps the delivery test off the live sctapi.ftqq.com.
type serverChanRedirect struct {
	serverChanProvider
	base string
}

func (r serverChanRedirect) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	url, body, err := r.serverChanProvider.Build(cfg, p, now)
	if err != nil {
		return "", nil, err
	}
	return r.base + strings.TrimPrefix(url, "https://sctapi.ftqq.com"), body, nil
}
