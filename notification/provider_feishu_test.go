package notification

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func feishuSamplePayload() Payload {
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
		At: time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC),
	}
}

// feishuFixedNow is an arbitrary but FIXED send instant: the signature test
// recomputes the HMAC from this exact second, so the assertion is on the real
// digest rather than "some base64 is present".
var feishuFixedNow = time.Unix(1700000000, 0)

// TestFeishuBuildNoSecret locks the unsigned body byte for byte, and in
// particular that timestamp/sign are ABSENT rather than empty — a bot without
// signing enabled rejects a request that carries them.
func TestFeishuBuildNoSecret(t *testing.T) {
	p := feishuSamplePayload()
	url, body, err := feishuProvider{}.Build(
		map[string]string{"webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/abc", "lang": "en"},
		p, feishuFixedNow)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if url != "https://open.feishu.cn/open-apis/bot/v2/hook/abc" {
		t.Fatalf("url rewritten: %s", url)
	}
	// Built as a literal rather than from a map, because a map marshals its keys
	// in sorted order and the wire body's field order is msg_type then content.
	text, err := json.Marshal(RenderTitle(p, "en") + "\n" + pushText(p, "en"))
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	want := `{"msg_type":"text","content":{"text":` + string(text) + `}}`
	if string(body) != want {
		t.Fatalf("body\n got %s\nwant %s", body, want)
	}
	if strings.Contains(string(body), "timestamp") || strings.Contains(string(body), "sign") {
		t.Fatalf("unsigned body carries signing keys: %s", body)
	}
}

// TestFeishuBuildSigned recomputes the signature independently: the HMAC key is
// "<unix seconds>\n<secret>" and the MESSAGE IS EMPTY, which is the inverse of
// DingTalk's arrangement. The timestamp must be a JSON string in seconds.
func TestFeishuBuildSigned(t *testing.T) {
	const secret = "s3cr3t"
	_, body, err := feishuProvider{}.Build(
		map[string]string{
			"webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/abc",
			"secret":      secret,
			"lang":        "en",
		}, feishuSamplePayload(), feishuFixedNow)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	ts := strconv.FormatInt(feishuFixedNow.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(ts+"\n"+secret))
	wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	var got struct {
		Timestamp string `json:"timestamp"`
		Sign      string `json:"sign"`
		MsgType   string `json:"msg_type"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if got.Timestamp != "1700000000" {
		t.Fatalf("timestamp=%q want seconds string 1700000000", got.Timestamp)
	}
	if got.Sign != wantSign {
		t.Fatalf("sign=%q want %q", got.Sign, wantSign)
	}
	if got.MsgType != "text" {
		t.Fatalf("msg_type=%q", got.MsgType)
	}
	// The timestamp must be a JSON string, not a number: Feishu rejects the
	// numeric form.
	if !strings.Contains(string(body), `"timestamp":"1700000000"`) {
		t.Fatalf("timestamp not sent as a JSON string: %s", body)
	}
}

func TestFeishuValidateConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]string
		ok   bool
	}{
		{"missing url", map[string]string{}, false},
		{"blank url", map[string]string{"webhook_url": "   "}, false},
		{"wrong scheme", map[string]string{"webhook_url": "ftp://open.feishu.cn/hook/abc"}, false},
		{"https", map[string]string{"webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/abc"}, true},
		{"http", map[string]string{"webhook_url": "http://open.feishu.cn/open-apis/bot/v2/hook/abc"}, true},
		{"secret optional", map[string]string{"webhook_url": "https://x/hook", "secret": ""}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := feishuProvider{}.ValidateConfig(c.cfg)
			if c.ok && msg != "" {
				t.Fatalf("valid config rejected: %s", msg)
			}
			if !c.ok && msg == "" {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestFeishuCheckResponse(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
		contain string
	}{
		{"current success", 200, `{"code":0,"msg":"success"}`, false, ""},
		{"current failure", 200, `{"code":19001,"msg":"param invalid"}`, true, "19001"},
		{"legacy success", 200, `{"StatusCode":0,"StatusMessage":"success"}`, false, ""},
		{"legacy failure", 200, `{"StatusCode":9499,"StatusMessage":"bad request"}`, true, "9499"},
		{"server error", 500, `oops`, true, "500"},
		{"garbage tolerated", 200, `{"code":0,"msg":"suc`, false, ""},
		{"empty tolerated", 200, ``, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := feishuProvider{}.CheckResponse(c.status, []byte(c.body))
			if c.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.contain != "" && !strings.Contains(err.Error(), c.contain) {
				t.Fatalf("error %q missing %q", err, c.contain)
			}
		})
	}
}

// TestFeishuBuildTruncates: an over-long message is cut at the byte cap, on a
// rune boundary, with the ellipsis counted against the cap.
func TestFeishuBuildTruncates(t *testing.T) {
	p := feishuSamplePayload()
	// Three bytes per character, so the cut lands mid-"character" unless the
	// truncator walks back to a rune start.
	p.Details[0].TargetName = strings.Repeat("网络监控", 3000)

	_, body, err := feishuProvider{}.Build(
		map[string]string{"webhook_url": "https://open.feishu.cn/hook/abc", "lang": "zh"}, p, feishuFixedNow)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var got feishuBody
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	text := got.Content.Text
	if len(text) > feishuMaxTextBytes {
		t.Fatalf("text %d bytes exceeds cap %d", len(text), feishuMaxTextBytes)
	}
	if len(text) < feishuMaxTextBytes-8 {
		t.Fatalf("text %d bytes: payload did not reach the cap, test proves nothing", len(text))
	}
	if !strings.HasSuffix(text, ellipsis) {
		t.Fatalf("truncated text lacks ellipsis: %q", text[len(text)-16:])
	}
	if !utf8.ValidString(text) {
		t.Fatal("truncation split a UTF-8 sequence")
	}
}

// TestFeishuDeliverProvider is the end-to-end run: POST as application/json to
// the configured URL, and an HTTP 200 carrying a non-zero code classified as a
// failure with the platform's own message in the snippet.
func TestFeishuDeliverProvider(t *testing.T) {
	var gotMethod, gotCT, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotCT, gotPath = r.Method, r.Header.Get("Content-Type"), r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"code":19021,"msg":"sign match fail or timestamp is not within one hour from current time"}`)
	}))
	defer srv.Close()

	svc := &Service{client: &http.Client{Timeout: 10 * time.Second}}
	cfg := map[string]string{"webhook_url": srv.URL + "/open-apis/bot/v2/hook/abc", "secret": "s3cr3t", "lang": "en"}
	status, snippet, err := svc.deliverProvider(context.Background(), feishuProvider{}, cfg, feishuSamplePayload())

	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if err == nil || !strings.Contains(err.Error(), "19021") {
		t.Fatalf("in-band failure not classified: %v", err)
	}
	if !strings.Contains(snippet, "sign match fail") {
		t.Fatalf("snippet lost platform message: %q", snippet)
	}
	if gotMethod != http.MethodPost || gotCT != "application/json" {
		t.Fatalf("method=%s content-type=%s", gotMethod, gotCT)
	}
	if gotPath != "/open-apis/bot/v2/hook/abc" {
		t.Fatalf("path=%s", gotPath)
	}
	var sent feishuBody
	if err := json.Unmarshal(gotBody, &sent); err != nil {
		t.Fatalf("sent body not valid JSON: %v (%s)", err, gotBody)
	}
	if sent.MsgType != "text" || sent.Sign == "" || sent.Content.Text == "" {
		t.Fatalf("sent body incomplete: %+v", sent)
	}
}
