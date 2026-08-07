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
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// dingTalkRedirect points a provider's hard-coded oapi.dingtalk.com URL at a
// local httptest server without letting the test rewrite the URL itself: the
// request that reaches the handler still carries the exact path and query Build
// produced, which is the thing under test.
type dingTalkRedirect struct {
	base *url.URL
	rt   http.RoundTripper
}

func (t dingTalkRedirect) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	c.URL.Scheme = t.base.Scheme
	c.URL.Host = t.base.Host
	c.Host = ""
	return t.rt.RoundTrip(c)
}

func dingTalkServiceFor(t *testing.T, srv *httptest.Server) *Service {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	return &Service{client: &http.Client{
		Transport: dingTalkRedirect{base: u, rt: srv.Client().Transport},
		Timeout:   10 * time.Second,
	}}
}

func dingTalkContent(t *testing.T, body []byte) string {
	t.Helper()
	var parsed dingTalkTextBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v (%s)", err, body)
	}
	if parsed.MsgType != "text" {
		t.Fatalf("msgtype=%q, want text (%s)", parsed.MsgType, body)
	}
	return parsed.Text.Content
}

// TestDingTalkBuildNoSecret locks the unsigned shape: access_token is the only
// query parameter (no timestamp/sign leaking in when 加签 is off), and the body
// is the fixed {"msgtype":"text"} envelope carrying the keyword prefix.
func TestDingTalkBuildNoSecret(t *testing.T) {
	target, body, err := dingTalkProvider{}.Build(
		map[string]string{"access_token": "tok123", "lang": "en"},
		webhookSamplePayload(), time.UnixMilli(1700000000000))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != dingTalkEndpoint {
		t.Fatalf("endpoint=%q want %q", got, dingTalkEndpoint)
	}
	q := u.Query()
	if len(q) != 1 || q.Get("access_token") != "tok123" {
		t.Fatalf("query=%v, want access_token only", q)
	}

	content := dingTalkContent(t, body)
	if !strings.HasPrefix(content, dingTalkKeywordPrefix) {
		t.Fatalf("content missing keyword prefix: %q", content)
	}
	title := RenderTitle(webhookSamplePayload(), "en")
	want := dingTalkKeywordPrefix + title + "\n" + pushText(webhookSamplePayload(), "en")
	if content != want {
		t.Fatalf("content=%q want %q", content, want)
	}
	if !strings.Contains(content, "Shop") {
		t.Fatalf("content lost the fault detail: %q", content)
	}
	// Exact envelope shape, not just "decodes into our struct".
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	if len(raw) != 2 || raw["msgtype"] != "text" {
		t.Fatalf("unexpected body shape: %s", body)
	}
	text, ok := raw["text"].(map[string]any)
	if !ok || len(text) != 1 || text["content"] != content {
		t.Fatalf("unexpected text object: %s", body)
	}
}

// TestDingTalkBuildSigned pins the 加签 signature direction: the secret is the
// HMAC key AND the tail of the signed message. Swapping the two (Feishu's
// orientation) still yields valid base64, so the signature is recomputed here
// independently rather than merely asserted present.
func TestDingTalkBuildSigned(t *testing.T) {
	const secret = "SECf1e2d3c4b5a6"
	now := time.UnixMilli(1700000000000)

	target, _, err := dingTalkProvider{}.Build(
		map[string]string{"access_token": "tok123", "secret": secret, "lang": "zh"},
		webhookSamplePayload(), now)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	q := u.Query()

	wantTS := strconv.FormatInt(now.UnixMilli(), 10)
	if q.Get("timestamp") != wantTS {
		t.Fatalf("timestamp=%q want %q", q.Get("timestamp"), wantTS)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(wantTS + "\n" + secret))
	wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if q.Get("sign") != wantSign {
		t.Fatalf("sign=%q want %q", q.Get("sign"), wantSign)
	}
	if q.Get("access_token") != "tok123" || len(q) != 3 {
		t.Fatalf("query=%v", q)
	}
	// The raw query must carry the base64 percent-encoded, never literal.
	if strings.Contains(u.RawQuery, "+") || strings.Contains(u.RawQuery, "=&") {
		t.Fatalf("signature not escaped in raw query: %q", u.RawQuery)
	}
}

func TestDingTalkValidateConfig(t *testing.T) {
	cases := []struct {
		name   string
		cfg    map[string]string
		wantOK bool
	}{
		{"missing", map[string]string{"lang": "en"}, false},
		{"empty", map[string]string{"access_token": ""}, false},
		{"blank", map[string]string{"access_token": "   "}, false},
		{"inner space", map[string]string{"access_token": "tok 123"}, false},
		{"trailing newline", map[string]string{"access_token": "tok123\n"}, false},
		{"valid", map[string]string{"access_token": "tok123"}, true},
		{"valid with secret", map[string]string{"access_token": "tok123", "secret": "SECabc"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := dingTalkProvider{}.ValidateConfig(tc.cfg)
			if tc.wantOK && msg != "" {
				t.Fatalf("want valid, got %q", msg)
			}
			if !tc.wantOK && msg == "" {
				t.Fatal("want an error message, got none")
			}
		})
	}
}

func TestDingTalkCheckResponse(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr string // "" = expect nil
	}{
		{"ok", 200, `{"errcode":0,"errmsg":"ok"}`, ""},
		{"bad token", 200, `{"errcode":300001,"errmsg":"token is not exist"}`, "300001"},
		{"bad sign", 200, `{"errcode":310000,"errmsg":"sign not match"}`, "310000"},
		{"server error", 500, `{"errcode":0,"errmsg":"ok"}`, "http 500"},
		{"gateway html", 502, `<html>bad gateway</html>`, "http 502"},
		{"garbage", 200, `not json at all`, ""},
		{"truncated json", 200, `{"errcode":300001,"errm`, ""},
		{"empty", 200, ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := dingTalkProvider{}.CheckResponse(tc.status, []byte(tc.body))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestDingTalkTruncatesContent: an oversized message is clipped at the byte cap
// on a rune boundary, not rejected and not sent half-encoded.
func TestDingTalkTruncatesContent(t *testing.T) {
	p := webhookSamplePayload()
	// Multi-byte name so a naive byte cut would land inside a UTF-8 sequence.
	p.Details[0].TargetName = strings.Repeat("测", dingTalkMaxContentBytes)

	_, body, err := dingTalkProvider{}.Build(map[string]string{"access_token": "tok123", "lang": "zh"}, p, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	content := dingTalkContent(t, body)

	if len(content) > dingTalkMaxContentBytes {
		t.Fatalf("content is %d bytes, over the %d cap", len(content), dingTalkMaxContentBytes)
	}
	if len(content) < dingTalkMaxContentBytes-utf8.UTFMax {
		t.Fatalf("content is %d bytes — expected a cut close to the %d cap", len(content), dingTalkMaxContentBytes)
	}
	if !strings.HasSuffix(content, ellipsis) {
		t.Fatalf("truncated content does not end with the ellipsis: %q", content[len(content)-16:])
	}
	if !utf8.ValidString(content) {
		t.Fatal("truncation cut inside a UTF-8 sequence")
	}
	if !strings.HasPrefix(content, dingTalkKeywordPrefix) {
		t.Fatal("truncation dropped the keyword prefix")
	}
}

// TestDingTalkDeliverSoftFailure is the end-to-end path: POST + JSON, and an
// HTTP 200 carrying a non-zero errcode must come back as a FAILURE with the
// platform's own errmsg in the snippet.
func TestDingTalkDeliverSoftFailure(t *testing.T) {
	var gotMethod, gotCT, gotPath, gotToken string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotCT, gotPath = r.Method, r.Header.Get("Content-Type"), r.URL.Path
		gotToken = r.URL.Query().Get("access_token")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"errcode":300001,"errmsg":"token is not exist"}`)
	}))
	defer srv.Close()

	status, snippet, err := dingTalkServiceFor(t, srv).deliverProvider(context.Background(),
		dingTalkProvider{}, map[string]string{"access_token": "tok123", "lang": "en"}, webhookSamplePayload())

	if gotMethod != http.MethodPost || gotCT != "application/json" {
		t.Fatalf("method=%s content-type=%s", gotMethod, gotCT)
	}
	if gotPath != "/robot/send" || gotToken != "tok123" {
		t.Fatalf("path=%s access_token=%s", gotPath, gotToken)
	}
	if c := dingTalkContent(t, gotBody); !strings.HasPrefix(c, dingTalkKeywordPrefix) {
		t.Fatalf("delivered content missing prefix: %q", c)
	}
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200", status)
	}
	if err == nil {
		t.Fatal("HTTP 200 with errcode 300001 must be reported as a failure")
	}
	if !strings.Contains(err.Error(), "300001") || !strings.Contains(snippet, "token is not exist") {
		t.Fatalf("err=%v snippet=%q", err, snippet)
	}
}

// TestDingTalkDeliverSuccess: errcode 0 is the only genuine success.
func TestDingTalkDeliverSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	status, _, err := dingTalkServiceFor(t, srv).deliverProvider(context.Background(),
		dingTalkProvider{}, map[string]string{"access_token": "tok123", "secret": "SECabc"}, webhookSamplePayload())
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
}
