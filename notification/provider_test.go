package notification

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeProvider is a Provider that records what it was asked to build and replies
// with whatever the test wants. It exists so the framework tests exercise
// deliverProvider's transport contract WITHOUT depending on any real platform's
// wire format — the six real providers own their own test files.
type fakeProvider struct {
	url       string
	body      []byte
	buildErr  error
	checkErr  error
	gotStatus int
	gotBody   string
	gotNow    time.Time
}

func (f *fakeProvider) ValidateConfig(cfg map[string]string) string { return cfg["bad"] }

func (f *fakeProvider) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	f.gotNow = now
	if f.buildErr != nil {
		return "", nil, f.buildErr
	}
	return f.url, f.body, nil
}

func (f *fakeProvider) CheckResponse(status int, body []byte) error {
	f.gotStatus, f.gotBody = status, string(body)
	return f.checkErr
}

func (f *fakeProvider) SecretKeys() []string { return []string{"token"} }

func TestProviderForRegistry(t *testing.T) {
	for _, typ := range []string{"dingtalk", "wecom", "feishu", "telegram", "serverchan", "wxpusher"} {
		if p, ok := ProviderFor(typ); !ok || p == nil {
			t.Errorf("ProviderFor(%q) = %v, %v; want a registered provider", typ, p, ok)
		}
	}
	for _, typ := range []string{"webhook", "email", "system", "nope", ""} {
		if _, ok := ProviderFor(typ); ok {
			t.Errorf("ProviderFor(%q) unexpectedly hit the push registry", typ)
		}
	}
}

func TestSecretKeysPerType(t *testing.T) {
	want := map[string][]string{
		"dingtalk":   {"access_token", "secret"},
		"wecom":      {"key"},
		"feishu":     {"webhook_url", "secret"},
		"telegram":   {"bot_token"},
		"serverchan": {"sendkey"},
		"wxpusher":   {"app_token"},
		"email":      {"password"},
		"webhook":    nil,
		"system":     nil,
		"nope":       nil,
	}
	for typ, exp := range want {
		got := SecretKeys(typ)
		if len(got) != len(exp) {
			t.Errorf("SecretKeys(%q) = %v, want %v", typ, got, exp)
			continue
		}
		for i := range exp {
			if got[i] != exp[i] {
				t.Errorf("SecretKeys(%q) = %v, want %v", typ, got, exp)
				break
			}
		}
	}
}

// TestRedactMasksProviderSecrets: a listed push channel hides its credential and
// keeps its destination readable — the console shows which chat it targets.
func TestRedactMasksProviderSecrets(t *testing.T) {
	c := redact(Channel{Type: "telegram", Config: map[string]string{
		"bot_token": "123456:AAAA-secret",
		"chat_id":   "-100123",
		"lang":      "zh",
	}})
	if c.Config["bot_token"] != MaskedSecret {
		t.Errorf("bot_token = %q, want the mask", c.Config["bot_token"])
	}
	if c.Config["chat_id"] != "-100123" || c.Config["lang"] != "zh" {
		t.Errorf("non-secret keys altered: %v", c.Config)
	}

	// An unset optional secret must stay empty, not become bullets: bullets would
	// claim a credential is configured when none is.
	dt := redact(Channel{Type: "dingtalk", Config: map[string]string{"access_token": "tok", "secret": ""}})
	if dt.Config["access_token"] != MaskedSecret || dt.Config["secret"] != "" {
		t.Errorf("dingtalk redact = %v", dt.Config)
	}

	// Email keeps its historical behaviour.
	em := redact(Channel{Type: "email", Config: map[string]string{"password": "hunter2", "host": "smtp.example.com"}})
	if em.Config["password"] != MaskedSecret || em.Config["host"] != "smtp.example.com" {
		t.Errorf("email redact = %v", em.Config)
	}
}

func TestMergeMaskedSecrets(t *testing.T) {
	stored := map[string]string{"bot_token": "real:token", "chat_id": "-1"}

	// The mask is replaced by the stored value; a real new value is a rotation and
	// survives; a non-secret key is never touched.
	posted := map[string]string{"bot_token": MaskedSecret, "chat_id": "-2"}
	MergeMaskedSecrets("telegram", posted, stored)
	if posted["bot_token"] != "real:token" || posted["chat_id"] != "-2" {
		t.Errorf("mask not restored: %v", posted)
	}

	posted = map[string]string{"bot_token": "new:token"}
	MergeMaskedSecrets("telegram", posted, stored)
	if posted["bot_token"] != "new:token" {
		t.Errorf("rotation overwritten: %v", posted)
	}

	// A secret key absent from posted stays absent (no resurrection from storage),
	// and a mask with nothing stored behind it stays a mask so validation can
	// reject it.
	posted = map[string]string{"chat_id": "-3"}
	MergeMaskedSecrets("telegram", posted, stored)
	if _, ok := posted["bot_token"]; ok {
		t.Errorf("absent secret key resurrected: %v", posted)
	}
	posted = map[string]string{"bot_token": MaskedSecret}
	MergeMaskedSecrets("telegram", posted, map[string]string{"chat_id": "-1"})
	if posted["bot_token"] != MaskedSecret {
		t.Errorf("mask with no stored value = %q", posted["bot_token"])
	}

	// Nil maps are a no-op rather than a panic (a config-less create/test body).
	MergeMaskedSecrets("telegram", nil, stored)
	MergeMaskedSecrets("telegram", map[string]string{}, nil)
}

func TestTruncateRunes(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 4, "hel…"},
		{"网络故障已恢复", 7, "网络故障已恢复"},
		{"网络故障已恢复", 4, "网络故…"},
		{"网络故障", 1, "…"},
		{"网络故障", 0, ""},
		{"", 3, ""},
	}
	for _, c := range cases {
		if got := truncateRunes(c.in, c.n); got != c.want {
			t.Errorf("truncateRunes(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestTruncateBytes(t *testing.T) {
	// "网" is 3 bytes; the cut must land on a rune boundary and the result must
	// never exceed the byte budget.
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 4, "h…"}, // "…" is 3 bytes, leaving room for one ASCII char
		{"网络故障", 12, "网络故障"},
		{"网络故障", 9, "网络…"},
		{"网络故障", 8, "网…"}, // 8-3=5 bytes back off to the 3-byte boundary
		{"网络故障", 3, "…"},
		{"网络故障", 2, ""},
	}
	for _, c := range cases {
		got := truncateBytes(c.in, c.n)
		if got != c.want {
			t.Errorf("truncateBytes(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
		if len(got) > c.n && len(c.in) > c.n {
			t.Errorf("truncateBytes(%q, %d) = %q exceeds the byte budget", c.in, c.n, got)
		}
	}
}

// TestDeliverProviderTransport locks the fixed transport every provider shares:
// POST, application/json, the provider's own URL and body, a 512-byte snippet,
// and CheckResponse seeing the real status and body.
func TestDeliverProviderTransport(t *testing.T) {
	var gotMethod, gotCT, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotCT, gotPath = r.Method, r.Header.Get("Content-Type"), r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	fp := &fakeProvider{url: srv.URL + "/robot/send", body: []byte(`{"msgtype":"text"}`)}
	before := time.Now()
	status, snippet, err := webhookTestService().deliverProvider(context.Background(), fp,
		map[string]string{"lang": "en"}, webhookSamplePayload())
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if gotMethod != http.MethodPost || gotCT != "application/json" || gotPath != "/robot/send" {
		t.Fatalf("method=%s content-type=%s path=%s", gotMethod, gotCT, gotPath)
	}
	if string(gotBody) != `{"msgtype":"text"}` {
		t.Fatalf("body=%s", gotBody)
	}
	if snippet != `{"errcode":0,"errmsg":"ok"}` {
		t.Fatalf("snippet=%q", snippet)
	}
	if fp.gotStatus != http.StatusOK || fp.gotBody != snippet {
		t.Fatalf("CheckResponse saw status=%d body=%q", fp.gotStatus, fp.gotBody)
	}
	if fp.gotNow.Before(before) {
		t.Fatalf("Build got now=%v, before the call at %v", fp.gotNow, before)
	}
}

// TestDeliverProviderSnippetCap: only the first 512 bytes of a reply are kept —
// a chatty error page must not become the console's response box.
func TestDeliverProviderSnippetCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 2000))
	}))
	defer srv.Close()

	_, snippet, err := webhookTestService().deliverProvider(context.Background(),
		&fakeProvider{url: srv.URL, body: []byte("{}")}, nil, webhookSamplePayload())
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(snippet) != 512 {
		t.Fatalf("snippet len=%d, want 512", len(snippet))
	}
}

// TestDeliverProviderCheckResponseError: an HTTP-200 soft failure is reported as
// an error while status/snippet still come back, so the console can show both.
func TestDeliverProviderCheckResponseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"errcode":310000,"errmsg":"sign not match"}`)
	}))
	defer srv.Close()

	soft := errors.New("dingtalk errcode 310000: sign not match")
	status, snippet, err := webhookTestService().deliverProvider(context.Background(),
		&fakeProvider{url: srv.URL, body: []byte("{}"), checkErr: soft}, nil, webhookSamplePayload())
	if !errors.Is(err, soft) {
		t.Fatalf("err=%v, want the CheckResponse error propagated", err)
	}
	if status != http.StatusOK || !strings.Contains(snippet, "sign not match") {
		t.Fatalf("status=%d snippet=%q", status, snippet)
	}
}

// TestDeliverProviderBuildError: a build failure (bad config, signing failure)
// never reaches the network.
func TestDeliverProviderBuildError(t *testing.T) {
	boom := errors.New("boom")
	status, snippet, err := webhookTestService().deliverProvider(context.Background(),
		&fakeProvider{buildErr: boom}, nil, webhookSamplePayload())
	if !errors.Is(err, boom) || status != 0 || snippet != "" {
		t.Fatalf("status=%d snippet=%q err=%v", status, snippet, err)
	}
}

// TestDeliverProviderUnreachable: a transport failure is returned as an error,
// and the error never echoes the request URL — provider URLs embed credentials
// (bot token in the path, access_token in the query), and this error reaches
// server logs and the test-send response. client.Do's *url.Error would carry
// the full URL; deliverProvider must unwrap it to the transport cause.
func TestDeliverProviderUnreachable(t *testing.T) {
	svc := &Service{client: &http.Client{Timeout: 500 * time.Millisecond}}
	_, _, err := svc.deliverProvider(context.Background(),
		&fakeProvider{url: "http://127.0.0.1:1/botSECRET-TOKEN/send", body: []byte("{}")}, nil, webhookSamplePayload())
	if err == nil {
		t.Fatal("expected transport error for unreachable url")
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("transport error leaks the credential-bearing URL: %v", err)
	}
}

// TestPushTextBilingual: the shared body renders in both languages and keeps the
// webhook body's line order — diagnosis, clues, fault lines, console link.
func TestPushTextBilingual(t *testing.T) {
	p := webhookSamplePayload()
	p.AttributionEvidence = []AttributionClue{{Kind: ClueOnlyTargetFailing, Targets: []string{"Shop"}}}
	p.URL = "https://console.example.com/incidents?incident=inc_1"

	en := pushText(p, "en")
	zh := pushText(p, "zh")
	if en == "" || zh == "" || en == zh {
		t.Fatalf("pushText did not localize:\nen=%q\nzh=%q", en, zh)
	}
	for _, want := range []string{"Single-host fault", "returned HTTP 503", "View details: " + p.URL} {
		if !strings.Contains(en, want) {
			t.Errorf("en body missing %q:\n%s", want, en)
		}
	}
	for _, want := range []string{"单机故障", "返回状态码 503", "查看详情：" + p.URL} {
		if !strings.Contains(zh, want) {
			t.Errorf("zh body missing %q:\n%s", want, zh)
		}
	}
	// Order: diagnosis first, clue before the fault line, link last.
	lines := strings.Split(en, "\n")
	if !strings.HasPrefix(lines[0], "Single-host fault") {
		t.Errorf("first line is not the diagnosis: %q", lines[0])
	}
	if !strings.HasPrefix(lines[len(lines)-1], "View details:") {
		t.Errorf("last line is not the console link: %q", lines[len(lines)-1])
	}
	clueIdx, faultIdx := -1, -1
	for i, l := range lines {
		if strings.Contains(l, "returned HTTP 503") {
			faultIdx = i
		} else if i > 0 && clueIdx == -1 && !strings.HasPrefix(l, "View details:") {
			clueIdx = i
		}
	}
	if clueIdx == -1 || faultIdx == -1 || clueIdx > faultIdx {
		t.Errorf("clue line does not precede the fault line (%d vs %d):\n%s", clueIdx, faultIdx, en)
	}

	// A payload with no link and no clues degrades to just the rendered lines.
	bare := webhookSamplePayload()
	if strings.Contains(pushText(bare, "en"), "View details") {
		t.Errorf("link line rendered without a URL: %q", pushText(bare, "en"))
	}
}

// TestSamplePayloadIsTest guards the shared test-send fixture: every channel type
// renders from it, and the event must stay marked as a test.
func TestSamplePayloadIsTest(t *testing.T) {
	p := SamplePayload("https://console.example.com")
	if p.Event != "test" || p.URL == "" || len(p.Details) != 1 {
		t.Fatalf("sample payload = %+v", p)
	}
	if body := pushText(p, "zh"); !strings.Contains(body, "测试通知") {
		t.Errorf("zh sample body does not read as a test: %q", body)
	}
}
