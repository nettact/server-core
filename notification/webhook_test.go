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
)

func webhookTestService() *Service {
	return &Service{client: &http.Client{Timeout: 10 * time.Second}}
}

func webhookSamplePayload() Payload {
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

// TestDeliverWebhookDefaultBody locks the no-template path: it must stay a POST
// of the structured webhookBody as application/json, unchanged by this feature.
func TestDeliverWebhookDefaultBody(t *testing.T) {
	var gotMethod, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotCT = r.Method, r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	status, _, err := webhookTestService().deliverWebhook(context.Background(),
		map[string]string{"url": srv.URL, "lang": "en"}, webhookSamplePayload())
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if gotMethod != http.MethodPost || gotCT != "application/json" {
		t.Fatalf("method=%s content-type=%s", gotMethod, gotCT)
	}
	var wb webhookBody
	if err := json.Unmarshal(gotBody, &wb); err != nil {
		t.Fatalf("decode default body: %v", err)
	}
	if wb.Event != "incident.opened" || wb.Title == "" || len(wb.Lines) == 0 {
		t.Fatalf("default body missing rendered fields: %+v", wb)
	}
	if wb.Severity != "critical" || len(wb.Details) != 1 || wb.Details[0].TargetName != "Shop" {
		t.Fatalf("default body lost structured payload: %+v", wb)
	}
}

// TestDeliverWebhookCustomTemplate exercises the full custom path: method, a URL
// variable, a header variable, and a JSON body template.
func TestDeliverWebhookCustomTemplate(t *testing.T) {
	var gotMethod, gotAuth, gotCT, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotAuth, gotCT, gotPath = r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := map[string]string{
		"url":     srv.URL + "/hook/{{severity}}",
		"lang":    "en",
		"method":  "PUT",
		"headers": `{"Authorization":"Bearer {{severity}}"}`,
		"body":    `{"msgtype":"text","text":{"content":"{{title}}: {{text}}"}}`,
	}
	status, _, err := webhookTestService().deliverWebhook(context.Background(), cfg, webhookSamplePayload())
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if gotMethod != "PUT" || gotPath != "/hook/critical" || gotAuth != "Bearer critical" {
		t.Fatalf("method=%s path=%s auth=%s", gotMethod, gotPath, gotAuth)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type=%s", gotCT)
	}
	var parsed map[string]any
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("template body not valid JSON: %v (%s)", err, gotBody)
	}
	if !strings.Contains(string(gotBody), "Network fault") {
		t.Fatalf("title not substituted into body: %s", gotBody)
	}
}

// TestDeliverWebhookGETNoBody: GET carries no body and sets no default Content-Type.
func TestDeliverWebhookGETNoBody(t *testing.T) {
	var gotCT string
	var gotLen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotLen = len(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := map[string]string{"url": srv.URL + "/{{severity}}", "method": "GET", "lang": "en"}
	status, _, err := webhookTestService().deliverWebhook(context.Background(), cfg, webhookSamplePayload())
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if gotLen != 0 || gotCT != "" {
		t.Fatalf("GET carried body=%d content-type=%q", gotLen, gotCT)
	}
}

// TestDeliverWebhookExplicitContentType: a user-set Content-Type wins.
func TestDeliverWebhookExplicitContentType(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := map[string]string{
		"url":     srv.URL,
		"headers": `{"Content-Type":"text/plain; charset=utf-8"}`,
		"body":    "hello {{severity}}",
	}
	if _, _, err := webhookTestService().deliverWebhook(context.Background(), cfg, webhookSamplePayload()); err != nil {
		t.Fatalf("err=%v", err)
	}
	if gotCT != "text/plain; charset=utf-8" {
		t.Fatalf("explicit content-type not honored: %q", gotCT)
	}
}

// TestDeliverWebhookErrorSnippet: a non-2xx status returns the response snippet
// (DingTalk-family soft failures reply 200/errcode, but 5xx is the simpler case).
func TestDeliverWebhookErrorSnippet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"errcode":310000,"errmsg":"invalid signature"}`)
	}))
	defer srv.Close()

	status, snippet, err := webhookTestService().deliverWebhook(context.Background(),
		map[string]string{"url": srv.URL}, webhookSamplePayload())
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if status != http.StatusInternalServerError || !strings.Contains(snippet, "errcode") {
		t.Fatalf("status=%d snippet=%q", status, snippet)
	}
}

// TestDeliverWebhookUnreachable: a transport failure is returned as an error.
func TestDeliverWebhookUnreachable(t *testing.T) {
	svc := &Service{client: &http.Client{Timeout: 500 * time.Millisecond}}
	if _, _, err := svc.deliverWebhook(context.Background(),
		map[string]string{"url": "http://127.0.0.1:1/nope"}, webhookSamplePayload()); err == nil {
		t.Fatal("expected transport error for unreachable url")
	}
}
