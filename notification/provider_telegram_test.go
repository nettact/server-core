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

func telegramCfg(extra map[string]string) map[string]string {
	cfg := map[string]string{"bot_token": "123456:ABC-DEF", "chat_id": "-100123", "lang": "en"}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

// TestTelegramBuildDefaultBase locks the public-host URL shape and the exact
// request body: chat_id must stay a JSON string (Telegram takes "@channel" in
// the same field) and the only other member is text.
func TestTelegramBuildDefaultBase(t *testing.T) {
	url, body, err := telegramProvider{}.Build(telegramCfg(nil), webhookSamplePayload(), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	const wantURL = "https://api.telegram.org/bot123456:ABC-DEF/sendMessage"
	if url != wantURL {
		t.Fatalf("url=%q want %q", url, wantURL)
	}

	var msg telegramMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("body is not valid JSON: %v (%s)", err, body)
	}
	if msg.ChatID != "-100123" {
		t.Fatalf("chat_id=%q", msg.ChatID)
	}
	p := webhookSamplePayload()
	wantText := RenderTitle(p, "en") + "\n" + pushText(p, "en")
	if msg.Text != wantText {
		t.Fatalf("text=%q want %q", msg.Text, wantText)
	}
	// Exact wire form, including chat_id-as-string and field order.
	want, err := json.Marshal(map[string]string{"chat_id": "-100123", "text": wantText})
	if err != nil {
		t.Fatalf("marshal expectation: %v", err)
	}
	if string(body) != string(want) {
		t.Fatalf("body=%s want %s", body, want)
	}
	if strings.Contains(string(body), "parse_mode") {
		t.Fatalf("parse_mode must not be sent (plain text): %s", body)
	}
}

// TestTelegramBuildAPIBaseOverride: the reverse-proxy override is honored and a
// trailing slash does not produce a "//bot…" path.
func TestTelegramBuildAPIBaseOverride(t *testing.T) {
	cfg := telegramCfg(map[string]string{"api_base": "https://tg.example.com/proxy/"})
	url, _, err := telegramProvider{}.Build(cfg, webhookSamplePayload(), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	const wantURL = "https://tg.example.com/proxy/bot123456:ABC-DEF/sendMessage"
	if url != wantURL {
		t.Fatalf("url=%q want %q", url, wantURL)
	}
}

func TestTelegramValidateConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]string
		bad  bool
	}{
		{"missing token", map[string]string{"chat_id": "-100123"}, true},
		{"blank token", map[string]string{"bot_token": "   ", "chat_id": "-100123"}, true},
		{"missing chat id", map[string]string{"bot_token": "123456:ABC"}, true},
		{"token with space", map[string]string{"bot_token": "123456: ABC", "chat_id": "-100123"}, true},
		{"token with trailing newline", map[string]string{"bot_token": "123456:ABC\n", "chat_id": "-100123"}, true},
		{"token with leading space", map[string]string{"bot_token": " 123456:ABC", "chat_id": "-100123"}, true},
		{"chat id with space", map[string]string{"bot_token": "123456:ABC", "chat_id": "-100 123"}, true},
		{"api base with leading space", map[string]string{"bot_token": "123456:ABC", "chat_id": "-100123", "api_base": " https://tg.example.com"}, true},
		{"ftp api base", map[string]string{"bot_token": "123456:ABC", "chat_id": "-100123", "api_base": "ftp://tg.example.com"}, true},
		{"valid minimal", map[string]string{"bot_token": "123456:ABC", "chat_id": "@nettact"}, false},
		{"valid with api base", map[string]string{"bot_token": "123456:ABC", "chat_id": "-100123", "api_base": "http://tg.example.com"}, false},
	}
	for _, c := range cases {
		got := telegramProvider{}.ValidateConfig(c.cfg)
		if c.bad && got == "" {
			t.Errorf("%s: expected a validation message", c.name)
		}
		if !c.bad && got != "" {
			t.Errorf("%s: unexpected validation message %q", c.name, got)
		}
	}
}

func TestTelegramCheckResponse(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
		want    []string
	}{
		{name: "ok true", status: 200, body: `{"ok":true,"result":{"message_id":7}}`},
		{
			name: "ok false", status: 400,
			body:    `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`,
			wantErr: true, want: []string{"400", "chat not found"},
		},
		{name: "garbage 5xx", status: 500, body: `<html>bad gateway`, wantErr: true, want: []string{"http 500"}},
		{name: "garbage 200", status: 200, body: `{"ok":true,"description":"trunc`},
	}
	for _, c := range cases {
		err := telegramProvider{}.CheckResponse(c.status, []byte(c.body))
		if c.wantErr && err == nil {
			t.Errorf("%s: expected an error", c.name)
			continue
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		for _, sub := range c.want {
			if !strings.Contains(err.Error(), sub) {
				t.Errorf("%s: error %q missing %q", c.name, err, sub)
			}
		}
	}
}

// TestTelegramTruncatesAtRuneLimit: the cap is telegramMaxRunes CHARACTERS, not
// bytes — a message of 3-byte characters must survive to its full rune budget.
func TestTelegramTruncatesAtRuneLimit(t *testing.T) {
	p := webhookSamplePayload()
	p.Details[0].TargetName = strings.Repeat("中", 5000)

	over := RenderTitle(p, "en") + "\n" + pushText(p, "en")
	if utf8.RuneCountInString(over) <= telegramMaxRunes {
		t.Fatalf("fixture no longer exceeds the cap: %d runes", utf8.RuneCountInString(over))
	}

	_, body, err := telegramProvider{}.Build(telegramCfg(nil), p, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var msg telegramMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n := utf8.RuneCountInString(msg.Text); n != telegramMaxRunes {
		t.Fatalf("text is %d runes, want telegramMaxRunes=%d", n, telegramMaxRunes)
	}
	if !strings.HasSuffix(msg.Text, ellipsis) {
		t.Fatalf("truncated text lost its ellipsis: %q", msg.Text[len(msg.Text)-16:])
	}
	if len(msg.Text) <= telegramMaxRunes {
		t.Fatalf("multi-byte text should exceed %d bytes, got %d — cap looks byte-based", telegramMaxRunes, len(msg.Text))
	}
}

// TestTelegramDeliverProvider is the end-to-end pass through the shared
// transport: POST /bot<token>/sendMessage as application/json, and an
// HTTP-200-with-ok:false reply classified as a failure.
func TestTelegramDeliverProvider(t *testing.T) {
	var gotMethod, gotCT, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotCT, gotPath = r.Method, r.Header.Get("Content-Type"), r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`)
	}))
	defer srv.Close()

	cfg := telegramCfg(map[string]string{"api_base": srv.URL})
	status, snippet, err := webhookTestService().deliverProvider(context.Background(),
		telegramProvider{}, cfg, webhookSamplePayload())
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if err == nil {
		t.Fatalf("ok:false must be an error (snippet %q)", snippet)
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("err=%v", err)
	}
	if gotMethod != http.MethodPost || gotCT != "application/json" {
		t.Fatalf("method=%s content-type=%s", gotMethod, gotCT)
	}
	if gotPath != "/bot123456:ABC-DEF/sendMessage" {
		t.Fatalf("path=%s", gotPath)
	}
	var msg telegramMessage
	if err := json.Unmarshal(gotBody, &msg); err != nil {
		t.Fatalf("server got invalid JSON: %v (%s)", err, gotBody)
	}
	if msg.ChatID != "-100123" || msg.Text == "" {
		t.Fatalf("server got %+v", msg)
	}
}
