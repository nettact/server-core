package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/opissue"
	"github.com/nettact/server-core/sse"
	"github.com/nettact/server-core/store/storetest"
)

// Response compression, and the one route it must not touch.
//
// The router compresses because nothing else in the stack does: both frontend
// bundles and every JSON response otherwise ship raw. The reason it is safe to
// install ABOVE the SSE route is narrow and worth pinning — chi decides by
// content type, and text/event-stream is not in its allowlist. Compressing a live
// event stream would buffer events behind the compressor's window, so a page that
// looks connected would go silent. That failure is invisible in a unit test of
// anything else, hence this file.

// sseFixture builds a router with a real SSE broker and a logged-in session.
func sseFixture(t *testing.T) (http.Handler, *http.Cookie) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	id := identity.New(db)
	admin, _, err := id.EnsureAdmin(ctx, "admin", "correct-horse-battery")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	session, _, err := id.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	bus := eventbus.New()
	d := Deps{
		Identity: id,
		Audit:    audit.New(db),
		OpIssue:  opissue.New(db, bus),
		SSE:      sse.NewBroker(),
	}
	return Router(d), &http.Cookie{Name: sessionCookie, Value: session}
}

// TestSSEStreamIsNotCompressed is the guard on installing Compress above the whole
// router. It runs over a real socket rather than a recorder because the failure it
// protects against — a stream that is served but never flushed — only exists on a
// real connection.
func TestSSEStreamIsNotCompressed(t *testing.T) {
	h, cookie := sseFixture(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(cookie)
	// Set by hand: the transport only skips its own transparent decompression
	// when the caller asked for the encoding itself, which is what makes
	// Content-Encoding observable here at all.
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the SSE handler needs an http.Flusher, and a "+
			"response writer wrapper that is not one fails exactly here", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Fatalf("Content-Encoding = %q on the event stream; compressing SSE buffers "+
			"events behind the compressor and the console goes quiet", enc)
	}

	// The connect snapshot must arrive without the stream being closed — proof the
	// bytes were flushed rather than held in a buffer waiting for more.
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, _ := resp.Body.Read(buf)
		done <- string(buf[:n])
	}()
	select {
	case got := <-done:
		if got == "" {
			t.Fatal("event stream produced no bytes")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no bytes from the event stream within 5s: the snapshot is stuck in a buffer")
	}
}

// TestPublicStatusPayloadIsCompressed covers the other half. The public target
// payload is the largest JSON this server emits — five windows and ninety daily
// cells per target — and it is served to anonymous readers on every poll.
func TestPublicStatusPayloadIsCompressed(t *testing.T) {
	h, _, cookie := statusPageFixture(t, false)
	createStatusPage(t, h, cookie, statusPagePayload)

	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/public/pages/home/target-statuses", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET target-statuses: %v", err)
	}
	defer resp.Body.Close()

	if enc := resp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var payload struct {
		DaysFrom string `json:"days_from"`
		Targets  []struct {
			Availability []struct {
				Window string `json:"window"`
			} `json:"availability"`
			Days []struct {
				Ratio    *float64 `json:"ratio"`
				Rounds   int64    `json:"rounds"`
				OKRounds int64    `json:"ok_rounds"`
			} `json:"days"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decompressed body is not the payload: %v (%s)", err, body)
	}
	if payload.DaysFrom == "" || len(payload.Targets) == 0 {
		t.Fatalf("payload did not survive the round trip: %s", body)
	}
	if n := len(payload.Targets[0].Availability); n != 5 {
		t.Fatalf("availability windows = %d, want 5", n)
	}
	if n := len(payload.Targets[0].Days); n != 90 {
		t.Fatalf("day cells = %d, want 90", n)
	}
	if day := payload.Targets[0].Days[0]; day.Ratio != nil || day.Rounds != 0 || day.OKRounds != 0 {
		t.Fatalf("empty day = %+v, want a null ratio and zero counts", day)
	}
}
