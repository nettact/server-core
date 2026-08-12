package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store/storetest"
)

func listenTestDeps(t *testing.T) Deps {
	t.Helper()
	db := storetest.Open(t)
	return Deps{Settings: settings.New(db), Audit: audit.New(db)}
}

func putSettings(t *testing.T, d Deps, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	d.handleUpdateSettings(w, httptest.NewRequest(http.MethodPut, "/api/v1/settings", strings.NewReader(body)))
	return w
}

func TestUpdateListenAddrValidation(t *testing.T) {
	d := listenTestDeps(t)
	cases := map[string]string{
		"no port":       `{"listen_addr":"127.0.0.1"}`,
		"not a number":  `{"listen_addr":"127.0.0.1:abc"}`,
		"port zero":     `{"listen_addr":"127.0.0.1:0"}`,
		"port too big":  `{"listen_addr":"127.0.0.1:65536"}`,
		"arbitrary ip":  `{"listen_addr":"192.168.1.5:12450"}`,
		"hostname":      `{"listen_addr":"localhost:12450"}`,
		"ipv6 loopback": `{"listen_addr":"[::1]:12450"}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			w := putSettings(t, d, payload)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestUpdateListenAddrSavesAndReportsPending(t *testing.T) {
	d := listenTestDeps(t)
	// Reserve a free port so the probe passes, then release it before the PUT.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	w := putSettings(t, d, `{"listen_addr":"`+addr+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		OK           bool   `json:"ok"`
		ListenEffect string `json:"listen_effect"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.ListenEffect != "pending" {
		t.Fatalf("resp=%+v", resp)
	}
	stored, err := d.Settings.Get(context.Background(), settings.KeyListenAddr)
	if err != nil || stored != addr {
		t.Fatalf("stored=%q err=%v", stored, err)
	}

	// Saving the same value again reports no listen effect.
	w = putSettings(t, d, `{"listen_addr":"`+addr+`"}`)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "listen_effect") {
		t.Fatalf("unchanged save status=%d body=%s", w.Code, w.Body.String())
	}

	// Empty clears the key.
	w = putSettings(t, d, `{"listen_addr":""}`)
	if w.Code != http.StatusOK {
		t.Fatalf("clear status=%d body=%s", w.Code, w.Body.String())
	}
	stored, _ = d.Settings.Get(context.Background(), settings.KeyListenAddr)
	if stored != "" {
		t.Fatalf("stored after clear=%q", stored)
	}
}

func TestUpdateListenAddrProbeRejectsBusyPort(t *testing.T) {
	d := listenTestDeps(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer ln.Close()

	w := putSettings(t, d, `{"listen_addr":"`+ln.Addr().String()+`"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "in use") {
		t.Fatalf("expected in-use message, got %s", w.Body.String())
	}
}

func TestUpdateListenAddrSamePortSkipsProbe(t *testing.T) {
	d := listenTestDeps(t)
	// Simulate the server holding the port itself: probe must be skipped when the
	// requested port equals the effective one (mode flip 127.0.0.1 <-> 0.0.0.0).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	d.ListenStatus = func(ctx context.Context) *ListenStatus {
		return &ListenStatus{EffectiveAddr: addr, Source: "default"}
	}

	w := putSettings(t, d, `{"listen_addr":"`+addr+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateListenAddrRejectedWhenExternallyManaged(t *testing.T) {
	for _, tc := range []struct {
		source string
		owner  string
	}{{"env", "NETTACT_SERVER_ADDR"}, {"flag", "-addr"}} {
		t.Run(tc.source, func(t *testing.T) {
			d := listenTestDeps(t)
			d.ListenStatus = func(context.Context) *ListenStatus {
				return &ListenStatus{EffectiveAddr: "127.0.0.1:12450", Source: tc.source}
			}

			w := putSettings(t, d, `{"listen_addr":"127.0.0.1:19000"}`)
			if w.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.owner) {
				t.Fatalf("expected %s ownership message, got %s", tc.owner, w.Body.String())
			}
			stored, err := d.Settings.Get(context.Background(), settings.KeyListenAddr)
			if err != nil || stored != "" {
				t.Fatalf("stored=%q err=%v; rejected update must not persist", stored, err)
			}
		})
	}
}

func TestUpdateListenAddrDesktopApply(t *testing.T) {
	d := listenTestDeps(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var applied string
	d.ApplyListenAddr = func(ctx context.Context, a string) error {
		applied = a
		return nil
	}

	w := putSettings(t, d, `{"listen_addr":"`+addr+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"listen_effect":"restarting"`) {
		t.Fatalf("expected restarting effect, got %s", w.Body.String())
	}
	if applied != addr {
		t.Fatalf("applied=%q want %q", applied, addr)
	}

	// Unchanged value must not re-trigger apply.
	applied = ""
	w = putSettings(t, d, `{"listen_addr":"`+addr+`"}`)
	if w.Code != http.StatusOK || applied != "" {
		t.Fatalf("unchanged save status=%d applied=%q", w.Code, applied)
	}
}

func TestServerInfoListenBlock(t *testing.T) {
	d := listenTestDeps(t)
	d.ListenStatus = func(ctx context.Context) *ListenStatus {
		return &ListenStatus{EffectiveAddr: "127.0.0.1:12450", Source: "db", Desktop: true, OverridesFlag: true}
	}
	if err := d.Settings.Set(context.Background(), settings.KeyListenAddr, "0.0.0.0:9000"); err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	w := httptest.NewRecorder()
	d.handleServerInfo(w, httptest.NewRequest(http.MethodGet, "/api/v1/server-info", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Listen *ListenStatus `json:"listen"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Listen == nil || resp.Listen.EffectiveAddr != "127.0.0.1:12450" ||
		resp.Listen.PendingAddr != "0.0.0.0:9000" || !resp.Listen.Desktop || !resp.Listen.OverridesFlag {
		t.Fatalf("listen=%+v", resp.Listen)
	}

	// Without a provider the block is absent.
	d.ListenStatus = nil
	w = httptest.NewRecorder()
	d.handleServerInfo(w, httptest.NewRequest(http.MethodGet, "/api/v1/server-info", nil))
	if strings.Contains(w.Body.String(), "listen") {
		t.Fatalf("unexpected listen block: %s", w.Body.String())
	}
}

func TestServerInfoDoesNotReportDatabaseAddressPendingWhenExternallyManaged(t *testing.T) {
	for _, source := range []string{"env", "flag"} {
		t.Run(source, func(t *testing.T) {
			d := listenTestDeps(t)
			d.ListenStatus = func(context.Context) *ListenStatus {
				return &ListenStatus{EffectiveAddr: "127.0.0.1:12450", Source: source}
			}
			if err := d.Settings.Set(context.Background(), settings.KeyListenAddr, "0.0.0.0:19000"); err != nil {
				t.Fatalf("seed setting: %v", err)
			}

			w := httptest.NewRecorder()
			d.handleServerInfo(w, httptest.NewRequest(http.MethodGet, "/api/v1/server-info", nil))
			var resp struct {
				Listen *ListenStatus `json:"listen"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Listen == nil || resp.Listen.Source != source || resp.Listen.PendingAddr != "" {
				t.Fatalf("listen=%+v", resp.Listen)
			}
		})
	}
}
