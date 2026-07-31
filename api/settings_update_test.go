package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/updatecheck"
)

func updateSettingsDeps(t *testing.T) Deps {
	t.Helper()
	db := storetest.Open(t)
	return Deps{Settings: settings.New(db), Audit: audit.New(db)}
}

func TestUpdateNoticeSettingsRoundTrip(t *testing.T) {
	d := updateSettingsDeps(t)
	ctx := context.Background()

	if d.Settings.Bool(ctx, settings.KeyUpdateNoticeDisabled) {
		t.Fatal("update notices default to disabled; want enabled")
	}
	if w := putSettings(t, d, `{"update_notice_disabled":"1","update_dismissed_version":"v1.2.3"}`); w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !d.Settings.Bool(ctx, settings.KeyUpdateNoticeDisabled) {
		t.Error("update_notice_disabled did not persist")
	}
	got, err := d.Settings.Get(ctx, settings.KeyUpdateDismissedVersion)
	if err != nil || got != "v1.2.3" {
		t.Errorf("update_dismissed_version = %q, err=%v", got, err)
	}

	// Both keys must come back through the generic settings GET the console reads.
	w := httptest.NewRecorder()
	d.handleGetSettings(w, httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil))
	var all map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if all["update_notice_disabled"] != "1" || all["update_dismissed_version"] != "v1.2.3" {
		t.Errorf("GET /settings = %v", all)
	}

	// Clearing the dismissed version removes it, which is how the console
	// re-arms the banner.
	if w := putSettings(t, d, `{"update_dismissed_version":""}`); w.Code != http.StatusOK {
		t.Fatalf("clear status=%d body=%s", w.Code, w.Body.String())
	}
	if got, _ := d.Settings.Get(ctx, settings.KeyUpdateDismissedVersion); got != "" {
		t.Errorf("update_dismissed_version = %q after clear", got)
	}
}

func TestUpdateSettingsRejectsBadValues(t *testing.T) {
	d := updateSettingsDeps(t)
	cases := map[string]string{
		"notice out of range": `{"update_notice_disabled":"2"}`,
		"notice not a number": `{"update_notice_disabled":"yes"}`,
		"version too long":    `{"update_dismissed_version":"` + strings.Repeat("v", 65) + `"}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if w := putSettings(t, d, payload); w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestServerInfoOmitsUpdateUntilChecked(t *testing.T) {
	d := updateSettingsDeps(t)

	// No update service at all (bare server-core, or checking switched off).
	if _, ok := decodeServerInfo(t, d)["update"]; ok {
		t.Error("server-info carried an update block without an update service")
	}

	// A service that has not completed a check yet is equally silent: a
	// half-filled block would make the console announce a version it never read.
	d.Update = updatecheck.New(updatecheck.Config{
		InstallType:    updatecheck.InstallServer,
		CurrentVersion: "v1.0.0",
		BaseURL:        "http://127.0.0.1:1",
	})
	if _, ok := decodeServerInfo(t, d)["update"]; ok {
		t.Error("server-info carried an update block before the first successful check")
	}
}

func decodeServerInfo(t *testing.T, d Deps) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	d.handleServerInfo(w, httptest.NewRequest(http.MethodGet, "/api/v1/server-info", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("server-info status=%d body=%s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}
