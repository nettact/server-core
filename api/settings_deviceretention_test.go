package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/nettact/server-core/settings"
)

// stored reads a setting's effective value the way the pruner does.
func stored(t *testing.T, d Deps, key string) int {
	t.Helper()
	n, ok := d.Settings.Int(context.Background(), key)
	if !ok {
		t.Fatalf("unknown setting %s", key)
	}
	return n
}

// The randomized-MAC window only narrows the master one, and the pruner clamps it
// to that. Storing a wider value would therefore be stored-but-not-honoured: the
// console would show 30 days while cleanup ran at 7.
func TestUpdateDeviceRetentionRejectsWiderRandomWindow(t *testing.T) {
	d := listenTestDeps(t)
	w := putSettings(t, d, `{"device_retention_days":"7","device_random_mac_retention_days":"30"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body %s)", w.Code, http.StatusBadRequest, w.Body.String())
	}
	// A rejected PUT must not have written either key.
	if got := stored(t, d, settings.KeyDeviceRetentionDays); got != 7 {
		t.Fatalf("device_retention_days = %d, want the 7 default left untouched", got)
	}
	if got := stored(t, d, settings.KeyDeviceRandomMACRetentionDays); got != 1 {
		t.Fatalf("device_random_mac_retention_days = %d, want the 1 default left untouched", got)
	}
}

// The same inversion reached from the other side: a PUT that only lowers the
// master window below an already-stored randomized window. A per-key check cannot
// see this, which is why the validator resolves absent keys from stored state.
func TestUpdateDeviceRetentionRejectsLoweringMasterBelowStoredRandom(t *testing.T) {
	d := listenTestDeps(t)
	if w := putSettings(t, d, `{"device_retention_days":"90","device_random_mac_retention_days":"30"}`); w.Code != http.StatusOK {
		t.Fatalf("seed status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	w := putSettings(t, d, `{"device_retention_days":"7"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body %s)", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if got := stored(t, d, settings.KeyDeviceRetentionDays); got != 90 {
		t.Fatalf("device_retention_days = %d, want the stored 90 left untouched", got)
	}
}

func TestUpdateDeviceRetentionAccepts(t *testing.T) {
	cases := map[string]struct {
		body                   string
		wantStable, wantRandom int
	}{
		"narrower random window":    {`{"device_retention_days":"7","device_random_mac_retention_days":"1"}`, 7, 1},
		"equal windows":             {`{"device_retention_days":"7","device_random_mac_retention_days":"7"}`, 7, 7},
		"random follows master (0)": {`{"device_retention_days":"7","device_random_mac_retention_days":"0"}`, 7, 0},
		// Master 0 turns retention off entirely, so nothing can outlive anything and
		// the randomized value is irrelevant rather than invalid.
		"retention off": {`{"device_retention_days":"0","device_random_mac_retention_days":"30"}`, 0, 30},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := listenTestDeps(t)
			w := putSettings(t, d, tc.body)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
			}
			if got := stored(t, d, settings.KeyDeviceRetentionDays); got != tc.wantStable {
				t.Fatalf("device_retention_days = %d, want %d", got, tc.wantStable)
			}
			if got := stored(t, d, settings.KeyDeviceRandomMACRetentionDays); got != tc.wantRandom {
				t.Fatalf("device_random_mac_retention_days = %d, want %d", got, tc.wantRandom)
			}
		})
	}
}
