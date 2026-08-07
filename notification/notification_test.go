package notification

import (
	"context"
	"runtime"
	"testing"

	"github.com/nettact/server-core/store/storetest"
)

// TestSystemChannelCRUD verifies a "system" channel round-trips through the
// store and that Notify dispatching to it is safe (no panic / no block). On
// unsupported platforms nativeNotify is a no-op; on Windows/macOS it fires a
// bounded, best-effort desktop notification.
func TestSystemChannelCRUD(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	svc := New(db, false)

	id, err := svc.Create(ctx, "Desktop", "system", map[string]string{}, true)
	if err != nil {
		t.Fatalf("create system channel: %v", err)
	}

	chans, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("list channels: %v", err)
	}
	var got *Channel
	for i := range chans {
		if chans[i].ID == id {
			got = &chans[i]
		}
	}
	if got == nil {
		t.Fatalf("created channel %s not returned by List", id)
	}
	if got.Type != "system" || got.Name != "Desktop" || !got.Enabled || !got.StormMerge {
		t.Fatalf("unexpected channel: %+v", *got)
	}

	// Dispatch to the enabled system channel must not panic or return an error.
	svc.Notify(ctx, nil, Payload{
		Event:          "incident.opened",
		State:          "open",
		Scope:          "site",
		AgentCount:     2,
		SuspectedLayer: "wan",
		Severity:       "critical",
		Details: []FaultDetail{{
			ProbeKind: "http", MetricKind: "probe.http.status", Comparator: "eq",
			Threshold: 200, Value: 503, Target: `http://x <test>`, Layer: "service",
			Severity: "critical", AgentHost: "node-1",
		}},
	})
}

// TestNativeSupportedMatchesOS guards the build-tag wiring: support must line up
// with the platform the tests run on.
func TestNativeSupportedMatchesOS(t *testing.T) {
	want := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	if NativeSupported() != want {
		t.Fatalf("NativeSupported()=%v, want %v for GOOS=%s", NativeSupported(), want, runtime.GOOS)
	}
}
