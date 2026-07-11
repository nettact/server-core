package notification

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nettact/server-core/store"
)

// TestSystemChannelCRUD verifies a "system" channel round-trips through the
// store and that Notify dispatching to it is safe (no panic / no block). On
// unsupported platforms nativeNotify is a no-op; on Windows/macOS it fires a
// bounded, best-effort desktop notification.
func TestSystemChannelCRUD(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	svc := New(db)

	id, err := svc.Create(ctx, "Desktop", "system", map[string]string{})
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
	if got.Type != "system" || got.Name != "Desktop" || !got.Enabled {
		t.Fatalf("unexpected channel: %+v", *got)
	}

	// Dispatch to the enabled system channel must not panic or return an error.
	svc.Notify(ctx, nil, Payload{
		Event:          "incident.opened",
		Summary:        `站点级故障 "WAN" 中断 <test>`, // exercises escaping paths
		SuspectedLayer: "WAN",
		Severity:       "critical",
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
