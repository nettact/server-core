package settings

import (
	"context"
	"testing"

	"github.com/nettact/server-core/store/storetest"
)

// The diag_* keys ride DesiredState to connected agents, so mutating one must
// fire the push hook — including a clear back to the default, which is as much
// a policy change as a number. Keys that stay server-side must not fire it: a
// retention edit rebuilding every agent's DesiredState would be pure noise.
func TestSetFiresDiagPolicyHookForDiagKeysOnly(t *testing.T) {
	db := storetest.Open(t)
	s := New(db)
	fired := 0
	s.OnDiagPolicyChange(func() { fired++ })
	ctx := context.Background()

	if err := s.Set(ctx, KeyDiagEnabled, "0"); err != nil {
		t.Fatalf("set diag_enabled: %v", err)
	}
	if fired != 1 {
		t.Fatalf("fired = %d after a diag set, want 1", fired)
	}
	if err := s.Set(ctx, KeyDiagConsecutiveFailures, ""); err != nil {
		t.Fatalf("clear diag_consecutive_failures: %v", err)
	}
	if fired != 2 {
		t.Fatalf("fired = %d after a diag clear, want 2", fired)
	}
	if err := s.Set(ctx, KeyGameRunRetentionDays, "30"); err != nil {
		t.Fatalf("set non-diag key: %v", err)
	}
	if fired != 2 {
		t.Fatalf("fired = %d after a non-diag set, want it unchanged at 2", fired)
	}
}
