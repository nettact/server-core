package identity

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
)

func openIdentityTestDB(t *testing.T) *store.DB {
	t.Helper()
	dataDir, err := os.MkdirTemp("", "nettact-identity-test-")
	if err != nil {
		t.Fatalf("make temp dir: %v", err)
	}
	db, err := store.Open(filepath.Join(dataDir, "identity.db"))
	if err != nil {
		_ = os.RemoveAll(dataDir)
		t.Fatalf("open DB: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		deadline := time.Now().Add(time.Second)
		for {
			err := os.RemoveAll(dataDir)
			if err == nil {
				if _, statErr := os.Stat(dataDir); os.IsNotExist(statErr) {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Errorf("remove temp dir %s: %v", dataDir, err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return db
}

func TestEnsureAdminReturnsExistingUser(t *testing.T) {
	ctx := context.Background()
	db := openIdentityTestDB(t)
	svc := New(db)

	first, gen, err := svc.EnsureAdmin(ctx, "admin", "first-password")
	if err != nil {
		t.Fatalf("first EnsureAdmin: %v", err)
	}
	if gen != "" {
		t.Fatalf("supplied-password first run generated a password %q; want empty", gen)
	}
	second, gen2, err := svc.EnsureAdmin(ctx, "ignored", "ignored-password")
	if err != nil {
		t.Fatalf("second EnsureAdmin: %v", err)
	}
	if gen2 != "" {
		t.Fatalf("second EnsureAdmin generated a password %q; want empty", gen2)
	}
	if second != first {
		t.Fatalf("existing admin = %+v; want %+v", second, first)
	}
	if _, err := svc.Authenticate(ctx, "admin", "first-password"); err != nil {
		t.Fatalf("original credentials no longer authenticate: %v", err)
	}
}

// TestEnsureAdminGeneratesFirstRunPassword covers the credential-free first run:
// EnsureAdmin creates the default "admin" user, returns a non-empty generated
// password that authenticates, and a second call neither re-generates nor errors.
func TestEnsureAdminGeneratesFirstRunPassword(t *testing.T) {
	ctx := context.Background()
	svc := New(openIdentityTestDB(t))

	user, gen, err := svc.EnsureAdmin(ctx, "", "")
	if err != nil {
		t.Fatalf("EnsureAdmin with empty credentials: %v", err)
	}
	if gen == "" {
		t.Fatal("EnsureAdmin did not generate an initial password")
	}
	if user.Username != "admin" {
		t.Fatalf("generated admin username = %q; want admin", user.Username)
	}
	if err := ValidatePassword(gen); err != nil {
		t.Fatalf("generated password fails policy: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "admin", gen); err != nil {
		t.Fatalf("generated password does not authenticate: %v", err)
	}
	second, gen2, err := svc.EnsureAdmin(ctx, "", "")
	if err != nil {
		t.Fatalf("second EnsureAdmin: %v", err)
	}
	if gen2 != "" {
		t.Fatalf("second EnsureAdmin re-generated a password %q; want empty", gen2)
	}
	if second.ID != user.ID {
		t.Fatalf("second EnsureAdmin returned %+v; want the existing %+v", second, user)
	}
}

func TestPruneSessionsKeepsLiveRows(t *testing.T) {
	ctx := context.Background()
	db := openIdentityTestDB(t)
	svc := New(db)
	admin, _, err := svc.EnsureAdmin(ctx, "admin", "password")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	liveID, _, err := svc.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create live session: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sessions(id,user_id,created_at,expires_at) VALUES(?,?,?,?)`,
		"expired", admin.ID, time.Now().UTC().Add(-2*time.Hour), time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	n, err := svc.PruneSessions(ctx)
	if err != nil || n != 1 {
		t.Fatalf("PruneSessions = %d, %v; want 1, nil", n, err)
	}
	if _, err := svc.ValidateSession(ctx, liveID); err != nil {
		t.Fatalf("live session was pruned: %v", err)
	}
	if _, err := svc.ValidateSession(ctx, "expired"); err == nil {
		t.Fatal("expired session still validates")
	}
}
