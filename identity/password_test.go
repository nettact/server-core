package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name string
		pw   string
		ok   bool
	}{
		{"too-short", "abc123", false},
		{"exactly-7", "1234567", false},
		{"exactly-8", "12345678", true},
		{"long-ok", strings.Repeat("a", 72), true},
		{"too-long-73-bytes", strings.Repeat("a", 73), false},
		{"multibyte-min-runes", "密码密码密码密码", true},                   // 8 runes, 24 bytes
		{"multibyte-7-runes", "密码密码密码密", false},                     // 7 runes → below the 8-codepoint floor
		{"multibyte-over-72-bytes", strings.Repeat("密", 25), false}, // 25 runes but 75 bytes → over bcrypt's 72-byte cap
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.pw)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidatePassword(%q) = %v; ok=%v", tc.pw, err, tc.ok)
			}
		})
	}
}

// TestUpdatePassword covers the new atomic signature: wrong old password and
// weak new password leave everything untouched, and a successful change rotates
// the hash while revoking every session except the kept one — all in one shot.
func TestUpdatePassword(t *testing.T) {
	ctx := context.Background()
	svc := New(openIdentityTestDB(t))
	admin, _, err := svc.EnsureAdmin(ctx, "admin", "old-password")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	keep, _, err := svc.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create kept session: %v", err)
	}
	other, _, err := svc.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}

	// Wrong old password is rejected with ErrAuth and does not change anything.
	if err := svc.UpdatePassword(ctx, admin.ID, "wrong", "new-password", keep); !errors.Is(err, ErrAuth) {
		t.Fatalf("UpdatePassword with wrong old password = %v; want ErrAuth", err)
	}
	// A weak new password is rejected by the policy (not ErrAuth).
	if err := svc.UpdatePassword(ctx, admin.ID, "old-password", "short", keep); err == nil || errors.Is(err, ErrAuth) {
		t.Fatalf("UpdatePassword with weak new password = %v; want policy error", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "old-password"); err != nil {
		t.Fatalf("rejected updates changed the password: %v", err)
	}
	// A rejected change must not have revoked any session.
	if _, err := svc.ValidateSession(ctx, other); err != nil {
		t.Fatalf("rejected change revoked a session: %v", err)
	}

	// Successful change: old password stops working, new one authenticates.
	if err := svc.UpdatePassword(ctx, admin.ID, "old-password", "new-password", keep); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "old-password"); !errors.Is(err, ErrAuth) {
		t.Fatalf("old password still authenticates after change: %v", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "new-password"); err != nil {
		t.Fatalf("new password does not authenticate: %v", err)
	}
	// The revocation rode along in the same transaction: other session gone, kept alive.
	if _, err := svc.ValidateSession(ctx, other); !errors.Is(err, ErrAuth) {
		t.Fatalf("other session survived the change: %v", err)
	}
	if _, err := svc.ValidateSession(ctx, keep); err != nil {
		t.Fatalf("kept session was revoked: %v", err)
	}
}

// TestUpdatePasswordConcurrentLosesWithErrAuth exercises the compare-and-swap
// guard against last-write-wins: once the password has rotated, a second change
// still presenting the original password is rejected with ErrAuth instead of
// silently clobbering the winner.
func TestUpdatePasswordConcurrentLosesWithErrAuth(t *testing.T) {
	ctx := context.Background()
	svc := New(openIdentityTestDB(t))
	admin, _, err := svc.EnsureAdmin(ctx, "admin", "old-password")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	// First writer wins.
	if err := svc.UpdatePassword(ctx, admin.ID, "old-password", "winner-password", ""); err != nil {
		t.Fatalf("first change: %v", err)
	}
	// Second writer still holding the stale original password must lose with ErrAuth.
	if err := svc.UpdatePassword(ctx, admin.ID, "old-password", "loser-password", ""); !errors.Is(err, ErrAuth) {
		t.Fatalf("stale concurrent change = %v; want ErrAuth", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "winner-password"); err != nil {
		t.Fatalf("winner password does not authenticate: %v", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "loser-password"); !errors.Is(err, ErrAuth) {
		t.Fatalf("loser password authenticates: %v", err)
	}
}

// TestLoginSession covers the atomic verify-and-mint login path: bad credentials
// and unknown users are ErrAuth, and the happy path returns a usable session.
func TestLoginSession(t *testing.T) {
	ctx := context.Background()
	svc := New(openIdentityTestDB(t))
	admin, _, err := svc.EnsureAdmin(ctx, "admin", "old-password")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}

	if _, _, _, err := svc.LoginSession(ctx, "admin", "wrong"); !errors.Is(err, ErrAuth) {
		t.Fatalf("bad password = %v; want ErrAuth", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "nobody", "old-password"); !errors.Is(err, ErrAuth) {
		t.Fatalf("unknown user = %v; want ErrAuth", err)
	}

	u, sid, exp, err := svc.LoginSession(ctx, "admin", "old-password")
	if err != nil {
		t.Fatalf("LoginSession: %v", err)
	}
	if u.ID != admin.ID || sid == "" || !exp.After(time.Now()) {
		t.Fatalf("LoginSession returned u=%+v sid=%q exp=%v", u, sid, exp)
	}
	if _, err := svc.ValidateSession(ctx, sid); err != nil {
		t.Fatalf("minted session does not validate: %v", err)
	}
}

// TestLoginSessionPasswordRotated proves a login for a rotated-away password is
// rejected rather than minting a full-TTL session for stale credentials.
func TestLoginSessionPasswordRotated(t *testing.T) {
	ctx := context.Background()
	svc := New(openIdentityTestDB(t))
	admin, _, err := svc.EnsureAdmin(ctx, "admin", "old-password")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	if err := svc.UpdatePassword(ctx, admin.ID, "old-password", "new-password", ""); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "old-password"); !errors.Is(err, ErrAuth) {
		t.Fatalf("stale-password login = %v; want ErrAuth", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "new-password"); err != nil {
		t.Fatalf("new password login: %v", err)
	}
}

func TestResetAdminPassword(t *testing.T) {
	ctx := context.Background()
	svc := New(openIdentityTestDB(t))

	// No user yet: reset must fail.
	if _, err := svc.ResetAdminPassword(ctx, "brand-new-password"); err == nil {
		t.Fatal("ResetAdminPassword succeeded with no admin user")
	}

	admin, _, err := svc.EnsureAdmin(ctx, "admin", "password")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	live, _, err := svc.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Weak password rejected by the policy.
	if _, err := svc.ResetAdminPassword(ctx, "short"); err == nil {
		t.Fatal("ResetAdminPassword accepted a weak password")
	}

	username, err := svc.ResetAdminPassword(ctx, "brand-new-password")
	if err != nil {
		t.Fatalf("ResetAdminPassword: %v", err)
	}
	if username != "admin" {
		t.Fatalf("ResetAdminPassword username = %q; want admin", username)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "brand-new-password"); err != nil {
		t.Fatalf("new password does not authenticate: %v", err)
	}
	if _, _, _, err := svc.LoginSession(ctx, "admin", "password"); !errors.Is(err, ErrAuth) {
		t.Fatalf("old password still authenticates after reset: %v", err)
	}
	if _, err := svc.ValidateSession(ctx, live); !errors.Is(err, ErrAuth) {
		t.Fatalf("session survived a password reset: %v", err)
	}
}
