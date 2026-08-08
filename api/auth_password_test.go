package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/store/storetest"
)

func passwordTestDeps(t *testing.T) (Deps, *identity.Service) {
	t.Helper()
	db := storetest.Open(t)
	id := identity.New(db)
	return Deps{Identity: id, Audit: audit.New(db)}, id
}

// changePassword invokes handleChangePassword with the given session cookie.
func changePassword(d Deps, sid, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", strings.NewReader(body))
	if sid != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	}
	w := httptest.NewRecorder()
	d.handleChangePassword(w, req)
	return w
}

func TestHandleChangePasswordFlow(t *testing.T) {
	ctx := context.Background()
	d, id := passwordTestDeps(t)
	admin, _, err := id.EnsureAdmin(ctx, "admin", "old-password")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	current, _, err := id.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create current session: %v", err)
	}
	other, _, err := id.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}

	// Wrong old password → 403 (distinct from requireSession's 401 "login required").
	if w := changePassword(d, current, `{"old_password":"wrong","new_password":"new-password"}`); w.Code != http.StatusForbidden {
		t.Fatalf("wrong old password status=%d body=%s", w.Code, w.Body.String())
	}
	// Weak new password → 400.
	if w := changePassword(d, current, `{"old_password":"old-password","new_password":"short"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("weak new password status=%d body=%s", w.Code, w.Body.String())
	}
	// A rejected change must not have altered anything.
	if _, _, _, err := id.LoginSession(ctx, "admin", "old-password"); err != nil {
		t.Fatalf("rejected change altered the password: %v", err)
	}

	// Successful change → 200.
	if w := changePassword(d, current, `{"old_password":"old-password","new_password":"new-password"}`); w.Code != http.StatusOK {
		t.Fatalf("change status=%d body=%s", w.Code, w.Body.String())
	}
	// Old password no longer works; new one authenticates.
	if _, _, _, err := id.LoginSession(ctx, "admin", "old-password"); !errors.Is(err, identity.ErrAuth) {
		t.Fatalf("old password still authenticates: %v", err)
	}
	if _, _, _, err := id.LoginSession(ctx, "admin", "new-password"); err != nil {
		t.Fatalf("new password does not authenticate: %v", err)
	}
	// The other session is revoked; the caller's session survives.
	if _, err := id.ValidateSession(ctx, other); !errors.Is(err, identity.ErrAuth) {
		t.Fatalf("other session survived the change: %v", err)
	}
	if _, err := id.ValidateSession(ctx, current); err != nil {
		t.Fatalf("current session was revoked: %v", err)
	}
}

// On a desktop install the admin password is random and never shown, so the
// console cannot send a current one. The change must succeed without it — and
// must still revoke the other sessions.
func TestHandleChangePasswordDesktopSkipsOldPassword(t *testing.T) {
	ctx := context.Background()
	d, id := passwordTestDeps(t)
	d.ListenStatus = func(context.Context) *ListenStatus { return &ListenStatus{Desktop: true} }
	admin, _, err := id.EnsureAdmin(ctx, "admin", "unknowable-random-secret")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	current, _, err := id.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create current session: %v", err)
	}
	other, _, err := id.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}

	if w := changePassword(d, current, `{"new_password":"chosen-password"}`); w.Code != http.StatusOK {
		t.Fatalf("desktop change status=%d body=%s", w.Code, w.Body.String())
	}
	if _, _, _, err := id.LoginSession(ctx, "admin", "chosen-password"); err != nil {
		t.Fatalf("new password does not authenticate: %v", err)
	}
	if _, err := id.ValidateSession(ctx, other); !errors.Is(err, identity.ErrAuth) {
		t.Fatalf("other session survived the change: %v", err)
	}
	if _, err := id.ValidateSession(ctx, current); err != nil {
		t.Fatalf("current session was revoked: %v", err)
	}

	// The policy still applies — desktop skips the old password, not the rules.
	if w := changePassword(d, current, `{"new_password":"short"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("weak new password status=%d body=%s", w.Code, w.Body.String())
	}
}

// The self-hosted server must keep demanding the old password: a session there
// can be obtained from anywhere with the password, so a stolen one must not be
// able to lock the owner out.
func TestHandleChangePasswordSelfHostedStillRequiresOldPassword(t *testing.T) {
	ctx := context.Background()
	d, id := passwordTestDeps(t)
	d.ListenStatus = func(context.Context) *ListenStatus { return &ListenStatus{Desktop: false} }
	admin, _, err := id.EnsureAdmin(ctx, "admin", "old-password")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	current, _, err := id.CreateSession(ctx, admin.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if w := changePassword(d, current, `{"new_password":"new-password"}`); w.Code != http.StatusForbidden {
		t.Fatalf("missing old password status=%d body=%s", w.Code, w.Body.String())
	}
	if _, _, _, err := id.LoginSession(ctx, "admin", "old-password"); err != nil {
		t.Fatalf("rejected change altered the password: %v", err)
	}
}
