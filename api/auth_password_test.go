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
	if _, err := id.Authenticate(ctx, "admin", "old-password"); err != nil {
		t.Fatalf("rejected change altered the password: %v", err)
	}

	// Successful change → 200.
	if w := changePassword(d, current, `{"old_password":"old-password","new_password":"new-password"}`); w.Code != http.StatusOK {
		t.Fatalf("change status=%d body=%s", w.Code, w.Body.String())
	}
	// Old password no longer works; new one authenticates.
	if _, err := id.Authenticate(ctx, "admin", "old-password"); !errors.Is(err, identity.ErrAuth) {
		t.Fatalf("old password still authenticates: %v", err)
	}
	if _, err := id.Authenticate(ctx, "admin", "new-password"); err != nil {
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
