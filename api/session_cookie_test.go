package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetSessionCookieAttributes(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	rr := httptest.NewRecorder()
	SetSessionCookie(rr, "session-value", expires, true)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie count = %d; want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != sessionCookie || c.Value != "session-value" || c.Path != "/" {
		t.Fatalf("cookie identity = %+v", c)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie security attributes = %+v", c)
	}
	if !c.Expires.Equal(expires) {
		t.Fatalf("Expires = %s; want %s", c.Expires, expires)
	}
}
