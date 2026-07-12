package settings

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nettact/server-core/store"
)

func TestSettingsRoundTrip(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	s := New(db)

	// Unset reads as empty, not an error.
	if v, err := s.Get(ctx, KeyConsoleBaseURL); err != nil || v != "" {
		t.Fatalf("Get unset = (%q,%v), want (\"\",nil)", v, err)
	}
	if got := s.ConsoleBaseURL(ctx); got != "" {
		t.Fatalf("ConsoleBaseURL unset = %q, want empty", got)
	}

	// Set + normalized read (trailing slash trimmed).
	if err := s.Set(ctx, KeyConsoleBaseURL, "http://localhost:8080/"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := s.ConsoleBaseURL(ctx); got != "http://localhost:8080" {
		t.Fatalf("ConsoleBaseURL = %q, want trimmed", got)
	}
	all, err := s.All(ctx)
	if err != nil || all[KeyConsoleBaseURL] != "http://localhost:8080/" {
		t.Fatalf("All = %v (err %v)", all, err)
	}

	// Empty value clears the key (unset == empty string).
	if err := s.Set(ctx, KeyConsoleBaseURL, ""); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	if v, _ := s.Get(ctx, KeyConsoleBaseURL); v != "" {
		t.Fatalf("after clear Get = %q, want empty", v)
	}

	// Nil-safe.
	var nilSvc *Service
	if got := nilSvc.ConsoleBaseURL(ctx); got != "" {
		t.Fatalf("nil ConsoleBaseURL = %q, want empty", got)
	}
}
