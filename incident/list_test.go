package incident

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
)

// TestListPagination verifies Count + List(limit, offset) page newest-first.
func TestListPagination(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES('site_default','H')`); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		// opened_at increasing with i, so i=24 is newest.
		if _, err := db.ExecContext(ctx,
			`INSERT INTO incidents(id, site_id, state, summary, opened_at) VALUES(?,?, 'open', ?, ?)`,
			fmt.Sprintf("inc_%02d", i), "site_default", fmt.Sprintf("s%02d", i), base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("seed incident %d: %v", i, err)
		}
	}

	svc := New(db, nil, nil, nil)

	total, err := svc.Count(ctx, "site_default")
	if err != nil || total != 25 {
		t.Fatalf("Count = %d (err %v), want 25", total, err)
	}

	// Page 1, size 15: newest 15 (inc_24 .. inc_10).
	p1, err := svc.List(ctx, "site_default", 15, 0)
	if err != nil {
		t.Fatalf("List p1: %v", err)
	}
	if len(p1) != 15 || p1[0].ID != "inc_24" || p1[14].ID != "inc_10" {
		t.Fatalf("page1 = %d items, first %q last %q", len(p1), first(p1), last(p1))
	}

	// Page 2, size 15: remaining 10 (inc_09 .. inc_00).
	p2, err := svc.List(ctx, "site_default", 15, 15)
	if err != nil {
		t.Fatalf("List p2: %v", err)
	}
	if len(p2) != 10 || p2[0].ID != "inc_09" || p2[9].ID != "inc_00" {
		t.Fatalf("page2 = %d items, first %q last %q", len(p2), first(p2), last(p2))
	}
}

func first(x []Incident) string {
	if len(x) == 0 {
		return ""
	}
	return x[0].ID
}
func last(x []Incident) string {
	if len(x) == 0 {
		return ""
	}
	return x[len(x)-1].ID
}
