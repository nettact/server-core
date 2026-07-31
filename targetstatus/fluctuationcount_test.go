package targetstatus

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The fluctuation count travels with every availability figure in the status
// batch, so its query has to be right about three things: the window, the site,
// and the (target, agent) grouping. Get the grouping wrong and one Agent's dips
// are attributed to another; get the window wrong and a figure that recovered
// last week still looks unexplained today.

func insertCountFixture(t *testing.T, db *store.DB, id, siteID, targetID, agentID string, endedAt time.Time) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO fluctuations(id, site_id, agent_id, target_id, fail_rounds, fail_threshold,
		    started_at, ended_at)
		VALUES(?,?,?,?,1,3,?,?)`,
		id, siteID, agentID, targetID, endedAt.Add(-10*time.Second), endedAt); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFluctuationCounts(t *testing.T) {
	db := storetest.Open(t)
	svc := New(db, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	// Two dips on one pair, one on a second Agent of the same target, one on
	// another target, one outside the window, and one in a different site.
	insertCountFixture(t, db, "flx_1", "site_a", "t_one", "agent_a", now.Add(-time.Hour))
	insertCountFixture(t, db, "flx_2", "site_a", "t_one", "agent_a", now.Add(-2*time.Hour))
	insertCountFixture(t, db, "flx_3", "site_a", "t_one", "agent_b", now.Add(-3*time.Hour))
	insertCountFixture(t, db, "flx_4", "site_a", "t_two", "agent_a", now.Add(-4*time.Hour))
	insertCountFixture(t, db, "flx_old", "site_a", "t_one", "agent_a", now.Add(-48*time.Hour))
	// A target belongs to exactly one site, so the other site's row needs its own
	// target id — (target, agent, started_at) is unique regardless of site.
	insertCountFixture(t, db, "flx_other", "site_b", "t_elsewhere", "agent_a", now.Add(-time.Hour))
	// Timestamps come from the agent's clock, so one running ahead lands in the
	// server's future. Such a dip is outside the availability window too, and must
	// not be counted as explaining a ratio that does not include it.
	insertCountFixture(t, db, "flx_future", "site_a", "t_one", "agent_a", now.Add(2*time.Hour))

	got, err := svc.loadFluctuationCounts(ctx, "site_a", now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatalf("loadFluctuationCounts: %v", err)
	}

	if n := got["t_one"]["agent_a"]; n != 2 {
		t.Errorf("t_one/agent_a = %d, want 2 (the older and the future-dated ones are outside the window)", n)
	}
	if n := got["t_one"]["agent_b"]; n != 1 {
		t.Errorf("t_one/agent_b = %d, want 1 — a second Agent's dips are its own", n)
	}
	if n := got["t_two"]["agent_a"]; n != 1 {
		t.Errorf("t_two/agent_a = %d, want 1", n)
	}
	if len(got) != 2 {
		t.Errorf("expected exactly the two targets of site_a, got %v", got)
	}
	// A target with no dips must be absent rather than present with 0, so the
	// caller's zero value is the only source of "none".
	if _, ok := got["t_none"]; ok {
		t.Error("a target with no fluctuations should not appear")
	}
}
