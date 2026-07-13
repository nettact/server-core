package registry

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
)

func mustExec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// TestUpdateAndDeleteAgent exercises the operator-facing agent CRUD: renaming an
// agent, and the hard delete that must clear every table referencing the agent
// (FK-constrained and not) in one transaction without tripping foreign_keys=ON.
func TestUpdateAndDeleteAgent(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed a site, an agent, and one row in every table that references the agent.
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_x','site_default',x'00','h','online')`)
	mustExec(t, db, `INSERT INTO interfaces(id,agent_id,name) VALUES('if1','agent_x','eth0')`)
	mustExec(t, db, `INSERT INTO agent_wifi(agent_id,state,sampled_at,last_sequence) VALUES('agent_x','ok',?,1)`, now)
	mustExec(t, db, `INSERT INTO config_versions(id,agent_id,version,desired_state,created_at) VALUES('cv1','agent_x',1,'{}',?)`, now)
	mustExec(t, db, `INSERT INTO agent_status_history(id,agent_id,status,changed_at) VALUES('ash1','agent_x','online',?)`, now)
	mustExec(t, db, `INSERT INTO agent_groups(id,site_id,name) VALUES('grp1','site_default','g')`)
	mustExec(t, db, `INSERT INTO agent_group_members(group_id,agent_id) VALUES('grp1','agent_x')`)
	mustExec(t, db, `INSERT INTO agent_packets(agent_id,sequence,received_at) VALUES('agent_x',1,?)`, now)
	mustExec(t, db, `INSERT INTO events(id,agent_id,site_id,ts,type) VALUES('e1','agent_x','site_default',?,'t')`, now)
	mustExec(t, db, `INSERT INTO alerts(id,agent_id,site_id,state,started_at) VALUES('al1','agent_x','site_default','firing',?)`, now)

	reg := New(db, 0)

	// UpdateAgent sets the operator-editable display name and Get reflects it.
	if err := reg.UpdateAgent(ctx, "agent_x", "My Agent"); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	a, err := reg.Get(ctx, "agent_x")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if a.DisplayName != "My Agent" {
		t.Fatalf("DisplayName = %q, want %q", a.DisplayName, "My Agent")
	}

	// DeleteAgent removes the agent and every referencing row, no FK error.
	if err := reg.DeleteAgent(ctx, "agent_x"); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	for _, tbl := range []string{
		"interfaces", "agent_wifi", "config_versions", "agent_status_history", "agent_group_members",
		"agent_packets", "events", "alerts",
	} {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+tbl+` WHERE agent_id='agent_x'`).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows for deleted agent", tbl, n)
		}
	}
	var agentN int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE id='agent_x'`).Scan(&agentN); err != nil {
		t.Fatalf("count agents: %v", err)
	}
	if agentN != 0 {
		t.Errorf("agents still has %d rows for deleted agent", agentN)
	}

	// Missing-agent mutations report sql.ErrNoRows (handlers map this to 404).
	if err := reg.DeleteAgent(ctx, "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("DeleteAgent(missing) = %v, want sql.ErrNoRows", err)
	}
	if err := reg.UpdateAgent(ctx, "nope", "x"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UpdateAgent(missing) = %v, want sql.ErrNoRows", err)
	}
}

// TestSweepStaleExcludesConnected verifies the sweep's exclusion list: an agent
// with a stale last_seen_at but a live WebSocket session (its ID is in exclude)
// must stay online, while an equally stale, non-excluded agent flips offline
// with a history row.
func TestSweepStaleExcludesConnected(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	stale := time.Now().UTC().Add(-time.Hour)

	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, stale)
	for _, id := range []string{"agent_connected", "agent_gone"} {
		mustExec(t, db,
			`INSERT INTO agents(id,site_id,public_key,token_hash,status,last_seen_at) VALUES(?,'site_default',x'00','h','online',?)`,
			id, stale)
	}

	reg := New(db, 0)
	n, err := reg.SweepStale(ctx, 10*time.Second, []string{"agent_connected"})
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if n != 1 {
		t.Errorf("SweepStale flipped %d agents, want 1", n)
	}
	for id, want := range map[string]string{"agent_connected": "online", "agent_gone": "offline"} {
		a, err := reg.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get(%s): %v", id, err)
		}
		if a.Status != want {
			t.Errorf("%s status = %q, want %q", id, a.Status, want)
		}
	}
	// Only the flipped agent gets an offline history row.
	if hist, _ := reg.StatusHistory(ctx, "agent_gone"); len(hist) != 1 || hist[0].Status != "offline" {
		t.Errorf("agent_gone history = %+v, want one offline event", hist)
	}
	if hist, _ := reg.StatusHistory(ctx, "agent_connected"); len(hist) != 0 {
		t.Errorf("agent_connected history = %+v, want none", hist)
	}
}
