package config

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

func seedAgent(t *testing.T, db *store.DB, id, siteID string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES(?,?,x'00','h','online')`,
		id, siteID); err != nil {
		t.Fatalf("seed agent %s: %v", id, err)
	}
}

// TestDesiredStateForScoping verifies per-agent target resolution: a broadcast
// target (all_agents) reaches every agent, while a group-scoped target reaches
// only agents that belong to one of its groups.
func TestDesiredStateForScoping(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	const siteID = "site_default"
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES(?, 'def', CURRENT_TIMESTAMP)`, siteID); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	seedAgent(t, db, "agent_a", siteID)
	seedAgent(t, db, "agent_b", siteID)

	reg := registry.New(db, 0)
	svc := New(db, reg, nil, nil)

	// Group "g1" contains only agent_a.
	gid, err := reg.CreateGroup(ctx, siteID, "g1")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := reg.UpdateGroup(ctx, gid, "g1", []string{"agent_a"}); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}

	// One broadcast target and one scoped to g1.
	targets := []ProbeTarget{
		{Kind: "icmp", Target: "1.1.1.1", Enabled: true, AllAgents: true},
		{Kind: "icmp", Target: "9.9.9.9", Enabled: true, AllAgents: false, GroupIDs: []string{gid}},
	}
	if err := svc.SetSiteTargets(ctx, siteID, targets); err != nil {
		t.Fatalf("SetSiteTargets: %v", err)
	}

	has := func(agentID, target string) bool {
		ds, err := svc.DesiredStateFor(ctx, agentID)
		if err != nil {
			t.Fatalf("DesiredStateFor(%s): %v", agentID, err)
		}
		for _, p := range ds.ProbeTargets {
			if p.Target == target {
				return true
			}
		}
		return false
	}

	// agent_a is in g1 → sees both. agent_b sees only the broadcast target.
	if !has("agent_a", "1.1.1.1") {
		t.Errorf("agent_a should receive broadcast target 1.1.1.1")
	}
	if !has("agent_a", "9.9.9.9") {
		t.Errorf("agent_a (in g1) should receive scoped target 9.9.9.9")
	}
	if !has("agent_b", "1.1.1.1") {
		t.Errorf("agent_b should receive broadcast target 1.1.1.1")
	}
	if has("agent_b", "9.9.9.9") {
		t.Errorf("agent_b (not in g1) must NOT receive scoped target 9.9.9.9")
	}

	// Round-trip the scope through ListSiteTargets so the UI reads it back.
	list, err := svc.ListSiteTargets(ctx, siteID)
	if err != nil {
		t.Fatalf("ListSiteTargets: %v", err)
	}
	for _, tg := range list {
		if tg.Target == "9.9.9.9" {
			if tg.AllAgents {
				t.Errorf("scoped target should report AllAgents=false")
			}
			if len(tg.GroupIDs) != 1 || tg.GroupIDs[0] != gid {
				t.Errorf("scoped target GroupIDs = %v, want [%s]", tg.GroupIDs, gid)
			}
		}
	}
}

// TestGroupSiteConsistency verifies the site-consistency invariants: a group may
// not take a member from another site, and a target may not be scoped to a group
// from another site.
func TestGroupSiteConsistency(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	for _, s := range []string{"site_a", "site_b"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES(?, ?, CURRENT_TIMESTAMP)`, s, s); err != nil {
			t.Fatalf("seed site %s: %v", s, err)
		}
	}
	seedAgent(t, db, "agent_a", "site_a")
	seedAgent(t, db, "agent_b", "site_b") // lives in the OTHER site

	reg := registry.New(db, 0)
	svc := New(db, reg, nil, nil)

	gid, err := reg.CreateGroup(ctx, "site_a", "g")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	// A site_a group must reject a site_b agent as a member.
	if _, err := reg.UpdateGroup(ctx, gid, "g", []string{"agent_b"}); err == nil {
		t.Errorf("UpdateGroup accepted a cross-site agent; want error")
	}
	// Same-site member is fine.
	if _, err := reg.UpdateGroup(ctx, gid, "g", []string{"agent_a"}); err != nil {
		t.Errorf("UpdateGroup rejected a same-site agent: %v", err)
	}

	// A site_b target must reject a scope binding to the site_a group.
	targets := []ProbeTarget{
		{Kind: "icmp", Target: "9.9.9.9", Enabled: true, AllAgents: false, GroupIDs: []string{gid}},
	}
	if err := svc.SetSiteTargets(ctx, "site_b", targets); err == nil {
		t.Errorf("SetSiteTargets accepted a cross-site group binding; want error")
	}
}
