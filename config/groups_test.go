package config

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

func openConfigTestDB(t *testing.T) (*store.DB, context.Context) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	for _, siteID := range []string{"site_default", "site_other"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES(?,?)`, siteID, siteID); err != nil {
			t.Fatalf("seed site %s: %v", siteID, err)
		}
	}
	for _, row := range []struct{ id, site string }{{"agent_a", "site_default"}, {"agent_b", "site_default"}, {"agent_other", "site_other"}} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES(?,?,x'00','h','online')`, row.id, row.site); err != nil {
			t.Fatalf("seed agent %s: %v", row.id, err)
		}
	}
	return db, ctx
}

func TestDesiredStateUsesMonitorGroupScope(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	reg := registry.New(db, 0)
	svc := New(db, reg, nil, nil)

	agid, err := reg.CreateGroup(ctx, "site_default", "agents-a")
	if err != nil {
		t.Fatalf("create agent group: %v", err)
	}
	if _, err := reg.UpdateGroup(ctx, agid, "agents-a", []string{"agent_a"}); err != nil {
		t.Fatalf("populate agent group: %v", err)
	}
	allID, err := svc.CreateGroup(ctx, "site_default", "all", false, true, nil)
	if err != nil {
		t.Fatalf("create all monitor group: %v", err)
	}
	scopedID, err := svc.CreateGroup(ctx, "site_default", "scoped", true, false, []string{agid})
	if err != nil {
		t.Fatalf("create scoped monitor group: %v", err)
	}
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "target_all", GroupID: allID, Kind: "icmp", Target: "1.1.1.1", Enabled: true},
		{ID: "target_scoped", GroupID: scopedID, Kind: "icmp", Target: "9.9.9.9", Enabled: true},
	}); err != nil {
		t.Fatalf("set targets: %v", err)
	}

	has := func(agentID, target string) bool {
		t.Helper()
		ds, err := svc.DesiredStateFor(ctx, agentID)
		if err != nil {
			t.Fatalf("desired state for %s: %v", agentID, err)
		}
		for _, got := range ds.ProbeTargets {
			if got.Target == target {
				return true
			}
		}
		return false
	}
	if !has("agent_a", "1.1.1.1") || !has("agent_a", "9.9.9.9") {
		t.Fatal("agent_a should receive both broadcast and scoped targets")
	}
	if !has("agent_b", "1.1.1.1") || has("agent_b", "9.9.9.9") {
		t.Fatal("agent_b should receive only the broadcast target")
	}
	listed, err := svc.ListSiteTargets(ctx, "site_default")
	if err != nil {
		t.Fatalf("list targets: %v", err)
	}
	for _, got := range listed {
		if got.ID == "target_scoped" && got.GroupID != scopedID {
			t.Fatalf("target group = %q, want %q", got.GroupID, scopedID)
		}
	}
}

func TestValidateGroupScopeRejectsBeforeMutation(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	reg := registry.New(db, 0)
	svc := New(db, reg, nil, nil)
	other, err := reg.CreateGroup(ctx, "site_other", "other-site")
	if err != nil {
		t.Fatalf("create other-site group: %v", err)
	}

	if err := svc.ValidateGroupScope(ctx, "site_default", false, []string{"missing"}); err == nil {
		t.Fatal("unknown agent group was accepted")
	}
	if err := svc.ValidateGroupScope(ctx, "site_default", false, []string{other}); err == nil {
		t.Fatal("cross-site agent group was accepted")
	}
	if err := svc.ValidateGroupScope(ctx, "site_default", true, []string{"missing"}); err != nil {
		t.Fatalf("all-agents scope should ignore submitted bindings: %v", err)
	}
}

func TestHostAnchorIsStoredButNotPushed(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	svc := New(db, registry.New(db, 0), nil, nil)
	groupID, err := svc.CreateGroup(ctx, "site_default", "all", false, true, nil)
	if err != nil {
		t.Fatalf("create monitor group: %v", err)
	}
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "icmp", GroupID: groupID, Kind: "icmp", Target: "1.1.1.1", Enabled: true},
		{ID: "wifi-anchor", GroupID: groupID, Kind: "host", Target: "*", Enabled: true},
	}); err != nil {
		t.Fatalf("set targets: %v", err)
	}
	ds, err := svc.DesiredStateFor(ctx, "agent_a")
	if err != nil {
		t.Fatalf("desired state: %v", err)
	}
	if len(ds.ProbeTargets) != 1 || ds.ProbeTargets[0].MonitorID != "icmp" {
		t.Fatalf("desired targets = %+v, want only icmp", ds.ProbeTargets)
	}
	stored, err := svc.ListSiteTargets(ctx, "site_default")
	if err != nil {
		t.Fatalf("list targets: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored targets = %d, want 2", len(stored))
	}
}
