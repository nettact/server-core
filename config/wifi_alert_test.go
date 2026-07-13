package config

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

func TestWiFiHostAnchorIsNotInDesiredState(t *testing.T) {
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
	seedAgent(t, db, "agent_wifi", siteID)

	svc := New(db, registry.New(db, 0), nil)
	if err := svc.SetSiteTargets(ctx, siteID, []ProbeTarget{
		{Kind: "icmp", Target: "1.1.1.1", Enabled: true, AllAgents: true},
		{Kind: "host", Target: "*", Enabled: true, AllAgents: true},
	}); err != nil {
		t.Fatalf("SetSiteTargets: %v", err)
	}

	ds, err := svc.DesiredStateFor(ctx, "agent_wifi")
	if err != nil {
		t.Fatalf("DesiredStateFor: %v", err)
	}
	if len(ds.ProbeTargets) != 1 || ds.ProbeTargets[0].Kind != "icmp" || ds.ProbeTargets[0].Target != "1.1.1.1" {
		t.Fatalf("DesiredState targets = %+v, want only ICMP probe", ds.ProbeTargets)
	}

	stored, err := svc.ListSiteTargets(ctx, siteID)
	if err != nil {
		t.Fatalf("ListSiteTargets: %v", err)
	}
	foundAnchor := false
	for _, target := range stored {
		if target.Kind == "host" && target.Target == "*" {
			foundAnchor = true
		}
	}
	if !foundAnchor {
		t.Fatal("host/* Wi-Fi alert anchor was not persisted")
	}
}
