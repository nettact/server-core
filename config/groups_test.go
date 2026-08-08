package config

import (
	"context"
	"sync"
	"testing"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func openConfigTestDB(t *testing.T) (*store.DB, context.Context) {
	t.Helper()
	db := storetest.Open(t)
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

func TestSetSiteTargetsIsIdempotentAndSiteSafe(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	reg := registry.New(db, 0, nil)
	bus := eventbus.New()
	svc := New(db, reg, bus, nil, nil)
	var configEvents int
	var statusEvents []eventbus.TargetStatusChanged
	bus.Subscribe(eventbus.TopicConfigChanged, func(eventbus.Message) { configEvents++ })
	bus.Subscribe(eventbus.TopicTargetStatusChanged, func(m eventbus.Message) {
		statusEvents = append(statusEvents, m.Payload.(eventbus.TargetStatusChanged))
	})
	localGroup, err := svc.CreateGroup(ctx, "site_default", "local", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := svc.CreateGroup(ctx, "site_other", "other", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := ProbeTarget{ID: "local", GroupID: localGroup, Kind: "http", Name: "Before", Target: "https://local.test", Enabled: true}
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{local}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSiteTargets(ctx, "site_other", []ProbeTarget{{ID: "foreign", GroupID: otherGroup, Kind: "dns", Target: "example.test", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	configEvents = 0
	statusEvents = nil
	var before int
	if err := db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{local}); err != nil {
		t.Fatal(err)
	}
	var after int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&after)
	if after != before {
		t.Fatalf("identical save serial = %d, want %d", after, before)
	}
	if configEvents != 0 || len(statusEvents) != 0 {
		t.Fatalf("identical save published config/status events: %d/%+v", configEvents, statusEvents)
	}

	local.Name = "After"
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{local}); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&after)
	if after != before {
		t.Fatalf("name-only save serial = %d, want %d", after, before)
	}
	var name string
	_ = db.QueryRowContext(ctx, `SELECT name FROM probe_tasks WHERE id='local'`).Scan(&name)
	if name != "After" {
		t.Fatalf("name = %q, want After", name)
	}
	if configEvents != 0 || len(statusEvents) != 1 || len(statusEvents[0].TargetIDs) != 1 || statusEvents[0].TargetIDs[0] != "local" {
		t.Fatalf("name-only events = config:%d status:%+v", configEvents, statusEvents)
	}

	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{{ID: "foreign", GroupID: localGroup, Kind: "dns", Target: "changed.test", Enabled: true}}); err == nil {
		t.Fatal("cross-site target id was accepted")
	}
	var foreignSite, foreignTarget string
	if err := db.QueryRowContext(ctx, `SELECT site_id,target FROM probe_tasks WHERE id='foreign'`).Scan(&foreignSite, &foreignTarget); err != nil {
		t.Fatal(err)
	}
	if foreignSite != "site_other" || foreignTarget != "example.test" {
		t.Fatalf("foreign target mutated to %s/%s", foreignSite, foreignTarget)
	}
	var localCount int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM probe_tasks WHERE id='local' AND site_id='site_default'`).Scan(&localCount)
	if localCount != 1 {
		t.Fatal("rejected cross-site request changed the local replacement set")
	}
}

func TestConcurrentTargetReplacementNeverMergesSets(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	svc := New(db, registry.New(db, 0, nil), nil, nil, nil)
	const groupID = "group-default"
	if _, err := db.ExecContext(ctx, `INSERT INTO monitor_groups(id,site_id,name,is_default,all_agents) VALUES(?,'site_default','Default',1,1)`, groupID); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		start := make(chan struct{})
		errCh := make(chan error, 2)
		var wg sync.WaitGroup
		for _, id := range []string{"set-a", "set-b"} {
			id := id
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{{ID: id, GroupID: groupID, Kind: "icmp", Target: id, Enabled: true}})
				errCh <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				t.Fatalf("concurrent replacement: %v", err)
			}
		}
		got, err := svc.ListSiteTargets(ctx, "site_default")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || (got[0].ID != "set-a" && got[0].ID != "set-b") {
			t.Fatalf("replacement merged sets: %+v", got)
		}
	}
}

func TestDesiredStateUsesMonitorGroupScope(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	reg := registry.New(db, 0, nil)
	svc := New(db, reg, nil, nil, nil)

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
	reg := registry.New(db, 0, nil)
	svc := New(db, reg, nil, nil, nil)
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
	svc := New(db, registry.New(db, 0, nil), nil, nil, nil)
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
