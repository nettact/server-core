package config

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

// TestSetSiteTargetsRejectDoesNotTerminate guards the P1 fix: when an update both
// removes a firing target and references an invalid (cross-site/unknown) group,
// the update must be rejected WITHOUT force-resolving the removed target's live
// alert. Otherwise a bounced config change would silently suppress an active alarm
// for a target that still exists.
func TestSetSiteTargetsRejectDoesNotTerminate(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	const siteID = "site_default"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name,created_at) VALUES(?, 'def', CURRENT_TIMESTAMP)`, siteID)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('ag1',?,x'00','h','online')`, siteID)
	// An existing target with a rule and a firing alert.
	exec(`INSERT INTO probe_tasks(id,site_id,kind,target,params,enabled,name,all_agents) VALUES('pt_del',?,'icmp','1.1.1.1','{}',1,'关键目标',1)`, siteID)
	exec(`INSERT INTO alert_rules(id,site_id,probe_task_id,name,metric_kind,comparator,threshold,for_seconds,layer,severity,enabled,is_template) VALUES('rule_del',?,'pt_del','R','probe.icmp.ok','lt',1,0,'wan','error',1,0)`, siteID)
	exec(`INSERT INTO alerts(id,rule_id,agent_id,site_id,target,state,value,started_at,fired_at) VALUES('al_del','rule_del','ag1',?,'1.1.1.1','firing',0,?,?)`, siteID, time.Now().UTC(), time.Now().UTC())

	bus := eventbus.New()
	var resolves int
	bus.Subscribe(eventbus.TopicAlertResolved, func(eventbus.Message) { resolves++ })
	alertSvc := alert.New(db, bus)
	svc := New(db, registry.New(db, 0), bus, alertSvc)

	// New set removes pt_del and adds a target bound to a non-existent group → reject.
	badGroup := []ProbeTarget{
		{Kind: "icmp", Target: "9.9.9.9", Enabled: true, AllAgents: false, GroupIDs: []string{"group_missing"}},
	}
	if err := svc.SetSiteTargets(ctx, siteID, badGroup); err == nil {
		t.Fatal("SetSiteTargets accepted an invalid group binding, want error")
	}

	// The rejected update must not have touched the live alert or its target.
	if resolves != 0 {
		t.Errorf("rejected update published %d resolve events, want 0", resolves)
	}
	var state string
	if err := db.QueryRowContext(ctx, `SELECT state FROM alerts WHERE id='al_del'`).Scan(&state); err != nil {
		t.Fatalf("alert lookup: %v", err)
	}
	if state != "firing" {
		t.Errorf("alert state = %q after rejected update, want firing", state)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM probe_tasks WHERE id='pt_del'`).Scan(&n); err != nil {
		t.Fatalf("task lookup: %v", err)
	}
	if n != 1 {
		t.Errorf("target pt_del count = %d after rejected update, want 1 (unchanged)", n)
	}

	// Positive control: a valid update that removes pt_del DOES terminate its alert.
	if err := svc.SetSiteTargets(ctx, siteID, []ProbeTarget{
		{Kind: "icmp", Target: "8.8.8.8", Enabled: true, AllAgents: true},
	}); err != nil {
		t.Fatalf("valid SetSiteTargets: %v", err)
	}
	if resolves != 1 {
		t.Errorf("valid removal published %d resolve events, want 1", resolves)
	}
}
