package alert

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/store"
)

// TestTerminateForRuleResolvesAndPublishes verifies that terminating a rule's
// alerts resolves every open row (firing and pending) and publishes exactly one
// TopicAlertResolved — for the firing row only — carrying ReasonDeleted, so the
// incident correlator can record a termination rather than a false recovery.
func TestTerminateForRuleResolvesAndPublishes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	now := time.Now().UTC()
	exec(`INSERT INTO sites(id,name) VALUES('site_default','H')`)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,hostname) VALUES('ag1','site_default',?,?,'h')`, []byte("k"), "th")
	exec(`INSERT INTO probe_tasks(id,site_id,kind,target,params,enabled,name,all_agents) VALUES('pt1','site_default','http','x','{}',1,'M',1)`)
	exec(`INSERT INTO alert_rules(id,site_id,probe_task_id,name,metric_kind,comparator,threshold,for_seconds,layer,severity,enabled,is_template) VALUES('rule1','site_default','pt1','R','probe.http.status','eq',200,0,'service','critical',1,0)`)
	exec(`INSERT INTO alerts(id,rule_id,agent_id,site_id,target,state,value,started_at) VALUES('firing1','rule1','ag1','site_default','x','firing',503,?)`, now)
	exec(`INSERT INTO alerts(id,rule_id,agent_id,site_id,target,state,value,started_at) VALUES('pending1','rule1','ag1','site_default','x','pending',503,?)`, now)

	bus := eventbus.New()
	var got []Raised
	bus.Subscribe(eventbus.TopicAlertResolved, func(m eventbus.Message) {
		if r, ok := m.Payload.(Raised); ok {
			got = append(got, r)
		}
	})
	svc := New(db, bus)

	if err := svc.TerminateForRule(ctx, "rule1"); err != nil {
		t.Fatalf("TerminateForRule: %v", err)
	}

	// Both rows resolved, none left open.
	var open int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE rule_id='rule1' AND state IN ('pending','firing')`).Scan(&open); err != nil {
		t.Fatalf("count open: %v", err)
	}
	if open != 0 {
		t.Fatalf("still %d open alerts, want 0", open)
	}

	// Exactly one resolve event — the firing one — with the deletion reason.
	if len(got) != 1 {
		t.Fatalf("published %d resolve events, want 1 (firing only): %+v", len(got), got)
	}
	if got[0].ID != "firing1" || got[0].Reason != ReasonDeleted {
		t.Fatalf("event = {ID:%q Reason:%q}, want {firing1 deleted}", got[0].ID, got[0].Reason)
	}

	// Idempotent: a second call finds nothing open and publishes nothing more.
	got = nil
	if err := svc.TerminateForRule(ctx, "rule1"); err != nil {
		t.Fatalf("TerminateForRule (2nd): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("second call published %d events, want 0", len(got))
	}
}
