package alert

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
)

// TestListActiveEnriched verifies ListActive joins in the descriptive fields the
// UI needs: the detecting agent's host, the probe's friendly name + kind, and
// the rule's metric condition.
func TestListActiveEnriched(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
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
	exec(`INSERT INTO sites(id,name) VALUES('site_default','Home')`)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,display_name) VALUES('ag1','site_default',?,?,'raw-host','客厅主机')`, []byte("k"), "th")
	exec(`INSERT INTO probe_tasks(id,site_id,kind,target,params,enabled,name,all_agents) VALUES('pt1','site_default','host','host','{}',1,'系统监控',1)`)
	exec(`INSERT INTO alert_rules(id,site_id,probe_task_id,name,metric_kind,comparator,threshold,for_seconds,layer,severity,enabled,is_template) VALUES('rule1','site_default','pt1','系统监控 报警','host.cpu.pct','gt',10,0,'local','warn',1,0)`)
	exec(`INSERT INTO alerts(id,rule_id,agent_id,site_id,target,state,value,started_at) VALUES('al1','rule1','ag1','site_default','host','firing',11,?)`, time.Now().UTC())

	svc := New(db, nil)
	got, err := svc.ListActive(ctx, "site_default")
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1", len(got))
	}
	a := got[0]
	// Who fired: display name preferred over raw hostname / id.
	if a.AgentHost != "客厅主机" {
		t.Errorf("AgentHost = %q, want 客厅主机", a.AgentHost)
	}
	// Why: the rule condition + probe identity needed to render a description.
	if a.TargetName != "系统监控" || a.ProbeKind != "host" {
		t.Errorf("probe fields = (%q,%q), want (系统监控,host)", a.TargetName, a.ProbeKind)
	}
	if a.MetricKind != "host.cpu.pct" || a.Comparator != "gt" || a.Threshold != 10 {
		t.Errorf("condition = (%q,%q,%v), want (host.cpu.pct,gt,10)", a.MetricKind, a.Comparator, a.Threshold)
	}
	if a.Value != 11 {
		t.Errorf("Value = %v, want 11", a.Value)
	}
}
