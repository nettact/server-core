package alert

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
)

func TestListForAgentScopesBeforeLimitAndFiltersEvidence(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent-1','site_default',x'00','h','online')`); err != nil {
		t.Fatal(err)
	}
	insertAlert := func(id string, started time.Time) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO alerts(id,agent_id,site_id,group_id,state,severity,started_at) VALUES(?,?,?,?,?,?,?)`,
			id, "agent-1", "site_default", "group-1", "resolved", "warn", started); err != nil {
			t.Fatal(err)
		}
	}
	insertEvidence := func(id, alertID, conditionID, targetID, targetAddr string, observed time.Time) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO alert_evidence(id,alert_id,condition_id,target_id,target_addr,metric_kind,comparator,threshold,value,observed_at) VALUES(?,?,?,?,?,'probe.dns.ok','lt',1,0,?)`,
			id, alertID, conditionID, targetID, targetAddr, observed); err != nil {
			t.Fatal(err)
		}
	}

	// The unrelated row is newer. LIMIT 1 must still return the older matching
	// alert, proving target filtering happens in SQL before the cap.
	insertAlert("alert-other", now)
	insertEvidence("e-other", "alert-other", "c-other", "monitor-other", "other.example", now)
	insertAlert("alert-match", now.Add(-time.Minute))
	insertEvidence("e-match", "alert-match", "c-match", "monitor-wanted", "wanted.example", now.Add(-time.Minute))
	insertEvidence("e-group-peer", "alert-match", "c-peer", "monitor-peer", "peer.example", now.Add(-time.Minute))

	service := New(db)
	alerts, err := service.ListForAgent(ctx, "agent-1", TargetScope{MonitorID: "monitor-wanted"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].ID != "alert-match" {
		t.Fatalf("monitor-scoped alerts = %+v", alerts)
	}
	if len(alerts[0].Evidence) != 1 || alerts[0].Evidence[0].TargetID != "monitor-wanted" {
		t.Fatalf("monitor-scoped evidence = %+v", alerts[0].Evidence)
	}

	alerts, err = service.ListForAgent(ctx, "agent-1", TargetScope{Address: "wanted.example"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || len(alerts[0].Evidence) != 1 || alerts[0].Evidence[0].TargetAddr != "wanted.example" {
		t.Fatalf("address-scoped alerts = %+v", alerts)
	}
}

func TestCountActive(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent-1','site_default',x'00','h','online')`); err != nil {
		t.Fatal(err)
	}
	insert := func(id, state string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO alerts(id,agent_id,site_id,group_id,state,severity,started_at) VALUES(?,?,?,?,?,?,?)`,
			id, "agent-1", "site_default", "group-1", state, "warn", now); err != nil {
			t.Fatal(err)
		}
	}

	service := New(db)
	n, err := service.CountActive(ctx, "site_default")
	if err != nil || n != 0 {
		t.Fatalf("empty CountActive = %d, %v", n, err)
	}

	insert("a-firing-1", "firing")
	insert("a-firing-2", "firing")
	insert("a-resolved", "resolved")
	n, err = service.CountActive(ctx, "site_default")
	if err != nil || n != 2 {
		t.Fatalf("CountActive = %d, %v; want 2", n, err)
	}
	n, err = service.CountActive(ctx, "site_other")
	if err != nil || n != 0 {
		t.Fatalf("other-site CountActive = %d, %v; want 0", n, err)
	}
}
