package incidentops

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

func openIncidentOpsTest(t *testing.T) (*store.DB, context.Context) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "incidentops.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES('site_default','Home')`); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	for _, id := range []string{"agent_a", "agent_b"} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES(?,'site_default',x'00','h','online')`, id); err != nil {
			t.Fatalf("seed agent %s: %v", id, err)
		}
	}
	return db, ctx
}

func seedIncidentAlert(t *testing.T, db *store.DB, incidentID, alertID, agentID, state string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES(?,'site_default','group','Group',?,'open',?)`, incidentID, "alert:"+alertID, now); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO alerts(id,agent_id,site_id,group_id,group_name,incident_id,state,started_at)
		VALUES(? ,?,'site_default','group','Group',?,?,?)`, alertID, agentID, incidentID, state, now); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
}

func TestTraceCohortClosesAfterMissedResolutionCallback(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentAlert(t, db, "inc_1", "alert_1", "agent_a", "firing")
	seedIncidentAlert(t, db, "inc_2", "alert_2", "agent_a", "firing")
	svc := New(db, nil, nil, nil)
	plan := derivedTrace{mode: "icmp", destKey: "ip:1.1.1.1", destHost: "1.1.1.1", destIP: "1.1.1.1"}

	first, created, _, err := svc.singleFlight(ctx, eventbus.EvidenceAdded{
		IncidentID: "inc_1", AlertID: "alert_1", AgentID: "agent_a", SiteID: "site_default",
	}, "cond_1", plan)
	if err != nil || !created {
		t.Fatalf("create first report: id=%s created=%v err=%v", first, created, err)
	}
	second, created, _, err := svc.singleFlight(ctx, eventbus.EvidenceAdded{
		IncidentID: "inc_2", AlertID: "alert_2", AgentID: "agent_a", SiteID: "site_default",
	}, "cond_2", plan)
	if err != nil || created || second != first {
		t.Fatalf("overlap did not share report: first=%s second=%s created=%v err=%v", first, second, created, err)
	}

	// Simulate a crash after alert resolution committed but before OnAlertResolved.
	if _, err := db.ExecContext(ctx, `UPDATE alerts SET state='resolved', resolved_at=? WHERE id IN('alert_1','alert_2')`, time.Now().UTC()); err != nil {
		t.Fatalf("resolve alerts: %v", err)
	}
	if err := svc.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	var open, active int
	if err := db.QueryRowContext(ctx, `SELECT cohort_open FROM trace_reports WHERE id=?`, first).Scan(&open); err != nil {
		t.Fatalf("read cohort: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_report_refs WHERE report_id=? AND active=1`, first).Scan(&active); err != nil {
		t.Fatalf("count refs: %v", err)
	}
	if open != 0 || active != 0 {
		t.Fatalf("recovered cohort = open:%d active:%d, want 0/0", open, active)
	}

	seedIncidentAlert(t, db, "inc_3", "alert_3", "agent_a", "firing")
	third, created, _, err := svc.singleFlight(ctx, eventbus.EvidenceAdded{
		IncidentID: "inc_3", AlertID: "alert_3", AgentID: "agent_a", SiteID: "site_default",
	}, "cond_3", plan)
	if err != nil || !created || third == first {
		t.Fatalf("new fault reused old report: old=%s new=%s created=%v err=%v", first, third, created, err)
	}
}

func seedQueuedTrace(t *testing.T, db *store.DB, id, agentID string, seq int) {
	t.Helper()
	now := time.Now().UTC().Add(time.Duration(seq) * time.Millisecond)
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO trace_reports(id,site_id,agent_id,dest_key,dest_host,mode,status,max_hops,attempts,timeout_ms,requested_at,deadline_at)
		VALUES(?,'site_default',?,?,?,'icmp','queued',30,3,30000,?,?)`,
		id, agentID, fmt.Sprintf("ip:192.0.2.%d", seq+1), fmt.Sprintf("192.0.2.%d", seq+1), now, now.Add(time.Minute)); err != nil {
		t.Fatalf("seed queued trace: %v", err)
	}
}

func TestTraceCapacityClaimsStayWithinAgentAndGlobalLimits(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	for i := 0; i < 8; i++ {
		seedQueuedTrace(t, db, fmt.Sprintf("a_%d", i), "agent_a", i)
		seedQueuedTrace(t, db, fmt.Sprintf("b_%d", i), "agent_b", 100+i)
	}
	svc := New(db, nil, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		for _, agentID := range []string{"agent_a", "agent_b"} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				_, _, _ = svc.claimNextTrace(ctx, id, 2, 3)
			}(agentID)
		}
	}
	wg.Wait()
	var global, a, b int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE status='running'`).Scan(&global); err != nil {
		t.Fatalf("count global: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE status='running' AND agent_id='agent_a'`).Scan(&a); err != nil {
		t.Fatalf("count agent_a: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE status='running' AND agent_id='agent_b'`).Scan(&b); err != nil {
		t.Fatalf("count agent_b: %v", err)
	}
	if global != 3 || a > 2 || b > 2 {
		t.Fatalf("running counts global/a/b = %d/%d/%d, want 3 and each <=2", global, a, b)
	}
}

func TestSnapshotSizeCapIncludesBaseAndEntries(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	set := settings.New(db)
	if err := set.Set(ctx, settings.KeyIncidentSnapshotMaxBytes, "65536"); err != nil {
		t.Fatalf("set max bytes: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES('inc','site_default','group','Group','alert:big','open',?)`, now); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	base := SnapshotBase{IncidentID: "inc", SiteID: "site_default", Group: baseGroup{ID: "group", Name: "Group"}, TriggeredAt: now, ReceivedAt: now}
	for i := 0; i < 500; i++ {
		samples := make([]baseSample, 12)
		for j := range samples {
			samples[j] = baseSample{TS: now.Add(time.Duration(j) * time.Second), Value: float64(j)}
		}
		base.Members = append(base.Members, baseMember{
			AlertID: fmt.Sprintf("alert-%d", i), RuleID: "rule", AgentID: "agent_a", StartedAt: now,
			Evidence: []baseEvidence{{ConditionID: "cond", TargetID: "target", MetricKind: "probe.icmp.loss_pct", Comparator: "gt", RecentSamples: samples}},
		})
	}
	baseJSON := mustJSON(base)
	if len(baseJSON) <= 65536 {
		t.Fatalf("fixture base too small: %d", len(baseJSON))
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incident_snapshots(id,incident_id,status,base,total_bytes,deadline_at,created_at)
		VALUES('snap','inc','collecting',?,?,?,?)`, baseJSON, len(baseJSON), now.Add(time.Minute), now); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	payload, _ := json.Marshal(entryPayload{Targets: []telemetry.SnapshotTargetResult{{MonitorID: "target", Target: strings.Repeat("x", 70000)}}})
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incident_snapshot_entries(id,snapshot_id,request_id,agent_id,status,payload,requested_at)
		VALUES('entry','snap','req','agent_a','complete',?,?)`, string(payload), now); err != nil {
		t.Fatalf("seed entry: %v", err)
	}

	total, truncated, err := New(db, nil, set, nil).enforceSizeCap(ctx, "snap")
	if err != nil {
		t.Fatalf("enforce cap: %v", err)
	}
	if !truncated || total > 65536 {
		t.Fatalf("cap result total=%d truncated=%v", total, truncated)
	}
	var storedBase, storedPayload string
	if err := db.QueryRowContext(ctx, `SELECT base FROM incident_snapshots WHERE id='snap'`).Scan(&storedBase); err != nil {
		t.Fatalf("read base: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT payload FROM incident_snapshot_entries WHERE id='entry'`).Scan(&storedPayload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !json.Valid([]byte(storedBase)) || (storedPayload != "" && !json.Valid([]byte(storedPayload))) {
		t.Fatal("truncation stored invalid JSON")
	}
	if len(storedBase)+len(storedPayload) != total {
		t.Fatalf("stored bytes=%d, reported total=%d", len(storedBase)+len(storedPayload), total)
	}
}
