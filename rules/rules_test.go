package rules

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

func mustExec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// seedSample writes one raw sample for (agent, kind, target) at ts (unix seconds).
func seedSample(t *testing.T, db *store.DB, agentID, siteID, kind, target string, value float64, ts int64) {
	t.Helper()
	res, err := db.ExecContext(context.Background(),
		`INSERT INTO series(agent_id, site_id, kind, target, layer, unit) VALUES(?,?,?,?,'','')`,
		agentID, siteID, kind, target)
	if err != nil {
		t.Fatalf("insert series: %v", err)
	}
	sid, _ := res.LastInsertId()
	mustExec(t, db, `INSERT INTO samples(series_id, ts, value) VALUES(?,?,?)`, sid, ts, value)
}

func firingAlerts(t *testing.T, db *store.DB, agentID string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM alerts WHERE agent_id=? AND state='firing'`, agentID).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

// TestEvaluateAgentHostScope verifies a host (system-status) alert scoped to a
// group only fires for agents in that group, even though every agent reports its
// own host.* metrics. An out-of-group agent breaching the same threshold must not
// alert.
func TestEvaluateAgentHostScope(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	const siteID = "site_default"
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES(?, 'def', CURRENT_TIMESTAMP)`, siteID)
	for _, id := range []string{"agent_in", "agent_out"} {
		mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES(?,?,x'00','h','online')`, id, siteID)
	}

	reg := registry.New(db, 0)
	cfg := config.New(db, reg)

	// Group "servers" contains only agent_in.
	gid, err := reg.CreateGroup(ctx, siteID, "servers")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := reg.UpdateGroup(ctx, gid, "servers", []string{"agent_in"}); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}

	// A host target scoped to the "servers" group, with a CPU>90 rule.
	if err := cfg.SetSiteTargets(ctx, siteID, []config.ProbeTarget{
		{Kind: "host", Target: "host", Enabled: true, AllAgents: false, GroupIDs: []string{gid}},
	}); err != nil {
		t.Fatalf("SetSiteTargets: %v", err)
	}
	ptid, err := cfg.TargetIDByTarget(ctx, siteID, "host")
	if err != nil {
		t.Fatalf("TargetIDByTarget: %v", err)
	}

	svc := New(db, alert.New(db, nil), metrics.New(db))
	if _, err := svc.CreateForTarget(ctx, siteID, ptid, Rule{
		Name: "cpu", MetricKind: "host.cpu.pct", Comparator: "gt", Threshold: 90,
		FailThreshold: 1, Severity: "error", Layer: "local",
	}); err != nil {
		t.Fatalf("CreateForTarget: %v", err)
	}

	// Both agents report a breaching CPU sample "now".
	now := time.Now().Unix()
	seedSample(t, db, "agent_in", siteID, "host.cpu.pct", "host", 99, now)
	seedSample(t, db, "agent_out", siteID, "host.cpu.pct", "host", 99, now)

	if err := svc.EvaluateAgent(ctx, "agent_in", siteID); err != nil {
		t.Fatalf("EvaluateAgent(agent_in): %v", err)
	}
	if err := svc.EvaluateAgent(ctx, "agent_out", siteID); err != nil {
		t.Fatalf("EvaluateAgent(agent_out): %v", err)
	}

	if n := firingAlerts(t, db, "agent_in"); n != 1 {
		t.Errorf("agent_in (in group) firing alerts = %d, want 1", n)
	}
	if n := firingAlerts(t, db, "agent_out"); n != 0 {
		t.Errorf("agent_out (not in group) firing alerts = %d, want 0 (host alert must respect scope)", n)
	}
}

// TestResolveOutOfScopeOnGroupChange verifies the counterpart to the scope
// filter: an alert already firing for an agent must resolve once that agent
// leaves the target's scope, otherwise the filter would strand it firing forever.
func TestResolveOutOfScopeOnGroupChange(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	const siteID = "site_default"
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES(?, 'def', CURRENT_TIMESTAMP)`, siteID)
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_x',?,x'00','h','online')`, siteID)

	reg := registry.New(db, 0)
	cfg := config.New(db, reg)
	gid, err := reg.CreateGroup(ctx, siteID, "servers")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := reg.UpdateGroup(ctx, gid, "servers", []string{"agent_x"}); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if err := cfg.SetSiteTargets(ctx, siteID, []config.ProbeTarget{
		{Kind: "host", Target: "host", Enabled: true, AllAgents: false, GroupIDs: []string{gid}},
	}); err != nil {
		t.Fatalf("SetSiteTargets: %v", err)
	}
	ptid, err := cfg.TargetIDByTarget(ctx, siteID, "host")
	if err != nil {
		t.Fatalf("TargetIDByTarget: %v", err)
	}

	alertSvc := alert.New(db, nil)
	svc := New(db, alertSvc, metrics.New(db))
	if _, err := svc.CreateForTarget(ctx, siteID, ptid, Rule{
		Name: "cpu", MetricKind: "host.cpu.pct", Comparator: "gt", Threshold: 90,
		FailThreshold: 1, Severity: "error", Layer: "local",
	}); err != nil {
		t.Fatalf("CreateForTarget: %v", err)
	}

	// agent_x breaches while in scope → the alert fires.
	seedSample(t, db, "agent_x", siteID, "host.cpu.pct", "host", 99, time.Now().Unix())
	if err := svc.EvaluateAgent(ctx, "agent_x", siteID); err != nil {
		t.Fatalf("EvaluateAgent: %v", err)
	}
	if n := firingAlerts(t, db, "agent_x"); n != 1 {
		t.Fatalf("precondition: agent_x firing alerts = %d, want 1", n)
	}

	// agent_x leaves the group → the scope-change sweep must resolve the alert.
	if _, err := reg.UpdateGroup(ctx, gid, "servers", nil); err != nil {
		t.Fatalf("UpdateGroup (remove member): %v", err)
	}
	if err := alertSvc.ResolveOutOfScope(ctx, siteID); err != nil {
		t.Fatalf("ResolveOutOfScope: %v", err)
	}
	if n := firingAlerts(t, db, "agent_x"); n != 0 {
		t.Errorf("agent_x firing alerts after leaving scope = %d, want 0 (must not strand)", n)
	}
	var resolved int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE agent_id='agent_x' AND state='resolved'`).Scan(&resolved); err != nil {
		t.Fatalf("count resolved: %v", err)
	}
	if resolved != 1 {
		t.Errorf("resolved alerts = %d, want 1", resolved)
	}
}
