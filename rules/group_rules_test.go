package rules

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

func openRulesTest(t *testing.T) (*store.DB, context.Context, *config.Service, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
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
	reg := registry.New(db, 0)
	cfg := config.New(db, reg, nil, nil)
	groupID, err := cfg.CreateGroup(ctx, "site_default", "network", true, true, nil)
	if err != nil {
		t.Fatalf("create monitor group: %v", err)
	}
	return db, ctx, cfg, groupID
}

func seedMonitorSample(t *testing.T, db *store.DB, agentID, monitorID, kind, target string, value float64) {
	t.Helper()
	ctx := context.Background()
	res, err := db.ExecContext(ctx,
		`INSERT INTO series(agent_id,site_id,monitor_id,kind,target,layer,unit) VALUES(?,'site_default',?,?,?,'','')`,
		agentID, monitorID, kind, target)
	if err != nil {
		t.Fatalf("insert series: %v", err)
	}
	seriesID, _ := res.LastInsertId()
	if _, err := db.ExecContext(ctx, `INSERT INTO samples(series_id,ts,value) VALUES(?,?,?)`, seriesID, time.Now().Unix(), value); err != nil {
		t.Fatalf("insert sample: %v", err)
	}
}

func TestRuleEvaluationIsPerAgentAndSupportsAND(t *testing.T) {
	db, ctx, cfg, groupID := openRulesTest(t)
	if err := cfg.SetSiteTargets(ctx, "site_default", []config.ProbeTarget{
		{ID: "ping-a", GroupID: groupID, Kind: "icmp", Target: "1.1.1.1", Enabled: true},
		{ID: "ping-b", GroupID: groupID, Kind: "icmp", Target: "9.9.9.9", Enabled: true},
	}); err != nil {
		t.Fatalf("set targets: %v", err)
	}
	svc := New(db, metrics.New(db), nil, nil, nil, nil)
	if _, err := svc.Create(ctx, "site_default", groupID, GroupRule{
		Name: "both paths down", Op: "and", Severity: "error", Layer: "internet",
		Conditions: []RuleCondition{
			{TargetID: "ping-a", MetricKind: "probe.icmp.loss_pct", Comparator: "gt", Threshold: 50, FailThreshold: 1},
			{TargetID: "ping-b", MetricKind: "probe.icmp.loss_pct", Comparator: "gt", Threshold: 50, FailThreshold: 1},
		},
	}); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	seedMonitorSample(t, db, "agent_a", "ping-a", "probe.icmp.loss_pct", "1.1.1.1", 100)
	seedMonitorSample(t, db, "agent_a", "ping-b", "probe.icmp.loss_pct", "9.9.9.9", 100)
	seedMonitorSample(t, db, "agent_b", "ping-a", "probe.icmp.loss_pct", "1.1.1.1", 100)
	seedMonitorSample(t, db, "agent_b", "ping-b", "probe.icmp.loss_pct", "9.9.9.9", 0)

	if err := svc.EvaluateAgent(ctx, "agent_a", "site_default"); err != nil {
		t.Fatalf("evaluate agent_a: %v", err)
	}
	if err := svc.EvaluateAgent(ctx, "agent_b", "site_default"); err != nil {
		t.Fatalf("evaluate agent_b: %v", err)
	}
	for _, tc := range []struct {
		agent string
		want  int
	}{{"agent_a", 1}, {"agent_b", 0}} {
		var got int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE agent_id=? AND state='firing'`, tc.agent).Scan(&got); err != nil {
			t.Fatalf("count alerts: %v", err)
		}
		if got != tc.want {
			t.Fatalf("%s firing alerts = %d, want %d", tc.agent, got, tc.want)
		}
	}
}

func TestEvidenceAndNotificationRoutingAreFrozenAndCosmeticUpdatePreservesLifecycle(t *testing.T) {
	db, ctx, cfg, groupID := openRulesTest(t)
	if err := cfg.SetSiteTargets(ctx, "site_default", []config.ProbeTarget{{
		ID: "tcp", GroupID: groupID, Kind: "tcp", Target: "db.example.test", Enabled: true,
		Params: pcfg.ProbeParams{Port: 5432},
	}}); err != nil {
		t.Fatalf("set target: %v", err)
	}
	svc := New(db, metrics.New(db), nil, nil, nil, nil)
	ruleID, err := svc.Create(ctx, "site_default", groupID, GroupRule{
		Name: "database down", Op: "or", Severity: "critical", Layer: "service", ChannelIDs: []string{"channel-a"},
		Conditions: []RuleCondition{{TargetID: "tcp", MetricKind: "probe.tcp.ok", Comparator: "lt", Threshold: 1, FailThreshold: 1}},
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	seedMonitorSample(t, db, "agent_a", "tcp", "probe.tcp.ok", "db.example.test", 0)
	if err := svc.EvaluateAgent(ctx, "agent_a", "site_default"); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	var alertID, alertChannels, targetAddr string
	var targetPort int
	if err := db.QueryRowContext(ctx, `
		SELECT a.id, a.channel_ids, e.target_addr, e.target_port
		FROM alerts a JOIN alert_evidence e ON e.alert_id=a.id
		WHERE a.rule_id=? AND a.state='firing'`, ruleID).Scan(&alertID, &alertChannels, &targetAddr, &targetPort); err != nil {
		t.Fatalf("read frozen evidence: %v", err)
	}
	if targetAddr != "db.example.test" || targetPort != 5432 {
		t.Fatalf("frozen endpoint = %s:%d, want db.example.test:5432", targetAddr, targetPort)
	}
	var channels []string
	if err := json.Unmarshal([]byte(alertChannels), &channels); err != nil || len(channels) != 1 || channels[0] != "channel-a" {
		t.Fatalf("frozen channels = %q (%v)", alertChannels, err)
	}

	current, err := svc.GetRule(ctx, ruleID)
	if err != nil {
		t.Fatalf("get rule: %v", err)
	}
	current.Name = "renamed database rule"
	current.ChannelIDs = []string{"channel-b"}
	if err := svc.Update(ctx, current); err != nil {
		t.Fatalf("cosmetic update: %v", err)
	}
	var state, stillChannels string
	if err := db.QueryRowContext(ctx, `SELECT state, channel_ids FROM alerts WHERE id=?`, alertID).Scan(&state, &stillChannels); err != nil {
		t.Fatalf("read alert after cosmetic update: %v", err)
	}
	if state != "firing" || stillChannels != alertChannels {
		t.Fatalf("cosmetic update changed lifecycle/routing: state=%s channels=%s", state, stillChannels)
	}

	current.Conditions[0].Threshold = 0.5
	if err := svc.Update(ctx, current); err != nil {
		t.Fatalf("semantic update: %v", err)
	}
	var reason string
	if err := db.QueryRowContext(ctx, `SELECT state, resolve_reason FROM alerts WHERE id=?`, alertID).Scan(&state, &reason); err != nil {
		t.Fatalf("read alert after semantic update: %v", err)
	}
	if state != "resolved" || reason != "configuration_changed" {
		t.Fatalf("semantic update result = %s/%s, want resolved/configuration_changed", state, reason)
	}
}
