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

func appendWiFiSample(t *testing.T, db *store.DB, agentID, kind, target string, value float64, ts int64) {
	t.Helper()
	var sid int64
	if err := db.QueryRowContext(context.Background(),
		`SELECT id FROM series WHERE agent_id=? AND monitor_id='' AND kind=? AND target=?`,
		agentID, kind, target).Scan(&sid); err != nil {
		t.Fatalf("find series (%s,%s,%s): %v", agentID, kind, target, err)
	}
	mustExec(t, db, `INSERT INTO samples(series_id, ts, value) VALUES(?,?,?)`, sid, ts, value)
}

func TestEvaluateAgentHostWiFiWildcard(t *testing.T) {
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
	cfg := config.New(db, reg, nil)
	gid, err := reg.CreateGroup(ctx, siteID, "wifi-agents")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := reg.UpdateGroup(ctx, gid, "wifi-agents", []string{"agent_in"}); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	const anchorID = "probe_wifi_host_anchor"
	if err := cfg.SetSiteTargets(ctx, siteID, []config.ProbeTarget{{
		ID: anchorID, Kind: "host", Target: "*", Enabled: true,
		AllAgents: false, GroupIDs: []string{gid},
	}}); err != nil {
		t.Fatalf("SetSiteTargets: %v", err)
	}

	alertSvc := alert.New(db, nil)
	ruleSvc := New(db, alertSvc, metrics.New(db))
	for _, rule := range []Rule{
		{Name: "wifi-down", MetricKind: "wifi.up", Comparator: "lt", Threshold: 1, FailThreshold: 1, Severity: "error", Layer: "wireless"},
		{Name: "wifi-signal", MetricKind: "wifi.signal_dbm", Comparator: "lt", Threshold: -70, FailThreshold: 1, Severity: "error", Layer: "wireless"},
		{Name: "wifi-quality", MetricKind: "wifi.quality_pct", Comparator: "lt", Threshold: 60, FailThreshold: 1, Severity: "error", Layer: "wireless"},
	} {
		if _, err := ruleSvc.CreateForTarget(ctx, siteID, anchorID, rule); err != nil {
			t.Fatalf("CreateForTarget(%s): %v", rule.Name, err)
		}
	}

	now := time.Now().Unix()
	// wlan0 breaches disconnect and quality; wlan1 breaches signal. Values equal
	// to the thresholds are healthy because every Wi-Fi preset uses strict lt.
	seedSample(t, db, "agent_in", siteID, "wifi.up", "wlan0", 0, now)
	seedSample(t, db, "agent_in", siteID, "wifi.up", "wlan1", 1, now)
	seedSample(t, db, "agent_in", siteID, "wifi.up", "wlan2", 1, now) // no signal/quality series: no synthetic zero
	seedSample(t, db, "agent_in", siteID, "wifi.signal_dbm", "wlan0", -70, now)
	seedSample(t, db, "agent_in", siteID, "wifi.signal_dbm", "wlan1", -71, now)
	seedSample(t, db, "agent_in", siteID, "wifi.quality_pct", "wlan0", 59, now)
	seedSample(t, db, "agent_in", siteID, "wifi.quality_pct", "wlan1", 60, now)
	seedSample(t, db, "agent_out", siteID, "wifi.signal_dbm", "wlan9", -100, now)

	if err := ruleSvc.EvaluateAgent(ctx, "agent_in", siteID); err != nil {
		t.Fatalf("EvaluateAgent(agent_in): %v", err)
	}
	if err := ruleSvc.EvaluateAgent(ctx, "agent_out", siteID); err != nil {
		t.Fatalf("EvaluateAgent(agent_out): %v", err)
	}

	rows, err := db.QueryContext(ctx, `
		SELECT r.name, a.target FROM alerts a JOIN alert_rules r ON r.id=a.rule_id
		WHERE a.agent_id='agent_in' AND a.state='firing' ORDER BY r.name, a.target`)
	if err != nil {
		t.Fatalf("query firing Wi-Fi alerts: %v", err)
	}
	var got []string
	for rows.Next() {
		var name, target string
		if err := rows.Scan(&name, &target); err != nil {
			rows.Close()
			t.Fatalf("scan firing Wi-Fi alert: %v", err)
		}
		got = append(got, name+":"+target)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close alert rows: %v", err)
	}
	want := []string{"wifi-down:wlan0", "wifi-quality:wlan0", "wifi-signal:wlan1"}
	if len(got) != len(want) {
		t.Fatalf("firing Wi-Fi alerts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("firing Wi-Fi alerts = %v, want %v", got, want)
		}
	}
	if n := firingAlerts(t, db, "agent_out"); n != 0 {
		t.Fatalf("out-of-scope agent firing alerts = %d, want 0", n)
	}

	// Insert healthy samples and rebuild the cache so each actual interface alert
	// follows the existing resolve path independently.
	recoveredAt := now + 1
	appendWiFiSample(t, db, "agent_in", "wifi.up", "wlan0", 1, recoveredAt)
	appendWiFiSample(t, db, "agent_in", "wifi.signal_dbm", "wlan1", -69, recoveredAt)
	appendWiFiSample(t, db, "agent_in", "wifi.quality_pct", "wlan0", 61, recoveredAt)
	ruleSvc = New(db, alertSvc, metrics.New(db))
	if err := ruleSvc.EvaluateAgent(ctx, "agent_in", siteID); err != nil {
		t.Fatalf("EvaluateAgent(recovered): %v", err)
	}
	if n := firingAlerts(t, db, "agent_in"); n != 0 {
		t.Errorf("firing alerts after recovery = %d, want 0", n)
	}
	var resolved int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE agent_id='agent_in' AND state='resolved'`).Scan(&resolved); err != nil {
		t.Fatalf("count resolved Wi-Fi alerts: %v", err)
	}
	if resolved != 3 {
		t.Errorf("resolved Wi-Fi alerts = %d, want 3", resolved)
	}
}
