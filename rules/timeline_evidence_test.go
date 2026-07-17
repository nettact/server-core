package rules

import (
	"strings"
	"testing"

	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/metrics"
)

func TestAppendedEvidenceTimelineNamesOnlyTheNewTarget(t *testing.T) {
	db, ctx, cfg, groupID := openRulesTest(t)
	if err := cfg.SetSiteTargets(ctx, "site_default", []config.ProbeTarget{
		{ID: "cf", GroupID: groupID, Kind: "icmp", Name: "cf", Target: "1.1.1.1", Enabled: true},
		{ID: "google", GroupID: groupID, Kind: "icmp", Name: "google", Target: "8.8.8.8", Enabled: true},
	}); err != nil {
		t.Fatalf("set targets: %v", err)
	}
	svc := New(db, metrics.New(db), nil, nil, nil, nil)
	if _, err := svc.Create(ctx, "site_default", groupID, GroupRule{
		Name: "overseas outage", Op: "or", Severity: "warn", Layer: "internet",
		Conditions: []RuleCondition{
			{TargetID: "cf", MetricKind: "probe.icmp.loss_pct", Comparator: "gte", Threshold: 100, FailThreshold: 1},
			{TargetID: "google", MetricKind: "probe.icmp.loss_pct", Comparator: "gte", Threshold: 100, FailThreshold: 1},
		},
	}); err != nil {
		t.Fatalf("create rule: %v", err)
	}

	// First only 1.1.1.1 is unreachable, so it opens the alert and incident.
	seedMonitorSample(t, db, "agent_a", "cf", "probe.icmp.loss_pct", "1.1.1.1", 100)
	seedMonitorSample(t, db, "agent_a", "google", "probe.icmp.loss_pct", "8.8.8.8", 0)
	if err := svc.EvaluateAgent(ctx, "agent_a", "site_default"); err != nil {
		t.Fatalf("evaluate first fault: %v", err)
	}

	// Then 8.8.8.8 becomes unreachable while the same OR alert is still firing.
	var seriesID, lastTS int64
	if err := db.QueryRowContext(ctx, `
		SELECT s.id, MAX(p.ts) FROM series s JOIN samples p ON p.series_id=s.id
		WHERE s.agent_id='agent_a' AND s.monitor_id='google' AND s.kind='probe.icmp.loss_pct'`).Scan(&seriesID, &lastTS); err != nil {
		t.Fatalf("find google series: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO samples(series_id,ts,value) VALUES(?,?,100)`, seriesID, lastTS+1); err != nil {
		t.Fatalf("append google failure: %v", err)
	}
	svc = New(db, metrics.New(db), nil, nil, nil, nil)
	if err := svc.EvaluateAgent(ctx, "agent_a", "site_default"); err != nil {
		t.Fatalf("evaluate appended fault: %v", err)
	}

	var message string
	if err := db.QueryRowContext(ctx, `
		SELECT COALESCE(message,'') FROM incident_timeline
		WHERE kind='alert.evidence' ORDER BY ts DESC LIMIT 1`).Scan(&message); err != nil {
		t.Fatalf("read evidence timeline: %v", err)
	}
	if !strings.Contains(message, "8.8.8.8") || strings.Contains(message, "1.1.1.1") || strings.Contains(message, "共 2 项") {
		t.Fatalf("appended evidence timeline = %q, want only the new 8.8.8.8 fault", message)
	}
}
