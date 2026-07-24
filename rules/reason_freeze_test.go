package rules

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
)

// seedMonitorSampleAt seeds one sample like seedMonitorSample but at an explicit
// unix timestamp, so a test can put two sibling metrics in the SAME probe cycle
// (equal TS) or deliberately in different cycles.
func seedMonitorSampleAt(t *testing.T, db *store.DB, agentID, monitorID, kind, target string, value float64, ts int64) {
	t.Helper()
	ctx := context.Background()
	var serial int
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(config_serial,0) FROM probe_tasks WHERE id=?`, monitorID).Scan(&serial)
	res, err := db.ExecContext(ctx,
		`INSERT INTO series(agent_id,site_id,monitor_id,kind,target,layer,unit,config_serial) VALUES(?,'site_default',?,?,?,'','',?)`,
		agentID, monitorID, kind, target, serial)
	if err != nil {
		t.Fatalf("insert series: %v", err)
	}
	seriesID, _ := res.LastInsertId()
	if _, err := db.ExecContext(ctx, `INSERT INTO samples(series_id,ts,value) VALUES(?,?,?)`, seriesID, ts, value); err != nil {
		t.Fatalf("insert sample: %v", err)
	}
}

// TestFreezeReasonCode verifies that when an alert fires on a probe condition, the
// sibling probe.<kind>.error_class value produced in the SAME cycle (equal TS) is
// frozen onto the alert's evidence — and that a reason from a DIFFERENT cycle is
// rejected rather than misattributed to the condition value.
func TestFreezeReasonCode(t *testing.T) {
	cases := []struct {
		name       string
		reasonTSΔ  int64 // reason sample ts offset from the value sample
		wantReason int
	}{
		{"same cycle freezes the reason", 0, telemetry.ProbeReasonUnreachable},
		{"cross-cycle reason is rejected", -30, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx, cfg, groupID := openRulesTest(t)
			if err := cfg.SetSiteTargets(ctx, "site_default", []config.ProbeTarget{
				{ID: "cf", GroupID: groupID, Kind: "icmp", Name: "cf", Target: "1.1.1.1", Enabled: true},
			}); err != nil {
				t.Fatalf("set targets: %v", err)
			}
			svc := New(db, metrics.New(db), nil, nil, nil, nil)
			if _, err := svc.Create(ctx, "site_default", groupID, GroupRule{
				Name: "cf outage", Op: "or", Severity: "warn", Layer: "internet",
				Conditions: []RuleCondition{
					{TargetID: "cf", MetricKind: "probe.icmp.loss_pct", Comparator: "gte", Threshold: 100, FailThreshold: 1},
				},
			}); err != nil {
				t.Fatalf("create rule: %v", err)
			}

			ts := time.Now().Unix()
			seedMonitorSampleAt(t, db, "agent_a", "cf", "probe.icmp.loss_pct", "1.1.1.1", 100, ts)
			seedMonitorSampleAt(t, db, "agent_a", "cf", string(telemetry.ICMPErrorClass), "1.1.1.1",
				float64(telemetry.ProbeReasonUnreachable), ts+tc.reasonTSΔ)
			if err := svc.EvaluateAgent(ctx, "agent_a", "site_default"); err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			var reason int
			if err := db.QueryRowContext(ctx, `
				SELECT reason_code FROM alert_evidence
				WHERE metric_kind='probe.icmp.loss_pct' ORDER BY observed_at DESC LIMIT 1`).Scan(&reason); err != nil {
				t.Fatalf("read evidence reason: %v", err)
			}
			if reason != tc.wantReason {
				t.Fatalf("frozen reason_code = %d, want %d", reason, tc.wantReason)
			}
		})
	}
}
