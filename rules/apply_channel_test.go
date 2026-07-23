package rules

import (
	"testing"

	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/metrics"
)

func TestAddChannelToAllRules(t *testing.T) {
	db, ctx, cfg, groupID := openRulesTest(t)
	if err := cfg.SetSiteTargets(ctx, "site_default", []config.ProbeTarget{
		{ID: "ping", GroupID: groupID, Kind: "icmp", Target: "1.1.1.1", Enabled: true},
	}); err != nil {
		t.Fatalf("set targets: %v", err)
	}
	svc := New(db, metrics.New(db), nil, nil, nil, nil)

	cond := []RuleCondition{{TargetID: "ping", MetricKind: "probe.icmp.loss_pct", Comparator: "gt", Threshold: 50, FailThreshold: 1}}
	withChan, err := svc.Create(ctx, "site_default", groupID, GroupRule{
		Name: "with channel", Op: "or", Severity: "warn", Layer: "internet", ChannelIDs: []string{"chan_a"}, Conditions: cond,
	})
	if err != nil {
		t.Fatalf("create rule 1: %v", err)
	}
	noChan, err := svc.Create(ctx, "site_default", groupID, GroupRule{
		Name: "no channel", Op: "or", Severity: "warn", Layer: "internet", Conditions: cond,
	})
	if err != nil {
		t.Fatalf("create rule 2: %v", err)
	}

	n, err := svc.AddChannelToAllRules(ctx, "chan_new")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if n != 2 {
		t.Fatalf("updated=%d want 2", n)
	}

	// The rule that already had a channel keeps it and gains the new one.
	r1, _ := svc.GetRule(ctx, withChan)
	if !containsString(r1.ChannelIDs, "chan_a") || !containsString(r1.ChannelIDs, "chan_new") {
		t.Fatalf("rule 1 channels=%v", r1.ChannelIDs)
	}
	// The rule that had none now routes only to the new channel.
	r2, _ := svc.GetRule(ctx, noChan)
	if len(r2.ChannelIDs) != 1 || r2.ChannelIDs[0] != "chan_new" {
		t.Fatalf("rule 2 channels=%v", r2.ChannelIDs)
	}

	// Idempotent: re-applying changes nothing.
	n, err = svc.AddChannelToAllRules(ctx, "chan_new")
	if err != nil {
		t.Fatalf("apply again: %v", err)
	}
	if n != 0 {
		t.Fatalf("second apply updated=%d want 0", n)
	}
}
