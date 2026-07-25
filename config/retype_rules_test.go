package config

import (
	"context"
	"errors"
	"testing"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

// seedRule inserts a group rule with the given (target, metric) conditions
// directly, so the config package can test the re-type reconcile without
// depending on the rules service (which imports config).
func seedRule(t *testing.T, db *store.DB, ctx context.Context, ruleID, groupID, name string, conds [][2]string) {
	t.Helper()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO group_rules(id, site_id, group_id, name, op, layer, severity, enabled)
		 VALUES(?,?,?,?,'or','service','warn',1)`, ruleID, "site_default", groupID, name); err != nil {
		t.Fatalf("seed rule %s: %v", ruleID, err)
	}
	for i, c := range conds {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO group_rule_conditions(id, rule_id, target_id, metric_kind, comparator, threshold, position)
			 VALUES(?,?,?,?,'lt',1,?)`, ruleID+"-c"+string(rune('a'+i)), ruleID, c[0], c[1], i); err != nil {
			t.Fatalf("seed condition %s/%s: %v", ruleID, c[1], err)
		}
	}
}

func conditionMetrics(t *testing.T, db *store.DB, ctx context.Context, ruleID string) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx,
		`SELECT metric_kind FROM group_rule_conditions WHERE rule_id=? ORDER BY position`, ruleID)
	if err != nil {
		t.Fatalf("read conditions: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			t.Fatalf("scan condition: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// Re-typing a monitor in place (dns → http) must drop the alert conditions the
// new kind can never satisfy. Left in place they would watch a metric family that
// never arrives again, which the engine reads as "no sample this pass" and
// answers by preserving the stored verdict — so the monitor could fail forever
// without the rule ever firing.
func TestSetSiteTargetsDropsConditionsInvalidatedByKindChange(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	svc := New(db, registry.New(db, 0, nil), eventbus.New(), nil)
	groupID, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	yahoo := ProbeTarget{ID: "mon-yahoo", GroupID: groupID, Kind: "dns", Name: "域名解析（雅虎日本）", Target: "www.yahoo.co.jp", Enabled: true}
	ping := ProbeTarget{ID: "mon-ping", GroupID: groupID, Kind: "icmp", Name: "Ping", Target: "1.1.1.1", Enabled: true}
	if _, err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{yahoo, ping}); err != nil {
		t.Fatal(err)
	}
	// mixed: one condition on the re-typed target + one on an untouched target.
	seedRule(t, db, ctx, "rule-mixed", groupID, "混合规则", [][2]string{
		{"mon-yahoo", "probe.dns.ok"},
		{"mon-ping", "probe.icmp.loss_pct"},
	})
	// dns-only: every condition dies with the kind change, so the rule goes too.
	seedRule(t, db, ctx, "rule-dns", groupID, "解析失败", [][2]string{
		{"mon-yahoo", "probe.dns.ok"},
		{"mon-yahoo", "probe.dns.resolve_ms"},
	})

	yahoo.Kind = "http"
	yahoo.Target = "https://www.yahoo.co.jp"
	cleanups, err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{yahoo, ping})
	if err != nil {
		t.Fatal(err)
	}

	// The mixed rule survives, minus the dead DNS condition; the sibling condition
	// bound to an untouched target must NOT be collateral damage.
	if got := conditionMetrics(t, db, ctx, "rule-mixed"); len(got) != 1 || got[0] != "probe.icmp.loss_pct" {
		t.Fatalf("rule-mixed conditions = %v, want [probe.icmp.loss_pct]", got)
	}
	var mixedRules int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_rules WHERE id='rule-mixed'`).Scan(&mixedRules)
	if mixedRules != 1 {
		t.Fatalf("rule-mixed rows = %d, want 1 (rule still has a live condition)", mixedRules)
	}

	// The dns-only rule lost its last condition and is removed whole.
	var dnsRules int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_rules WHERE id='rule-dns'`).Scan(&dnsRules)
	if dnsRules != 0 {
		t.Fatalf("rule-dns rows = %d, want 0 (no conditions left)", dnsRules)
	}
	var orphanConds int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_rule_conditions WHERE metric_kind LIKE 'probe.dns.%'`).Scan(&orphanConds)
	if orphanConds != 0 {
		t.Fatalf("%d dns conditions survived the kind change", orphanConds)
	}

	// The report the console shows the user must name both rules and every metric.
	if len(cleanups) != 2 {
		t.Fatalf("cleanups = %+v, want one entry per affected rule", cleanups)
	}
	byRule := map[string]RuleCleanup{}
	for _, c := range cleanups {
		byRule[c.RuleID] = c
	}
	mixed, ok := byRule["rule-mixed"]
	if !ok {
		t.Fatalf("cleanups missing rule-mixed: %+v", cleanups)
	}
	if mixed.RuleDeleted || len(mixed.Metrics) != 1 || mixed.Metrics[0] != "probe.dns.ok" {
		t.Fatalf("rule-mixed cleanup = %+v", mixed)
	}
	if mixed.MonitorID != "mon-yahoo" || mixed.MonitorName != yahoo.Name || mixed.OldKind != "dns" || mixed.NewKind != "http" || mixed.RuleName != "混合规则" {
		t.Fatalf("rule-mixed cleanup identity = %+v", mixed)
	}
	dns, ok := byRule["rule-dns"]
	if !ok {
		t.Fatalf("cleanups missing rule-dns: %+v", cleanups)
	}
	if !dns.RuleDeleted || len(dns.Metrics) != 2 {
		t.Fatalf("rule-dns cleanup = %+v, want the whole rule reported as deleted with both metrics", dns)
	}
}

// A payload repeating one target id cannot be reconciled coherently: the last
// entry wins the upsert while the kind-change classification reads an earlier
// one, so a re-type-then-restore payload would keep the original kind yet still
// delete the conditions valid for it. The whole request must be rejected, with
// nothing written and no condition touched.
func TestSetSiteTargetsRejectsDuplicateTargetIDs(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	svc := New(db, registry.New(db, 0, nil), eventbus.New(), nil)
	groupID, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	dns := ProbeTarget{ID: "mon-dup", GroupID: groupID, Kind: "dns", Name: "Yahoo", Target: "www.yahoo.co.jp", Enabled: true}
	if _, err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{dns}); err != nil {
		t.Fatal(err)
	}
	seedRule(t, db, ctx, "rule-dns", groupID, "解析失败", [][2]string{{"mon-dup", "probe.dns.ok"}})

	retyped := dns
	retyped.Kind = "http"
	retyped.Target = "https://www.yahoo.co.jp"
	// Same id twice: re-typed first, original second (the one that would persist).
	_, err = svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{retyped, dns})
	if err == nil {
		t.Fatal("duplicate target id was accepted")
	}
	// A malformed payload, not a server fault — the API layer matches this sentinel
	// to answer 400 instead of inviting the client to retry a doomed request.
	if !errors.Is(err, ErrDuplicateTargetID) {
		t.Fatalf("error = %v, want it to wrap ErrDuplicateTargetID", err)
	}
	var kind string
	if err := db.QueryRowContext(ctx, `SELECT kind FROM probe_tasks WHERE id='mon-dup'`).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "dns" {
		t.Fatalf("stored kind = %q, want the rejected request to have changed nothing", kind)
	}
	if got := conditionMetrics(t, db, ctx, "rule-dns"); len(got) != 1 || got[0] != "probe.dns.ok" {
		t.Fatalf("rule-dns conditions = %v, want the still-valid [probe.dns.ok]", got)
	}
}

// A save that does not re-type anything must not touch rules — and must report no
// cleanup, so the console never nags about alarms that are still live.
func TestSetSiteTargetsKeepsConditionsWhenKindIsUnchanged(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	svc := New(db, registry.New(db, 0, nil), eventbus.New(), nil)
	groupID, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	site := ProbeTarget{ID: "mon-site", GroupID: groupID, Kind: "http", Name: "Site", Target: "https://a.test", Enabled: true}
	if _, err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{site}); err != nil {
		t.Fatal(err)
	}
	seedRule(t, db, ctx, "rule-http", groupID, "站点不可用", [][2]string{{"mon-site", "probe.http.ok"}})

	// A material edit that keeps the kind (new URL) — conditions stay live.
	site.Target = "https://b.test"
	cleanups, err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{site})
	if err != nil {
		t.Fatal(err)
	}
	if len(cleanups) != 0 {
		t.Fatalf("cleanups = %+v, want none", cleanups)
	}
	if got := conditionMetrics(t, db, ctx, "rule-http"); len(got) != 1 || got[0] != "probe.http.ok" {
		t.Fatalf("rule-http conditions = %v, want [probe.http.ok]", got)
	}
}
