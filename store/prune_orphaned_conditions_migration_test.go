package store

import (
	"database/sql"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// applyMigrationsBelow applies every migration with a version < stop, recording
// each in schema_migrations so a later Open() picks up exactly the remainder.
func applyMigrationsBelow(t *testing.T, raw *sql.DB, stop int) {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := strconv.Atoi(strings.SplitN(entry.Name(), "_", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		if version >= stop {
			continue
		}
		migs = append(migs, mig{version, entry.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	for _, m := range migs {
		body, err := migrationsFS.ReadFile("migrations/" + m.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", m.name, err)
		}
		if _, err := raw.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, m.version, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
}

// Migration 0021 repairs the alert conditions left behind by an in-place monitor
// kind change made before SetSiteTargets learned to drop them. It must prune
// exactly the conditions the target's CURRENT kind can never satisfy — and touch
// nothing else, since deleting a live condition would silently disarm an alarm.
func TestPruneOrphanedRuleConditionsMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prune.db")
	raw, err := sql.Open("sqlite", path+dsnPragmas)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	applyMigrationsBelow(t, raw, 21)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name) VALUES('site','Site')`)
	exec(`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('grp','site','G',1)`)
	// mon-yahoo was a DNS monitor, re-typed to HTTP; mon-ping is untouched.
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled)
	      VALUES('mon-yahoo','site','grp','http','Yahoo','https://www.yahoo.co.jp','{}',1)`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled)
	      VALUES('mon-gw','site','grp','gateway','GW','gateway','{}',1)`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled)
	      VALUES('mon-host','site','grp','host','Host','host','{}',1)`)
	mkRule := func(id, name string) {
		exec(`INSERT INTO group_rules(id,site_id,group_id,name,op,layer,severity,enabled)
		      VALUES(?,'site','grp',?,'or','service','warn',1)`, id, name)
	}
	mkCond := func(id, ruleID, targetID, metric string) {
		exec(`INSERT INTO group_rule_conditions(id,rule_id,target_id,metric_kind,comparator,threshold)
		      VALUES(?,?,?,?,'lt',1)`, id, ruleID, targetID, metric)
	}
	mkRule("rule-dead", "解析失败")
	mkCond("c-dead", "rule-dead", "mon-yahoo", "probe.dns.ok") // orphaned by the re-type
	mkRule("rule-mixed", "混合")
	mkCond("c-mixed-dead", "rule-mixed", "mon-yahoo", "probe.dns.resolve_ms") // orphaned
	mkCond("c-mixed-live", "rule-mixed", "mon-yahoo", "probe.http.ok")        // still valid
	mkRule("rule-gateway", "网关")
	mkCond("c-gateway", "rule-gateway", "mon-gw", "probe.icmp.loss_pct") // gateway rides ICMP
	mkRule("rule-host", "主机")
	mkCond("c-host-cpu", "rule-host", "mon-host", "host.cpu.pct")
	mkCond("c-host-wifi", "rule-host", "mon-host", "wifi.up")
	mkCond("c-host-iface", "rule-host", "mon-host", "iface.up")
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path) // applies 0021
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	survivors := map[string]bool{}
	rows, err := db.Query(`SELECT id FROM group_rule_conditions`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		survivors[id] = true
	}
	rows.Close()
	for _, id := range []string{"c-mixed-live", "c-gateway", "c-host-cpu", "c-host-wifi", "c-host-iface"} {
		if !survivors[id] {
			t.Errorf("live condition %s was pruned", id)
		}
	}
	for _, id := range []string{"c-dead", "c-mixed-dead"} {
		if survivors[id] {
			t.Errorf("orphaned condition %s survived", id)
		}
	}

	// rule-dead lost its only condition and goes with it; every other rule stays.
	rules := map[string]bool{}
	rrows, err := db.Query(`SELECT id FROM group_rules`)
	if err != nil {
		t.Fatal(err)
	}
	for rrows.Next() {
		var id string
		if err := rrows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		rules[id] = true
	}
	rrows.Close()
	if rules["rule-dead"] {
		t.Error("rule-dead has no conditions left but survived")
	}
	for _, id := range []string{"rule-mixed", "rule-gateway", "rule-host"} {
		if !rules[id] {
			t.Errorf("rule %s was deleted despite having live conditions", id)
		}
	}
}
