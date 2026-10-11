package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// routeTables are the tables 0004 creates; each must exist after both a fresh
// install and an upgrade.
var routeTables = []string{
	"asn_info", "route_ips", "route_paths", "route_epochs", "route_epoch_variants",
	"route_runs_detail", "route_monitor_state", "route_changes",
}

// TestRouteMonitorUpgradeFromPreviousRelease builds a database exactly as the
// previous release left it — the whole chain through the baseline repair,
// with an enrolled agent and a monitor — and opens it through the normal
// path: 0004 must add the capabilities column with the "declares nothing"
// default on the existing agent, create the route tables empty, and keep the
// existing rows intact.
func TestRouteMonitorUpgradeFromPreviousRelease(t *testing.T) {
	path := filepath.Join(testStoreDir(t), "upgrade.db")
	raw := openRaw(t, path)
	prev := &DB{DB: raw, path: path}
	if err := prev.migrateTo(repairBaselineVersion); err != nil {
		t.Fatalf("migrate to previous release: %v", err)
	}
	if columnSet(t, raw, "agents")["capabilities"] {
		t.Fatal("the previous-release shape already has agents.capabilities")
	}
	seedAgentAndMonitor(t, raw)
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	var host, caps string
	if err := db.QueryRow(`SELECT hostname, capabilities FROM agents WHERE id='agent_a'`).Scan(&host, &caps); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if host != "box-1" || caps != "[]" {
		t.Errorf("upgraded agent = hostname %q caps %q, want box-1 / []", host, caps)
	}
	for _, tbl := range routeTables {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n); err != nil {
			t.Errorf("%s: %v", tbl, err)
		} else if n != 0 {
			t.Errorf("%s has %d rows after upgrade", tbl, n)
		}
	}
	assertLedger(t, db.DB)
	assertRouteRowsCascade(t, db.DB)
	if v := integrityCheck(t, db.DB); v != "ok" {
		t.Errorf("integrity_check = %s", v)
	}
}

// TestRouteMonitorFreshInstall: a fresh database has the column and tables,
// and the foreign keys behave — deleting a monitor or an agent takes its
// route history with it, so neither delete path needs to know these tables.
func TestRouteMonitorFreshInstall(t *testing.T) {
	db, err := Open(filepath.Join(testStoreDir(t), "fresh.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	if !columnSet(t, db.DB, "agents")["capabilities"] {
		t.Fatal("agents has no capabilities column")
	}
	for _, tbl := range routeTables {
		if ok, err := tableExists(t.Context(), db.DB, tbl); err != nil || !ok {
			t.Errorf("table %s missing (%v)", tbl, err)
		}
	}
	seedAgentAndMonitor(t, db.DB)
	assertRouteRowsCascade(t, db.DB)
}

func seedAgentAndMonitor(t *testing.T, db *sql.DB) {
	t.Helper()
	now := time.Now().UTC()
	mustExec(t, db, `INSERT OR IGNORE INTO sites(id,name) VALUES('site_default','Default')`)
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,hostname,status) VALUES('agent_a','site_default',x'00','h','box-1','online')`)
	mustExec(t, db, `INSERT INTO monitor_groups(id,site_id,name,all_agents,created_at) VALUES('g1','site_default','G',1,?)`, now)
	mustExec(t, db, `INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m1','site_default','g1','trace','T','example.com','{}',1,1)`)
	mustExec(t, db, `INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m2','site_default','g1','trace','T2','example.org','{}',1,1)`)
}

// assertRouteRowsCascade writes one row into every route table and checks that
// deleting the monitor, then the agent, leaves nothing behind but the shared
// dictionaries (which retention reclaims by reference).
func assertRouteRowsCascade(t *testing.T, db *sql.DB) {
	t.Helper()
	now := time.Now().Unix()
	mustExec(t, db, `INSERT INTO asn_info(asn,name,country,updated_at) VALUES(4134,'X','CN',?)`, now)
	mustExec(t, db, `INSERT INTO route_ips(id,ip,first_seen,last_seen) VALUES(1,'8.8.8.8',?,?)`, now, now)
	mustExec(t, db, `INSERT INTO route_paths(id,hash,ip_path,as_path,first_seen) VALUES(1,x'01',x'0101',x'',?)`, now)
	for _, m := range []string{"m1", "m2"} {
		mustExec(t, db, `INSERT INTO route_epochs(agent_id,monitor_id,path_id,start_ts,end_ts) VALUES('agent_a',?,1,?,?)`, m, now, now)
		mustExec(t, db, `INSERT INTO route_epoch_variants(epoch_id,path_id,count,last_ts) VALUES(last_insert_rowid(),1,1,?)`, now)
		mustExec(t, db, `INSERT INTO route_runs_detail(agent_id,monitor_id,report_id,run_ts,path_id,hops) VALUES('agent_a',?,?,?,1,x'')`, m, "r-"+m, now)
		mustExec(t, db, `INSERT INTO route_monitor_state(agent_id,monitor_id,epoch_id) VALUES('agent_a',?,(SELECT MAX(id) FROM route_epochs))`, m)
		mustExec(t, db, `INSERT INTO route_changes(agent_id,monitor_id,from_epoch_id,to_epoch_id,kind,segment,confirmed_at,before_run_id)
			VALUES('agent_a',?,(SELECT MAX(id) FROM route_epochs),(SELECT MAX(id) FROM route_epochs),'route','unknown',?,(SELECT MAX(id) FROM route_runs_detail))`, m, now)
	}
	count := func(q string) int {
		var n int
		if err := db.QueryRow(q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	mustExec(t, db, `DELETE FROM probe_tasks WHERE id='m1'`)
	for _, tbl := range []string{"route_epochs", "route_runs_detail", "route_monitor_state", "route_changes"} {
		if n := count(`SELECT COUNT(*) FROM ` + tbl + ` WHERE monitor_id='m1'`); n != 0 {
			t.Errorf("%s kept %d rows of a deleted monitor", tbl, n)
		}
	}
	if n := count(`SELECT COUNT(*) FROM route_epoch_variants`); n != 1 {
		t.Errorf("variants = %d after deleting one of two monitors, want 1", n)
	}
	mustExec(t, db, `DELETE FROM probe_tasks WHERE id='m2'`)
	mustExec(t, db, `DELETE FROM agents WHERE id='agent_a'`)
	for _, tbl := range []string{"route_epochs", "route_epoch_variants", "route_runs_detail", "route_monitor_state", "route_changes"} {
		if n := count(`SELECT COUNT(*) FROM ` + tbl); n != 0 {
			t.Errorf("%s kept %d rows", tbl, n)
		}
	}
}
