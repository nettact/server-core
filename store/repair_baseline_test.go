package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// releasedBaselines are the texts of 0001_init.sql that releases shipped before
// the current one, oldest first, named by the first 12 hex digits of their
// sha256. Each is a schema some installation in the field may have recorded as
// "version 1". The current text is not listed: it is the embedded file itself.
var releasedBaselines = []string{
	"0625decd665c",
	"42303dc7d58b",
	"a3da0975f7ae",
	"58a399eccac5",
	"b0afc93e23a7",
	"8a86e838218b",
	"92440a7a8015",
}

// legacyLeftovers are the tables earlier baselines created that today's does
// not. The repair leaves them (and their indexes) in place; every other object
// of an upgraded database must match a fresh install.
var legacyLeftovers = map[string]bool{
	"agent_packets": true, "samples": true, "rollup_1m": true, "rollup_1h": true, "rollup_1d": true,
	"incident_snapshot_entries": true,
}

func readReleasedBaseline(t *testing.T, id string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "released_0001", id+".sql"))
	if err != nil {
		t.Fatalf("read fixture %s: %v", id, err)
	}
	return string(body)
}

// The fixtures are only evidence if they are byte-for-byte what shipped: a
// fixture "tidied" by an editor would test a schema nobody has.
func TestReleasedBaselineFixturesAreTheShippedTexts(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "released_0001"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, e := range entries {
		onDisk = append(onDisk, strings.TrimSuffix(e.Name(), ".sql"))
	}
	want := append([]string(nil), releasedBaselines...)
	sort.Strings(want)
	sort.Strings(onDisk)
	if strings.Join(onDisk, ",") != strings.Join(want, ",") {
		t.Fatalf("fixtures on disk = %v, want %v", onDisk, want)
	}
	for _, id := range releasedBaselines {
		sum := sha256.Sum256([]byte(readReleasedBaseline(t, id)))
		if got := hex.EncodeToString(sum[:])[:12]; got != id {
			t.Errorf("fixture %s hashes to %s", id, got)
		}
	}
	cur, err := migrationsFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cur)
	if got := hex.EncodeToString(sum[:])[:12]; got != "6ca396f3ac17" {
		t.Errorf("0001_init.sql hashes to %s: a shipped migration was edited again — add a new step instead", got)
	}
}

// buildReleasedDatabase reproduces an installation of an earlier release: that
// release's 0001 text applied by hand, with a pre-name-column ledger recording
// version 1, and rows written the way that release wrote them. When
// withSchema8 is set it also applies 0002 and records it — what any later
// release that carried 0002 (but not the repair) did on its next start.
func buildReleasedDatabase(t *testing.T, path, baseline string, withSchema8 bool) {
	t.Helper()
	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	mustExec(t, raw, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`)
	mustExec(t, raw, baseline)
	mustExec(t, raw, `INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC())
	if withSchema8 {
		body, err := migrationsFS.ReadFile("migrations/0002_schema8_epoch.sql")
		if err != nil {
			t.Fatal(err)
		}
		mustExec(t, raw, string(body))
		mustExec(t, raw, `INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?)`, time.Now().UTC())
	}
	seedReleasedRows(t, raw)
}

var seedTime = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

// seedReleasedRows writes one row into each table the repair rebuilds, using
// only the columns the database at hand has (insertRow filters), so the same
// seed is valid against every released shape.
func seedReleasedRows(t *testing.T, db *sql.DB) {
	t.Helper()
	insertRow(t, db, "sites", map[string]any{"id": "site_default", "name": "Home"})
	insertRow(t, db, "agents", map[string]any{
		"id": "agent_a", "site_id": "site_default", "public_key": []byte{0}, "token_hash": "h",
		"hostname": "box-1", "status": "online", "reported_config_version": 7,
	})
	insertRow(t, db, "enrollment_tokens", map[string]any{
		"token_hash": "tok_1", "site_id": "site_default", "note": "kitchen", "expires_at": seedTime,
	})
	// Three series, the newest deleted: the AUTOINCREMENT high-water mark (3)
	// is above the largest surviving id (2), which is exactly what a rebuild
	// that forgot sqlite_sequence would lose.
	for _, kind := range []string{"icmp.rtt", "icmp.loss", "dns.rtt"} {
		insertRow(t, db, "series", map[string]any{"agent_id": "agent_a", "site_id": "site_default", "kind": kind})
	}
	mustExec(t, db, `DELETE FROM series WHERE kind='dns.rtt'`)
	insertRow(t, db, "incidents", map[string]any{
		"id": "inc_1", "site_id": "site_default", "group_id": "g", "group_name": "G",
		"open_key": "sig:sig_1", "state": "open", "opened_at": seedTime,
	})
	insertRow(t, db, "incident_snapshots", map[string]any{
		"id": "snap_1", "incident_id": "inc_1", "base": `{"kept":true}`, "created_at": seedTime,
		"status": "complete", "deadline_at": seedTime,
	})
	insertRow(t, db, "fault_signals", map[string]any{
		"id": "sig_1", "agent_id": "agent_a", "site_id": "site_default", "target_id": "probe_x",
		"detector_key": "availability", "group_id": "g", "group_name": "G", "incident_id": "inc_1",
		"state": "firing", "observed_at": seedTime, "confirmed_at": seedTime,
	})
	tr := map[string]any{
		"id": "tr_1", "site_id": "site_default", "agent_id": "agent_a", "dest_key": "ip:192.0.2.1",
		"dest_host": "192.0.2.1", "mode": "icmp", "max_hops": 30, "attempts": 3,
		"timeout_ms": 1000, "requested_at": seedTime, "deadline_at": seedTime.Add(time.Minute),
		"started_at": seedTime.Add(time.Second), "received_at": seedTime,
	}
	if columnSet(t, db, "trace_reports")["cohort_open"] {
		tr["status"] = "running" // the removed command lifecycle's in-flight state
	} else {
		tr["status"] = "succeeded"
	}
	insertRow(t, db, "trace_reports", tr)
}

func insertRow(t *testing.T, db *sql.DB, table string, values map[string]any) {
	t.Helper()
	have := columnSet(t, db, table)
	var cols, marks []string
	var args []any
	for c, v := range values {
		if !have[c] {
			continue
		}
		cols = append(cols, c)
		marks = append(marks, "?")
		args = append(args, v)
	}
	mustExec(t, db, fmt.Sprintf(`INSERT INTO %s(%s) VALUES(%s)`, table, strings.Join(cols, ","), strings.Join(marks, ",")), args...)
}

func columnSet(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	cols, err := tableColumns(context.Background(), db, table)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, c := range cols {
		out[c.name] = true
	}
	return out
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", firstLine(q), err)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// currentWrites are statements the current code issues against tables that
// drifted, verbatim in shape (incidentops scene ingest, incidentops snapshot
// freeze, the fault engine's signal insert, status-page creation). Each is what
// broke, silently or loudly, on an unrepaired database.
var currentWrites = []struct {
	name string
	sql  string
	args []any
}{
	{"scene report", `INSERT OR IGNORE INTO scene_reports(id, site_id, agent_id, agent_name,
		collected_at, received_at, delivery_lag_ms, clock_ahead, payload, truncated)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		[]any{"scene_1", "site_default", "agent_a", "box-1", seedTime, seedTime, 0, 0, "{}", 0}},
	// INSERT OR IGNORE also ignores NOT NULL violations, so on the old shape
	// (deadline_at NOT NULL, no default) this "succeeds" and stores nothing.
	{"incident snapshot", `INSERT OR IGNORE INTO incident_snapshots(id, incident_id, base, truncated, created_at)
		VALUES(?,?,?,?,?)`,
		[]any{"snap_2", "inc_2", "{}", 0, seedTime}},
	{"fault signal", `INSERT INTO fault_signals(id, site_id, agent_id, target_id, detector_key, probe_kind,
		group_id, group_name, target_name, target_addr, target_port, agent_name, layer, severity,
		state, fail_threshold, recover_threshold, metric_kind, comparator, value, threshold,
		reason_code, reason_detail, baseline_p50, baseline_p95,
		resolver_addr, resolver_protocol, stun_addr, stun_transport,
		proxy_id, proxy_type, proxy_addr, proxy_config_serial, target_config_serial,
		rounds_json, size_sweep_json, flow_fanout_json, observed_at, confirmed_at, incident_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'firing', ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		[]any{"sig_2", "site_default", "agent_a", "probe_y", "availability", "icmp",
			"g", "G", "", "", 0, "", "", "",
			3, 2, "", "", 0.0, 0.0, 0, "", 0.0, 0.0,
			"", "", "", "", "", "", "", 0, 1,
			"[]", nil, nil, seedTime, seedTime, "inc_2"}},
	{"status page", `INSERT INTO status_pages(id, site_id, slug, title, description, enabled,
		show_target_address, show_agent_view, show_target_view,
		show_incidents, agent_metrics, is_home, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		[]any{"sp_1", "site_default", "home", "Home", "", 1, 0, 1, 1, 1, "", 0, seedTime, seedTime}},
}

// runCurrentWrites issues currentWrites in one transaction and reports the
// first failure, plus whether each write actually stored its row.
func runCurrentWrites(t *testing.T, db *sql.DB) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES('inc_2','site_default','g','G','sig:sig_2','open',?)`, seedTime); err != nil {
		return fmt.Errorf("seed incident: %w", err)
	}
	for _, w := range currentWrites {
		res, err := tx.Exec(w.sql, w.args...)
		if err != nil {
			return fmt.Errorf("%s: %w", w.name, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("%s: stored %d rows, want 1", w.name, n)
		}
	}
	return tx.Commit()
}

// The regression. For every 0001 text a release shipped, a database created by
// that release and then opened by this build must end up with exactly the
// schema a fresh install has, keep its rows, and accept the writes the current
// code issues — which the same database, upgraded the way builds without the
// repair upgraded it, rejected.
func TestUpgradeFromEveryReleasedBaselineMatchesAFreshInstall(t *testing.T) {
	fresh := openFreshForCompare(t)
	want := schemaFingerprint(t, fresh.DB)

	for _, id := range releasedBaselines {
		for _, withSchema8 := range []bool{false, true} {
			name := id + "/ledger-v1"
			if withSchema8 {
				name = id + "/ledger-v1-v2"
			}
			t.Run(name, func(t *testing.T) {
				dir := testStoreDir(t)
				path := filepath.Join(dir, "released.db")
				buildReleasedDatabase(t, path, readReleasedBaseline(t, id), withSchema8)

				// Before: the shape an unrepaired upgrade leaves behind.
				if !withSchema8 {
					// 0002 as builds before the repair applied it.
					applyAsBeforeRepair(t, path)
				}
				before := openRaw(t, path)
				oldTraceShape := columnSet(t, before, "trace_reports")["cohort_open"]
				if err := runCurrentWrites(t, before); err == nil {
					t.Error("the current writes succeeded on the unrepaired database; the fixture no longer reproduces the drift")
				}
				if schemaFingerprint(t, before) == want {
					t.Error("the unrepaired database already matches a fresh install")
				}
				before.Close()

				db, err := Open(path)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				defer db.Close()

				if got := schemaFingerprint(t, db.DB); got != want {
					t.Errorf("schema after repair differs from a fresh install:\n%s", diffLines(want, got))
				}
				assertLeftoversOnly(t, db.DB)
				assertSeedSurvived(t, db.DB, oldTraceShape)
				assertLedger(t, db.DB)
				if err := runCurrentWrites(t, db.DB); err != nil {
					t.Errorf("current writes after repair: %v", err)
				}
				if v := integrityCheck(t, db.DB); v != "ok" {
					t.Errorf("integrity_check = %s", v)
				}
			})
		}
	}
}

// applyAsBeforeRepair runs the migrator the way builds without the repair did:
// 0002 on top of whatever version 1 left, recorded by number only.
func applyAsBeforeRepair(t *testing.T, path string) {
	t.Helper()
	raw := openRaw(t, path)
	defer raw.Close()
	body, err := migrationsFS.ReadFile("migrations/0002_schema8_epoch.sql")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, raw, string(body))
	mustExec(t, raw, `INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?)`, time.Now().UTC())
}

func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	return raw
}

func openFreshForCompare(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(testStoreDir(t), "fresh.db"))
	if err != nil {
		t.Fatalf("Open fresh: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func assertSeedSurvived(t *testing.T, db *sql.DB, oldTraceShape bool) {
	t.Helper()
	var hostname string
	var epoch int
	if err := db.QueryRow(`SELECT hostname, enrollment_epoch FROM agents WHERE id='agent_a'`).Scan(&hostname, &epoch); err != nil {
		t.Fatalf("agent: %v", err)
	}
	if hostname != "box-1" || epoch != 1 {
		t.Errorf("agent = %q epoch %d, want box-1 epoch 1", hostname, epoch)
	}
	var note string
	var revoked int
	var agentID sql.NullString
	if err := db.QueryRow(`SELECT note, revoked, agent_id FROM enrollment_tokens WHERE token_hash='tok_1'`).Scan(&note, &revoked, &agentID); err != nil {
		t.Fatalf("enrollment token: %v", err)
	}
	if note != "kitchen" || revoked != 0 || agentID.Valid {
		t.Errorf("enrollment token = %q/%d/%v", note, revoked, agentID)
	}

	// Series keep their ids, and a deleted id is still never reused.
	var ids []int64
	rows, err := db.Query(`SELECT id FROM series ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if fmt.Sprint(ids) != "[1 2]" {
		t.Errorf("series ids = %v, want [1 2]", ids)
	}
	res, err := db.Exec(`INSERT INTO series(agent_id, site_id, kind) VALUES('agent_a','site_default','tcp.rtt')`)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := res.LastInsertId(); id != 4 {
		t.Errorf("next series id = %d, want 4 (the deleted 3 must never be reused)", id)
	}

	var base string
	var truncated int
	if err := db.QueryRow(`SELECT base, truncated FROM incident_snapshots WHERE id='snap_1'`).Scan(&base, &truncated); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if base != `{"kept":true}` {
		t.Errorf("snapshot base = %q", base)
	}
	var sigState, sigTarget string
	var serial int
	if err := db.QueryRow(`SELECT state, target_id, target_config_serial FROM fault_signals WHERE id='sig_1'`).Scan(&sigState, &sigTarget, &serial); err != nil {
		t.Fatalf("fault signal: %v", err)
	}
	if sigState != "firing" || sigTarget != "probe_x" || serial != 0 {
		t.Errorf("fault signal = %s/%s/%d", sigState, sigTarget, serial)
	}

	// An old-shape trace was in flight under the removed command lifecycle: it
	// becomes canceled, and its receive time is the closest the old row has
	// (it never completed, so when it started). A current-shape row is copied.
	var status string
	var received time.Time
	if err := db.QueryRow(`SELECT status, received_at FROM trace_reports WHERE id='tr_1'`).Scan(&status, &received); err != nil {
		t.Fatalf("trace report: %v", err)
	}
	wantStatus, wantReceived := "succeeded", seedTime
	if oldTraceShape {
		wantStatus, wantReceived = "canceled", seedTime.Add(time.Second)
	}
	if status != wantStatus || !received.Equal(wantReceived) {
		t.Errorf("trace = %s received %v, want %s received %v", status, received, wantStatus, wantReceived)
	}
}

func assertLedger(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var v int
		var n string
		rows.Scan(&v, &n)
		got = append(got, fmt.Sprintf("%d=%s", v, n))
	}
	want := "1=0001_init.sql 2=0002_schema8_epoch.sql 3=" + repairBaselineName + " 4=0004_route_monitor.sql"
	if strings.Join(got, " ") != want {
		t.Errorf("ledger = %v, want %s", got, want)
	}
}

// assertLeftoversOnly: whatever an upgraded database has beyond a fresh
// install's objects must be a known leftover table or an index on one.
func assertLeftoversOnly(t *testing.T, db *sql.DB) {
	t.Helper()
	ref, err := fullChainSchema(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, o := range ref {
		known[o.name] = true
	}
	live, err := readSchema(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range live {
		if !known[o.name] && !legacyLeftovers[o.tbl] {
			t.Errorf("unexpected object %s %s on %s", o.typ, o.name, o.tbl)
		}
	}
}

// schemaFingerprint renders every object a fresh install defines — normalized
// DDL plus what SQLite itself reports for it (columns with type, nullability,
// default and key position; foreign keys; every index including the automatic
// ones, with its columns, uniqueness and origin) — one line per fact, sorted.
// Objects a fresh install does not have are ignored here and policed by
// assertLeftoversOnly.
func schemaFingerprint(t *testing.T, db *sql.DB) string {
	t.Helper()
	ctx := context.Background()
	ref, err := fullChainSchema(ctx)
	if err != nil {
		t.Fatal(err)
	}
	live, err := readSchema(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	liveBy := map[string]schemaObject{}
	for _, o := range live {
		liveBy[o.name] = o
	}
	var lines []string
	add := func(format string, a ...any) { lines = append(lines, fmt.Sprintf(format, a...)) }
	for _, o := range ref {
		cur, ok := liveBy[o.name]
		if !ok {
			add("%s %s MISSING", o.typ, o.name)
			continue
		}
		add("%s %s on %s: %s", cur.typ, cur.name, cur.tbl, normalizeDDL(cur.sql))
		if o.typ != "table" {
			continue
		}
		q := func(query string) {
			rows, err := db.Query(query, o.name)
			if err != nil {
				t.Fatalf("%s(%s): %v", query, o.name, err)
			}
			defer rows.Close()
			cols, _ := rows.Columns()
			for rows.Next() {
				vals := make([]any, len(cols))
				ptrs := make([]any, len(cols))
				for i := range vals {
					ptrs[i] = &vals[i]
				}
				rows.Scan(ptrs...)
				add("%s %s: %v", firstWord(query), o.name, vals)
			}
		}
		q(`SELECT 'col', cid, name, type, "notnull", dflt_value, pk, hidden FROM pragma_table_xinfo(?)`)
		q(`SELECT 'fk', id, seq, "table", "from", "to", on_update, on_delete, match FROM pragma_foreign_key_list(?)`)
		q(`SELECT 'idx', l.name, l."unique", l.origin, l.partial, i.seqno, i.name FROM pragma_index_list(?) l, pragma_index_info(l.name) i`)
		q(`SELECT 'tbl', type, ncol, wr, strict FROM pragma_table_list WHERE schema='main' AND name=?`)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func firstWord(q string) string {
	q = strings.TrimPrefix(q, "SELECT '")
	return q[:strings.IndexByte(q, '\'')]
}

func diffLines(want, got string) string {
	w := map[string]bool{}
	for _, l := range strings.Split(want, "\n") {
		w[l] = true
	}
	g := map[string]bool{}
	for _, l := range strings.Split(got, "\n") {
		g[l] = true
	}
	var b strings.Builder
	for _, l := range strings.Split(want, "\n") {
		if !g[l] {
			b.WriteString("- " + l + "\n")
		}
	}
	for _, l := range strings.Split(got, "\n") {
		if !w[l] {
			b.WriteString("+ " + l + "\n")
		}
	}
	return b.String()
}

func integrityCheck(t *testing.T, db *sql.DB) string {
	t.Helper()
	var v string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// rawSchemaDump is sqlite_master verbatim, in storage order — the strictest
// possible "nothing changed".
func rawSchemaDump(t *testing.T, db queryer) string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT type, name, tbl_name, COALESCE(sql,'') FROM sqlite_master ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var a, n, tb, s string
		rows.Scan(&a, &n, &tb, &s)
		fmt.Fprintf(&b, "%s|%s|%s|%s\n", a, n, tb, s)
	}
	return b.String()
}

// The repair must be a strict no-op on a database already in today's shape —
// it runs once on every installation, fresh ones included — and running it a
// second time over a repaired database must change nothing either.
func TestRepairIsANoOpOnTheCurrentShapeAndIdempotent(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(t *testing.T) string{
		"fresh install": func(t *testing.T) string {
			return filepath.Join(testStoreDir(t), "fresh.db")
		},
		"repaired 0625decd665c": func(t *testing.T) string {
			path := filepath.Join(testStoreDir(t), "old.db")
			buildReleasedDatabase(t, path, readReleasedBaseline(t, "0625decd665c"), false)
			return path
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			path := mk(t)
			// The repair only ever runs against the database as it stands
			// before the later steps (it is step 3; 0004 onward come after), so
			// that is the shape it must leave untouched.
			raw := openRaw(t, path)
			db := &DB{DB: raw, path: path}
			if err := db.migrateTo(repairBaselineVersion); err != nil {
				t.Fatalf("migrate to the repair: %v", err)
			}
			before := rawSchemaDump(t, db.DB)
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := repairBaselineDrift(ctx, tx); err != nil {
				tx.Rollback()
				t.Fatalf("repair again: %v", err)
			}
			if after := rawSchemaDump(t, tx); after != before {
				t.Errorf("running the repair again changed the schema:\n%s", diffLines(before, after))
			}
			tx.Rollback()
			db.Close()

			// The normal open path then runs only the later steps, and a
			// second open re-runs nothing and changes nothing.
			db1, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			full := rawSchemaDump(t, db1.DB)
			db1.Close()
			db2, err := Open(path)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer db2.Close()
			if after := rawSchemaDump(t, db2.DB); after != full {
				t.Errorf("reopen changed the schema:\n%s", diffLines(full, after))
			}
			assertLedger(t, db2.DB)
		})
	}
}

// A fresh install runs the whole chain, records each step by name, and its
// schema is exactly the reference the repair derives — so the repair's view of
// "current" and the files' cannot drift apart.
func TestFreshInstallRecordsNamedStepsAndMatchesTheReference(t *testing.T) {
	db := openFreshForCompare(t)
	assertLedger(t, db.DB)
	ref, err := fullChainSchema(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	live, err := readSchema(context.Background(), db.DB)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != len(ref) {
		t.Fatalf("fresh install has %d objects, reference %d", len(live), len(ref))
	}
	for i := range ref {
		if live[i] != ref[i] {
			t.Errorf("object %d: fresh %s %s, reference %s %s", i, live[i].typ, live[i].name, ref[i].typ, ref[i].name)
		}
	}
}

// buildPreBaselineDatabase reproduces a database of the migration history that
// preceded the release baseline: its own 0001 (with the rule-engine alerting
// tables) and a ledger that recorded its whole chain by number.
func buildPreBaselineDatabase(t *testing.T, path string, recorded int) {
	t.Helper()
	raw := openRaw(t, path)
	defer raw.Close()
	body, err := os.ReadFile(filepath.Join("testdata", "pre_baseline_0001.sql"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, raw, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`)
	mustExec(t, raw, string(body))
	for v := 1; v <= recorded; v++ {
		mustExec(t, raw, `INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, v, time.Now().UTC())
	}
}

// A database from the older history must be refused, loudly and without being
// touched: its version numbers collide with this chain's, so treating it as
// current would skip steps it never ran.
func TestPreBaselineDatabaseIsRefusedUntouched(t *testing.T) {
	for _, recorded := range []int{1, 21, 23} {
		t.Run(fmt.Sprintf("versions-1-to-%d", recorded), func(t *testing.T) {
			path := filepath.Join(testStoreDir(t), "old-history.db")
			buildPreBaselineDatabase(t, path, recorded)
			raw := openRaw(t, path)
			before := rawSchemaDump(t, raw)
			raw.Close()

			db, err := Open(path)
			if err == nil {
				db.Close()
				t.Fatal("Open accepted a database from the older migration history")
			}
			if !errors.Is(err, ErrPreBaselineDatabase) {
				t.Fatalf("Open error = %v, want ErrPreBaselineDatabase", err)
			}
			if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "move it aside") {
				t.Errorf("error does not say which file or what to do: %v", err)
			}

			raw = openRaw(t, path)
			defer raw.Close()
			if after := rawSchemaDump(t, raw); after != before {
				t.Errorf("the refused database was modified:\n%s", diffLines(before, after))
			}
			var n int
			raw.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n)
			if n != recorded {
				t.Errorf("ledger has %d rows, want the untouched %d", n, recorded)
			}
		})
	}
}

// A version 2 recorded by number whose own mark (packet_receipts) is absent is
// not this history's version 2, whatever else the database contains.
func TestLegacyLedgerWithAForeignVersion2IsRefused(t *testing.T) {
	path := filepath.Join(testStoreDir(t), "foreign-v2.db")
	buildReleasedDatabase(t, path, readReleasedBaseline(t, "92440a7a8015"), false)
	raw := openRaw(t, path)
	mustExec(t, raw, `INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?)`, time.Now().UTC())
	raw.Close()
	if db, err := Open(path); !errors.Is(err, ErrPreBaselineDatabase) {
		if db != nil {
			db.Close()
		}
		t.Fatalf("Open error = %v, want ErrPreBaselineDatabase", err)
	}
}

// Once the ledger is named, a recorded name that disagrees with this build's
// step of the same number is the same collision and is refused; a step this
// build does not know (a newer build's, after a rollback) and an unnamed row
// written by a build older than the name column are both accepted.
func TestNamedLedgerChecksNamesButToleratesNewerAndUnnamedRows(t *testing.T) {
	path := filepath.Join(testStoreDir(t), "named.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.DB, `INSERT INTO schema_migrations(version, applied_at, name) VALUES(99, ?, '0099_from_a_newer_build')`, time.Now().UTC())
	mustExec(t, db.DB, `UPDATE schema_migrations SET name='' WHERE version=2`)
	db.Close()

	db, err = Open(path)
	if err != nil {
		t.Fatalf("Open with a newer step and an unnamed row: %v", err)
	}
	mustExec(t, db.DB, `UPDATE schema_migrations SET name='0002_some_other_history.sql' WHERE version=2`)
	db.Close()

	if db, err := Open(path); !errors.Is(err, ErrPreBaselineDatabase) {
		if db != nil {
			db.Close()
		}
		t.Fatalf("Open error = %v, want ErrPreBaselineDatabase for a mismatched name", err)
	}
}

func TestLoadMigrationsMergesGoStepsWithoutCollisions(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i, m := range migs {
		if m.version != i+1 {
			t.Errorf("migration %d has version %d: the chain must be contiguous", i, m.version)
		}
		got = append(got, m.name)
	}
	if want := "0001_init.sql 0002_schema8_epoch.sql " + repairBaselineName + " 0004_route_monitor.sql"; strings.Join(got, " ") != want {
		t.Errorf("chain = %v, want %s", got, want)
	}
}

func TestNormalizeDDL(t *testing.T) {
	cases := []struct{ a, b string }{
		{"CREATE TABLE t(\n  a INTEGER, -- note\n  b TEXT /* x */ NOT NULL\n)", "CREATE TABLE t(a INTEGER,b TEXT NOT NULL)"},
		{"CREATE TABLE t ( a TEXT DEFAULT '--not a comment' )", "CREATE TABLE t(a TEXT DEFAULT '--not a comment')"},
		{`CREATE TABLE "t"(a TEXT DEFAULT 'it''s  two')`, `CREATE TABLE "t"(a TEXT DEFAULT 'it''s  two')`},
	}
	for _, c := range cases {
		if got := normalizeDDL(c.a); got != c.b {
			t.Errorf("normalizeDDL(%q) = %q, want %q", c.a, got, c.b)
		}
	}
	if normalizeDDL("CREATE TABLE t(a TEXT NOT NULL)") == normalizeDDL("CREATE TABLE t(a TEXT)") {
		t.Error("a constraint difference normalized away")
	}
}

// fullChainSchema is the shape every database must end in: the repair's
// reference (baselineFiles) with every later .sql step applied on top, in
// version order. The later steps are deliberately outside the repair's
// reference — they run after it, against the shape it leaves, on fresh and
// upgraded databases alike — so the comparisons that used to be against the
// reference alone are against this.
func fullChainSchema(ctx context.Context) ([]schemaObject, error) {
	mem, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer mem.Close()
	mem.SetMaxOpenConns(1)
	for _, f := range baselineFiles {
		body, err := migrationsFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if _, err := mem.ExecContext(ctx, string(body)); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	migs, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	for _, m := range migs {
		if m.version <= repairBaselineVersion || m.sql == "" {
			continue
		}
		if _, err := mem.ExecContext(ctx, m.sql); err != nil {
			return nil, fmt.Errorf("%s: %w", m.name, err)
		}
	}
	return readSchema(ctx, mem)
}
