package store_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The baseline is now the whole schema — the 0002–0005 chain was squashed back
// into it — so what needs checking is that nothing was lost in the squash. Each
// column below is one the chain added or removed, and each is the kind of thing
// a hand-merge drops silently: a column that arrived as an ALTER, a partial
// index, two whole tables, and four columns that a DROP had taken back out.
func TestTheBaselineCreatesTheWholeSchema(t *testing.T) {
	db, err := store.Open(filepath.Join(storetest.Dir(t), "fresh.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Arrived as an ALTER on agents; its absence breaks the permission endpoints.
	if !columnNames(t, db.DB, "agents")["perm_unsupported_reasons"] {
		t.Error("agents has no perm_unsupported_reasons")
	}

	// AGENT-006 reinstall tokens: the optional agent binding + revoke flag ride on
	// enrollment_tokens, and their absence silently breaks the reinstall flow.
	tokens := columnNames(t, db.DB, "enrollment_tokens")
	for _, col := range []string{"agent_id", "revoked"} {
		if !tokens[col] {
			t.Errorf("enrollment_tokens has no %s", col)
		}
	}
	if !indexNames(t, db.DB, "enrollment_tokens")["idx_enrollment_tokens_agent"] {
		t.Error("enrollment_tokens has no idx_enrollment_tokens_agent")
	}

	// The machine-level readings live in their own table, keyed by (agent,
	// second), and must NOT also be in game_buckets. Two sources for one fact is
	// the exact outcome the move existed to prevent, and it is what a squash that
	// kept the original CREATE would produce.
	buckets := columnNames(t, db.DB, "game_buckets")
	for _, col := range []string{"gpu_util_pct", "gpu_mem_used", "gpu_mem_size", "busiest_core_pct"} {
		if buckets[col] {
			t.Errorf("game_buckets still has %s, which belongs to game_host_seconds", col)
		}
	}
	// The per-process readings stay: they are about a process rather than the
	// machine, and dropping them with their neighbours is the easy mistake.
	for _, col := range []string{"proc_vram_used", "proc_cpu_pct", "hist"} {
		if !buckets[col] {
			t.Errorf("game_buckets lost %s, which was never machine-level", col)
		}
	}

	host := columnNames(t, db.DB, "game_host_seconds")
	for _, col := range []string{"agent_id", "site_id", "ts", "cpu_total_pct", "cpu_busiest_pct", "mem_used", "mem_total", "gpu_util_pct", "gpu_mem_used", "gpu_mem_size", "quality"} {
		if !host[col] {
			t.Errorf("game_host_seconds has no %s", col)
		}
	}
	gaps := columnNames(t, db.DB, "game_run_gaps")
	for _, col := range []string{"id", "run_id", "reason", "started_at", "ended_at"} {
		if !gaps[col] {
			t.Errorf("game_run_gaps has no %s", col)
		}
	}

	// The reaper's partial index. An index is invisible to every query that would
	// otherwise pass, so nothing else here would notice it missing.
	if !indexNames(t, db.DB, "game_runs")["idx_game_runs_open"] {
		t.Error("game_runs has no idx_game_runs_open")
	}
	if !indexNames(t, db.DB, "game_run_gaps")["idx_game_run_gaps_run"] {
		t.Error("game_run_gaps has no idx_game_run_gaps_run")
	}
	if !indexNames(t, db.DB, "game_host_seconds")["idx_game_host_seconds_ts"] {
		t.Error("game_host_seconds has no idx_game_host_seconds_ts")
	}
}

// Reopening an existing database must be a no-op that leaves its rows alone. The
// migrator skips a version already recorded, so a second Open must neither
// re-run the baseline (every CREATE would fail) nor recreate the file.
func TestReopeningAnExistingDatabaseChangesNothing(t *testing.T) {
	path := filepath.Join(storetest.Dir(t), "existing.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO sites(id,name) VALUES('site_default','Default')`); err != nil {
		db.Close()
		t.Fatalf("seed site: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,status,perm_supported)
		 VALUES('agent_old','site_default',x'00','h','box-1','online','["probe.dns"]')`); err != nil {
		db.Close()
		t.Fatalf("seed agent: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	db2, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()

	var hostname, reasons string
	if err := db2.QueryRow(
		`SELECT hostname, perm_unsupported_reasons FROM agents WHERE id='agent_old'`).Scan(&hostname, &reasons); err != nil {
		t.Fatalf("read seeded agent: %v", err)
	}
	if hostname != "box-1" {
		t.Errorf("hostname = %q, want the value written before the reopen", hostname)
	}
	// The default is an empty object: "nothing was probed", not "everything is
	// supported".
	if reasons != "{}" {
		t.Errorf("perm_unsupported_reasons default = %q, want %q", reasons, "{}")
	}

	var versions int
	if err := db2.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	// One squashed baseline — schema additions are edited into 0001, never a chain.
	if versions != 1 {
		t.Errorf("schema_migrations has %d rows, want 1 for the squashed baseline", versions)
	}
}

func columnNames(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	return namesFrom(t, db, `SELECT name FROM pragma_table_info(?)`, table)
}

func indexNames(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	return namesFrom(t, db, `SELECT name FROM pragma_index_list(?)`, table)
}

func namesFrom(t *testing.T, db *sql.DB, query, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(query, table)
	if err != nil {
		t.Fatalf("%s(%s): %v", query, table, err)
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan name: %v", err)
		}
		names[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s(%s): %v", query, table, err)
	}
	return names
}
