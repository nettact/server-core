package store_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// TestMigrationsApplyToAnExistingDatabase is about the migrations being
// INCREMENTAL, which a test that only ever opens a fresh file cannot show: every
// migration passes trivially against an empty directory, including one that was
// edited into 0001 after 0001 had already been applied somewhere and would
// therefore never run again on a real database.
//
// So this builds a database at the 0001 baseline by hand — schema applied,
// version 1 recorded, rows present — closes it, and reopens it through
// store.Open. Everything after 0001 must apply on top, leaving the existing data
// alone. The 0002 column is checked concretely because it is the one whose
// absence on a live dev database would break the permission endpoints.
func TestMigrationsApplyToAnExistingDatabase(t *testing.T) {
	path := filepath.Join(storetest.Dir(t), "existing.db")

	// --- a database that has only ever seen 0001 ---
	baseline, err := os.ReadFile(filepath.Join("migrations", "0001_init.sql"))
	if err != nil {
		t.Fatalf("read baseline migration: %v", err)
	}
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`,
		string(baseline),
	} {
		if _, err := old.Exec(stmt); err != nil {
			old.Close()
			t.Fatalf("build baseline: %v", err)
		}
	}
	if _, err := old.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC()); err != nil {
		old.Close()
		t.Fatalf("record baseline version: %v", err)
	}
	// Real data, as a live dev database has: a migration that silently dropped and
	// recreated the table would pass every schema assertion below.
	if _, err := old.Exec(
		`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, time.Now().UTC()); err != nil {
		old.Close()
		t.Fatalf("seed site: %v", err)
	}
	if _, err := old.Exec(
		`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,status,perm_supported)
		 VALUES('agent_old','site_default',x'00','h','box-1','online','["probe.dns"]')`); err != nil {
		old.Close()
		t.Fatalf("seed agent: %v", err)
	}
	if got := columnNames(t, old, "agents"); got["perm_unsupported_reasons"] {
		old.Close()
		t.Fatal("precondition: the baseline must not already have perm_unsupported_reasons")
	}
	if err := old.Close(); err != nil {
		t.Fatalf("close baseline: %v", err)
	}

	// --- reopening runs everything after 0001 ---
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("open existing database: %v", err)
	}
	defer db.Close()

	if !columnNames(t, db.DB, "agents")["perm_unsupported_reasons"] {
		t.Fatal("0002 did not apply to the existing database")
	}
	var versions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if versions < 2 {
		t.Fatalf("schema_migrations has %d rows, want every migration recorded", versions)
	}

	// The pre-existing row survived and picked up the column default — an empty
	// object, meaning "nothing was probed", not "everything is supported".
	var hostname, reasons string
	if err := db.QueryRow(
		`SELECT hostname, perm_unsupported_reasons FROM agents WHERE id='agent_old'`).Scan(&hostname, &reasons); err != nil {
		t.Fatalf("read migrated agent: %v", err)
	}
	if hostname != "box-1" {
		t.Errorf("hostname = %q, want the pre-migration value", hostname)
	}
	if reasons != "{}" {
		t.Errorf("perm_unsupported_reasons default = %q, want %q", reasons, "{}")
	}

	// Re-running is a no-op: a second Open must not try to add the column twice.
	// (sql.DB.Close is idempotent, so the deferred close above stays correct.)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen after migrating: %v", err)
	}
	db2.Close()
}

func columnNames(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatalf("table_info(%s): %v", table, err)
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		names[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info(%s): %v", table, err)
	}
	return names
}
