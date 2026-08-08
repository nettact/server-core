package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// A connection appearing on a live database must not want the WRITE lock.
//
// Both pools create connections on demand, so connection setup runs at arbitrary
// moments under load — including while a transaction is mid-flight. A
// connection-initialization pragma that takes the write lock then kills that
// transaction outright rather than delaying it: SQLite skips the busy handler
// once a connection holds a transaction (retrying could deadlock), so
// busy_timeout does not cover the upgrade and the write fails on the spot. That
// is exactly what a DSN-level `auto_vacuum=INCREMENTAL` did — it compiles to a
// write transaction — and it turned ordinary startup load into SQLITE_BUSY.
func TestOpeningAnotherHandleLeavesAnOpenWriteTransactionAlone(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(storetest.Dir(t), "concurrent.db")

	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(a INTEGER)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck // the happy path commits below
	if _, err := tx.ExecContext(ctx, `INSERT INTO t VALUES(1)`); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// A second handle opens while that transaction holds the write lock, and its
	// reader pool spins up a connection of its own.
	start := time.Now()
	other, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open while a write transaction is open: %v", err)
	}
	defer other.Close()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Open took %v: connection setup is waiting on the write lock", elapsed)
	}
	var n int
	if err := other.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("read through the second handle: %v", err)
	}

	// The transaction that was already running must still be able to write.
	if _, err := tx.ExecContext(ctx, `INSERT INTO t VALUES(2)`); err != nil {
		t.Fatalf("write after a foreign connection appeared: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// Now that auto_vacuum is set by Open rather than by the DSN, pin that a fresh
// database still comes out INCREMENTAL: the metrics purge reclaims space with
// `PRAGMA incremental_vacuum`, which is a silent no-op on a database that was
// created without it, and the file cannot be switched over afterwards without a
// full VACUUM.
func TestFreshDatabaseIsIncrementalAutoVacuum(t *testing.T) {
	path := filepath.Join(storetest.Dir(t), "vacuum.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	const incremental = 2
	var mode int
	if err := db.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		t.Fatalf("read auto_vacuum: %v", err)
	}
	if mode != incremental {
		t.Fatalf("auto_vacuum = %d, want %d (INCREMENTAL)", mode, incremental)
	}

	// It is a property of the file, so reopening must not have to set it again.
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if err := reopened.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		t.Fatalf("read auto_vacuum after reopen: %v", err)
	}
	if mode != incremental {
		t.Fatalf("auto_vacuum after reopen = %d, want %d (INCREMENTAL)", mode, incremental)
	}
	if _, err := reopened.Exec(`PRAGMA incremental_vacuum(10)`); err != nil {
		t.Fatalf("incremental_vacuum: %v", err)
	}
}
