package store

// This file is package-internal (package store, not store_test) so tests can
// reach the unexported sqliteTx — the only way to sabotage the underlying
// *sql.Tx now that the SQLiteTx migration seam is deleted.

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// openInternal opens a migrated database with the same Windows-tolerant
// cleanup storetest would give — duplicated here because storetest imports
// this package and an internal test importing it would be a cycle.
func openInternal(t *testing.T) *DB {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-store-internal-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		for i := 0; i < 20; i++ {
			if err := os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
	return db
}

// TestWriteTxPostDiscardedOnCommitError covers the commit-failure arm, which
// SQLite makes hard to trigger honestly: the shipped schema has no deferred
// constraints, and statement-time failures surface at Exec, inside fn. The
// test therefore sabotages the transaction by rolling the underlying *sql.Tx
// back out from under WriteTx — Commit then fails with sql.ErrTxDone, the
// exact shape of a driver-level COMMIT failure — and asserts post was not run
// and the error surfaced. The constraint this does NOT simulate (a COMMIT
// rejected by the engine after statements succeeded) shares the same code
// path: post is only ever invoked after Commit returns nil.
func TestWriteTxPostDiscardedOnCommitError(t *testing.T) {
	db := openInternal(t)
	ctx := context.Background()

	var posts atomic.Int32
	err := db.WriteTx(ctx, Standalone(), func(wtx WriteTx) (func(), error) {
		raw := wtx.(*sqliteTx).tx
		if err := raw.Rollback(); err != nil {
			return nil, err
		}
		return func() { posts.Add(1) }, nil
	})
	if err == nil {
		t.Fatal("WriteTx = nil, want the commit error")
	}
	if posts.Load() != 0 {
		t.Fatalf("post ran %d times after commit error, want 0", posts.Load())
	}
}
