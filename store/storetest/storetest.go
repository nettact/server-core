// Package storetest opens throwaway databases for tests.
//
// It exists because t.TempDir() is the wrong owner for a SQLite file on Windows.
// t.TempDir registers a cleanup that RemoveAll's the directory and FAILS THE TEST
// if that errors — but Windows releases a database file's handles and memory
// mapping slightly after Close returns, so a perfectly good test intermittently
// fails on the unlink instead of on anything it asserted. Tying the file's
// lifetime to a best-effort cleanup keeps the failure signal honest: a red test
// then means the code is wrong, not that the OS was still finishing up.
package storetest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
)

// Open returns a migrated database in its own temporary directory, closed and
// removed when the test ends. It takes testing.TB so benchmarks can use it too.
func Open(t testing.TB) *store.DB {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-test-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		removeEventually(dir)
	})
	return db
}

// Dir returns a temporary directory with the same forgiving cleanup, for tests
// that need a path to put a database at rather than an already-open handle —
// the server module's, which hand a DBPath to a whole server and cannot close
// its handles themselves.
func Dir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-test-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { removeEventually(dir) })
	return dir
}

// removeEventually deletes the directory, retrying briefly while Windows still
// holds the database file. It never fails the test: a leftover directory under
// the OS temp root is the operating system's to reap, and reporting it as a test
// failure would be reporting the wrong thing.
func removeEventually(dir string) {
	for i := 0; i < 20; i++ {
		if err := os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}
