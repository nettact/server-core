// Package tsstoretest opens throwaway tsstore instances for tests, mirroring
// storetest's contract: a temp directory, production-like options, and a
// Windows-tolerant cleanup — the head chunks and WAL are memory-mapped, and
// Windows releases those handles slightly after Close, so removal is retried
// rather than silently skipped (a test that leaks a directory should say so).
package tsstoretest

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/tsstore"
)

// UUID is the dataset identity every test instance is bound to.
const UUID = "tsstoretest-dataset"

// Open returns a ready store in a temp dir, closed and removed at cleanup.
func Open(t testing.TB) *tsstore.Prom {
	t.Helper()
	return OpenCfg(t, tsstore.Config{})
}

// OpenCfg is Open with explicit retention config (for retention tests).
func OpenCfg(t testing.TB, cfg tsstore.Config) *tsstore.Prom {
	t.Helper()
	dir := Dir(t)
	p, err := tsstore.Open(dir, cfg, UUID)
	if err != nil {
		t.Fatalf("tsstore.Open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// Dir returns a temp directory removed (with retries) at cleanup.
func Dir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-tsdb-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { removeEventually(t, dir) })
	return dir
}

func removeEventually(t testing.TB, dir string) {
	for i := 0; i < 20; i++ {
		if err := os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("tsstoretest: leaked %s: %v", dir, err)
	}
}
