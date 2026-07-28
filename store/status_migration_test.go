package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// tempDBPath returns a database path in its own directory, removed on a
// best-effort basis when the test ends. It does NOT use t.TempDir: that fails
// the test when RemoveAll errors, and on Windows the database file can still be
// locked for a moment after Close, which would turn an OS timing detail into a
// spurious test failure. (Other packages get this from store/storetest, which
// cannot be imported here without an import cycle.)
func tempDBPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-store-test-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 20; i++ {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
	return filepath.Join(dir, "upgrade.db")
}

func TestStatusMigrationSeedsMonotonicSerialAndDropsLegacyTable(t *testing.T) {
	path := tempDBPath(t)
	raw, err := sql.Open("sqlite", path+dsnPragmas)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := strconv.Atoi(strings.SplitN(entry.Name(), "_", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		if version >= 14 {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", entry.Name(), err)
		}
		if _, err := raw.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, version, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	// Current 0001 is clean-cut and no longer creates this table. Recreate the
	// historical 0001 shape explicitly so this is a real 0013 -> 0014 upgrade,
	// not merely a fresh-schema test.
	if _, err := raw.Exec(`CREATE TABLE config_versions(
		id TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL REFERENCES agents(id),
		version INTEGER NOT NULL,
		desired_state TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		UNIQUE(agent_id, version))`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO sites(id,name) VALUES('site','Site')`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO agents(
		id,site_id,public_key,token_hash,status,config_version,reported_config_version,last_status_config_version)
		VALUES('agent','site',x'00','h','online',7,9,8)`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var serial int
	if err := db.QueryRow(`SELECT config_serial FROM sites WHERE id='site'`).Scan(&serial); err != nil {
		t.Fatal(err)
	}
	if serial != 9 {
		t.Fatalf("migrated site config_serial = %d, want max legacy watermark 9", serial)
	}
	var legacyTables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='config_versions'`).Scan(&legacyTables); err != nil {
		t.Fatal(err)
	}
	if legacyTables != 0 {
		t.Fatal("legacy config_versions table survived migration")
	}
}
