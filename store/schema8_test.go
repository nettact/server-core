package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSchema8UpgradeFromV1 builds a database at exactly the previously
// released schema — the 0001 baseline applied by hand with its ledger row
// recorded, plus the data a released installation has — then opens it through
// the normal path so the migrator applies 0002, and asserts the upgrade: the
// new columns and the receipt table exist, pre-existing rows keep their data
// and land on generation 1, and no rotation is staged.
//
// The runner applies every unrecorded migration, so "a database at the
// previous release" cannot be produced by the runner itself; the 0001 SQL is
// applied raw, exactly as a released build would have done.
func TestSchema8UpgradeFromV1(t *testing.T) {
	dir := testStoreDir(t)
	path := filepath.Join(dir, "upgrade.db")

	baseline, err := migrationsFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("read 0001: %v", err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(string(baseline)); err != nil {
		raw.Close()
		t.Fatalf("apply 0001: %v", err)
	}
	// The migrator owns the ledger table (the 0001 file does not create it);
	// a released installation has it with 0001 recorded.
	if _, err := raw.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`); err != nil {
		raw.Close()
		t.Fatalf("create ledger: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC()); err != nil {
		raw.Close()
		t.Fatalf("record 0001: %v", err)
	}
	// A released installation has data: an agent row written under the 0001
	// schema must survive the upgrade with its data intact and epoch 1.
	if _, err := raw.Exec(`INSERT INTO sites(id,name) VALUES('site_default','Default')`); err != nil {
		raw.Close()
		t.Fatalf("seed site: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,status,high_sequence)
		VALUES('agent_old','site_default',x'00','oldhash','box-1','online',42)`); err != nil {
		raw.Close()
		t.Fatalf("seed agent: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	// The normal open path: the migrator applies 0002.
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open after v1: %v", err)
	}
	defer db.Close()

	var hostname string
	var epoch, pendingEpoch uint64
	var pendingUntil, high int64
	if err := db.QueryRow(`SELECT hostname, enrollment_epoch, pending_next_epoch, pending_next_until, high_sequence
		FROM agents WHERE id='agent_old'`).Scan(&hostname, &epoch, &pendingEpoch, &pendingUntil, &high); err != nil {
		t.Fatalf("read upgraded agent: %v", err)
	}
	if hostname != "box-1" || high != 42 {
		t.Errorf("upgraded agent = hostname %q high %d, want the pre-upgrade values", hostname, high)
	}
	if epoch != 1 {
		t.Errorf("enrollment_epoch = %d, want the 1 default for pre-schema-8 rows", epoch)
	}
	if pendingEpoch != 0 || pendingUntil != 0 {
		t.Errorf("pending rotation = %d/%d, want none staged on upgrade", pendingEpoch, pendingUntil)
	}

	// The new table exists and is empty.
	var receipts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM packet_receipts`).Scan(&receipts); err != nil {
		t.Fatalf("packet_receipts: %v", err)
	}
	if receipts != 0 {
		t.Errorf("packet_receipts has %d rows on upgrade, want 0", receipts)
	}
	// Exactly the two migrations are recorded.
	var versions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if versions != 2 {
		t.Errorf("schema_migrations has %d rows, want 2 (0001 + 0002)", versions)
	}
}

// TestSchema8FreshInstall: a fresh database runs the whole chain and lands
// with the schema-8 defaults — an enrolled row's generation starts at 1 and
// the receipt ledger accepts rows keyed (agent, epoch, sequence).
func TestSchema8FreshInstall(t *testing.T) {
	dir := testStoreDir(t)
	db, err := Open(filepath.Join(dir, "fresh.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO sites(id,name) VALUES('site_default','Default')`); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_a','site_default',x'00','h','online')`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	var epoch uint64
	if err := db.QueryRow(`SELECT enrollment_epoch FROM agents WHERE id='agent_a'`).Scan(&epoch); err != nil {
		t.Fatalf("read epoch: %v", err)
	}
	if epoch != 1 {
		t.Errorf("fresh enrollment_epoch = %d, want 1", epoch)
	}
	// The ledger's key shape: one row per (agent, epoch, sequence), deduping
	// the same slot.
	if _, err := db.Exec(`INSERT INTO packet_receipts(agent_id,enrollment_epoch,sequence,fingerprint,received_at)
		VALUES('agent_a',1,5,'fp-a',?)`, now.Unix()); err != nil {
		t.Fatalf("insert receipt: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO packet_receipts(agent_id,enrollment_epoch,sequence,fingerprint,received_at)
		VALUES('agent_a',1,5,'fp-a',?)`, now.Unix()); err == nil {
		t.Fatal("a second receipt for the same (agent, epoch, sequence) was accepted")
	}
	if _, err := db.Exec(`INSERT INTO packet_receipts(agent_id,enrollment_epoch,sequence,fingerprint,received_at)
		VALUES('agent_a',2,5,'fp-a',?)`, now.Unix()); err != nil {
		t.Fatalf("a new epoch must own its own slot: %v", err)
	}
}

// testStoreDir returns a temp directory with the same best-effort cleanup
// storetest uses; this package cannot import storetest (cycle), and the
// Windows handle-release caveat applies here all the same.
func testStoreDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-test-")
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
	return dir
}
