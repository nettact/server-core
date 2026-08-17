package store_test

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"

	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func TestScopeValidation(t *testing.T) {
	standalone := store.Standalone()
	sys := store.SystemScope("sweeper")

	cases := []struct {
		name    string
		s       store.Scope
		wantErr bool
	}{
		{"zero scope", store.Scope{}, true},
		{"actor only, no tenant", store.Scope{ActorID: "user-1"}, true},
		{"empty-string tenant", store.Scope{TenantID: ""}, true},
		{"named tenant", store.Scope{TenantID: "tenant-a"}, false},
		{"named tenant with actor", store.Scope{TenantID: "tenant-a", ActorID: "user-1"}, false},
		{"standalone", standalone, false},
		{"system", sys, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestScopeSystemFlag(t *testing.T) {
	// SystemScope is the ONLY constructor for the system flag — the field is
	// unexported, so a literal can never set it. Assert the observable
	// consequences of that: IsSystem and the tenant exemption.
	if got := store.SystemScope("job").IsSystem(); !got {
		t.Fatal("SystemScope(...).IsSystem() = false")
	}
	if got := (store.Scope{}).IsSystem(); got {
		t.Fatal("zero Scope.IsSystem() = true; system must come only from SystemScope")
	}
	if got := (store.Scope{TenantID: "standalone"}).IsSystem(); got {
		t.Fatal("tenant Scope.IsSystem() = true")
	}
	if got := store.Standalone().IsSystem(); got {
		t.Fatal("Standalone().IsSystem() = true")
	}
	if got := store.Standalone().TenantID; got != "standalone" {
		t.Fatalf("Standalone().TenantID = %q, want \"standalone\"", got)
	}
	if got := store.SystemScope("x").TenantID; got != "" {
		t.Fatalf("SystemScope tenant = %q, want empty", got)
	}
}

func TestDialectRebind(t *testing.T) {
	cases := []struct {
		name    string
		d       store.Dialect
		in, out string
	}{
		{"sqlite identity", store.DialectSQLite, "SELECT a FROM t WHERE id=? AND v=?", "SELECT a FROM t WHERE id=? AND v=?"},
		{"postgres two", store.DialectPostgres, "SELECT a FROM t WHERE id=? AND v=?", "SELECT a FROM t WHERE id=$1 AND v=$2"},
		{"postgres many across clauses", store.DialectPostgres,
			"INSERT INTO t(a,b) VALUES(?,?) ON CONFLICT(a) DO UPDATE SET b=excluded.b WHERE b>? AND c=?",
			"INSERT INTO t(a,b) VALUES($1,$2) ON CONFLICT(a) DO UPDATE SET b=excluded.b WHERE b>$3 AND c=$4"},
		{"postgres zero placeholders", store.DialectPostgres, "SELECT 1", "SELECT 1"},
		// Unknown dialect values fail safe to SQLite form rather than guessing.
		{"unknown dialect identity", store.Dialect(99), "a=?", "a=?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.d.Rebind(tc.in); got != tc.out {
				t.Fatalf("Rebind(%q) = %q, want %q", tc.in, got, tc.out)
			}
		})
	}
}

// TestWriteTxPostAfterCommit proves the post closure runs after the commit and
// exactly once. The proof is visibility: post reads the row fn wrote through
// the READ pool — a separate connection that WAL mode keeps blind to
// uncommitted data — so a WriteTx that ran post before committing would fail
// the read. A second WriteTx ordering cannot help: the single write connection
// serializes them anyway.
func TestWriteTxPostAfterCommit(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE contract_kv(id TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}

	var posts atomic.Int32
	visibleAfterCommit := false
	err := db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		if _, err := wtx.ExecContext(ctx, `INSERT INTO contract_kv(id, v) VALUES('k1', 'v1')`); err != nil {
			return nil, err
		}
		return func() {
			posts.Add(1)
			var v string
			if err := db.Read().QueryRowContext(ctx, `SELECT v FROM contract_kv WHERE id='k1'`).Scan(&v); err != nil {
				t.Errorf("post-commit read: %v", err)
				return
			}
			if v != "v1" {
				t.Errorf("post-commit read = %q, want v1 (post ran before commit?)", v)
				return
			}
			visibleAfterCommit = true
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 {
		t.Fatalf("post ran %d times, want 1", posts.Load())
	}
	if !visibleAfterCommit {
		t.Fatal("post could not see the committed row")
	}
}

func TestWriteTxPostDiscardedOnFnError(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE contract_kv(id TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}

	var posts atomic.Int32
	err := db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		if _, err := wtx.ExecContext(ctx, `INSERT INTO contract_kv(id, v) VALUES('k1', 'v1')`); err != nil {
			return nil, err
		}
		return func() { posts.Add(1) }, sql.ErrTxDone // any fn error: tx must roll back, post discarded
	})
	if err == nil {
		t.Fatal("WriteTx = nil, want the fn error")
	}
	if posts.Load() != 0 {
		t.Fatalf("post ran %d times after fn error, want 0", posts.Load())
	}
	var n int
	if err := db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM contract_kv`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d rows visible after rollback, want 0", n)
	}
}

// TestWriteTxPostDiscardedOnCommitError is in tx_internal_test.go (package
// store): it sabotages the underlying *sql.Tx to force the commit-error arm,
// which needs the unexported adapter now that the SQLiteTx bridge is gone.

func TestWriteTxRejectsInvalidScope(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()

	called := false
	err := db.WriteTx(ctx, store.Scope{}, func(store.WriteTx) (func(), error) {
		called = true
		return nil, nil
	})
	if err == nil {
		t.Fatal("WriteTx with zero scope = nil, want validation error")
	}
	if called {
		t.Fatal("fn ran despite invalid scope")
	}
}

func TestReadTxRejectsInvalidScope(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()

	called := false
	err := db.ReadTx(ctx, store.Scope{}, func(store.Executor) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("ReadTx with zero scope = nil, want validation error")
	}
	if called {
		t.Fatal("fn ran despite invalid scope")
	}
}

func TestReadTxSeesCommittedData(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE contract_kv(id TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		_, err := wtx.ExecContext(ctx, `INSERT INTO contract_kv(id, v) VALUES('k1', 'v1')`)
		return nil, err
	}); err != nil {
		t.Fatal(err)
	}

	var got string
	err := db.ReadTx(ctx, store.Standalone(), func(ex store.Executor) error {
		return ex.QueryRowContext(ctx, `SELECT v FROM contract_kv WHERE id='k1'`).Scan(&got)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1" {
		t.Fatalf("ReadTx saw %q, want v1", got)
	}
}

func TestWriteTxReportsScopeAndDialect(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	s := store.Scope{TenantID: "tenant-a", ActorID: "user-1"}

	err := db.WriteTx(ctx, s, func(wtx store.WriteTx) (func(), error) {
		if got := wtx.Scope(); got != s {
			t.Fatalf("Scope() = %+v, want %+v", got, s)
		}
		if got := wtx.Dialect(); got != store.DialectSQLite {
			t.Fatalf("Dialect() = %v, want DialectSQLite", got)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAdaptTxRoundTrip pins the owner-side seam: AdaptTx hands a manually
// opened *sql.Tx to WriteTx-typed entry points, and the wrap is transparent —
// a write through the WriteTx facade is visible to the raw transaction.
func TestAdaptTxRoundTrip(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE contract_kv(id TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}

	raw, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wtx := store.AdaptTx(raw, store.Standalone())
	if got := wtx.Scope(); got != store.Standalone() {
		t.Fatalf("AdaptTx Scope() = %+v", got)
	}
	if got := wtx.Dialect(); got != store.DialectSQLite {
		t.Fatalf("AdaptTx Dialect() = %v", got)
	}
	if _, err := wtx.ExecContext(ctx, `INSERT INTO contract_kv(id, v) VALUES('k1', 'v1')`); err != nil {
		t.Fatal(err)
	}
	// Same underlying transaction: the raw handle sees the facade's write.
	var v string
	if err := raw.QueryRowContext(ctx, `SELECT v FROM contract_kv WHERE id='k1'`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "v1" {
		t.Fatalf("raw handle saw %q, want v1", v)
	}
	if err := raw.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestWriteTxPrepareContext pins the PrepareContext extension: a statement prepared
// on the WriteTx executes against the same transaction and is callable
// repeatedly.
func TestWriteTxPrepareContext(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE contract_kv(id TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}

	err := db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		stmt, err := wtx.PrepareContext(ctx, `INSERT INTO contract_kv(id, v) VALUES(?, ?)`)
		if err != nil {
			return nil, err
		}
		defer stmt.Close()
		for _, kv := range [][2]string{{"k1", "v1"}, {"k2", "v2"}} {
			if _, err := stmt.ExecContext(ctx, kv[0], kv[1]); err != nil {
				return nil, err
			}
		}
		var n int
		if err := wtx.QueryRowContext(ctx, `SELECT COUNT(*) FROM contract_kv`).Scan(&n); err != nil {
			return nil, err
		}
		if n != 2 {
			t.Fatalf("rows=%d, want 2", n)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
