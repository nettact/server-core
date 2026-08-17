package store_test

// The DB-touching half of the AccountScope contract (cloud/adr/0006 JB-2).
// Split from account_scope_test.go because storetest imports store, so an
// in-package test file cannot import it back.

import (
	"context"
	"testing"

	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// An account scope must reach the transaction entry points intact, and the
// transaction must be able to tell which boundary it was opened under —
// otherwise repository code has no way to assert it is on the account path.
func TestAccountScopeReachesWriteTx(t *testing.T) {
	db := storetest.Open(t)
	s := store.AccountScope("acct-1", "user-9")

	err := db.WriteTx(context.Background(), s, func(wtx store.WriteTx) (func(), error) {
		got := wtx.Scope()
		if !got.IsAccount() {
			t.Error("WriteTx lost the account discriminant")
		}
		if got.IsSystem() {
			t.Error("account scope arrived as a system scope")
		}
		if got.AccountID != "acct-1" {
			t.Errorf("AccountID = %q, want acct-1", got.AccountID)
		}
		if got.TenantID != "" {
			t.Errorf("account scope arrived carrying tenant %q", got.TenantID)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("WriteTx with a valid account scope: %v", err)
	}
}

// And a malformed account scope must be refused before the database is touched,
// exactly as the zero-value scope is. Constructed via the exported surface (an
// account id is required, so the empty-string call is the reachable mistake).
func TestAccountScopeWithoutIDIsRefusedBeforeAnyWork(t *testing.T) {
	db := storetest.Open(t)

	called := false
	err := db.WriteTx(context.Background(), store.AccountScope("", "user-9"), func(store.WriteTx) (func(), error) {
		called = true
		return nil, nil
	})
	if err == nil {
		t.Fatal("WriteTx accepted an account scope with no account id")
	}
	if called {
		t.Fatal("fn ran despite an invalid account scope")
	}
}

func TestAccountScopeReachesReadTx(t *testing.T) {
	db := storetest.Open(t)

	called := false
	err := db.ReadTx(context.Background(), store.AccountScope("", ""), func(store.Executor) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("ReadTx accepted an account scope with no account id")
	}
	if called {
		t.Fatal("fn ran despite an invalid account scope")
	}
}
