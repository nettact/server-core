package store

// Fail-closed contract tests for AccountScope (cloud/adr/0006 JB-2).
//
// JB-2 requires: AccountScope is the only construction point; Validate is
// fail-closed (AccountID non-empty AND TenantID empty); the three scope kinds
// are mutually exclusive and any two holding at once is an error.
//
// This file is deliberately in package `store` rather than `store_test`: the
// cases below build Scope struct literals with the unexported discriminants
// set, which is the only way to prove that a malformed scope would still be
// refused if one were ever constructed inside the package. The DB-touching
// half lives in account_scope_db_test.go (package store_test), because
// storetest imports store and an in-package test cannot import it back.

import "testing"

func TestAccountScopeConstruction(t *testing.T) {
	s := AccountScope("acct-1", "user-9")
	if err := s.Validate(); err != nil {
		t.Fatalf("AccountScope should validate: %v", err)
	}
	if !s.IsAccount() {
		t.Error("IsAccount() = false")
	}
	if s.IsSystem() {
		t.Error("account scope reports IsSystem()")
	}
	if s.AccountID != "acct-1" || s.ActorID != "user-9" {
		t.Errorf("fields not carried: %+v", s)
	}
	if s.TenantID != "" {
		t.Errorf("account scope must not carry a tenant, got %q", s.TenantID)
	}
}

// The three kinds must stay tellable apart. Testing the accessors rather than
// the fields is the point: domain code must never infer the kind from a field
// being empty (an account genuinely named "" would otherwise pass as tenant).
func TestScopeKindsAreMutuallyExclusive(t *testing.T) {
	for _, tc := range []struct {
		name            string
		scope           Scope
		system, account bool
	}{
		{"tenant", Standalone(), false, false},
		{"system", SystemScope("job"), true, false},
		{"account", AccountScope("acct-1", "user-9"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.scope.Validate(); err != nil {
				t.Fatalf("should validate: %v", err)
			}
			if tc.scope.IsSystem() != tc.system {
				t.Errorf("IsSystem() = %v, want %v", tc.scope.IsSystem(), tc.system)
			}
			if tc.scope.IsAccount() != tc.account {
				t.Errorf("IsAccount() = %v, want %v", tc.scope.IsAccount(), tc.account)
			}
		})
	}
}

// Every shape Validate must refuse.
func TestScopeValidateIsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope Scope
	}{
		{"zero value", Scope{}},
		{"account without account id", Scope{account: true}},
		{"account with only an actor", Scope{ActorID: "user-9", account: true}},
		{"account carrying a tenant", Scope{TenantID: "t1", AccountID: "a1", account: true}},
		{"system carrying a tenant", Scope{TenantID: "t1", system: true}},
		{"system carrying an account", Scope{AccountID: "a1", system: true}},
		{"system and account at once", Scope{AccountID: "a1", system: true, account: true}},
		{"tenant carrying an account", Scope{TenantID: "t1", AccountID: "a1"}},
		{"tenant with only an account id", Scope{AccountID: "a1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.scope.Validate(); err == nil {
				t.Fatalf("Validate accepted %+v; it must be refused", tc.scope)
			}
		})
	}
}

// The GUC name is frozen by JB-2 so the PostgreSQL adapter (W3-06) has exactly
// one spelling to implement against. Asserting it here keeps a rename from
// passing review unnoticed.
func TestAccountGUCNameIsFrozen(t *testing.T) {
	if AccountGUC != "app.account_id" {
		t.Errorf("AccountGUC = %q, cloud/adr/0006 JB-2 froze app.account_id", AccountGUC)
	}
}
