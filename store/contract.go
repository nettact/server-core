package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
)

// This file is the CLOUD-014A milestone: the minimal Scope/Executor/WriteTx
// store contract that shared domain logic can be written against once and run
// on the SQLite single-writer connection today and on PostgreSQL tenant
// transactions later. Deliberately absent: a PostgreSQL implementation (the
// dialect + adapter here are the SQLite ones), row-level security (per-row
// tenant enforcement lands with the PostgreSQL adapter, not in this contract),
// and any kind of ORM — repositories needing truly different SQL per store
// keep two explicit implementations behind one interface, they do not get a
// query builder.

// Scope identifies the tenant boundary a call runs under. Zero-value scopes
// are invalid by construction: every read and write must carry one, and the
// entry points (DB.WriteTx / DB.ReadTx) refuse a scope that fails Validate
// before they touch the database.
//
// The scope is carried on the transaction so repository code can assert which
// tenant it was opened under (WriteTx.Scope), but it is NOT an enforcement
// mechanism: nothing here filters rows by TenantID. The single-tenant
// deployments this milestone serves have exactly one tenant in the database,
// and per-row enforcement arrives with the PostgreSQL adapter's RLS policy in
// the cloud milestone — a repository that relies on the scope field for
// filtering would silently break the day the adapter starts enforcing
// differently.
type Scope struct {
	// TenantID is the tenant the call reads or writes under. Empty only for
	// system scopes (see SystemScope); every other scope must name a tenant.
	TenantID string
	// ActorID identifies the acting principal — the user id for console
	// actions, a job name for platform jobs. It is provenance for audit and
	// RLS policy resolution, not authorization by itself.
	ActorID string

	// system marks a scope opened for a platform job that runs outside any
	// tenant boundary (migrations, sweepers, cross-tenant reconciliation).
	// Unexported so SystemScope is the only way to get one.
	system bool
}

// Validate reports whether the scope may open a transaction. Tenant scopes
// require a non-empty TenantID; system scopes (created exclusively by
// SystemScope) are exempt because platform jobs deliberately run outside a
// tenant. ActorID is not validated: provenance may legitimately be absent.
func (s Scope) Validate() error {
	if s.system {
		return nil
	}
	if s.TenantID == "" {
		return errors.New("store: scope has no tenant (construct with Standalone or SystemScope, never Scope{})")
	}
	return nil
}

// IsSystem reports whether this is a platform-job scope. Domain code that must
// treat "no tenant" specially checks this instead of testing TenantID == "",
// so a tenant that is genuinely named "" can never masquerade as system.
func (s Scope) IsSystem() bool { return s.system }

// SystemScope returns the scope for platform jobs that run outside any tenant.
// It is the ONLY way to construct a system scope — the flag is unexported and
// Validate rejects a zero-value Scope — so a call that must cross tenant
// boundaries can always be told apart from one that forgot its scope.
func SystemScope(actor string) Scope {
	return Scope{ActorID: actor, system: true}
}

// Standalone returns the fixed scope the self-hosted server and the desktop
// app run under: exactly one tenant, conventionally named "standalone". Domain
// code calls this unconditionally — there is no `if cloud` branch anywhere;
// the cloud milestone swaps the scope construction at the composition seam,
// not inside the packages.
func Standalone() Scope {
	return Scope{TenantID: "standalone"}
}

// Dialect names the SQL dialect a repository's statements are written in. It
// exists so a repository can be dialect-aware without being dialect-specific:
// the narrow, enumerable differences in the migrated slice are handled by
// Rebind, and anything beyond that surface is a per-dialect implementation
// behind one interface rather than inline branching.
type Dialect int

const (
	// DialectSQLite is the current deployment dialect: ? placeholders, INSERT
	// OR IGNORE, ON CONFLICT ... DO UPDATE, no RETURNING, JSON marshalled in
	// Go, times stored as strings/ints.
	DialectSQLite Dialect = iota
	// DialectPostgres is the cloud-milestone dialect. Declared now so the
	// contract is complete; nothing in this repo executes it yet.
	DialectPostgres
)

// Rebind rewrites a query's placeholders for the dialect: identity for
// SQLite, ? → $1, $2, … for PostgreSQL. It is deliberately lexical and
// deliberately dumb — no awareness of string literals, comments, or operators
// like the JSON `?` operator — because the enumerable dialect surface is
// exactly: positional placeholders. A query that needs anything beyond that
// (RETURNING, upsert syntax, the `?` operator) is not part of the shared
// surface and belongs in an explicit per-dialect implementation. Unknown
// Dialect values rebind to SQLite form rather than guessing.
func (d Dialect) Rebind(query string) string {
	if d != DialectPostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	for i, n := 0, 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteString("$")
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

// Executor is the minimal read/execute surface a repository may use. It is
// deliberately smaller than *sql.DB or *sql.Tx: Prepare, ping, pingers and
// transaction control are all excluded, so a repository written against it
// cannot accidentally open a nested transaction or grab the single writer for
// a long-lived statement. Both the read pool (*sql.DB) and an open WriteTx
// satisfy it, which is what lets one code path run both pre-transaction reads
// and in-transaction reads.
//
// Error semantics are the driver's, preserved: QueryRowContext(...).Scan
// returns sql.ErrNoRows exactly as with a raw handle, and everything else
// surfaces verbatim. Repositories must treat any non-nil, non-ErrNoRows error
// as an opaque failure — normalizing driver-specific codes (SQLITE_BUSY,
// serialization failures, …) is the adapter's concern, so retry and mapping
// logic lives behind the interface rather than leaking into every repository.
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// WriteTx is an Executor bound to an open write transaction. Owners of the
// transaction (store.DB.WriteTx) create and commit it; domain functions only
// receive it and must never Commit or Rollback it, and must never open a
// nested transaction on it — the single-writer store has no such thing, and a
// future adapter's savepoint semantics would not be what the code thinks it
// asked for.
type WriteTx interface {
	Executor
	// Dialect reports the SQL dialect this transaction's statements run
	// under, so a repository can Rebind shared queries and pick per-dialect
	// implementations for the rest.
	Dialect() Dialect
	// Scope returns the scope this transaction was opened with. Repositories
	// may assert on it (fail loudly rather than write to the wrong tenant);
	// per-row enforcement is the adapter's job, not theirs.
	Scope() Scope
}
