package store

import (
	"context"
	"database/sql"
)

// This file is the SQLite adapter for the CLOUD-014A contract: the sqliteTx
// wrapper plus the DB.WriteTx / DB.ReadTx entry points. It is the ONLY
// adapter in this milestone; the PostgreSQL adapter arrives with the cloud
// milestone and must satisfy the same contract (see contract.go).

// Compile-time pins: the read pool and an open *sql.Tx satisfy Executor, and
// the adapter satisfies WriteTx. Kept in the shipped package (not a test) so
// an edit to either side fails the build instead of some distant repository.
var (
	_ Executor = (*sql.DB)(nil)
	_ Executor = (*sql.Tx)(nil)
	_ WriteTx  = (*sqliteTx)(nil)
)

// sqliteTx is a WriteTx over one open *sql.Tx on the SQLite write handle,
// carrying the scope it was opened under and its dialect. It never exposes
// Commit/Rollback — the Executor surface is all a repository gets, so the
// transaction's lifetime stays with DB.WriteTx, the only place that can end it.
type sqliteTx struct {
	tx      *sql.Tx
	scope   Scope
	dialect Dialect
}

func (t *sqliteTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, query, args...)
}

func (t *sqliteTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, query, args...)
}

func (t *sqliteTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(ctx, query, args...)
}

func (t *sqliteTx) Dialect() Dialect { return t.dialect }

func (t *sqliteTx) Scope() Scope { return t.scope }

func (t *sqliteTx) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return t.tx.PrepareContext(ctx, query)
}

// WriteTx opens a write transaction on the single writer handle — SQLite
// semantics preserved: the existing DSN's _txlock=immediate makes the BEGIN
// take the write lock up front, under the busy handler, exactly as every
// pre-contract BeginTx call did — validates the scope first (a zero or
// tenant-less scope fails closed before the connection is touched), runs fn,
// and on success runs its returned post closure AFTER commit. If fn fails or
// the commit fails, post is discarded and the transaction is rolled back. post
// runs outside any transaction.
//
// The post-commit closure is the contract's answer to the existing
// "commit, then publish" pattern (ingest's touchPost, fault outcomes, …):
// everything that must happen after durability — and must NOT happen when the
// transaction rolled back — is what fn returns, so the two can never be
// accidentally reordered by a future caller.
func (d *DB) WriteTx(ctx context.Context, s Scope, fn func(WriteTx) (post func(), err error)) error {
	if err := s.Validate(); err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	wtx := &sqliteTx{tx: tx, scope: s, dialect: DialectSQLite}
	post, err := fn(wtx)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if post != nil {
		post()
	}
	return nil
}

// ReadTx runs fn against the read pool inside a read-only transaction. The
// transaction itself is the ordinary deferred BEGIN on a pool connection that
// the query_only pragma (see Open) has already made read-only, which is the
// enforcement this store has always relied on; ReadOnly TxOptions are not
// used because driver support for them varies and the pragma is stronger.
// fn receives an Executor — not a WriteTx — so a read path cannot even reach
// for the SQLiteTx bridge or a write; read-side tenant enforcement arrives
// with the PostgreSQL adapter's RLS policy.
func (d *DB) ReadTx(ctx context.Context, s Scope, fn func(Executor) error) error {
	if err := s.Validate(); err != nil {
		return err
	}
	tx, err := d.Read().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	return fn(&sqliteTx{tx: tx, scope: s, dialect: DialectSQLite})
}

// AdaptTx wraps an already-open *sql.Tx as a WriteTx for a transaction OWNER
// that still manages its own BeginTx/Commit/Rollback (the packages on the
// 014B ledger) and for tests that need to hand a WriteTx-typed entry point a
// transaction whose lifetime they control. This is the safe direction of the
// old migration seam: *sql.Tx → WriteTx loses nothing, while the removed
// SQLiteTx bridge went the other way and let code reach a raw handle back out
// of a WriteTx — the scope bypass CLOUD-015 deleted. Owners should prefer
// DB.WriteTx and are migrated onto it as their 014B slices land.
//
// scope must be the scope the owner opened the transaction under; domain code
// downstream asserts on it.
func AdaptTx(tx *sql.Tx, s Scope) WriteTx {
	return &sqliteTx{tx: tx, scope: s, dialect: DialectSQLite}
}
