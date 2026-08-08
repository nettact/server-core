// Package store opens the SQLite database (pure-Go modernc driver, CGO-free)
// and applies embedded migrations. It is shared by every server-core module.
package store

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

// DB carries two handles over the same SQLite file. The embedded *sql.DB is the
// WRITE handle — a single connection, since SQLite has one writer — so all
// existing call sites (ingest, rollup, retention, alert state, config CRUD)
// keep their serialized-writer safety. Read-only paths (chart queries, latest
// snapshots, list endpoints) should go through Read() instead: WAL mode lets
// any number of readers run concurrently with the writer, so putting reads on
// their own small pool keeps a long dashboard query from stalling ingest.
type DB struct {
	*sql.DB         // write handle: MaxOpenConns(1)
	read    *sql.DB // read-only pool; nil in hand-built test values
}

// Shared PRAGMAs (DSN form so every pooled connection gets them):
// cache_size is negative-KiB (64 MiB) and mmap_size 256 MiB — the defaults
// (~2 MiB cache, no mmap) thrash once the samples table grows to GBs.
// wal_autocheckpoint is raised from the default 1000 pages (4 MiB) to 8192
// (32 MiB): ingest rewrites the same hot pages — every series' b-tree tail,
// the dedup and detector rows — on every commit, and each checkpoint copies
// each distinct hot page into the main file once more. Checkpointing 8× less
// often coalesces 8× more of those rewrites into one back-copy, cutting total
// block writes roughly in half for the cost of a WAL that can reach ~32 MiB.
//
// busy_timeout comes first so every pragma after it is already covered by the
// busy handler rather than failing outright on a contended file.
//
// auto_vacuum is deliberately NOT in this list, even though the store depends on
// it (metrics purge reclaims space with `PRAGMA incremental_vacuum`). Setting
// auto_vacuum compiles to a *write* transaction, so as a shared DSN pragma it
// makes every connection either pool opens — read-only ones included — take the
// WAL write lock while it initializes. That is invisible at startup and lethal
// later: both pools create connections on demand, so one appears at an arbitrary
// moment under load, and a transaction that is already open and tries to write
// just then gets SQLITE_BUSY *immediately* — SQLite skips the busy handler once
// the connection holds a transaction, since retrying there could deadlock, so
// busy_timeout does not cover it. It is instead set by Open on a first-run
// database only (see autoVacuumPragma), which is the only time it does anything.
const dsnPragmas = "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" +
	"&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)" +
	"&_pragma=cache_size(-65536)&_pragma=mmap_size(268435456)&_pragma=temp_store(MEMORY)" +
	"&_pragma=wal_autocheckpoint(8192)"

// autoVacuumPragma switches a database to incremental auto-vacuum. It has to
// ride on the connection that creates the file and it has to be in the DSN, not
// a statement: SQLite only accepts the setting while page 1 is still unread, so
// the very first query on the handle is already too late, and the mode cannot be
// changed afterwards without a full VACUUM. Open therefore appends it to the
// write handle's DSN exactly when the file does not exist yet — where the write
// lock it takes is uncontended because nothing else has the database open.
const autoVacuumPragma = "&_pragma=auto_vacuum(INCREMENTAL)"

// Open opens (creating if needed) the SQLite database at path, applies pending
// migrations, and returns a ready DB with separate write and read handles.
func Open(path string) (*DB, error) {
	// _txlock=immediate makes every transaction on the write handle start as
	// BEGIN IMMEDIATE. The default deferred BEGIN only takes the write lock on
	// the first mutation, and an upgrade that finds the lock held fails with
	// SQLITE_BUSY on the spot — SQLite does not invoke the busy handler once the
	// connection is inside a transaction, so busy_timeout does not cover it and a
	// perfectly ordinary write dies instead of waiting its turn. Taking the lock
	// up front puts the wait back under the busy handler. It costs no
	// concurrency: the write pool is one connection, so these were serialized
	// already.
	writeDSN := path + dsnPragmas + "&_txlock=immediate"
	if isFreshDatabase(path) {
		writeDSN += autoVacuumPragma
	}
	w, err := sql.Open("sqlite", writeDSN)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite has a single writer; cap the write pool to avoid SQLITE_BUSY churn.
	w.SetMaxOpenConns(1)
	if err := w.Ping(); err != nil {
		w.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	db := &DB{DB: w}
	if err := db.migrate(); err != nil {
		w.Close()
		return nil, err
	}

	// Read pool: query_only guards against accidental writes sneaking onto a
	// reader connection (which would fight the single writer for the lock).
	r, err := sql.Open("sqlite", path+dsnPragmas+"&_pragma=query_only(ON)")
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("open sqlite reader: %w", err)
	}
	r.SetMaxOpenConns(6)
	if err := r.Ping(); err != nil {
		r.Close()
		w.Close()
		return nil, fmt.Errorf("ping sqlite reader: %w", err)
	}
	db.read = r
	return db, nil
}

// Read returns the read-only pool, falling back to the write handle when the
// DB was constructed without one (tests wrapping a bare *sql.DB).
func (d *DB) Read() *sql.DB {
	if d.read != nil {
		return d.read
	}
	return d.DB
}

// isFreshDatabase reports whether path has no database in it yet, so Open knows
// whether the handle it is about to build is the one that will create the file.
// A zero-length file counts as fresh: that is how SQLite itself treats one, and
// it is what a half-finished first run leaves behind. Guessing wrong is cheap in
// both directions — a false positive sets a mode the file already has, a false
// negative leaves auto-vacuum off on a database that will simply grow instead of
// reclaiming pages — so a stat error is not worth failing Open over.
func isFreshDatabase(path string) bool {
	fi, err := os.Stat(path)
	return err != nil || fi.Size() == 0
}

// Close closes both handles.
//
// Each connection drops its memory map first. Both pools are opened with a
// 256 MiB mmap_size, and on Windows a mapped file stays locked until the mapping
// is released — which the OS may do a little after the handle closes. Without
// this the database file can still be locked immediately after Close returns,
// which shows up as a failure to delete the directory holding it (and, for a
// desktop user, as an "in use" error when relocating or removing the data
// directory right after shutdown). Setting mmap_size to 0 unmaps synchronously,
// so Close returning really does mean the file is free.
func (d *DB) Close() error {
	if d.read != nil {
		_, _ = d.read.Exec(`PRAGMA mmap_size=0`)
		_ = d.read.Close()
	}
	_, _ = d.DB.Exec(`PRAGMA mmap_size=0`)
	return d.DB.Close()
}
