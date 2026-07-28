// Package store opens the SQLite database (pure-Go modernc driver, CGO-free)
// and applies embedded migrations. It is shared by every server-core module.
package store

import (
	"database/sql"
	"fmt"

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
const dsnPragmas = "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)" +
	"&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_pragma=auto_vacuum(INCREMENTAL)" +
	"&_pragma=cache_size(-65536)&_pragma=mmap_size(268435456)&_pragma=temp_store(MEMORY)"

// Open opens (creating if needed) the SQLite database at path, applies pending
// migrations, and returns a ready DB with separate write and read handles.
func Open(path string) (*DB, error) {
	w, err := sql.Open("sqlite", path+dsnPragmas)
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
