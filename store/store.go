// Package store opens the SQLite database (pure-Go modernc driver, CGO-free)
// and applies embedded migrations. It is shared by every server-core module.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

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
	path    string  // database file path; "" in hand-built test values
}

// Shared PRAGMAs (DSN form so every pooled connection gets them):
// cache_size is negative-KiB (16 MiB) — the DB is relational control-plane
// data now (agents, config, incidents, dictionaries); the GB-scale samples
// table that once justified a 64 MiB cache + mmap lives in the tsstore data
// plane. mmap stays for cheap reads of the mid-sized tables (events, game).
// wal_autocheckpoint stays at 8192 (32 MiB): ingest still rewrites a small hot
// set (detector rows, the agents row) every commit, and checkpointing 8× less
// often coalesces those rewrites into one back-copy.
//
// journal_size_limit caps what the WAL file shrinks back to after a checkpoint
// that resets the log. Without it, the file keeps its high-water mark forever:
// one connection stuck in a read transaction (a crashed-but-not-collected
// handler, or a driver bug that returns a connection to the pool mid
// transaction) blocks back-fill past its snapshot, the log balloons for as
// long as the pin lasts, and when the pin finally clears the gigabytes stay
// allocated even though only a few MB are live. 64 MiB is 2× the
// autocheckpoint threshold — enough that the normal steady state never
// triggers a truncate, small enough that a balloon is given back.
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
	"&_pragma=cache_size(-16384)&_pragma=mmap_size(268435456)&_pragma=temp_store(MEMORY)" +
	"&_pragma=wal_autocheckpoint(8192)&_pragma=journal_size_limit(67108864)"

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
	db := &DB{DB: w, path: path}
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
	// Recycle read connections instead of keeping them for the process
	// lifetime. A read connection that goes bad silently — the shape observed
	// in production was one returned to the pool with its read transaction
	// still open, which pins the WAL read mark and blocks checkpointing
	// forever — is otherwise immortal: nothing ever closes an idle pool
	// connection by default. Bounded lifetimes turn that from a permanent leak
	// into a ≤30-minute one. This only reaps connections that come BACK to the
	// pool; one checked out and never returned (a leaked Rows) is beyond
	// database/sql's reach, which is what the WAL watchdog's logging is for.
	r.SetConnMaxLifetime(30 * time.Minute)
	r.SetConnMaxIdleTime(5 * time.Minute)
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

// ErrCheckpointBusy reports that the checkpoint never ran because another
// checkpoint held SQLite's checkpoint lock. It is a routine outcome, not a
// fault: the log is untouched and the next attempt can simply try again.
var ErrCheckpointBusy = errors.New("store: checkpoint skipped, another checkpoint holds the lock")

// WALSize reports the current size in bytes of the write-ahead log file, or 0
// if it does not exist (a fresh database, or one whose last close deleted it).
// It is a plain stat — cheap enough for a watchdog to call on a timer.
func (d *DB) WALSize() (int64, error) {
	if d.path == "" {
		return 0, nil
	}
	fi, err := os.Stat(d.path + "-wal")
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return fi.Size(), nil
}

// Checkpoint runs a passive WAL checkpoint on the write handle and reports how
// far it got: walFrames is the total frame count of the log, backfilled is how
// many of those frames have been copied into the database. backfilled falling
// short of walFrames — especially at the same value across successive calls —
// is the signature of a pinned reader: some connection is sitting in a read
// transaction and the checkpoint cannot advance past its snapshot.
//
// The PRAGMA's "busy" column is NOT the stall signal, and the counts are not
// meaningful without it — the two failure modes it distinguishes are easy to
// conflate:
//
//   - A reader pinning the log does NOT set busy. A passive checkpoint copies
//     what it can past no one and reports success, so busy would read 0 in
//     exactly the case this call exists to detect. Only backfilled falling
//     short of walFrames shows it.
//   - Another checkpointer DOES set busy, in passive mode too: the checkpoint
//     takes SQLite's dedicated checkpoint lock before it ever looks at the
//     mode, and failing that lock is reported as busy with both counters left
//     at their -1 sentinel. Ignoring the column there would hand the caller
//     (-1, -1), whose difference is zero — a stalled checkpoint dressed up as
//     a clean drain.
//
// So busy is folded into ErrCheckpointBusy and the counts are returned only
// when they mean something, which keeps the caller's comparison honest.
//
// A passive checkpoint is the same kind wal_autocheckpoint already runs after
// commits, so calling this on a timer adds no new contention beyond briefly
// occupying the write handle.
func (d *DB) Checkpoint(ctx context.Context) (walFrames, backfilled int, err error) {
	var busy int
	if err := d.QueryRowContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`).
		Scan(&busy, &walFrames, &backfilled); err != nil {
		return 0, 0, err
	}
	if busy != 0 {
		return 0, 0, ErrCheckpointBusy
	}
	// Negative counters WITHOUT busy are a different thing entirely: SQLite
	// also answers (0, -1, -1) when the database is not in WAL mode at all.
	// That is no lag rather than a stalled drain, so it reports zeroes — and
	// folding it into ErrCheckpointBusy instead would have callers retrying
	// contention that does not exist. Open always sets journal_mode(WAL), so
	// this is unreachable through this package today; it is handled anyway so
	// the sentinels can never surface as counts a caller would subtract.
	if walFrames < 0 || backfilled < 0 {
		return 0, 0, nil
	}
	return walFrames, backfilled, nil
}

// ReadStats exposes the read pool's counters (in-use vs idle connections) so a
// watchdog can say WHICH side is holding connections when the WAL stops
// checkpointing; database/sql offers no per-connection attribution, so this is
// as close as the standard library gets.
func (d *DB) ReadStats() sql.DBStats {
	return d.Read().Stats()
}
