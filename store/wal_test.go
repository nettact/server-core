package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// journal_size_limit is what lets the WAL file shrink back after a balloon
// (a pinned reader once grew it to gigabytes of dead space that survived the
// pin). It rides in the shared DSN pragma string, so the thing that can break
// silently is the plumbing: a driver upgrade that stops honoring the pragma in
// DSN form would leave every new connection at the -1 default and nothing
// would fail until the next balloon. Assert it on BOTH pools — each has its
// own DSN and its own connections.
func TestJournalSizeLimitIsSetOnBothPools(t *testing.T) {
	db := storetest.Open(t)
	const want = 67108864
	var got int64
	if err := db.QueryRow(`PRAGMA journal_size_limit`).Scan(&got); err != nil {
		t.Fatalf("write handle: %v", err)
	}
	if got != want {
		t.Errorf("write handle journal_size_limit = %d, want %d", got, want)
	}
	if err := db.Read().QueryRow(`PRAGMA journal_size_limit`).Scan(&got); err != nil {
		t.Fatalf("read pool: %v", err)
	}
	if got != want {
		t.Errorf("read pool journal_size_limit = %d, want %d", got, want)
	}
}

// The watchdog helpers are trivial wiring, but they are wiring the watchdog
// trusts blind: WALSize must see the real -wal file next to the database, and
// Checkpoint must parse the PRAGMA's three-column row. Exercise both against a
// database that has actually written something.
func TestWALSizeAndCheckpoint(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO app_settings(key, value) VALUES('wal_test','x')`); err != nil {
		t.Fatalf("write: %v", err)
	}
	size, err := db.WALSize()
	if err != nil {
		t.Fatalf("WALSize: %v", err)
	}
	if size <= 0 {
		t.Errorf("WALSize = %d after a write, want > 0", size)
	}
	frames, backfilled, err := db.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if frames <= 0 || backfilled != frames {
		t.Errorf("Checkpoint frames=%d backfilled=%d, want a fully backfilled non-empty log", frames, backfilled)
	}
}

// A reader holding a snapshot is what stalls checkpointing in production, and
// the watchdog can only see it through the frame counts: a passive checkpoint
// reports success in this very situation, so a test that trusted the PRAGMA's
// busy column would pass while the real signal went unread.
func TestCheckpointReportsAPinnedReaderThroughFrameCounts(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO app_settings(key, value) VALUES('pin_a','1')`); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if _, _, err := db.Checkpoint(ctx); err != nil {
		t.Fatalf("drain checkpoint: %v", err)
	}

	// Open a read transaction and leave it open, then write past its snapshot.
	tx, err := db.Read().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin reader: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	var seen string
	if err := tx.QueryRowContext(ctx,
		`SELECT value FROM app_settings WHERE key='pin_a'`).Scan(&seen); err != nil {
		t.Fatalf("reader query: %v", err)
	}
	for i := range 50 {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO app_settings(key, value) VALUES(?, ?)`,
			fmt.Sprintf("pin_%d", i), "x"); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	frames, backfilled, err := db.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if backfilled >= frames {
		t.Fatalf("Checkpoint frames=%d backfilled=%d: the held read transaction should have stopped the back-fill short", frames, backfilled)
	}
}

// A checkpoint that loses the checkpoint lock reports busy and leaves both
// counters at -1. Returning those raw would make frames-minus-backfilled zero,
// i.e. a stalled checkpoint indistinguishable from a clean drain, so the busy
// row has to surface as ErrCheckpointBusy instead of as counts.
func TestCheckpointBusyIsNotMistakenForADrain(t *testing.T) {
	path := filepath.Join(storetest.Dir(t), "busy.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO app_settings(key, value) VALUES('busy','1')`); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Hold a read snapshot open. A TRUNCATE checkpoint waits for readers to
	// clear, and it holds SQLite's checkpoint lock the whole time it waits —
	// which is the contention this test needs.
	reader, err := db.Read().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin reader: %v", err)
	}
	readerDone := false
	releaseReader := func() {
		if !readerDone {
			readerDone = true
			_ = reader.Rollback()
		}
	}
	defer releaseReader()
	var v string
	if err := reader.QueryRowContext(ctx,
		`SELECT value FROM app_settings WHERE key='busy'`).Scan(&v); err != nil {
		t.Fatalf("reader query: %v", err)
	}

	other, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatalf("open second handle: %v", err)
	}
	defer other.Close()
	blocking := make(chan struct{})
	go func() {
		defer close(blocking)
		var b, l, c int
		_ = other.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&b, &l, &c)
	}()
	// Once the competing TRUNCATE owns the checkpoint lock it keeps it until the
	// reader below is released, so the only timing-sensitive part is it STARTING.
	// Retries are spaced rather than tight: probing is itself a checkpoint, and a
	// hot loop wins the lock often enough to starve the very contention under
	// test (a 20 ms poll never observes busy at all). Wide gaps leave the lock
	// free for the goroutine to take and hold.
	var sawBusy bool
	for attempt := 0; attempt < 12 && !sawBusy; attempt++ {
		time.Sleep(500 * time.Millisecond)
		frames, backfilled, err := db.Checkpoint(ctx)
		switch {
		case errors.Is(err, store.ErrCheckpointBusy):
			sawBusy = true
			if frames != 0 || backfilled != 0 {
				t.Errorf("busy Checkpoint returned counts frames=%d backfilled=%d, want both zero so no caller can subtract the -1 sentinels into a false clean drain", frames, backfilled)
			}
		case err != nil:
			t.Fatalf("Checkpoint: %v", err)
		case frames < 0 || backfilled < 0:
			t.Fatalf("Checkpoint leaked sentinel counters frames=%d backfilled=%d", frames, backfilled)
		}
	}
	if !sawBusy {
		t.Fatal("never observed a contended checkpoint; the competing TRUNCATE should have taken the checkpoint lock and held it while the reader stayed open")
	}

	releaseReader() // let the TRUNCATE finish instead of burning its busy_timeout
	<-blocking
}
