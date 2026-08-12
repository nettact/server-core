package registry

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func TestTouchLastSeenThrottled(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_t','site_default',x'00','h','online')`)
	reg := New(db, 0, eventbus.New())

	if err := reg.TouchLastSeenThrottled(ctx, "agent_t"); err != nil {
		t.Fatalf("first throttled touch: %v", err)
	}
	var first time.Time
	if err := db.QueryRowContext(ctx, `SELECT last_seen_at FROM agents WHERE id='agent_t'`).Scan(&first); err != nil {
		t.Fatalf("read last_seen: %v", err)
	}

	// Within touchInterval the durable value must not move: zero queries, no
	// UPDATE. Prove it by racing the wall clock as little as possible — write a
	// sentinel and confirm the throttled touch leaves it alone.
	sentinel := first.Add(-time.Minute)
	mustExec(t, db, `UPDATE agents SET last_seen_at=? WHERE id='agent_t'`, sentinel)
	if err := reg.TouchLastSeenThrottled(ctx, "agent_t"); err != nil {
		t.Fatalf("second throttled touch: %v", err)
	}
	var got time.Time
	if err := db.QueryRowContext(ctx, `SELECT last_seen_at FROM agents WHERE id='agent_t'`).Scan(&got); err != nil {
		t.Fatalf("read last_seen: %v", err)
	}
	if !got.Equal(sentinel) {
		t.Fatalf("throttled touch wrote last_seen (%v) despite fresh throttle", got)
	}

	// Once the throttle window has passed, the touch writes again. Age the
	// in-memory clock instead of sleeping.
	reg.touchMu.Lock()
	reg.lastTouch["agent_t"] = time.Now().Add(-touchInterval - time.Second)
	reg.touchMu.Unlock()
	if err := reg.TouchLastSeenThrottled(ctx, "agent_t"); err != nil {
		t.Fatalf("due throttled touch: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT last_seen_at FROM agents WHERE id='agent_t'`).Scan(&got); err != nil {
		t.Fatalf("read last_seen: %v", err)
	}
	if got.Equal(sentinel) {
		t.Fatalf("due throttled touch did not write")
	}
}

// A due TouchLastSeenTx inside a transaction that ROLLS BACK must leave the
// throttle due: the post closure is what advances the clock, and it never ran.
// This is the 83d427e class — in-memory state outrunning its transaction turns
// the skip optimization into silent data loss.
func TestTouchLastSeenTxRollbackKeepsDue(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status,last_seen_at) VALUES('agent_t','site_default',x'00','h','online',?)`, now.Add(-time.Hour))
	reg := New(db, 0, eventbus.New())

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	post, err := reg.TouchLastSeenTx(ctx, store.AdaptTx(tx, store.Standalone()), "agent_t")
	if err != nil {
		t.Fatalf("TouchLastSeenTx: %v", err)
	}
	if post == nil {
		t.Fatalf("touch not due despite hour-old last_seen")
	}
	_ = tx.Rollback() // post deliberately NOT called

	// The next transactional touch must still be due and must write.
	tx2, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin2: %v", err)
	}
	post2, err := reg.TouchLastSeenTx(ctx, store.AdaptTx(tx2, store.Standalone()), "agent_t")
	if err != nil {
		t.Fatalf("TouchLastSeenTx 2: %v", err)
	}
	if post2 == nil {
		t.Fatalf("throttle advanced by a rolled-back transaction")
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	post2()

	// And now it is NOT due (committed + post ran).
	tx3, _ := db.BeginTx(ctx, nil)
	post3, err := reg.TouchLastSeenTx(ctx, store.AdaptTx(tx3, store.Standalone()), "agent_t")
	if err != nil {
		t.Fatalf("TouchLastSeenTx 3: %v", err)
	}
	if post3 != nil {
		t.Fatalf("touch due immediately after a committed touch")
	}
	_ = tx3.Rollback()
}

// An offline agent's due transactional touch records the online transition —
// history row and liveness event — exactly like the untrottled path.
func TestTouchTxRecordsTransition(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status,last_seen_at) VALUES('agent_t','site_default',x'00','h','offline',?)`, now.Add(-time.Hour))
	bus := eventbus.New()
	events := 0
	bus.Subscribe(eventbus.TopicAgentLivenessChanged, func(m eventbus.Message) { events++ })
	reg := New(db, 0, bus)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	post, err := reg.TouchLastSeenTx(ctx, store.AdaptTx(tx, store.Standalone()), "agent_t")
	if err != nil || post == nil {
		t.Fatalf("TouchLastSeenTx: post-nil=%v err=%v", post == nil, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	post()

	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM agents WHERE id='agent_t'`).Scan(&status); err != nil || status != "online" {
		t.Fatalf("status=%q err=%v, want online", status, err)
	}
	var hist int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_status_history WHERE agent_id='agent_t' AND status='online'`).Scan(&hist); err != nil || hist != 1 {
		t.Fatalf("history rows=%d err=%v, want 1", hist, err)
	}
	if events != 1 {
		t.Fatalf("liveness events=%d, want 1 (published by post, after commit)", events)
	}
}
