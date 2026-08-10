package ingest

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/incidentops"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

func openSeqIngest(t *testing.T) (*store.DB, *Service) {
	t.Helper()
	db := storetest.Open(t)
	now := time.Now().UTC()
	mustSeqExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	mustSeqExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_seq','site_default',x'00','h','online')`)
	return db, New(db, nil, metrics.New(db, tsstoretest.Open(t)), nil, nil, nil)
}

func mustSeqExec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %s: %v", q, err)
	}
}

func seqPacket(seq uint64, ts time.Time) telemetry.Packet {
	return telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_seq", SiteID: "site_default",
		Sequence: seq, SentAt: ts,
		Events: []telemetry.Event{{
			ID: "evt-" + time.Duration(seq).String(), TS: ts,
			Type: telemetry.EventIfaceDown, Severity: telemetry.SeverityWarn, Message: "m",
		}},
	}
}

// TestSequenceWatermarkDedup pins the high_sequence replay semantics: a new
// sequence is processed and persists the watermark; the same sequence again is
// skipped but acked at the high; a lower never-seen sequence is skipped too —
// the agent WAL's FIFO single-in-flight contract makes a legitimate gap
// impossible, so below-watermark means replay, full stop. A fresh Service on
// the same DB re-seeds from the column.
func TestSequenceWatermarkDedup(t *testing.T) {
	db, svc := openSeqIngest(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute)

	ack, err := svc.Ingest(ctx, "agent_seq", "site_default", seqPacket(5, t0))
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("seq 5: ack=%+v err=%v", ack, err)
	}
	var events int
	countEvents := func() int {
		t.Helper()
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_seq'`).Scan(&events); err != nil {
			t.Fatalf("count events: %v", err)
		}
		return events
	}
	if countEvents() != 1 {
		t.Fatalf("events after seq 5 = %d, want 1", events)
	}
	var high int
	if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id='agent_seq'`).Scan(&high); err != nil || high != 5 {
		t.Fatalf("high_sequence=%d err=%v, want 5", high, err)
	}

	// Exact replay: skipped, acked at the high.
	ack, err = svc.Ingest(ctx, "agent_seq", "site_default", seqPacket(5, t0))
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("replay seq 5: ack=%+v err=%v", ack, err)
	}
	if countEvents() != 1 {
		t.Fatalf("replay wrote an event")
	}

	// Below-watermark, never seen: still a replay by contract.
	ack, err = svc.Ingest(ctx, "agent_seq", "site_default", seqPacket(3, t0))
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("gap seq 3: ack=%+v err=%v", ack, err)
	}
	if countEvents() != 1 {
		t.Fatalf("gap sequence wrote an event")
	}

	// A fresh Service (process restart) seeds from agents.high_sequence.
	svc2 := New(db, nil, metrics.New(db, tsstoretest.Open(t)), nil, nil, nil)
	ack, err = svc2.Ingest(ctx, "agent_seq", "site_default", seqPacket(4, t0))
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("restart gap seq 4: ack=%+v err=%v", ack, err)
	}
	if countEvents() != 1 {
		t.Fatalf("restart gap wrote an event")
	}
}

// TestStaleWatermarkReadDoesNotAdmitTheBatch pins the admission gate. The
// replay check reads the watermark BEFORE the transaction, which is a
// check-then-act: two sessions for one agent (hub supersession closes the old
// socket asynchronously, so they overlap briefly) can read the same value and
// both call their packet new. Only the guarded UPDATE can settle it, so its
// RowsAffected — not the earlier read — has to decide whether the batch is
// processed. Otherwise the loser re-runs detector evaluation and re-stores the
// batch under a sequence the winner already claimed.
//
// A stale in-memory watermark reproduces the loser's exact view: the column has
// moved on, this Service has not noticed.
func TestStaleWatermarkReadDoesNotAdmitTheBatch(t *testing.T) {
	db, svc := openSeqIngest(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute)

	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", seqPacket(1, t0)); err != nil {
		t.Fatalf("seq 1: %v", err)
	}
	countEvents := func() int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_seq'`).Scan(&n); err != nil {
			t.Fatalf("count events: %v", err)
		}
		return n
	}
	if countEvents() != 1 {
		t.Fatalf("events after seq 1 = %d, want 1", countEvents())
	}

	// The winning session committed sequence 5; this Service still believes the
	// high is 1, so sequence 3 looks new to it and nothing before the UPDATE can
	// tell it otherwise.
	mustSeqExec(t, db, `UPDATE agents SET high_sequence=5 WHERE id='agent_seq'`)

	ack, err := svc.Ingest(ctx, "agent_seq", "site_default", seqPacket(3, t0))
	if err != nil {
		t.Fatalf("seq 3 on a stale watermark: %v", err)
	}
	if countEvents() != 1 {
		t.Fatalf("a batch the guarded UPDATE refused still wrote its events (%d): the pre-transaction "+
			"read admitted work the watermark had already claimed", countEvents())
	}
	if ack.HighestSequence != 5 {
		t.Fatalf("ack.HighestSequence=%d, want 5 — the ack must restate the committed watermark", ack.HighestSequence)
	}
	var high int
	if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id='agent_seq'`).Scan(&high); err != nil {
		t.Fatalf("high_sequence: %v", err)
	}
	if high != 5 {
		t.Fatalf("high_sequence=%d, want 5 — a refused batch must not move the watermark", high)
	}
}

type failingTracer struct{}

func (failingTracer) IngestTracesTx(context.Context, *sql.Tx, string, string, []telemetry.TraceResult) (*incidentops.TraceOutcome, error) {
	return nil, errors.New("boom")
}
func (failingTracer) PublishTraceOutcome(context.Context, *incidentops.TraceOutcome) {}

// TestWatermarkNotAdvancedOnRollback pins the 83d427e rule for the sequence
// watermark: a transaction that rolls back must leave both the column and the
// in-memory high untouched, and the retried sequence must then perform the
// work.
func TestWatermarkNotAdvancedOnRollback(t *testing.T) {
	db, _ := openSeqIngest(t)
	ctx := context.Background()
	svc := New(db, nil, metrics.New(db, tsstoretest.Open(t)), nil, nil, failingTracer{})
	t0 := time.Now().UTC().Add(-time.Minute)

	pkt := seqPacket(7, t0)
	pkt.TraceResults = []telemetry.TraceResult{{ReportID: "tr1"}}
	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", pkt); err == nil {
		t.Fatalf("ingest with failing tracer succeeded")
	}
	var high int
	if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id='agent_seq'`).Scan(&high); err != nil || high != 0 {
		t.Fatalf("high_sequence=%d err=%v after rollback, want 0", high, err)
	}

	// The retry (same sequence, no traces this time) performs the work.
	ack, err := svc.Ingest(ctx, "agent_seq", "site_default", seqPacket(7, t0))
	if err != nil || ack.HighestSequence != 7 {
		t.Fatalf("retry seq 7: ack=%+v err=%v", ack, err)
	}
	var events int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_seq'`).Scan(&events); err != nil || events != 1 {
		t.Fatalf("events=%d err=%v after retry, want 1", events, err)
	}
}

// TestReenrollEpochBlocksStaleSession pins the epoch guard: a packet that read
// its watermark before a reenrollment reset must not fold its sequence into
// the fresh installation's watermark after commit.
func TestReenrollEpochBlocksStaleSession(t *testing.T) {
	db, svc := openSeqIngest(t)
	ctx := context.Background()

	// The stale session read (high=0, epoch=0)…
	_, epoch, err := svc.currentHigh(ctx, "agent_seq")
	if err != nil {
		t.Fatalf("currentHigh: %v", err)
	}
	// …then a reenrollment reset the watermark and bumped the epoch…
	svc.ResetSeqWatermark(ctx, "agent_seq")
	// …and the stale session's post-commit advance must be discarded: the ack
	// restates the sequence (harmless — the socket is dying anyway) but the
	// in-memory high stays 0 so the fresh WAL's sequence 1 is accepted.
	_ = svc.noteCommittedSeq("agent_seq", 5000, epoch, true)
	high, _, err := svc.currentHigh(ctx, "agent_seq")
	if err != nil {
		t.Fatalf("currentHigh 2: %v", err)
	}
	if high != 0 {
		t.Fatalf("stale-epoch advance folded: high=%d, want 0", high)
	}
	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", seqPacket(1, time.Now().UTC())); err != nil {
		t.Fatalf("fresh install seq 1 rejected: %v", err)
	}
	var events int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_seq'`).Scan(&events); err != nil || events != 1 {
		t.Fatalf("events=%d err=%v, want 1 (seq 1 processed)", events, err)
	}
}
