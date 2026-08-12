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

// receiptFor returns the stored fingerprint for one (epoch, sequence) slot and
// whether the slot exists.
func receiptFor(t *testing.T, db *store.DB, epoch, seq uint64) (string, bool) {
	t.Helper()
	var fp string
	err := db.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM packet_receipts WHERE agent_id='agent_seq' AND enrollment_epoch=? AND sequence=?`,
		epoch, seq).Scan(&fp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read receipt (%d,%d): %v", epoch, seq, err)
	}
	return fp, true
}

func countEvents(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM events WHERE agent_id='agent_seq'`).Scan(&n); err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

// TestSequenceWatermarkDedup pins the high_sequence replay semantics under the
// receipt ledger: a new sequence is processed, persists the watermark, and
// writes its receipt; the same sequence again with the same content is skipped
// but acked at the high; a below-watermark sequence that was never admitted is
// a sequence conflict — the agent WAL's FIFO single-in-flight contract makes a
// legitimate gap impossible, so a slot without a receipt means the sequence
// must not be renumbered in place. A fresh Service on the same DB re-seeds from
// the column and answers the replay from the durable receipt.
func TestSequenceWatermarkDedup(t *testing.T) {
	db, svc := openSeqIngest(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute)

	ack, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(5, t0))
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("seq 5: ack=%+v err=%v", ack, err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("events after seq 5 = %d, want 1", countEvents(t, db))
	}
	var high int
	if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id='agent_seq'`).Scan(&high); err != nil || high != 5 {
		t.Fatalf("high_sequence=%d err=%v, want 5", high, err)
	}
	// The admission wrote its receipt, carrying the content fingerprint.
	fp5, ok := receiptFor(t, db, 1, 5)
	if !ok {
		t.Fatalf("receipt for (epoch 1, seq 5) not written on admission")
	}
	if want := PacketFingerprint(seqPacket(5, t0)); fp5 != want {
		t.Errorf("receipt fingerprint = %q, want %q", fp5, want)
	}

	// Exact replay: skipped, acked at the high, and the receipt is left alone.
	ack, err = svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(5, t0))
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("replay seq 5: ack=%+v err=%v", ack, err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("replay wrote an event")
	}
	if fp, _ := receiptFor(t, db, 1, 5); fp != fp5 {
		t.Errorf("replay rewrote the receipt: %q -> %q", fp5, fp)
	}

	// Below-watermark, never admitted: the slot has no receipt, so this is a
	// conflict, not a duplicate — no ack, no state change.
	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(3, t0)); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("gap seq 3 = %v, want ErrSequenceConflict", err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("conflicting gap wrote an event")
	}
	if fp, ok := receiptFor(t, db, 1, 3); ok {
		t.Fatalf("conflicting gap wrote a receipt: %q", fp)
	}

	// A fresh Service (process restart) seeds from agents.high_sequence and
	// answers the replay from the durable receipt ledger.
	svc2 := New(db, nil, metrics.New(db, tsstoretest.Open(t)), nil, nil, nil)
	ack, err = svc2.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(5, t0))
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("restart replay seq 5: ack=%+v err=%v", ack, err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("restart replay wrote an event")
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
// With the receipt ledger, a refused batch whose slot carries no receipt is a
// sequence conflict: the watermark moved past a sequence this epoch never
// committed, and renumbering it in place is forbidden. Nothing is stored and
// no ack goes out.
//
// A stale in-memory watermark reproduces the loser's exact view: the column has
// moved on, this Service has not noticed.
func TestStaleWatermarkReadDoesNotAdmitTheBatch(t *testing.T) {
	db, svc := openSeqIngest(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute)

	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(1, t0)); err != nil {
		t.Fatalf("seq 1: %v", err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("events after seq 1 = %d, want 1", countEvents(t, db))
	}

	// The winning session committed sequence 5 (and its receipt, as any real
	// admission would); this Service still believes the high is 1, so sequence
	// 3 looks new to it and nothing before the UPDATE can tell it otherwise.
	mustSeqExec(t, db, `UPDATE agents SET high_sequence=5 WHERE id='agent_seq'`)
	mustSeqExec(t, db, `INSERT INTO packet_receipts(agent_id,enrollment_epoch,sequence,fingerprint,received_at)
		VALUES('agent_seq',1,5,?,?)`, PacketFingerprint(seqPacket(5, t0)), time.Now().UTC().Unix())

	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(3, t0)); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("seq 3 on a stale watermark = %v, want ErrSequenceConflict", err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("a batch the guarded UPDATE refused still wrote its events (%d): the pre-transaction "+
			"read admitted work the watermark had already claimed", countEvents(t, db))
	}
	var high int
	if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id='agent_seq'`).Scan(&high); err != nil {
		t.Fatalf("high_sequence: %v", err)
	}
	if high != 5 {
		t.Fatalf("high_sequence=%d, want 5 — a refused batch must not move the watermark", high)
	}

	// The counterpart of the race above: the OTHER session admitted THIS
	// sequence (its receipt exists), so the refused batch is a duplicate of the
	// winner's work, not a conflict — acked at the adopted watermark.
	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(5, t0)); !errors.Is(err, nil) {
		t.Fatalf("duplicate of the winner's batch = %v, want success", err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("a duplicate of the winner's batch wrote its events (%d)", countEvents(t, db))
	}
}

type failingTracer struct{}

func (failingTracer) IngestTracesTx(context.Context, *sql.Tx, string, string, []telemetry.TraceResult) (*incidentops.TraceOutcome, error) {
	return nil, errors.New("boom")
}
func (failingTracer) PublishTraceOutcome(context.Context, *incidentops.TraceOutcome) {}
func (failingTracer) IngestScenesTx(context.Context, *sql.Tx, string, string, []telemetry.SceneReport) (*incidentops.SceneOutcome, error) {
	return nil, errors.New("boom")
}
func (failingTracer) PublishSceneOutcome(context.Context, *incidentops.SceneOutcome) {}

// TestWatermarkNotAdvancedOnRollback pins the 83d427e rule for the sequence
// watermark — now extended to the receipt ledger: a transaction that rolls
// back must leave the column, the in-memory high AND the receipt row
// untouched, and the retried sequence must then perform the work.
func TestWatermarkNotAdvancedOnRollback(t *testing.T) {
	db, _ := openSeqIngest(t)
	ctx := context.Background()
	svc := New(db, nil, metrics.New(db, tsstoretest.Open(t)), nil, nil, failingTracer{})
	t0 := time.Now().UTC().Add(-time.Minute)

	pkt := seqPacket(7, t0)
	pkt.TraceResults = []telemetry.TraceResult{{ReportID: "tr1"}}
	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, pkt); err == nil {
		t.Fatalf("ingest with failing tracer succeeded")
	}
	var high int
	if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id='agent_seq'`).Scan(&high); err != nil || high != 0 {
		t.Fatalf("high_sequence=%d err=%v after rollback, want 0", high, err)
	}
	if _, ok := receiptFor(t, db, 1, 7); ok {
		t.Fatalf("receipt for seq 7 exists after a rollback — the ledger must only hold committed admissions")
	}

	// The retry (same sequence, no traces this time) performs the work.
	ack, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(7, t0))
	if err != nil || ack.HighestSequence != 7 {
		t.Fatalf("retry seq 7: ack=%+v err=%v", ack, err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("events=%d after retry, want 1", countEvents(t, db))
	}
	if fp, ok := receiptFor(t, db, 1, 7); !ok || fp != PacketFingerprint(seqPacket(7, t0)) {
		t.Fatalf("receipt after retry = %q, %v; want the committed fingerprint", fp, ok)
	}
}

// TestReplayWithDifferentContentConflicts: the same (epoch, sequence) served
// with different domain content must be refused with ErrSequenceConflict and
// NO state change — the conflicting batch is rolled back wholesale.
func TestReplayWithDifferentContentConflicts(t *testing.T) {
	db, svc := openSeqIngest(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute)

	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(2, t0)); err != nil {
		t.Fatalf("seq 2: %v", err)
	}
	fp2, ok := receiptFor(t, db, 1, 2)
	if !ok {
		t.Fatalf("receipt for seq 2 missing")
	}
	highBefore := func() int {
		var high int
		if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id='agent_seq'`).Scan(&high); err != nil {
			t.Fatalf("high_sequence: %v", err)
		}
		return high
	}
	if highBefore() != 2 {
		t.Fatalf("high_sequence = %d, want 2", highBefore())
	}

	// Same sequence, different content: a different event message is enough.
	alt := seqPacket(2, t0)
	alt.Events[0].Message = "different content"
	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, alt); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("different-content replay = %v, want ErrSequenceConflict", err)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("conflicting replay wrote events")
	}
	if highBefore() != 2 {
		t.Fatalf("conflicting replay moved the watermark to %d", highBefore())
	}
	if fp, _ := receiptFor(t, db, 1, 2); fp != fp2 {
		t.Fatalf("conflicting replay rewrote the receipt: %q -> %q", fp2, fp)
	}
}

// TestRotationLetsFreshSequenceReAdmit simulates the registry's RotateEpoch
// commit — advance the generation, zero the watermark column — plus the
// ResetSeqWatermark seam, and verifies the fresh WAL's sequence 1 re-admits
// under the new epoch with its own receipt slot, while the old epoch's ledger
// rows stay untouched.
func TestRotationLetsFreshSequenceReAdmit(t *testing.T) {
	db, svc := openSeqIngest(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute)

	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(5, t0)); err != nil {
		t.Fatalf("seq 5 epoch 1: %v", err)
	}
	if _, ok := receiptFor(t, db, 1, 5); !ok {
		t.Fatalf("receipt (1,5) missing")
	}

	// What RotateEpoch commits, and what it calls afterwards.
	mustSeqExec(t, db, `UPDATE agents SET enrollment_epoch=2, high_sequence=0 WHERE id='agent_seq'`)
	svc.ResetSeqWatermark(ctx, "agent_seq")

	ack, err := svc.Ingest(ctx, "agent_seq", "site_default", 2, seqPacket(1, t0))
	if err != nil || ack.HighestSequence != 1 {
		t.Fatalf("fresh seq 1 epoch 2: ack=%+v err=%v", ack, err)
	}
	if fp, ok := receiptFor(t, db, 2, 1); !ok || fp != PacketFingerprint(seqPacket(1, t0)) {
		t.Fatalf("receipt (2,1) = %q, %v; want the admitted fingerprint", fp, ok)
	}
	if _, ok := receiptFor(t, db, 1, 5); !ok {
		t.Fatalf("the old epoch's receipt was disturbed")
	}
}

// TestStaleSessionCannotAdvanceNewEpochFloor pins the epoch-pinned admission:
// a session carrying the PRE-rotation epoch must not advance the new
// generation's watermark — the guarded UPDATE refuses on the epoch mismatch
// and the batch reads as a conflict, with the column untouched.
func TestStaleSessionCannotAdvanceNewEpochFloor(t *testing.T) {
	db, svc := openSeqIngest(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute)

	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(1, t0)); err != nil {
		t.Fatalf("seq 1: %v", err)
	}

	// A rotation (or reinstall) commits under the session: generation 2, a
	// zeroed watermark. The stale session still carries epoch 1.
	mustSeqExec(t, db, `UPDATE agents SET enrollment_epoch=2, high_sequence=0 WHERE id='agent_seq'`)

	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(2, t0)); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("stale-epoch ingest = %v, want ErrSequenceConflict", err)
	}
	var high int
	if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id='agent_seq'`).Scan(&high); err != nil {
		t.Fatalf("high_sequence: %v", err)
	}
	if high != 0 {
		t.Fatalf("high_sequence = %d, want 0 — a stale session must not advance the new epoch's floor", high)
	}
	if countEvents(t, db) != 1 {
		t.Fatalf("stale-epoch batch wrote events")
	}
}

// TestAcceptedFloor: the floor is a straight DB read of the current epoch's
// committed high — the cache reset does not move it.
func TestAcceptedFloor(t *testing.T) {
	_, svc := openSeqIngest(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute)

	floor, err := svc.AcceptedFloor(ctx, "agent_seq")
	if err != nil || floor != 0 {
		t.Fatalf("empty floor = %d, %v; want 0", floor, err)
	}
	if _, err := svc.Ingest(ctx, "agent_seq", "site_default", 1, seqPacket(7, t0)); err != nil {
		t.Fatalf("seq 7: %v", err)
	}
	// The in-memory cache is reset (as after a rotation); the DB column — the
	// committed truth the hub must push — is what it is.
	svc.ResetSeqWatermark(ctx, "agent_seq")
	floor, err = svc.AcceptedFloor(ctx, "agent_seq")
	if err != nil || floor != 7 {
		t.Fatalf("floor after ingest = %d, %v; want 7 (the committed high, not the cache)", floor, err)
	}
	if _, err := svc.AcceptedFloor(ctx, "no_such_agent"); err == nil {
		t.Fatal("AcceptedFloor for a missing agent succeeded")
	}
}
