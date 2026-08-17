package ingest

// This file is the ingest characterization suite: it pins, against the
// CURRENT implementation, the observable behavior the extraction of
// ApplyPacketTx must not change. The existing tests are the contract; these
// pin the seams that extraction is most likely to disturb (replay admission,
// watermark semantics, rollback atomicity, post-commit ordering, the
// data-plane failure contract). They were written and run green BEFORE the
// extraction and must pass unchanged afterwards.
//
// Where a characterization can only be observed through the extracted API
// (the in-tx generation re-check, which no single Ingest call can interpose
// between the pre-tx read and the transaction), the same test also exists in
// apply_test.go against ApplyPacketTx directly; the comment on each test says
// so.

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/incidentops"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/tsstore"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

// charReceipt returns the stored fingerprint for one (agent, epoch, sequence)
// slot and whether the slot exists.
func charReceipt(t *testing.T, db *store.DB, agentID string, epoch, seq uint64) (string, bool) {
	t.Helper()
	var fp string
	err := db.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM packet_receipts WHERE agent_id=? AND enrollment_epoch=? AND sequence=?`,
		agentID, epoch, seq).Scan(&fp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read receipt (%s,%d,%d): %v", agentID, epoch, seq, err)
	}
	return fp, true
}

// charHarness is the shared fixture: one site, one agent, one default monitor
// group and one ICMP target — the minimal real world an availability round
// can be judged in.
type charHarness struct {
	t   *testing.T
	db  *store.DB
	m   *metrics.Store
	bus *eventbus.Bus
	ctx context.Context
}

func newCharHarness(t *testing.T, ts tsstore.SeriesStore) *charHarness {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_a','site_default',x'00','h','online')`)
	exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents) VALUES('mg','site_default','Default',1,0,1)`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	      VALUES('t_icmp','site_default','mg','icmp','Router','192.168.1.1','{}',1,1)`)
	if ts == nil {
		ts = tsstoretest.Open(t)
	}
	return &charHarness{t: t, db: db, m: metrics.New(db, ts), bus: eventbus.New(), ctx: ctx}
}

func (h *charHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(h.ctx, q, args...); err != nil {
		h.t.Fatalf("exec %q: %v", q, err)
	}
}

// icmpRounds returns n consecutive ICMP rounds ending ~now, each carrying the
// sent-count the round-completeness rule demands. loss 100 = a failing round,
// loss 0 = a healthy one.
func icmpRounds(n int, loss, rttMs float64) []telemetry.Metric {
	base := time.Now().Unix() - int64(2*n)
	ms := make([]telemetry.Metric, 0, 3*n)
	for i := range n {
		ts := time.Unix(base+int64(2*i), 0).UTC()
		ms = append(ms,
			telemetry.Metric{TS: ts, Kind: telemetry.ICMPLoss, Target: "192.168.1.1",
				Value: loss, Unit: telemetry.UnitPct, MonitorID: "t_icmp", ConfigSerial: 1},
			telemetry.Metric{TS: ts, Kind: telemetry.ICMPSent, Target: "192.168.1.1",
				Value: float64(pcfg.PingCount(pcfg.ProbeParams{})), Unit: telemetry.UnitCount,
				MonitorID: "t_icmp", ConfigSerial: 1},
			telemetry.Metric{TS: ts, Kind: telemetry.ICMPRTTms, Target: "192.168.1.1",
				Value: rttMs, Unit: telemetry.UnitMs, MonitorID: "t_icmp", ConfigSerial: 1},
		)
	}
	return ms
}

// charPacket builds one telemetry packet for agent_a, sequence seq.
func charPacket(seq uint64, ms []telemetry.Metric) telemetry.Packet {
	return telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_a", SiteID: "site_default",
		Sequence: seq, SentAt: time.Now().UTC(), Metrics: ms,
	}
}

// stateSnapshot is everything the characterization tests compare across a
// replay or a rollback: the relational state ingest's transaction writes.
type stateSnapshot struct {
	high       int
	signals    int
	incidents  int
	timeline   int
	deliveries int
	detectors  int
	failRounds int
	rawSamples int
	latestRTT  float64
}

func (h *charHarness) snapshot() stateSnapshot {
	h.t.Helper()
	s := stateSnapshot{}
	qr := func(dst any, q string, args ...any) {
		h.t.Helper()
		if err := h.db.Read().QueryRowContext(h.ctx, q, args...).Scan(dst); err != nil {
			h.t.Fatalf("%s: %v", q, err)
		}
	}
	qr(&s.high, `SELECT high_sequence FROM agents WHERE id='agent_a'`)
	qr(&s.signals, `SELECT COUNT(*) FROM fault_signals WHERE agent_id='agent_a'`)
	qr(&s.incidents, `SELECT COUNT(*) FROM incidents`)
	qr(&s.timeline, `SELECT COUNT(*) FROM incident_timeline`)
	qr(&s.deliveries, `SELECT COUNT(*) FROM notification_deliveries`)
	qr(&s.detectors, `SELECT COUNT(*) FROM detector_state WHERE agent_id='agent_a'`)
	if s.detectors > 0 {
		qr(&s.failRounds, `SELECT fail_rounds FROM detector_state WHERE agent_id='agent_a' LIMIT 1`)
	}
	ids, err := h.m.ResolveSeriesIDs(h.ctx, "site_default", "agent_a", "t_icmp", string(telemetry.ICMPRTTms), "192.168.1.1")
	if err != nil {
		h.t.Fatalf("ResolveSeriesIDs: %v", err)
	}
	if len(ids) > 0 {
		rc, err := h.m.CountRange(h.ctx, ids, 0, 0)
		if err != nil {
			h.t.Fatalf("CountRange: %v", err)
		}
		s.rawSamples = int(rc.Samples)
	}
	latest, err := h.m.LatestPerSeries(h.ctx, "agent_a", string(telemetry.ICMPRTTms), "192.168.1.1", 0)
	if err != nil {
		h.t.Fatalf("LatestPerSeries: %v", err)
	}
	if len(latest) > 0 {
		s.latestRTT = latest[0].Value
	}
	return s
}

// TestCharacterizationDuplicateReplayAdvancesNothing pins the replay contract
// end to end: re-serving an identical (agent, epoch, sequence) acks with the
// watermark restated and advances NOTHING — detector state, incidents,
// timeline (the outbox the ingest path writes), notification deliveries, the
// latest cache and the TSDB appends are all bit-identical afterwards.
func TestCharacterizationDuplicateReplayAdvancesNothing(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, fault.New(h.db, h.bus, nil), nil, nil)

	// Three failing rounds confirm an availability fault: a signal, an open
	// incident, timeline rows and detector state all exist to be disturbed.
	pkt := charPacket(5, icmpRounds(fault.DefaultDetection().FailRounds, 100, 300))
	ack, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, pkt)
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("admission: ack=%+v err=%v", ack, err)
	}
	before := h.snapshot()
	if before.signals == 0 || before.incidents == 0 || before.detectors == 0 || before.rawSamples == 0 {
		t.Fatalf("fixture did not confirm a fault: %+v", before)
	}

	ack, err = svc.Ingest(h.ctx, "agent_a", "site_default", 1, pkt)
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("replay: ack=%+v err=%v", ack, err)
	}
	after := h.snapshot()
	if after != before {
		t.Fatalf("replay advanced state:\n before=%+v\n  after=%+v", before, after)
	}
}

// TestCharacterizationSequenceGapAdmitsAndWatermarkFollowsMax pins the shared
// allocator gap contract: sequence 1 then 5 (never 2-4) both admit, and the
// ack watermark follows the maximum committed sequence.
func TestCharacterizationSequenceGapAdmitsAndWatermarkFollowsMax(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)
	t0 := time.Now().UTC().Add(-time.Minute)

	mk := func(seq uint64) telemetry.Packet {
		return telemetry.Packet{
			SchemaVersion: protocol.SchemaVersion, AgentID: "agent_a", SiteID: "site_default",
			Sequence: seq, SentAt: t0,
			Events: []telemetry.Event{{
				ID: "evt-" + time.Duration(seq).String(), TS: t0,
				Type: telemetry.EventIfaceDown, Severity: telemetry.SeverityWarn, Message: "m",
			}},
		}
	}
	ack, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, mk(1))
	if err != nil || ack.HighestSequence != 1 {
		t.Fatalf("seq 1: ack=%+v err=%v", ack, err)
	}
	ack, err = svc.Ingest(h.ctx, "agent_a", "site_default", 1, mk(5))
	if err != nil || ack.HighestSequence != 5 {
		t.Fatalf("seq 5: ack=%+v err=%v", ack, err)
	}
	var high int
	if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil {
		t.Fatal(err)
	}
	if high != 5 {
		t.Fatalf("high_sequence=%d, want 5 (watermark follows MAX)", high)
	}
	var events int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_a'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatalf("events=%d, want 2 (both packets admitted)", events)
	}
}

// TestCharacterizationOldSequenceDifferentFingerprintConflicts pins the
// below-watermark conflict: a sequence at or below the watermark carrying
// different content than its receipt is ErrSequenceConflict — nothing
// commits, no ack goes out.
func TestCharacterizationOldSequenceDifferentFingerprintConflicts(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)
	t0 := time.Now().UTC().Add(-time.Minute)

	mk := func(seq uint64, msg string) telemetry.Packet {
		return telemetry.Packet{
			SchemaVersion: protocol.SchemaVersion, AgentID: "agent_a", SiteID: "site_default",
			Sequence: seq, SentAt: t0,
			Events: []telemetry.Event{{
				ID: "evt-" + time.Duration(seq).String(), TS: t0,
				Type: telemetry.EventIfaceDown, Severity: telemetry.SeverityWarn, Message: msg,
			}},
		}
	}
	if _, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, mk(5, "original")); err != nil {
		t.Fatalf("seq 5: %v", err)
	}
	if _, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, mk(5, "renumbered content")); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("different-content replay = %v, want ErrSequenceConflict", err)
	}
	var high int
	if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil {
		t.Fatal(err)
	}
	if high != 5 {
		t.Fatalf("high_sequence=%d after conflict, want 5", high)
	}
	var events int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_a'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("events=%d after conflict, want 1 (nothing committed)", events)
	}
}

// TestCharacterizationConcurrentSessionsAdmitExactlyOnce pins the guarded
// UPDATE as the admission gate under real concurrency: N sessions race the
// same (agent, epoch, sequence) with different payloads — exactly one admits,
// every loser reads as a conflict (its fingerprint differs from the winner's
// receipt), and the watermark advances once.
func TestCharacterizationConcurrentSessionsAdmitExactlyOnce(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)
	t0 := time.Now().UTC().Add(-time.Minute)

	const n = 8
	acks := make(chan error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pkt := telemetry.Packet{
				SchemaVersion: protocol.SchemaVersion, AgentID: "agent_a", SiteID: "site_default",
				Sequence: 4, SentAt: t0,
				Events: []telemetry.Event{{
					ID: "evt-race-" + time.Duration(i).String(), TS: t0,
					Type: telemetry.EventIfaceDown, Severity: telemetry.SeverityWarn,
					Message: "payload " + time.Duration(i).String(),
				}},
			}
			_, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, pkt)
			acks <- err
		}(i)
	}
	wg.Wait()
	close(acks)
	var admitted, conflicts int
	for err := range acks {
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, ErrSequenceConflict):
			conflicts++
		default:
			t.Fatalf("unexpected ingest error: %v", err)
		}
	}
	if admitted != 1 {
		t.Fatalf("admitted=%d, want exactly 1 of %d sessions", admitted, n)
	}
	if conflicts != n-1 {
		t.Fatalf("conflicts=%d, want %d (every loser has a different fingerprint)", conflicts, n-1)
	}
	var high int
	if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil {
		t.Fatal(err)
	}
	if high != 4 {
		t.Fatalf("high_sequence=%d, want 4 (advanced exactly once)", high)
	}
	var events int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_a'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("events=%d, want 1 (only the winner's payload committed)", events)
	}
}

// TestCharacterizationObsoleteGenerationFilteredPreTx pins the provenance
// gate's pre-tx half through a single Ingest call: after the target's
// config_serial advances, a backlog packet carrying the old serial is
// admitted (the sequence is real) but its samples are dropped before the
// fault engine or the data plane ever see them. The in-tx re-check half —
// a serial that advances BETWEEN the pre-tx read and the transaction, which
// no single Ingest call can interpose — is pinned by
// TestApplyPacketTxGenerationRecheck in apply_test.go.
func TestCharacterizationObsoleteGenerationFilteredPreTx(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, fault.New(h.db, h.bus, nil), nil, nil)

	ack, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, charPacket(1, icmpRounds(1, 0, 30)))
	if err != nil || ack.HighestSequence != 1 {
		t.Fatalf("current generation: ack=%+v err=%v", ack, err)
	}
	before := h.snapshot()

	// The operator materially edits the target; the agent's WAL still holds
	// rounds produced under generation 1.
	h.exec(`UPDATE probe_tasks SET config_serial=2 WHERE id='t_icmp'`)
	ack, err = svc.Ingest(h.ctx, "agent_a", "site_default", 1, charPacket(2, icmpRounds(1, 100, 300)))
	if err != nil || ack.HighestSequence != 2 {
		t.Fatalf("obsolete generation: ack=%+v err=%v (the sequence itself must still admit)", ack, err)
	}
	after := h.snapshot()
	if after.rawSamples != before.rawSamples {
		t.Fatalf("obsolete-generation samples reached the data plane: raw %d -> %d", before.rawSamples, after.rawSamples)
	}
	if after.failRounds != before.failRounds || after.detectors != before.detectors {
		t.Fatalf("obsolete-generation samples reached the fault engine: before=%+v after=%+v", before, after)
	}
}

// failAfterWriteEvaluator writes one poison row through the transaction and
// then fails — proving that EVERYTHING written in the same transaction,
// including writes made before the failure, rolls back with the batch.
type failAfterWriteEvaluator struct{}

func (failAfterWriteEvaluator) EvaluateAgentTx(ctx context.Context, tx store.WriteTx, agentID, siteID string, rounds []fault.Round) (*fault.Outcome, error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO events(id, agent_id, site_id, ts, type, layer, severity, message, attrs)
		VALUES('evt-poison-eval', 'agent_a', 'site_default', 0, 'custom', '', 'warn', 'poison', '')`); err != nil {
		return nil, err
	}
	return nil, errors.New("evaluator exploded mid-transaction")
}

func (failAfterWriteEvaluator) EvaluateHostTx(ctx context.Context, tx store.WriteTx, agentID, siteID string, rounds []fault.HostRound, mounts map[string]fault.HostMountView) (*fault.Outcome, error) {
	return nil, errors.New("host evaluator exploded mid-transaction")
}

func (failAfterWriteEvaluator) PublishOutcome(context.Context, *fault.Outcome) {}

// TestCharacterizationEvaluatorErrorRollsBackTheWholeBatch pins the fault
// evaluator's rollback contract: an evaluation error withholds the ack, the
// watermark does not advance, and detector/incident/notification/event rows —
// including rows written BEFORE the failure, in the same transaction — are
// all absent. The next replay of the same sequence admits.
func TestCharacterizationEvaluatorErrorRollsBackTheWholeBatch(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, failAfterWriteEvaluator{}, nil, nil)

	// Failing rounds so the evaluator is genuinely reached; one packet event so
	// a write that happened BEFORE the failure also has to roll back.
	pkt := charPacket(7, icmpRounds(fault.DefaultDetection().FailRounds, 100, 300))
	pkt.Events = []telemetry.Event{{
		ID: "evt-pre-eval", TS: time.Now().UTC().Add(-time.Minute),
		Type: telemetry.EventIfaceDown, Severity: telemetry.SeverityWarn, Message: "before the boom",
	}}
	if _, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, pkt); err == nil {
		t.Fatal("ingest with a failing evaluator succeeded")
	}
	s := h.snapshot()
	if s.high != 0 {
		t.Fatalf("high_sequence=%d after rollback, want 0", s.high)
	}
	if s.signals != 0 || s.incidents != 0 || s.timeline != 0 || s.deliveries != 0 || s.detectors != 0 {
		t.Fatalf("relational state survived the rollback: %+v", s)
	}
	if s.rawSamples != 0 {
		t.Fatalf("raw samples reached the data plane after a rollback: %d", s.rawSamples)
	}
	var events int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_a'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("events=%d after rollback, want 0 (packet events AND the poison row must both be gone)", events)
	}
	if _, ok := charReceipt(t, h.db, "agent_a", 1, 7); ok {
		t.Fatal("receipt exists after rollback — the ledger must only hold committed admissions")
	}

	// The retry, same sequence, no failing evaluator: performs the work.
	svc2 := New(h.db, h.bus, h.m, nil, nil, nil)
	ack, err := svc2.Ingest(h.ctx, "agent_a", "site_default", 1, pkt)
	if err != nil || ack.HighestSequence != 7 {
		t.Fatalf("retry: ack=%+v err=%v", ack, err)
	}
}

// failAfterWriteTracer mirrors the evaluator stub on the evidence path.
type failAfterWriteTracer struct{}

func (failAfterWriteTracer) IngestTracesTx(ctx context.Context, tx store.WriteTx, agentID, siteID string, results []telemetry.TraceResult) (*incidentops.TraceOutcome, error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO events(id, agent_id, site_id, ts, type, layer, severity, message, attrs)
		VALUES('evt-poison-trace', 'agent_a', 'site_default', 0, 'custom', '', 'warn', 'poison', '')`); err != nil {
		return nil, err
	}
	return nil, errors.New("trace store exploded mid-transaction")
}

func (failAfterWriteTracer) PublishTraceOutcome(context.Context, *incidentops.TraceOutcome) {}

func (failAfterWriteTracer) IngestScenesTx(ctx context.Context, tx store.WriteTx, agentID, siteID string, reports []telemetry.SceneReport) (*incidentops.SceneOutcome, error) {
	return nil, errors.New("scene store exploded mid-transaction")
}

func (failAfterWriteTracer) PublishSceneOutcome(context.Context, *incidentops.SceneOutcome) {}

// TestCharacterizationEvidenceErrorRollsBackTheWholeBatch pins the same
// rollback contract on the incidentops evidence path (traces/scenes).
func TestCharacterizationEvidenceErrorRollsBackTheWholeBatch(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, failAfterWriteTracer{})

	pkt := charPacket(7, icmpRounds(1, 0, 30))
	pkt.TraceResults = []telemetry.TraceResult{{ReportID: "tr1"}}
	if _, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, pkt); err == nil {
		t.Fatal("ingest with a failing tracer succeeded")
	}
	s := h.snapshot()
	if s.high != 0 || s.detectors != 0 || s.rawSamples != 0 {
		t.Fatalf("state survived the rollback: %+v", s)
	}
	var events int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM events WHERE agent_id='agent_a'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("events=%d after rollback, want 0 (the poison row must be gone)", events)
	}
	if _, ok := charReceipt(t, h.db, "agent_a", 1, 7); ok {
		t.Fatal("receipt exists after rollback")
	}

	// The retry without traces admits the same sequence.
	svc2 := New(h.db, h.bus, h.m, nil, nil, nil)
	ack, err := svc2.Ingest(h.ctx, "agent_a", "site_default", 1, pkt)
	if err != nil || ack.HighestSequence != 7 {
		t.Fatalf("retry: ack=%+v err=%v", ack, err)
	}
}

// failingSeriesStore is a tsstore whose AppendRaw always fails; everything
// else delegates to a real store. It stands in for "the data plane is down
// while the database is fine".
type failingSeriesStore struct {
	tsstore.SeriesStore
	err error
}

func (f failingSeriesStore) AppendRaw(ctx context.Context, samples []tsstore.RawSample) (tsstore.AppendResult, error) {
	return tsstore.AppendResult{}, f.err
}

// TestCharacterizationDataPlaneFailureStillAcks pins the current post-commit
// contract: when the TSDB append fails, the committed ack is still returned
// and the relational state is fully committed — only the chart points are
// missing (the gap's observable form today is the ingest log line, plus the
// returned error once Commit exists; both are asserted in apply_test.go).
func TestCharacterizationDataPlaneFailureStillAcks(t *testing.T) {
	real := tsstoretest.Open(t)
	failing := failingSeriesStore{SeriesStore: real, err: errors.New("disk gone")}
	h := newCharHarness(t, failing)
	svc := New(h.db, h.bus, h.m, fault.New(h.db, h.bus, nil), nil, nil)

	pkt := charPacket(3, icmpRounds(1, 0, 30))
	ack, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, pkt)
	if err != nil {
		t.Fatalf("ingest with a dead data plane must still ack: %v", err)
	}
	if ack.HighestSequence != 3 {
		t.Fatalf("ack=%+v, want the committed watermark 3", ack)
	}
	var high int
	if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil {
		t.Fatal(err)
	}
	if high != 3 {
		t.Fatalf("high_sequence=%d, want 3 (relational commit is complete)", high)
	}
	if _, ok := charReceipt(t, h.db, "agent_a", 1, 3); !ok {
		t.Fatal("receipt missing — the admission must be committed")
	}
	var detectors int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM detector_state WHERE agent_id='agent_a'`).Scan(&detectors); err != nil {
		t.Fatal(err)
	}
	if detectors == 0 {
		t.Fatalf("detector_state rows=%d, want the fault evaluation committed", detectors)
	}
	ids, err := h.m.ResolveSeriesIDs(h.ctx, "site_default", "agent_a", "t_icmp", string(telemetry.ICMPRTTms), "192.168.1.1")
	if err != nil {
		t.Fatalf("ResolveSeriesIDs: %v", err)
	}
	if len(ids) > 0 {
		if rc, err := h.m.CountRange(h.ctx, ids, 0, 0); err != nil || rc.Samples != 0 {
			t.Fatalf("raw samples=%+v err=%v, want 0 (the data plane never got them)", rc, err)
		}
	}
}

// TestCharacterizationPostCommitPublishSeesCommittedState pins the
// post-commit ordering through a bus subscription: the publish callback runs
// after the transaction committed, so it observes the committed row. The
// read pool cannot see the write transaction's uncommitted data, so a
// publish that raced ahead of the commit would observe a missing row and
// fail this test.
func TestCharacterizationPostCommitPublishSeesCommittedState(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, fault.New(h.db, h.bus, nil), nil, nil)

	var handlerErr error
	sawCommitted := false
	h.bus.Subscribe(eventbus.TopicTargetStatusChanged, func(eventbus.Message) {
		var high int
		if err := h.db.Read().QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil {
			handlerErr = err
			return
		}
		sawCommitted = high >= 1
	})

	ack, err := svc.Ingest(h.ctx, "agent_a", "site_default", 1, charPacket(1, icmpRounds(1, 0, 30)))
	if err != nil || ack.HighestSequence != 1 {
		t.Fatalf("ingest: ack=%+v err=%v", ack, err)
	}
	if handlerErr != nil {
		t.Fatalf("publish handler: %v", handlerErr)
	}
	if !sawCommitted {
		t.Fatal("the publish callback could not see the committed watermark — publish ran before commit?")
	}
}
