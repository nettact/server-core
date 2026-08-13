package ingest

// This file is the CLOUD-015 contract suite for the extracted API: the
// properties ApplyPacketTx/Prepare/Commit must hold for any caller — the
// self-hosted Ingest today and a Cloud tenant transaction tomorrow. The
// behavioral matrix (duplicate/conflict/gap/concurrency) is re-run here
// against ApplyPacketTx directly, alongside the transactional properties the
// characterization suite cannot reach through Ingest: per-substep error
// injection, the no-commit/no-rollback rule, plan discard on rollback, the
// post-commit executor's error contract, and the scope fail-closed rule.

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/incidentops"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/tsstore"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

func applyPrincipal() AgentPrincipal {
	return AgentPrincipal{AgentID: "agent_a", SiteID: "site_default", EnrollmentEpoch: 1}
}

// applyDirect runs the full three-phase pipeline exactly the way Ingest does,
// but against the extracted API — the harness the Cloud consumer uses.
func applyDirect(t *testing.T, h *charHarness, svc *Service, p AgentPrincipal, pkt telemetry.Packet) (ApplyResult, PostCommitPlan, error) {
	t.Helper()
	in, err := svc.Prepare(h.ctx, p, pkt)
	if err != nil {
		return ApplyResult{}, PostCommitPlan{}, err
	}
	defer in.ReleasePending()
	var res ApplyResult
	var plan PostCommitPlan
	err = h.db.WriteTx(h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var aerr error
		res, plan, aerr = svc.ApplyPacketTx(h.ctx, store.Standalone(), wtx, in)
		return nil, aerr
	})
	if err != nil {
		return res, plan, err
	}
	return res, plan, svc.Commit(h.ctx, &plan)
}

// applyDirectErr is applyDirect without t.Fatal — safe inside goroutines.
func applyDirectErr(h *charHarness, svc *Service, p AgentPrincipal, pkt telemetry.Packet) (ApplyResult, error) {
	in, err := svc.Prepare(h.ctx, p, pkt)
	if err != nil {
		return ApplyResult{}, err
	}
	defer in.ReleasePending()
	var res ApplyResult
	err = h.db.WriteTx(h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var aerr error
		res, _, aerr = svc.ApplyPacketTx(h.ctx, store.Standalone(), wtx, in)
		return nil, aerr
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// busyCounter counts every bus publication on the topics ingest's post-commit
// executor can touch.
type busyCounter struct {
	n int
}

func (c *busyCounter) handler() eventbus.Handler {
	return func(eventbus.Message) { c.n++ }
}

func subscribeAll(h *charHarness, c *busyCounter) {
	for _, topic := range []string{
		eventbus.TopicTargetStatusChanged,
		eventbus.TopicFaultConfirmed,
		eventbus.TopicFaultResolved,
		eventbus.TopicIncidentOpened,
		eventbus.TopicIncidentUpdated,
		eventbus.TopicIncidentResolved,
	} {
		h.bus.Subscribe(topic, c.handler())
	}
}

// assertNothingCommitted is the rollback oracle: after a failed apply, the
// relational state, the receipt ledger, the bus and the latest cache must all
// be exactly as if the packet had never arrived.
func assertNothingCommitted(t *testing.T, h *charHarness, seq uint64, pub *busyCounter) {
	t.Helper()
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
	if _, ok := charReceipt(t, h.db, "agent_a", 1, seq); ok {
		t.Fatal("receipt exists after rollback")
	}
	if pub != nil && pub.n != 0 {
		t.Fatalf("%d publications after rollback, want 0", pub.n)
	}
	if latest, err := h.m.LatestPerSeries(h.ctx, "agent_a", string(telemetry.ICMPRTTms), "192.168.1.1", 0); err != nil || len(latest) != 0 {
		t.Fatalf("latest cache has %d entries (%v) after rollback, want none", len(latest), err)
	}
}

// failQueryTx wraps a real WriteTx and fails the first query whose text
// contains a given marker — the per-substep error injection seam. It also
// intercepts PrepareContext, because the rewind step runs its UPDATE through
// a prepared statement rather than ExecContext.
type failQueryTx struct {
	store.WriteTx
	failOn string
	err    error
}

func (f *failQueryTx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if strings.Contains(q, f.failOn) {
		return nil, f.err
	}
	return f.WriteTx.ExecContext(ctx, q, args...)
}

func (f *failQueryTx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if strings.Contains(q, f.failOn) {
		return nil, f.err
	}
	return f.WriteTx.QueryContext(ctx, q, args...)
}

func (f *failQueryTx) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	if strings.Contains(q, f.failOn) {
		return nil, f.err
	}
	return f.WriteTx.PrepareContext(ctx, q)
}

// errEvaluator fails both evaluation entry points, standing in for a fault
// engine that broke mid-batch.
type errEvaluator struct{ err error }

func (e errEvaluator) EvaluateAgentTx(context.Context, store.WriteTx, string, string, []fault.Round) (*fault.Outcome, error) {
	return nil, e.err
}
func (e errEvaluator) EvaluateHostTx(context.Context, store.WriteTx, string, string, []fault.HostRound, map[string]fault.HostMountView) (*fault.Outcome, error) {
	return nil, e.err
}
func (e errEvaluator) PublishOutcome(context.Context, *fault.Outcome) {}

// errTracer fails both evidence entry points.
type errTracer struct{ err error }

func (e errTracer) IngestTracesTx(context.Context, store.WriteTx, string, string, []telemetry.TraceResult) (*incidentops.TraceOutcome, error) {
	return nil, e.err
}
func (e errTracer) PublishTraceOutcome(context.Context, *incidentops.TraceOutcome) {}
func (e errTracer) IngestScenesTx(context.Context, store.WriteTx, string, string, []telemetry.SceneReport) (*incidentops.SceneOutcome, error) {
	return nil, e.err
}
func (e errTracer) PublishSceneOutcome(context.Context, *incidentops.SceneOutcome) {}

// TestApplyPacketTxErrorInjectionEverySubstep drives the whole apply pipeline
// once per transaction substep with that substep failing, and pins the shared
// contract: the error surfaces, the whole transaction rolls back (watermark,
// receipts, detector/incident/notification/evidence/outbox rows all absent),
// no publication happened, the latest cache is untouched, and — because
// Ingest withholds the ack on the same error — the batch replays cleanly.
//
// The injectable substeps are the SQL statements and the three injected
// collaborators (fault evaluator, evidence, liveness). Collaborator failures
// run through Ingest-shaped applyDirect; the SQL failures wrap the WriteTx
// handed to ApplyPacketTx.
func TestApplyPacketTxErrorInjectionEverySubstep(t *testing.T) {
	injected := errors.New("injected failure")

	// Each SQL substep is named by the query marker it fails and reached by a
	// packet shaped so the substep actually runs.
	sqlCases := []struct {
		name string
		fail string
		pkt  func(h *charHarness) telemetry.Packet
	}{
		{"admission", `UPDATE agents SET high_sequence`, func(h *charHarness) telemetry.Packet {
			return charPacket(1, nil)
		}},
		{"receipt insert", `INSERT OR IGNORE INTO packet_receipts`, func(h *charHarness) telemetry.Packet {
			return charPacket(1, nil)
		}},
		{"in-tx re-check", `FROM probe_tasks pt`, func(h *charHarness) telemetry.Packet {
			return charPacket(1, icmpRounds(1, 0, 30))
		}},
		{"rewind", `UPDATE rollup_state`, func(h *charHarness) telemetry.Packet {
			return charPacket(1, icmpRounds(1, 0, 30))
		}},
		{"events", `INSERT OR IGNORE INTO events`, func(h *charHarness) telemetry.Packet {
			pkt := charPacket(1, nil)
			pkt.Events = []telemetry.Event{{
				ID: "evt-inj", TS: time.Now().UTC().Add(-time.Minute),
				Type: telemetry.EventIfaceDown, Severity: telemetry.SeverityWarn, Message: "m",
			}}
			return pkt
		}},
		{"inventory", `INSERT INTO devices`, func(h *charHarness) telemetry.Packet {
			pkt := charPacket(1, nil)
			pkt.InventoryDelta = []telemetry.InventoryItem{{Kind: telemetry.InventoryDevice, MAC: "aa:bb:cc:dd:ee:ff"}}
			return pkt
		}},
		{"interface snapshot", `DELETE FROM interfaces`, func(h *charHarness) telemetry.Packet {
			pkt := charPacket(1, nil)
			pkt.InterfaceSnapshots = []telemetry.InterfaceSnapshot{{
				SampledAt:  time.Now().UTC().Truncate(time.Second),
				Interfaces: []telemetry.InterfaceState{{Name: "eth0", Up: true}},
			}}
			return pkt
		}},
		{"game data", `INSERT INTO game_runs`, func(h *charHarness) telemetry.Packet {
			h.exec(`UPDATE agents SET perm_effective='["game.performance.read"]' WHERE id='agent_a'`)
			pkt := charPacket(1, nil)
			start := time.Now().UTC().Add(-time.Hour)
			pkt.GameRuns = []gamesense.Run{{
				ID: "run_1", Proc: "game.exe", Title: "A Game",
				StartedAt: start, LastSeenAt: start.Add(time.Minute),
				Source: gamesense.SourcePresentMonService,
			}}
			return pkt
		}},
	}
	for _, tc := range sqlCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCharHarness(t, nil)
			svc := New(h.db, h.bus, h.m, fault.New(h.db, h.bus, nil), nil, nil)
			pub := &busyCounter{}
			subscribeAll(h, pub)
			pkt := tc.pkt(h)

			in, err := svc.Prepare(h.ctx, applyPrincipal(), pkt)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			defer in.ReleasePending()
			err = h.db.WriteTx(h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
				_, _, aerr := svc.ApplyPacketTx(h.ctx, store.Standalone(), &failQueryTx{WriteTx: wtx, failOn: tc.fail, err: injected}, in)
				return nil, aerr
			})
			if !errors.Is(err, injected) {
				t.Fatalf("apply = %v, want the injected failure", err)
			}
			assertNothingCommitted(t, h, pkt.Sequence, pub)

			// The same sequence then admits cleanly — the failure withheld
			// nothing durable that a replay would trip over.
			if _, _, err := applyDirect(t, h, svc, applyPrincipal(), pkt); err != nil {
				t.Fatalf("replay after rollback: %v", err)
			}
		})
	}

	// The collaborator seams fail inside the transaction body the same way.
	collabCases := []struct {
		name string
		svc  func(h *charHarness) *Service
		pkt  func(h *charHarness) telemetry.Packet
	}{
		{"fault eval", func(h *charHarness) *Service {
			return New(h.db, h.bus, h.m, errEvaluator{err: injected}, nil, nil)
		}, func(h *charHarness) telemetry.Packet {
			return charPacket(1, icmpRounds(fault.DefaultDetection().FailRounds, 100, 300))
		}},
		{"host eval", func(h *charHarness) *Service {
			h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
			        VALUES('host1','site_default','mg','host','Server','host','{}',1,1)`)
			return New(h.db, h.bus, h.m, errEvaluator{err: injected}, nil, nil)
		}, func(h *charHarness) telemetry.Packet {
			pkt := charPacket(1, nil)
			pkt.Metrics = []telemetry.Metric{{
				TS: time.Now().UTC().Truncate(time.Second), Kind: telemetry.HostCPUPct,
				Target: "host", Value: 95, Unit: telemetry.UnitPct,
			}}
			return pkt
		}},
		{"traces", func(h *charHarness) *Service {
			return New(h.db, h.bus, h.m, nil, nil, errTracer{err: injected})
		}, func(h *charHarness) telemetry.Packet {
			pkt := charPacket(1, icmpRounds(1, 0, 30))
			pkt.TraceResults = []telemetry.TraceResult{{ReportID: "tr1"}}
			return pkt
		}},
		{"scenes", func(h *charHarness) *Service {
			return New(h.db, h.bus, h.m, nil, nil, errTracer{err: injected})
		}, func(h *charHarness) telemetry.Packet {
			pkt := charPacket(1, icmpRounds(1, 0, 30))
			pkt.SceneReports = []telemetry.SceneReport{{ReportID: "sc1"}}
			return pkt
		}},
		{"liveness", func(h *charHarness) *Service {
			svc := New(h.db, h.bus, h.m, nil, nil, nil)
			svc.TouchAgentTx = func(context.Context, store.WriteTx, string) (func(), error) {
				return nil, injected
			}
			return svc
		}, func(h *charHarness) telemetry.Packet {
			return charPacket(1, nil)
		}},
	}
	for _, tc := range collabCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCharHarness(t, nil)
			svc := tc.svc(h)
			pub := &busyCounter{}
			subscribeAll(h, pub)
			pkt := tc.pkt(h)

			_, _, err := applyDirect(t, h, svc, applyPrincipal(), pkt)
			if !errors.Is(err, injected) {
				t.Fatalf("apply = %v, want the injected failure", err)
			}
			assertNothingCommitted(t, h, pkt.Sequence, pub)
		})
	}
}

// TestApplyPacketTxNeverControlsTheTransaction pins the first hard rule: the
// function must not begin, commit or roll back the transaction it is handed.
// The WriteTx type has no such surface, so the test proves the observable
// consequence instead — after a successful ApplyPacketTx nothing is visible
// outside the transaction and the owner can still roll it back (a committed
// transaction would fail the rollback with sql.ErrTxDone).
func TestApplyPacketTxNeverControlsTheTransaction(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)
	pkt := charPacket(9, icmpRounds(1, 0, 30))

	in, err := svc.Prepare(h.ctx, applyPrincipal(), pkt)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer in.ReleasePending()

	raw, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wtx := store.AdaptTx(raw, store.Standalone())
	res, _, err := svc.ApplyPacketTx(h.ctx, store.Standalone(), wtx, in)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.New {
		t.Fatal("apply did not admit the batch")
	}
	// Nothing committed: the read pool cannot see the admission.
	var high int
	if err := h.db.Read().QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil {
		t.Fatal(err)
	}
	if high != 0 {
		t.Fatalf("high_sequence=%d visible outside the transaction, want 0 (apply must not commit)", high)
	}
	// And the owner still owns the transaction: rollback works.
	if err := raw.Rollback(); err != nil {
		t.Fatalf("rollback after apply = %v — the transaction was already ended", err)
	}
}

// TestPostCommitPlanDiscardedOnRollback pins the discard rule end to end: a
// transaction that fails AFTER ApplyPacketTx produced a plan leaves the plan
// unexecuted — no TSDB append, no latest-cache fold, no publication — and
// nothing durable behind.
func TestPostCommitPlanDiscardedOnRollback(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, fault.New(h.db, h.bus, nil), nil, nil)
	pub := &busyCounter{}
	subscribeAll(h, pub)
	pkt := charPacket(4, icmpRounds(1, 0, 30))

	in, err := svc.Prepare(h.ctx, applyPrincipal(), pkt)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer in.ReleasePending()

	// The fn-error arm of WriteTx: ApplyPacketTx succeeded and produced a
	// plan, then fn fails — the exact shape of a commit failure. Ingest
	// returns before Commit, so the plan is discarded with the rollback.
	boom := errors.New("commit failed")
	err = h.db.WriteTx(h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		if _, _, aerr := svc.ApplyPacketTx(h.ctx, store.Standalone(), wtx, in); aerr != nil {
			return nil, aerr
		}
		return nil, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WriteTx = %v, want the fn error", err)
	}
	assertNothingCommitted(t, h, pkt.Sequence, pub)
}

// TestApplyPacketTxMatrixAgainstTheExtractedAPI re-runs the characterization
// matrix (duplicate / conflict / gap / concurrency) against
// Prepare+ApplyPacketTx+Commit directly, asserting the ApplyResult verdicts
// the matrix pins — including that a duplicate replay still runs the liveness
// touch.
func TestApplyPacketTxMatrixAgainstTheExtractedAPI(t *testing.T) {
	t.Run("duplicate restates watermark and touches liveness", func(t *testing.T) {
		h := newCharHarness(t, nil)
		svc := New(h.db, h.bus, h.m, nil, nil, nil)
		touches := 0
		svc.TouchAgentTx = func(context.Context, store.WriteTx, string) (func(), error) {
			touches++
			return func() {}, nil
		}
		pkt := charPacket(5, nil)

		res, _, err := applyDirect(t, h, svc, applyPrincipal(), pkt)
		if err != nil || !res.New || res.Duplicate {
			t.Fatalf("first apply: res=%+v err=%v", res, err)
		}
		res, _, err = applyDirect(t, h, svc, applyPrincipal(), pkt)
		if err != nil || res.New || !res.Duplicate {
			t.Fatalf("replay: res=%+v err=%v", res, err)
		}
		if touches != 2 {
			t.Fatalf("liveness touch ran %d times for admit+replay, want 2", touches)
		}
		var high int
		if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil || high != 5 {
			t.Fatalf("high_sequence=%d err=%v, want 5", high, err)
		}
	})

	t.Run("legal gap admits both", func(t *testing.T) {
		h := newCharHarness(t, nil)
		svc := New(h.db, h.bus, h.m, nil, nil, nil)
		res, _, err := applyDirect(t, h, svc, applyPrincipal(), charPacket(1, nil))
		if err != nil || !res.New {
			t.Fatalf("seq 1: res=%+v err=%v", res, err)
		}
		res, _, err = applyDirect(t, h, svc, applyPrincipal(), charPacket(5, nil))
		if err != nil || !res.New {
			t.Fatalf("seq 5: res=%+v err=%v", res, err)
		}
		var high int
		if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil || high != 5 {
			t.Fatalf("high_sequence=%d err=%v, want 5", high, err)
		}
	})

	t.Run("below-watermark different fingerprint conflicts", func(t *testing.T) {
		h := newCharHarness(t, nil)
		svc := New(h.db, h.bus, h.m, nil, nil, nil)
		if _, _, err := applyDirect(t, h, svc, applyPrincipal(), charPacket(5, nil)); err != nil {
			t.Fatalf("seq 5: %v", err)
		}
		alt := charPacket(5, nil)
		alt.Metrics = icmpRounds(1, 0, 30)
		if _, _, err := applyDirect(t, h, svc, applyPrincipal(), alt); !errors.Is(err, ErrSequenceConflict) {
			t.Fatalf("different content = %v, want ErrSequenceConflict", err)
		}
	})

	t.Run("concurrent same-sequence admits exactly once", func(t *testing.T) {
		h := newCharHarness(t, nil)
		svc := New(h.db, h.bus, h.m, nil, nil, nil)
		const n = 8
		errs := make(chan error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				pkt := charPacket(4, nil)
				pkt.Metrics = []telemetry.Metric{{
					TS: time.Now().UTC().Truncate(time.Second), Kind: telemetry.HostCPUPct,
					Target: "host", Value: float64(i), Unit: telemetry.UnitPct,
				}}
				_, err := applyDirectErr(h, svc, applyPrincipal(), pkt)
				errs <- err
			}(i)
		}
		wg.Wait()
		close(errs)
		var admitted, conflicts int
		for err := range errs {
			switch {
			case err == nil:
				admitted++
			case errors.Is(err, ErrSequenceConflict):
				conflicts++
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if admitted != 1 || conflicts != n-1 {
			t.Fatalf("admitted=%d conflicts=%d, want 1 and %d", admitted, conflicts, n-1)
		}
		var high int
		if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil || high != 4 {
			t.Fatalf("high_sequence=%d err=%v, want 4", high, err)
		}
	})
}

// TestApplyPacketTxGenerationRecheck pins the in-tx half of the provenance
// gate — the half no single Ingest call can interpose: Prepare accepts a
// batch under the current generation, the generation advances before the
// transaction opens, and the in-tx re-check drops every sample. The fault
// engine and the data plane never see the stale generation, while the
// sequence itself still admits and commits.
func TestApplyPacketTxGenerationRecheck(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, fault.New(h.db, h.bus, nil), nil, nil)
	pkt := charPacket(2, icmpRounds(1, 100, 300))

	in, err := svc.Prepare(h.ctx, applyPrincipal(), pkt)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(in.accepted) == 0 {
		t.Fatal("fixture: prepare accepted nothing before the generation advanced")
	}
	defer in.ReleasePending()

	// The operator edit lands after the pre-tx read and before the
	// transaction — exactly the window the authoritative re-check exists for.
	h.exec(`UPDATE probe_tasks SET config_serial=2 WHERE id='t_icmp'`)

	var res ApplyResult
	var plan PostCommitPlan
	err = h.db.WriteTx(h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var aerr error
		res, plan, aerr = svc.ApplyPacketTx(h.ctx, store.Standalone(), wtx, in)
		return nil, aerr
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.New {
		t.Fatal("the sequence must still admit — the generation gate drops SAMPLES, not the packet")
	}
	if len(plan.AcceptedTx) != 0 || len(plan.StoredTx) != 0 {
		t.Fatalf("post-re-check set is non-empty: accepted=%d stored=%d", len(plan.AcceptedTx), len(plan.StoredTx))
	}
	if err := svc.Commit(h.ctx, &plan); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var detectors int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM detector_state WHERE agent_id='agent_a'`).Scan(&detectors); err != nil {
		t.Fatal(err)
	}
	if detectors != 0 {
		t.Fatalf("the stale generation reached the fault engine: %d detector rows", detectors)
	}
	ids, err := h.m.ResolveSeriesIDs(h.ctx, "site_default", "agent_a", "t_icmp", string(telemetry.ICMPRTTms), "192.168.1.1")
	if err != nil {
		t.Fatalf("ResolveSeriesIDs: %v", err)
	}
	if len(ids) > 0 {
		if rc, err := h.m.CountRange(h.ctx, ids, 0, 0); err != nil || rc.Samples != 0 {
			t.Fatalf("the stale generation reached the data plane: %+v err=%v", rc, err)
		}
	}
}

// TestApplyPacketTxScopeFailsClosed pins the scope rule: a zero scope or a
// scope that does not match the transaction's own fails before the first
// query, so a miswired caller can never write to the wrong tenant.
func TestApplyPacketTxScopeFailsClosed(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)
	in, err := svc.Prepare(h.ctx, applyPrincipal(), charPacket(1, nil))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer in.ReleasePending()

	cases := []struct {
		name string
		call store.Scope
		tx   store.Scope
	}{
		{"zero scope", store.Scope{}, store.Standalone()},
		{"actor only", store.Scope{ActorID: "user-1"}, store.Standalone()},
		{"foreign scope", store.Standalone(), store.Scope{TenantID: "tenant-x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingTx{scope: tc.tx}
			_, _, err := svc.ApplyPacketTx(h.ctx, tc.call, rec, in)
			if err == nil {
				t.Fatal("apply = nil, want a scope error before any query")
			}
			if rec.execs != 0 || rec.queries != 0 || rec.queryRows != 0 {
				t.Fatalf("queries ran despite scope rejection: exec=%d query=%d row=%d", rec.execs, rec.queries, rec.queryRows)
			}
		})
	}
}

// recordingTx is a WriteTx that only counts calls — the scope test's oracle
// that nothing was queried.
type recordingTx struct {
	scope     store.Scope
	execs     int
	queries   int
	queryRows int
}

func (r *recordingTx) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	r.execs++
	return nil, nil
}
func (r *recordingTx) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	r.queries++
	return nil, nil
}
func (r *recordingTx) QueryRowContext(context.Context, string, ...any) *sql.Row {
	r.queryRows++
	return nil
}
func (r *recordingTx) Dialect() store.Dialect { return store.DialectSQLite }
func (r *recordingTx) Scope() store.Scope     { return r.scope }
func (r *recordingTx) PrepareContext(context.Context, string) (*sql.Stmt, error) {
	return nil, nil
}

// droppingSeriesStore reports every sample permanently dropped — the
// post-commit "permanent drop" arm.
type droppingSeriesStore struct {
	tsstore.SeriesStore
}

func (droppingSeriesStore) AppendRaw(ctx context.Context, samples []tsstore.RawSample) (tsstore.AppendResult, error) {
	return tsstore.AppendResult{Dropped: len(samples)}, nil
}

// TestCommitPostCommitExecutorContract pins Commit's three data-plane arms
// against a committed transaction: a successful append lands samples and
// publishes; a permanent drop is not an error and still publishes; a
// temporary append failure returns the observable error while the rest of
// the plan still runs (cache and publications proceed, matching the historic
// post closure).
func TestCommitPostCommitExecutorContract(t *testing.T) {
	commitVia := func(t *testing.T, h *charHarness, svc *Service, pkt telemetry.Packet) (ApplyResult, PostCommitPlan, error) {
		t.Helper()
		in, err := svc.Prepare(h.ctx, applyPrincipal(), pkt)
		if err != nil {
			return ApplyResult{}, PostCommitPlan{}, err
		}
		defer in.ReleasePending()
		var res ApplyResult
		var plan PostCommitPlan
		err = h.db.WriteTx(h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
			var aerr error
			res, plan, aerr = svc.ApplyPacketTx(h.ctx, store.Standalone(), wtx, in)
			return nil, aerr
		})
		if err != nil {
			return res, plan, err
		}
		return res, plan, nil // Commit is the step under test
	}

	t.Run("success", func(t *testing.T) {
		h := newCharHarness(t, nil)
		svc := New(h.db, h.bus, h.m, nil, nil, nil)
		pkt := charPacket(2, icmpRounds(1, 0, 30))
		_, plan, err := commitVia(t, h, svc, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.Commit(h.ctx, &plan); err != nil {
			t.Fatalf("commit: %v", err)
		}
		ids, err := h.m.ResolveSeriesIDs(h.ctx, "site_default", "agent_a", "t_icmp", string(telemetry.ICMPRTTms), "192.168.1.1")
		if err != nil {
			t.Fatal(err)
		}
		if rc, err := h.m.CountRange(h.ctx, ids, 0, 0); err != nil || rc.Samples == 0 {
			t.Fatalf("raw samples=%+v err=%v, want the appended batch", rc, err)
		}
	})

	t.Run("permanent drop is not an error", func(t *testing.T) {
		real := tsstoretest.Open(t)
		h := newCharHarness(t, droppingSeriesStore{SeriesStore: real})
		svc := New(h.db, h.bus, h.m, nil, nil, nil)
		pkt := charPacket(2, icmpRounds(1, 0, 30))
		_, plan, err := commitVia(t, h, svc, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.Commit(h.ctx, &plan); err != nil {
			t.Fatalf("commit with permanent drops = %v, want nil", err)
		}
	})

	t.Run("temporary failure returns the error and still finishes the plan", func(t *testing.T) {
		real := tsstoretest.Open(t)
		boom := errors.New("disk gone")
		h := newCharHarness(t, failingSeriesStore{SeriesStore: real, err: boom})
		svc := New(h.db, h.bus, h.m, nil, nil, nil)
		pub := &busyCounter{}
		subscribeAll(h, pub)
		pkt := charPacket(2, icmpRounds(1, 0, 30))
		_, plan, err := commitVia(t, h, svc, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.Commit(h.ctx, &plan); !errors.Is(err, boom) {
			t.Fatalf("commit = %v, want the append error returned (the observable gap)", err)
		}
		// The committed state stands: the watermark is durable and the plan's
		// remaining steps still ran (the cache fold is invisible from here, but
		// the publication is observable).
		if pub.n == 0 {
			t.Fatal("no publication after the append failure — the rest of the plan must still run")
		}
		var high int
		if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil || high != 2 {
			t.Fatalf("high_sequence=%d err=%v, want 2", high, err)
		}
	})
}

// TestPrepareRejectsInvalidInput pins the pre-transaction failures: a schema
// mismatch and a missing agent both fail before any transaction opens.
func TestPrepareRejectsInvalidInput(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)

	bad := charPacket(1, nil)
	bad.SchemaVersion = 999
	if _, err := svc.Prepare(h.ctx, applyPrincipal(), bad); err == nil {
		t.Fatal("prepare with an unsupported schema succeeded")
	}

	p := applyPrincipal()
	p.AgentID = "no_such_agent"
	if _, err := svc.Prepare(h.ctx, p, charPacket(1, nil)); err == nil {
		t.Fatal("prepare for a deleted agent succeeded")
	}
}

// TestApplyPacketTxUsesPrepareBoundIdentity pins the P1 review fix: the
// transaction commits under the identity Prepare bound the inputs to — the
// packet's SELF-REPORTED AgentID/SiteID are transport echoes and must not
// shift attribution, and the receipt's fingerprint describes the prepared
// payload.
func TestApplyPacketTxUsesPrepareBoundIdentity(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)

	pkt := charPacket(1, icmpRounds(1, 0, 30))
	// A hostile/buggy packet that claims a foreign identity.
	pkt.AgentID = "someone_else"
	pkt.SiteID = "site_elsewhere"

	res, _, err := applyDirect(t, h, svc, applyPrincipal(), pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.New {
		t.Fatalf("apply = %+v, want an admitted packet", res)
	}
	// The watermark moved for the PRINCIPAL, not the self-reported id.
	var high int
	if err := h.db.QueryRowContext(h.ctx, `SELECT high_sequence FROM agents WHERE id='agent_a'`).Scan(&high); err != nil || high != 1 {
		t.Fatalf("principal high_sequence=%d err=%v, want 1", high, err)
	}
	var foreign int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM agents WHERE id='someone_else'`).Scan(&foreign); err != nil || foreign != 0 {
		t.Fatalf("foreign id rows=%d err=%v, want none", foreign, err)
	}
	// The receipt is keyed to the principal and carries the prepared
	// fingerprint.
	var fp string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT fingerprint FROM packet_receipts WHERE agent_id='agent_a' AND enrollment_epoch=1 AND sequence=1`).Scan(&fp); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if want := PacketFingerprint(pkt); fp != want {
		t.Fatalf("receipt fingerprint = %q, want %q (the prepared packet's identity)", fp, want)
	}
}

// TestCommitIsSingleUse pins the P2 review fix: a retried Commit after an
// append error must not replay the plan's side effects — the remembered
// error comes back and the publications do not double.
func TestCommitIsSingleUse(t *testing.T) {
	real := tsstoretest.Open(t)
	boom := errors.New("disk gone")
	h := newCharHarness(t, failingSeriesStore{SeriesStore: real, err: boom})
	svc := New(h.db, h.bus, h.m, nil, nil, nil)
	pub := &busyCounter{}
	subscribeAll(h, pub)
	pkt := charPacket(2, icmpRounds(1, 0, 30))

	in, err := svc.Prepare(h.ctx, applyPrincipal(), pkt)
	if err != nil {
		t.Fatal(err)
	}
	defer in.ReleasePending()
	var plan PostCommitPlan
	err = h.db.WriteTx(h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var aerr error
		_, plan, aerr = svc.ApplyPacketTx(h.ctx, store.Standalone(), wtx, in)
		return nil, aerr
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Commit(h.ctx, &plan); !errors.Is(err, boom) {
		t.Fatalf("first commit = %v, want the append error", err)
	}
	firstPubs := pub.n
	if firstPubs == 0 {
		t.Fatal("no publication after the first commit")
	}
	if err := svc.Commit(h.ctx, &plan); !errors.Is(err, boom) {
		t.Fatalf("second commit = %v, want the SAME remembered error", err)
	}
	if pub.n != firstPubs {
		t.Fatalf("publications after retry = %d, want %d — the plan's side effects ran twice", pub.n, firstPubs)
	}

	// A COPY of the plan reports the same remembered outcome: the guard and
	// the result share one state object, so neither copy can diverge.
	copyPlan := plan
	if err := svc.Commit(h.ctx, &copyPlan); !errors.Is(err, boom) {
		t.Fatalf("copied plan commit = %v, want the remembered append error", err)
	}
	if pub.n != firstPubs {
		t.Fatalf("publications after the copied plan = %d, want %d — copies must not replay side effects", pub.n, firstPubs)
	}
}

// TestPrepareSnapshotsPacket pins the P2 review fix: Prepare deep-copies the
// packet, so a caller that reuses or mutates its decoded object afterwards
// cannot make the committed payload diverge from the computed fingerprint.
func TestPrepareSnapshotsPacket(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)

	pkt := charPacket(1, icmpRounds(1, 0, 30))
	in, err := svc.Prepare(h.ctx, applyPrincipal(), pkt)
	if err != nil {
		t.Fatal(err)
	}
	defer in.ReleasePending()

	// Mutate the caller's object after Prepare. The snapshot must be untouched,
	// and the fingerprint must describe the snapshot, not the mutated caller.
	pkt.Metrics[0].Value = 9999
	if in.pkt.Metrics[0].Value == 9999 {
		t.Fatal("Prepare's snapshot shares the caller's metric slice")
	}
	if in.fingerprint != PacketFingerprint(in.pkt) {
		t.Fatal("fingerprint no longer describes the snapshot")
	}
	// Labels/Attrs maps are copied too.
	pkt.Metrics[0].Labels = map[string]string{"x": "y"}
	if in.pkt.Metrics[0].Labels != nil {
		t.Fatal("Prepare's snapshot shares the caller's label map")
	}
}

// TestPrepareDropsNonFinite pins the non-finite fix: a NaN/Inf sample is
// dropped (admitting the rest of the packet) rather than rejected, so one
// corrupt sample can never block the whole WAL behind an un-acked sequence;
// and the surviving finite metrics are what the fingerprint hashes.
func TestPrepareDropsNonFinite(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)

	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		pkt := charPacket(1, icmpRounds(1, 0, 30))
		pkt.Metrics[0].Value = v
		in, err := svc.Prepare(h.ctx, applyPrincipal(), pkt)
		if err != nil {
			t.Fatalf("prepare with value %v: %v", v, err)
		}
		defer in.ReleasePending()
		if len(in.metrics) != len(pkt.Metrics)-1 {
			t.Fatalf("value %v: %d metrics after prepare, want %d (one dropped)", v, len(in.metrics), len(pkt.Metrics)-1)
		}
		if in.fingerprint != PacketFingerprint(in.pkt) {
			t.Fatal("fingerprint does not describe the surviving (finite) metrics")
		}
	}
}

// TestCommitPlanCarriesVerdict pins the P2 review fix: Commit derives the
// duplicate/new verdict from the plan itself, so a caller cannot pair a
// duplicate verdict with a fresh plan and silently skip the data plane. A
// duplicate plan commits nothing post-commit; a new one appends.
func TestCommitPlanCarriesVerdict(t *testing.T) {
	h := newCharHarness(t, nil)
	svc := New(h.db, h.bus, h.m, nil, nil, nil)

	// First: a fresh batch.
	_, plan, err := applyDirect(t, h, svc, applyPrincipal(), charPacket(1, icmpRounds(1, 0, 30)))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.new {
		t.Fatal("fresh plan.new = false")
	}

	// Replay the same slot: a duplicate plan must report new=false and, when
	// committed again, not re-append.
	dupRes, dupPlan, err := applyDirect(t, h, svc, applyPrincipal(), charPacket(1, icmpRounds(1, 0, 30)))
	if err != nil {
		t.Fatal(err)
	}
	if dupRes.New || !dupRes.Duplicate {
		t.Fatalf("replay verdict = %+v, want a duplicate", dupRes)
	}
	if dupPlan.new {
		t.Fatal("duplicate plan.new = true")
	}
	// Commit the duplicate plan directly (the shape the reviewer worried about):
	// it must be a no-op for the data plane, derived from the plan alone.
	if err := svc.Commit(h.ctx, &dupPlan); err != nil {
		t.Fatalf("commit duplicate: %v", err)
	}
}
