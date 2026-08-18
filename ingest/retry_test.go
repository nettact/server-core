package ingest

// Two properties this package's other suites cannot reach through the
// self-hosted entry point:
//
//   - the transaction core performs NO side-effecting I/O while the write
//     transaction is open (the forward timing statement; the existing rollback
//     tests only prove the negative, that a discarded plan leaves nothing
//     behind);
//   - the transaction core is attempt-local: a transaction owner that enters it
//     more than once with the same prepared inputs — because its backend rolled
//     an attempt back and re-ran it — ends up with exactly the state of a single
//     run made under the world the committing attempt actually saw.
//
// The second property has no natural load here: on a single-writer backend a
// transaction function is entered exactly once, so nothing in the ordinary
// suite ever executes it twice. It is nonetheless a real obligation, because a
// backend that permits concurrent writers reports serialization conflicts and
// its transaction owner retries the whole function. Everything the function
// captures must therefore be rebuilt on every entry and never accumulated
// across entries, so that only the attempt that actually commits is
// observable. The retry is injected here by hand: the owner rolls the first
// attempt back and runs the second to completion.

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/tsstore"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

// countingSeriesStore counts AppendRaw calls and otherwise delegates to a real
// store: the observation seam for "did the data plane get written, and when".
type countingSeriesStore struct {
	tsstore.SeriesStore
	appends *int64
}

func (c countingSeriesStore) AppendRaw(ctx context.Context, samples []tsstore.RawSample) (tsstore.AppendResult, error) {
	atomic.AddInt64(c.appends, 1)
	return c.SeriesStore.AppendRaw(ctx, samples)
}

// applyRun is one scripted run of the pipeline over its own harness: a fresh
// database, a fresh data plane whose appends are counted, and a subscription
// to every topic the post-commit executor can publish on.
type applyRun struct {
	h       *charHarness
	svc     *Service
	pub     *busyCounter
	appends *int64
}

func newApplyRun(t *testing.T) *applyRun {
	t.Helper()
	appends := new(int64)
	h := newCharHarness(t, countingSeriesStore{SeriesStore: tsstoretest.Open(t), appends: appends})
	svc := New(h.db, h.bus, h.m, fault.New(h.db, h.bus, nil), nil, nil)
	pub := &busyCounter{}
	subscribeAll(h, pub)
	return &applyRun{h: h, svc: svc, pub: pub, appends: appends}
}

// applyObservations is what a run is compared on: the relational and
// data-plane state it left, plus the two side-effect counters.
type applyObservations struct {
	state     stateSnapshot
	appends   int64
	publishes int
}

func (r *applyRun) observe() applyObservations {
	return applyObservations{
		state:     r.h.snapshot(),
		appends:   atomic.LoadInt64(r.appends),
		publishes: r.pub.n,
	}
}

// bumpTargetGeneration commits a material edit of the probe target between two
// attempts: the packet's samples now carry an obsolete generation, so the
// authoritative in-transaction re-check drops them. It stands in for the
// concurrent edit that would have made an attempt fail on a backend with more
// than one writer, and it is what makes the two attempts of a retry
// observably DIFFERENT — without that, both attempts would write the same
// idempotent rows and an implementation that leaked one attempt's work into
// the next would be indistinguishable from a correct one.
func bumpTargetGeneration(r *applyRun) {
	r.h.exec(`UPDATE probe_tasks SET config_serial=2 WHERE id='t_icmp'`)
}

// TestNoSideEffectIOInsideTheTransaction asserts the forward half of "side
// effects happen only after the commit": sampled at the last instant the write
// transaction is still open — inside the transaction function, after the
// transaction core has run and produced its plan — the data-plane append count
// and the publication count are both zero. They become non-zero only once the
// owner runs the plan, after the transaction returned.
//
// The existing rollback tests assert the complementary negative (a transaction
// that never commits leaves no append, no cache fold and no publication). This
// one rules out the case those cannot see: a side effect that happens inside
// the transaction and then commits anyway, which would look identical from the
// outside.
func TestNoSideEffectIOInsideTheTransaction(t *testing.T) {
	r := newApplyRun(t)
	pkt := charPacket(2, icmpRounds(1, 0, 30))
	in, err := r.svc.Prepare(r.h.ctx, applyPrincipal(), pkt)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer in.ReleasePending()

	var plan PostCommitPlan
	var res ApplyResult
	var inTxAppends int64
	var inTxPublishes int
	err = r.h.db.WriteTx(r.h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var aerr error
		res, plan, aerr = r.svc.ApplyPacketTx(r.h.ctx, store.Standalone(), wtx, in)
		// Sampled while the transaction is still open: the function has not
		// returned, so the owner has not committed and cannot have run
		// anything post-commit.
		inTxAppends = atomic.LoadInt64(r.appends)
		inTxPublishes = r.pub.n
		return nil, aerr
	})
	if err != nil {
		t.Fatalf("write transaction: %v", err)
	}
	if !res.New {
		t.Fatal("the batch was not admitted; the rest of this test would prove nothing")
	}
	if inTxAppends != 0 {
		t.Fatalf("%d data-plane appends happened while the transaction was still open, want 0", inTxAppends)
	}
	if inTxPublishes != 0 {
		t.Fatalf("%d publications happened while the transaction was still open, want 0", inTxPublishes)
	}

	if err := r.svc.Commit(r.h.ctx, &plan); err != nil {
		t.Fatalf("post-commit executor: %v", err)
	}
	// Self-control: if this batch produced no side effects at all, the two
	// zero assertions above would have held for a reason that has nothing to
	// do with ordering.
	obs := r.observe()
	if obs.appends == 0 {
		t.Fatal("no data-plane append happened even after the plan ran — this batch exercises no append, " +
			"so the in-transaction zero above was vacuous")
	}
	if obs.publishes == 0 {
		t.Fatal("no publication happened even after the plan ran — this batch publishes nothing, " +
			"so the in-transaction zero above was vacuous")
	}
	if obs.state.rawSamples == 0 || obs.state.high != 2 {
		t.Fatalf("post-commit state %+v, want the committed watermark 2 and raw samples present", obs.state)
	}
}

// runOnce is the reference shape: prepare, one transaction, one plan. between
// runs after prepare and before the transaction opens, so the transaction sees
// the same world the retried run's committing attempt will see.
func runOnce(t *testing.T, pkt telemetry.Packet, between func(*applyRun)) applyObservations {
	t.Helper()
	r := newApplyRun(t)
	in, err := r.svc.Prepare(r.h.ctx, applyPrincipal(), pkt)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer in.ReleasePending()
	if between != nil {
		between(r)
	}
	var res ApplyResult
	var plan PostCommitPlan
	err = r.h.db.WriteTx(r.h.ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var aerr error
		res, plan, aerr = r.svc.ApplyPacketTx(r.h.ctx, store.Standalone(), wtx, in)
		return nil, aerr
	})
	if err != nil {
		t.Fatalf("write transaction: %v", err)
	}
	if !res.New {
		t.Fatalf("reference run verdict %+v, want an admission", res)
	}
	if err := r.svc.Commit(r.h.ctx, &plan); err != nil {
		t.Fatalf("post-commit executor: %v", err)
	}
	return r.observe()
}

// runRetried is the injected retry: prepare once, enter the transaction core,
// throw that whole transaction away, let the world change, then enter it again
// on a fresh transaction and commit that one. Only the second attempt's plan
// is executed — the first attempt's is discarded with its transaction, which
// is the owner's half of the obligation.
func runRetried(t *testing.T, pkt telemetry.Packet, between func(*applyRun)) applyObservations {
	t.Helper()
	r := newApplyRun(t)
	// Prepared once and reused across attempts, which is the real shape: the
	// prepare phase runs outside the transaction, so a retrying owner does not
	// redo it.
	in, err := r.svc.Prepare(r.h.ctx, applyPrincipal(), pkt)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer in.ReleasePending()

	raw1, err := r.h.db.BeginTx(r.h.ctx, nil)
	if err != nil {
		t.Fatalf("begin attempt 1: %v", err)
	}
	res1, plan1, err := r.svc.ApplyPacketTx(r.h.ctx, store.Standalone(), store.AdaptTx(raw1, store.Standalone()), in)
	if err != nil {
		t.Fatalf("attempt 1: %v", err)
	}
	if !res1.New {
		t.Fatalf("attempt 1 verdict %+v, want an admission — the discarded attempt must have done real work, "+
			"or there is nothing for it to leak into attempt 2", res1)
	}
	if err := raw1.Rollback(); err != nil {
		t.Fatalf("rollback attempt 1: %v", err)
	}
	_ = plan1 // discarded on purpose; executing it anyway is a mutation of this test

	if between != nil {
		between(r)
	}

	raw2, err := r.h.db.BeginTx(r.h.ctx, nil)
	if err != nil {
		t.Fatalf("begin attempt 2: %v", err)
	}
	res2, plan2, err := r.svc.ApplyPacketTx(r.h.ctx, store.Standalone(), store.AdaptTx(raw2, store.Standalone()), in)
	if err != nil {
		t.Fatalf("attempt 2: %v", err)
	}
	if !res2.New {
		t.Fatalf("attempt 2 verdict %+v, want a fresh admission — attempt 1's watermark write went away with "+
			"its rollback, so the second entry must admit rather than read its own discarded work as a replay", res2)
	}
	if err := raw2.Commit(); err != nil {
		t.Fatalf("commit attempt 2: %v", err)
	}
	if err := r.svc.Commit(r.h.ctx, &plan2); err != nil {
		t.Fatalf("post-commit executor: %v", err)
	}
	return r.observe()
}

// TestApplyPacketTxIsAttemptLocalUnderOwnerRetry pins attempt locality in two
// shapes.
//
// The first is the plain one: two identical attempts, one of them discarded,
// must land exactly one run's worth of state — no double-advanced watermark,
// no doubled append, no doubled publication, and the second attempt admits the
// batch afresh instead of reading its own rolled-back write as a replay.
//
// The second has the teeth. Identical attempts write identical, largely
// idempotent rows, so leaked work from a discarded attempt can hide inside
// them. So the world CHANGES between the attempts — the probe target's
// generation moves, exactly the kind of concurrent edit that makes an attempt
// fail on a backend with more than one writer — and the committing attempt's
// authoritative re-check therefore drops what the first attempt had accepted.
// The run must then be indistinguishable from a single run made under the new
// generation: any sample, detector row, append or publication that survives is
// the discarded attempt's work leaking through captured state.
//
// What it proves: every entry into the transaction core rebuilds its result
// and its post-commit plan wholesale from the transaction it was handed. What
// it does not prove: anything about a particular backend's retry machinery —
// the injected rollback-then-rerun is the transaction-level equivalent (a
// whole transaction discarded, the function re-entered), and the owner-side
// half belongs to whoever writes that owner.
func TestApplyPacketTxIsAttemptLocalUnderOwnerRetry(t *testing.T) {
	// Failing rounds on purpose: a failing round advances a detector counter
	// the snapshot reads, so leaked work moves a number instead of landing on
	// an idempotent write and hiding.
	pkt := charPacket(6, icmpRounds(2, 100, 25))

	t.Run("identical attempts land exactly one run", func(t *testing.T) {
		clean := runOnce(t, pkt, nil)
		// Self-control: a reference run that left nothing behind would make
		// the equality below hold for every implementation, correct or not.
		if clean.state.high == 0 || clean.state.rawSamples == 0 || clean.appends == 0 || clean.publishes == 0 {
			t.Fatalf("the reference run left nothing to compare: %+v", clean)
		}
		if clean.state.failRounds == 0 {
			t.Fatalf("the reference run advanced no detector counter (%+v); a doubling defect would then be "+
				"invisible to the comparison below", clean.state)
		}
		if got := runRetried(t, pkt, nil); got != clean {
			t.Fatalf("after a retried transaction:\n got %+v\nwant %+v (exactly one run)", got, clean)
		}
	})

	t.Run("only the committing attempt's own view is committed", func(t *testing.T) {
		clean := runOnce(t, pkt, bumpTargetGeneration)
		// Self-control: the generation bump must actually change the outcome.
		// If it did not, this subtest would be the previous one with extra
		// steps and would catch nothing.
		plain := runOnce(t, pkt, nil)
		if clean == plain {
			t.Fatalf("the generation bump changed nothing (%+v) — the comparison below has no content", clean)
		}
		if clean.state.rawSamples != 0 || clean.state.detectors != 0 || clean.appends != 0 || clean.publishes != 0 {
			t.Fatalf("reference run under the new generation = %+v, want the samples dropped by the "+
				"authoritative re-check (no samples, no detector rows, no append, no publication)", clean)
		}
		if clean.state.high != int(pkt.Sequence) {
			t.Fatalf("reference watermark %d, want %d — the batch must still be admitted and acked",
				clean.state.high, pkt.Sequence)
		}
		if got := runRetried(t, pkt, bumpTargetGeneration); got != clean {
			t.Fatalf("after a retried transaction whose attempts saw different generations:\n got %+v\nwant %+v\n"+
				"the discarded attempt's work reached the commit through state carried across entries",
				got, clean)
		}
	})
}
