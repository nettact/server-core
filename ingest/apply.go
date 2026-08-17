package ingest

// The ingest transaction core, split out of Ingest so an external host can
// run the same domain logic inside its own store transaction, while the
// self-hosted Ingest keeps its exact external behavior. The split is the
// three phases Ingest always had, made explicit:
//
//	Prepare        — everything resolved OUTSIDE the write transaction
//	                 (schema, timestamp policy, provenance pre-filter, series
//	                 ids, baselines, the replay-gate read, the pending-append
//	                 marks). Fails before any write is taken.
//	ApplyPacketTx  — the transaction core: liveness, admission/replay, the
//	                 authoritative in-tx re-check, and every relational write.
//	                 It never begins, commits or rolls back a transaction,
//	                 never opens a connection, never does network I/O — the
//	                 caller owns the transaction's lifetime.
//	Commit         — the post-commit executor: the actions that run only
//	                 after a successful commit, in their exact historic order.
//
// The behavioral contract this extraction must not move is pinned by the
// characterization suite (characterization_test.go) and apply_test.go.

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"math"
	"sync"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/baseline"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/gamedata"
	"github.com/nettact/server-core/incidentops"
	"github.com/nettact/server-core/store"
)

// AgentPrincipal is the verified identity of the packet's sender, derived
// from the credential — never from the packet's self-reported fields. The
// packet's AgentID/SiteID are transport echoes; every write inside
// ApplyPacketTx is attributed to this principal, not to them.
type AgentPrincipal struct {
	AgentID         string
	SiteID          string
	EnrollmentEpoch uint64
}

// PreparedInputs carries everything the prepare phase resolved OUTSIDE the
// write transaction. It is NOT an authorization decision: the authoritative
// re-check (probe provenance against the transaction) stays inside
// ApplyPacketTx and can only shrink what Prepare accepted. Fields are
// unexported because the only way to build one is Prepare — an external
// caller never assembles these by hand, and unexported fields make the invariant
// ("came from Prepare") structural.
type PreparedInputs struct {
	// principal and pkt are the identity PreparedInputs was built FOR: the
	// fields are set by Prepare and consumed by ApplyPacketTx, which no longer
	// accepts them separately — a caller cannot cross inputs prepared for one
	// packet onto another principal or payload without the mismatch being
	// structurally impossible.
	principal AgentPrincipal
	pkt       telemetry.Packet
	// fingerprint is the semantic content identity, computed on the PRISTINE
	// packet before the timestamp filter mutates it (see PacketFingerprint).
	fingerprint string
	// now is the packet's wall clock: the timestamp-policy anchor, the
	// receipt's received_at, and the ack's ServerTime are all this instant.
	now time.Time
	// metrics is the packet's metric slice after the timestamp policy filter.
	// Everything downstream — wifi projection, the host gate, rounds — sees
	// this slice, never the pristine one.
	metrics []telemetry.Metric
	// accepted/stored are the pre-tx provenance result: the metrics that
	// passed the generation/scope filter, and the same plus the derived
	// availability samples (one EnsureSeries covers both).
	accepted []telemetry.Metric
	stored   []telemetry.Metric
	// bands are the historical baselines the degradation detectors will
	// judge against, resolved pre-tx so the write connection never waits on
	// the baseline store.
	bands map[baseline.BandKey]baseline.Band
	// seriesIDs maps the stored metrics to their series ids, resolved (and
	// committed) before the transaction opens.
	seriesIDs map[string]int64
	// hostBatch reports whether the packet carries anything the system-status
	// detectors could judge, and cores is the agent's last known logical core
	// count for the load-per-core judgement.
	hostBatch bool
	cores     float64
	// isNew is the pre-tx replay-gate verdict (Sequence > cached high). The
	// authoritative admission runs in-tx; a refusal turns this into a
	// duplicate or a conflict, and ApplyResult.New is the truth.
	isNew bool
	// cacheEpoch is the epoch the pre-tx watermark read ran under, kept so the
	// ack's cache advance can be pinned to the generation it was read under.
	cacheEpoch uint64
	// pendingDone releases the pending-append marks taken by Prepare. It is
	// idempotent by construction: Commit releases it after the append, and
	// the Ingest-level defer releases it again harmlessly on every path where
	// the append never ran (rollback, refusal, empty post-re-check set).
	pendingDone func()
}

// ReleasePending releases the pending-append marks if they have not been
// released yet. Safe to call more than once; Ingest defers it so a rollback
// or a refusal can never leak marks.
func (in *PreparedInputs) ReleasePending() {
	if in.pendingDone != nil {
		in.pendingDone()
		in.pendingDone = nil
	}
}

// ApplyResult reports what the transaction decided for this packet. It is the
// in-transaction truth — the pre-tx gate in PreparedInputs is only a hint.
type ApplyResult struct {
	// New is true when this sequence was admitted (the guarded UPDATE moved
	// the watermark). Only a New batch runs the domain writes and the
	// post-commit sample work.
	New bool
	// Duplicate is true when the slot was already admitted with this exact
	// fingerprint — a replayed WAL batch. It still proves liveness (the
	// touch runs), but nothing else advances.
	Duplicate bool
	// AdoptHigh is the committed watermark adopted when the guarded UPDATE
	// refused the batch because another session had already moved the column;
	// zero when the batch was admitted or was an ordinary replay. The ack
	// restates this instead of the stale pre-tx read.
	AdoptHigh uint64
}

// commitState carries a plan's once-guard and its remembered outcome.
type commitState struct {
	once sync.Once
	err  error
}

// PostCommitPlan is pure data describing the actions to run only after a
// successful commit. The function itself performs none of them; it is
// discarded wholesale on rollback, which is what keeps a rolled-back batch
// from publishing, caching or appending anything.
type PostCommitPlan struct {
	// new is the admission verdict the plan was built for. It is set by
	// ApplyPacketTx and consumed by Commit, so a caller cannot pair a
	// duplicate verdict with a fresh plan and silently skip the data plane —
	// the plan is self-describing.
	new bool
	// commit is the plan's single-use state: the guard and the remembered
	// outcome live in ONE shared object, so a copy of the plan reports the
	// same result as the original — committing either copy runs the side
	// effects once and both return the same error. Plans are therefore
	// copy-safe; Commit is still NOT safe for concurrent use (a plan belongs
	// to one post-commit executor; the guarantee is for sequential retries).
	commit *commitState
	// AgentID/SiteID/Sequence name the committed batch.
	AgentID  string
	SiteID   string
	Sequence uint64
	// SeriesIDs + StoredTx are the authoritative post-re-check sample set:
	// the exact metrics the append and the latest cache consume.
	SeriesIDs map[string]int64
	StoredTx  []telemetry.Metric
	// AcceptedTx are the reported (non-derived) metrics that passed the
	// in-tx re-check: what UpdateLatest folds and what the status event names.
	AcceptedTx []telemetry.Metric
	// Outcome/HostOutcome/Traces/Scenes are the publications the transaction
	// produced. nil = nothing to publish for that step.
	Outcome     *fault.Outcome
	HostOutcome *fault.Outcome
	Traces      *incidentops.TraceOutcome
	Scenes      *incidentops.SceneOutcome

	// touchPost is the liveness post-commit closure (throttle advance +
	// offline→online publish). Runs for replays too.
	touchPost func()
	// pendingDone is PreparedInputs' release handle, carried into the plan
	// only when this batch will actually append samples.
	pendingDone func()
}

// Prepare resolves everything the transaction will need, outside any write
// transaction: schema validation, the timestamp policy, the provenance
// pre-filter, series ids, baselines, the host anchors' inputs, the replay
// gate and the pending-append marks. On error nothing was written and no
// transaction was taken.
func (s *Service) Prepare(ctx context.Context, p AgentPrincipal, pkt telemetry.Packet) (PreparedInputs, error) {
	var in PreparedInputs
	if err := protocol.ValidateSchema(pkt.SchemaVersion); err != nil {
		return in, err
	}
	in.principal = p
	// Snapshot the packet BEFORE the fingerprint and the filters: the transaction
	// commits this copy, so a caller that reuses or mutates its decoded object
	// after Prepare cannot make the committed payload diverge from the
	// fingerprint.
	pkt = snapshotPacket(pkt)
	// Non-finite metric values are DROPPED, not rejected: the protobuf double
	// can carry NaN/Inf, JSON cannot encode them, and hashing them would
	// collapse every non-finite payload into one digest (a false duplicate).
	// Rejecting the whole packet would be worse — the FIFO WAL re-serves an
	// un-acked in-flight sequence after every reconnect, so one bad sample
	// would block the agent's entire telemetry stream forever. Dropping the
	// corrupt sample and admitting the rest keeps that from happening; the
	// fingerprint is computed on the surviving (finite) metrics, so a replay of
	// the same batch hashes identically.
	if n := dropNonFinite(&pkt.Metrics); n > 0 {
		log.Printf("ingest: dropped %d non-finite samples from agent %s (corrupt telemetry)", n, p.AgentID)
	}
	in.now = time.Now().UTC()
	in.fingerprint = PacketFingerprint(pkt)

	// Timestamp policy, enforced before ANYTHING sees the metrics. The data
	// plane's out-of-order floor is relative to its GLOBAL head time: one agent
	// with a badly-future clock would push the head forward and turn every
	// other agent's honest samples into un-appendable ancient history. Samples
	// beyond a small future slack are therefore dropped here — the agent
	// anchors its clock to the server on every ack, so exceeding the slack is a
	// broken machine, not jitter — and so are samples older than the deepest
	// legitimate replay (the agent WAL holds 72h). Dropping BEFORE rounds are
	// built keeps the fault engine, the latest cache and the data plane
	// describing the same reality; a dropped sample exists nowhere.
	if len(pkt.Metrics) > 0 {
		kept, future, ancient := filterTimestamps(pkt.Metrics, in.now)
		if future+ancient > 0 {
			log.Printf("ingest: dropped %d future-stamped and %d ancient samples from agent %s (clock trouble?)", future, ancient, p.AgentID)
			pkt.Metrics = kept
		}
	}
	in.metrics = pkt.Metrics
	in.pkt = pkt

	// Provenance gate (pre-tx, read pool): a probe sample is accepted only if its
	// monitor still belongs to this site AND is still in this agent's scope AND its
	// ConfigSerial exactly matches the target's current material generation.
	// Unknown monitors (deleted/recreated), out-of-scope or foreign-site monitors,
	// lower serials (obsolete backlog / replay), and higher serials (corrupt/forged
	// future) are dropped. System metrics (MonitorID=="") carry generation 0 and
	// always pass. The authoritative re-check runs inside the write transaction.
	if len(pkt.Metrics) > 0 {
		meta, err := s.probeMeta(ctx, s.db.Read(), p.AgentID, p.SiteID, monitorIDs(pkt.Metrics))
		if err != nil {
			return in, err
		}
		var dropped int
		in.accepted, dropped = filterByGeneration(pkt.Metrics, meta)
		if dropped > 0 {
			log.Printf("ingest: dropped %d obsolete-generation probe samples from agent %s", dropped, p.AgentID)
		}
		// The derived availability samples are stored alongside the reported ones, so
		// one EnsureSeries call covers both and their series exist before the tx opens.
		preRounds := fault.BuildRounds(in.accepted, meta)
		in.stored = append(in.accepted, fault.AvailabilitySamples(preRounds)...)
		// Historical baselines for the degradation detectors, resolved here for the
		// same reason series ids are: the write connection is single, and nothing that
		// can be answered from the read pool should be answered while holding it. The
		// in-tx re-check can only SHRINK the round set (a target that left scope or
		// advanced its generation), never grow it, so these keys are a superset of what
		// the transaction will ask for.
		if s.baseline != nil {
			if in.bands, err = s.baseline.Bands(ctx, p.AgentID, bandRequests(preRounds)); err != nil {
				return in, err
			}
		}
	}

	// Resolve series ids before opening the tx (SQLite is single-connection).
	if len(in.stored) > 0 {
		var err error
		if in.seriesIDs, err = s.metrics.EnsureSeries(ctx, p.AgentID, p.SiteID, in.stored); err != nil {
			return in, err
		}
	}

	// The machine's core count, for the load-per-core judgement, resolved off the
	// write path for the same reason the baselines above are. A batch carrying its
	// own count overrides this; this covers the ordinary case where the count
	// arrived in some earlier packet.
	in.hostBatch = hasHostMetrics(pkt.Metrics)
	if in.hostBatch {
		in.cores = s.latestCores(ctx, p.AgentID)
	}

	// Replay gate. Read BEFORE the transaction: high may seed from the DB, and
	// the single write connection is already checked out once the transaction
	// opens — a pool query then would deadlock against our own transaction.
	high, cacheEpoch, err := s.currentHigh(ctx, p.AgentID)
	if err != nil {
		return in, err
	}
	in.cacheEpoch = cacheEpoch
	in.isNew = pkt.Sequence > high

	// Mark the batch's series in-flight before the transaction opens, not just
	// before the commit. EnsureSeries above ALREADY committed any new series
	// row, so from that moment a concurrent rollup pass can load the series,
	// see no rollup_state row and no pending mark, and later insert
	// last_ts=upTo — while this batch's in-transaction rewind updates zero rows
	// precisely because the row did not exist yet. A first batch older than the
	// pass's overlap would then never be aggregated by any pass. Marking here
	// shrinks that window to EnsureSeries→here; the rollup CAS re-checks the
	// mark as well, which is what actually closes it. The once-wrapper makes
	// the handle idempotent: Commit releases it after the append and the
	// Ingest-level defer releases it again on every path the append never ran.
	if in.isNew && len(in.seriesIDs) > 0 {
		raw := s.metrics.BeginPendingAppend(in.seriesIDs)
		var once sync.Once
		in.pendingDone = func() { once.Do(raw) }
	}
	return in, nil
}

// ApplyPacketTx runs the whole transaction core for one packet inside the
// caller's open write transaction: the liveness touch, the epoch-pinned
// admission with its receipt ledger, the authoritative in-tx provenance
// re-check, and every relational write (rewind, events, inventory,
// interfaces, game data, fault evaluation, evidence). It returns the
// transaction's verdict and the post-commit plan.
//
// Hard rules: it never begins, commits or rolls back a transaction — the
// WriteTx type has no such surface, and the caller (store.DB.WriteTx, or an
// equivalent transaction owner in another host) owns the lifetime; it never opens a
// connection on the global DB; it never does network I/O. On error the caller
// rolls back and discards the plan — the characterization suite pins that
// nothing survives that path.
//
// scope is the tenant boundary the transaction was opened under. It must
// validate AND match the transaction's own Scope(); anything else fails
// closed before the first query, because a mismatched pair means a caller
// bug that would otherwise write to the wrong tenant.
func (s *Service) ApplyPacketTx(ctx context.Context, scope store.Scope, wtx store.WriteTx, in PreparedInputs) (ApplyResult, PostCommitPlan, error) {
	var res ApplyResult
	plan := PostCommitPlan{commit: &commitState{}}
	if err := scope.Validate(); err != nil {
		return res, plan, err
	}
	if wtx.Scope() != scope {
		return res, plan, errors.New("ingest: write transaction scope does not match the call's scope")
	}
	// The identity the transaction commits under is the one Prepare bound the
	// inputs to: the principal and packet are not caller-supplied here, so a
	// crossed prepare cannot attribute one packet's data to another principal
	// or admit a receipt whose fingerprint describes a different payload.
	p := in.principal
	pkt := in.pkt

	isNew := in.isNew

	// Liveness rides the packet transaction (a replay proves liveness too). The
	// post closure — throttle advance and the offline→online publish — runs only
	// after commit; a rollback discards it and the next packet retries.
	if s.TouchAgentTx != nil {
		tp, terr := s.TouchAgentTx(ctx, wtx, p.AgentID)
		if terr != nil {
			return res, plan, terr
		}
		plan.touchPost = tp
	}

	if isNew {
		// Persist the dedup watermark with the batch it admits — and let this
		// UPDATE, not the pre-tx read, be the admission gate.
		//
		// Reading the watermark outside the transaction is a check-then-act: two
		// overlapping sessions for one agent (hub supersession closes the old
		// socket asynchronously, so they coexist briefly) can read the same
		// watermark and both conclude the packet is new. Only one of them can
		// raise the column; the loser must NOT go on to evaluate faults and
		// store the batch a second time, or equal sequences double-advance
		// detector state and a lower sequence can land after a higher one. The
		// removed agent_packets UNIQUE insert was exactly this atomic
		// test-and-set — the monotone guard restores it only if its result is
		// what admits the work.
		//
		// The guard is PINNED TO THE EPOCH (schema 8): a rotation or reinstall
		// zeroes the column under a NEW generation, so a session that still
		// carries the old epoch would otherwise sail past the guard and
		// advance the new epoch's floor with stale-epoch sequences. With the
		// pin, the guarded UPDATE refuses it and the epoch re-check below
		// turns the refusal into a conflict. The replay path needs no extra
		// guard: a sequence <= high is only "a replay" within the same epoch
		// precisely because admission cannot cross the epoch boundary.
		//
		// affected==0 also covers a deleted agent (no row left to raise). The
		// receipt check below decides: a deleted agent's ledger rows cascade
		// away with it, so the batch reads as a conflict and the hub drives a
		// rotation whose reconnect fails authentication outright — the agent's
		// terminal outcome for a deleted identity.
		execRes, err := wtx.ExecContext(ctx,
			`UPDATE agents SET high_sequence=? WHERE id=? AND high_sequence<? AND enrollment_epoch=?`,
			pkt.Sequence, p.AgentID, pkt.Sequence, p.EnrollmentEpoch)
		if err != nil {
			return res, plan, err
		}
		admitted, err := execRes.RowsAffected()
		if err != nil {
			return res, plan, err
		}
		if admitted == 0 {
			// The column has already moved past this read — or the row's
			// generation has. Adopt the committed value so the ack tells the
			// agent where the watermark actually stands instead of restating
			// our stale one; but FIRST check whose watermark this is: an epoch
			// that no longer matches the session's means a rotation/reinstall
			// committed under it, and this batch must not silently advance the
			// new generation's floor. That is a conflict (the hub challenges),
			// not a restated ack.
			var rowEpoch uint64
			rerr := wtx.QueryRowContext(ctx,
				`SELECT high_sequence, enrollment_epoch FROM agents WHERE id=?`, p.AgentID).
				Scan(&res.AdoptHigh, &rowEpoch)
			switch {
			case errors.Is(rerr, sql.ErrNoRows):
				// Deleted agent: no row to adopt from; the receipt lookup
				// below (ledger cascade-emptied) decides.
			case rerr != nil:
				return res, plan, rerr
			case rowEpoch != p.EnrollmentEpoch:
				return res, plan, ErrSequenceConflict
			}
			// The receipt ledger settles what the refusal means. A receipt for
			// THIS slot carrying the same content: the concurrent session
			// admitted the same batch — a duplicate, ack the adopted watermark.
			// A different fingerprint, or no receipt at all (the watermark
			// advanced past a sequence that was never committed): a conflict —
			// fail the batch, roll back, and let the hub drive a rotation.
			stored, serr := s.receiptFingerprint(ctx, wtx, p.AgentID, p.EnrollmentEpoch, pkt.Sequence)
			switch {
			case errors.Is(serr, sql.ErrNoRows):
				return res, plan, ErrSequenceConflict
			case serr != nil:
				return res, plan, serr
			case stored != in.fingerprint:
				return res, plan, ErrSequenceConflict
			}
			isNew = false
			res.Duplicate = true
		} else {
			// The admission admits the receipt: one durable row per committed
			// (agent, epoch, sequence), carrying the fingerprint that makes a
			// later replay of the slot verifiable. The OR IGNORE tolerates the
			// one corner where the slot already exists after a watermark reset
			// within the same epoch — the row then necessarily carries this
			// content or the admission itself would not have passed the
			// monotone guard's epoch-pinned history.
			if _, err := wtx.ExecContext(ctx, `
				INSERT OR IGNORE INTO packet_receipts(agent_id, enrollment_epoch, sequence, fingerprint, received_at)
				VALUES(?,?,?,?,?)`,
				p.AgentID, p.EnrollmentEpoch, pkt.Sequence, in.fingerprint, in.now.Unix()); err != nil {
				return res, plan, err
			}
		}
	} else {
		// Replay (sequence at or below the watermark): the receipt for this
		// (epoch, sequence) slot must exist and carry this exact content. A
		// missing slot or a different fingerprint is a conflict — the WAL's
		// FIFO single-in-flight contract makes a legitimate below-watermark
		// gap impossible, so a slot without a receipt is a sequence that was
		// skipped by whoever moved the watermark, and renumbering it in place
		// is forbidden (see ErrSequenceConflict). Same fingerprint = the same
		// batch served again: duplicate as today, ack restates the watermark.
		stored, serr := s.receiptFingerprint(ctx, wtx, p.AgentID, p.EnrollmentEpoch, pkt.Sequence)
		switch {
		case errors.Is(serr, sql.ErrNoRows):
			return res, plan, ErrSequenceConflict
		case serr != nil:
			return res, plan, serr
		case stored != in.fingerprint:
			return res, plan, ErrSequenceConflict
		}
		res.Duplicate = true
	}
	res.New = isNew
	plan.new = isNew

	if isNew {
		// Authoritative in-tx re-check: config edits serialize on the single write
		// connection, so a serial read here has no TOCTOU with the pre-tx filter.
		acceptedTx := in.accepted
		storedTx := in.stored
		var rounds []fault.Round
		if len(in.accepted) > 0 {
			meta, err := s.probeMeta(ctx, wtx, p.AgentID, p.SiteID, monitorIDs(in.accepted))
			if err != nil {
				return res, plan, err
			}
			acceptedTx, _ = filterByGeneration(in.accepted, meta)
			rounds = fault.BuildRounds(acceptedTx, meta)
			attachBaselines(rounds, in.bands)
			storedTx = append(acceptedTx, fault.AvailabilitySamples(rounds)...)
		}
		// Raw samples reach the data plane AFTER this transaction commits (see
		// the post-commit block); what rides HERE is the durable intent their
		// backfill needs — the 1m rollup watermark rewind, computed from the
		// same authoritative storedTx the append will use, so an
		// obsolete-generation sample the re-check dropped can neither rewind a
		// watermark nor reach storage.
		if err := s.metrics.RewindForBatch(ctx, wtx, p.AgentID, in.seriesIDs, storedTx); err != nil {
			return res, plan, err
		}
		for _, e := range pkt.Events {
			if _, err := wtx.ExecContext(ctx,
				`INSERT OR IGNORE INTO events(id, agent_id, site_id, ts, type, layer, severity, message, attrs)
				 VALUES(?,?,?,?,?,?,?,?,?)`,
				e.ID, p.AgentID, p.SiteID, e.TS.UTC(), string(e.Type), string(e.Layer), string(e.Severity), e.Message, encodeMap(e.Attrs)); err != nil {
				return res, plan, err
			}
		}
		for _, it := range pkt.InventoryDelta {
			if err := applyInventory(ctx, wtx, p.AgentID, p.SiteID, it, in.now); err != nil {
				return res, plan, err
			}
		}
		// Apply only the packet's LAST interface snapshot: the WAL drains in
		// collection order, so within one packet the last snapshot is the newest
		// round. This gives each (agent, sequence) a single, unambiguous
		// last-wins current state, ordered by the monotonic packet sequence. The
		// packet's (timestamp-filtered) metrics are passed so the same round's
		// wifi.* numerics are projected onto the interface rows (matched by exact
		// Metric.TS). wifi.* are system metrics (MonitorID==""), unaffected by the
		// provenance gate.
		if n := len(pkt.InterfaceSnapshots); n > 0 {
			if err := applyInterfaceSnapshot(ctx, wtx, p.AgentID, pkt.InterfaceSnapshots[n-1], in.metrics, pkt.Sequence, in.now); err != nil {
				return res, plan, err
			}
		}
		// Game presentation data rides beside the metrics rather than as metrics,
		// because a second of frames is a distribution and not a value. It is written
		// in the same transaction so a committed packet never leaves a run without the
		// seconds that arrived with it. Its own permission gate lives in gamedata.Apply.
		if _, err := gamedata.Apply(ctx, wtx, p.AgentID, p.SiteID,
			pkt.GameRuns, pkt.GameBuckets, pkt.GameGaps, pkt.GameHostSeconds); err != nil {
			return res, plan, err
		}
		// Fault evaluation runs INSIDE this transaction so detector state, fault
		// signals, incidents, notification plans and the sequence watermark
		// commit atomically: the next status read can never observe an updated
		// signal alongside stale detector counters or vice versa. An evaluation
		// error rolls the whole batch back and the agent's ack is withheld (it
		// retries the sequence). Evaluation consumes the batch's own rounds
		// directly — it has never read stored samples — which is precisely what
		// lets the RAW samples commit elsewhere: their durability is deferred to
		// the data plane append after this commit, and a crash in that gap loses
		// chart points only (an accepted contract), never a detection.
		if s.fault != nil && len(rounds) > 0 {
			if out, ferr := s.fault.EvaluateAgentTx(ctx, wtx, p.AgentID, p.SiteID, rounds); ferr != nil {
				return res, plan, ferr
			} else {
				plan.Outcome = out
			}
		}
		// The system-status detectors run in the same transaction, over the same
		// batch, under the same contract: a machine that has been pegged for the
		// configured duration opens a fault, plans its notification and commits with
		// the samples that prove it. Its anchors are resolved here rather than pre-tx
		// because a threshold edit serializes on this same write connection, so what
		// is read here is what the evaluation is judged against.
		if s.fault != nil && in.hostBatch {
			metas, err := hostMeta(ctx, wtx, p.AgentID, p.SiteID, in.cores, config.DefaultRegularSeconds,
				reportedUploadSeconds(ctx, wtx, p.AgentID))
			if err != nil {
				return res, plan, err
			}
			if len(metas) > 0 {
				hostRounds, mounts := fault.BuildHostRounds(acceptedTx, metas)
				if out, ferr := s.fault.EvaluateHostTx(ctx, wtx, p.AgentID, p.SiteID, hostRounds, mounts); ferr != nil {
					return res, plan, ferr
				} else {
					plan.HostOutcome = out
				}
			}
		}
		// Traceroute reports the agent ran on its own initiative. They land in this
		// same transaction, after the fault evaluation, so a report and the rounds
		// that explain it commit together and a report can attach to a fault the
		// very batch it arrived in has just confirmed.
		if s.tracer != nil && len(pkt.TraceResults) > 0 {
			if tr, terr := s.tracer.IngestTracesTx(ctx, wtx, p.AgentID, p.SiteID, pkt.TraceResults); terr != nil {
				return res, plan, terr
			} else {
				plan.Traces = tr
			}
		}
		// Incident scenes the agent collected on its own fault edges, on the same
		// terms and for the same reason. Ordered after the traces only for
		// determinism; neither reads the other's rows.
		if s.tracer != nil && len(pkt.SceneReports) > 0 {
			if sc, serr := s.tracer.IngestScenesTx(ctx, wtx, p.AgentID, p.SiteID, pkt.SceneReports); serr != nil {
				return res, plan, serr
			} else {
				plan.Scenes = sc
			}
		}

		plan.AgentID = p.AgentID
		plan.SiteID = p.SiteID
		plan.Sequence = pkt.Sequence
		plan.SeriesIDs = in.seriesIDs
		plan.StoredTx = storedTx
		plan.AcceptedTx = acceptedTx
		// Only a batch that will actually append samples releases the
		// pending-append marks from inside the post-commit executor; every
		// other path (rollback, refusal, empty post-re-check set) releases
		// them through Ingest's defer.
		if len(storedTx) > 0 {
			plan.pendingDone = in.pendingDone
		}
	}
	return res, plan, nil
}

// Commit executes the post-commit plan, in the exact historic order the old
// post closure ran: liveness touch → raw-sample append (a failure still
// releases the pending marks and is returned, loudly logged, while the rest
// of the plan proceeds) → latest cache → fault outcomes → evidence outcomes →
// one precise target-status event. It must only ever be called after the
// transaction that produced the plan committed; on rollback the plan is
// discarded and this function is never reached.
//
// Observability: the append step is the only one with an error channel today
// (UpdateLatest and the publish surfaces return nothing), and its failure
// keeps the byte-identical log line the old path had. The returned error is
// the programmatic form of the same gap — a caller that runs its own
// executor equivalent can surface it the same way.
func (s *Service) Commit(ctx context.Context, plan *PostCommitPlan) error {
	if plan.commit == nil {
		plan.commit = &commitState{}
	}
	plan.commit.once.Do(func() {
		plan.commit.err = s.commitOnce(ctx, plan)
	})
	return plan.commit.err
}

func (s *Service) commitOnce(ctx context.Context, plan *PostCommitPlan) error {
	if plan.touchPost != nil {
		plan.touchPost()
	}
	if !plan.new {
		return nil
	}
	var appendErr error
	// Raw samples land in the data plane now, after the commit that admitted
	// the packet: what the in-tx re-check dropped can never be stored, and a
	// crash before this append loses ≤ one packet of chart points while the
	// committed watermark makes the replay a no-op (accepted contract). An
	// append failure deliberately still ACKS: the SQLite state is committed,
	// a replay would be deduplicated anyway, and alerting must not be
	// hostage to data-plane trouble — the gap is charts, loudly logged.
	if len(plan.StoredTx) > 0 {
		ares, err := s.metrics.AppendRawSamples(ctx, plan.AgentID, plan.SeriesIDs, plan.StoredTx)
		switch {
		case err != nil:
			log.Printf("ingest: DATA-PLANE APPEND FAILED for agent %s seq %d (%d samples lost to charts): %v",
				plan.AgentID, plan.Sequence, len(plan.StoredTx), err)
			appendErr = err
		case ares.Dropped > 0:
			log.Printf("ingest: data plane dropped %d/%d samples from agent %s (post-filter — investigate)",
				ares.Dropped, len(plan.StoredTx), plan.AgentID)
		}
		if plan.pendingDone != nil {
			plan.pendingDone()
		}
	}
	// Post-commit, in order: refresh the in-memory latest cache (only after
	// commit — a rolled-back batch must not surface as "current"), publish the
	// fault outcome's lifecycle events, then one precise target-status event over
	// the accepted probe monitors ∪ the outcome's changed targets. Only reported
	// metrics enter the latest cache: the derived availability series is
	// bookkeeping for the rollups, never a "current value" any view reads.
	if len(plan.AcceptedTx) > 0 {
		s.metrics.UpdateLatest(plan.AgentID, plan.SeriesIDs, plan.AcceptedTx)
	}
	if s.fault != nil && plan.Outcome != nil {
		s.fault.PublishOutcome(ctx, plan.Outcome)
	}
	if s.fault != nil && plan.HostOutcome != nil {
		s.fault.PublishOutcome(ctx, plan.HostOutcome)
	}
	if s.tracer != nil && plan.Traces != nil {
		s.tracer.PublishTraceOutcome(ctx, plan.Traces)
	}
	if s.tracer != nil && plan.Scenes != nil {
		s.tracer.PublishSceneOutcome(ctx, plan.Scenes)
	}
	if s.bus != nil {
		ids := monitorIDs(plan.AcceptedTx)
		if plan.Outcome != nil {
			ids = append(ids, plan.Outcome.ChangedTargetIDs...)
		}
		// Host samples carry no monitor id, so a host anchor whose fault state just
		// moved would never reach monitorIDs. Its own outcome is the only thing that
		// refreshes the anchor's row in the console.
		if plan.HostOutcome != nil {
			ids = append(ids, plan.HostOutcome.ChangedTargetIDs...)
		}
		if len(ids) > 0 {
			s.bus.Publish(eventbus.TopicTargetStatusChanged,
				eventbus.TargetStatusChanged{SiteID: plan.SiteID, TargetIDs: dedupeStrings(ids)})
		}
	}
	return appendErr
}

// snapshotPacket deep-copies a packet so the transaction commits an immutable
// copy: Prepare is the boundary at which the caller's decoded object stops
// being observed. The fingerprint-relevant fields (metrics, events, inventory)
// are copied through their nested maps; the remaining payload slices (latest-
// wins interface/game/trace/scene records, which the fingerprint deliberately
// excludes) get a top-level slice copy so a concurrent append cannot panic the
// transaction, though a caller racing a mutation of their contents owns that
// race exactly as it would with any other shared slice.
func snapshotPacket(pkt telemetry.Packet) telemetry.Packet {
	pkt.Metrics = snapshotMetrics(pkt.Metrics)
	pkt.Events = snapshotEvents(pkt.Events)
	pkt.InventoryDelta = append(pkt.InventoryDelta[:0:0], pkt.InventoryDelta...)
	pkt.InterfaceSnapshots = append(pkt.InterfaceSnapshots[:0:0], pkt.InterfaceSnapshots...)
	pkt.GameRuns = append(pkt.GameRuns[:0:0], pkt.GameRuns...)
	pkt.GameBuckets = append(pkt.GameBuckets[:0:0], pkt.GameBuckets...)
	pkt.GameGaps = append(pkt.GameGaps[:0:0], pkt.GameGaps...)
	pkt.GameHostSeconds = append(pkt.GameHostSeconds[:0:0], pkt.GameHostSeconds...)
	pkt.TraceResults = append(pkt.TraceResults[:0:0], pkt.TraceResults...)
	pkt.SceneReports = append(pkt.SceneReports[:0:0], pkt.SceneReports...)
	return pkt
}

func snapshotMetrics(ms []telemetry.Metric) []telemetry.Metric {
	if ms == nil {
		return nil
	}
	out := make([]telemetry.Metric, len(ms))
	copy(out, ms)
	for i := range out {
		if out[i].Labels != nil {
			out[i].Labels = cloneStrMap(out[i].Labels)
		}
	}
	return out
}

func snapshotEvents(es []telemetry.Event) []telemetry.Event {
	if es == nil {
		return nil
	}
	out := make([]telemetry.Event, len(es))
	copy(out, es)
	for i := range out {
		if out[i].Attrs != nil {
			out[i].Attrs = cloneStrMap(out[i].Attrs)
		}
	}
	return out
}

func cloneStrMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// dropNonFinite removes NaN/Inf metric values in place and reports how many
// were dropped. Non-finite values are corrupt protobuf telemetry (JSON cannot
// encode them, so they can never be fingerprinted or stored); dropping them
// admits the rest of the packet rather than re-serving the whole batch forever.
func dropNonFinite(ms *[]telemetry.Metric) int {
	if ms == nil || len(*ms) == 0 {
		return 0
	}
	kept := (*ms)[:0]
	dropped := 0
	for _, m := range *ms {
		if math.IsNaN(m.Value) || math.IsInf(m.Value, 0) {
			dropped++
			continue
		}
		kept = append(kept, m)
	}
	*ms = kept
	return dropped
}
