// Package ingest receives, validates, dedups and persists telemetry packets —
// the heart of the ingest loop (architecture §3.3 / §5.1). Dedup is on
// (agent_id, sequence): a replayed batch is acknowledged but not re-stored.
// Metric samples go to the time-series store (package metrics); events and
// inventory are written here.
package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"hash/fnv"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/baseline"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/gamedata"
	"github.com/nettact/server-core/incidentops"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
)

// Ack is returned to the agent after a successful ingest. HighestSequence is the
// confirmed watermark the agent's uploader uses to prune its WAL.
type Ack struct {
	HighestSequence uint64    `json:"highest_sequence"`
	ServerTime      time.Time `json:"server_time"`
}

// Evaluator is the fault-engine surface ingest drives inside its own sample
// transaction so telemetry samples and their fault evaluation reach one committed
// state atomically. Satisfied by *fault.Service; kept as a small interface so
// ingest unit tests can pass nil (evaluation is then skipped). PublishOutcome runs
// post-commit, off the write path.
type Evaluator interface {
	EvaluateAgentTx(ctx context.Context, tx *sql.Tx, agentID, siteID string, rounds []fault.Round) (*fault.Outcome, error)
	// EvaluateHostTx advances the system-status detectors over the same batch, in
	// the same transaction. Separate from EvaluateAgentTx because host readings are
	// not probe rounds — they carry a threshold and a third "hold" verdict that a
	// probe round has no use for.
	EvaluateHostTx(ctx context.Context, tx *sql.Tx, agentID, siteID string,
		rounds []fault.HostRound, mounts map[string]fault.HostMountView) (*fault.Outcome, error)
	PublishOutcome(ctx context.Context, out *fault.Outcome)
}

// Baseliner is the historical-baseline surface ingest consults BEFORE opening its
// write transaction, so a degradation detector judges each round against the
// target's own history without the single SQLite writer ever waiting on that
// lookup. Satisfied by *baseline.Service; nil-safe — with no baseliner the
// degradation detectors simply never receive a band and judge nothing, which is
// the same state every target is in for its first few days anyway.
type Baseliner interface {
	Bands(ctx context.Context, agentID string, reqs map[baseline.BandKey]int) (map[baseline.BandKey]baseline.Band, error)
}

// AgentEvidence persists the agent-initiated evidence a packet carries — the
// traceroutes an agent ran on its own initiative, and the scenes it collected on
// its own fault edges — in ingest's own write transaction. Satisfied by
// *incidentops.Service; kept as a small interface so ingest unit tests can pass
// nil (both payloads are then dropped, which no test asserts against).
//
// It shares the transaction for the same reason the fault evaluator does: this
// evidence describes the rounds arriving beside it, and committing the two
// separately would let the console see an incident whose evidence was computed
// without what was in the same packet. A failure withholds the ack, the agent
// replays, and the agent-minted report id makes the replay a no-op.
type AgentEvidence interface {
	IngestTracesTx(ctx context.Context, tx *sql.Tx, agentID, siteID string, results []telemetry.TraceResult) (*incidentops.TraceOutcome, error)
	PublishTraceOutcome(ctx context.Context, out *incidentops.TraceOutcome)
	IngestScenesTx(ctx context.Context, tx *sql.Tx, agentID, siteID string, reports []telemetry.SceneReport) (*incidentops.SceneOutcome, error)
	PublishSceneOutcome(ctx context.Context, out *incidentops.SceneOutcome)
}

type Service struct {
	db       *store.DB
	bus      *eventbus.Bus
	metrics  *metrics.Store
	fault    Evaluator     // nil-safe: telemetry then commits without inline evaluation
	baseline Baseliner     // nil-safe: degradation detection is then never fed
	tracer   AgentEvidence // nil-safe: agent-initiated evidence is then not persisted

	// TouchAgentTx, when set, folds the agent's liveness bump into the ingest
	// transaction (registry.TouchLastSeenTx): called once per packet — replays
	// included, a replayed packet still proves the agent alive — it returns a
	// post closure to run after commit (throttle advance + liveness publish) or
	// (nil, nil) when the durable last_seen is fresh enough. A function field
	// rather than a registry reference so ingest stays free of a registry
	// import; wired at composition (server.Start), mirroring
	// registry.ResetSeqWatermark. nil is a no-op.
	TouchAgentTx func(ctx context.Context, tx *sql.Tx, agentID string) (post func(), err error)

	// Per-agent highest-committed-sequence watermark, mirroring
	// agents.high_sequence: cached so the hot ingest path does not re-read the
	// row on every packet, seeded from the DB on first sight of an agent. The
	// epoch counts ResetSeqWatermark calls; a post-commit advance carrying a
	// stale epoch is discarded, so a session that straddled a reenrollment can
	// never resurrect the previous installation's watermark.
	seqMu sync.Mutex
	seq   map[string]*seqState
}

// seqState is one agent's in-memory sequence watermark. high advances only
// after the transaction that recorded the sequence has committed — the
// rollback-discarded write of the old dedup-table design, kept as a hard rule
// (the 83d427e class: state that outruns its transaction fabricates skips).
type seqState struct {
	high  uint64
	epoch uint64
}

func New(db *store.DB, bus *eventbus.Bus, m *metrics.Store, ev Evaluator, bl Baseliner, tr AgentEvidence) *Service {
	return &Service{db: db, bus: bus, metrics: m, fault: ev, baseline: bl, tracer: tr, seq: make(map[string]*seqState)}
}

// Timestamp policy bounds (see Ingest's enforcement comment).
const (
	// tsFutureSlack tolerates ack-anchored clock jitter; a sample further ahead
	// is a broken clock and would poison the data plane's global OOO floor.
	tsFutureSlack = 2 * time.Minute
	// tsPastHorizon is the deepest legitimate replay: the agent WAL retains at
	// most 72h, plus an hour of slack. (The data plane's OOO window is 75h.)
	tsPastHorizon = 73 * time.Hour
)

// filterTimestamps drops samples outside the ingest timestamp policy,
// returning the kept slice (aliasing the input's backing array when nothing
// was dropped) and the per-class drop counts.
func filterTimestamps(ms []telemetry.Metric, now time.Time) (kept []telemetry.Metric, future, ancient int) {
	hi := now.Add(tsFutureSlack)
	lo := now.Add(-tsPastHorizon)
	for i := range ms {
		switch {
		case ms[i].TS.After(hi):
			future++
		case ms[i].TS.Before(lo):
			ancient++
		}
	}
	if future+ancient == 0 {
		return ms, 0, 0
	}
	kept = make([]telemetry.Metric, 0, len(ms)-future-ancient)
	for i := range ms {
		if ms[i].TS.After(hi) || ms[i].TS.Before(lo) {
			continue
		}
		kept = append(kept, ms[i])
	}
	return kept, future, ancient
}

// Ingest stores one telemetry packet idempotently and returns the ack watermark.
func (s *Service) Ingest(ctx context.Context, agentID, siteID string, pkt telemetry.Packet) (Ack, error) {
	if err := protocol.ValidateSchema(pkt.SchemaVersion); err != nil {
		return Ack{}, err
	}
	now := time.Now().UTC()

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
		kept, future, ancient := filterTimestamps(pkt.Metrics, now)
		if future+ancient > 0 {
			log.Printf("ingest: dropped %d future-stamped and %d ancient samples from agent %s (clock trouble?)", future, ancient, agentID)
			pkt.Metrics = kept
		}
	}

	// Provenance gate (pre-tx, read pool): a probe sample is accepted only if its
	// monitor still belongs to this site AND is still in this agent's scope AND its
	// ConfigSerial exactly matches the target's current material generation.
	// Unknown monitors (deleted/recreated), out-of-scope or foreign-site monitors,
	// lower serials (obsolete backlog / replay), and higher serials (corrupt/forged
	// future) are dropped. System metrics (MonitorID=="") carry generation 0 and
	// always pass. The authoritative re-check runs inside the write tx below.
	var accepted []telemetry.Metric
	var stored []telemetry.Metric
	var bands map[baseline.BandKey]baseline.Band
	if len(pkt.Metrics) > 0 {
		meta, err := s.probeMeta(ctx, s.db.Read(), agentID, siteID, monitorIDs(pkt.Metrics))
		if err != nil {
			return Ack{}, err
		}
		var dropped int
		accepted, dropped = filterByGeneration(pkt.Metrics, meta)
		if dropped > 0 {
			log.Printf("ingest: dropped %d obsolete-generation probe samples from agent %s", dropped, agentID)
		}
		// The derived availability samples are stored alongside the reported ones, so
		// one EnsureSeries call covers both and their series exist before the tx opens.
		preRounds := fault.BuildRounds(accepted, meta)
		stored = append(accepted, fault.AvailabilitySamples(preRounds)...)
		// Historical baselines for the degradation detectors, resolved here for the
		// same reason series ids are: the write connection is single, and nothing that
		// can be answered from the read pool should be answered while holding it. The
		// in-tx re-check can only SHRINK the round set (a target that left scope or
		// advanced its generation), never grow it, so these keys are a superset of what
		// the transaction will ask for.
		if s.baseline != nil {
			if bands, err = s.baseline.Bands(ctx, agentID, bandRequests(preRounds)); err != nil {
				return Ack{}, err
			}
		}
	}

	// Resolve series ids before opening the tx (SQLite is single-connection).
	var seriesIDs map[string]int64
	if len(stored) > 0 {
		var err error
		if seriesIDs, err = s.metrics.EnsureSeries(ctx, agentID, siteID, stored); err != nil {
			return Ack{}, err
		}
	}

	// The machine's core count, for the load-per-core judgement, resolved off the
	// write path for the same reason the baselines above are. A batch carrying its
	// own count overrides this; this covers the ordinary case where the count
	// arrived in some earlier packet.
	hostBatch := hasHostMetrics(pkt.Metrics)
	var cores float64
	if hostBatch {
		cores = s.latestCores(ctx, agentID)
	}

	// Replay gate. Read BEFORE the transaction: currentHigh may seed from the
	// DB, and the single write connection is already checked out once WriteTx
	// opens its transaction — a pool query here would deadlock against our own
	// transaction.
	high, epoch, err := s.currentHigh(ctx, agentID)
	if err != nil {
		return Ack{}, err
	}
	isNew := pkt.Sequence > high
	// Set when the guarded UPDATE refuses the batch: the watermark the column
	// actually holds, adopted before the ack is built.
	var adoptHigh uint64

	// Mark the batch's series in-flight before the transaction opens, not just
	// before the commit. EnsureSeries above ALREADY committed any new series
	// row, so from that moment a concurrent rollup pass can load the series,
	// see no rollup_state row and no pending mark, and later insert
	// last_ts=upTo — while this batch's in-transaction rewind updates zero rows
	// precisely because the row did not exist yet. A first batch older than the
	// pass's overlap would then never be aggregated by any pass. Marking here
	// shrinks that window to EnsureSeries→here; the rollup CAS re-checks the
	// mark as well, which is what actually closes it.
	var pendingDone func()
	if isNew && len(seriesIDs) > 0 {
		pendingDone = s.metrics.BeginPendingAppend(seriesIDs)
		defer func() {
			if pendingDone != nil {
				pendingDone()
			}
		}()
	}

	// The transaction: everything relational for this packet runs inside one
	// WriteTx on the single writer handle. The contract commits first, then
	// runs the closure fn returns — preserving the exact ordering the old
	// BeginTx path had (commit → touchPost → AppendRawSamples/UpdateLatest/
	// PublishOutcome) and discarding that closure on any fn or commit error,
	// which is what the old `committed` flag did. An append failure still acks
	// (see the post closure); nothing about that contract changed.
	//
	// fault/gamedata/incidentops/metrics.RewindForBatch and the registry's
	// TouchAgentTx still take *sql.Tx; they are reached through the SQLiteTx
	// migration seam (store.MIGRATION.md) until CLOUD-015 migrates them. The
	// migrated helpers (probeMeta, hostMeta, the admission gate, events,
	// inventory, interface snapshots) use the WriteTx directly.
	err = s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		tx, ok := s.db.SQLiteTx(wtx)
		if !ok {
			return nil, errors.New("ingest: write transaction is not the SQLite adapter")
		}

		// Liveness rides the packet transaction (a replay proves liveness too). The
		// post closure — throttle advance and the offline→online publish — runs only
		// after commit; a rollback discards it and the next packet retries.
		var touchPost func()
		if s.TouchAgentTx != nil {
			tp, terr := s.TouchAgentTx(ctx, tx, agentID)
			if terr != nil {
				return nil, terr
			}
			touchPost = tp
		}

		if isNew {
			// Persist the dedup watermark with the batch it admits — and let this
			// UPDATE, not the pre-tx read, be the admission gate.
			//
			// Reading currentHigh outside the transaction is a check-then-act: two
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
			// affected==0 also covers a deleted agent (no row left to raise) and a
			// session that lost a reenrollment race. Dropping the batch is right in
			// both: the watermark it would advance no longer belongs to it. The ack
			// still goes out, so nothing replays forever.
			res, err := wtx.ExecContext(ctx,
				`UPDATE agents SET high_sequence=? WHERE id=? AND high_sequence<?`,
				pkt.Sequence, agentID, pkt.Sequence)
			if err != nil {
				return nil, err
			}
			admitted, err := res.RowsAffected()
			if err != nil {
				return nil, err
			}
			if admitted == 0 {
				// The column has already moved past this read. Adopt its value so
				// the ack tells the agent where the watermark actually stands
				// instead of restating our stale one — otherwise it would prune to
				// a lower point and resend batches that can only be refused again.
				// No row (deleted agent) leaves it at zero and the ack falls back to
				// the ordinary replay answer.
				if err := wtx.QueryRowContext(ctx,
					`SELECT high_sequence FROM agents WHERE id=?`, agentID).Scan(&adoptHigh); err != nil &&
					!errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
			}
			isNew = admitted > 0
		}

		var acceptedTx []telemetry.Metric
		var storedTx []telemetry.Metric
		var outcome *fault.Outcome
		var hostOutcome *fault.Outcome
		var traces *incidentops.TraceOutcome
		var scenes *incidentops.SceneOutcome
		if isNew {
			// Authoritative in-tx re-check: config edits serialize on the single write
			// connection, so a serial read here has no TOCTOU with the pre-tx filter.
			acceptedTx = accepted
			var rounds []fault.Round
			storedTx = stored
			if len(accepted) > 0 {
				meta, err := s.probeMeta(ctx, wtx, agentID, siteID, monitorIDs(accepted))
				if err != nil {
					return nil, err
				}
				acceptedTx, _ = filterByGeneration(accepted, meta)
				rounds = fault.BuildRounds(acceptedTx, meta)
				attachBaselines(rounds, bands)
				storedTx = append(acceptedTx, fault.AvailabilitySamples(rounds)...)
			}
			// Raw samples reach the data plane AFTER this transaction commits (see
			// the post-commit block); what rides HERE is the durable intent their
			// backfill needs — the 1m rollup watermark rewind, computed from the
			// same authoritative storedTx the append will use, so an
			// obsolete-generation sample the re-check dropped can neither rewind a
			// watermark nor reach storage.
			if err := s.metrics.RewindForBatch(ctx, tx, agentID, seriesIDs, storedTx); err != nil {
				return nil, err
			}
			for _, e := range pkt.Events {
				if _, err := wtx.ExecContext(ctx,
					`INSERT OR IGNORE INTO events(id, agent_id, site_id, ts, type, layer, severity, message, attrs)
					 VALUES(?,?,?,?,?,?,?,?,?)`,
					e.ID, agentID, siteID, e.TS.UTC(), string(e.Type), string(e.Layer), string(e.Severity), e.Message, encodeMap(e.Attrs)); err != nil {
					return nil, err
				}
			}
			for _, it := range pkt.InventoryDelta {
				if err := applyInventory(ctx, wtx, agentID, siteID, it, now); err != nil {
					return nil, err
				}
			}
			// Apply only the packet's LAST interface snapshot: the WAL drains in
			// collection order, so within one packet the last snapshot is the newest
			// round. This gives each (agent, sequence) a single, unambiguous
			// last-wins current state, ordered by the monotonic packet sequence. The
			// packet's metrics are passed so the same round's wifi.* numerics are
			// projected onto the interface rows (matched by exact Metric.TS). wifi.*
			// are system metrics (MonitorID==""), unaffected by the provenance gate.
			if n := len(pkt.InterfaceSnapshots); n > 0 {
				if err := applyInterfaceSnapshot(ctx, wtx, agentID, pkt.InterfaceSnapshots[n-1], pkt.Metrics, pkt.Sequence, now); err != nil {
					return nil, err
				}
			}
			// Game presentation data rides beside the metrics rather than as metrics,
			// because a second of frames is a distribution and not a value. It is written
			// in the same transaction so a committed packet never leaves a run without the
			// seconds that arrived with it. Its own permission gate lives in gamedata.Apply.
			if _, err := gamedata.Apply(ctx, tx, agentID, siteID,
				pkt.GameRuns, pkt.GameBuckets, pkt.GameGaps, pkt.GameHostSeconds); err != nil {
				return nil, err
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
				if out, ferr := s.fault.EvaluateAgentTx(ctx, tx, agentID, siteID, rounds); ferr != nil {
					return nil, ferr
				} else {
					outcome = out
				}
			}
			// The system-status detectors run in the same transaction, over the same
			// batch, under the same contract: a machine that has been pegged for the
			// configured duration opens a fault, plans its notification and commits with
			// the samples that prove it. Its anchors are resolved here rather than pre-tx
			// because a threshold edit serializes on this same write connection, so what
			// is read here is what the evaluation is judged against.
			if s.fault != nil && hostBatch {
				metas, err := hostMeta(ctx, wtx, agentID, siteID, cores, config.DefaultRegularSeconds,
					reportedUploadSeconds(ctx, wtx, agentID))
				if err != nil {
					return nil, err
				}
				if len(metas) > 0 {
					hostRounds, mounts := fault.BuildHostRounds(acceptedTx, metas)
					if out, ferr := s.fault.EvaluateHostTx(ctx, tx, agentID, siteID, hostRounds, mounts); ferr != nil {
						return nil, ferr
					} else {
						hostOutcome = out
					}
				}
			}
			// Traceroute reports the agent ran on its own initiative. They land in this
			// same transaction, after the fault evaluation, so a report and the rounds
			// that explain it commit together and a report can attach to a fault the
			// very batch it arrived in has just confirmed.
			if s.tracer != nil && len(pkt.TraceResults) > 0 {
				if tr, terr := s.tracer.IngestTracesTx(ctx, tx, agentID, siteID, pkt.TraceResults); terr != nil {
					return nil, terr
				} else {
					traces = tr
				}
			}
			// Incident scenes the agent collected on its own fault edges, on the same
			// terms and for the same reason. Ordered after the traces only for
			// determinism; neither reads the other's rows.
			if s.tracer != nil && len(pkt.SceneReports) > 0 {
				if sc, serr := s.tracer.IngestScenesTx(ctx, tx, agentID, siteID, pkt.SceneReports); serr != nil {
					return nil, serr
				} else {
					scenes = sc
				}
			}
		}

		// The post-commit closure: WriteTx runs it exactly once, only after the
		// commit succeeded, and discards it with the rollback otherwise — the
		// ordering the old BeginTx path enforced by hand (commit → touchPost →
		// AppendRawSamples/UpdateLatest/PublishOutcome), now structural.
		post := func() {
			if touchPost != nil {
				touchPost()
			}
			if isNew {
				// Raw samples land in the data plane now, after the commit that admitted
				// the packet: what the in-tx re-check dropped can never be stored, and a
				// crash before this append loses ≤ one packet of chart points while the
				// committed watermark makes the replay a no-op (accepted contract). An
				// append failure deliberately still ACKS: the SQLite state is committed,
				// a replay would be deduplicated anyway, and alerting must not be
				// hostage to data-plane trouble — the gap is charts, loudly logged.
				if len(storedTx) > 0 {
					res, err := s.metrics.AppendRawSamples(ctx, agentID, seriesIDs, storedTx)
					switch {
					case err != nil:
						log.Printf("ingest: DATA-PLANE APPEND FAILED for agent %s seq %d (%d samples lost to charts): %v",
							agentID, pkt.Sequence, len(storedTx), err)
					case res.Dropped > 0:
						log.Printf("ingest: data plane dropped %d/%d samples from agent %s (post-filter — investigate)",
							res.Dropped, len(storedTx), agentID)
					}
					pendingDone()
					pendingDone = nil
				}
				// Post-commit, in order: refresh the in-memory latest cache (only after
				// commit — a rolled-back batch must not surface as "current"), publish the
				// fault outcome's lifecycle events, then one precise target-status event over
				// the accepted probe monitors ∪ the outcome's changed targets. Only reported
				// metrics enter the latest cache: the derived availability series is
				// bookkeeping for the rollups, never a "current value" any view reads.
				if len(acceptedTx) > 0 {
					s.metrics.UpdateLatest(agentID, seriesIDs, acceptedTx)
				}
				if s.fault != nil && outcome != nil {
					s.fault.PublishOutcome(ctx, outcome)
				}
				if s.fault != nil && hostOutcome != nil {
					s.fault.PublishOutcome(ctx, hostOutcome)
				}
				if s.tracer != nil && traces != nil {
					s.tracer.PublishTraceOutcome(ctx, traces)
				}
				if s.tracer != nil && scenes != nil {
					s.tracer.PublishSceneOutcome(ctx, scenes)
				}
				if s.bus != nil {
					ids := monitorIDs(acceptedTx)
					if outcome != nil {
						ids = append(ids, outcome.ChangedTargetIDs...)
					}
					// Host samples carry no monitor id, so a host anchor whose fault state just
					// moved would never reach monitorIDs. Its own outcome is the only thing that
					// refreshes the anchor's row in the console.
					if hostOutcome != nil {
						ids = append(ids, hostOutcome.ChangedTargetIDs...)
					}
					if len(ids) > 0 {
						s.bus.Publish(eventbus.TopicTargetStatusChanged,
							eventbus.TargetStatusChanged{SiteID: siteID, TargetIDs: dedupeStrings(ids)})
					}
				}
			}
		}
		return post, nil
	})
	if err != nil {
		return Ack{}, err
	}

	return Ack{
		HighestSequence: s.ackSequence(agentID, pkt.Sequence, epoch, isNew, adoptHigh),
		ServerTime:      now,
	}, nil
}

// monitorIDs returns the distinct non-empty MonitorIDs referenced by a batch.
func monitorIDs(ms []telemetry.Metric) []string {
	seen := map[string]bool{}
	var out []string
	for i := range ms {
		id := ms[i].MonitorID
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// dedupeStrings returns the distinct non-empty strings of ss, preserving order.
func dedupeStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// probeMeta loads each referenced probe target's current generation, identity and
// built-in detector sensitivity in one query. Absent ids simply do not appear in
// the map, which is what makes a deleted monitor's backlog drop out. A target with
// no probe_detection_settings row uses the balanced defaults, so the zero-config
// path costs no rows and no extra query.
func (s *Service) probeMeta(ctx context.Context, q store.Executor, agentID, siteID string, ids []string) (map[string]fault.TargetMeta, error) {
	out := make(map[string]fault.TargetMeta, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	def := fault.DefaultDetection()
	// Site ownership AND the sending agent's current scope both gate the lookup.
	// The generation check alone is not enough: a group-scope edit is not a
	// material target change, so it leaves config_serial untouched, and an agent
	// that just left the scope could still drain WAL backlog for that target —
	// opening a fault that no later round will ever recover, because the agent has
	// stopped probing it. A target id belonging to another site would likewise be
	// evaluated under the sender's site. An out-of-scope target simply drops out of
	// this map, so its samples are rejected by the generation filter downstream.
	// The agent-reported schedule joins in alongside the target's own params because
	// the two can legitimately disagree: the agent floors every interval at its local
	// MinProbeInterval, so a 10s ICMP target on an agent configured with a 60s floor
	// really runs every 60s. Deriving the round-gap tolerance from the unfloored
	// params would then make every round look like it followed a gap, resetting the
	// failing streak each time and preventing a fault from EVER confirming on that
	// agent. Only the reported value knows the real cadence.
	// The proxy join carries the target's egress identity onto the fault evidence:
	// a probe pinned to a proxy dials the PROXY, so a path diagnostic aimed at the
	// target would measure a path the probe never took. Reading it here rather than
	// at diagnosis time is what keeps it frozen — and it is sound to read live,
	// because a proxy edit bumps every referencing task's config_serial, so samples
	// that survive the generation filter were produced under this very row.
	query := `
		SELECT pt.id, pt.kind, pt.group_id, COALESCE(pt.name,''), COALESCE(pt.target,''),
		       COALESCE(pt.params,''), pt.enabled, pt.config_serial,
		       COALESCE(ds.fail_rounds, ?), COALESCE(ds.recover_rounds, ?),
		       COALESCE(ds.icmp_loss_pct, ?), COALESCE(ds.smart_enabled, ?),
		       COALESCE(ds.smart_sensitivity, ?), COALESCE(ds.revision, 1),
		       ms.source, ms.target_config_serial, ms.effective_interval_seconds,
		       ms.cycle_deadline_ms, ms.upload_interval_seconds,
		       COALESCE(pt.proxy_id,''), COALESCE(px.type,''), COALESCE(px.host,''),
		       COALESCE(px.port,0), COALESCE(px.wg_endpoint,''), COALESCE(px.config_serial,0)
		FROM probe_tasks pt
		LEFT JOIN probe_detection_settings ds ON ds.target_id = pt.id
		LEFT JOIN monitor_status ms ON ms.monitor_id = pt.id AND ms.agent_id = ?
		LEFT JOIN proxies px ON px.id = pt.proxy_id
		WHERE pt.site_id = ? AND ` + config.AgentScopePredicate + `
		  AND pt.id IN (` + placeholders(len(ids)) + `)`
	args := make([]any, 0, len(ids)+8)
	defSmart := 0
	if def.SmartEnabled {
		defSmart = 1
	}
	args = append(args, def.FailRounds, def.RecoverRounds, def.ICMPLossPct, defSmart, def.SmartSensitivity,
		agentID, siteID, agentID)
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m fault.TargetMeta
		var params string
		var enabled, smartEnabled int
		var sched reportedSchedule
		var proxyHost, wgEndpoint string
		var proxyPort int
		if err := rows.Scan(&m.ID, &m.Kind, &m.GroupID, &m.Name, &m.Addr, &params, &enabled, &m.ConfigSerial,
			&m.Det.FailRounds, &m.Det.RecoverRounds, &m.Det.ICMPLossPct, &smartEnabled,
			&m.Det.SmartSensitivity, &m.Det.Revision,
			&sched.source, &sched.configSerial, &sched.intervalSeconds,
			&sched.cycleDeadlineMs, &sched.uploadSeconds,
			&m.ProxyID, &m.ProxyType, &proxyHost, &proxyPort, &wgEndpoint, &m.ProxyConfigSerial); err != nil {
			return nil, err
		}
		m.Enabled = enabled == 1
		m.Det.SmartEnabled = smartEnabled == 1
		m.Port = portFromParams(params)
		m.PingCount = fault.ConfiguredPingCount(m.Kind, params)
		m.ProxyAddr = proxyAddr(m.ProxyType, proxyHost, proxyPort, wgEndpoint)
		m.MaxRoundGap = roundGap(m.Kind, params, sched, m.ConfigSerial)
		m.Det = m.Det.Normalize()
		out[m.ID] = m
	}
	return out, rows.Err()
}

// reportedSchedule is one pair's agent-reported effective schedule, all nullable:
// no monitor_status row yet, or a row that has not been confirmed for the current
// generation, leaves every field invalid.
type reportedSchedule struct {
	source          sql.NullString
	configSerial    sql.NullInt64
	intervalSeconds sql.NullInt64
	cycleDeadlineMs sql.NullInt64
	uploadSeconds   sql.NullInt64
}

// confirmedFor reports whether this row is the agent's own echo for the given
// target generation, i.e. whether its schedule describes what the agent is really
// running now. Mirrors the `confirmed` test in targetstatus.deriveAgent.
func (s reportedSchedule) confirmedFor(configSerial int) bool {
	return s.source.Valid && s.source.String == "reported" &&
		s.configSerial.Valid && int(s.configSerial.Int64) == configSerial &&
		s.intervalSeconds.Valid && s.intervalSeconds.Int64 > 0 &&
		s.cycleDeadlineMs.Valid && s.cycleDeadlineMs.Int64 > 0
}

// proxyAddr renders a proxy's dialable identity: the peer endpoint for a
// WireGuard tunnel (already "host:port"), the listener for a relay proxy. Empty
// when the columns for this type are unset, so a half-formed address is reported
// as an undiagnosable egress rather than traced as if it were real.
func proxyAddr(proxyType, host string, port int, wgEndpoint string) string {
	if proxyType == pcfg.ProxyTypeWireGuard {
		return strings.TrimSpace(wgEndpoint)
	}
	if host == "" || port <= 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// portFromParams extracts the target port from a probe_tasks.params blob, frozen
// onto a fault signal so traceroute derivation never re-reads live (possibly
// edited) probe config.
func portFromParams(params string) int {
	if params == "" {
		return 0
	}
	var p pcfg.ProbeParams
	if json.Unmarshal([]byte(params), &p) != nil {
		return 0
	}
	return p.Port
}

// roundGap derives how far apart two of this target's rounds may be and still
// count as consecutive.
//
// It is the same StaleAfter window the freshness derivation uses, so the engine's
// notion of "these rounds are adjacent" cannot drift from the server's notion of
// "this sample still describes the present". Deriving it per target matters
// because the intervals span three orders of magnitude — 10s for ICMP, 30 minutes
// for NAT — so no fixed threshold could serve both.
//
// The agent's own reported schedule wins when it has confirmed one for this
// generation, because only it accounts for the agent-local MinProbeInterval floor;
// the desired config is the fallback until that echo arrives, exactly as in
// targetstatus.deriveAgent. Getting this backwards would silently disable fault
// confirmation on any agent whose floor exceeds a target's configured interval.
func roundGap(kind, params string, sched reportedSchedule, configSerial int) time.Duration {
	if sched.confirmedFor(configSerial) {
		var upload time.Duration
		if sched.uploadSeconds.Valid && sched.uploadSeconds.Int64 > 0 {
			upload = time.Duration(sched.uploadSeconds.Int64) * time.Second
		}
		return pcfg.StaleAfter(
			time.Duration(sched.intervalSeconds.Int64)*time.Second,
			time.Duration(sched.cycleDeadlineMs.Int64)*time.Millisecond,
			upload)
	}
	var p pcfg.ProbeParams
	if params != "" {
		_ = json.Unmarshal([]byte(params), &p) // a bad blob just yields the kind's defaults
	}
	return pcfg.StaleAfter(pcfg.EffectiveInterval(kind, p), pcfg.CycleDeadline(kind, p), pcfg.DefaultUploadInterval)
}

// filterByGeneration keeps system metrics (MonitorID=="") verbatim and each probe
// metric only when its ConfigSerial exactly equals the target's current serial.
// Returns the accepted metrics and the number dropped.
func filterByGeneration(ms []telemetry.Metric, meta map[string]fault.TargetMeta) ([]telemetry.Metric, int) {
	accepted := make([]telemetry.Metric, 0, len(ms))
	dropped := 0
	for i := range ms {
		m := ms[i]
		if m.MonitorID == "" {
			accepted = append(accepted, m)
			continue
		}
		cur, ok := meta[m.MonitorID]
		if !ok || m.ConfigSerial != cur.ConfigSerial {
			dropped++
			continue
		}
		accepted = append(accepted, m)
	}
	return accepted, dropped
}

// placeholders returns "?,?,…" with n placeholders for an IN clause.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// currentHigh returns the agent's committed sequence watermark and the epoch it
// was read under, seeding from agents.high_sequence on first sight. A packet
// with Sequence <= high is a replay: the agent's WAL is FIFO per server with a
// single in-flight packet resent under its original sequence until acked, and
// the ack is already cumulative — so a below-watermark sequence that was never
// processed cannot legitimately exist, and dropping it is exact. A missing
// agents row (agent deleted mid-flight) surfaces as an error and fails the
// packet, which is correct: nothing should ingest under a deleted identity.
func (s *Service) currentHigh(ctx context.Context, agentID string) (high, epoch uint64, err error) {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	st, ok := s.seq[agentID]
	if !ok {
		var dbHigh uint64
		if err := s.db.QueryRowContext(ctx,
			`SELECT high_sequence FROM agents WHERE id=?`, agentID).Scan(&dbHigh); err != nil {
			return 0, 0, err
		}
		st = &seqState{high: dbHigh}
		s.seq[agentID] = st
	}
	return st.high, st.epoch, nil
}

// ackSequence produces the value the agent prunes its WAL by. adoptHigh is
// nonzero only when the guarded UPDATE refused this batch because the column
// had already moved past the pre-transaction read; raising the in-memory
// watermark to it first keeps the ack honest, so the agent prunes to where the
// watermark really is instead of resending batches that can only be refused
// again.
func (s *Service) ackSequence(agentID string, seq, epoch uint64, committed bool, adoptHigh uint64) uint64 {
	if adoptHigh > 0 {
		s.seqMu.Lock()
		if st, ok := s.seq[agentID]; ok && st.epoch == epoch && adoptHigh > st.high {
			st.high = adoptHigh
		}
		s.seqMu.Unlock()
	}
	return s.noteCommittedSeq(agentID, seq, epoch, committed)
}

// noteCommittedSeq folds a sequence whose transaction has COMMITTED into the
// in-memory watermark and returns the ack value. epoch must be the value
// currentHigh returned for this packet: if ResetSeqWatermark ran in between
// (reenrollment), the advance is discarded — folding it would resurrect the
// previous installation's watermark and misread the fresh WAL's low sequences
// as replays. For a replay (committed=false) nothing advances; the ack simply
// restates the current high.
func (s *Service) noteCommittedSeq(agentID string, seq, epoch uint64, committed bool) uint64 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	st, ok := s.seq[agentID]
	if !ok || st.epoch != epoch {
		if ok {
			return st.high
		}
		return 0
	}
	if committed && seq > st.high {
		st.high = seq
	}
	if st.high > seq {
		return st.high
	}
	return seq
}

// ResetSeqWatermark resets the in-memory per-agent sequence watermark and bumps
// its epoch. Used by reenrollment (AGENT-006): the fresh WAL starts again at
// sequence 1 and the reenroll transaction zeroed agents.high_sequence — a stale
// in-memory high would make the ack report a watermark the new installation
// never reached, and the agent's Outbox.FastForward would then jump its next
// sequence past batches that were never uploaded. The epoch bump additionally
// discards any in-flight packet's post-commit advance from a session that
// authenticated before the reenrollment (see noteCommittedSeq).
func (s *Service) ResetSeqWatermark(ctx context.Context, agentID string) {
	s.seqMu.Lock()
	if st, ok := s.seq[agentID]; ok {
		st.high = 0
		st.epoch++
	} else {
		s.seq[agentID] = &seqState{epoch: 1}
	}
	s.seqMu.Unlock()
}

func encodeMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

func applyInventory(ctx context.Context, tx store.WriteTx, agentID, siteID string, it telemetry.InventoryItem, now time.Time) error {
	switch it.Kind {
	case telemetry.InventoryDevice:
		if it.Op == telemetry.OpRemove {
			return nil // keep device history in P0
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO devices(id, site_id, mac, ip, hostname, vendor, first_seen, last_seen)
			VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(site_id, mac) DO UPDATE SET
				ip=excluded.ip, hostname=excluded.hostname, vendor=excluded.vendor, last_seen=excluded.last_seen`,
			siteID+"/"+it.MAC, siteID, it.MAC, it.IP, it.Hostname, it.Vendor, now, now)
		return err
	}
	return nil
}

// applyInterfaceSnapshot replaces the agent's interface rows with the snapshot's
// authoritative full set and upserts the collection-level Wi-Fi verdict. It runs
// inside the per-packet tx after sequence dedup, so it only ever sees a
// non-duplicate packet. Replacement is ordered by the monotonic packet sequence
// (the delivery-order signal), never by SampledAt: only a strictly higher
// sequence replaces current state, so an agent clock correction/rollback can no
// longer freeze current state (a later, higher-sequence disconnect/SSID change
// still wins). SampledAt is stored solely for freshness / WAL-replay age.
//
// The current-round numeric readings (signal/quality/rx/tx) are projected onto
// each interface row from the packet's wifi.* metrics whose Metric.TS exactly
// equals this snapshot's SampledAt — so the numbers belong to the same
// authoritative round as the categorical state. A field the driver omitted this
// round (or a disconnected/unreadable adapter) has no such metric and stores
// NULL, never an earlier round's value. With several snapshots in one packet
// only the last snapshot is applied, and only its exact-timestamp metrics match.
func applyInterfaceSnapshot(ctx context.Context, tx store.WriteTx, agentID string, snap telemetry.InterfaceSnapshot, metrics []telemetry.Metric, seq uint64, now time.Time) error {
	var storedSeq, storedHash sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT last_sequence, iface_hash FROM agent_wifi WHERE agent_id=?`, agentID).Scan(&storedSeq, &storedHash)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if storedSeq.Valid && seq <= uint64(storedSeq.Int64) {
		return nil // not a newer packet; delivery order is the authority
	}

	nums := wifiNumericsForRound(metrics, snap.SampledAt)

	// A wired agent's interface set — and even a wireless one's between roams —
	// is byte-identical round after round, yet the authoritative-full-set
	// replacement below rewrites every row (and thus every touched SQLite page)
	// on every packet. Hash the exact content the rows would carry and skip the
	// replacement when nothing changed; the agent_wifi upsert still runs so the
	// freshness clock (sampled_at) and the sequence guard stay current. The hash
	// is stored in the same row, so it commits or rolls back with the data it
	// describes and disappears with the agent — no cache to invalidate.
	hash := int64(ifaceContentHash(snap.Interfaces, nums))
	if !storedHash.Valid || storedHash.Int64 != hash {
		if _, err := tx.ExecContext(ctx, `DELETE FROM interfaces WHERE agent_id=?`, agentID); err != nil {
			return err
		}
		for _, ifc := range snap.Interfaces {
			up := 0
			if ifc.Up {
				up = 1
			}
			isw := 0
			if ifc.IsWireless {
				isw = 1
			}
			var wState, wReason, wSSID, wBand sql.NullString
			var wChannel sql.NullInt64
			if ifc.WiFi != nil {
				wState = nullStr(string(ifc.WiFi.State))
				wReason = nullStr(string(ifc.WiFi.Reason))
				wSSID = nullStr(ifc.WiFi.SSID)
				wBand = nullStr(string(ifc.WiFi.Band))
				wChannel = sql.NullInt64{Int64: int64(ifc.WiFi.Channel), Valid: true}
			}
			n := nums[ifc.Name] // zero value: all-NULL when the round had no numerics for this iface
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO interfaces(id, agent_id, name, addrs, gateway, dns, up, is_wireless,
					wifi_state, wifi_reason, wifi_ssid, wifi_band, wifi_channel,
					wifi_signal_dbm, wifi_quality_pct, wifi_rx_mbps, wifi_tx_mbps, updated_at)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				agentID+"/"+ifc.Name, agentID, ifc.Name, encodeSlice(ifc.Addrs), ifc.Gateway, encodeSlice(ifc.DNS),
				up, isw, wState, wReason, wSSID, wBand, wChannel,
				n.signalDBm, n.qualityPct, n.rxMbps, n.txMbps, now); err != nil {
				return err
			}
		}
	}

	var defaultGateway, defaultInterface sql.NullString
	if snap.DefaultRoute != nil {
		defaultGateway = nullStr(snap.DefaultRoute.Gateway)
		defaultInterface = nullStr(snap.DefaultRoute.Interface)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO agent_wifi(agent_id, state, reason, sampled_at, last_sequence, default_gateway, default_interface, iface_hash)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET
			state=excluded.state, reason=excluded.reason,
			sampled_at=excluded.sampled_at, last_sequence=excluded.last_sequence,
			default_gateway=excluded.default_gateway, default_interface=excluded.default_interface,
			iface_hash=excluded.iface_hash`,
		agentID, string(snap.WiFiState), nullStr(string(snap.WiFiReason)), snap.SampledAt.UTC(), int64(seq),
		defaultGateway, defaultInterface, hash)
	return err
}

// ifaceContentHash digests exactly the fields the interfaces rows persist —
// the snapshot's per-interface facts plus the projected current-round numerics
// — in a fixed field order with length-unambiguous framing. updated_at is
// deliberately outside the hash: it is a consequence of writing, not content,
// and hashing it would defeat the skip.
//
// Interfaces are hashed in name order, not snapshot order. The OS does not
// promise a stable enumeration order across rounds, and the stored rows are
// order-free anyway (keyed agent_id+name, read back ORDER BY name) — so an
// order-sensitive hash would flap on identical content and quietly turn the
// skip off for exactly the agents it was built for.
func ifaceContentHash(ifaces []telemetry.InterfaceState, nums map[string]wifiNumeric) uint64 {
	if !sort.SliceIsSorted(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name }) {
		ifaces = append([]telemetry.InterfaceState(nil), ifaces...)
		sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
	}
	h := fnv.New64a()
	w := func(parts ...string) {
		for _, p := range parts {
			_, _ = h.Write([]byte(strconv.Itoa(len(p))))
			_, _ = h.Write([]byte{':'})
			_, _ = h.Write([]byte(p))
		}
	}
	for _, ifc := range ifaces {
		w(ifc.Name, encodeSlice(ifc.Addrs), ifc.Gateway, encodeSlice(ifc.DNS),
			strconv.FormatBool(ifc.Up), strconv.FormatBool(ifc.IsWireless))
		if ifc.WiFi != nil {
			w(string(ifc.WiFi.State), string(ifc.WiFi.Reason), ifc.WiFi.SSID,
				string(ifc.WiFi.Band), strconv.Itoa(ifc.WiFi.Channel))
		} else {
			w("-")
		}
		n := nums[ifc.Name]
		w(nullInt64Key(n.signalDBm), nullInt64Key(n.qualityPct),
			nullFloat64Key(n.rxMbps), nullFloat64Key(n.txMbps))
	}
	return h.Sum64()
}

func nullInt64Key(v sql.NullInt64) string {
	if !v.Valid {
		return "-"
	}
	return strconv.FormatInt(v.Int64, 10)
}

func nullFloat64Key(v sql.NullFloat64) string {
	if !v.Valid {
		return "-"
	}
	return strconv.FormatFloat(v.Float64, 'g', -1, 64)
}

// wifiNumeric holds the projected current-round numeric columns for one
// interface. All fields default to invalid (SQL NULL).
type wifiNumeric struct {
	signalDBm, qualityPct sql.NullInt64
	rxMbps, txMbps        sql.NullFloat64
}

// wifiNumericsForRound indexes, by interface (Target), the wifi.* numeric
// samples that belong to exactly this collection round — Metric.TS equal to the
// applied snapshot's SampledAt. Metrics from any other round in the same packet
// are ignored, so no earlier round's value is ever carried forward.
func wifiNumericsForRound(metrics []telemetry.Metric, sampledAt time.Time) map[string]wifiNumeric {
	out := map[string]wifiNumeric{}
	for _, m := range metrics {
		if !m.TS.Equal(sampledAt) {
			continue
		}
		n := out[m.Target]
		switch m.Kind {
		case telemetry.WiFiSignalDBm:
			n.signalDBm = sql.NullInt64{Int64: int64(m.Value), Valid: true}
		case telemetry.WiFiQualityPct:
			n.qualityPct = sql.NullInt64{Int64: int64(m.Value), Valid: true}
		case telemetry.WiFiLinkRxMbps:
			n.rxMbps = sql.NullFloat64{Float64: m.Value, Valid: true}
		case telemetry.WiFiLinkTxMbps:
			n.txMbps = sql.NullFloat64{Float64: m.Value, Valid: true}
		default:
			continue
		}
		out[m.Target] = n
	}
	return out
}

func nullStr(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func encodeSlice(s []string) string {
	if len(s) == 0 {
		return ""
	}
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(b)
}
