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
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/baseline"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
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

// ErrSequenceConflict reports a replayed packet whose (epoch, sequence) slot
// does not carry the content being presented: the receipt is missing (the
// watermark advanced past a sequence that was never committed under this
// epoch) or its stored fingerprint differs (the sequence was reused for
// different content). Either way the batch must never be renumbered in place
// — the hub answers with an epoch rotation challenge and withholds the ack.
// The transaction is rolled back, so nothing about the conflicting batch is
// stored.
var ErrSequenceConflict = errors.New("ingest: sequence conflict")

// Evaluator is the fault-engine surface ingest drives inside its own sample
// transaction so telemetry samples and their fault evaluation reach one committed
// state atomically. Satisfied by *fault.Service; kept as a small interface so
// ingest unit tests can pass nil (evaluation is then skipped). PublishOutcome runs
// post-commit, off the write path. The tx methods take a store.WriteTx (CLOUD-015):
// the evaluator runs inside the caller's transaction and must never need a raw
// handle back out of it.
type Evaluator interface {
	EvaluateAgentTx(ctx context.Context, tx store.WriteTx, agentID, siteID string, rounds []fault.Round) (*fault.Outcome, error)
	// EvaluateHostTx advances the system-status detectors over the same batch, in
	// the same transaction. Separate from EvaluateAgentTx because host readings are
	// not probe rounds — they carry a threshold and a third "hold" verdict that a
	// probe round has no use for.
	EvaluateHostTx(ctx context.Context, tx store.WriteTx, agentID, siteID string,
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
	IngestTracesTx(ctx context.Context, tx store.WriteTx, agentID, siteID string, results []telemetry.TraceResult) (*incidentops.TraceOutcome, error)
	PublishTraceOutcome(ctx context.Context, out *incidentops.TraceOutcome)
	IngestScenesTx(ctx context.Context, tx store.WriteTx, agentID, siteID string, reports []telemetry.SceneReport) (*incidentops.SceneOutcome, error)
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
	// registry.ResetSeqWatermark. nil is a no-op. Takes the WriteTx since
	// CLOUD-015 — it runs inside the packet transaction and must not reach a
	// raw handle back out of it.
	TouchAgentTx func(ctx context.Context, tx store.WriteTx, agentID string) (post func(), err error)

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
//
// epoch is the credential generation the sending session authenticated under
// (registry.AuthResult.Epoch). It keys the receipt ledger: admission compares
// the packet's sequence against the CURRENT epoch's high_sequence — a packet
// served under a stale epoch never reaches the receipt table through the
// replay path (it would be admitted against the reset watermark instead), and
// stale-epoch packets surface as a Hello-epoch mismatch at the hub, not here.
//
// The work is the three-phase pipeline of apply.go: Prepare resolves
// everything outside the write transaction, ApplyPacketTx runs the
// transaction core, and Commit executes the post-commit plan — only after
// WriteTx returned nil, i.e. the commit succeeded. A rollback discards the
// plan, so nothing post-commit ever observes a batch that did not commit.
func (s *Service) Ingest(ctx context.Context, agentID, siteID string, epoch uint64, pkt telemetry.Packet) (Ack, error) {
	p := AgentPrincipal{AgentID: agentID, SiteID: siteID, EnrollmentEpoch: epoch}
	in, err := s.Prepare(ctx, p, pkt)
	if err != nil {
		return Ack{}, err
	}
	defer in.ReleasePending()

	var res ApplyResult
	var plan PostCommitPlan
	err = s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var aerr error
		res, plan, aerr = s.ApplyPacketTx(ctx, store.Standalone(), wtx, in)
		return nil, aerr
	})
	if err != nil {
		return Ack{}, err
	}

	// The commit succeeded; the plan runs now, after it. An append failure
	// inside Commit is logged there and returned, but deliberately still
	// ACKS — the SQLite state is committed and a replay would be deduplicated
	// anyway (see Commit).
	_ = s.Commit(ctx, res, &plan)

	return Ack{
		HighestSequence: s.ackSequence(p.AgentID, pkt.Sequence, in.cacheEpoch, res.New, res.AdoptHigh),
		ServerTime:      in.now,
	}, nil
}

// receiptFingerprint returns the stored content fingerprint for one (agent,
// epoch, sequence) receipt slot, or sql.ErrNoRows when no receipt exists for
// the slot.
func (s *Service) receiptFingerprint(ctx context.Context, wtx store.WriteTx, agentID string, epoch, seq uint64) (string, error) {
	var fp string
	err := wtx.QueryRowContext(ctx,
		`SELECT fingerprint FROM packet_receipts WHERE agent_id=? AND enrollment_epoch=? AND sequence=?`,
		agentID, epoch, seq).Scan(&fp)
	return fp, err
}

// AcceptedFloor returns the current epoch's committed sequence high-watermark
// (agents.high_sequence) — the durable value the hub pushes as the schema-8
// SequenceFloor on connect. Mirrors currentHigh, but a straight DB read: the
// floor must be the committed truth, not whatever the in-memory cache of this
// process happens to hold.
func (s *Service) AcceptedFloor(ctx context.Context, agentID string) (uint64, error) {
	var high uint64
	err := s.db.QueryRowContext(ctx,
		`SELECT high_sequence FROM agents WHERE id=?`, agentID).Scan(&high)
	return high, err
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
