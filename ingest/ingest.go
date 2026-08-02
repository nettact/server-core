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
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/gamedata"
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
	PublishOutcome(ctx context.Context, out *fault.Outcome)
}

type Service struct {
	db      *store.DB
	bus     *eventbus.Bus
	metrics *metrics.Store
	fault   Evaluator // nil-safe: telemetry then commits without inline evaluation

	// Per-agent highest-sequence watermark, cached so the hot ingest path does
	// not re-run MAX(sequence) on every packet. Loaded from the DB on first
	// sight of an agent, then maintained in memory.
	seqMu   sync.Mutex
	highSeq map[string]uint64
}

func New(db *store.DB, bus *eventbus.Bus, m *metrics.Store, ev Evaluator) *Service {
	return &Service{db: db, bus: bus, metrics: m, fault: ev, highSeq: make(map[string]uint64)}
}

// Ingest stores one telemetry packet idempotently and returns the ack watermark.
func (s *Service) Ingest(ctx context.Context, agentID, siteID string, pkt telemetry.Packet) (Ack, error) {
	if err := protocol.ValidateSchema(pkt.SchemaVersion); err != nil {
		return Ack{}, err
	}
	now := time.Now().UTC()

	// Provenance gate (pre-tx, read pool): a probe sample is accepted only if its
	// monitor still belongs to this site AND is still in this agent's scope AND its
	// ConfigSerial exactly matches the target's current material generation.
	// Unknown monitors (deleted/recreated), out-of-scope or foreign-site monitors,
	// lower serials (obsolete backlog / replay), and higher serials (corrupt/forged
	// future) are dropped. System metrics (MonitorID=="") carry generation 0 and
	// always pass. The authoritative re-check runs inside the write tx below.
	var accepted []telemetry.Metric
	var stored []telemetry.Metric
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
		stored = append(accepted, fault.AvailabilitySamples(fault.BuildRounds(accepted, meta))...)
	}

	// Resolve series ids before opening the tx (SQLite is single-connection).
	var seriesIDs map[string]int64
	if len(stored) > 0 {
		var err error
		if seriesIDs, err = s.metrics.EnsureSeries(ctx, agentID, siteID, stored); err != nil {
			return Ack{}, err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Ack{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Dedup: INSERT OR IGNORE on (agent_id, sequence). affected==0 => replay.
	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO agent_packets(agent_id, sequence, received_at, sent_at) VALUES(?,?,?,?)`,
		agentID, pkt.Sequence, now, pkt.SentAt)
	if err != nil {
		return Ack{}, err
	}
	affected, _ := res.RowsAffected()

	var acceptedTx []telemetry.Metric
	var outcome *fault.Outcome
	if affected > 0 {
		// Authoritative in-tx re-check: config edits serialize on the single write
		// connection, so a serial read here has no TOCTOU with the pre-tx filter.
		acceptedTx = accepted
		var rounds []fault.Round
		storedTx := stored
		if len(accepted) > 0 {
			meta, err := s.probeMeta(ctx, tx, agentID, siteID, monitorIDs(accepted))
			if err != nil {
				return Ack{}, err
			}
			acceptedTx, _ = filterByGeneration(accepted, meta)
			rounds = fault.BuildRounds(acceptedTx, meta)
			storedTx = append(acceptedTx, fault.AvailabilitySamples(rounds)...)
		}
		if err := s.metrics.InsertSamples(ctx, tx, agentID, seriesIDs, storedTx); err != nil {
			return Ack{}, err
		}
		for _, e := range pkt.Events {
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO events(id, agent_id, site_id, ts, type, layer, severity, message, attrs)
				 VALUES(?,?,?,?,?,?,?,?,?)`,
				e.ID, agentID, siteID, e.TS.UTC(), string(e.Type), string(e.Layer), string(e.Severity), e.Message, encodeMap(e.Attrs)); err != nil {
				return Ack{}, err
			}
		}
		for _, it := range pkt.InventoryDelta {
			if err := applyInventory(ctx, tx, agentID, siteID, it, now); err != nil {
				return Ack{}, err
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
			if err := applyInterfaceSnapshot(ctx, tx, agentID, pkt.InterfaceSnapshots[n-1], pkt.Metrics, pkt.Sequence, now); err != nil {
				return Ack{}, err
			}
		}
		// Game presentation data rides beside the metrics rather than as metrics,
		// because a second of frames is a distribution and not a value. It is written
		// in the same transaction so a committed packet never leaves a run without the
		// seconds that arrived with it. Its own permission gate lives in gamedata.Apply.
		if _, err := gamedata.Apply(ctx, tx, agentID, siteID,
			pkt.GameRuns, pkt.GameBuckets, pkt.GameGaps, pkt.GameHostSeconds); err != nil {
			return Ack{}, err
		}
		// Fault evaluation runs INSIDE this sample transaction so samples, detector
		// state, fault signals, incidents and notification plans commit atomically:
		// the next status read can never observe an updated signal alongside stale
		// detector counters or vice versa. An evaluation error rolls the whole batch
		// back and the agent's ack is withheld (it retries the sequence). Evaluation
		// consumes the batch's own rounds directly, so it never depends on the
		// latest-value cache, which is only refreshed post-commit.
		if s.fault != nil && len(rounds) > 0 {
			outcome, err = s.fault.EvaluateAgentTx(ctx, tx, agentID, siteID, rounds)
			if err != nil {
				return Ack{}, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return Ack{}, err
	}
	committed = true

	if affected > 0 {
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
		if s.bus != nil {
			ids := monitorIDs(acceptedTx)
			if outcome != nil {
				ids = append(ids, outcome.ChangedTargetIDs...)
			}
			if len(ids) > 0 {
				s.bus.Publish(eventbus.TopicTargetStatusChanged,
					eventbus.TargetStatusChanged{SiteID: siteID, TargetIDs: dedupeStrings(ids)})
			}
		}
	}

	high, err := s.watermark(ctx, agentID, pkt.Sequence)
	if err != nil {
		return Ack{}, err
	}
	return Ack{HighestSequence: high, ServerTime: now}, nil
}

// rowQuerier is the read subset shared by the read pool (*store.DB / *sql.DB) and
// an open *sql.Tx, so the provenance serial lookup runs both pre-tx and in-tx.
type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
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
func (s *Service) probeMeta(ctx context.Context, q rowQuerier, agentID, siteID string, ids []string) (map[string]fault.TargetMeta, error) {
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
		       COALESCE(ds.icmp_loss_pct, ?), COALESCE(ds.revision, 1),
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
	args := make([]any, 0, len(ids)+6)
	args = append(args, def.FailRounds, def.RecoverRounds, def.ICMPLossPct, agentID, siteID, agentID)
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
		var enabled int
		var sched reportedSchedule
		var proxyHost, wgEndpoint string
		var proxyPort int
		if err := rows.Scan(&m.ID, &m.Kind, &m.GroupID, &m.Name, &m.Addr, &params, &enabled, &m.ConfigSerial,
			&m.Det.FailRounds, &m.Det.RecoverRounds, &m.Det.ICMPLossPct, &m.Det.Revision,
			&sched.source, &sched.configSerial, &sched.intervalSeconds,
			&sched.cycleDeadlineMs, &sched.uploadSeconds,
			&m.ProxyID, &m.ProxyType, &proxyHost, &proxyPort, &wgEndpoint, &m.ProxyConfigSerial); err != nil {
			return nil, err
		}
		m.Enabled = enabled == 1
		m.Port = portFromParams(params)
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

// watermark returns the agent's highest confirmed sequence, maintained in
// memory (seeded from the DB once per agent per process).
func (s *Service) watermark(ctx context.Context, agentID string, seq uint64) (uint64, error) {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	cur, ok := s.highSeq[agentID]
	if !ok {
		var high sql.NullInt64
		if err := s.db.QueryRowContext(ctx,
			`SELECT MAX(sequence) FROM agent_packets WHERE agent_id=?`, agentID).Scan(&high); err != nil {
			return 0, err
		}
		cur = uint64(high.Int64)
	}
	if seq > cur {
		cur = seq
	}
	s.highSeq[agentID] = cur
	return cur, nil
}

// PrunePackets deletes dedup rows older than keep. The agent WAL retains at
// most 72h of unacked samples, so anything older can never legitimately replay;
// without pruning agent_packets grows by one row per packet forever.
func (s *Service) PrunePackets(ctx context.Context, keep time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM agent_packets WHERE received_at < ?`, time.Now().UTC().Add(-keep))
	return err
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

func applyInventory(ctx context.Context, tx *sql.Tx, agentID, siteID string, it telemetry.InventoryItem, now time.Time) error {
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
func applyInterfaceSnapshot(ctx context.Context, tx *sql.Tx, agentID string, snap telemetry.InterfaceSnapshot, metrics []telemetry.Metric, seq uint64, now time.Time) error {
	var storedSeq sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT last_sequence FROM agent_wifi WHERE agent_id=?`, agentID).Scan(&storedSeq)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if storedSeq.Valid && seq <= uint64(storedSeq.Int64) {
		return nil // not a newer packet; delivery order is the authority
	}

	nums := wifiNumericsForRound(metrics, snap.SampledAt)

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

	var defaultGateway, defaultInterface sql.NullString
	if snap.DefaultRoute != nil {
		defaultGateway = nullStr(snap.DefaultRoute.Gateway)
		defaultInterface = nullStr(snap.DefaultRoute.Interface)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO agent_wifi(agent_id, state, reason, sampled_at, last_sequence, default_gateway, default_interface)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET
			state=excluded.state, reason=excluded.reason,
			sampled_at=excluded.sampled_at, last_sequence=excluded.last_sequence,
			default_gateway=excluded.default_gateway, default_interface=excluded.default_interface`,
		agentID, string(snap.WiFiState), nullStr(string(snap.WiFiReason)), snap.SampledAt.UTC(), int64(seq),
		defaultGateway, defaultInterface)
	return err
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
