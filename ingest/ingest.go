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
	"strings"
	"sync"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/rules"
	"github.com/nettact/server-core/store"
)

// Ack is returned to the agent after a successful ingest. HighestSequence is the
// confirmed watermark the agent's uploader uses to prune its WAL.
type Ack struct {
	HighestSequence uint64    `json:"highest_sequence"`
	ServerTime      time.Time `json:"server_time"`
}

// Evaluator is the fault-engine surface ingest drives inside its own sample
// transaction so telemetry samples and their rule evaluation reach one committed
// state atomically. Satisfied by *rules.Service; kept as a small interface so
// ingest unit tests can pass nil (evaluation is then skipped). PublishOutcome runs
// post-commit, off the write path.
type Evaluator interface {
	EvaluateAgentTx(ctx context.Context, tx *sql.Tx, agentID, siteID string, overlay *rules.Overlay) (*rules.Outcome, error)
	PublishOutcome(ctx context.Context, out *rules.Outcome)
}

type Service struct {
	db      *store.DB
	bus     *eventbus.Bus
	metrics *metrics.Store
	rules   Evaluator // nil-safe: telemetry then commits without inline evaluation

	// Per-agent highest-sequence watermark, cached so the hot ingest path does
	// not re-run MAX(sequence) on every packet. Loaded from the DB on first
	// sight of an agent, then maintained in memory.
	seqMu   sync.Mutex
	highSeq map[string]uint64
}

func New(db *store.DB, bus *eventbus.Bus, m *metrics.Store, ev Evaluator) *Service {
	return &Service{db: db, bus: bus, metrics: m, rules: ev, highSeq: make(map[string]uint64)}
}

// Ingest stores one telemetry packet idempotently and returns the ack watermark.
func (s *Service) Ingest(ctx context.Context, agentID, siteID string, pkt telemetry.Packet) (Ack, error) {
	if err := protocol.ValidateSchema(pkt.SchemaVersion); err != nil {
		return Ack{}, err
	}
	now := time.Now().UTC()

	// Provenance gate (pre-tx, read pool): a probe sample is accepted only if its
	// monitor still exists AND its ConfigSerial exactly matches the target's
	// current material generation. Unknown monitors (deleted/recreated), lower
	// serials (obsolete backlog / replay), and higher serials (corrupt/forged
	// future) are dropped. System metrics (MonitorID=="") carry generation 0 and
	// always pass. The authoritative re-check runs inside the write tx below.
	var accepted []telemetry.Metric
	if len(pkt.Metrics) > 0 {
		serials, err := s.probeSerials(ctx, s.db.Read(), monitorIDs(pkt.Metrics))
		if err != nil {
			return Ack{}, err
		}
		var dropped int
		accepted, dropped = filterByGeneration(pkt.Metrics, serials)
		if dropped > 0 {
			log.Printf("ingest: dropped %d obsolete-generation probe samples from agent %s", dropped, agentID)
		}
	}

	// Resolve series ids before opening the tx (SQLite is single-connection).
	var seriesIDs map[string]int64
	if len(accepted) > 0 {
		var err error
		if seriesIDs, err = s.metrics.EnsureSeries(ctx, agentID, siteID, accepted); err != nil {
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
	var outcome *rules.Outcome
	if affected > 0 {
		// Authoritative in-tx re-check: config edits serialize on the single write
		// connection, so a serial read here has no TOCTOU with the pre-tx filter.
		acceptedTx = accepted
		if len(accepted) > 0 {
			serials, err := s.probeSerials(ctx, tx, monitorIDs(accepted))
			if err != nil {
				return Ack{}, err
			}
			acceptedTx, _ = filterByGeneration(accepted, serials)
		}
		if err := s.metrics.InsertSamples(ctx, tx, agentID, seriesIDs, acceptedTx); err != nil {
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
		// Rule evaluation runs INSIDE this sample transaction so samples,
		// rule_condition_state, alerts, incidents and evidence commit atomically:
		// the next status read can never observe updated alerts with stale condition
		// state or vice versa. An evaluation error rolls the whole batch back and the
		// agent's ack is withheld (it retries the sequence). The overlay carries the
		// accepted batch so the in-tx pass sees this cycle's values before the
		// post-commit latest-cache refresh.
		if s.rules != nil {
			overlay := rules.BuildOverlay(acceptedTx, now.Add(-5*time.Minute).Unix())
			outcome, err = s.rules.EvaluateAgentTx(ctx, tx, agentID, siteID, overlay)
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
		// rule outcome's lifecycle events/notifications, then one precise
		// target-status event over the accepted probe monitors ∪ the rule outcome's
		// changed targets.
		if len(acceptedTx) > 0 {
			s.metrics.UpdateLatest(agentID, seriesIDs, acceptedTx)
		}
		if s.rules != nil && outcome != nil {
			s.rules.PublishOutcome(ctx, outcome)
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

// probeSerials loads the current material generation (config_serial) of each
// referenced probe target. Absent ids simply do not appear in the map.
func (s *Service) probeSerials(ctx context.Context, q rowQuerier, ids []string) (map[string]int, error) {
	out := make(map[string]int, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	query := `SELECT id, config_serial FROM probe_tasks WHERE id IN (` + placeholders(len(ids)) + `)`
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var serial int
		if err := rows.Scan(&id, &serial); err != nil {
			return nil, err
		}
		out[id] = serial
	}
	return out, rows.Err()
}

// filterByGeneration keeps system metrics (MonitorID=="") verbatim and each probe
// metric only when its ConfigSerial exactly equals the target's current serial.
// Returns the accepted metrics and the number dropped.
func filterByGeneration(ms []telemetry.Metric, serials map[string]int) ([]telemetry.Metric, int) {
	accepted := make([]telemetry.Metric, 0, len(ms))
	dropped := 0
	for i := range ms {
		m := ms[i]
		if m.MonitorID == "" {
			accepted = append(accepted, m)
			continue
		}
		cur, ok := serials[m.MonitorID]
		if !ok || m.ConfigSerial != cur {
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

	_, err = tx.ExecContext(ctx, `
		INSERT INTO agent_wifi(agent_id, state, reason, sampled_at, last_sequence)
		VALUES(?,?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET
			state=excluded.state, reason=excluded.reason,
			sampled_at=excluded.sampled_at, last_sequence=excluded.last_sequence`,
		agentID, string(snap.WiFiState), nullStr(string(snap.WiFiReason)), snap.SampledAt.UTC(), int64(seq))
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
