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
	"sync"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
)

// Ack is returned to the agent after a successful ingest. HighestSequence is the
// confirmed watermark the agent's uploader uses to prune its WAL.
type Ack struct {
	HighestSequence uint64    `json:"highest_sequence"`
	ServerTime      time.Time `json:"server_time"`
}

type Service struct {
	db      *store.DB
	bus     *eventbus.Bus
	metrics *metrics.Store

	// Per-agent highest-sequence watermark, cached so the hot ingest path does
	// not re-run MAX(sequence) on every packet. Loaded from the DB on first
	// sight of an agent, then maintained in memory.
	seqMu   sync.Mutex
	highSeq map[string]uint64
}

func New(db *store.DB, bus *eventbus.Bus, m *metrics.Store) *Service {
	return &Service{db: db, bus: bus, metrics: m, highSeq: make(map[string]uint64)}
}

// Ingest stores one telemetry packet idempotently and returns the ack watermark.
func (s *Service) Ingest(ctx context.Context, agentID, siteID string, pkt telemetry.Packet) (Ack, error) {
	if err := protocol.ValidateSchema(pkt.SchemaVersion); err != nil {
		return Ack{}, err
	}
	now := time.Now().UTC()

	// Resolve series ids before opening the tx (SQLite is single-connection).
	var seriesIDs map[string]int64
	if len(pkt.Metrics) > 0 {
		var err error
		if seriesIDs, err = s.metrics.EnsureSeries(ctx, agentID, siteID, pkt.Metrics); err != nil {
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

	if affected > 0 {
		if err := s.metrics.InsertSamples(ctx, tx, agentID, seriesIDs, pkt.Metrics); err != nil {
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
	}

	if err := tx.Commit(); err != nil {
		return Ack{}, err
	}
	committed = true

	if affected > 0 {
		// Fold the committed batch into the in-memory latest cache (only after
		// commit — a rolled-back batch must not surface as "current").
		if len(pkt.Metrics) > 0 {
			s.metrics.UpdateLatest(agentID, seriesIDs, pkt.Metrics)
		}
		if s.bus != nil {
			s.bus.Publish(eventbus.TopicTelemetryIngested, eventbus.TelemetryIngested{AgentID: agentID, SiteID: siteID})
		}
	}

	high, err := s.watermark(ctx, agentID, pkt.Sequence)
	if err != nil {
		return Ack{}, err
	}
	return Ack{HighestSequence: high, ServerTime: now}, nil
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
	case telemetry.InventoryInterface:
		if it.Op == telemetry.OpRemove {
			_, err := tx.ExecContext(ctx, `DELETE FROM interfaces WHERE agent_id=? AND name=?`, agentID, it.Name)
			return err
		}
		up := 0
		if it.Up {
			up = 1
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO interfaces(id, agent_id, name, addrs, gateway, dns, up, updated_at)
			VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(agent_id, name) DO UPDATE SET
				addrs=excluded.addrs, gateway=excluded.gateway, dns=excluded.dns,
				up=excluded.up, updated_at=excluded.updated_at`,
			agentID+"/"+it.Name, agentID, it.Name, encodeSlice(it.Addrs), it.Gateway, encodeSlice(it.DNS), up, now)
		return err
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
