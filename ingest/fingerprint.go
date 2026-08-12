package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/nettact/protocol/telemetry"
)

// PacketFingerprint returns the semantic identity of a packet's domain
// content, as sha256 hex over the canonical JSON of a hand-written stable
// subset. It is what the packet_receipts ledger stores beside every admitted
// (agent, epoch, sequence), so a replayed sequence can be told apart from a
// renumbered one: same fingerprint = the same batch served again (duplicate,
// ack the watermark); different fingerprint or no receipt at all = the
// sequence was reused for different content, which must never be renumbered
// in place — the hub answers it with an epoch rotation challenge.
//
// What is deliberately EXCLUDED:
//
//   - SchemaVersion, AgentID, SiteID, Sequence, SentAt — transport identity,
//     not content. The receipt key (agent, epoch, sequence) already names the
//     slot; including these would only differ between legitimate re-serves
//     of one batch under two routes.
//   - Per-sample timestamps (Metric.TS, Event.TS): the WAL re-serves batches
//     with clock-corrected stamps, so timestamps are not identity — hashing
//     them would read every clock correction as a conflict.
//   - InterfaceSnapshots, GameRuns/GameBuckets/GameGaps/GameHostSeconds,
//     TraceResults, SceneReports: these are latest-wins or self-describing
//     records whose own keys (interface rounds ordered by packet sequence,
//     run+second, report ids) already make re-serving idempotent. A sequence
//     reuse that differs ONLY in these reads as a duplicate — a bounded,
//     documented trade-off: treating them as identity would make every
//     legitimate WAL re-serve of growing game runs a false conflict, which is
//     worse than the collision it prevents.
//
// Inventory items are included in full: a device delta is content, and its
// LastSeen is part of what the agent recorded about the device.
//
// This function is the single place Cloud's extended spec later replaces — a
// richer content hash or a Merkle structure lands here, and the ledger
// semantics stay unchanged.
func PacketFingerprint(pkt telemetry.Packet) string {
	canon := fingerprintPacket{
		Metrics:   make([]fingerprintMetric, 0, len(pkt.Metrics)),
		Events:    make([]fingerprintEvent, 0, len(pkt.Events)),
		Inventory: pkt.InventoryDelta,
	}
	for _, m := range pkt.Metrics {
		canon.Metrics = append(canon.Metrics, fingerprintMetric{
			Kind:         string(m.Kind),
			Target:       m.Target,
			Layer:        string(m.Layer),
			Value:        m.Value,
			Unit:         m.Unit,
			Labels:       m.Labels,
			MonitorID:    m.MonitorID,
			ConfigSerial: m.ConfigSerial,
		})
	}
	for _, e := range pkt.Events {
		canon.Events = append(canon.Events, fingerprintEvent{
			ID:       e.ID,
			Type:     string(e.Type),
			Layer:    string(e.Layer),
			Severity: string(e.Severity),
			Message:  e.Message,
			Attrs:    e.Attrs,
		})
	}
	// encoding/json emits map keys sorted and struct fields in declaration
	// order, so identical content hashes identically. Slice order is kept as
	// the packet carried it: the WAL re-serves batches byte-identical.
	b, err := json.Marshal(canon)
	if err != nil {
		// Unreachable for this all-JSON-scalar struct. Fail CLOSED: a digest no
		// real fingerprint can equal, so the receipt comparison reads it as a
		// conflict rather than a false duplicate.
		return "marshal-error"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fingerprintPacket / fingerprintMetric / fingerprintEvent are the canonical
// stable subset PacketFingerprint hashes. Hand-written rather than derived
// from the wire structs so a field added to telemetry.Packet is included in
// the fingerprint only by a deliberate edit here — transport-volatile fields
// must never leak in by default.
type fingerprintPacket struct {
	Metrics   []fingerprintMetric      `json:"metrics,omitempty"`
	Events    []fingerprintEvent       `json:"events,omitempty"`
	Inventory []telemetry.InventoryItem `json:"inventory,omitempty"`
}

// fingerprintMetric is a Metric without its timestamp.
type fingerprintMetric struct {
	Kind         string            `json:"kind"`
	Target       string            `json:"target,omitempty"`
	Layer        string            `json:"layer,omitempty"`
	Value        float64           `json:"value"`
	Unit         string            `json:"unit,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	MonitorID    string            `json:"monitor_id,omitempty"`
	ConfigSerial int               `json:"config_serial,omitempty"`
}

// fingerprintEvent is an Event without its timestamp.
type fingerprintEvent struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Layer    string            `json:"layer,omitempty"`
	Severity string            `json:"severity"`
	Message  string            `json:"message,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}
