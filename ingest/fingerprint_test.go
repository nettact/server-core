package ingest

import (
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/telemetry"
)

// clonePacket deep-copies the slice headers so mutating a copy cannot reach
// back into base through a shared backing array.
func clonePacket(p telemetry.Packet) telemetry.Packet {
	p.Metrics = append([]telemetry.Metric(nil), p.Metrics...)
	p.Events = append([]telemetry.Event(nil), p.Events...)
	p.InventoryDelta = append([]telemetry.InventoryItem(nil), p.InventoryDelta...)
	return p
}

// TestPacketFingerprintIsContentIdentity pins what the receipt ledger hashes:
// transport-volatile fields (schema, ids, sequence, sent-at) and per-sample
// timestamps are NOT identity — the WAL re-serves batches with clock-corrected
// stamps, so hashing them would read every correction as a conflict — while
// the domain content (metric values/kinds/labels, event payloads, inventory)
// is.
func TestPacketFingerprintIsContentIdentity(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Second)
	base := telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_x", SiteID: "site_default",
		Sequence: 1, SentAt: ts,
		Metrics: []telemetry.Metric{
			{TS: ts, Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Value: 11.2, Unit: telemetry.UnitMs,
				Labels: map[string]string{"a": "1"}, MonitorID: "mon1", ConfigSerial: 3},
		},
		Events: []telemetry.Event{
			{ID: "e1", TS: ts, Type: telemetry.EventIfaceDown, Severity: telemetry.SeverityWarn, Message: "m"},
		},
		InventoryDelta: []telemetry.InventoryItem{{Kind: telemetry.InventoryDevice, Op: telemetry.OpUpsert, MAC: "aa:bb", IP: "10.0.0.1"}},
	}
	fp := PacketFingerprint(base)

	// Transport fields do not matter…
	alt := clonePacket(base)
	alt.SchemaVersion = 999
	alt.AgentID = "other"
	alt.SiteID = "elsewhere"
	alt.Sequence = 42
	alt.SentAt = ts.Add(time.Hour)
	if PacketFingerprint(alt) != fp {
		t.Error("transport-volatile fields changed the fingerprint")
	}
	// …and neither do the timestamps…
	alt = clonePacket(base)
	alt.Metrics[0].TS = ts.Add(time.Hour)
	alt.Events[0].TS = ts.Add(time.Hour)
	if PacketFingerprint(alt) != fp {
		t.Error("sample timestamps changed the fingerprint — clock corrections would read as conflicts")
	}
	// …but the content does.
	alt = clonePacket(base)
	alt.Metrics[0].Value = 11.3
	if PacketFingerprint(alt) == fp {
		t.Error("a different metric value hashed identically")
	}
	alt = clonePacket(base)
	alt.Metrics[0].Labels = map[string]string{"a": "2"}
	if PacketFingerprint(alt) == fp {
		t.Error("a different label hashed identically")
	}
	alt = clonePacket(base)
	alt.Metrics[0].ConfigSerial = 4
	if PacketFingerprint(alt) == fp {
		t.Error("a different config serial hashed identically")
	}
	alt = clonePacket(base)
	alt.Events[0].Message = "other"
	if PacketFingerprint(alt) == fp {
		t.Error("a different event message hashed identically")
	}
	alt = clonePacket(base)
	alt.Events = nil
	if PacketFingerprint(alt) == fp {
		t.Error("dropping the events hashed identically")
	}
	alt = clonePacket(base)
	alt.InventoryDelta = nil
	if PacketFingerprint(alt) == fp {
		t.Error("dropping the inventory hashed identically")
	}
	// Documented exclusions: latest-wins / self-describing records are OUT of
	// the fingerprint — differing only there reads as a duplicate.
	alt = clonePacket(base)
	alt.InterfaceSnapshots = []telemetry.InterfaceSnapshot{{SampledAt: ts, WiFiState: telemetry.WiFiCollectionOK}}
	alt.GameHostSeconds = []gamesense.HostSecond{{TS: ts}}
	alt.TraceResults = []telemetry.TraceResult{{ReportID: "tr1"}}
	alt.SceneReports = []telemetry.SceneReport{{ReportID: "sc1"}}
	if PacketFingerprint(alt) != fp {
		t.Error("the documented exclusions changed the fingerprint")
	}

	// Deterministic for identical content: map keys serialize sorted.
	if PacketFingerprint(base) != PacketFingerprint(base) {
		t.Error("the fingerprint is not deterministic")
	}
}
