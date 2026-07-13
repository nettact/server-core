package ingest

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/inventory"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
)

func openWiFiIngest(t *testing.T) (*store.DB, *Service, *inventory.Service, *metrics.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "wifi.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_wifi','site_default',x'00','h','online')`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	m := metrics.New(db)
	return db, New(db, nil, m), inventory.New(db), m
}

func wifiPacket(seq uint64, sampled time.Time, state telemetry.WiFiLinkState, ssid string, interfaces bool) telemetry.Packet {
	snap := telemetry.InterfaceSnapshot{SampledAt: sampled, WiFiState: telemetry.WiFiCollectionOK, Interfaces: []telemetry.InterfaceState{}}
	if interfaces {
		wifi := &telemetry.WiFiInfo{State: state}
		if state == telemetry.WiFiConnected {
			wifi.SSID = ssid
			wifi.Band = telemetry.WiFiBand5
			wifi.Channel = 36
		}
		snap.Interfaces = append(snap.Interfaces, telemetry.InterfaceState{
			Name: "wlan0", Up: true, IsWireless: true,
			WiFi: wifi,
		})
	}
	p := telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_wifi", SiteID: "site_default",
		Sequence: seq, SentAt: sampled, InterfaceSnapshots: []telemetry.InterfaceSnapshot{snap},
	}
	if state == telemetry.WiFiConnected && interfaces {
		p.Metrics = []telemetry.Metric{
			{TS: sampled, Kind: telemetry.WiFiUp, Target: "wlan0", Layer: telemetry.LayerWireless, Value: 1, Unit: telemetry.UnitBool},
			{TS: sampled, Kind: telemetry.WiFiSignalDBm, Target: "wlan0", Layer: telemetry.LayerWireless, Value: -55, Unit: telemetry.UnitDBm},
			{TS: sampled, Kind: telemetry.WiFiQualityPct, Target: "wlan0", Layer: telemetry.LayerWireless, Value: 90, Unit: telemetry.UnitPct},
			{TS: sampled, Kind: telemetry.WiFiLinkRxMbps, Target: "wlan0", Layer: telemetry.LayerWireless, Value: 432.1, Unit: telemetry.UnitMbps},
			{TS: sampled, Kind: telemetry.WiFiLinkTxMbps, Target: "wlan0", Layer: telemetry.LayerWireless, Value: 866.7, Unit: telemetry.UnitMbps},
		}
	}
	return p
}

func TestInterfaceSnapshotUsesSequenceAndExactRoundNumerics(t *testing.T) {
	db, svc, inv, metricStore := openWiFiIngest(t)
	ctx := context.Background()
	t1 := time.Date(2026, 7, 13, 1, 0, 0, 123456789, time.UTC)

	if _, err := svc.Ingest(ctx, "agent_wifi", "site_default", wifiPacket(10, t1, telemetry.WiFiConnected, "home", true)); err != nil {
		t.Fatalf("ingest connected: %v", err)
	}
	col, ifaces, err := inv.ListInterfaces(ctx, "agent_wifi")
	if err != nil || col.State != "ok" || len(ifaces) != 1 || ifaces[0].WiFi == nil {
		t.Fatalf("connected inventory: col=%+v ifaces=%+v err=%v", col, ifaces, err)
	}
	w := ifaces[0].WiFi
	if w.SSID != "home" || w.SignalDBm == nil || *w.SignalDBm != -55 || w.TxMbps == nil || *w.TxMbps != 866.7 {
		t.Fatalf("current-round Wi-Fi values=%+v", w)
	}

	// A newly seen but lower packet sequence must not replace authoritative
	// current state, even if its wall-clock sample is later.
	if _, err := svc.Ingest(ctx, "agent_wifi", "site_default", wifiPacket(9, t1.Add(time.Hour), telemetry.WiFiConnected, "wrong", true)); err != nil {
		t.Fatalf("ingest lower sequence: %v", err)
	}
	_, ifaces, _ = inv.ListInterfaces(ctx, "agent_wifi")
	if got := ifaces[0].WiFi.SSID; got != "home" {
		t.Fatalf("lower sequence replaced current SSID: %q", got)
	}

	// A higher sequence wins despite device-clock rollback and clears all stale
	// categorical/numeric fields on disconnect.
	if _, err := svc.Ingest(ctx, "agent_wifi", "site_default", wifiPacket(11, t1.Add(-time.Hour), telemetry.WiFiDisconnected, "stale", true)); err != nil {
		t.Fatalf("ingest clock rollback disconnect: %v", err)
	}
	_, ifaces, _ = inv.ListInterfaces(ctx, "agent_wifi")
	w = ifaces[0].WiFi
	if w.State != "disconnected" || w.SSID != "" || w.Band != "" || w.Channel != 0 || w.SignalDBm != nil || w.TxMbps != nil {
		t.Fatalf("disconnect retained details: %+v", w)
	}

	// Wi-Fi history remains queryable, but /latest's Store method excludes it
	// because current Dashboard values come from the authoritative snapshot.
	pts, err := metricStore.Query(ctx, metrics.Query{AgentID: "agent_wifi", Kind: string(telemetry.WiFiSignalDBm), SinceUnix: t1.Add(-time.Minute).Unix()})
	if err != nil || len(pts) != 2 { // seq 10 and the lower-sequence packet both remain valid history
		t.Fatalf("Wi-Fi history=%+v err=%v", pts, err)
	}
	latest, err := metricStore.LatestSnapshot(ctx, "agent_wifi", t1.Add(-time.Minute).Unix())
	if err != nil {
		t.Fatalf("LatestSnapshot: %v", err)
	}
	for _, p := range latest {
		if p.Kind == string(telemetry.WiFiSignalDBm) {
			t.Fatalf("Wi-Fi leaked into per-series current snapshot: %+v", p)
		}
	}

	// An explicit zero-interface snapshot is authoritative and clears rows.
	if _, err := svc.Ingest(ctx, "agent_wifi", "site_default", wifiPacket(12, t1.Add(-30*time.Minute), "", "", false)); err != nil {
		t.Fatalf("ingest empty snapshot: %v", err)
	}
	_, ifaces, err = inv.ListInterfaces(ctx, "agent_wifi")
	if err != nil || len(ifaces) != 0 {
		t.Fatalf("empty snapshot did not clear rows: %+v err=%v", ifaces, err)
	}

	var cols int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('interfaces') WHERE name='wifi_tx_mbps'`).Scan(&cols); err != nil || cols != 1 {
		t.Fatalf("wifi_tx_mbps migration column count=%d err=%v", cols, err)
	}
}
