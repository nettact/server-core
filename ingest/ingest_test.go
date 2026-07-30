package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/inventory"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func openWiFiIngest(t *testing.T) (*store.DB, *Service, *inventory.Service, *metrics.Store) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_wifi','site_default',x'00','h','online')`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	m := metrics.New(db)
	return db, New(db, nil, m, nil), inventory.New(db, nil), m
}

func wifiPacket(seq uint64, sampled time.Time, state telemetry.WiFiLinkState, ssid string, interfaces bool) telemetry.Packet {
	snap := telemetry.InterfaceSnapshot{SampledAt: sampled, WiFiState: telemetry.WiFiCollectionOK, Interfaces: []telemetry.InterfaceState{}}
	if interfaces {
		snap.DefaultRoute = &telemetry.SnapshotRoute{Gateway: "192.168.1.1", Interface: "wlan0"}
		wifi := &telemetry.WiFiInfo{State: state}
		if state == telemetry.WiFiConnected {
			wifi.SSID = ssid
			wifi.Band = telemetry.WiFiBand5
			wifi.Channel = 36
		}
		snap.Interfaces = append(snap.Interfaces, telemetry.InterfaceState{
			Name: "wlan0", Gateway: "192.168.1.1", Up: true, IsWireless: true,
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
	// Keep the samples inside the raw-data query tier. A fixed wall-clock
	// timestamp eventually makes Query select a rollup table, but this test does
	// not run the rollup worker and is specifically exercising raw ingest.
	t1 := time.Now().UTC().Add(-15 * time.Minute).Truncate(time.Second)

	if _, err := svc.Ingest(ctx, "agent_wifi", "site_default", wifiPacket(10, t1, telemetry.WiFiConnected, "home", true)); err != nil {
		t.Fatalf("ingest connected: %v", err)
	}
	col, ifaces, err := inv.ListInterfaces(ctx, "agent_wifi")
	if err != nil || col.State != "ok" || len(ifaces) != 1 || ifaces[0].WiFi == nil {
		t.Fatalf("connected inventory: col=%+v ifaces=%+v err=%v", col, ifaces, err)
	}
	if col.DefaultRoute == nil || col.DefaultRoute.Gateway != "192.168.1.1" || col.DefaultRoute.Interface != "wlan0" {
		t.Fatalf("default route=%+v", col.DefaultRoute)
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
	col, ifaces, err = inv.ListInterfaces(ctx, "agent_wifi")
	if err != nil || len(ifaces) != 0 {
		t.Fatalf("empty snapshot did not clear rows: %+v err=%v", ifaces, err)
	}
	if col.DefaultRoute != nil {
		t.Fatalf("empty snapshot retained default route: %+v", col.DefaultRoute)
	}

	var cols int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('interfaces') WHERE name='wifi_tx_mbps'`).Scan(&cols); err != nil || cols != 1 {
		t.Fatalf("wifi_tx_mbps migration column count=%d err=%v", cols, err)
	}
}

func TestProbeMetricsRequireExactTargetGeneration(t *testing.T) {
	metrics := []telemetry.Metric{
		{Kind: telemetry.HostCPUPct},
		{Kind: telemetry.HTTPOK, MonitorID: "current", ConfigSerial: 5},
		{Kind: telemetry.HTTPOK, MonitorID: "stale", ConfigSerial: 4},
		{Kind: telemetry.HTTPOK, MonitorID: "future", ConfigSerial: 6},
		{Kind: telemetry.HTTPOK, MonitorID: "deleted", ConfigSerial: 5},
	}
	accepted, dropped := filterByGeneration(metrics, map[string]fault.TargetMeta{
		"current": {ID: "current", Kind: "http", Enabled: true, ConfigSerial: 5},
		"stale":   {ID: "stale", Kind: "http", Enabled: true, ConfigSerial: 5},
		"future":  {ID: "future", Kind: "http", Enabled: true, ConfigSerial: 5},
	})
	if dropped != 3 {
		t.Fatalf("dropped = %d, want stale + future + deleted", dropped)
	}
	if len(accepted) != 2 || accepted[0].MonitorID != "" || accepted[1].MonitorID != "current" {
		t.Fatalf("accepted = %+v, want system + exact-current", accepted)
	}
}
