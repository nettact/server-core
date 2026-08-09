package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

// openHostIngest wires a real fault engine behind ingest, so these tests exercise
// the seam that matters: host readings judged INSIDE the sample transaction.
func openHostIngest(t *testing.T, allAgents bool) (*store.DB, *Service) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status,hostname)
	      VALUES('agent_h','site_default',x'00','h','online','node-1')`)
	all := 0
	if allAgents {
		all = 1
	}
	exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
	      VALUES('mg','site_default','Default',1,0,?)`, all)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	      VALUES('h1','site_default','mg','host','Server','host','{}',1,1)`)
	m := metrics.New(db, tsstoretest.Open(t))
	return db, New(db, nil, m, fault.New(db, nil, nil), nil, nil)
}

func hostSample(ts time.Time, kind telemetry.MetricKind, target string, v float64, unit string) telemetry.Metric {
	return telemetry.Metric{TS: ts, Kind: kind, Target: target, Layer: telemetry.LayerLocal, Value: v, Unit: unit}
}

// hostPacket carries one reading of a busy machine.
func hostPacket(seq uint64, ts time.Time, cpuPct float64) telemetry.Packet {
	return telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_h", SiteID: "site_default",
		Sequence: seq, SentAt: ts,
		Metrics: []telemetry.Metric{
			hostSample(ts, telemetry.HostCPUPct, "host", cpuPct, telemetry.UnitPct),
		},
	}
}

func firingHostSignals(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM fault_signals WHERE state='firing' AND detector_key LIKE 'host_%'`).Scan(&n); err != nil {
		t.Fatalf("count host signals: %v", err)
	}
	return n
}

// TestIngestConfirmsHostFaultInTheSampleTransaction is the end-to-end promise:
// the agent pushes ordinary host metrics and the server, with no rule and no
// per-agent configuration, opens a fault in the same commit as the samples.
func TestIngestConfirmsHostFaultInTheSampleTransaction(t *testing.T) {
	db, svc := openHostIngest(t, true)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)

	// The default is 90% for 5 minutes, which is ten readings at the 30s cadence.
	for i := 0; i < 9; i++ {
		if _, err := svc.Ingest(ctx, "agent_h", "site_default",
			hostPacket(uint64(i+1), base.Add(time.Duration(i)*30*time.Second), 95)); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	if n := firingHostSignals(t, db); n != 0 {
		t.Fatalf("confirmed after 9 of 10 readings (%d signals)", n)
	}
	if _, err := svc.Ingest(ctx, "agent_h", "site_default",
		hostPacket(10, base.Add(9*30*time.Second), 95)); err != nil {
		t.Fatalf("ingest 10: %v", err)
	}
	if n := firingHostSignals(t, db); n != 1 {
		t.Fatalf("host signals = %d after the tenth reading, want 1", n)
	}
	// The samples that prove it committed with it. The raw data plane lives in the
	// embedded TSDB now, so count the host.cpu.pct series via the exported read
	// (MonitorID is empty on host samples, matching the series key).
	ids, err := svc.metrics.ResolveSeriesIDs(ctx, "site_default", "agent_h", "", string(telemetry.HostCPUPct), "host")
	if err != nil {
		t.Fatalf("resolve host cpu series: %v", err)
	}
	rc, err := svc.metrics.CountRange(ctx, ids, 0, 0)
	if err != nil {
		t.Fatalf("count samples: %v", err)
	}
	if rc.Samples != 10 {
		t.Errorf("stored %d samples alongside the fault, want 10", rc.Samples)
	}
}

// TestIngestSkipsHostAnchorsOutOfScope: an anchor whose monitor group does not
// reach this agent must not judge it. Scope is resolved by the same predicate the
// config downlink uses, so this is the one place it can silently diverge.
func TestIngestSkipsHostAnchorsOutOfScope(t *testing.T) {
	db, svc := openHostIngest(t, false) // group broadcasts to nobody
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)

	for i := 0; i < 12; i++ {
		if _, err := svc.Ingest(ctx, "agent_h", "site_default",
			hostPacket(uint64(i+1), base.Add(time.Duration(i)*30*time.Second), 99)); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	if n := firingHostSignals(t, db); n != 0 {
		t.Fatalf("an out-of-scope anchor judged the agent (%d signals)", n)
	}
	var states int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM detector_state`).Scan(&states); err != nil {
		t.Fatalf("count detector state: %v", err)
	}
	if states != 0 {
		t.Errorf("an out-of-scope anchor left %d detector rows", states)
	}
}

// TestIngestDisabledHostAnchorIsInert: disabling the anchor is how an operator
// turns system-status alerting off, and it has to stop evaluation outright.
func TestIngestDisabledHostAnchorIsInert(t *testing.T) {
	db, svc := openHostIngest(t, true)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `UPDATE probe_tasks SET enabled=0 WHERE id='h1'`); err != nil {
		t.Fatalf("disable anchor: %v", err)
	}
	base := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)
	for i := 0; i < 12; i++ {
		if _, err := svc.Ingest(ctx, "agent_h", "site_default",
			hostPacket(uint64(i+1), base.Add(time.Duration(i)*30*time.Second), 99)); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	if n := firingHostSignals(t, db); n != 0 {
		t.Fatalf("a disabled anchor confirmed %d faults", n)
	}
}

// TestIngestReadsCoresFromTheCacheAcrossPackets pins the fallback: the core count
// is reported like any other series, so a packet that does not repeat it must
// still be judged from what the machine last said.
func TestIngestReadsCoresFromTheCacheAcrossPackets(t *testing.T) {
	db, svc := openHostIngest(t, true)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)

	// First packet carries the core count; the rest carry only the load average.
	first := telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_h", SiteID: "site_default",
		Sequence: 1, SentAt: base,
		Metrics: []telemetry.Metric{
			hostSample(base, telemetry.HostCPUCores, "host", 4, telemetry.UnitCount),
			hostSample(base, telemetry.HostLoad1, "host", 16, telemetry.UnitLoad),
		},
	}
	if _, err := svc.Ingest(ctx, "agent_h", "site_default", first); err != nil {
		t.Fatalf("ingest first: %v", err)
	}
	for i := 1; i < 10; i++ {
		ts := base.Add(time.Duration(i) * 30 * time.Second)
		pkt := telemetry.Packet{
			SchemaVersion: protocol.SchemaVersion, AgentID: "agent_h", SiteID: "site_default",
			Sequence: uint64(i + 1), SentAt: ts,
			Metrics:  []telemetry.Metric{hostSample(ts, telemetry.HostLoad1, "host", 16, telemetry.UnitLoad)},
		}
		if _, err := svc.Ingest(ctx, "agent_h", "site_default", pkt); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM fault_signals WHERE state='firing' AND detector_key='host_load'`).Scan(&n); err != nil {
		t.Fatalf("count load signals: %v", err)
	}
	if n != 1 {
		t.Fatalf("load signals = %d, want 1 (16.0 across 4 cores is 4.0 per core)", n)
	}
}

// TestIngestReplayDoesNotDoubleFoldHostReadings: an unacked packet is retried, and
// the dedup that protects samples has to protect the detectors too.
func TestIngestReplayDoesNotDoubleFoldHostReadings(t *testing.T) {
	db, svc := openHostIngest(t, true)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)

	pkt := hostPacket(1, base, 95)
	for i := 0; i < 15; i++ {
		if _, err := svc.Ingest(ctx, "agent_h", "site_default", pkt); err != nil {
			t.Fatalf("ingest replay %d: %v", i, err)
		}
	}
	if n := firingHostSignals(t, db); n != 0 {
		t.Fatalf("a replayed packet confirmed a fault")
	}
	var fail int
	if err := db.QueryRowContext(ctx,
		`SELECT fail_rounds FROM detector_state WHERE detector_key='host_cpu'`).Scan(&fail); err != nil {
		t.Fatalf("read detector state: %v", err)
	}
	if fail != 1 {
		t.Errorf("fail_rounds = %d after 15 deliveries of one reading, want 1", fail)
	}
}

// TestIngestProbeOnlyBatchTouchesNoHostState: the overwhelming majority of
// batches carry no host metrics, and they must not pay for the host path.
func TestIngestProbeOnlyBatchTouchesNoHostState(t *testing.T) {
	db, svc := openHostIngest(t, true)
	ctx := context.Background()
	ts := time.Now().UTC().Truncate(time.Second)
	pkt := telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_h", SiteID: "site_default",
		Sequence: 1, SentAt: ts,
		Metrics: []telemetry.Metric{
			hostSample(ts, telemetry.HostUptime, "host", 1234, telemetry.UnitSec),
		},
	}
	if _, err := svc.Ingest(ctx, "agent_h", "site_default", pkt); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var states int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM detector_state`).Scan(&states); err != nil {
		t.Fatalf("count detector state: %v", err)
	}
	if states != 0 {
		t.Errorf("a batch with no judgeable host metric created %d detector rows", states)
	}
}
