package ingest

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/asnlookup"
	"github.com/nettact/server-core/incidentops"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

// recordingTracer captures what reaches the diagnosis-trace path.
type recordingTracer struct{ got []telemetry.TraceResult }

func (r *recordingTracer) IngestTracesTx(_ context.Context, _ store.WriteTx, _, _ string, rs []telemetry.TraceResult) (*incidentops.TraceOutcome, error) {
	r.got = append(r.got, rs...)
	return nil, nil
}
func (r *recordingTracer) PublishTraceOutcome(context.Context, *incidentops.TraceOutcome) {}
func (r *recordingTracer) IngestScenesTx(context.Context, store.WriteTx, string, string, []telemetry.SceneReport) (*incidentops.SceneOutcome, error) {
	return nil, nil
}
func (r *recordingTracer) PublishSceneOutcome(context.Context, *incidentops.SceneOutcome) {}

type oneASN struct{}

func (oneASN) Version() string { return "v-test" }
func (oneASN) Lookup(a netip.Addr) (asnlookup.Info, bool) {
	if !asnlookup.IsPublicIPv4(a) {
		return asnlookup.Info{}, false
	}
	return asnlookup.Info{ASN: uint32(a.As4()[0]) * 10, Name: "X", Prefix: "x"}, true
}

func openRouteIngest(t *testing.T) (*store.DB, *Service, *recordingTracer) {
	t.Helper()
	db := storetest.Open(t)
	for _, q := range []string{
		`INSERT INTO sites(id,name) VALUES('site_default','Default')`,
		`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_a','site_default',x'00','h','online')`,
		`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('g_all','site_default','All',1)`,
		`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('g_none','site_default','Nobody',0)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,config_serial) VALUES('m_trace','site_default','g_all','trace','example.com','{}',1,4)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,config_serial) VALUES('m_icmp','site_default','g_all','icmp','example.com','{}',1,4)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,config_serial) VALUES('m_scoped_out','site_default','g_none','trace','example.org','{}',1,4)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,config_serial) VALUES('m_off','site_default','g_all','trace','example.net','{}',0,4)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tr := &recordingTracer{}
	svc := New(db, nil, metrics.New(db, tsstoretest.Open(t)), nil, nil, tr)
	svc.ASN = oneASN{}
	return db, svc, tr
}

func scheduledSweep(id, monitor string, serial int, at time.Time) telemetry.TraceResult {
	return telemetry.TraceResult{
		ReportID: id, DestinationIP: "31.0.0.9", Reached: true, ReachedTTL: 2,
		SubjectKind: telemetry.TraceSubjectTarget, PathScope: telemetry.TracePathDirect,
		TriggerReason: telemetry.TraceTriggerScheduled, Status: telemetry.TraceStatusSucceeded,
		StartedAt: at, MonitorID: monitor, ConfigSerial: serial,
		Hops: []telemetry.TraceHop{
			{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "11.0.0.1", RTTMs: 1}}},
			{TTL: 2, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "31.0.0.9", RTTMs: 20}}},
		},
	}
}

func routePacket(seq uint64, trs ...telemetry.TraceResult) telemetry.Packet {
	return telemetry.Packet{SchemaVersion: protocol.SchemaVersion, AgentID: "agent_a", SiteID: "site_default",
		Sequence: seq, SentAt: time.Now().UTC(), TraceResults: trs}
}

// Scheduled sweeps go to route history and never to the diagnosis store;
// diagnosis traces keep their path exactly; sweeps for monitors that are not
// this agent's current trace monitors are dropped while the packet is still
// acked; and a replayed packet changes nothing.
func TestScheduledSweepsAreRoutedToRouteHistory(t *testing.T) {
	db, svc, tracer := openRouteIngest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)

	diag := telemetry.TraceResult{ReportID: "diag-1", TriggerReason: telemetry.TraceTriggerConsecutiveFailures,
		Status: telemetry.TraceStatusSucceeded}
	noMonitor := scheduledSweep("sched-no-monitor", "", 0, at)
	stale := scheduledSweep("stale", "m_trace", 3, at)
	future := scheduledSweep("future", "m_trace", 5, at)
	wrongKind := scheduledSweep("wrong-kind", "m_icmp", 4, at)
	outOfScope := scheduledSweep("out-of-scope", "m_scoped_out", 4, at)
	disabled := scheduledSweep("disabled", "m_off", 4, at)
	unknown := scheduledSweep("unknown", "m_gone", 4, at)
	proxied := scheduledSweep("proxied", "m_trace", 4, at)
	proxied.PathScope, proxied.EgressProxyID = telemetry.TracePathWireGuardInner, "px1"
	good := scheduledSweep("good", "m_trace", 4, at)

	pkt := routePacket(1, diag, noMonitor, stale, future, wrongKind, outOfScope, disabled, unknown, proxied, good)
	ack, err := svc.Ingest(ctx, "agent_a", "site_default", 1, pkt)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if ack.HighestSequence != 1 {
		t.Fatalf("ack = %d, want the packet acked despite the dropped sweeps", ack.HighestSequence)
	}
	if len(tracer.got) != 2 || tracer.got[0].ReportID != "diag-1" || tracer.got[1].ReportID != "sched-no-monitor" {
		t.Fatalf("diagnosis path got %+v, want exactly the diagnosis trace and the monitor-less sweep", tracer.got)
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM route_runs_detail`); n != 1 {
		t.Fatalf("route runs = %d, want only the current-generation sweep", n)
	}
	var report string
	db.QueryRow(`SELECT report_id FROM route_runs_detail`).Scan(&report)
	if report != "good" {
		t.Errorf("recorded %q", report)
	}
	if n := count(`SELECT COUNT(*) FROM route_epochs WHERE agent_id='agent_a' AND monitor_id='m_trace' AND config_serial=4`); n != 1 {
		t.Errorf("epochs = %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM route_ips WHERE asn<>0 AND asn_db_version='v-test'`); n != 2 {
		t.Errorf("the injected resolver was not used: %d resolved hops", n)
	}
	if n := count(`SELECT COUNT(*) FROM trace_reports`); n != 0 {
		t.Errorf("trace_reports = %d: scheduled sweeps must never reach the diagnosis store", n)
	}

	// Replay of the same packet: deduplicated before any domain write.
	if _, err := svc.Ingest(ctx, "agent_a", "site_default", 1, pkt); err != nil {
		t.Fatalf("replay: %v", err)
	}
	var runs int
	db.QueryRow(`SELECT run_count FROM route_epochs`).Scan(&runs)
	if runs != 1 || count(`SELECT COUNT(*) FROM route_runs_detail`) != 1 || len(tracer.got) != 2 {
		t.Errorf("replay changed state: runs=%d tracer=%d", runs, len(tracer.got))
	}

	// The same report in a NEW packet (an agent that re-queued it) is a no-op
	// too: route history is idempotent per report id on its own.
	again := scheduledSweep("good", "m_trace", 4, at)
	if _, err := svc.Ingest(ctx, "agent_a", "site_default", 1, routePacket(2, again)); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT run_count FROM route_epochs`).Scan(&runs)
	if runs != 1 {
		t.Errorf("a re-sent report was counted twice: runs=%d", runs)
	}

	// A nil resolver is supported: the sweep is recorded without ASNs.
	svc.ASN = nil
	if _, err := svc.Ingest(ctx, "agent_a", "site_default", 1, routePacket(3, scheduledSweep("next", "m_trace", 4, at.Add(10*time.Minute)))); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT COUNT(*) FROM route_runs_detail`); n != 2 {
		t.Errorf("nil resolver: runs = %d", n)
	}
	var dev int
	db.QueryRow(`SELECT run_count, deviation_count FROM route_epochs`).Scan(&runs, &dev)
	if runs != 2 || dev != 0 {
		t.Errorf("an AS-less sweep must extend the era, not deviate from it: runs=%d deviations=%d", runs, dev)
	}
}
