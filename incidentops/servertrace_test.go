package incidentops

import (
	"testing"
	"time"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/protocol/telemetry"
)

// disconnectTrace is a report the Agent ran because its session to the server
// dropped at lostAt, walking toward the server's own address.
func disconnectTrace(id string, lostAt time.Time) telemetry.TraceResult {
	r := basicReport(id, "ip:203.0.113.10", "203.0.113.10")
	r.Mode, r.Port = "tcp", 12450
	r.TriggerReason = telemetry.TraceTriggerServerDisconnect
	r.FirstFailedAt = lostAt
	return r
}

// The report arrives only once the Agent has reconnected, by which time its
// connectivity fault has usually resolved: it must still land on that outage's
// incident, and be readable there.
func TestDisconnectTraceFilesUnderResolvedConnectivityFault(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	lost := now.Add(-3 * time.Minute)
	resolved := now.Add(-5 * time.Second)
	seedConnectivitySignal(t, db, "inc_conn", "sig_conn", "agent_a", "resolved", lost.Add(-2*time.Second), &resolved)
	svc := New(db, nil, settings.New(db), eventbus.New())

	ingestTraces(t, svc, ctx, "agent_a", disconnectTrace("trace_srv", lost))

	if n := countRows(t, db,
		`SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_srv' AND incident_id='inc_conn' AND signal_id='sig_conn'`); n != 1 {
		t.Fatalf("disconnect trace not filed under the connectivity fault (%d refs)", n)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_conn' AND kind='diag.completed'`); n != 1 {
		t.Fatalf("%d timeline entries, want 1", n)
	}
	got, err := svc.TracesForIncident(ctx, "inc_conn")
	if err != nil || len(got) != 1 || got[0].TriggerReason != telemetry.TraceTriggerServerDisconnect {
		t.Fatalf("traces for incident = %+v, err %v", got, err)
	}
}

// A monitor that watches the server's own address must not adopt the
// disconnect trace — neither on arrival nor when its own fault confirms later.
func TestDisconnectTraceIgnoresTargetFaultOnSameDest(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_tgt", "sig_tgt", "agent_a", "firing")
	seedEvidence(t, db, "sig_tgt", "tcp", "203.0.113.10", 12450, "probe.tcp.connect_ok")
	svc := New(db, nil, settings.New(db), eventbus.New())

	ingestTraces(t, svc, ctx, "agent_a", disconnectTrace("trace_srv", time.Now().UTC()))
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_tgt", IncidentID: "inc_tgt", SiteID: "site_default", AgentID: "agent_a",
		DetectorKey: "availability",
	}); err != nil {
		t.Fatalf("claim back: %v", err)
	}

	if n := countRows(t, db, `SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_srv'`); n != 0 {
		t.Fatalf("disconnect trace attached to a target fault (%d refs)", n)
	}
}

// A session that dropped for less than the detector's grace has no outage to
// own the edge; the report stays unattached rather than adopting an older one.
func TestDisconnectTraceWithoutOutageStaysUnattached(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	oldResolved := now.Add(-30 * time.Minute)
	seedConnectivitySignal(t, db, "inc_old", "sig_old", "agent_a", "resolved", now.Add(-40*time.Minute), &oldResolved)
	svc := New(db, nil, settings.New(db), eventbus.New())

	ingestTraces(t, svc, ctx, "agent_a", disconnectTrace("trace_srv", now.Add(-time.Minute)))

	if n := countRows(t, db, `SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_srv'`); n != 0 {
		t.Fatalf("disconnect trace adopted a previous outage (%d refs)", n)
	}
}
