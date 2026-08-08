package incidentops

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// ingestTraces runs one packet's worth of reports through the write transaction
// the telemetry ingest would have opened, then publishes as ingest does
// post-commit.
func ingestTraces(t *testing.T, svc *Service, ctx context.Context, agentID string, results ...telemetry.TraceResult) {
	t.Helper()
	tx, err := svc.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	out, err := svc.IngestTracesTx(ctx, tx, agentID, "site_default", results)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("ingest traces: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	svc.PublishTraceOutcome(ctx, out)
}

// basicReport is a well-formed report toward destKey.
func basicReport(id, destKey, destHost string) telemetry.TraceResult {
	now := time.Now().UTC()
	return telemetry.TraceResult{
		ReportID: id, Mode: "icmp",
		DestKey: destKey, DestHost: destHost, DestinationIP: destHost,
		SubjectKind: telemetry.TraceSubjectTarget, PathScope: telemetry.TracePathDirect,
		TriggerReason: telemetry.TraceTriggerConsecutiveFailures, TriggerStreak: 3,
		FirstFailedAt: now.Add(-time.Minute),
		Status:        telemetry.TraceStatusPartial, MaxHops: 30, AttemptsPerHop: 3,
		StartedAt: now.Add(-10 * time.Second), CompletedAt: now,
		Hops: []telemetry.TraceHop{
			{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "192.168.1.1", RTTMs: 1.5}, {Timeout: true}}},
			{TTL: 2, Attempts: []telemetry.TraceAttempt{{Timeout: true}}},
		},
	}
}

func traceStatus(t *testing.T, db *store.DB, id string) (status, reason, subject, trigger string, streak int) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(),
		`SELECT status, reason, subject_kind, trigger_reason, trigger_streak FROM trace_reports WHERE id=?`, id).
		Scan(&status, &reason, &subject, &trigger, &streak); err != nil {
		t.Fatalf("read report %s: %v", id, err)
	}
	return
}

// The report describes itself, so everything the console renders it under has to
// survive the round trip into storage — including the trigger, which is the only
// record of why the trace happened at all now that nothing asked for it.
func TestIngestStoresTheSelfDescribedReport(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	ingestTraces(t, svc, ctx, "agent_a", basicReport("trace_1", "ip:8.8.8.8", "8.8.8.8"))

	status, reason, subject, trigger, streak := traceStatus(t, db, "trace_1")
	if status != telemetry.TraceStatusPartial || reason != "" {
		t.Fatalf("status/reason = %s/%s", status, reason)
	}
	if subject != telemetry.TraceSubjectTarget {
		t.Fatalf("subject = %q", subject)
	}
	if trigger != telemetry.TraceTriggerConsecutiveFailures || streak != 3 {
		t.Fatalf("trigger = %s/%d", trigger, streak)
	}
	var hops int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_hops WHERE report_id='trace_1'`).Scan(&hops); err != nil {
		t.Fatalf("count hops: %v", err)
	}
	if hops != 3 {
		t.Fatalf("stored %d hop attempts, want 3", hops)
	}
}

// A report id belongs to the agent that minted it. A second agent presenting the
// same id must not be able to overwrite the stored execution — the id collides
// and the original stands.
func TestIngestIsIdempotentPerAgentAndReport(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	ingestTraces(t, svc, ctx, "agent_a", basicReport("trace_1", "ip:8.8.8.8", "8.8.8.8"))

	impostor := basicReport("trace_1", "ip:1.1.1.1", "1.1.1.1")
	impostor.Status = telemetry.TraceStatusSucceeded
	ingestTraces(t, svc, ctx, "agent_b", impostor)

	var owner, destKey, status string
	if err := db.QueryRowContext(ctx,
		`SELECT agent_id, dest_key, status FROM trace_reports WHERE id='trace_1'`).Scan(&owner, &destKey, &status); err != nil {
		t.Fatalf("read report: %v", err)
	}
	if owner != "agent_a" || destKey != "ip:8.8.8.8" || status != telemetry.TraceStatusPartial {
		t.Fatalf("a foreign agent overwrote the report: %s/%s/%s", owner, destKey, status)
	}
}

// A status the Agent never produces is a malformed payload, not a new state. It
// is stored as failed rather than as an invented status, and it must not abort
// the whole telemetry packet it rode in on.
func TestIngestNormalizesAMalformedStatus(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	bad := basicReport("trace_bad", "ip:8.8.8.8", "8.8.8.8")
	bad.Status = "running"
	bad.Mode = "udp"
	ingestTraces(t, svc, ctx, "agent_a", bad)

	status, _, _, _, _ := traceStatus(t, db, "trace_bad")
	if status != telemetry.TraceStatusFailed {
		t.Fatalf("status = %q, want %q", status, telemetry.TraceStatusFailed)
	}
	var mode string
	if err := db.QueryRowContext(ctx, `SELECT mode FROM trace_reports WHERE id='trace_bad'`).Scan(&mode); err != nil {
		t.Fatalf("read mode: %v", err)
	}
	if mode != "icmp" {
		t.Fatalf("mode = %q, want the icmp default", mode)
	}
}

// A report arriving while the fault is already firing attaches on the spot: the
// incident gets its reference and its timeline entry without waiting for another
// confirmation that may never come.
func TestIngestAttachesToAnAlreadyFiringFault(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedEvidence(t, db, "sig_1", "icmp", "8.8.8.8", 0, "probe.icmp.loss_pct")
	svc := New(db, nil, settings.New(db), nil)

	ingestTraces(t, svc, ctx, "agent_a", basicReport("trace_1", "ip:8.8.8.8", "8.8.8.8"))

	var refs int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_1' AND incident_id='inc_1' AND active=1`).Scan(&refs); err != nil {
		t.Fatalf("count refs: %v", err)
	}
	if refs != 1 {
		t.Fatalf("refs = %d, want 1", refs)
	}
	var timeline int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_1' AND kind='diag.completed' AND ref='trace_1'`).Scan(&timeline); err != nil {
		t.Fatalf("count timeline: %v", err)
	}
	if timeline != 1 {
		t.Fatalf("timeline entries = %d, want 1", timeline)
	}
}

// The join is by destination, and the destination of an indirect probe is not
// its monitored target: a DNS fault is traced to its resolver. A report of the
// resolver must attach to the DNS fault, and a report of the queried name must
// not — attaching by the nominal target would pair a fault with evidence about a
// path its packets never took.
func TestIngestMatchesTheDiagnosedDestinationNotTheMonitoredTarget(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_dns", "sig_dns", "agent_a", "firing")
	seedEvidence(t, db, "sig_dns", "dns", "example.com", 0, "probe.dns.ok")
	if _, err := db.ExecContext(ctx,
		`UPDATE fault_signals SET resolver_addr='9.9.9.9:53', resolver_protocol='' WHERE id='sig_dns'`); err != nil {
		t.Fatalf("seed resolver evidence: %v", err)
	}
	svc := New(db, nil, settings.New(db), nil)

	// A trace of the queried NAME must not attach.
	ingestTraces(t, svc, ctx, "agent_a", basicReport("trace_name", "host:example.com", "example.com"))
	var wrong int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_name'`).Scan(&wrong); err != nil {
		t.Fatalf("count wrong refs: %v", err)
	}
	if wrong != 0 {
		t.Fatalf("a trace of the queried name attached to the resolver fault (%d refs)", wrong)
	}

	// A trace of the RESOLVER does.
	resolver := basicReport("trace_resolver", "ip:9.9.9.9", "9.9.9.9")
	resolver.SubjectKind = telemetry.TraceSubjectResolver
	ingestTraces(t, svc, ctx, "agent_a", resolver)
	var right int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_resolver' AND incident_id='inc_dns'`).Scan(&right); err != nil {
		t.Fatalf("count resolver refs: %v", err)
	}
	if right != 1 {
		t.Fatalf("resolver trace refs = %d, want 1", right)
	}
}

// A report older than the claim window belongs to an earlier outage. Presenting
// it as this incident's evidence would describe a network state nobody observed
// during the fault.
func TestClaimIgnoresReportsOutsideTheWindow(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedEvidence(t, db, "sig_1", "icmp", "8.8.8.8", 0, "probe.icmp.loss_pct")
	seedStoredTrace(t, db, "trace_old", "", "", "agent_a", "ip:8.8.8.8", "8.8.8.8")
	if _, err := db.ExecContext(ctx,
		`UPDATE trace_reports SET received_at=? WHERE id='trace_old'`,
		time.Now().UTC().Add(-2*claimWindow)); err != nil {
		t.Fatalf("age the report: %v", err)
	}
	svc := New(db, nil, settings.New(db), nil)

	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
	}); err != nil {
		t.Fatalf("on signal confirmed: %v", err)
	}
	var refs int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_old'`).Scan(&refs); err != nil {
		t.Fatalf("count refs: %v", err)
	}
	if refs != 0 {
		t.Fatalf("a stale report was claimed as evidence (%d refs)", refs)
	}
}

// A quality degradation is not a reachability fault — its target is answering,
// just slowly — and an Agent never traces one. Claiming any report for it would
// present a path diagnostic as the explanation of a latency trend.
func TestClaimSkipsDegradationSignals(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedEvidence(t, db, "sig_1", "icmp", "8.8.8.8", 0, "probe.icmp.rtt_ms")
	seedStoredTrace(t, db, "trace_1", "", "", "agent_a", "ip:8.8.8.8", "8.8.8.8")
	svc := New(db, nil, settings.New(db), nil)

	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
		DetectorKey: fault.DetectorLatencyDegradation,
	}); err != nil {
		t.Fatalf("on signal confirmed: %v", err)
	}
	var refs int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_1'`).Scan(&refs); err != nil {
		t.Fatalf("count refs: %v", err)
	}
	if refs != 0 {
		t.Fatalf("a degradation signal claimed a traceroute (%d refs)", refs)
	}
}

// Resolution stops a report counting as live evidence without deleting it: the
// history of what was found stays readable.
func TestResolutionDeactivatesReferencesWithoutDeletingTheReport(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedStoredTrace(t, db, "trace_1", "inc_1", "sig_1", "agent_a", "ip:8.8.8.8", "8.8.8.8")
	svc := New(db, nil, settings.New(db), nil)

	if err := svc.OnSignalResolved(ctx, "sig_1"); err != nil {
		t.Fatalf("on signal resolved: %v", err)
	}
	var active, reports int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_1' AND active=1`).Scan(&active); err != nil {
		t.Fatalf("count active refs: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE id='trace_1'`).Scan(&reports); err != nil {
		t.Fatalf("count reports: %v", err)
	}
	if active != 0 || reports != 1 {
		t.Fatalf("active refs = %d, reports = %d; want 0/1", active, reports)
	}
}
