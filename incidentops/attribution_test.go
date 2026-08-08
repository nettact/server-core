package incidentops

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
)

// The trace's reached-point is the strongest attribution evidence there is, so
// both paths that can attach one — ingest, and a later fault confirmation
// claiming a report that arrived first — have to re-answer "where did this
// break". Only an attribution that actually changed is published, so a trace
// that confirms the current guess stays quiet.

// seedISPScene sets up the shape where a LAN-only trace changes the verdict: a
// healthy gateway reference plus one failing public ICMP target. The honest
// first-stage attribution is service; a trace that never left the LAN upgrades it
// to isp.

func TestIngestedTraceRecomputesAttribution(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	if _, err := db.ExecContext(ctx, `
		INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
		VALUES('group','site_default','Group',1,0,1)`); err != nil {
		t.Fatalf("seed monitor group: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		VALUES('probe_gw','site_default','group','gateway','GW','gateway','{}',1,1)`); err != nil {
		t.Fatalf("seed gateway task: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id,monitor_id,status,config_version,updated_at)
		VALUES('agent_a','probe_gw','active',1,?)`, time.Now().UTC()); err != nil {
		t.Fatalf("seed monitor status: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO detector_state(target_id,agent_id,fail_rounds,ok_rounds,last_round_ts,pending_fails,updated_at)
		VALUES('probe_gw','agent_a',0,0,?, '[]', ?)`, time.Now().UTC().Unix(), time.Now().UTC()); err != nil {
		t.Fatalf("seed detector state: %v", err)
	}
	// Make the firing member look like a public ICMP failure.
	if _, err := db.ExecContext(ctx, `
		UPDATE fault_signals SET probe_kind='icmp', target_addr='8.8.8.8', metric_kind='probe.icmp.loss_pct', reason_code=?
		WHERE id='sig_1'`, telemetry.ProbeReasonTimeout); err != nil {
		t.Fatalf("shape signal: %v", err)
	}
	// Pin the first stage (what recomputeIncident would have written at open time).
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	changed, _, err := fault.RecomputeAttributionTx(ctx, tx, "inc_1")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("RecomputeAttributionTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !changed {
		t.Fatalf("first-stage recompute must write the service attribution")
	}

	bus := eventbus.New()
	var seen eventBusMu
	bus.Subscribe(eventbus.TopicIncidentUpdated, func(m eventbus.Message) { seen.add(m) })
	svc := New(db, nil, settings.New(db), bus)

	lanOnly := telemetry.TraceResult{
		ReportID: "trace_lan", Mode: "icmp",
		DestKey: "ip:8.8.8.8", DestHost: "8.8.8.8",
		SubjectKind: telemetry.TraceSubjectTarget, PathScope: telemetry.TracePathDirect,
		TriggerReason: telemetry.TraceTriggerConsecutiveFailures, TriggerStreak: 3,
		Status: telemetry.TraceStatusPartial, MaxHops: 30, AttemptsPerHop: 3,
		Hops: []telemetry.TraceHop{{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "192.168.1.1", RTTMs: 2}}}},
	}
	ingestTraces(t, svc, ctx, "agent_a", lanOnly)

	var loc string
	if err := db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_1'`).Scan(&loc); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	if loc != fault.LocationISP {
		t.Fatalf("attribution after LAN-only trace = %q want %q", loc, fault.LocationISP)
	}
	if got := seen.count(); got != 1 {
		t.Fatalf("TopicIncidentUpdated published %d time(s), want 1", got)
	}

	// A replayed packet re-presents the same report id. It must change nothing and
	// publish nothing — the Agent's outbox retries under the original sequence, so
	// this is the ordinary case, not an anomaly.
	ingestTraces(t, svc, ctx, "agent_a", lanOnly)
	if got := seen.count(); got != 1 {
		t.Fatalf("replayed report published %d time(s), want still 1", got)
	}
	var reports int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE id='trace_lan'`).Scan(&reports); err != nil {
		t.Fatalf("count reports: %v", err)
	}
	if reports != 1 {
		t.Fatalf("replay stored %d rows for one report id", reports)
	}
}

type eventBusMu struct {
	n int
}

func (m *eventBusMu) add(_ eventbus.Message) { m.n++ }
func (m *eventBusMu) count() int             { return m.n }

// A report that arrives BEFORE its fault is confirmed is the normal case during
// an outage: the Agent traced while nothing could be uploaded and the whole
// backlog drained afterwards. The confirmation claims it, publishes the changed
// attribution to both surfaces (fault centre + target-status page), and does not
// re-claim on a repeat.
func TestConfirmationClaimsAnEarlierTraceAndPublishes(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	if _, err := db.ExecContext(ctx, `
		INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
		VALUES('group','site_default','Group',1,0,1)`); err != nil {
		t.Fatalf("seed monitor group: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		VALUES('probe_gw','site_default','group','gateway','GW','gateway','{}',1,1)`); err != nil {
		t.Fatalf("seed gateway task: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id,monitor_id,status,config_version,updated_at)
		VALUES('agent_a','probe_gw','active',1,?)`, time.Now().UTC()); err != nil {
		t.Fatalf("seed monitor status: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO detector_state(target_id,agent_id,fail_rounds,ok_rounds,last_round_ts,pending_fails,updated_at)
		VALUES('probe_gw','agent_a',0,0,?, '[]', ?)`, time.Now().UTC().Unix(), time.Now().UTC()); err != nil {
		t.Fatalf("seed detector state: %v", err)
	}
	seedEvidence(t, db, "sig_1", "icmp", "8.8.8.8", 0, "probe.icmp.loss_pct")

	// The report landed first and attached to nothing.
	seedStoredTrace(t, db, "trace_early", "", "", "agent_a", "ip:8.8.8.8", "8.8.8.8")
	if _, err := db.ExecContext(ctx, `
		INSERT INTO trace_hops(report_id,ttl,attempt,addr,rtt_us,timed_out)
		VALUES('trace_early',1,0,'192.168.1.1',2000,0)`); err != nil {
		t.Fatalf("seed hop: %v", err)
	}

	bus := eventbus.New()
	var seen eventBusMu2
	bus.Subscribe(eventbus.TopicIncidentUpdated, func(eventbus.Message) { seen.incident++ })
	bus.Subscribe(eventbus.TopicTargetStatusChanged, func(eventbus.Message) { seen.target++ })
	svc := New(db, nil, settings.New(db), bus)

	ev := fault.SignalEvent{SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default"}
	if err := svc.OnSignalConfirmed(ctx, ev); err != nil {
		t.Fatalf("on signal confirmed: %v", err)
	}

	var refs int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trace_report_refs WHERE report_id='trace_early' AND incident_id='inc_1' AND active=1`).Scan(&refs); err != nil {
		t.Fatalf("count refs: %v", err)
	}
	if refs != 1 {
		t.Fatalf("the confirmation claimed %d reports, want 1", refs)
	}
	var loc string
	if err := db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_1'`).Scan(&loc); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	if loc != fault.LocationISP {
		t.Fatalf("attribution after claim = %q want %q", loc, fault.LocationISP)
	}
	if seen.incident != 1 || seen.target != 1 {
		t.Fatalf("published incident=%d target=%d, want 1/1", seen.incident, seen.target)
	}

	// A timeline entry names the evidence so an operator can see where it came from.
	var timeline int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_1' AND kind='diag.completed' AND ref='trace_early'`).Scan(&timeline); err != nil {
		t.Fatalf("count timeline: %v", err)
	}
	if timeline != 1 {
		t.Fatalf("timeline entries = %d, want 1", timeline)
	}

	// Re-running the handler must not claim the same report twice: it is already
	// referenced, so the window query no longer selects it.
	if err := svc.OnSignalConfirmed(ctx, ev); err != nil {
		t.Fatalf("second confirm: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_1' AND kind='diag.completed'`).Scan(&timeline); err != nil {
		t.Fatalf("count timeline again: %v", err)
	}
	if timeline != 1 {
		t.Fatalf("re-confirm added timeline entries: %d, want 1", timeline)
	}
}

type eventBusMu2 struct {
	incident int
	target   int
}
