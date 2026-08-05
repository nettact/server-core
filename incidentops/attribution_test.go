package incidentops

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
)

// IngestTrace's second stage (INCIDENT-003): a terminal trace recomputes the
// referencing incidents' attribution in the same tx, and only an attribution
// that actually changed is published as a TopicIncidentUpdated post-commit.

func TestIngestTraceRecomputesAttribution(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	// A healthy gateway reference + one failing public ICMP target: the honest
	// first-stage attribution is service; a LAN-only trace upgrades it to isp.
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
		UPDATE fault_signals SET probe_kind='icmp', target_addr='8.8.8.8', reason_code=?
		WHERE id='sig_1'`, telemetry.ProbeReasonTimeout); err != nil {
		t.Fatalf("shape signal: %v", err)
	}
	// Recompute directly to pin the first stage (what recomputeIncident would
	// have written at open time).
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
	var mu eventBusMu
	bus.Subscribe(eventbus.TopicIncidentUpdated, func(m eventbus.Message) {
		mu.add(m)
	})
	svc := New(db, nil, settings.New(db), bus)

	seedPlannedTrace(t, db, "trace_lan", "inc_1", "sig_1", "agent_a", pathScopeDirect, "", 0)
	if err := svc.IngestTrace(ctx, "agent_a", telemetry.TraceResult{
		ReportID: "trace_lan", Status: telemetry.TraceStatusPartial, Reached: false, ReachedTTL: 0,
		Hops:      []telemetry.TraceHop{{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "192.168.1.1", RTTMs: 2}}}},
		PathScope: telemetry.TracePathDirect,
	}); err != nil {
		t.Fatalf("ingest LAN-only trace: %v", err)
	}

	var loc string
	if err := db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_1'`).Scan(&loc); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	if loc != fault.LocationISP {
		t.Fatalf("attribution after LAN-only trace = %q want %q", loc, fault.LocationISP)
	}
	if got := mu.count(); got != 1 {
		t.Fatalf("TopicIncidentUpdated published %d time(s), want 1", got)
	}

	// A second ingest of the same evidence must not re-publish.
	if err := svc.IngestTrace(ctx, "agent_a", telemetry.TraceResult{
		ReportID: "trace_lan", Status: telemetry.TraceStatusPartial, Reached: false, ReachedTTL: 0,
		Hops:      []telemetry.TraceHop{{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "192.168.1.1", RTTMs: 2}}}},
		PathScope: telemetry.TracePathDirect,
	}); err != nil {
		t.Fatalf("re-ingest trace: %v", err)
	}
	if got := mu.count(); got != 1 {
		t.Fatalf("re-ingest published %d time(s), want still 1", got)
	}
}

type eventBusMu struct {
	n int
}

func (m *eventBusMu) add(_ eventbus.Message) { m.n++ }
func (m *eventBusMu) count() int             { return m.n }

// RecomputeAfterTerminalTrace folds a shared trace the incident attached to only
// after it was confirmed (single-flight cohort already terminal), and publishes
// BOTH the incident update (fault centre + open drawer) and the target-status
// change (target-status page FaultRef).
func TestRecomputeAfterTerminalTracePublishes(t *testing.T) {
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
	if _, err := db.ExecContext(ctx, `
		UPDATE fault_signals SET probe_kind='icmp', target_addr='8.8.8.8', reason_code=?
		WHERE id='sig_1'`, telemetry.ProbeReasonTimeout); err != nil {
		t.Fatalf("shape signal: %v", err)
	}
	// A terminal LAN-only trace already referenced by this incident's signal, as
	// a cohort attached after confirmation would leave behind.
	seedPlannedTrace(t, db, "trace_attach", "inc_1", "sig_1", "agent_a", pathScopeDirect, "", 0)
	if _, err := db.ExecContext(ctx, `UPDATE trace_reports SET status='partial' WHERE id='trace_attach'`); err != nil {
		t.Fatalf("terminalize trace: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO trace_hops(report_id,ttl,attempt,addr,rtt_us,timed_out)
		VALUES('trace_attach',1,1,'192.168.1.1',1000,0)`); err != nil {
		t.Fatalf("seed trace hop: %v", err)
	}

	bus := eventbus.New()
	var mu eventBusMu2
	bus.Subscribe(eventbus.TopicIncidentUpdated, func(m eventbus.Message) { mu.incident++ })
	bus.Subscribe(eventbus.TopicTargetStatusChanged, func(m eventbus.Message) { mu.target++ })
	svc := New(db, nil, settings.New(db), bus)

	svc.recomputeAfterTerminalTrace(ctx, "inc_1")

	var loc string
	if err := db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_1'`).Scan(&loc); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	if loc != fault.LocationISP {
		t.Fatalf("attribution after terminal attach = %q want %q", loc, fault.LocationISP)
	}
	if mu.incident != 1 || mu.target != 1 {
		t.Fatalf("published incident=%d target=%d, want 1/1", mu.incident, mu.target)
	}
}

type eventBusMu2 struct {
	incident int
	target   int
}
