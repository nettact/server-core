package incidentops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func openIncidentOpsTest(t *testing.T) (*store.DB, context.Context) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES('site_default','Home')`); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	for _, id := range []string{"agent_a", "agent_b"} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES(?,'site_default',x'00','h','online')`, id); err != nil {
			t.Fatalf("seed agent %s: %v", id, err)
		}
	}
	return db, ctx
}

func seedIncidentSignal(t *testing.T, db *store.DB, incidentID, signalID, agentID, state string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES(?,'site_default','group','Group',?,'open',?)`, incidentID, "sig:"+signalID, now); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO fault_signals(id,agent_id,site_id,target_id,detector_key,group_id,group_name,incident_id,state,observed_at,confirmed_at)
		VALUES(?,?,'site_default',?,'availability','group','Group',?,?,?,?)`,
		signalID, agentID, "probe_"+signalID, incidentID, state, now, now); err != nil {
		t.Fatalf("seed fault signal: %v", err)
	}
}

// The refs pushed to the agent decide how it interprets each target. A gateway
// monitor's target is the sentinel "gateway", so the NIC selection has to travel
// with it — that is the only thing that lets the agent resolve the right gateway
// from its routing table instead of handing the sentinel to DNS. Host anchors
// name a metric series, not a destination, so they must not be sent at all.
func TestSnapshotTargetsCarryIfaceAndDropHostAnchors(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_st", "sig_gw", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_st2", "sig_host", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_st3", "sig_tcp", "agent_a", "firing")
	// seedIncidentSignal derives target_id as "probe_"+signalID.
	for _, q := range []string{
		`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('mg','site_default','all',1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		 VALUES('probe_sig_gw','site_default','mg','gateway','LAN gateway','gateway','{"interface":"以太网"}',1,1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		 VALUES('probe_sig_host','site_default','mg','host','Host CPU','host','{}',1,1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		 VALUES('probe_sig_tcp','site_default','mg','tcp','TLS port','1.1.1.1','{"port":443}',1,1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed probe task: %v", err)
		}
	}
	svc := New(db, nil, settings.New(db), nil)

	got := map[string]pcfg.SnapshotTargetRef{}
	for _, incidentID := range []string{"inc_st", "inc_st2", "inc_st3"} {
		// nil frozen base: this exercises the live-config fallback path.
		for _, ref := range svc.snapshotTargets(ctx, incidentID, "agent_a", nil) {
			got[ref.MonitorID] = ref
		}
	}

	gw, ok := got["probe_sig_gw"]
	if !ok {
		t.Fatalf("gateway target missing from %v", got)
	}
	if gw.Iface != "以太网" {
		t.Errorf("gateway iface = %q, want 以太网", gw.Iface)
	}
	if _, ok := got["probe_sig_host"]; ok {
		t.Error("host anchor was sent to the agent; it has nothing to resolve")
	}
	if tcp := got["probe_sig_tcp"]; tcp.Port != 443 || tcp.Iface != "" {
		t.Errorf("tcp ref = port:%d iface:%q, want port 443 and no iface", tcp.Port, tcp.Iface)
	}
}

// An agent can be offline for the whole collection window. The refs it finally
// receives on reconnect must be the ones frozen when the incident opened — not
// re-derived from probe_tasks, which the operator may have edited or deleted
// meanwhile. Re-deriving collected the scene against the NEW config: a retyped
// host monitor slipped past the host exclusion, and an edited gateway monitor
// sent a different NIC, so the agent resolved a gateway unrelated to the fault.
func TestReconnectRePushUsesFrozenTargetRefs(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_frz", "sig_frz", "agent_a", "firing")
	for _, q := range []string{
		`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('mg','site_default','all',1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		 VALUES('probe_sig_frz','site_default','mg','gateway','LAN gateway','gateway','{"interface":"以太网"}',1,1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Give the snapshot a live deadline so the reconnect path considers it.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incident_snapshots(id,incident_id,status,base,total_bytes,deadline_at,created_at)
		VALUES('isnap_frz','inc_frz','collecting','',0,?,?)`,
		time.Now().UTC().Add(10*time.Minute), time.Now().UTC()); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	svc := New(db, nil, settings.New(db), nil)
	pusher := &capturePusher{}
	svc.SetPusher(pusher)
	if err := svc.OnIncidentOpened(ctx, eventbus.IncidentEvent{IncidentID: "inc_frz", SiteID: "site_default"}); err != nil {
		t.Fatalf("on incident opened: %v", err)
	}
	if len(pusher.snapReq) != 1 || len(pusher.snapReq[0].Targets) != 1 {
		t.Fatalf("initial push = %+v, want one request with one target", pusher.snapReq)
	}
	if got := pusher.snapReq[0].Targets[0].Iface; got != "以太网" {
		t.Fatalf("initial iface = %q, want 以太网", got)
	}

	// The operator now retargets the monitor at another NIC — and a second
	// operator deletes a different one entirely. Neither may reach the re-push.
	if _, err := db.ExecContext(ctx,
		`UPDATE probe_tasks SET params='{"interface":"Wi-Fi"}' WHERE id='probe_sig_frz'`); err != nil {
		t.Fatalf("edit monitor: %v", err)
	}

	svc.OnAgentConnected(ctx, "agent_a")
	if len(pusher.snapReq) != 2 {
		t.Fatalf("re-push count = %d, want 2", len(pusher.snapReq))
	}
	re := pusher.snapReq[1]
	if len(re.Targets) != 1 {
		t.Fatalf("re-pushed targets = %+v, want 1", re.Targets)
	}
	if re.Targets[0].Iface != "以太网" {
		t.Errorf("re-pushed iface = %q, want the frozen 以太网 (config was edited to Wi-Fi)", re.Targets[0].Iface)
	}
	if re.RequestID != pusher.snapReq[0].RequestID {
		t.Errorf("re-push minted a new request id %q, want %q", re.RequestID, pusher.snapReq[0].RequestID)
	}

	// Deleting the monitor outright must not empty the frozen refs either.
	if _, err := db.ExecContext(ctx, `DELETE FROM probe_tasks WHERE id='probe_sig_frz'`); err != nil {
		t.Fatalf("delete monitor: %v", err)
	}
	svc.OnAgentConnected(ctx, "agent_a")
	if len(pusher.snapReq) != 3 {
		t.Fatalf("second re-push count = %d, want 3", len(pusher.snapReq))
	}
	if got := pusher.snapReq[2].Targets; len(got) != 1 || got[0].Iface != "以太网" {
		t.Errorf("after delete, re-pushed targets = %+v, want the frozen gateway ref", got)
	}
}

// OnIncidentOpened runs post-commit, so a monitor edit can land between the
// incident transaction and the entry-creation read. The refs frozen onto the
// entry must come from the base captured INSIDE the transaction — reading live
// probe_tasks here froze the edited config permanently: a re-NIC'd gateway
// resolved the wrong gateway, and a monitor retyped to "host" vanished from the
// scene entirely, with the base right next to it still showing the config that
// raised the incident.
func TestEntryTargetsFrozenAgainstPostCommitEdit(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_gap", "sig_gap", "agent_a", "firing")
	for _, q := range []string{
		`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('mg','site_default','all',1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		 VALUES('probe_sig_gap','site_default','mg','gateway','LAN gateway','gateway','{"interface":"以太网"}',1,1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	svc := New(db, nil, settings.New(db), nil)

	// The incident transaction: the base freezes the gateway's NIC selection.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := svc.WriteIncidentBase(ctx, tx, "inc_gap", time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("write incident base: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// The gap: an edit commits before the post-commit handler runs. Retyping to
	// "host" is the harshest edit — under live reads it excluded the target.
	if _, err := db.ExecContext(ctx,
		`UPDATE probe_tasks SET kind='host', params='{"interface":"Wi-Fi"}' WHERE id='probe_sig_gap'`); err != nil {
		t.Fatalf("edit monitor: %v", err)
	}

	pusher := &capturePusher{}
	svc.SetPusher(pusher)
	if err := svc.OnIncidentOpened(ctx, eventbus.IncidentEvent{IncidentID: "inc_gap", SiteID: "site_default"}); err != nil {
		t.Fatalf("on incident opened: %v", err)
	}
	if len(pusher.snapReq) != 1 || len(pusher.snapReq[0].Targets) != 1 {
		t.Fatalf("push = %+v, want one request with the frozen gateway target", pusher.snapReq)
	}
	ref := pusher.snapReq[0].Targets[0]
	if ref.Kind != "gateway" || ref.Iface != "以太网" {
		t.Errorf("pushed ref = kind:%q iface:%q, want the tx-frozen gateway/以太网", ref.Kind, ref.Iface)
	}
}

func TestTraceCohortClosesAfterMissedResolutionCallback(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_2", "sig_2", "agent_a", "firing")
	svc := New(db, nil, settings.New(db), nil)
	plan := derivedTrace{mode: "icmp", destKey: "ip:1.1.1.1", destHost: "1.1.1.1", destIP: "1.1.1.1",
		subjectKind: traceSubjectTarget, pathScope: pathScopeDirect}

	first, created, _, err := svc.singleFlight(ctx, fault.SignalEvent{
		IncidentID: "inc_1", SignalID: "sig_1", AgentID: "agent_a", SiteID: "site_default",
	}, plan)
	if err != nil || !created {
		t.Fatalf("create first report: id=%s created=%v err=%v", first, created, err)
	}
	second, created, _, err := svc.singleFlight(ctx, fault.SignalEvent{
		IncidentID: "inc_2", SignalID: "sig_2", AgentID: "agent_a", SiteID: "site_default",
	}, plan)
	if err != nil || created || second != first {
		t.Fatalf("overlap did not share report: first=%s second=%s created=%v err=%v", first, second, created, err)
	}

	// Simulate a crash after the faults resolved but before OnSignalResolved ran.
	if _, err := db.ExecContext(ctx, `UPDATE fault_signals SET state='resolved', resolved_at=? WHERE id IN('sig_1','sig_2')`, time.Now().UTC()); err != nil {
		t.Fatalf("resolve signals: %v", err)
	}
	if err := svc.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	var open, active int
	if err := db.QueryRowContext(ctx, `SELECT cohort_open FROM trace_reports WHERE id=?`, first).Scan(&open); err != nil {
		t.Fatalf("read cohort: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_report_refs WHERE report_id=? AND active=1`, first).Scan(&active); err != nil {
		t.Fatalf("count refs: %v", err)
	}
	if open != 0 || active != 0 {
		t.Fatalf("recovered cohort = open:%d active:%d, want 0/0", open, active)
	}

	seedIncidentSignal(t, db, "inc_3", "sig_3", "agent_a", "firing")
	third, created, _, err := svc.singleFlight(ctx, fault.SignalEvent{
		IncidentID: "inc_3", SignalID: "sig_3", AgentID: "agent_a", SiteID: "site_default",
	}, plan)
	if err != nil || !created || third == first {
		t.Fatalf("new fault reused old report: old=%s new=%s created=%v err=%v", first, third, created, err)
	}
}

// Two in-tunnel plans toward the SAME address, mode and port must not share a
// report when they run through different tunnels — or different generations of
// one tunnel. Two WireGuard networks can both contain 10.0.0.10, and a rotated
// key is a different path even when the address is not.
func TestTraceCohortSeparatesDifferentEgress(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_2", "sig_2", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_3", "sig_3", "agent_a", "firing")
	svc := New(db, nil, settings.New(db), nil)
	base := derivedTrace{mode: "icmp", destKey: "ip:10.0.0.10", destHost: "10.0.0.10", destIP: "10.0.0.10",
		subjectKind: traceSubjectTarget, subjectReason: subjectTunnelTargetUnreachable,
		pathScope: pathScopeWGInner, egressID: "px_1", egressConfigSerial: 3}

	first, created, _, err := svc.singleFlight(ctx, fault.SignalEvent{
		IncidentID: "inc_1", SignalID: "sig_1", AgentID: "agent_a", SiteID: "site_default",
	}, base)
	if err != nil || !created {
		t.Fatalf("create first report: id=%s created=%v err=%v", first, created, err)
	}

	otherTunnel := base
	otherTunnel.egressID = "px_2"
	second, created, _, err := svc.singleFlight(ctx, fault.SignalEvent{
		IncidentID: "inc_2", SignalID: "sig_2", AgentID: "agent_a", SiteID: "site_default",
	}, otherTunnel)
	if err != nil || !created || second == first {
		t.Fatalf("different tunnel shared a report: first=%s second=%s created=%v err=%v", first, second, created, err)
	}

	otherGeneration := base
	otherGeneration.egressConfigSerial = 4
	third, created, _, err := svc.singleFlight(ctx, fault.SignalEvent{
		IncidentID: "inc_3", SignalID: "sig_3", AgentID: "agent_a", SiteID: "site_default",
	}, otherGeneration)
	if err != nil || !created || third == first || third == second {
		t.Fatalf("different generation shared a report: %s/%s/%s created=%v err=%v", first, second, third, created, err)
	}

	var open int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE cohort_open=1`).Scan(&open); err != nil {
		t.Fatalf("count open cohorts: %v", err)
	}
	if open != 3 {
		t.Fatalf("open cohorts = %d, want 3 (one per egress identity)", open)
	}
}

// An in-tunnel plan is gated on the GRANTED permission set alone: its probes are
// built in userspace and injected into the WireGuard device, so the raw-socket
// capability that strips ICMP from supported/effective is irrelevant to it. A
// policy that never granted ICMP still terminalizes the plan.
func TestInnerTraceGatesOnGrantedNotEffective(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	evd := traceEvidence{probeKind: "icmp", targetAddr: "10.7.0.5", reasonCode: telemetry.ProbeReasonTimeout,
		proxyID: "px_1", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820", proxyConfigSerial: 3}

	// agent_a: granted ICMP but supported/effective empty (the unprivileged-host
	// shape). The in-tunnel plan must still dispatch — the same permission state
	// terminalizes a DIRECT ICMP plan, which is the contrast that proves the gate
	// reads granted.
	setAgentPerms(t, db, "agent_a", nil, []permission.ID{permission.DiagnosticTracerouteICMP}, nil)
	d, ok := svc.deriveTrace(ctx, "agent_a", evd)
	if !ok || d.terminal != "" {
		t.Fatalf("inner plan = %+v ok=%v, want dispatchable despite empty effective set", d, ok)
	}
	if d.pathScope != pathScopeWGInner || d.egressID != "px_1" || d.egressConfigSerial != 3 {
		t.Fatalf("inner plan path=%s egress=%q/%d, want wireguard_inner/px_1/3", d.pathScope, d.egressID, d.egressConfigSerial)
	}
	direct, ok := svc.deriveTrace(ctx, "agent_a", traceEvidence{probeKind: "icmp", targetAddr: "192.0.2.10"})
	if !ok || direct.terminal != telemetry.TraceStatusUnsupported {
		t.Fatalf("direct plan under the same permissions = %+v ok=%v, want terminal unsupported", direct, ok)
	}

	// agent_b: nothing granted → terminal, and never dispatched.
	setAgentPerms(t, db, "agent_b", nil, nil, nil)
	denied, ok := svc.deriveTrace(ctx, "agent_b", evd)
	if !ok || denied.terminal != telemetry.TraceStatusUnsupported || denied.reason != reasonPermissionDenied {
		t.Fatalf("ungranted inner plan = %+v ok=%v, want terminal unsupported/permission_denied", denied, ok)
	}
}

// seedPlannedTrace inserts a running report with an explicit path plan and an
// active reference, mimicking what singleFlight + claimNextTrace would leave
// behind for the ingest path to answer. The cohort is seeded closed so tests can
// stack same-key fixtures without tripping the single-flight index — ingest and
// request-building never read cohort state.
func seedPlannedTrace(t *testing.T, db *store.DB, id, incidentID, signalID, agentID, pathScope, egressID string, egressSerial int) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO trace_reports(id,site_id,agent_id,dest_key,dest_host,mode,status,max_hops,attempts,timeout_ms,
			path_scope,egress_id,egress_config_serial,cohort_open,requested_at,deadline_at)
		VALUES(?,'site_default',?,'ip:10.0.0.10','10.0.0.10','icmp','running',30,3,30000,?,?,?,0,?,?)`,
		id, agentID, pathScope, egressID, egressSerial, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("seed planned trace: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO trace_report_refs(report_id,incident_id,signal_id,active,created_at)
		VALUES(?,?,?,1,?)`, id, incidentID, signalID, now); err != nil {
		t.Fatalf("seed trace ref: %v", err)
	}
}

// IngestTrace must hold every result to the path its plan asked for. A result
// that attests the planned path lands with the agent's own verdict — including
// the agent's fail-closed egress errors — and a result that attests any other
// path is recorded as failed/attestation_mismatch with every claim about that
// path (status, reached, hops) discarded.
func TestIngestTraceValidatesPathAttestation(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	svc := New(db, nil, settings.New(db), nil)
	hops := []telemetry.TraceHop{{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "10.0.0.1", RTTMs: 2}}}}

	readBack := func(id string) (status, reason string, reached, hopCount int) {
		t.Helper()
		if err := db.QueryRowContext(ctx, `
			SELECT status, reason, reached,
			       (SELECT COUNT(*) FROM trace_hops WHERE report_id=trace_reports.id)
			FROM trace_reports WHERE id=?`, id).Scan(&status, &reason, &reached, &hopCount); err != nil {
			t.Fatalf("read report %s: %v", id, err)
		}
		return
	}

	// A matching in-tunnel attestation is accepted verbatim.
	seedPlannedTrace(t, db, "trace_ok", "inc_1", "sig_1", "agent_a", pathScopeWGInner, "px_1", 3)
	if err := svc.IngestTrace(ctx, "agent_a", telemetry.TraceResult{
		ReportID: "trace_ok", Status: telemetry.TraceStatusSucceeded, Reached: true, ReachedTTL: 1, Hops: hops,
		PathScope: telemetry.TracePathWireGuardInner, EgressProxyID: "px_1", EgressConfigSerial: 3,
	}); err != nil {
		t.Fatalf("ingest matching result: %v", err)
	}
	if status, _, reached, hopCount := readBack("trace_ok"); status != telemetry.TraceStatusSucceeded || reached != 1 || hopCount != 1 {
		t.Fatalf("matching result stored status=%s reached=%d hops=%d, want succeeded/1/1", status, reached, hopCount)
	}
	sums, err := svc.TracesForIncident(ctx, "inc_1")
	if err != nil || len(sums) != 1 {
		t.Fatalf("TracesForIncident = %+v err=%v, want the one report", sums, err)
	}
	if sums[0].PathScope != pathScopeWGInner || sums[0].EgressID != "px_1" || sums[0].EgressConfigSerial != 3 {
		t.Fatalf("summary path=%s egress=%q/%d, want wireguard_inner/px_1/3",
			sums[0].PathScope, sums[0].EgressID, sums[0].EgressConfigSerial)
	}

	// A host-stack attestation on an in-tunnel plan means the probes never ran
	// where the plan said: nothing the agent claimed may survive, not even its
	// "succeeded".
	seedPlannedTrace(t, db, "trace_lied", "inc_1", "sig_1", "agent_a", pathScopeWGInner, "px_1", 3)
	if err := svc.IngestTrace(ctx, "agent_a", telemetry.TraceResult{
		ReportID: "trace_lied", Status: telemetry.TraceStatusSucceeded, Reached: true, ReachedTTL: 1, Hops: hops,
	}); err != nil {
		t.Fatalf("ingest mismatched result: %v", err)
	}
	if status, reason, reached, hopCount := readBack("trace_lied"); status != telemetry.TraceStatusFailed ||
		reason != reasonAttestationMismatch || reached != 0 || hopCount != 0 {
		t.Fatalf("mismatch stored status=%s reason=%s reached=%d hops=%d, want failed/attestation_mismatch/0/0",
			status, reason, reached, hopCount)
	}
	var completions int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incident_timeline WHERE kind='diag.completed' AND ref='trace_lied'`).Scan(&completions); err != nil {
		t.Fatalf("count completions: %v", err)
	}
	if completions != 1 {
		t.Fatalf("rejected result emitted %d completion events, want 1 (terminal, just not the agent's verdict)", completions)
	}

	// A wrong egress generation is the same lie in a subtler spelling: the probes
	// ran through a tunnel the plan never named.
	seedPlannedTrace(t, db, "trace_gen", "inc_1", "sig_1", "agent_a", pathScopeWGInner, "px_1", 3)
	if err := svc.IngestTrace(ctx, "agent_a", telemetry.TraceResult{
		ReportID: "trace_gen", Status: telemetry.TraceStatusSucceeded, Hops: hops,
		PathScope: telemetry.TracePathWireGuardInner, EgressProxyID: "px_1", EgressConfigSerial: 4,
	}); err != nil {
		t.Fatalf("ingest wrong-generation result: %v", err)
	}
	if status, reason, _, hopCount := readBack("trace_gen"); status != telemetry.TraceStatusFailed ||
		reason != reasonAttestationMismatch || hopCount != 0 {
		t.Fatalf("wrong generation stored status=%s reason=%s hops=%d, want failed/attestation_mismatch/0",
			status, reason, hopCount)
	}

	// The agent's own fail-closed outcome attests the PLANNED path and carries
	// its own reason — it must pass validation and keep that reason.
	seedPlannedTrace(t, db, "trace_fc", "inc_1", "sig_1", "agent_a", pathScopeWGInner, "px_1", 3)
	if err := svc.IngestTrace(ctx, "agent_a", telemetry.TraceResult{
		ReportID: "trace_fc", Status: telemetry.TraceStatusFailed, Reason: "egress_generation_mismatch",
		PathScope: telemetry.TracePathWireGuardInner, EgressProxyID: "px_1", EgressConfigSerial: 3,
	}); err != nil {
		t.Fatalf("ingest fail-closed result: %v", err)
	}
	if status, reason, _, _ := readBack("trace_fc"); status != telemetry.TraceStatusFailed || reason != "egress_generation_mismatch" {
		t.Fatalf("fail-closed stored status=%s reason=%s, want failed/egress_generation_mismatch preserved", status, reason)
	}

	// A direct plan holds the mirror expectation: claiming a tunnel is rejected...
	seedPlannedTrace(t, db, "trace_direct", "inc_1", "sig_1", "agent_a", pathScopeDirect, "", 0)
	if err := svc.IngestTrace(ctx, "agent_a", telemetry.TraceResult{
		ReportID: "trace_direct", Status: telemetry.TraceStatusSucceeded, Hops: hops,
		PathScope: telemetry.TracePathWireGuardInner, EgressProxyID: "px_9", EgressConfigSerial: 9,
	}); err != nil {
		t.Fatalf("ingest tunnel-claiming result: %v", err)
	}
	if status, reason, _, _ := readBack("trace_direct"); status != telemetry.TraceStatusFailed || reason != reasonAttestationMismatch {
		t.Fatalf("tunnel claim on direct plan stored status=%s reason=%s, want failed/attestation_mismatch", status, reason)
	}

	// ...while an empty PathScope reads as direct, including on a
	// wireguard_physical plan — that trace is executed on the host stack, it is
	// merely ABOUT a tunnel.
	seedPlannedTrace(t, db, "trace_phys", "inc_1", "sig_1", "agent_a", pathScopeWGPhysical, "", 0)
	if err := svc.IngestTrace(ctx, "agent_a", telemetry.TraceResult{
		ReportID: "trace_phys", Status: telemetry.TraceStatusSucceeded, Reached: true, ReachedTTL: 1, Hops: hops,
	}); err != nil {
		t.Fatalf("ingest physical-plan result: %v", err)
	}
	if status, _, _, hopCount := readBack("trace_phys"); status != telemetry.TraceStatusSucceeded || hopCount != 1 {
		t.Fatalf("physical plan stored status=%s hops=%d, want succeeded/1", status, hopCount)
	}
}

// The wire request must carry the egress pin for an in-tunnel plan and ONLY for
// it: a physical-endpoint plan pushed with a pin would be executed inside the
// very tunnel it is supposed to examine from outside.
func TestBuildTraceRequestCarriesEgressOnlyForInnerPlans(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	svc := New(db, nil, settings.New(db), nil)

	seedPlannedTrace(t, db, "trace_inner", "inc_1", "sig_1", "agent_a", pathScopeWGInner, "px_1", 3)
	req, ok := svc.buildTraceRequest(ctx, "trace_inner")
	if !ok || req.EgressProxyID != "px_1" || req.EgressConfigSerial != 3 {
		t.Fatalf("inner request = %+v ok=%v, want egress px_1/3", req, ok)
	}

	// Hand-seed a physical plan with egress columns populated: even then the pin
	// must not reach the wire, proving the scope — not the columns — decides.
	seedPlannedTrace(t, db, "trace_phys", "inc_1", "sig_1", "agent_a", pathScopeWGPhysical, "px_1", 3)
	req, ok = svc.buildTraceRequest(ctx, "trace_phys")
	if !ok || req.EgressProxyID != "" || req.EgressConfigSerial != 0 {
		t.Fatalf("physical request = %+v ok=%v, want no egress pin", req, ok)
	}
}

func seedQueuedTrace(t *testing.T, db *store.DB, id, agentID string, seq int) {
	t.Helper()
	now := time.Now().UTC().Add(time.Duration(seq) * time.Millisecond)
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO trace_reports(id,site_id,agent_id,dest_key,dest_host,mode,status,max_hops,attempts,timeout_ms,requested_at,deadline_at)
		VALUES(?,'site_default',?,?,?,'icmp','queued',30,3,30000,?,?)`,
		id, agentID, fmt.Sprintf("ip:192.0.2.%d", seq+1), fmt.Sprintf("192.0.2.%d", seq+1), now, now.Add(time.Minute)); err != nil {
		t.Fatalf("seed queued trace: %v", err)
	}
}

func TestTraceCapacityClaimsStayWithinAgentAndGlobalLimits(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	for i := 0; i < 8; i++ {
		seedQueuedTrace(t, db, fmt.Sprintf("a_%d", i), "agent_a", i)
		seedQueuedTrace(t, db, fmt.Sprintf("b_%d", i), "agent_b", 100+i)
	}
	svc := New(db, nil, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		for _, agentID := range []string{"agent_a", "agent_b"} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				_, _, _ = svc.claimNextTrace(ctx, id, 2, 3)
			}(agentID)
		}
	}
	wg.Wait()
	var global, a, b int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE status='running'`).Scan(&global); err != nil {
		t.Fatalf("count global: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE status='running' AND agent_id='agent_a'`).Scan(&a); err != nil {
		t.Fatalf("count agent_a: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports WHERE status='running' AND agent_id='agent_b'`).Scan(&b); err != nil {
		t.Fatalf("count agent_b: %v", err)
	}
	if global != 3 || a > 2 || b > 2 {
		t.Fatalf("running counts global/a/b = %d/%d/%d, want 3 and each <=2", global, a, b)
	}
}

func TestSnapshotSizeCapIncludesBaseAndEntries(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	set := settings.New(db)
	if err := set.Set(ctx, settings.KeyIncidentSnapshotMaxBytes, "65536"); err != nil {
		t.Fatalf("set max bytes: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES('inc','site_default','group','Group','alert:big','open',?)`, now); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	base := SnapshotBase{IncidentID: "inc", SiteID: "site_default", Group: baseGroup{ID: "group", Name: "Group"}, TriggeredAt: now, ReceivedAt: now}
	for i := 0; i < 500; i++ {
		samples := make([]baseSample, 12)
		for j := range samples {
			samples[j] = baseSample{TS: now.Add(time.Duration(j) * time.Second), Value: float64(j)}
		}
		base.Members = append(base.Members, baseMember{
			SignalID: fmt.Sprintf("sig-%d", i), DetectorKey: "availability", AgentID: "agent_a",
			ObservedAt: now, ConfirmedAt: now,
			Evidence: baseEvidence{TargetID: "target", MetricKind: "probe.icmp.loss_pct", Comparator: "gt", RecentSamples: samples},
		})
	}
	baseJSON := mustJSON(base)
	if len(baseJSON) <= 65536 {
		t.Fatalf("fixture base too small: %d", len(baseJSON))
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incident_snapshots(id,incident_id,status,base,total_bytes,deadline_at,created_at)
		VALUES('snap','inc','collecting',?,?,?,?)`, baseJSON, len(baseJSON), now.Add(time.Minute), now); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	payload, _ := json.Marshal(entryPayload{Targets: []telemetry.SnapshotTargetResult{{MonitorID: "target", Target: strings.Repeat("x", 70000)}}})
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incident_snapshot_entries(id,snapshot_id,request_id,agent_id,status,payload,requested_at)
		VALUES('entry','snap','req','agent_a','complete',?,?)`, string(payload), now); err != nil {
		t.Fatalf("seed entry: %v", err)
	}

	total, truncated, err := New(db, nil, set, nil).enforceSizeCap(ctx, "snap")
	if err != nil {
		t.Fatalf("enforce cap: %v", err)
	}
	if !truncated || total > 65536 {
		t.Fatalf("cap result total=%d truncated=%v", total, truncated)
	}
	var storedBase, storedPayload string
	if err := db.QueryRowContext(ctx, `SELECT base FROM incident_snapshots WHERE id='snap'`).Scan(&storedBase); err != nil {
		t.Fatalf("read base: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT payload FROM incident_snapshot_entries WHERE id='entry'`).Scan(&storedPayload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !json.Valid([]byte(storedBase)) || (storedPayload != "" && !json.Valid([]byte(storedPayload))) {
		t.Fatal("truncation stored invalid JSON")
	}
	if len(storedBase)+len(storedPayload) != total {
		t.Fatalf("stored bytes=%d, reported total=%d", len(storedBase)+len(storedPayload), total)
	}
}

// setAgentPerms writes an agent's three reported permission views (as their
// JSON string-array column encodings).
func setAgentPerms(t *testing.T, db *store.DB, agentID string, supported, granted, effective []permission.ID) {
	t.Helper()
	enc := func(ids []permission.ID) string {
		return mustJSON(permission.NewSet(ids...).Strings())
	}
	if _, err := db.ExecContext(context.Background(),
		`UPDATE agents SET perm_supported=?, perm_granted=?, perm_effective=? WHERE id=?`,
		enc(supported), enc(granted), enc(effective), agentID); err != nil {
		t.Fatalf("set agent perms: %v", err)
	}
}

// seedEvidence freezes a signal's trigger-time evidence — the probe kind, the
// destination and the port the traceroute derivation reads. Subject evidence
// (resolver / STUN / proxy) is seeded by seedSubjectEvidence.
func seedEvidence(t *testing.T, db *store.DB, signalID, probeKind, targetAddr string, targetPort int, metricKind string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		UPDATE fault_signals SET probe_kind=?, target_addr=?, target_port=?, metric_kind=?, comparator='gt', threshold=0, value=1
		WHERE id=?`, probeKind, targetAddr, targetPort, metricKind, signalID); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
}

// seedSubjectEvidence freezes the diagnosis-subject columns a DIAG-003 plan reads:
// where the probe actually dialed, and the classified cause that separates a
// tunnel failure from a failure beyond the tunnel.
func seedSubjectEvidence(t *testing.T, db *store.DB, signalID string, evd traceEvidence) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		UPDATE fault_signals SET reason_code=?, resolver_addr=?, resolver_protocol=?,
		    stun_addr=?, stun_transport=?, proxy_id=?, proxy_type=?, proxy_addr=?, proxy_config_serial=?
		WHERE id=?`,
		evd.reasonCode, evd.resolverAddr, evd.resolverProtocol, evd.stunAddr, evd.stunTransport,
		evd.proxyID, evd.proxyType, evd.proxyAddr, evd.proxyConfigSerial, signalID); err != nil {
		t.Fatalf("seed subject evidence: %v", err)
	}
}

// capturePusher accepts every push and records the requests it saw.
type capturePusher struct {
	mu      sync.Mutex
	traces  []pcfg.TraceRequest
	snapReq []pcfg.IncidentSnapshotRequest
}

func (p *capturePusher) PushIncidentSnapshotRequest(_ string, req pcfg.IncidentSnapshotRequest) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.snapReq = append(p.snapReq, req)
	return true
}

func (p *capturePusher) PushTraceRequest(_ string, req pcfg.TraceRequest) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.traces = append(p.traces, req)
	return true
}

// TestTraceFallsBackToICMPWhenTCPPermissionUnavailable covers the unprivileged-
// Windows shape: the policy grants TCP traceroute but the runtime cannot open a
// raw socket, so supported/effective carry only ICMP. A TCP-monitor fault must
// then derive an ICMP-mode report that records the fallback, keeps the frozen
// port, and dispatches normally with Mode=icmp on the wire.
func TestTraceFallsBackToICMPWhenTCPPermissionUnavailable(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a",
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP, permission.DiagnosticTracerouteTCP},
		[]permission.ID{permission.DiagnosticTracerouteICMP})
	seedEvidence(t, db, "sig_1", "tcp", "192.0.2.10", 443, "probe.tcp.rtt_ms")

	svc := New(db, nil, settings.New(db), nil)
	pusher := &capturePusher{}
	svc.SetPusher(pusher)
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
	}); err != nil {
		t.Fatalf("on fault confirmed: %v", err)
	}

	var mode, status, from, reason string
	var port int
	if err := db.QueryRowContext(ctx,
		`SELECT mode, status, port, fallback_from, fallback_reason FROM trace_reports`).
		Scan(&mode, &status, &port, &from, &reason); err != nil {
		t.Fatalf("read report: %v", err)
	}
	if mode != "icmp" || from != "tcp" || reason != "raw_socket_unavailable" || port != 443 {
		t.Fatalf("report mode=%s fallback_from=%s fallback_reason=%s port=%d, want icmp/tcp/raw_socket_unavailable/443",
			mode, from, reason, port)
	}
	if status != "running" {
		t.Fatalf("report status=%s, want running (queued report dispatched)", status)
	}
	if len(pusher.traces) != 1 || pusher.traces[0].Mode != pcfg.TraceModeICMP {
		t.Fatalf("pushed requests=%+v, want exactly one with Mode=icmp", pusher.traces)
	}
}

// Both one-shot pushes must carry their window as a receipt-relative budget, not
// as this server's absolute deadline. An agent's clock is independent of ours, so
// a timestamp would have the whole skew taken out of the window — a skew larger
// than the window expires the request on arrival and the agent reports timeouts
// (and, before the target error classes were split, "DNS resolution failed") for
// work it was never given time to attempt. Bounding each budget by its configured
// window is what distinguishes a duration from a smuggled epoch timestamp.
func TestPushedWindowsAreRelativeBudgets(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a",
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP})
	seedEvidence(t, db, "sig_1", "icmp", "192.0.2.10", 0, "probe.icmp.loss_pct")

	svc := New(db, nil, settings.New(db), nil)
	pusher := &capturePusher{}
	svc.SetPusher(pusher)
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
	}); err != nil {
		t.Fatalf("on fault confirmed: %v", err)
	}
	if err := svc.OnIncidentOpened(ctx, eventbus.IncidentEvent{
		IncidentID: "inc_1", SiteID: "site_default", Severity: "critical",
	}); err != nil {
		t.Fatalf("on incident opened: %v", err)
	}

	if len(pusher.snapReq) != 1 {
		t.Fatalf("snapshot pushes = %d, want 1", len(pusher.snapReq))
	}
	snapWindow := int(svc.snapshotDeadline(ctx).Milliseconds())
	if got := pusher.snapReq[0].BudgetMs; got <= 0 || got > snapWindow {
		t.Errorf("snapshot BudgetMs = %d, want within (0, %d]", got, snapWindow)
	}

	if len(pusher.traces) != 1 {
		t.Fatalf("trace pushes = %d, want 1", len(pusher.traces))
	}
	traceWindow := int(svc.diagTotalTimeout(ctx).Milliseconds())
	if got := pusher.traces[0].BudgetMs; got <= 0 || got > traceWindow {
		t.Errorf("trace BudgetMs = %d, want within (0, %d]", got, traceWindow)
	}
}

// TestTraceTerminalReasonDistinguishesPolicyFromCapability covers a TCP-monitor
// fault on an agent with no traceroute permission at all: the report is
// terminal unsupported and never dispatched, and the reason separates a
// capability gap (granted but unsupported → raw_socket_unavailable) from a
// policy denial (never granted → permission_denied).
func TestTraceTerminalReasonDistinguishesPolicyFromCapability(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	pusher := &capturePusher{}
	svc.SetPusher(pusher)

	// agent_a: granted tcp, supported/effective empty → capability gap.
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a", nil, []permission.ID{permission.DiagnosticTracerouteTCP}, nil)
	seedEvidence(t, db, "sig_1", "tcp", "192.0.2.10", 443, "probe.tcp.rtt_ms")
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
	}); err != nil {
		t.Fatalf("on fault confirmed: %v", err)
	}
	var status, reason, from string
	if err := db.QueryRowContext(ctx,
		`SELECT status, reason, fallback_from FROM trace_reports WHERE agent_id='agent_a'`).
		Scan(&status, &reason, &from); err != nil {
		t.Fatalf("read agent_a report: %v", err)
	}
	if status != telemetry.TraceStatusUnsupported || reason != "raw_socket_unavailable" || from != "" {
		t.Fatalf("agent_a report status=%s reason=%s fallback_from=%q, want unsupported/raw_socket_unavailable/''",
			status, reason, from)
	}
	if len(pusher.traces) != 0 {
		t.Fatalf("terminal report was dispatched: %+v", pusher.traces)
	}

	// agent_b: nothing granted → policy denial.
	setAgentPerms(t, db, "agent_b", nil, nil, nil)
	d, ok := svc.deriveTrace(ctx, "agent_b", traceEvidence{probeKind: "tcp", targetAddr: "192.0.2.10", targetPort: 443})
	if !ok || d.terminal != telemetry.TraceStatusUnsupported || d.reason != "permission_denied" {
		t.Fatalf("ungranted plan = %+v ok=%v, want terminal unsupported/permission_denied", d, ok)
	}
}

// TestTraceReadsIncludeFallbackFields verifies both read paths surface the
// persisted fallback columns.
func TestTraceReadsIncludeFallbackFields(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO trace_reports(id,site_id,agent_id,dest_key,dest_host,mode,port,fallback_from,fallback_reason,
			status,max_hops,attempts,timeout_ms,requested_at,deadline_at)
		VALUES('trace_fb','site_default','agent_a','ip:192.0.2.10','192.0.2.10','icmp',443,'tcp','raw_socket_unavailable',
			'queued',30,3,30000,?,?)`, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("seed report: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO trace_report_refs(report_id,incident_id,signal_id,active,created_at)
		VALUES('trace_fb','inc_1','sig_1',1,?)`, now); err != nil {
		t.Fatalf("seed ref: %v", err)
	}

	svc := New(db, nil, nil, nil)
	list, err := svc.TracesForIncident(ctx, "inc_1")
	if err != nil {
		t.Fatalf("traces for incident: %v", err)
	}
	if len(list) != 1 || list[0].FallbackFrom != "tcp" || list[0].FallbackReason != "raw_socket_unavailable" {
		t.Fatalf("incident traces = %+v, want one with fallback tcp/raw_socket_unavailable", list)
	}
	view, siteID, ok, err := svc.TraceReport(ctx, "trace_fb")
	if err != nil || !ok || siteID != "site_default" {
		t.Fatalf("trace report: ok=%v site=%s err=%v", ok, siteID, err)
	}
	if view.FallbackFrom != "tcp" || view.FallbackReason != "raw_socket_unavailable" {
		t.Fatalf("report view fallback = %s/%s, want tcp/raw_socket_unavailable", view.FallbackFrom, view.FallbackReason)
	}
}

// TestWriteIncidentBaseDoesNotSelfDeadlockWithProductionSettings exercises the
// real server-lite wiring shape: a non-nil settings service is consulted while
// the fault engine already owns the database's single write connection. Settings
// reads must use the read pool; using the write handle waits forever for the
// surrounding transaction to release its own connection.
func TestWriteIncidentBaseDoesNotSelfDeadlockWithProductionSettings(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES('inc_deadlock','site_default','group','Group','alert:deadlock','open',?)`, now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed incident: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- New(db, nil, settings.New(db), nil).WriteIncidentBase(ctx, tx, "inc_deadlock", now)
	}()

	select {
	case err := <-done:
		_ = tx.Rollback()
		if err != nil {
			t.Fatalf("write incident base: %v", err)
		}
	case <-time.After(time.Second):
		_ = tx.Rollback()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("WriteIncidentBase deadlocked reading settings through the single write connection")
	}
}
