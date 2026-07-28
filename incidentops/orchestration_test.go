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

func TestTraceCohortClosesAfterMissedResolutionCallback(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_2", "sig_2", "agent_a", "firing")
	svc := New(db, nil, settings.New(db), nil)
	plan := derivedTrace{mode: "icmp", destKey: "ip:1.1.1.1", destHost: "1.1.1.1", destIP: "1.1.1.1"}

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
// destination and the port the traceroute derivation reads.
func seedEvidence(t *testing.T, db *store.DB, signalID, probeKind, targetAddr string, targetPort int, metricKind string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		UPDATE fault_signals SET probe_kind=?, target_addr=?, target_port=?, metric_kind=?, comparator='gt', threshold=0, value=1
		WHERE id=?`, probeKind, targetAddr, targetPort, metricKind, signalID); err != nil {
		t.Fatalf("seed evidence: %v", err)
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
	d, ok := svc.deriveTrace(ctx, "agent_b", "tcp", "192.0.2.10", 443)
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
