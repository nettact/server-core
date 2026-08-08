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

// seedPlannedTrace inserts a running report with an explicit path plan and an
// active reference, mimicking what singleFlight + claimNextTrace would leave
// behind for the ingest path to answer. The cohort is seeded closed so tests can
// stack same-key fixtures without tripping the single-flight index — ingest and
// request-building never read cohort state.
// seedStoredTrace writes a report as ingest would have, already referenced by an
// incident's signal.
func seedStoredTrace(t *testing.T, db *store.DB, id, incidentID, signalID, agentID, destKey, destHost string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO trace_reports(id,site_id,agent_id,dest_key,dest_host,mode,status,max_hops,attempts,
			path_scope,trigger_reason,trigger_streak,started_at,completed_at,received_at)
		VALUES(?,'site_default',?,?,?,'icmp','partial',30,3,'direct','consecutive_failures',3,?,?,?)`,
		id, agentID, destKey, destHost, now, now, now); err != nil {
		t.Fatalf("seed stored trace: %v", err)
	}
	if incidentID == "" {
		return
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO trace_report_refs(report_id,incident_id,signal_id,active,created_at)
		VALUES(?,?,?,1,?)`, id, incidentID, signalID, now); err != nil {
		t.Fatalf("seed trace ref: %v", err)
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

// capturePusher accepts every push and records the requests it saw.
type capturePusher struct {
	mu      sync.Mutex
	snapReq []pcfg.IncidentSnapshotRequest
}

func (p *capturePusher) PushIncidentSnapshotRequest(_ string, req pcfg.IncidentSnapshotRequest) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.snapReq = append(p.snapReq, req)
	return true
}

// The one-shot snapshot push must carry its window as a receipt-relative budget,
// not as this server's absolute deadline. An agent's clock is independent of
// ours, so a timestamp would have the whole skew taken out of the window — a skew
// larger than the window expires the request on arrival and the agent reports
// timeouts for work it was never given time to attempt. Bounding the budget by
// its configured window is what distinguishes a duration from a smuggled epoch
// timestamp.
func TestPushedWindowsAreRelativeBudgets(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")

	svc := New(db, nil, settings.New(db), nil)
	pusher := &capturePusher{}
	svc.SetPusher(pusher)
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
}

// TestWriteIncidentBaseDoesNotSelfDeadlockWithProductionSettings exercises the
// real server wiring shape: a non-nil settings service is consulted while
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
