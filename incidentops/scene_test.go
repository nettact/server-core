package incidentops

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// ingestScenes runs one packet's worth of scenes through the write transaction
// the telemetry ingest would have opened, then publishes as ingest does
// post-commit.
func ingestScenes(t *testing.T, svc *Service, ctx context.Context, agentID string, reports ...telemetry.SceneReport) {
	t.Helper()
	tx, err := svc.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	out, err := svc.IngestScenesTx(ctx, tx, agentID, "site_default", reports)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("ingest scenes: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	svc.PublishSceneOutcome(ctx, out)
}

// seedSceneSignal writes a firing signal the way the availability path would,
// including the frozen target generation that is the server half of the scene
// claim key.
func seedSceneSignal(t *testing.T, db *store.DB, incidentID, signalID, agentID, targetID string, serial int, observedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES(?,'site_default','group','Group',?,'open',?)`, incidentID, "sig:"+signalID, observedAt); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO fault_signals(id,agent_id,site_id,target_id,target_config_serial,detector_key,
			group_id,group_name,incident_id,state,observed_at,confirmed_at)
		VALUES(?,?,'site_default',?,?,'availability','group','Group',?,'firing',?,?)`,
		signalID, agentID, targetID, serial, incidentID, observedAt, observedAt); err != nil {
		t.Fatalf("seed fault signal: %v", err)
	}
}

// seedConnectivitySignal writes the per-agent connectivity signal the sweeper
// opens, with its incident in the matching lifecycle state (the partial
// open_key unique index only admits one OPEN incident per agent, which is also
// what really happens: a reconnect resolves the incident before the next drop
// opens another).
func seedConnectivitySignal(t *testing.T, db *store.DB, incidentID, signalID, agentID, state string, observedAt time.Time, resolvedAt *time.Time) {
	t.Helper()
	ctx := context.Background()
	incidentState := "open"
	if state == "resolved" {
		incidentState = "resolved"
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at,resolved_at)
		VALUES(?,'site_default','','',?,?,?,?)`,
		incidentID, "agent:"+agentID, incidentState, observedAt, resolvedAt); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO fault_signals(id,agent_id,site_id,target_id,detector_key,incident_id,state,observed_at,confirmed_at,resolved_at)
		VALUES(?,?,'site_default','',?,?,?,?,?,?)`,
		signalID, agentID, fault.DetectorAgentConnectivity, incidentID, state, observedAt, observedAt, resolvedAt); err != nil {
		t.Fatalf("seed connectivity signal: %v", err)
	}
}

// seedResolvedSceneSignal is seedSceneSignal for an outage that already closed,
// which is the state a short fault is in by the time a cooldown-held scene
// reaches the server.
func seedResolvedSceneSignal(t *testing.T, db *store.DB, incidentID, signalID, agentID, targetID string, serial int, observedAt, resolvedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at,resolved_at)
		VALUES(?,'site_default','group','Group',?,'resolved',?,?)`,
		incidentID, "sig:"+signalID, observedAt, resolvedAt); err != nil {
		t.Fatalf("seed resolved incident: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO fault_signals(id,agent_id,site_id,target_id,target_config_serial,detector_key,
			group_id,group_name,incident_id,state,observed_at,confirmed_at,resolved_at)
		VALUES(?,?,'site_default',?,?,'availability','group','Group',?,'resolved',?,?,?)`,
		signalID, agentID, targetID, serial, incidentID, observedAt, observedAt, resolvedAt); err != nil {
		t.Fatalf("seed resolved fault signal: %v", err)
	}
}

func probeTrigger(monitorID string, serial int, firstFailedAt time.Time) telemetry.SceneTrigger {
	return telemetry.SceneTrigger{
		Kind: telemetry.SceneTriggerProbeFault, MonitorID: monitorID, ConfigSerial: serial,
		TriggerStreak: 3, FirstFailedAt: firstFailedAt,
	}
}

func disconnectTrigger(at time.Time) telemetry.SceneTrigger {
	return telemetry.SceneTrigger{
		Kind: telemetry.SceneTriggerServerDisconnect, DisconnectedAt: at,
		Reason: "timeout", EdgeCount: 2,
	}
}

// basicScene is a well-formed report with one collected group, one denied group
// and one group the server does not recognise.
func basicScene(id string, collectedAt time.Time, triggers ...telemetry.SceneTrigger) telemetry.SceneReport {
	return telemetry.SceneReport{
		ReportID: id, CollectedAt: collectedAt, Triggers: triggers,
		Groups: []telemetry.SnapshotGroupResult{
			{Group: telemetry.SnapshotGroupNetwork, Status: telemetry.ScopeCollected, CollectedAt: collectedAt},
			{Group: telemetry.SnapshotGroupAgent, Status: telemetry.ScopeDenied, Reason: "permission_denied"},
			{Group: "processes", Status: telemetry.ScopeCollected},
		},
		Network: &telemetry.SnapshotNetwork{
			DNSServers: []string{"1.1.1.1"},
			Interfaces: []telemetry.SnapshotInterface{{Name: "eth0", Up: true, Addrs: []string{"192.168.1.10"}}},
		},
		Agent: &telemetry.SnapshotAgentInfo{AgentID: "agent_a", Hostname: "box"},
	}
}

func scenePayloadOf(t *testing.T, db *store.DB, reportID string) scenePayload {
	t.Helper()
	var raw string
	if err := db.QueryRowContext(context.Background(),
		`SELECT payload FROM scene_reports WHERE id=?`, reportID).Scan(&raw); err != nil {
		t.Fatalf("read payload %s: %v", reportID, err)
	}
	var p scenePayload
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
	}
	return p
}

func countRows(t *testing.T, db *store.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// The scene is stored allowlisted: a group the server does not recognise is
// dropped outright, and a typed section survives only when its own group
// reported collected. Storing a denied group's payload would present data the
// agent said it could not read.
func TestIngestStoresAllowlistedGroupsOnly(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	now := time.Now().UTC()
	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_1", now, probeTrigger("probe_x", 1, now)))

	p := scenePayloadOf(t, db, "scene_1")
	if len(p.Groups) != 2 {
		t.Fatalf("stored %d group results, want the two allowlisted ones: %+v", len(p.Groups), p.Groups)
	}
	for _, g := range p.Groups {
		if g.Group == "processes" {
			t.Fatal("a non-allowlisted group was persisted")
		}
	}
	if p.Network == nil || len(p.Network.DNSServers) != 1 {
		t.Fatalf("collected network group was not stored: %+v", p.Network)
	}
	if p.Agent != nil {
		t.Fatal("a denied group's payload was stored")
	}

	// The trigger is the claim key and has to survive the round trip.
	var kind, monitorID string
	var serial, streak int
	if err := db.QueryRowContext(ctx,
		`SELECT kind, monitor_id, config_serial, trigger_streak FROM scene_report_triggers WHERE report_id='scene_1' AND idx=0`).
		Scan(&kind, &monitorID, &serial, &streak); err != nil {
		t.Fatalf("read trigger: %v", err)
	}
	if kind != telemetry.SceneTriggerProbeFault || monitorID != "probe_x" || serial != 1 || streak != 3 {
		t.Fatalf("trigger = %s/%s/%d/%d", kind, monitorID, serial, streak)
	}
}

// A replayed packet re-presents the same agent-minted id. It must be a complete
// no-op: the WAL guarantees at-least-once delivery, so this is the normal case
// after any ack that did not make it back, not an error.
func TestIngestSceneReplayIsANoOp(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	now := time.Now().UTC()
	seedSceneSignal(t, db, "inc_1", "sig_1", "agent_a", "probe_x", 4, now)

	scene := basicScene("scene_dup", now, probeTrigger("probe_x", 4, now))
	ingestScenes(t, svc, ctx, "agent_a", scene)
	ingestScenes(t, svc, ctx, "agent_a", scene)

	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_reports WHERE id='scene_dup'`); n != 1 {
		t.Fatalf("stored %d rows for one report id", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_dup'`); n != 1 {
		t.Fatalf("%d refs after a replay, want 1", n)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_1' AND kind='scene.collected'`); n != 1 {
		t.Fatalf("%d timeline entries after a replay, want 1", n)
	}
}

// The claim key is (monitor, material generation), not the monitor alone. A
// target edited between the agent's collection and the server's confirmation is
// a different destination wearing the same id, so a scene stamped with the old
// generation must not become the new one's evidence.
func TestIngestAttachMatchesOnConfigSerial(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), eventbus.New())
	now := time.Now().UTC()
	seedSceneSignal(t, db, "inc_live", "sig_live", "agent_a", "probe_x", 7, now)

	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_match", now, probeTrigger("probe_x", 7, now)),
		basicScene("scene_stale", now, probeTrigger("probe_x", 6, now)))

	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_match' AND incident_id='inc_live'`); n != 1 {
		t.Fatalf("the same-generation scene was not filed (%d refs)", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_stale'`); n != 0 {
		t.Fatalf("a scene from the target's previous generation was claimed (%d refs)", n)
	}
	// Stale or not, both are stored: an unclaimed scene waits, it is not discarded.
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_reports`); n != 2 {
		t.Fatalf("stored %d scenes, want both", n)
	}
}

// A quality degradation is not a reachability fault: its target is answering,
// just slowly, and the agent's local streak that produced the scene is an
// availability streak. Sharing a monitor must not put a hard failure's scene in
// a latency trend's evidence.
func TestIngestAttachSkipsDegradationSignals(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	seedSceneSignal(t, db, "inc_deg", "sig_deg", "agent_a", "probe_x", 2, now)
	if _, err := db.ExecContext(ctx,
		`UPDATE fault_signals SET detector_key=? WHERE id='sig_deg'`, fault.DetectorLatencyDegradation); err != nil {
		t.Fatalf("retype signal: %v", err)
	}
	svc := New(db, nil, settings.New(db), nil)
	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_deg", now, probeTrigger("probe_x", 2, now)))

	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_deg'`); n != 0 {
		t.Fatalf("a degradation signal claimed a scene (%d refs)", n)
	}
}

// A scene whose streak began well before the signal's first failing round is a
// PREVIOUS outage of the same monitor. A reconnect drains both outages' records
// in one packet stamped with the same receipt time, so only the agent's own edge
// time can separate them.
func TestIngestAttachRejectsAnEarlierOutagesScene(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	seedSceneSignal(t, db, "inc_now", "sig_now", "agent_a", "probe_x", 1, now)
	svc := New(db, nil, settings.New(db), nil)

	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_old", now, probeTrigger("probe_x", 1, now.Add(-time.Hour))),
		basicScene("scene_new", now, probeTrigger("probe_x", 1, now.Add(-30*time.Second))))

	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_old'`); n != 0 {
		t.Fatalf("a previous outage's scene was claimed (%d refs)", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_new'`); n != 1 {
		t.Fatalf("this outage's scene was not claimed (%d refs)", n)
	}
}

// The case the agent-side collection exists for, and the one easiest to get
// wrong. A disconnect scene cannot arrive until the agent has reconnected and
// drained its WAL — and the connectivity fault resolves the moment it
// reconnects. Matching only firing signals would therefore drop every disconnect
// scene ever collected.
func TestIngestAttachClaimsARecentlyResolvedConnectivitySignal(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	disconnectedAt := now.Add(-3 * time.Minute)
	resolved := now.Add(-5 * time.Second)
	seedConnectivitySignal(t, db, "inc_conn", "sig_conn", "agent_a", "resolved", disconnectedAt, &resolved)
	svc := New(db, nil, settings.New(db), eventbus.New())

	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_conn", disconnectedAt, disconnectTrigger(disconnectedAt)))

	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_conn' AND incident_id='inc_conn'`); n != 1 {
		t.Fatalf("the disconnect scene was not filed against the resolved connectivity fault (%d refs)", n)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_conn' AND kind='scene.collected'`); n != 1 {
		t.Fatalf("%d timeline entries, want 1", n)
	}
}

// A connectivity signal resolved long ago describes a different outage; the
// claim window is what keeps it from adopting an unrelated scene.
func TestIngestAttachIgnoresALongResolvedConnectivitySignal(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	old := now.Add(-2 * claimWindow)
	seedConnectivitySignal(t, db, "inc_old", "sig_old", "agent_a", "resolved", old, &old)
	svc := New(db, nil, settings.New(db), nil)

	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_late", now, disconnectTrigger(now.Add(-time.Minute))))

	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_late'`); n != 0 {
		t.Fatalf("a scene was filed against an outage that ended half an hour ago (%d refs)", n)
	}
}

// The other ordering: the agent collected and shipped before this server
// confirmed anything, so ingest found no fault to file it under. The
// confirmation has to go looking for what already landed, or the evidence for
// exactly the faults that take longest to confirm is the evidence that is lost.
func TestClaimBackFilesASceneThatArrivedFirst(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	svc := New(db, nil, settings.New(db), eventbus.New())

	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_early", now, probeTrigger("probe_x", 3, now.Add(-time.Minute))))
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs`); n != 0 {
		t.Fatalf("the scene attached to something that does not exist yet (%d refs)", n)
	}

	seedSceneSignal(t, db, "inc_later", "sig_later", "agent_a", "probe_x", 3, now)
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_later", IncidentID: "inc_later", AgentID: "agent_a", SiteID: "site_default",
		TargetID: "probe_x", DetectorKey: fault.DetectorAvailability,
	}); err != nil {
		t.Fatalf("on signal confirmed: %v", err)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_early' AND incident_id='inc_later'`); n != 1 {
		t.Fatalf("the confirmation did not claim the waiting scene (%d refs)", n)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_later' AND kind='scene.collected'`); n != 1 {
		t.Fatalf("%d timeline entries, want 1", n)
	}

	// Re-confirming must not repeat the timeline line for evidence already shown.
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_later", IncidentID: "inc_later", AgentID: "agent_a", SiteID: "site_default",
		TargetID: "probe_x", DetectorKey: fault.DetectorAvailability,
	}); err != nil {
		t.Fatalf("re-confirm: %v", err)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_later' AND kind='scene.collected'`); n != 1 {
		t.Fatalf("a re-confirmation repeated the timeline entry (%d)", n)
	}
}

// Same ordering on the connectivity key: a flapping link ships the first
// disconnect's scene, then drops again, and only then does the sweeper confirm.
// The signal has no target, so the agent id is the whole key.
func TestClaimBackFilesADisconnectScene(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	svc := New(db, nil, settings.New(db), eventbus.New())

	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_flap", now, disconnectTrigger(now.Add(-2*time.Minute))))
	seedConnectivitySignal(t, db, "inc_flap", "sig_flap", "agent_a", "firing", now, nil)

	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_flap", IncidentID: "inc_flap", AgentID: "agent_a", SiteID: "site_default",
		DetectorKey: fault.DetectorAgentConnectivity,
	}); err != nil {
		t.Fatalf("on signal confirmed: %v", err)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_flap' AND incident_id='inc_flap'`); n != 1 {
		t.Fatalf("the connectivity confirmation did not claim the waiting scene (%d refs)", n)
	}
}

// A flapping link leaves several closed connectivity outages inside the claim
// window. The ordering gate alone only rules out the ones that started after the
// edge, so without picking the latest compatible outage a ten-minute-old
// incident would adopt a scene describing the drop two minutes ago.
func TestIngestAttachPicksTheLatestCompatibleDisconnect(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	early, earlyEnd := now.Add(-10*time.Minute), now.Add(-9*time.Minute)
	late, lateEnd := now.Add(-2*time.Minute), now.Add(-time.Minute)
	seedConnectivitySignal(t, db, "inc_early", "sig_early", "agent_a", "resolved", early, &earlyEnd)
	seedConnectivitySignal(t, db, "inc_late", "sig_late", "agent_a", "resolved", late, &lateEnd)
	svc := New(db, nil, settings.New(db), nil)

	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_flap2", late, disconnectTrigger(late)))

	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_flap2' AND incident_id='inc_late'`); n != 1 {
		t.Fatalf("the scene was not filed against the outage it describes (%d refs)", n)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_flap2' AND incident_id='inc_early'`); n != 0 {
		t.Fatalf("an earlier flap's incident adopted the scene (%d refs)", n)
	}
}

// Two connectivity outages in quick succession are closer together than
// attachSlack, so the range tests alone cannot separate them: the first outage's
// scene passes every bound the second signal applies. On stock settings the
// spacing is grace(60s)+recover(30s) ≈ 95s against a 120s slack, so this is not
// a corner case — it is what a flapping uplink does all afternoon.
//
// Both claim paths must agree that the scene belongs to the outage that was in
// progress when the agent stamped it, and to nothing else.
func TestConsecutiveDisconnectsDoNotShareAScene(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	// C1 ran 10:00:00 → 10:01:35; the agent dropped again at 10:01:40 and C2 was
	// confirmed a minute later. The two observed_at are 100s apart.
	c1Start, c1End := now.Add(-160*time.Second), now.Add(-65*time.Second)
	c2Start := now.Add(-60 * time.Second)
	seedConnectivitySignal(t, db, "inc_c1", "sig_c1", "agent_a", "resolved", c1Start, &c1End)
	seedConnectivitySignal(t, db, "inc_c2", "sig_c2", "agent_a", "firing", c2Start, nil)
	svc := New(db, nil, settings.New(db), eventbus.New())

	// The scene describes C1's drop and arrived while C1 was still the live outage.
	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_c1", c1Start, disconnectTrigger(c1Start)))
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_c1' AND incident_id='inc_c1'`); n != 1 {
		t.Fatalf("the scene was not filed against the outage it describes (%d refs)", n)
	}

	// C2 confirming must not adopt it. Its observed_at is only 100s after the edge,
	// so every window and slack bound admits the scene; only asking which outage
	// OWNS the edge rules it out.
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_c2", IncidentID: "inc_c2", AgentID: "agent_a", SiteID: "site_default",
		DetectorKey: fault.DetectorAgentConnectivity,
	}); err != nil {
		t.Fatalf("on signal confirmed: %v", err)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_c1' AND incident_id='inc_c2'`); n != 0 {
		t.Fatalf("the next outage adopted the previous drop's scene (%d refs)", n)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_c2' AND kind='scene.collected'`); n != 0 {
		t.Fatalf("the next outage's timeline announced a scene it does not own (%d rows)", n)
	}
}

// A scene that waited out an outage is the feature working, not a broken clock.
// Reading the absolute collected-vs-received gap as skew put a clock warning on
// exactly the evidence this whole path exists to deliver — an agent offline for
// twenty minutes would have every scene labelled "the clocks differ by 1200s".
// Only the agent stamping a scene in the server's FUTURE is a clock complaint.
func TestDeliveryLagIsNotReportedAsAClockFault(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	now := time.Now().UTC()

	// Collected 20 minutes ago, delivered on reconnect: a large positive lag and
	// no clock complaint.
	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_late", now.Add(-20*time.Minute), disconnectTrigger(now.Add(-20*time.Minute))))
	// Stamped 30s in the server's future: delivery cannot explain that.
	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_ahead", now.Add(30*time.Second), disconnectTrigger(now)))

	var lateLag int64
	var lateAhead int
	if err := db.QueryRowContext(ctx,
		`SELECT delivery_lag_ms, clock_ahead FROM scene_reports WHERE id='scene_late'`).
		Scan(&lateLag, &lateAhead); err != nil {
		t.Fatalf("read late scene: %v", err)
	}
	if lateAhead != 0 {
		t.Error("a scene that waited out an outage was flagged as a clock fault")
	}
	if lateLag < 19*60*1000 {
		t.Errorf("delivery lag = %dms, want roughly the 20-minute wait", lateLag)
	}

	var aheadLag int64
	var aheadFlag int
	if err := db.QueryRowContext(ctx,
		`SELECT delivery_lag_ms, clock_ahead FROM scene_reports WHERE id='scene_ahead'`).
		Scan(&aheadLag, &aheadFlag); err != nil {
		t.Fatalf("read ahead scene: %v", err)
	}
	if aheadFlag != 1 {
		t.Error("an agent clock running ahead of the server was not flagged")
	}
	if aheadLag >= 0 {
		t.Errorf("delivery lag = %dms, want negative for a future-stamped scene", aheadLag)
	}
}

// The probe path needs the same owner rule the disconnect path has. A monitor
// that recovers and fails again inside attachSlack — a default ICMP target can
// start its next outage about 50 seconds later — otherwise lets the previous
// outage's scene pass every range test the new signal applies.
func TestConsecutiveProbeOutagesDoNotShareAScene(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	firstStart, firstEnd := now.Add(-150*time.Second), now.Add(-100*time.Second)
	secondStart := now.Add(-50 * time.Second)
	seedResolvedSceneSignal(t, db, "inc_p1", "sig_p1", "agent_a", "probe_x", 7, firstStart, firstEnd)
	seedSceneSignal(t, db, "inc_p2", "sig_p2", "agent_a", "probe_x", 7, secondStart)
	svc := New(db, nil, settings.New(db), eventbus.New())

	// The scene describes the FIRST outage.
	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_p1", firstStart, probeTrigger("probe_x", 7, firstStart)))
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_p1' AND incident_id='inc_p1'`); n != 1 {
		t.Fatalf("the scene was not filed against the outage it describes (%d refs)", n)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_p1' AND incident_id='inc_p2'`); n != 0 {
		t.Fatalf("the second outage adopted the first one's scene at ingest (%d refs)", n)
	}

	// And the claim-back path must agree.
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_p2", IncidentID: "inc_p2", AgentID: "agent_a", SiteID: "site_default",
		DetectorKey: "availability",
	}); err != nil {
		t.Fatalf("on signal confirmed: %v", err)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_p1' AND incident_id='inc_p2'`); n != 0 {
		t.Fatalf("claim-back gave the second outage the first one's scene (%d refs)", n)
	}
}

// The agent's scene cooldown can hold an edge past the fault's own recovery, so
// the recovery rounds reach the server first and the signal resolves before the
// scene is even queued. Its confirmation callback already ran, so a firing-only
// match at ingest would strand the scene permanently — evidence collected,
// delivered, and never looked at.
func TestSceneAttachesToARecentlyResolvedProbeFault(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	start, end := now.Add(-4*time.Minute), now.Add(-2*time.Minute)
	seedResolvedSceneSignal(t, db, "inc_short", "sig_short", "agent_a", "probe_y", 2, start, end)
	svc := New(db, nil, settings.New(db), nil)

	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_held", now, probeTrigger("probe_y", 2, start)))

	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_held' AND incident_id='inc_short'`); n != 1 {
		t.Fatalf("a scene delayed past its fault's recovery was stranded (%d refs)", n)
	}
}

// A slow monitor confirms long after the agent's own threshold fires: a 30-minute
// NAT target on the stable profile confirms at five failures while the agent
// collects at three, so the signal that owns the scene appears about an hour
// after the scene arrived. A receipt cutoff shorter than that rejects an exact
// agent/monitor/generation match on age alone.
func TestSlowCadenceSceneIsStillClaimable(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	edge := now.Add(-90 * time.Minute)
	svc := New(db, nil, settings.New(db), eventbus.New())

	// The scene arrives an hour and a half before anything confirms.
	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_slow", edge, probeTrigger("probe_nat", 1, edge)))
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_slow'`); n != 0 {
		t.Fatalf("a scene attached before any signal existed (%d refs)", n)
	}
	// Age the receipt to what it would really be by confirmation time: the whole
	// point is that the scene has been sitting here for an hour and a half.
	if _, err := db.ExecContext(ctx,
		`UPDATE scene_reports SET received_at=? WHERE id='scene_slow'`, edge); err != nil {
		t.Fatalf("age receipt: %v", err)
	}

	// The signal's own outage began at the edge and confirms only now.
	seedSceneSignal(t, db, "inc_slow", "sig_slow", "agent_a", "probe_nat", 1, edge)
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_slow", IncidentID: "inc_slow", AgentID: "agent_a", SiteID: "site_default",
		DetectorKey: "availability",
	}); err != nil {
		t.Fatalf("on signal confirmed: %v", err)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_slow' AND incident_id='inc_slow'`); n != 1 {
		t.Fatalf("a slow monitor's scene could never be claimed (%d refs)", n)
	}
}

// A scene that arrives before its fault has exactly one later chance: the
// post-commit confirmation handler. That handler is best-effort — the event is
// never replayed and the bus swallows its error — so a process exiting in that
// gap, or one transient failure, used to strand the scene until retention
// deleted it. Telemetry replay cannot bring it back either: the packet is
// deduplicated by sequence. The reconcile pass is what makes the claim durable.
func TestReconcileClaimsASceneWhoseConfirmationWasMissed(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	start := now.Add(-5 * time.Minute)
	svc := New(db, nil, settings.New(db), eventbus.New())

	// The scene lands before any signal exists, so ingest attaches nothing.
	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_missed", start, probeTrigger("probe_z", 9, start)))
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_missed'`); n != 0 {
		t.Fatalf("a scene attached before its signal existed (%d refs)", n)
	}

	// The signal is now durable, but OnSignalConfirmed never ran for it.
	seedSceneSignal(t, db, "inc_missed", "sig_missed", "agent_a", "probe_z", 9, start)

	if err := svc.ReconcileSceneClaims(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_missed' AND incident_id='inc_missed'`); n != 1 {
		t.Fatalf("the stranded scene was not recovered (%d refs)", n)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id='inc_missed' AND kind='scene.collected'`); n != 1 {
		t.Fatalf("timeline rows = %d, want exactly one", n)
	}

	// Running again must change nothing.
	if err := svc.ReconcileSceneClaims(ctx); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_missed'`); n != 1 {
		t.Fatalf("reconcile is not idempotent (%d refs)", n)
	}
}

// Retention deliberately outlives the claim horizon so the last pass that can
// claim a scene precedes the pass that may delete it. That grace is only real if
// the reconciler scans to the RETENTION horizon: bounding its scan by the claim
// window instead keeps the scene on disk and skips it on every pass, which
// deletes it just as surely and two hours later.
func TestReconcileScansToTheRetentionHorizon(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	edge := now.Add(-sceneClaimWindow - time.Hour)
	svc := New(db, nil, settings.New(db), eventbus.New())

	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_edge", edge, probeTrigger("probe_e", 2, edge)))
	// Age it past the claim horizon but still inside retention — the grace window.
	if _, err := db.ExecContext(ctx,
		`UPDATE scene_reports SET received_at=? WHERE id='scene_edge'`, edge); err != nil {
		t.Fatalf("age receipt: %v", err)
	}
	if now.Sub(edge) <= sceneClaimWindow || now.Sub(edge) >= unreferencedSceneRetention {
		t.Fatalf("test scene is not inside the grace window: aged %s", now.Sub(edge))
	}

	seedSceneSignal(t, db, "inc_edge", "sig_edge", "agent_a", "probe_e", 2, edge)
	if err := svc.ReconcileSceneClaims(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n := countRows(t, db,
		`SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_edge' AND incident_id='inc_edge'`); n != 1 {
		t.Fatalf("a scene inside the retention grace was skipped by reconciliation (%d refs)", n)
	}
}

// The console reads the two halves together: the server's frozen base and every
// claimed agent scene, each carrying the trigger that explains why it exists.
func TestSnapshotViewCarriesScenesAndTriggers(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	seedSceneSignal(t, db, "inc_v", "sig_v", "agent_a", "probe_x", 5, now)
	svc := New(db, nil, settings.New(db), nil)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := svc.WriteIncidentBase(ctx, tx, "inc_v", now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("write base: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_v", now, probeTrigger("probe_x", 5, now)))

	view, ok, err := svc.Snapshot(ctx, "inc_v")
	if err != nil || !ok {
		t.Fatalf("snapshot: ok=%v err=%v", ok, err)
	}
	if len(view.Base) == 0 {
		t.Fatal("the server base is missing from the view")
	}
	if len(view.Scenes) != 1 {
		t.Fatalf("view has %d scenes, want 1", len(view.Scenes))
	}
	sc := view.Scenes[0]
	if sc.ReportID != "scene_v" || sc.AgentID != "agent_a" {
		t.Fatalf("scene identity = %s/%s", sc.ReportID, sc.AgentID)
	}
	if sc.CollectedAt == nil || sc.ReceivedAt.IsZero() {
		t.Fatalf("scene timestamps = %v / %v", sc.CollectedAt, sc.ReceivedAt)
	}
	if len(sc.Triggers) != 1 || sc.Triggers[0].Kind != telemetry.SceneTriggerProbeFault ||
		sc.Triggers[0].MonitorID != "probe_x" || sc.Triggers[0].ConfigSerial != 5 {
		t.Fatalf("scene triggers = %+v", sc.Triggers)
	}
	if len(sc.Payload) == 0 {
		t.Fatal("scene payload is missing")
	}
}

// A scene that never found a fault is invisible to every read path once its
// claim window closes, so retention ages it out whole. A claimed one is that
// incident's evidence and survives the same pass.
func TestRetentionAgesOutUnreferencedScenesOnly(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	seedSceneSignal(t, db, "inc_keep", "sig_keep", "agent_a", "probe_x", 1, now)
	svc := New(db, nil, settings.New(db), nil)

	ingestScenes(t, svc, ctx, "agent_a",
		basicScene("scene_kept", now, probeTrigger("probe_x", 1, now)),
		basicScene("scene_orphan", now, probeTrigger("probe_gone", 1, now)))
	if _, err := db.ExecContext(ctx,
		`UPDATE scene_reports SET received_at=?`, now.Add(-2*unreferencedSceneRetention)); err != nil {
		t.Fatalf("age the scenes: %v", err)
	}

	if err := svc.Retention(ctx); err != nil {
		t.Fatalf("retention: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_reports WHERE id='scene_orphan'`); n != 0 {
		t.Fatal("an unreferenced scene outlived its retention window")
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_reports WHERE id='scene_kept'`); n != 1 {
		t.Fatal("a claimed scene was deleted as if it were orphaned")
	}
	// The triggers go with the deleted row, not before it.
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_triggers WHERE report_id='scene_orphan'`); n != 0 {
		t.Fatalf("%d orphaned trigger rows survived the cascade", n)
	}
}

// Retention drops the payload of a scene whose every incident is resolved and
// expired, but keeps the row: the triggers and timestamps are what let a reader
// see that a scene WAS collected for this fault and has since aged out.
func TestRetentionClearsExpiredScenePayloads(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	seedSceneSignal(t, db, "inc_exp", "sig_exp", "agent_a", "probe_x", 1, now)
	svc := New(db, nil, settings.New(db), nil)
	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_exp", now, probeTrigger("probe_x", 1, now)))

	if _, err := db.ExecContext(ctx,
		`UPDATE incidents SET state='resolved', resolved_at=? WHERE id='inc_exp'`,
		now.Add(-365*24*time.Hour)); err != nil {
		t.Fatalf("resolve incident: %v", err)
	}
	if err := svc.Retention(ctx); err != nil {
		t.Fatalf("retention: %v", err)
	}

	var payload string
	if err := db.QueryRowContext(ctx, `SELECT payload FROM scene_reports WHERE id='scene_exp'`).Scan(&payload); err != nil {
		t.Fatalf("read scene: %v", err)
	}
	if payload != "" {
		t.Fatalf("expired scene payload survived: %q", payload)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_triggers WHERE report_id='scene_exp'`); n != 1 {
		t.Fatalf("the trigger was dropped with the payload (%d rows)", n)
	}
}

// The payload cap is enforced before the row is stored — there is no later pass
// to settle an over-budget total against — and it sheds the optional detail in a
// fixed order so two identical scenes reduce identically.
func TestScenePayloadIsCappedBeforeStorage(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	set := settings.New(db)
	const budget = 65536
	if err := set.Set(ctx, settings.KeyIncidentSnapshotMaxBytes, "65536"); err != nil {
		t.Fatalf("set max bytes: %v", err)
	}
	svc := New(db, nil, set, nil)
	now := time.Now().UTC()

	scene := basicScene("scene_big", now, probeTrigger("probe_x", 1, now))
	for i := 0; i < 4000; i++ {
		scene.Targets = append(scene.Targets, telemetry.SnapshotTargetResult{
			MonitorID: "probe_x", Kind: "http", Target: "https://example.test/a/rather/long/path",
			ResolvedIPs: []string{"203.0.113.10", "203.0.113.11"},
		})
	}
	scene.Groups = append(scene.Groups, telemetry.SnapshotGroupResult{
		Group: telemetry.SnapshotGroupTargets, Status: telemetry.ScopeCollected})
	ingestScenes(t, svc, ctx, "agent_a", scene)

	var raw string
	var truncated int
	if err := db.QueryRowContext(ctx,
		`SELECT payload, truncated FROM scene_reports WHERE id='scene_big'`).Scan(&raw, &truncated); err != nil {
		t.Fatalf("read scene: %v", err)
	}
	if len(raw) > budget {
		t.Fatalf("stored %d bytes over the %d cap", len(raw), budget)
	}
	if truncated != 1 {
		t.Fatal("a shed scene was not marked truncated")
	}
	if raw != "" && !json.Valid([]byte(raw)) {
		t.Fatal("truncation stored invalid JSON")
	}
	p := scenePayloadOf(t, db, "scene_big")
	if len(p.Targets) != 0 {
		t.Fatalf("target detail survived the cap (%d entries)", len(p.Targets))
	}
	if len(p.Groups) == 0 {
		t.Fatal("the group outcomes were shed; a reduced scene must still read as reduced")
	}
}

// A scene with no trigger can never be filed against anything, so it is dropped
// rather than stored to age out unread.
func TestIngestDropsATriggerlessScene(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	now := time.Now().UTC()
	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_none", now))

	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_reports`); n != 0 {
		t.Fatalf("stored %d triggerless scenes", n)
	}
}

// A report id belongs to the agent that minted it. A second agent presenting the
// same id must not overwrite the stored scene.
func TestIngestSceneRejectsAForeignAgentsID(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	svc := New(db, nil, settings.New(db), nil)
	now := time.Now().UTC()
	ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_owned", now, probeTrigger("probe_x", 1, now)))
	ingestScenes(t, svc, ctx, "agent_b", basicScene("scene_owned", now, probeTrigger("probe_y", 9, now)))

	var owner string
	if err := db.QueryRowContext(ctx, `SELECT agent_id FROM scene_reports WHERE id='scene_owned'`).Scan(&owner); err != nil {
		t.Fatalf("read scene: %v", err)
	}
	if owner != "agent_a" {
		t.Fatalf("owner = %s, want the agent that minted the id", owner)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_triggers WHERE report_id='scene_owned'`); n != 1 {
		t.Fatalf("%d trigger rows, want only the original agent's", n)
	}
}
