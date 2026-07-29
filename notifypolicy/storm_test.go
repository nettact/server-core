package notifypolicy

import (
	"strconv"
	"testing"
	"time"

	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/incident"
	"github.com/nettact/server-core/settings"
)

// These tests pin the promise alert-storm suppression makes to someone whose
// upstream link just died: ONE message, not one per monitor group — and one
// summary when it comes back, even if the server was restarted in between. The
// failure they exist to prevent is the one that makes people mute alarms
// forever.

// stormHarness extends the policy harness with several monitor groups, since a
// storm is by definition about more than one of them.
func stormHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	for _, g := range []struct{ id, name string }{
		{"mg_web", "Websites"}, {"mg_dns", "DNS"}, {"mg_nat", "NAT"}, {"mg_extra", "Extra"},
	} {
		h.exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
			VALUES(?,'site_default',?,0,1,1)`, g.id, g.name)
	}
	return h
}

// openFault opens one incident in its own monitor group, observed by agentID,
// and runs the real planning path — including storm correlation.
func (h *harness) openFault(id, groupID, layer, severity, agentID string, now time.Time) {
	h.t.Helper()
	h.exec(`INSERT INTO incidents(id,site_id,group_id,group_name,open_key,title,suspected_layer,state,severity,opened_at)
		VALUES(?,'site_default',?,(SELECT name FROM monitor_groups WHERE id=?),?,'Group down',?,'open',?,?)`,
		id, groupID, groupID, "grp:"+groupID+":"+id, layer, severity, now)
	h.exec(`INSERT INTO fault_signals(id,site_id,agent_id,agent_name,target_id,target_name,target_addr,
		detector_key,probe_kind,group_id,layer,metric_kind,comparator,threshold,value,severity,state,
		observed_at,confirmed_at,incident_id)
		VALUES(?,'site_default',?,'imini',?, 'Router','192.168.1.1','availability','icmp',?,?,
		'probe.icmp.loss_pct','gte',100,100,?, 'firing',?,?,?)`,
		"sig_"+id, agentID, "t_"+id, groupID, layer, severity, now, now, id)

	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	err = h.svc.PlanOpenTx(h.ctx, tx, fault.IncidentScope{
		IncidentID: id, SiteID: "site_default", GroupID: groupID, AgentID: agentID, Severity: severity,
	}, now)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("plan %s: %v", id, err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
}

// dueNow backdates every pending delivery so the next Tick dispatches it. This
// is exactly the state a server finds after being down across a delay.
func (h *harness) dueNow() {
	h.t.Helper()
	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE status='pending'`, time.Now().UTC().Add(-time.Second))
}

func (h *harness) tick() {
	h.t.Helper()
	if err := h.svc.Tick(h.ctx); err != nil {
		h.t.Fatalf("tick: %v", err)
	}
}

func (h *harness) setInt(key string, v int) {
	h.t.Helper()
	if err := settings.New(h.db).Set(h.ctx, key, strconv.Itoa(v)); err != nil {
		h.t.Fatalf("set %s: %v", key, err)
	}
}

// countRows is a small assertion helper for delivery bookkeeping.
func (h *harness) countRows(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(h.ctx, q, args...).Scan(&n); err != nil {
		h.t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func (h *harness) stormID() string {
	h.t.Helper()
	var id string
	if err := h.db.QueryRowContext(h.ctx, `SELECT COALESCE(MAX(id),'') FROM alert_storms`).Scan(&id); err != nil {
		h.t.Fatalf("storm id: %v", err)
	}
	return id
}

// TestStormCollapsesSimultaneousFaults is the headline promise: three groups
// breaking at once under one Agent produce ONE message, not three.
func TestStormCollapsesSimultaneousFaults(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	// The third crosses the default threshold of 3 and forms the storm.
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)

	if n := h.countRows(`SELECT COUNT(*) FROM alert_storms WHERE state='open'`); n != 1 {
		t.Fatalf("open storms = %d, want 1", n)
	}
	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND status=?`,
		eventOpened, statusPending); n != 0 {
		t.Fatalf("%d per-incident notices survived; all three must be superseded", n)
	}
	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND status=?`,
		eventStormOpened, statusPending); n != 1 {
		t.Fatalf("storm notices = %d, want exactly 1", n)
	}
	// Every member is still fully recorded and linked — a storm summarizes, it
	// never swallows the record.
	if n := h.countRows(`SELECT COUNT(*) FROM incidents WHERE storm_id IS NOT NULL`); n != 3 {
		t.Fatalf("storm members = %d, want 3", n)
	}

	h.dueNow()
	h.tick()
	if h.cap.count() != 1 {
		t.Fatalf("sent %d notifications, want exactly 1", h.cap.count())
	}
	got := h.cap.at(0)
	if got.payload.Event != eventStormOpened {
		t.Fatalf("event = %q, want %q", got.payload.Event, eventStormOpened)
	}
	if got.payload.Storm == nil {
		t.Fatal("storm payload missing")
	}
	if got.payload.Storm.FaultCount != 3 || got.payload.Storm.GroupCount != 3 {
		t.Fatalf("counts = %d faults / %d groups, want 3/3",
			got.payload.Storm.FaultCount, got.payload.Storm.GroupCount)
	}
	// Root-cause annotation: WAN is the most fundamental layer present, so that is
	// what the notice blames — not the DNS and service failures above it.
	if got.payload.SuspectedLayer != "wan" {
		t.Fatalf("suspected layer = %q, want wan", got.payload.SuspectedLayer)
	}
	if got.payload.Storm.AgentName != "imini" {
		t.Fatalf("agent name = %q, want the frozen signal name", got.payload.Storm.AgentName)
	}
}

// TestBelowThresholdIsUnchanged: two simultaneous faults are not a storm, and
// must behave exactly as they did before this feature existed.
func TestBelowThresholdIsUnchanged(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)

	if n := h.countRows(`SELECT COUNT(*) FROM alert_storms`); n != 0 {
		t.Fatalf("storms = %d, want none below the threshold", n)
	}
	h.dueNow()
	h.tick()
	if h.cap.count() != 2 {
		t.Fatalf("sent %d, want one notification per incident", h.cap.count())
	}
}

// TestStormAbsorbsLaterMembers: once a storm is running, everything else that
// breaks under the same Agent joins it silently.
func TestStormAbsorbsLaterMembers(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)
	h.dueNow()
	h.tick() // the storm notice goes out

	h.openFault("inc_extra", "mg_extra", "service", "warn", "agent_a", now.Add(time.Minute))
	h.dueNow()
	h.tick()

	if h.cap.count() != 1 {
		t.Fatalf("sent %d, want 1 — a member joining a running storm says nothing", h.cap.count())
	}
	var stormID string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT COALESCE(storm_id,'') FROM incidents WHERE id='inc_extra'`).Scan(&stormID); err != nil {
		t.Fatalf("read member: %v", err)
	}
	if stormID == "" {
		t.Fatal("the late member was not folded into the running storm")
	}
}

// TestEscalatingMemberDoesNotBreakOutOfTheStorm: when a member's severity rises
// past a policy floor that had skipped a channel, that channel's newly-planned
// notice must go through the storm too. Left alone it would announce "1 fault"
// in the middle of an outage whose truth is "4 at once".
func TestEscalatingMemberDoesNotBreakOutOfTheStorm(t *testing.T) {
	h := stormHarness(t)
	// The floor is what makes this real: at warn the policy covers nothing, so the
	// storm forms with no channels at all. The escalation to critical is the FIRST
	// moment ch_a is routed anywhere — a brand-new pending row that did not exist
	// when the storm swept its members.
	def := h.setDefaultChannels("ch_a")
	def.MinSeverity = "error"
	if _, err := h.svc.Update(h.ctx, def.ID, def); err != nil {
		t.Fatalf("raise policy floor: %v", err)
	}
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)

	// The member gets worse, exactly as confirmSignal reports it: the incident row
	// is recomputed first, then the planner is told.
	h.exec(`UPDATE incidents SET severity='critical' WHERE id='inc_nat'`)
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	err = h.svc.EscalateTx(h.ctx, tx, fault.IncidentScope{
		IncidentID: "inc_nat", SiteID: "site_default", GroupID: "mg_nat",
		AgentID: "agent_a", Severity: "critical",
	}, now)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("escalate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND status=?`,
		eventOpened, statusPending); n != 0 {
		t.Fatalf("%d per-incident notices escaped the storm on escalation", n)
	}
	h.dueNow()
	h.tick()
	if h.cap.count() != 1 {
		t.Fatalf("sent %d, want exactly 1", h.cap.count())
	}
	// The storm now carries the worse severity, so the one message that goes out
	// says how bad it really is.
	if got := h.cap.at(0).payload.Severity; got != "critical" {
		t.Fatalf("storm severity = %q, want critical", got)
	}
}

// TestMergedIncidentStaysWithItsOwnStorm: a merge-enabled group's incident
// collects signals from every agent in scope, so an escalation can arrive
// carrying a different AgentID than the one whose storm owns the incident.
// Routing its notices to that other agent's storm would split one fault's
// announcements across two summaries.
func TestMergedIncidentStaysWithItsOwnStorm(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	// agent_a's burst forms storm A, which owns inc_web.
	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)
	stormA := h.stormID()

	// agent_b has its own burst, so its own storm.
	h.openFault("inc_b1", "mg_extra", "service", "warn", "agent_b", now)
	h.exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
		VALUES('mg_b2','site_default','B2',0,1,1)`)
	h.exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
		VALUES('mg_b3','site_default','B3',0,1,1)`)
	h.openFault("inc_b2", "mg_b2", "service", "warn", "agent_b", now)
	h.openFault("inc_b3", "mg_b3", "service", "warn", "agent_b", now)
	if n := h.countRows(`SELECT COUNT(*) FROM alert_storms WHERE state='open'`); n != 2 {
		t.Fatalf("open storms = %d, want 2 (one per agent)", n)
	}

	// A second agent's signal escalates the merged incident that storm A owns.
	h.exec(`UPDATE incidents SET severity='critical' WHERE id='inc_web'`)
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	err = h.svc.EscalateTx(h.ctx, tx, fault.IncidentScope{
		IncidentID: "inc_web", SiteID: "site_default", GroupID: "mg_web",
		AgentID: "agent_b", Severity: "critical",
	}, now)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("escalate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var owner string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT storm_id FROM incidents WHERE id='inc_web'`).Scan(&owner); err != nil {
		t.Fatalf("read member: %v", err)
	}
	if owner != stormA {
		t.Fatalf("incident moved to storm %q, want to stay in %q", owner, stormA)
	}
	// Its escalated severity belongs to the storm that owns it, not to agent_b's.
	var sevA string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT severity FROM alert_storms WHERE id=?`, stormA).Scan(&sevA); err != nil {
		t.Fatalf("read storm A: %v", err)
	}
	if sevA != "critical" {
		t.Fatalf("owning storm severity = %q, want critical", sevA)
	}
	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE storm_id<>? AND event_kind=?`,
		stormA, eventStormOpened); n != 1 {
		// agent_b's own storm has exactly its own one channel row — none stolen from inc_web.
		t.Fatalf("agent_b's storm has %d notices, want only its own 1", n)
	}
}

// TestPartialRecoveryRefreshesStormSeverity: when a merged incident's worst
// member recovers and another is still firing, the fault engine never calls
// ResolveTx — so without an explicit hook the storm keeps announcing a severity
// that has already gone away.
func TestPartialRecoveryRefreshesStormSeverity(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "critical", "agent_a", now)

	var sev string
	if err := h.db.QueryRowContext(h.ctx, `SELECT severity FROM alert_storms`).Scan(&sev); err != nil {
		t.Fatalf("read storm: %v", err)
	}
	if sev != "critical" {
		t.Fatalf("storm severity = %q, want critical to start", sev)
	}

	// The critical member partially recovers: the incident drops to warn but stays
	// open, which is the path that skips ResolveTx entirely.
	h.exec(`UPDATE incidents SET severity='warn' WHERE id='inc_nat'`)
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := h.svc.RecomputeTx(h.ctx, tx, "inc_nat", now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("recompute: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if err := h.db.QueryRowContext(h.ctx, `SELECT severity FROM alert_storms`).Scan(&sev); err != nil {
		t.Fatalf("read storm: %v", err)
	}
	if sev != "warn" {
		t.Fatalf("storm severity = %q after partial recovery, want warn", sev)
	}
	h.dueNow()
	h.tick()
	if got := h.cap.at(0).payload.Severity; got != "warn" {
		t.Fatalf("delayed notice announced %q, want the severity that is actually current", got)
	}
}

// TestUnroutedEscalationStillRefreshesTheStorm: a member whose own group routes
// nowhere still raised the severity of the storm that speaks for it through
// other members' channels.
func TestUnroutedEscalationStillRefreshesTheStorm(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)

	// The group that is about to escalate routes nowhere: an enabled override with
	// no channels is the documented way to say "record, send nothing".
	if _, err := h.svc.Create(h.ctx, "site_default", Policy{
		Name: "silent", ScopeKind: ScopeGroup, ScopeID: "mg_nat", Enabled: true,
		MinSeverity: "warn", ChannelIDs: []string{},
	}); err != nil {
		t.Fatalf("create silent policy: %v", err)
	}

	h.exec(`UPDATE incidents SET severity='critical' WHERE id='inc_nat'`)
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	err = h.svc.EscalateTx(h.ctx, tx, fault.IncidentScope{
		IncidentID: "inc_nat", SiteID: "site_default", GroupID: "mg_nat",
		AgentID: "agent_a", Severity: "critical",
	}, now)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("escalate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var sev string
	if err := h.db.QueryRowContext(h.ctx, `SELECT severity FROM alert_storms`).Scan(&sev); err != nil {
		t.Fatalf("read storm: %v", err)
	}
	if sev != "critical" {
		t.Fatalf("storm severity = %q, want critical — the member escalated even though it routes nowhere", sev)
	}
}

// TestStormRecoveryPreferenceIsMerged: one channel routed by two policies with
// different notify_recovery must not have the outcome decided by which fault
// happened to confirm first.
func TestStormRecoveryPreferenceIsMerged(t *testing.T) {
	h := stormHarness(t)
	def := h.setDefaultChannels("ch_a")
	// The site default reaches ch_a but does NOT want recovery notices.
	def.NotifyRecovery = false
	if _, err := h.svc.Update(h.ctx, def.ID, def); err != nil {
		t.Fatalf("update default: %v", err)
	}
	// One group overrides to the same channel and DOES want them.
	if _, err := h.svc.Create(h.ctx, "site_default", Policy{
		Name: "wants recovery", ScopeKind: ScopeGroup, ScopeID: "mg_nat", Enabled: true,
		MinSeverity: "warn", NotifyRecovery: true, ChannelIDs: []string{"ch_a"},
	}); err != nil {
		t.Fatalf("create override: %v", err)
	}
	now := time.Now().UTC()

	// The no-recovery member confirms FIRST, so it is the one that would win a
	// first-write-wins merge.
	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)

	var recovery int
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT recovery_enabled FROM notification_deliveries WHERE event_kind=? AND channel_id='ch_a'`,
		eventStormOpened).Scan(&recovery); err != nil {
		t.Fatalf("read storm delivery: %v", err)
	}
	if recovery != 1 {
		t.Fatal("a policy that asked for a recovery notice lost it to confirmation order")
	}

	h.dueNow()
	h.tick()
	back := now.Add(3 * time.Minute)
	for _, id := range []string{"inc_web", "inc_dns", "inc_nat"} {
		h.resolveIncident(id, fault.ReasonRecovered, back)
	}
	h.dueNow()
	h.tick()
	if h.cap.count() != 2 {
		t.Fatalf("sent %d, want 2 — the recovery its policy asked for must arrive", h.cap.count())
	}
}

// TestStormRecoverySpeaksOnlyForWhatRecovered: with one member genuinely back
// and two ended by configuration changes, the summary must not claim all three
// recovered. Announcing a recovery that did not happen is the failure this whole
// pipeline is built to avoid.
func TestStormRecoverySpeaksOnlyForWhatRecovered(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)
	h.dueNow()
	h.tick()

	end := now.Add(4 * time.Minute)
	h.resolveIncident("inc_web", fault.ReasonTargetDeleted, end)
	h.resolveIncident("inc_dns", fault.ReasonConfigChanged, end)
	h.resolveIncident("inc_nat", fault.ReasonRecovered, end)
	h.dueNow()
	h.tick()

	if h.cap.count() != 2 {
		t.Fatalf("sent %d, want 2", h.cap.count())
	}
	st := h.cap.at(1).payload.Storm
	if st == nil {
		t.Fatal("recovery payload carries no storm detail")
	}
	if st.FaultCount != 1 || st.GroupCount != 1 {
		t.Fatalf("recovery claims %d faults / %d groups recovered, want 1/1 — the other two were deleted or reconfigured",
			st.FaultCount, st.GroupCount)
	}
	if len(st.Groups) != 1 || st.Groups[0].Name != "NAT" {
		t.Fatalf("recovery lists %+v, want only the group that actually came back", st.Groups)
	}
}

// TestStormRecoveryIsOneSummary: N faults coming back produce ONE recovery
// notice, not N.
func TestStormRecoveryIsOneSummary(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)
	h.dueNow()
	h.tick()

	back := now.Add(12 * time.Minute)
	h.resolveIncident("inc_web", fault.ReasonRecovered, back)
	h.resolveIncident("inc_dns", fault.ReasonRecovered, back)
	// Nothing may be announced while any member is still broken.
	h.dueNow()
	h.tick()
	if h.cap.count() != 1 {
		t.Fatalf("sent %d after a PARTIAL recovery, want still 1", h.cap.count())
	}

	h.resolveIncident("inc_nat", fault.ReasonRecovered, back)
	h.dueNow()
	h.tick()
	if h.cap.count() != 2 {
		t.Fatalf("sent %d, want 2 (one storm notice + one summary recovery)", h.cap.count())
	}
	got := h.cap.at(1)
	if got.payload.Event != eventStormResolved {
		t.Fatalf("event = %q, want %q", got.payload.Event, eventStormResolved)
	}
	if got.payload.Storm == nil || got.payload.Storm.DurationS < 600 {
		t.Fatalf("recovery must carry how long the outage lasted, got %+v", got.payload.Storm)
	}
	var state string
	if err := h.db.QueryRowContext(h.ctx, `SELECT state FROM alert_storms`).Scan(&state); err != nil {
		t.Fatalf("read storm: %v", err)
	}
	if state != "resolved" {
		t.Fatalf("storm state = %q, want resolved", state)
	}
}

// TestStormRecoverySurvivesRestart: the whole point of persisting the storm is
// that a server bounced mid-outage still sends ONE summary rather than N loose
// recoveries. The second Service stands in for the process that came back.
func TestStormRecoverySurvivesRestart(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)
	h.dueNow()
	h.tick()

	// Restart: fresh service, fresh notifier, same database. Nothing about the
	// storm lives in memory.
	restarted := &capture{}
	h.svc = New(h.db, restarted, settings.New(h.db), nil)
	h.cap = restarted
	if err := h.svc.RecoverStorms(h.ctx); err != nil {
		t.Fatalf("recover storms: %v", err)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM alert_storms WHERE state='open'`); n != 1 {
		t.Fatalf("recovery closed a storm that still has open members (open storms = %d)", n)
	}

	back := now.Add(20 * time.Minute)
	for _, id := range []string{"inc_web", "inc_dns", "inc_nat"} {
		h.resolveIncident(id, fault.ReasonRecovered, back)
	}
	h.dueNow()
	h.tick()
	if restarted.count() != 1 {
		t.Fatalf("sent %d after restart, want exactly 1 summary recovery", restarted.count())
	}
	if ev := restarted.at(0).payload.Event; ev != eventStormResolved {
		t.Fatalf("event = %q, want %q", ev, eventStormResolved)
	}
}

// TestStormClosedByReconfigurationSaysNothing: deleting or reconfiguring every
// member ends the storm, but nothing "recovered" — announcing one would be a
// lie, and leaving the storm open forever would be a zombie.
func TestStormClosedByReconfigurationSaysNothing(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)
	h.dueNow()
	h.tick()

	gone := now.Add(time.Minute)
	for _, id := range []string{"inc_web", "inc_dns", "inc_nat"} {
		h.resolveIncident(id, fault.ReasonTargetDeleted, gone)
	}
	h.dueNow()
	h.tick()

	if h.cap.count() != 1 {
		t.Fatalf("sent %d, want still 1 — a deleted target never 'recovered'", h.cap.count())
	}
	var state string
	if err := h.db.QueryRowContext(h.ctx, `SELECT state FROM alert_storms`).Scan(&state); err != nil {
		t.Fatalf("read storm: %v", err)
	}
	if state != "resolved" {
		t.Fatalf("storm state = %q, want resolved — a storm whose members are gone must not linger", state)
	}
}

// TestStormWithOneGenuineRecoveryAnnounces: a mixed ending still announces,
// because something really did come back.
func TestStormWithOneGenuineRecoveryAnnounces(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)
	h.dueNow()
	h.tick()

	end := now.Add(2 * time.Minute)
	h.resolveIncident("inc_web", fault.ReasonTargetDeleted, end)
	h.resolveIncident("inc_dns", fault.ReasonConfigChanged, end)
	h.resolveIncident("inc_nat", fault.ReasonRecovered, end)
	h.dueNow()
	h.tick()

	if h.cap.count() != 2 {
		t.Fatalf("sent %d, want 2 — one member genuinely recovered", h.cap.count())
	}
}

// TestStormThresholdZeroDisablesCorrelation: the escape hatch has to be
// complete, restoring the per-incident behaviour exactly.
func TestStormThresholdZeroDisablesCorrelation(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	h.setInt(settings.KeyIncidentStormThreshold, 0)
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)

	if n := h.countRows(`SELECT COUNT(*) FROM alert_storms`); n != 0 {
		t.Fatalf("storms = %d, want none when correlation is off", n)
	}
	h.dueNow()
	h.tick()
	if h.cap.count() != 3 {
		t.Fatalf("sent %d, want 3 — one per incident", h.cap.count())
	}
}

// TestStormWindowExcludesOlderFaults: three faults spread over a day are not
// "at once", and correlating them would be a false claim about a shared cause.
func TestStormWindowExcludesOlderFaults(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	h.setInt(settings.KeyIncidentStormWindowSeconds, 60)
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now.Add(-2*time.Hour))
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now.Add(-time.Hour))
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)

	if n := h.countRows(`SELECT COUNT(*) FROM alert_storms`); n != 0 {
		t.Fatalf("storms = %d, want none — the earlier faults are outside the window", n)
	}
}

// TestStormIsPerAgent: two agents each losing one thing is not one event, and
// merging them would blame a shared cause that was never observed.
func TestStormIsPerAgent(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_a1", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_a2", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_b1", "mg_nat", "wan", "warn", "agent_b", now)

	if n := h.countRows(`SELECT COUNT(*) FROM alert_storms`); n != 0 {
		t.Fatalf("storms = %d, want none — neither agent saw three faults", n)
	}
}

// TestChannelOptedOutKeepsPerIncidentNotices: a machine consumer that needs one
// record per incident is not made lossy by a summary meant for a human.
func TestChannelOptedOutKeepsPerIncidentNotices(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a", "ch_b")
	h.exec(`UPDATE notification_channels SET storm_merge=0 WHERE id='ch_b'`)
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)

	// ch_a merged: its three per-incident notices are superseded by one storm
	// notice. ch_b opted out: its three survive untouched.
	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND status=? AND channel_id='ch_a'`,
		eventOpened, statusPending); n != 0 {
		t.Fatalf("merged channel kept %d per-incident notices, want 0", n)
	}
	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND status=? AND channel_id='ch_b'`,
		eventOpened, statusPending); n != 3 {
		t.Fatalf("opted-out channel has %d per-incident notices, want 3", n)
	}
	stormChannels := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND channel_id='ch_b'`, eventStormOpened)
	if stormChannels != 0 {
		t.Fatalf("opted-out channel was given %d storm notices, want 0", stormChannels)
	}

	h.dueNow()
	h.tick()
	// One storm notice to ch_a, three incident notices to ch_b.
	if h.cap.count() != 4 {
		t.Fatalf("sent %d groups, want 4 (1 storm + 3 per-incident)", h.cap.count())
	}

	// Recovery pairs the same way: ch_b gets its three, ch_a gets one summary.
	back := now.Add(5 * time.Minute)
	for _, id := range []string{"inc_web", "inc_dns", "inc_nat"} {
		h.resolveIncident(id, fault.ReasonRecovered, back)
	}
	h.dueNow()
	h.tick()
	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND channel_id='ch_b' AND status=?`,
		eventResolved, statusSent); n != 3 {
		t.Fatalf("opted-out channel got %d recoveries, want 3", n)
	}
	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND channel_id='ch_a' AND status=?`,
		eventStormResolved, statusSent); n != 1 {
		t.Fatalf("merged channel got %d summary recoveries, want 1", n)
	}
	// And no channel ever receives a lone per-incident recovery for a notice the
	// storm swallowed.
	if n := h.countRows(
		`SELECT COUNT(*) FROM notification_deliveries WHERE event_kind=? AND channel_id='ch_a'`,
		eventResolved); n != 0 {
		t.Fatalf("merged channel was given %d per-incident recoveries, want 0", n)
	}
}

// TestStormDeliveriesVisibleFromMember: an operator opening a member fault must
// see that it WAS announced, as part of a storm — not an empty notification list
// that reads as "nobody was told".
func TestStormDeliveriesVisibleFromMember(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)
	h.dueNow()
	h.tick()

	stormID := h.stormID()
	var found bool
	for _, d := range h.deliveries("inc_web") {
		if d.StormID == stormID && d.EventKind == eventStormOpened && d.Status == statusSent {
			found = true
		}
	}
	if !found {
		t.Fatalf("member fault does not surface the storm notice that announced it: %+v", h.deliveries("inc_web"))
	}
}

// TestMemberNotifyCountsFoldInTheStorm: the fault centre's notify column must
// answer "was this fault announced". A member's own records are all canceled, so
// counting only those would report "recorded only" for a fault everyone was told
// about — and, before the summary goes out, must NOT claim it was told.
func TestMemberNotifyCountsFoldInTheStorm(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	inc := incident.New(h.db)
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "warn", "agent_a", now)

	// The summary is planned but not yet due: nobody has been told anything.
	got, err := inc.Get(h.ctx, "inc_web")
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if got.NotifiedCount != 0 {
		t.Fatalf("notified_count = %d before the summary went out, want 0", got.NotifiedCount)
	}
	if got.PendingNotifyCount != 1 {
		t.Fatalf("pending_notify_count = %d, want the storm's pending summary counted", got.PendingNotifyCount)
	}

	h.dueNow()
	h.tick()
	got, err = inc.Get(h.ctx, "inc_web")
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if got.NotifiedCount != 1 {
		t.Fatalf("notified_count = %d after the summary went out, want 1", got.NotifiedCount)
	}
	if got.StormID == "" {
		t.Fatal("member does not report its storm")
	}
}

// TestStormReadModel backs the console banner: the counts it shows have to be
// the real ones.
func TestStormReadModel(t *testing.T) {
	h := stormHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()

	h.openFault("inc_web", "mg_web", "service", "warn", "agent_a", now)
	h.openFault("inc_dns", "mg_dns", "dns", "warn", "agent_a", now)
	h.openFault("inc_nat", "mg_nat", "wan", "critical", "agent_a", now)

	var severity, layer string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT severity, suspected_layer FROM alert_storms`).Scan(&severity, &layer); err != nil {
		t.Fatalf("read storm: %v", err)
	}
	if severity != "critical" {
		t.Fatalf("storm severity = %q, want the worst member's", severity)
	}
	if layer != "wan" {
		t.Fatalf("storm layer = %q, want the most fundamental member's", layer)
	}
}
