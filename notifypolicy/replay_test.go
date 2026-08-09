package notifypolicy

import (
	"testing"
	"time"

	"github.com/nettact/server-core/fault"
)

// openReplayedIncident opens an incident whose confirming evidence is old — the
// shape an agent's backlog produces when it reconnects after an outage and its
// buffered rounds are folded at their own timestamps.
func (h *harness) openReplayedIncident(id, severity string, evidenceAge time.Duration, now time.Time) {
	h.t.Helper()
	evidence := now.Add(-evidenceAge)
	h.exec(`INSERT INTO incidents(id,site_id,group_id,open_key,title,state,severity,opened_at)
		VALUES(?,'site_default','mg',?, 'Router unreachable','open',?,?)`, id, "sig:"+id, severity, now)
	h.exec(`INSERT INTO fault_signals(id,site_id,agent_id,agent_name,target_id,target_name,target_addr,
		detector_key,probe_kind,metric_kind,comparator,threshold,value,severity,state,observed_at,confirmed_at,incident_id)
		VALUES(?,'site_default','agent_a','node-1',?, 'Router','192.168.1.1','availability','icmp',
		'probe.icmp.loss_pct','gte',100,100,?, 'firing',?,?,?)`,
		"sig_"+id, "t1_"+id, severity, evidence, evidence, id)

	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	err = h.svc.PlanOpenTx(h.ctx, tx, fault.IncidentScope{
		IncidentID: id, SiteID: "site_default", GroupID: "mg", Severity: severity,
		ReplayLag: now.Sub(evidence),
	}, now)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("plan: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
}

// zeroDelayPolicy points the site default at a channel and removes its delays —
// a legal configuration, and the one that breaks the assumption that the delay
// alone keeps a replayed fault quiet.
func (h *harness) zeroDelayPolicy(ids ...string) {
	h.t.Helper()
	p := h.sitePolicy()
	p.Enabled = true
	p.ChannelIDs = ids
	p.WarnDelaySec = 0
	p.CriticalDelaySec = 0
	if _, err := h.svc.Update(h.ctx, p.ID, p); err != nil {
		h.t.Fatalf("update policy: %v", err)
	}
}

// The scenario this exists for: an agent buffers a 20-minute outage through a
// reboot, reconnects, and its backlog confirms AND resolves the fault within
// seconds of each other on the wire. With a zero delay the worker would
// otherwise get a chance to alarm about an outage that ended before the message
// was composed.
func TestReplayedFaultIsNotAnnouncedWhenItHasAlreadyRecovered(t *testing.T) {
	h := newHarness(t)
	h.zeroDelayPolicy("ch_a")
	now := time.Now().UTC()

	h.openReplayedIncident("inc_1", "warn", 20*time.Minute, now)

	ds := h.deliveries("inc_1")
	if len(ds) != 1 || ds[0].Status != statusPending {
		t.Fatalf("expected one pending delivery, got %+v", ds)
	}
	if !ds[0].DueAt.After(now.Add(30 * time.Second)) {
		t.Fatalf("due_at = %v, want a settle floor beyond %v — a zero-delay policy must not "+
			"let replayed evidence be announced immediately", ds[0].DueAt, now)
	}

	// The worker runs between the two packets of the drain. This is the tick the
	// delay alone would have failed to hold.
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick between packets: %v", err)
	}
	if h.cap.count() != 0 {
		t.Fatalf("a replayed fault was announced before its recovery could arrive (%d sent)", h.cap.count())
	}

	// The rest of the backlog lands and resolves it, at its own evidence time.
	h.resolveIncident("inc_1", fault.ReasonRecovered, now.Add(-19*time.Minute))
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick after recovery: %v", err)
	}
	if h.cap.count() != 0 {
		t.Fatalf("an outage that had already ended was announced, sent %d", h.cap.count())
	}
	if ds := h.deliveries("inc_1"); len(ds) != 1 || ds[0].Status != statusCanceled {
		t.Fatalf("expected the pending notice to be canceled, got %+v", ds)
	}
}

// The floor is a delay, not a suppression: a replayed fault that is still
// broken when the backlog runs out is announced, one settle window later.
func TestReplayedFaultStillFiringIsStillAnnounced(t *testing.T) {
	h := newHarness(t)
	h.zeroDelayPolicy("ch_a")
	now := time.Now().UTC()

	h.openReplayedIncident("inc_1", "warn", 20*time.Minute, now)
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 0 {
		t.Fatal("sent inside the settle window")
	}

	// Nothing resolved it: the target is still down. Once the window passes the
	// notice goes out exactly as it would for a live fault.
	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE incident_id='inc_1'`, now.Add(-time.Second))
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick after the window: %v", err)
	}
	if h.cap.count() != 1 {
		t.Fatalf("a replayed fault that never recovered must still be announced, sent %d", h.cap.count())
	}
}

// Live telemetry must be unaffected: an ordinary fault keeps the delay its
// policy asks for, zero included.
func TestLiveFaultKeepsItsConfiguredDelay(t *testing.T) {
	h := newHarness(t)
	h.zeroDelayPolicy("ch_a")
	now := time.Now().UTC()

	h.openIncident("inc_1", "warn", now)
	ds := h.deliveries("inc_1")
	if len(ds) != 1 {
		t.Fatalf("expected one delivery, got %+v", ds)
	}
	if ds[0].DueAt.After(now.Add(time.Second)) {
		t.Fatalf("due_at = %v, want immediate for a zero-delay policy on live evidence", ds[0].DueAt)
	}
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 1 {
		t.Fatalf("a live fault under a zero-delay policy must be announced at once, sent %d", h.cap.count())
	}
}

// A policy whose delay already exceeds the settle window keeps it: the floor
// raises, never lowers. Deciding WHETHER a confirmation is a replay belongs to
// the fault engine (it is the only side that knows the target's cadence), so a
// zero lag here means "live" and needs no threshold of its own.
func TestSettleFloorNeverShortensAConfiguredDelay(t *testing.T) {
	if got := dueDelay(10*time.Minute, 30*time.Minute); got != 10*time.Minute {
		t.Fatalf("dueDelay = %s, want the policy's own 10m", got)
	}
	if got := dueDelay(0, 30*time.Minute); got != replaySettle {
		t.Fatalf("dueDelay = %s, want the %s settle floor", got, replaySettle)
	}
	if got := dueDelay(0, 0); got != 0 {
		t.Fatalf("dueDelay = %s, want 0 for live evidence", got)
	}
	if got := dueDelay(30*time.Second, 0); got != 30*time.Second {
		t.Fatalf("dueDelay = %s, want the policy's own 30s on live evidence", got)
	}
}
