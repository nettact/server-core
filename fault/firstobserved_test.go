package fault

import (
	"database/sql"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// incidentTimes reads the two instants an incident carries, plus its state.
func (h *harness) incidentTimes(id string) (openedAt time.Time, firstObserved sql.NullTime, resolvedAt sql.NullTime) {
	h.t.Helper()
	err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT opened_at, first_observed_at, resolved_at FROM incidents WHERE id=?`, id).
		Scan(&openedAt, &firstObserved, &resolvedAt)
	if err != nil {
		h.t.Fatalf("read incident times: %v", err)
	}
	return
}

func (h *harness) onlyIncidentID() string {
	h.t.Helper()
	var id string
	if err := h.db.Read().QueryRowContext(h.ctx, `SELECT id FROM incidents`).Scan(&id); err != nil {
		h.t.Fatalf("read incident id: %v", err)
	}
	return id
}

// mergeGroup turns on the default group's merge policy, so every target's fault
// attaches to ONE incident — the shape in which a start time has to be the
// minimum over members rather than just the first one written.
func (h *harness) mergeGroup() {
	h.t.Helper()
	h.exec(`UPDATE monitor_groups SET merge_enabled=1 WHERE id='mg'`)
}

// addTarget registers a second (third, …) ICMP monitor in the default group.
func (h *harness) addTarget(id, addr string) {
	h.t.Helper()
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		VALUES(?,'site_default','mg','icmp',?,?,'{}',1,1)`, id, id, addr)
}

// lossFor lives in fluctuation_test.go; this file reuses it.

// evaluateTarget confirms one target's fault from rounds at the given
// timestamps, registering the monitor first.
func (h *harness) evaluateTarget(id string, det DetectionSettings, tss ...int64) {
	h.t.Helper()
	addr := "10.0.0." + id[len(id)-1:]
	h.addTarget(id, addr)
	meta := map[string]TargetMeta{
		id: {ID: id, Kind: "icmp", GroupID: "mg", Name: id, Addr: addr,
			Enabled: true, ConfigSerial: 1, Det: det.Normalize()},
	}
	ms := make([]telemetry.Metric, 0, len(tss))
	for _, ts := range tss {
		ms = append(ms, lossFor(id, addr, ts, 100))
	}
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	if _, err := h.svc.EvaluateAgentTx(h.ctx, tx, "agent_a", "site_default", BuildRounds(ms, meta)); err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("evaluate %s: %v", id, err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
}

// The headline case: an agent buffers an outage through a reboot and uploads it
// on reconnect. The incident must record WHEN THE OUTAGE HAPPENED, not when the
// packet arrived — otherwise a twenty-minute outage renders as a blip at the
// moment of reconnection, which is what the fault list used to show.
func TestReplayedOutageRecordsWhenItActuallyHappened(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection() // 3 rounds to confirm

	// Evidence from twenty minutes ago, all arriving in one batch.
	base := time.Now().Add(-20 * time.Minute).Unix()
	h.evaluate(det, loss(base, 100))
	h.evaluate(det, loss(base+10, 100))
	h.evaluate(det, loss(base+20, 100))

	id := h.onlyIncidentID()
	openedAt, firstObserved, _ := h.incidentTimes(id)

	if !firstObserved.Valid {
		t.Fatal("first_observed_at is null on a confirmed fault")
	}
	if got := firstObserved.Time.Unix(); got != base {
		t.Fatalf("first_observed_at = %d, want the first failing round (%d)", got, base)
	}
	// opened_at stays wall-clock: ordering, the 24h statistics and storm
	// correlation are all built on receipt time.
	if lag := time.Since(openedAt); lag > time.Minute {
		t.Fatalf("opened_at is %s old; it must be the moment the server recorded this", lag)
	}
	if !openedAt.After(firstObserved.Time.Add(19 * time.Minute)) {
		t.Fatalf("opened_at %s and first_observed_at %s should be ~20 minutes apart",
			openedAt, firstObserved.Time)
	}

	// The recovery is in the same backlog, at its own evidence time.
	h.evaluate(det, loss(base+30, 0))
	h.evaluate(det, loss(base+40, 0))

	_, firstObserved, resolvedAt := h.incidentTimes(id)
	if !resolvedAt.Valid {
		t.Fatal("the replayed recovery did not resolve the incident")
	}
	// This is the number the fault list shows as duration.
	if got := resolvedAt.Time.Sub(firstObserved.Time); got < 30*time.Second {
		t.Fatalf("recorded duration = %s, want the outage's real span (>= 30s of evidence)", got)
	}
}

// A merged incident's start is the earliest of its members', including a member
// that joins later carrying older evidence.
func TestFirstObservedIsLoweredByAnEarlierMember(t *testing.T) {
	h := newHarness(t)
	h.mergeGroup()
	det := DefaultDetection()

	late := time.Now().Add(-5 * time.Minute).Unix()
	h.evaluateTarget("t_late", det, late, late+10, late+20)
	id := h.onlyIncidentID()
	_, firstObserved, _ := h.incidentTimes(id)
	if got := firstObserved.Time.Unix(); got != late {
		t.Fatalf("first_observed_at = %d, want %d", got, late)
	}

	// A second target of the same group confirms from OLDER evidence.
	early := time.Now().Add(-30 * time.Minute).Unix()
	h.evaluateTarget("t_early", det, early, early+10, early+20)

	_, firstObserved, _ = h.incidentTimes(id)
	if got := firstObserved.Time.Unix(); got != early {
		t.Fatalf("first_observed_at = %d, want it lowered to the earlier member's %d", got, early)
	}

	// And it never moves forward again.
	later := time.Now().Add(-time.Minute).Unix()
	h.evaluateTarget("t_later", det, later, later+10, later+20)
	_, firstObserved, _ = h.incidentTimes(id)
	if got := firstObserved.Time.Unix(); got != early {
		t.Fatalf("first_observed_at moved forward to %d; it is a running minimum", got)
	}
}

// An Agent-connectivity fault starts when the Agent was last seen, not when the
// grace period expired — the same distinction its signal already carries.
func TestAgentConnectivityFirstObservedIsTheLastSeenTime(t *testing.T) {
	h := newHarness(t)
	offline := time.Now().Add(-15 * time.Minute).UTC().Truncate(time.Second)
	now := time.Now().UTC()

	if _, err := h.svc.OpenAgentSignal(h.ctx, AgentSignalInput{
		AgentID: "agent_a", SiteID: "site_default", Name: "node-1",
		Reason: "unexpected", OfflineSince: offline,
	}, now); err != nil {
		t.Fatalf("open agent signal: %v", err)
	}

	id := h.onlyIncidentID()
	openedAt, firstObserved, _ := h.incidentTimes(id)
	if !firstObserved.Valid {
		t.Fatal("first_observed_at is null on an Agent-connectivity fault")
	}
	if got := firstObserved.Time.UTC().Truncate(time.Second); !got.Equal(offline) {
		t.Fatalf("first_observed_at = %s, want the last-seen time %s", got, offline)
	}
	if !openedAt.After(firstObserved.Time.Add(14 * time.Minute)) {
		t.Fatalf("opened_at %s should trail the last-seen time by the grace period", openedAt)
	}
}

// A slow upload cadence is not a replay. An install is free to configure an
// upload interval longer than the replay threshold, and every one of its live
// faults would then inherit the settle delay if lateness were judged against a
// fixed constant instead of the target's own reporting rhythm.
func TestReplayLagIgnoresLatenessWithinTheTargetsOwnCadence(t *testing.T) {
	now := time.Now()

	// A five-minute upload cadence: rounds routinely land minutes after they were
	// taken, with no backlog involved.
	slow := 6 * time.Minute
	if got := replayLagOf(now.Add(-4*time.Minute), now, slow); got != 0 {
		t.Fatalf("lag = %s for a round inside a slow agent's own gap, want 0", got)
	}
	// Past that rhythm it is a backlog again.
	if got := replayLagOf(now.Add(-20*time.Minute), now, slow); got != 20*time.Minute {
		t.Fatalf("lag = %s, want the full 20m once past the cadence", got)
	}

	// A brisk target keeps the constant floor, so ordinary batching and drain
	// latency never reads as a replay either.
	brisk := 30 * time.Second
	if got := replayLagOf(now.Add(-90*time.Second), now, brisk); got != 0 {
		t.Fatalf("lag = %s inside the %s floor, want 0", got, ReplayThreshold)
	}
	if got := replayLagOf(now.Add(-20*time.Minute), now, brisk); got != 20*time.Minute {
		t.Fatalf("lag = %s, want 20m", got)
	}

	// No evidence time, and a clock running ahead, both mean "not a replay".
	if got := replayLagOf(time.Time{}, now, brisk); got != 0 {
		t.Fatalf("lag = %s with no evidence time, want 0", got)
	}
	if got := replayLagOf(now.Add(time.Hour), now, brisk); got != 0 {
		t.Fatalf("lag = %s for future-dated evidence, want 0", got)
	}
}
