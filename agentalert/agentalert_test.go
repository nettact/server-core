package agentalert

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// fakeRecorder stands in for the fault engine, recording what the liveness state
// machine decided without a database. These tests are about the state machine —
// when a fault is confirmed, when it resolves, and under which reason — not about
// how the fault is stored or whether anything is notified (the policy layer owns
// that and has its own coverage).
type fakeRecorder struct {
	firing   map[string]string // agentID -> signal id
	opened   []fault.AgentSignalInput
	resolved []resolveCall
	seq      int
}

type resolveCall struct {
	agentID string
	reason  string
}

func newFakeRecorder() *fakeRecorder { return &fakeRecorder{firing: map[string]string{}} }

func (f *fakeRecorder) OpenAgentSignal(_ context.Context, in fault.AgentSignalInput, _ time.Time) (string, error) {
	if _, ok := f.firing[in.AgentID]; ok {
		return "", nil // already firing; the unique index makes this a no-op
	}
	f.seq++
	id := "sig_" + strconv.Itoa(f.seq)
	f.firing[in.AgentID] = id
	f.opened = append(f.opened, in)
	return id, nil
}

func (f *fakeRecorder) ResolveAgentSignal(_ context.Context, agentID, reason string, _ time.Time) error {
	if _, ok := f.firing[agentID]; !ok {
		return nil
	}
	delete(f.firing, agentID)
	f.resolved = append(f.resolved, resolveCall{agentID: agentID, reason: reason})
	return nil
}

func (f *fakeRecorder) FiringAgentSignals(context.Context) (map[string]string, error) {
	out := make(map[string]string, len(f.firing))
	for k, v := range f.firing {
		out[k] = v
	}
	return out, nil
}

// lastResolve returns the most recent resolve reason for an agent, or "".
func (f *fakeRecorder) lastResolve(agentID string) string {
	for i := len(f.resolved) - 1; i >= 0; i-- {
		if f.resolved[i].agentID == agentID {
			return f.resolved[i].reason
		}
	}
	return ""
}

// lastOpen returns the most recent open input for an agent.
func (f *fakeRecorder) lastOpen(agentID string) (fault.AgentSignalInput, bool) {
	for i := len(f.opened) - 1; i >= 0; i-- {
		if f.opened[i].AgentID == agentID {
			return f.opened[i], true
		}
	}
	return fault.AgentSignalInput{}, false
}

type harness struct {
	t      *testing.T
	db     *store.DB
	set    *settings.Service
	faults *fakeRecorder
	eng    *Engine
	clock  time.Time
	ctx    context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	set := settings.New(db)
	rec := newFakeRecorder()
	h := &harness{t: t, db: db, set: set, faults: rec, ctx: ctx, clock: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	h.eng = New(db, set, rec, eventbus.New())
	h.eng.now = func() time.Time { return h.clock }
	// Short, clear timings; the machine is clock-driven so absolute values only
	// need to be internally consistent.
	h.setInt(settings.KeyAgentConnectivityGraceSeconds, 30)
	h.setInt(settings.KeyAgentConnectivityRecoverSeconds, 10)
	return h
}

func mustExec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func (h *harness) setInt(key string, v int) {
	h.t.Helper()
	if err := h.set.Set(h.ctx, key, strconv.Itoa(v)); err != nil {
		h.t.Fatalf("set %s: %v", key, err)
	}
}

// seedAgent inserts an agent. firstConn/lastSeen nil => NULL column.
func (h *harness) seedAgent(id string, firstConn, lastSeen *time.Time, muted bool, disconnectKind string) {
	h.t.Helper()
	m := 0
	if muted {
		m = 1
	}
	mustExec(h.t, h.db, `INSERT INTO agents(id, site_id, public_key, token_hash, status, hostname,
		first_connected_at, last_seen_at, connectivity_alerts_muted, last_disconnect_kind)
		VALUES(?, 'site_default', x'00', ?, 'offline', ?, ?, ?, ?, ?)`,
		id, "hash_"+id, id+"-host", firstConn, lastSeen, m, disconnectKind)
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

func (h *harness) tick(connected ...string) {
	h.t.Helper()
	if err := h.eng.Tick(h.ctx, connected); err != nil {
		h.t.Fatalf("tick: %v", err)
	}
}

// firing reports whether the agent currently has a confirmed connectivity fault.
func (h *harness) firing(agentID string) bool {
	_, ok := h.faults.firing[agentID]
	return ok
}

// openCount counts how many times a fault was confirmed for an agent, so a
// duplicate confirmation is visible even after the first one resolved.
func (h *harness) openCount(agentID string) int {
	n := 0
	for _, in := range h.faults.opened {
		if in.AgentID == agentID {
			n++
		}
	}
	return n
}

// takeAgentOffline drives an agent from connected to a confirmed offline fault.
func (h *harness) takeAgentOffline(id string) {
	h.t.Helper()
	h.tick(id) // connected
	h.advance(1 * time.Second)
	h.tick() // absent: absentSince set
	h.advance(30 * time.Second)
	h.tick() // offline >= grace: confirm
	if !h.firing(id) {
		h.t.Fatalf("expected a confirmed fault after grace")
	}
}

func ptr(t time.Time) *time.Time { return &t }

func TestGraceThenConfirmOnce(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")

	h.tick("agent_a")
	h.advance(1 * time.Second)
	h.tick() // first absent tick: establishes the monotonic baseline
	h.advance(28 * time.Second)
	h.tick() // 28s < grace 30: not yet
	if h.firing("agent_a") {
		t.Fatal("expected no fault before grace")
	}
	h.advance(2 * time.Second)
	h.tick() // 30s >= grace: confirms
	if !h.firing("agent_a") {
		t.Fatal("expected a fault at grace")
	}
	// Dedup: another tick while absent must not confirm a second fault.
	h.advance(1 * time.Second)
	h.tick()
	if n := h.openCount("agent_a"); n != 1 {
		t.Fatalf("expected exactly 1 confirmation (dedup), got %d", n)
	}
	in, ok := h.lastOpenOf("agent_a")
	if !ok || in.Reason != "unexpected" {
		t.Fatalf("expected reason unexpected, got %+v", in)
	}
	// observed_at is when the agent was last seen, not when grace expired, so the
	// recorded outage covers the whole gap.
	if !in.OfflineSince.Equal(base) {
		t.Fatalf("offline_since = %v, want the agent's last-seen time %v", in.OfflineSince, base)
	}
}

func (h *harness) lastOpenOf(agentID string) (fault.AgentSignalInput, bool) {
	return h.faults.lastOpen(agentID)
}

func TestRecoveryWithinGraceNoFault(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")

	h.tick("agent_a")
	h.advance(1 * time.Second)
	h.tick()                    // absent
	h.advance(20 * time.Second) // < grace 30
	h.tick("agent_a")           // reconnects before grace
	if h.firing("agent_a") {
		t.Fatal("expected no fault on early recovery")
	}
	h.advance(20 * time.Second)
	h.tick("agent_a")
	if n := h.openCount("agent_a"); n != 0 {
		t.Fatalf("expected no confirmation at all, got %d", n)
	}
}

func TestRecoveryConfirmation(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	// Reconnect: not resolved until sustained >= recover (10s).
	h.tick("agent_a")
	if !h.firing("agent_a") {
		t.Fatal("expected still firing right after reconnect")
	}
	h.advance(9 * time.Second)
	h.tick("agent_a")
	if !h.firing("agent_a") {
		t.Fatal("expected still firing before the recovery window closed")
	}
	h.advance(1 * time.Second) // now 10s connected
	h.tick("agent_a")
	if h.firing("agent_a") {
		t.Fatal("expected resolved after sustained reconnection")
	}
	if got := h.faults.lastResolve("agent_a"); got != fault.ReasonRecovered {
		t.Fatalf("resolve reason = %q, want recovered", got)
	}
}

func TestFlapDoesNotDuplicateOrResolve(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	h.tick("agent_a")          // reconnect
	h.advance(5 * time.Second) // < recover 10
	h.tick()                   // drops again before confirm
	if !h.firing("agent_a") || h.openCount("agent_a") != 1 {
		t.Fatalf("expected exactly one still-firing fault, firing=%v opens=%d", h.firing("agent_a"), h.openCount("agent_a"))
	}
	if len(h.faults.resolved) != 0 {
		t.Fatalf("a flap must not resolve the fault: %+v", h.faults.resolved)
	}
}

func TestRestartSettleNoImmediateFault(t *testing.T) {
	h := newHarness(t)
	// Agent connected a day ago and has been offline since — an engine measuring
	// grace from last_seen would confirm immediately; the monotonic baseline must
	// not, or every restart would fire the whole fleet at once.
	dayAgo := h.clock.Add(-24 * time.Hour)
	h.seedAgent("agent_a", ptr(dayAgo), ptr(dayAgo), false, "error")

	h.tick() // first observed absence: baseline = now, not last_seen
	if h.firing("agent_a") {
		t.Fatal("expected no fault on the first tick after a restart")
	}
	h.advance(29 * time.Second)
	h.tick()
	if h.firing("agent_a") {
		t.Fatal("expected no fault before grace measured from startup")
	}
	h.advance(1 * time.Second)
	h.tick()
	if !h.firing("agent_a") {
		t.Fatal("expected a fault at startup + grace")
	}
}

func TestMuteMidFlightThenUnmuteReopens(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	// Mute: end the fault as 'muted' — the operator silenced the detector, the
	// agent did not come back, so this must never read as a recovery.
	mustExec(t, h.db, `UPDATE agents SET connectivity_alerts_muted=1 WHERE id='agent_a'`)
	h.tick()
	if h.firing("agent_a") {
		t.Fatal("expected the fault to end on mute")
	}
	if got := h.faults.lastResolve("agent_a"); got != fault.ReasonMuted {
		t.Fatalf("resolve reason = %q, want muted", got)
	}

	// Unmute while still offline past grace: a fresh fault confirms.
	mustExec(t, h.db, `UPDATE agents SET connectivity_alerts_muted=0 WHERE id='agent_a'`)
	h.tick()
	if !h.firing("agent_a") || h.openCount("agent_a") != 2 {
		t.Fatalf("expected a fresh confirmation after unmute, firing=%v opens=%d", h.firing("agent_a"), h.openCount("agent_a"))
	}
}

func TestOnMuteChangedResolvesFiring(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	mustExec(t, h.db, `UPDATE agents SET connectivity_alerts_muted=1 WHERE id='agent_a'`)
	h.eng.OnMuteChanged(h.ctx, "agent_a", true)
	if h.firing("agent_a") || h.faults.lastResolve("agent_a") != fault.ReasonMuted {
		t.Fatalf("expected muted via OnMuteChanged, firing=%v reason=%q", h.firing("agent_a"), h.faults.lastResolve("agent_a"))
	}
}

func TestDisableMidFlightResolves(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	h.setInt(settings.KeyAgentConnectivityEnabled, 0)
	h.tick()
	if h.firing("agent_a") || h.faults.lastResolve("agent_a") != fault.ReasonDisabled {
		t.Fatalf("expected disabled, firing=%v reason=%q", h.firing("agent_a"), h.faults.lastResolve("agent_a"))
	}
}

func TestNeverConnectedExcluded(t *testing.T) {
	h := newHarness(t)
	h.seedAgent("agent_a", nil, nil, false, "") // first_connected_at NULL

	h.tick()
	h.advance(60 * time.Second)
	h.tick()
	h.advance(60 * time.Second)
	h.tick()
	// Nothing was ever lost, so there is no outage to report.
	if h.openCount("agent_a") != 0 {
		t.Fatalf("expected a never-connected agent to raise no fault, got %d", h.openCount("agent_a"))
	}
}

func TestReasonMapping(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_clean", ptr(base), ptr(base), false, "clean")
	h.seedAgent("agent_schema", ptr(base), ptr(base), false, "unsupported_schema")
	h.seedAgent("agent_err", ptr(base), ptr(base), false, "error")

	h.tick("agent_clean", "agent_schema", "agent_err")
	h.advance(1 * time.Second)
	h.tick() // first absent tick: baseline
	h.advance(30 * time.Second)
	h.tick() // all absent past grace

	want := map[string]string{
		"agent_clean":  "clean_shutdown",
		"agent_schema": "version_incompatible",
		"agent_err":    "unexpected",
	}
	for id, reason := range want {
		in, ok := h.lastOpenOf(id)
		if !ok || in.Reason != reason {
			t.Fatalf("agent %s: expected reason %s, got %+v", id, reason, in)
		}
	}
}

func TestFrozenDisplayName(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	mustExec(t, h.db, `UPDATE agents SET display_name='Living Room' WHERE id='agent_a'`)
	h.takeAgentOffline("agent_a")

	in, ok := h.lastOpenOf("agent_a")
	if !ok || in.Name != "Living Room" {
		t.Fatalf("expected the display name frozen onto the fault, got %+v", in)
	}
}
