package agentalert

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// fakeNotifier captures dispatched notifications (channel selection + payload) on
// a buffered channel so tests can deterministically wait for (or assert the
// absence of) a notification even though the engine dispatches on a goroutine.
type dispatch struct {
	channels []string
	p        notification.Payload
}
type fakeNotifier struct{ ch chan dispatch }

func newFakeNotifier() *fakeNotifier { return &fakeNotifier{ch: make(chan dispatch, 32)} }

func (f *fakeNotifier) Notify(_ context.Context, channels []string, p notification.Payload) {
	f.ch <- dispatch{channels: channels, p: p}
}

type harness struct {
	t     *testing.T
	db    *store.DB
	set   *settings.Service
	notif *fakeNotifier
	eng   *Engine
	clock time.Time
	ctx   context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	set := settings.New(db)
	notif := newFakeNotifier()
	h := &harness{t: t, db: db, set: set, notif: notif, ctx: ctx, clock: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	h.eng = New(db, set, notif, eventbus.New())
	h.eng.now = func() time.Time { return h.clock }
	// Short, clear timings; the machine is clock-driven so absolute values only
	// need to be internally consistent.
	h.setInt(settings.KeyAgentAlertGraceSeconds, 30)
	h.setInt(settings.KeyAgentAlertRecoverSeconds, 10)
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

func (h *harness) firingCount(agentID string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT COUNT(*) FROM agent_alerts WHERE agent_id=? AND status='firing'`, agentID).Scan(&n); err != nil {
		h.t.Fatalf("count firing: %v", err)
	}
	return n
}

func (h *harness) alertRow(agentID string) (status, reason, resolveReason string) {
	h.t.Helper()
	err := h.db.QueryRowContext(h.ctx,
		`SELECT status, reason, COALESCE(resolve_reason,'') FROM agent_alerts WHERE agent_id=? ORDER BY opened_at DESC LIMIT 1`,
		agentID).Scan(&status, &reason, &resolveReason)
	if err != nil {
		h.t.Fatalf("alert row: %v", err)
	}
	return
}

func (h *harness) expectPayloads(n int) []dispatch {
	h.t.Helper()
	var got []dispatch
	for i := 0; i < n; i++ {
		select {
		case d := <-h.notif.ch:
			got = append(got, d)
		case <-time.After(2 * time.Second):
			h.t.Fatalf("timed out waiting for payload %d of %d", i+1, n)
		}
	}
	return got
}

func (h *harness) expectNoPayload() {
	h.t.Helper()
	select {
	case p := <-h.notif.ch:
		h.t.Fatalf("unexpected payload: %+v", p)
	case <-time.After(100 * time.Millisecond):
	}
}

// takeAgentOffline drives an agent from connected to a fired offline alert and
// returns after the offline notification has been dispatched and drained.
func (h *harness) takeAgentOffline(id string) {
	h.t.Helper()
	h.tick(id) // connected
	h.advance(1 * time.Second)
	h.tick() // absent: absentSince set
	h.advance(30 * time.Second)
	h.tick() // offline >= grace: open + queue
	if h.firingCount(id) != 1 {
		h.t.Fatalf("expected 1 firing after grace, got %d", h.firingCount(id))
	}
	h.advance(15 * time.Second)
	h.tick() // batch window elapsed: flush
	ps := h.expectPayloads(1)
	if ps[0].p.Event != "agent.offline" {
		h.t.Fatalf("expected agent.offline, got %s", ps[0].p.Event)
	}
}

func ptr(t time.Time) *time.Time { return &t }

func TestGraceThenFireOnceWithNotification(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")

	h.tick("agent_a")
	h.advance(1 * time.Second)
	h.tick() // first absent tick: establishes the monotonic baseline
	h.advance(28 * time.Second)
	h.tick() // 28s < grace 30: no alert yet
	if got := h.firingCount("agent_a"); got != 0 {
		t.Fatalf("expected no alert before grace, got %d", got)
	}
	h.advance(2 * time.Second)
	h.tick() // 30s >= grace: fires
	if got := h.firingCount("agent_a"); got != 1 {
		t.Fatalf("expected 1 firing at grace, got %d", got)
	}
	// Dedup: another tick while absent must not open a second alert.
	h.advance(1 * time.Second)
	h.tick()
	if got := h.firingCount("agent_a"); got != 1 {
		t.Fatalf("expected still 1 firing (dedup), got %d", got)
	}
	// Flush the notification and assert its shape.
	h.advance(15 * time.Second)
	h.tick()
	ps := h.expectPayloads(1)
	if ps[0].p.Event != "agent.offline" || ps[0].p.AgentCount != 1 || len(ps[0].p.Agents) != 1 {
		t.Fatalf("bad offline payload: %+v", ps[0])
	}
	if ps[0].p.Agents[0].Reason != "unexpected" {
		t.Fatalf("expected reason unexpected, got %q", ps[0].p.Agents[0].Reason)
	}
	h.expectNoPayload()
}

func TestRecoveryWithinGraceNoAlert(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")

	h.tick("agent_a")
	h.advance(1 * time.Second)
	h.tick()                    // absent
	h.advance(20 * time.Second) // < grace 30
	h.tick("agent_a")           // reconnects before grace
	if got := h.firingCount("agent_a"); got != 0 {
		t.Fatalf("expected no alert on early recovery, got %d firing", got)
	}
	h.advance(20 * time.Second)
	h.tick("agent_a")
	h.expectNoPayload()
}

func TestRecoveryConfirmation(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	// Reconnect: not resolved until sustained >= recover (10s).
	h.tick("agent_a")
	if st, _, _ := h.alertRow("agent_a"); st != "firing" {
		t.Fatalf("expected still firing right after reconnect, got %s", st)
	}
	h.advance(9 * time.Second)
	h.tick("agent_a")
	if st, _, _ := h.alertRow("agent_a"); st != "firing" {
		t.Fatalf("expected still firing before confirm, got %s", st)
	}
	h.advance(1 * time.Second) // now 10s connected
	h.tick("agent_a")
	if st, _, rr := h.alertRow("agent_a"); st != "resolved" || rr != "recovered" {
		t.Fatalf("expected resolved/recovered, got %s/%s", st, rr)
	}
	// Recovery notification flushes after the batch window.
	h.advance(15 * time.Second)
	h.tick("agent_a")
	ps := h.expectPayloads(1)
	if ps[0].p.Event != "agent.recovered" {
		t.Fatalf("expected agent.recovered, got %s", ps[0].p.Event)
	}
}

func TestFlapNoDuplicateOrRecovery(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	h.tick("agent_a")          // reconnect
	h.advance(5 * time.Second) // < recover 10
	h.tick()                   // drops again before confirm
	if got := h.firingCount("agent_a"); got != 1 {
		t.Fatalf("expected still exactly 1 firing (no dup, no resolve), got %d", got)
	}
	if st, _, _ := h.alertRow("agent_a"); st != "firing" {
		t.Fatalf("expected still firing after flap, got %s", st)
	}
	h.expectNoPayload()
}

func TestRestartSettleNoImmediateAlert(t *testing.T) {
	h := newHarness(t)
	// Agent connected a day ago and has been offline since — a naive last_seen
	// based engine would fire immediately; the monotonic baseline must not.
	dayAgo := h.clock.Add(-24 * time.Hour)
	h.seedAgent("agent_a", ptr(dayAgo), ptr(dayAgo), false, "error")

	h.tick() // first observed absence: baseline = now, not last_seen
	if got := h.firingCount("agent_a"); got != 0 {
		t.Fatalf("expected no alert on first tick after restart, got %d", got)
	}
	h.advance(29 * time.Second)
	h.tick()
	if got := h.firingCount("agent_a"); got != 0 {
		t.Fatalf("expected no alert before grace from startup, got %d", got)
	}
	h.advance(1 * time.Second)
	h.tick()
	if got := h.firingCount("agent_a"); got != 1 {
		t.Fatalf("expected alert at startup+grace, got %d", got)
	}
}

func TestMuteMidFlightThenUnmuteReopens(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	// Mute: resolve firing as 'muted', no notification.
	mustExec(t, h.db, `UPDATE agents SET connectivity_alerts_muted=1 WHERE id='agent_a'`)
	h.tick()
	if st, _, rr := h.alertRow("agent_a"); st != "resolved" || rr != "muted" {
		t.Fatalf("expected resolved/muted, got %s/%s", st, rr)
	}
	h.expectNoPayload()

	// Unmute while still offline past grace: a fresh alert opens + notifies.
	mustExec(t, h.db, `UPDATE agents SET connectivity_alerts_muted=0 WHERE id='agent_a'`)
	h.tick()
	if got := h.firingCount("agent_a"); got != 1 {
		t.Fatalf("expected fresh firing after unmute, got %d", got)
	}
	h.advance(15 * time.Second)
	h.tick()
	ps := h.expectPayloads(1)
	if ps[0].p.Event != "agent.offline" {
		t.Fatalf("expected agent.offline after unmute, got %s", ps[0].p.Event)
	}
}

func TestOnMuteChangedResolvesFiring(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	mustExec(t, h.db, `UPDATE agents SET connectivity_alerts_muted=1 WHERE id='agent_a'`)
	h.eng.OnMuteChanged(h.ctx, "agent_a", true)
	if st, _, rr := h.alertRow("agent_a"); st != "resolved" || rr != "muted" {
		t.Fatalf("expected resolved/muted via OnMuteChanged, got %s/%s", st, rr)
	}
	h.expectNoPayload()
}

func TestDisableMidFlightResolves(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.takeAgentOffline("agent_a")

	h.setInt(settings.KeyAgentAlertEnabled, 0)
	h.tick()
	if st, _, rr := h.alertRow("agent_a"); st != "resolved" || rr != "disabled" {
		t.Fatalf("expected resolved/disabled, got %s/%s", st, rr)
	}
	h.expectNoPayload()
}

func TestNeverConnectedExcluded(t *testing.T) {
	h := newHarness(t)
	h.seedAgent("agent_a", nil, nil, false, "") // first_connected_at NULL

	h.tick()
	h.advance(60 * time.Second)
	h.tick()
	h.advance(60 * time.Second)
	h.tick()
	if got := h.firingCount("agent_a"); got != 0 {
		t.Fatalf("expected never-connected agent to raise no alert, got %d", got)
	}
	h.expectNoPayload()
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
		if _, r, _ := h.alertRow(id); r != reason {
			t.Fatalf("agent %s: expected reason %s, got %s", id, reason, r)
		}
	}
}

func TestMultiAgentMergedNotification(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")
	h.seedAgent("agent_b", ptr(base), ptr(base), false, "error")

	h.tick("agent_a", "agent_b")
	h.advance(1 * time.Second)
	h.tick() // both absent
	h.advance(30 * time.Second)
	h.tick() // both open + queue in the same window
	h.advance(15 * time.Second)
	h.tick() // flush merged
	ps := h.expectPayloads(1)
	if ps[0].p.AgentCount != 2 || len(ps[0].p.Agents) != 2 {
		t.Fatalf("expected one merged payload with 2 agents, got count=%d agents=%d", ps[0].p.AgentCount, len(ps[0].p.Agents))
	}
	h.expectNoPayload()
}

// TestMuteDuringBatchWindowDropsNotice verifies that muting an agent while its
// offline notice is still buffered (inside the 15s batch window) drops the notice
// so no agent.offline notification is ever sent.
func TestMuteDuringBatchWindowDropsNotice(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")

	h.tick("agent_a")
	h.advance(1 * time.Second)
	h.tick() // absent baseline
	h.advance(30 * time.Second)
	h.tick() // open + queue offline notice (pendingSince = now, not yet flushed)
	if h.firingCount("agent_a") != 1 {
		t.Fatalf("expected 1 firing before mute")
	}

	// Mute inside the batch window and tick: the alert resolves 'muted' and the
	// queued offline notice must be dropped.
	mustExec(t, h.db, `UPDATE agents SET connectivity_alerts_muted=1 WHERE id='agent_a'`)
	h.tick()
	if st, _, rr := h.alertRow("agent_a"); st != "resolved" || rr != "muted" {
		t.Fatalf("expected resolved/muted, got %s/%s", st, rr)
	}
	// Advance past the batch window and tick: nothing must flush.
	h.advance(15 * time.Second)
	h.tick()
	h.expectNoPayload()
}

// TestRecoveryUsesFrozenSettings verifies the recovery notification routes through
// the severity + channels frozen when the alert opened, not the current settings.
func TestRecoveryUsesFrozenSettings(t *testing.T) {
	h := newHarness(t)
	base := h.clock
	h.seedAgent("agent_a", ptr(base), ptr(base), false, "error")

	// Freeze severity=error + channels=[chan_A] at open.
	if err := h.set.Set(h.ctx, settings.KeyAgentAlertSeverity, "error"); err != nil {
		t.Fatal(err)
	}
	if err := h.set.Set(h.ctx, settings.KeyAgentAlertChannelIDs, `["chan_A"]`); err != nil {
		t.Fatal(err)
	}
	h.takeAgentOffline("agent_a")
	// The offline notice used the frozen selection.
	// (takeAgentOffline already drained it; re-open would double count — assert on recovery.)

	// Operator changes the settings while the agent is down.
	if err := h.set.Set(h.ctx, settings.KeyAgentAlertSeverity, "info"); err != nil {
		t.Fatal(err)
	}
	if err := h.set.Set(h.ctx, settings.KeyAgentAlertChannelIDs, `["chan_B"]`); err != nil {
		t.Fatal(err)
	}

	// Reconnect + confirm recovery.
	h.tick("agent_a")
	h.advance(10 * time.Second)
	h.tick("agent_a") // resolve recovered + queue
	h.advance(15 * time.Second)
	h.tick("agent_a") // flush
	ps := h.expectPayloads(1)
	if ps[0].p.Event != "agent.recovered" {
		t.Fatalf("expected agent.recovered, got %s", ps[0].p.Event)
	}
	if ps[0].p.Severity != "error" {
		t.Fatalf("recovery severity = %q, want frozen 'error'", ps[0].p.Severity)
	}
	if len(ps[0].channels) != 1 || ps[0].channels[0] != "chan_A" {
		t.Fatalf("recovery channels = %v, want frozen [chan_A]", ps[0].channels)
	}
}
