package fault

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

// An ICMP round's loss is a ratio over the echoes the agent actually SENT, and
// the agent sends fewer than configured when its probe-concurrency budget could
// not admit them. A round that managed one echo of five reports either 0% or
// 100% — figures indistinguishable from a healthy or a dead target, on exactly
// the metric this detector reads. These tests pin that such a round is stored
// but never believed.

// sent builds the probe.icmp.sent sibling of a round at ts.
func sent(ts int64, n int) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPSent, Target: "192.168.1.1",
		Value: float64(n), Unit: telemetry.UnitCount, MonitorID: "t_icmp", ConfigSerial: 1,
	}
}

// metaWithCount is meta() plus the configured packet count an incoming round's
// sent figure is measured against.
func (h *harness) metaWithCount(det DetectionSettings, count int) map[string]TargetMeta {
	m := h.meta(det)
	tm := m["t_icmp"]
	tm.PingCount = count
	m["t_icmp"] = tm
	return m
}

func TestRoundComplete(t *testing.T) {
	cases := []struct {
		name       string
		kind       string
		sent, want int
		complete   bool
	}{
		{"a full icmp round", "icmp", 5, 5, true},
		{"a truncated icmp round", "icmp", 2, 5, false},
		{"a truncated gateway round", "gateway", 1, 5, false},
		// More than configured cannot happen, but a future packet-count edit
		// racing a round in flight must not be read as truncation.
		{"more than configured", "icmp", 6, 5, true},
		// No count from the agent fails CLOSED. Every agent that can connect
		// emits it (the schema version was bumped for this contract), so the only
		// way to arrive without one is a producer regression — and waving that
		// through would silently restore the behaviour this check removes.
		{"agent reported no count", "icmp", 0, 5, false},
		// An unreadable configured count fails OPEN: the SERVER could not do the
		// comparison, which makes the check inapplicable rather than failed.
		// Silencing a monitor whose agent is reporting fine would punish the
		// wrong side.
		{"no configured count", "icmp", 2, 0, true},
		{"no counts at all", "icmp", 0, 0, true},
		// Only ICMP has an incomplete state; the others emit a boolean ok.
		{"http is never incomplete", "http", 0, 0, true},
		{"dns is never incomplete", "dns", 1, 5, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RoundComplete(c.kind, c.sent, c.want); got != c.complete {
				t.Errorf("RoundComplete(%q, %d, %d) = %v, want %v", c.kind, c.sent, c.want, got, c.complete)
			}
		})
	}
}

// Both the detector and the status chip measure a round's reported sent count
// against this, so they have to derive it the same way. They did not once: one
// defaulted a malformed blob to five while the other returned zero, which put a
// green chip beside a fault state that had deliberately abstained.
func TestConfiguredPingCount(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		params string
		want   int
	}{
		{"empty params take the protocol default", "icmp", "", 5},
		{"empty object takes the default too", "icmp", "{}", 5},
		{"an explicit count wins", "icmp", `{"packet_count":3}`, 3},
		{"gateway reads the same field", "gateway", `{"packet_count":7}`, 7},
		// Zero disables the check (RoundComplete's fail-open branch): the server
		// could not read its own bookkeeping, which makes the comparison
		// inapplicable rather than failed.
		{"malformed params disable the check", "icmp", `{"packet_count":`, 0},
		{"not an object at all", "icmp", `"nope"`, 0},
		// Other kinds have no packet count to compare against.
		{"http has none", "http", `{"packet_count":5}`, 0},
		{"dns has none", "dns", "{}", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ConfiguredPingCount(c.kind, c.params); got != c.want {
				t.Errorf("ConfiguredPingCount(%q, %q) = %d, want %d", c.kind, c.params, got, c.want)
			}
		})
	}
}

// A truncated round reaching 100% loss must not count toward a confirmation.
// The agent could not send the packets; that says nothing about the target.
func TestIncompleteFailingRoundConfirmsNothing(t *testing.T) {
	h := newHarness(t)
	det := DetectionSettings{FailRounds: 2, RecoverRounds: 1, ICMPLossPct: 100}

	ms := []telemetry.Metric{
		loss(1000, 100), sent(1000, 1),
		loss(1010, 100), sent(1010, 2),
		loss(1020, 100), sent(1020, 1),
	}
	rounds := BuildRounds(ms, h.metaWithCount(det, 5))
	if len(rounds) != 0 {
		t.Fatalf("built %d rounds from truncated cycles, want none to reach a verdict", len(rounds))
	}
	h.evaluateRounds(rounds)
	if n := h.countSignals(); n != 0 {
		t.Fatalf("truncated rounds confirmed %d fault(s)", n)
	}
}

// The mirror image, and the more dangerous one: a truncated round that happened
// to get its one echo back reports 0% loss. Believing it would clear a real
// outage the moment the agent got busy.
func TestIncompleteSucceedingRoundClearsNothing(t *testing.T) {
	h := newHarness(t)
	det := DetectionSettings{FailRounds: 2, RecoverRounds: 1, ICMPLossPct: 100}

	// Two complete failing rounds confirm a fault.
	h.evaluate(det, loss(1000, 100), sent(1000, 5), loss(1010, 100), sent(1010, 5))
	if n := len(h.firingSignals()); n != 1 {
		t.Fatalf("firing signals = %d, want the fault confirmed", n)
	}

	// A truncated healthy-looking round must not recover it.
	rounds := BuildRounds([]telemetry.Metric{loss(1020, 0), sent(1020, 1)}, h.metaWithCount(det, 5))
	if len(rounds) != 0 {
		t.Fatalf("a truncated round reached a verdict: %+v", rounds)
	}
	h.evaluateRounds(rounds)
	if n := len(h.firingSignals()); n != 1 {
		t.Fatalf("firing signals = %d, want the fault still standing after a truncated round", n)
	}

	// A COMPLETE healthy round still recovers it — the gate withholds judgment,
	// it does not freeze the monitor.
	h.evaluate(det, loss(1030, 0), sent(1030, 5))
	if n := len(h.firingSignals()); n != 0 {
		t.Fatalf("firing signals = %d, want the fault cleared by a complete round", n)
	}
}

// A complete round is unaffected by the gate. A round with NO sent sibling is
// not: after the schema bump every connected agent emits one, so its absence is
// a producer regression, and waving it through would silently restore the
// behaviour the check removes.
func TestCompleteRoundsStillReachAVerdict(t *testing.T) {
	h := newHarness(t)
	det := DetectionSettings{FailRounds: 2, RecoverRounds: 1, ICMPLossPct: 100}

	withSent := BuildRounds([]telemetry.Metric{loss(1000, 100), sent(1000, 5)}, h.metaWithCount(det, 5))
	if len(withSent) != 1 || withSent[0].Class != RoundFail {
		t.Fatalf("complete failing round = %+v, want one RoundFail", withSent)
	}
	withoutSent := BuildRounds([]telemetry.Metric{loss(1010, 100)}, h.metaWithCount(det, 5))
	if len(withoutSent) != 0 {
		t.Fatalf("a round with no sent sibling = %+v, want no verdict", withoutSent)
	}
	// The server's own inability to read the configured count is the other way
	// round: the check cannot run, so the round is judged as it always was.
	noWant := BuildRounds([]telemetry.Metric{loss(1020, 100)}, h.metaWithCount(det, 0))
	if len(noWant) != 1 || noWant[0].Class != RoundFail {
		t.Fatalf("round with an unreadable configured count = %+v, want one RoundFail", noWant)
	}
}

// Truncation only affects the round it is reported on. A complete round in the
// same batch still reaches its verdict, so one busy moment cannot blind a whole
// upload.
func TestTruncationIsPerRound(t *testing.T) {
	h := newHarness(t)
	det := DetectionSettings{FailRounds: 2, RecoverRounds: 1, ICMPLossPct: 100}

	rounds := BuildRounds([]telemetry.Metric{
		loss(1000, 100), sent(1000, 2), // truncated → no verdict
		loss(1010, 100), sent(1010, 5), // complete → counts
	}, h.metaWithCount(det, 5))

	if len(rounds) != 1 {
		t.Fatalf("built %d rounds, want only the complete one", len(rounds))
	}
	if rounds[0].TS != 1010 || rounds[0].Class != RoundFail {
		t.Fatalf("surviving round = %+v, want the complete failing round at 1010", rounds[0])
	}
}

// An incomplete round produces no probe.round.ok sample either, so it stays out
// of the availability denominator rather than counting as a failed round in the
// uptime ratio.
func TestIncompleteRoundIsAbsentFromAvailability(t *testing.T) {
	h := newHarness(t)
	det := DetectionSettings{FailRounds: 2, RecoverRounds: 1, ICMPLossPct: 100}

	rounds := BuildRounds([]telemetry.Metric{loss(1000, 100), sent(1000, 1)}, h.metaWithCount(det, 5))
	if got := AvailabilitySamples(rounds); len(got) != 0 {
		t.Fatalf("availability samples = %+v, want none from a truncated round", got)
	}
}

// evaluateRounds is evaluate() for a round slice already built, so a test can
// assert on the rounds AND drive the engine with exactly those.
func (h *harness) evaluateRounds(rounds []Round) {
	h.t.Helper()
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	if _, err := h.svc.EvaluateAgentTx(h.ctx, store.AdaptTx(tx, store.Standalone()), "agent_a", "site_default", rounds); err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("evaluate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
}
