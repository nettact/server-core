package fault

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/baseline"
)

// The degradation detectors' contract: they judge a round against the target's
// own history, they refuse to judge anything an outage touched, they refuse to
// narrate the past, and what they record is recorded at a severity the default
// notification policy will not send. Each test below pins one of those.

// degGap is the round-gap tolerance the tests pin explicitly, so a change to the
// ICMP default schedule cannot silently turn these into gap-abandonment tests.
const degGap = 5 * time.Minute

// smartDet is the default sensitivity with smart detection on.
func smartDet() DetectionSettings { return DefaultDetection() }

// degMeta is the icmp target's metadata with an explicit round-gap tolerance.
func degMeta(det DetectionSettings) map[string]TargetMeta {
	return map[string]TargetMeta{
		"t_icmp": {ID: "t_icmp", Kind: "icmp", GroupID: "mg", Name: "Router", Addr: "192.168.1.1",
			Enabled: true, ConfigSerial: 1, Det: det.Normalize(), MaxRoundGap: degGap},
	}
}

func rtt(ts int64, ms float64) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPRTTms, Target: "192.168.1.1",
		Value: ms, Unit: telemetry.UnitMs, MonitorID: "t_icmp", ConfigSerial: 1,
	}
}

// stdBand is a target that usually sits around 40ms. At standard sensitivity its
// degradation threshold is max(45*1.5, 40+15) = 67.5ms.
var stdBand = baseline.Band{P50: 40, P95: 45, Days: 7, Samples: 5000}

// evalDeg runs one ingest-equivalent pass with the given band attached to every
// judged metric, mirroring what ingest.attachBaselines does.
func (h *harness) evalDeg(det DetectionSettings, band baseline.Band, ms ...telemetry.Metric) *Outcome {
	h.t.Helper()
	rounds := BuildRounds(ms, degMeta(det))
	for i := range rounds {
		kinds := DegradationMetricKinds(rounds[i].Det, rounds[i].Kind)
		if len(kinds) == 0 || band.Days == 0 {
			continue
		}
		rounds[i].Baselines = map[string]baseline.Band{}
		for _, k := range kinds {
			rounds[i].Baselines[k] = band
		}
	}
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	out, err := h.svc.EvaluateAgentTx(h.ctx, tx, "agent_a", "site_default", rounds)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("evaluate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
	return out
}

// degRounds builds n consecutive healthy ICMP rounds ending ~now, each carrying
// the given RTT. Timestamps are anchored to the present because the degradation
// detectors refuse to judge anything older than one round gap.
func degRounds(n int, rttMs float64) []telemetry.Metric {
	return degRoundsLoss(n, rttMs, 0)
}

func degRoundsLoss(n int, rttMs, lossPct float64) []telemetry.Metric {
	return degRoundsFrom(time.Now().Unix()-int64(2*n), n, rttMs, lossPct)
}

// degRoundsFrom builds n rounds at two-second spacing starting at base. Tests
// that evaluate more than one batch must sequence them through this, because a
// second batch reusing the first's timestamps is a REPLAY — every round would sit
// at or below the detector's watermark and change nothing.
func degRoundsFrom(base int64, n int, rttMs, lossPct float64) []telemetry.Metric {
	var ms []telemetry.Metric
	for i := range n {
		ts := base + int64(2*i)
		ms = append(ms, loss(ts, lossPct), rtt(ts, rttMs))
	}
	return ms
}

func (h *harness) degSignal(t *testing.T, key string) *Signal {
	t.Helper()
	for _, s := range h.firingSignals() {
		if s.DetectorKey == key {
			return &s
		}
	}
	return nil
}

func TestDegradationConfirmsAfterThresholdRounds(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)

	// One round short of the threshold: nothing yet. A trend is not a trend until
	// it has been one for a while.
	h.evalDeg(det, stdBand, degRounds(need-1, 300)...)
	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatalf("confirmed after %d rounds, threshold is %d", need-1, need)
	}

	h = newHarness(t)
	h.evalDeg(det, stdBand, degRounds(need, 300)...)
	sig := h.degSignal(t, DetectorLatencyDegradation)
	if sig == nil {
		t.Fatal("no latency degradation signal after the threshold was reached")
	}
	if sig.Severity != SeverityInfo {
		t.Fatalf("severity = %q, want %q — info is what keeps this out of the default policy", sig.Severity, SeverityInfo)
	}
	if sig.Comparator != ComparatorGteBaseline {
		t.Fatalf("comparator = %q, want %q", sig.Comparator, ComparatorGteBaseline)
	}
	if sig.MetricKind != string(telemetry.ICMPRTTms) {
		t.Fatalf("metric kind = %q", sig.MetricKind)
	}
	// The band is frozen, not recomputed: by the time anybody reads this the
	// rolling baseline has begun absorbing the degradation it explains.
	if sig.BaselineP50 != stdBand.P50 || sig.BaselineP95 != stdBand.P95 {
		t.Fatalf("frozen band = (%v, %v), want (%v, %v)",
			sig.BaselineP50, sig.BaselineP95, stdBand.P50, stdBand.P95)
	}
	if want := DegradationThreshold(stdBand, det.SmartSensitivity, string(telemetry.ICMPRTTms)); sig.Threshold != want {
		t.Fatalf("threshold = %v, want %v", sig.Threshold, want)
	}
	if sig.Value != 300 {
		t.Fatalf("value = %v, want the confirming round's 300", sig.Value)
	}
	if len(sig.Rounds) != need {
		t.Fatalf("froze %d rounds of evidence, want all %d of the streak", len(sig.Rounds), need)
	}
}

func TestDegradationIncidentStaysInfo(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	h.evalDeg(det, stdBand, degRounds(DegradationFailRounds(det.SmartSensitivity), 300)...)
	sig := h.degSignal(t, DetectorLatencyDegradation)
	if sig == nil {
		t.Fatal("no degradation signal")
	}
	var severity string
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT severity FROM incidents WHERE id=?`, sig.IncidentID).Scan(&severity); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	// An incident made only of info members must stay info. A warn floor here would
	// silently promote every degradation past the default policy's min_severity and
	// send exactly the notification this design exists to avoid.
	if severity != SeverityInfo {
		t.Fatalf("incident severity = %q, want %q", severity, SeverityInfo)
	}
}

func TestDegradationRecoversAfterInBandRounds(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	base := time.Now().Unix() - int64(2*(need+DegradationRecoverRounds))

	h.evalDeg(det, stdBand, degRoundsFrom(base, need, 300, 0)...)
	if h.degSignal(t, DetectorLatencyDegradation) == nil {
		t.Fatal("setup: no degradation signal")
	}
	h.evalDeg(det, stdBand, degRoundsFrom(base+int64(2*need), DegradationRecoverRounds, 41, 0)...)
	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatal("still firing after enough in-band rounds to recover")
	}
}

func TestDegradationSilentWhileAvailabilityFailing(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	// Total loss with a wild RTT alongside it: the target is down, and a target
	// that is down must not ALSO be reported as slow.
	need := DegradationFailRounds(det.SmartSensitivity)
	h.evalDeg(det, stdBand, degRoundsLoss(need+det.FailRounds, 900, 100)...)

	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatal("opened a degradation signal during an availability outage")
	}
	if sig := h.degSignal(t, DetectorAvailability); sig == nil {
		t.Fatal("availability did not confirm — the fixture is wrong, not the detector")
	}
}

func TestDegradationDoesNotFireOnRecoveryAfterOutage(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	// Outage, then a long slow patch. The slow rounds while availability is still
	// firing must not accumulate, so no degradation can confirm the instant the
	// target starts answering again.
	h.evalDeg(det, stdBand, degRoundsLoss(det.FailRounds+need, 900, 100)...)
	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatal("degradation confirmed from rounds observed during the outage")
	}
}

func TestDegradationIgnoresBackfilledRounds(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	// A WAL backfill after a reconnect: plenty of degraded rounds, all older than
	// one round gap. Availability judges backfill on purpose; a low-severity
	// observation about how things are going must not narrate the past.
	base := time.Now().Add(-2 * degGap).Unix()
	var ms []telemetry.Metric
	for i := 0; i < need+3; i++ {
		ts := base + int64(2*i)
		ms = append(ms, loss(ts, 0), rtt(ts, 300))
	}
	h.evalDeg(det, stdBand, ms...)
	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatal("confirmed a degradation from backfilled rounds")
	}
	// The watermark still advanced, so a replay of the same packet is a no-op.
	var last int64
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT last_round_ts FROM detector_state WHERE target_id='t_icmp' AND agent_id='agent_a' AND detector_key=?`,
		DetectorLatencyDegradation).Scan(&last); err != nil {
		t.Fatalf("read detector state: %v", err)
	}
	if want := base + int64(2*(need+2)); last != want {
		t.Fatalf("watermark = %d, want %d — a refused round must still be marked folded", last, want)
	}
}

func TestDegradationSilentWhileLearning(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	// baseline.Band{} (Days 0) means evalDeg attaches nothing, which is what a
	// target in its first days looks like.
	h.evalDeg(det, baseline.Band{}, degRounds(DegradationFailRounds(det.SmartSensitivity)*2, 5000)...)
	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatal("judged a target that has no baseline yet")
	}
}

func TestSmartLossYieldsToConfiguredThreshold(t *testing.T) {
	det := smartDet()
	if got := DegradationMetricKinds(det, "icmp"); len(got) != 2 {
		t.Fatalf("default icmp target judges %v, want both latency and loss", got)
	}
	// An operator who moved the loss threshold has stated their tolerance in the
	// plainest way the product offers. Arguing with them about 15% when they said
	// 30% is not a feature.
	det.ICMPLossPct = 30
	kinds := DegradationMetricKinds(det, "icmp")
	if len(kinds) != 1 || kinds[0] != string(telemetry.ICMPRTTms) {
		t.Fatalf("with a custom loss threshold the judged kinds are %v, want latency only", kinds)
	}
}

func TestSmartDisabledJudgesNothing(t *testing.T) {
	det := smartDet()
	det.SmartEnabled = false
	if got := DegradationMetricKinds(det, "icmp"); len(got) != 0 {
		t.Fatalf("smart off still judges %v", got)
	}
	h := newHarness(t)
	h.evalDeg(det, stdBand, degRounds(20, 900)...)
	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatal("confirmed a degradation with smart detection switched off")
	}
}

func TestDegradationOpensItsOwnIncident(t *testing.T) {
	h := newHarness(t)
	// A merging group: availability members share one incident. A degradation must
	// still not join it — "slow" under a title that says "unreachable" is a claim
	// nobody made.
	h.exec(`UPDATE monitor_groups SET merge_enabled=1 WHERE id='mg'`)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	base := time.Now().Unix() - int64(2*(need+det.FailRounds))

	h.evalDeg(det, stdBand, degRoundsFrom(base, need, 300, 0)...)
	deg := h.degSignal(t, DetectorLatencyDegradation)
	if deg == nil {
		t.Fatal("no degradation signal")
	}
	h.evalDeg(det, stdBand, degRoundsFrom(base+int64(2*need), det.FailRounds, 900, 100)...)
	avail := h.degSignal(t, DetectorAvailability)
	if avail == nil {
		t.Fatal("no availability signal")
	}
	if avail.IncidentID == deg.IncidentID {
		t.Fatal("availability and degradation landed in the same incident")
	}
	var openKey string
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT open_key FROM incidents WHERE id=?`, deg.IncidentID).Scan(&openKey); err != nil {
		t.Fatalf("read open key: %v", err)
	}
	if openKey != "deg:grp:mg" {
		t.Fatalf("degradation open_key = %q, want the deg-prefixed group key", openKey)
	}
}

func TestDegradationThresholdShape(t *testing.T) {
	rttKind := string(telemetry.ICMPRTTms)
	lossKind := string(telemetry.ICMPLoss)
	cases := []struct {
		name        string
		band        baseline.Band
		sensitivity string
		metric      string
		want        float64
	}{
		// The p95 arm dominates on a jittery target: its ordinary spread is absorbed
		// rather than reported.
		{"jittery target, p95 arm", baseline.Band{P50: 40, P95: 200}, SmartStandard, rttKind, 300},
		// The p50 arm dominates on a metronomic one, and this is the case the whole
		// floor exists for: without it a 1ms LAN target would report a degradation at
		// 2ms, which is true and useless.
		{"fast LAN target, floor arm", baseline.Band{P50: 1, P95: 2}, SmartStandard, rttKind, 16},
		{"fast LAN target, sensitive", baseline.Band{P50: 1, P95: 2}, SmartSensitive, rttKind, 9},
		{"fast LAN target, loose", baseline.Band{P50: 1, P95: 2}, SmartLoose, rttKind, 31},
		// A clean target's loss baseline is 0/0, so the effective threshold is exactly
		// the sensitivity floor. Deliberate, not an accident of the formula.
		{"clean loss baseline", baseline.Band{}, SmartStandard, lossKind, 10},
		{"clean loss baseline, sensitive", baseline.Band{}, SmartSensitive, lossKind, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DegradationThreshold(c.band, c.sensitivity, c.metric); got != c.want {
				t.Fatalf("threshold = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDegradationTitles(t *testing.T) {
	sig := Signal{DetectorKey: DetectorLatencyDegradation, TargetName: "Router", ProbeKind: "icmp"}
	if got := SignalTitleLang(sig, "zh"); got != "「Router」延迟明显高于平时" {
		t.Fatalf("zh latency title = %q", got)
	}
	if got := SignalTitleLang(sig, "en"); got != `"Router" is markedly slower than usual` {
		t.Fatalf("en latency title = %q", got)
	}
	sig.DetectorKey = DetectorLossDegradation
	if got := SignalTitleLang(sig, "zh"); got != "「Router」丢包明显高于平时" {
		t.Fatalf("zh loss title = %q", got)
	}
}

func TestBuildRoundsCarriesQualityMetricsWithoutDisturbingVerdicts(t *testing.T) {
	det := smartDet()
	ts := time.Now().Unix()
	rounds := BuildRounds([]telemetry.Metric{loss(ts, 0), rtt(ts, 42)}, degMeta(det))
	if len(rounds) != 1 {
		t.Fatalf("built %d rounds, want 1", len(rounds))
	}
	r := rounds[0]
	if r.Class != RoundSuccess {
		t.Fatalf("class = %v, want success — a quality metric must not change the verdict", r.Class)
	}
	if r.Latencies[string(telemetry.ICMPRTTms)] != 42 {
		t.Fatalf("rtt not carried: %v", r.Latencies)
	}
	// ICMP loss is both the availability verdict and a judged quality metric; it has
	// to appear in both places.
	if r.Latencies[string(telemetry.ICMPLoss)] != 0 {
		t.Fatalf("loss not carried: %v", r.Latencies)
	}

	// A cycle carrying ONLY a quality metric is still not a round: without the
	// primary metric there is no verdict to attach anything to.
	if got := BuildRounds([]telemetry.Metric{rtt(ts, 42)}, degMeta(det)); len(got) != 0 {
		t.Fatalf("built %d rounds from a quality-only cycle, want 0", len(got))
	}
}

func TestDegradationRejectsRoundsFromTheFuture(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	// An Agent whose clock runs a day ahead. Nothing may be judged from these —
	// and, more importantly, the watermark must not follow them: parked in the
	// future it would reject every honest round until wall time caught up,
	// silently disabling degradation detection on that Agent.
	base := time.Now().Add(24 * time.Hour).Unix()
	h.evalDeg(det, stdBand, degRoundsFrom(base, need+3, 300, 0)...)

	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatal("confirmed a degradation from rounds stamped in the future")
	}
	var last int64
	err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT last_round_ts FROM detector_state WHERE target_id='t_icmp' AND agent_id='agent_a' AND detector_key=?`,
		DetectorLatencyDegradation).Scan(&last)
	if err == nil && last >= base {
		t.Fatalf("watermark = %d, want it left behind the future rounds at %d", last, base)
	}

	// The real point: honest rounds arriving now must still be judged.
	h.evalDeg(det, stdBand, degRounds(need, 300)...)
	if sig := h.degSignal(t, DetectorLatencyDegradation); sig == nil {
		t.Fatal("honest rounds were rejected; the watermark followed the bad clock")
	}
}

func TestConfirmedOutageSupersedesAFiringDegradation(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	base := time.Now().Unix() - int64(2*(need+det.FailRounds))

	h.evalDeg(det, stdBand, degRoundsFrom(base, need, 300, 0)...)
	deg := h.degSignal(t, DetectorLatencyDegradation)
	if deg == nil {
		t.Fatal("setup: no degradation signal")
	}
	// Now the target stops answering entirely. "Markedly slower than usual" is not
	// a claim worth keeping open about something that has stopped answering, and
	// leaving both firing tells the operator two contradictory things at once.
	h.evalDeg(det, stdBand, degRoundsFrom(base+int64(2*need), det.FailRounds, 900, 100)...)

	if h.degSignal(t, DetectorAvailability) == nil {
		t.Fatal("availability did not confirm — the fixture is wrong, not the detector")
	}
	if sig := h.degSignal(t, DetectorLatencyDegradation); sig != nil {
		t.Fatal("the degradation is still firing alongside a confirmed outage")
	}
	var state, reason string
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT state, resolve_reason FROM fault_signals WHERE id=?`, deg.ID).Scan(&state, &reason); err != nil {
		t.Fatalf("read signal: %v", err)
	}
	if state != "resolved" || reason != ReasonSuperseded {
		t.Fatalf("degradation ended as (%q, %q), want (resolved, %q)", state, reason, ReasonSuperseded)
	}
	// Superseded is not a recovery: nothing recovered, so no recovery notice.
	if IsRecovery(reason) {
		t.Fatal("superseded counts as a recovery")
	}
}

func TestWorstSeverityKeepsAnAllInfoSet(t *testing.T) {
	if got := WorstSeverity([]string{SeverityInfo, SeverityInfo}); got != SeverityInfo {
		t.Fatalf("all-info set = %q, want info — a warn floor here promotes every quality degradation", got)
	}
	if got := WorstSeverity([]string{SeverityInfo, SeverityError}); got != SeverityError {
		t.Fatalf("mixed set = %q, want error", got)
	}
	// Unreadable data is announced rather than swallowed.
	if got := WorstSeverity(nil); got != SeverityWarn {
		t.Fatalf("empty set = %q, want warn", got)
	}
	if got := WorstSeverity([]string{"", "nonsense"}); got != SeverityWarn {
		t.Fatalf("unrecognized set = %q, want warn", got)
	}
}

func TestZeroBaselineIsStillSerialized(t *testing.T) {
	// A clean target's packet-loss baseline is legitimately p50=0, p95=0, and that
	// is the most common loss degradation there is. With omitempty the fields
	// vanish and an API consumer cannot tell "usually 0% loss" — the whole point of
	// the evidence — from "no baseline recorded".
	blob, err := json.Marshal(Signal{
		DetectorKey: DetectorLossDegradation, Comparator: ComparatorGteBaseline,
		Value: 18, Threshold: 10,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"baseline_p50", "baseline_p95"} {
		v, ok := got[k]
		if !ok {
			t.Fatalf("%s is absent from the JSON; a zero baseline reads as no baseline", k)
		}
		if v != float64(0) {
			t.Fatalf("%s = %v, want 0", k, v)
		}
	}
}
