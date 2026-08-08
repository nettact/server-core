package fault

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// The system-status detectors' contract, in one place: they judge READINGS, not
// batches; they hold state through the band between the threshold and its
// recovery floor; they convert a configured duration into rounds against the
// real cadence; and they never judge a machine on evidence they do not have.

// hostHarness extends the availability harness with a kind='host' anchor.
type hostHarness struct {
	*harness
	set HostSettings
}

func newHostHarness(t *testing.T) *hostHarness {
	t.Helper()
	h := newHarness(t)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	        VALUES('t_host','site_default','mg','host','Server','host','{}',1,1)`)
	return &hostHarness{harness: h, set: DefaultHostSettings()}
}

// metas returns the anchor's evaluation metadata at the given cadence and core
// count. cores 0 means the machine never reported one.
func (h *hostHarness) metas(intervalSeconds int, cores float64) []HostTargetMeta {
	return []HostTargetMeta{{
		ID: "t_host", GroupID: "mg", Name: "Server", ConfigSerial: 1,
		Set: h.set, IntervalSeconds: intervalSeconds, Cores: cores,
	}}
}

// evaluateHost runs one ingest-equivalent pass at the 30s default cadence.
func (h *hostHarness) evaluateHost(ms ...telemetry.Metric) *Outcome {
	h.t.Helper()
	return h.evaluateHostAt(30, 0, ms...)
}

func (h *hostHarness) evaluateHostAt(intervalSeconds int, cores float64, ms ...telemetry.Metric) *Outcome {
	h.t.Helper()
	rounds, mounts := BuildHostRounds(ms, h.metas(intervalSeconds, cores))
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	out, err := h.svc.EvaluateHostTx(h.ctx, tx, "agent_a", "site_default", rounds, mounts)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("evaluate host: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
	return out
}

// hostState reads one detector's streak counters and watermark.
func (h *hostHarness) hostState(detectorKey string) (failRounds, okRounds int, lastRoundTS int64, exists bool) {
	h.t.Helper()
	err := h.db.QueryRowContext(h.ctx,
		`SELECT fail_rounds, ok_rounds, last_round_ts FROM detector_state
		 WHERE target_id='t_host' AND agent_id='agent_a' AND detector_key=?`, detectorKey).
		Scan(&failRounds, &okRounds, &lastRoundTS)
	if err != nil {
		return 0, 0, 0, false
	}
	return failRounds, okRounds, lastRoundTS, true
}

func (h *hostHarness) hostSignals() []Signal {
	h.t.Helper()
	var out []Signal
	for _, s := range h.firingSignals() {
		if IsHostDetector(s.DetectorKey) {
			out = append(out, s)
		}
	}
	return out
}

// cpu / mem / load / disk / netRx build one reading's metrics.
func cpu(ts int64, pct float64) telemetry.Metric {
	return hostMetric(ts, telemetry.HostCPUPct, "host", pct, telemetry.UnitPct)
}

func memPct(ts int64, pct float64) telemetry.Metric {
	return hostMetric(ts, telemetry.HostMemPct, "host", pct, telemetry.UnitPct)
}

func load1(ts int64, v float64) telemetry.Metric {
	return hostMetric(ts, telemetry.HostLoad1, "host", v, telemetry.UnitLoad)
}

func coresMetric(ts int64, n float64) telemetry.Metric {
	return hostMetric(ts, telemetry.HostCPUCores, "host", n, telemetry.UnitCount)
}

func diskPct(ts int64, mount string, pct float64) telemetry.Metric {
	return hostMetric(ts, telemetry.HostDiskPct, mount, pct, telemetry.UnitPct)
}

func netRx(ts int64, bytesPerSec float64) telemetry.Metric {
	return hostMetric(ts, telemetry.HostNetRxBps, "host", bytesPerSec, telemetry.UnitBps)
}

func hostMetric(ts int64, kind telemetry.MetricKind, target string, v float64, unit string) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: kind, Target: target,
		Layer: telemetry.LayerLocal, Value: v, Unit: unit,
	}
}

// TestHostConfirmsAfterConfiguredDuration is the promise the form makes: "above
// 90% for 5 minutes" means five minutes of readings, not five readings.
func TestHostConfirmsAfterConfiguredDuration(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false

	// 300s / 30s cadence = ten readings. Nine must not confirm.
	for i := 0; i < 9; i++ {
		h.evaluateHost(cpu(1000+int64(i)*30, 95))
	}
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("confirmed after 9 of 10 readings (%d signals)", n)
	}
	if fail, _, _, _ := h.hostState(DetectorHostCPU); fail != 9 {
		t.Fatalf("fail_rounds = %d, want 9", fail)
	}

	h.evaluateHost(cpu(1000+9*30, 95))
	sigs := h.hostSignals()
	if len(sigs) != 1 {
		t.Fatalf("want exactly one signal after the tenth reading, got %d", len(sigs))
	}
	s := sigs[0]
	if s.DetectorKey != DetectorHostCPU {
		t.Errorf("detector = %q, want %q", s.DetectorKey, DetectorHostCPU)
	}
	if s.Severity != SeverityWarn {
		t.Errorf("severity = %q, want warn", s.Severity)
	}
	if s.MetricKind != string(telemetry.HostCPUPct) || s.Comparator != hostComparator {
		t.Errorf("evidence = %s %s, want %s gte", s.MetricKind, s.Comparator, telemetry.HostCPUPct)
	}
	if s.Value != 95 || s.Threshold != 90 {
		t.Errorf("value/threshold = %v/%v, want 95/90", s.Value, s.Threshold)
	}
	if s.FailThreshold != 10 {
		t.Errorf("fail_threshold = %d, want 10 readings", s.FailThreshold)
	}
	if s.Layer != hostLayer {
		t.Errorf("layer = %q, want %q", s.Layer, hostLayer)
	}
	// Every failing reading is frozen, not just the confirming one.
	if len(s.Rounds) != 10 {
		t.Errorf("froze %d rounds, want all 10", len(s.Rounds))
	}
}

// TestHostDurationConvertsAgainstRealCadence pins the reason durations are stored
// in seconds: the same five minutes is five readings at a 60s cadence, not ten.
func TestHostDurationConvertsAgainstRealCadence(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false

	for i := 0; i < 4; i++ {
		h.evaluateHostAt(60, 0, cpu(1000+int64(i)*60, 95))
	}
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("confirmed after 4 of 5 readings at a 60s cadence")
	}
	h.evaluateHostAt(60, 0, cpu(1000+4*60, 95))
	sigs := h.hostSignals()
	if len(sigs) != 1 {
		t.Fatalf("want one signal after 5 readings at a 60s cadence, got %d", len(sigs))
	}
	if sigs[0].FailThreshold != 5 {
		t.Errorf("fail_threshold = %d, want 5", sigs[0].FailThreshold)
	}
}

// TestHostHoldZoneKeepsTheStreak is the hysteresis contract. A machine hovering
// just under its threshold has not recovered — it is still where the operator
// said to worry — so the streak survives, and once firing it neither resolves nor
// accumulates recovery credit.
func TestHostHoldZoneKeepsTheStreak(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false
	h.set.CPUDurationS = 90 // three readings at 30s

	ts := int64(1000)
	h.evaluateHost(cpu(ts, 95))
	ts += 30
	// 87 is below the 90 threshold but above the 85 recovery floor: hold.
	h.evaluateHost(cpu(ts, 87))
	fail, ok, mark, _ := h.hostState(DetectorHostCPU)
	if fail != 1 || ok != 0 {
		t.Fatalf("hold advanced a streak: fail=%d ok=%d, want 1/0", fail, ok)
	}
	if mark != ts {
		t.Fatalf("hold did not advance the watermark: %d, want %d", mark, ts)
	}

	ts += 30
	h.evaluateHost(cpu(ts, 95))
	ts += 30
	h.evaluateHost(cpu(ts, 95))
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("streak did not survive the hold: %d signals, want 1", n)
	}

	// A hold while firing keeps it firing and banks no recovery.
	ts += 30
	h.evaluateHost(cpu(ts, 88))
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("a hold resolved a firing signal")
	}
	if _, ok, _, _ := h.hostState(DetectorHostCPU); ok != 0 {
		t.Fatalf("a hold banked %d recovery rounds, want 0", ok)
	}

	// Only a reading below the floor recovers, and only after the full count.
	for i := 0; i < hostRecoverRounds; i++ {
		ts += 30
		h.evaluateHost(cpu(ts, 40))
	}
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("did not resolve after %d clear readings", hostRecoverRounds)
	}
}

// TestHostHoldsDoNotTripTheGapRule is the trap the hold zone sets. A watermark
// that stood still through a run of held readings would make the next one look
// like it followed a silence, and a live streak would be abandoned on evidence
// that arrived perfectly.
func TestHostHoldsDoNotTripTheGapRule(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false
	h.set.CPUDurationS = 60 // two readings

	ts := int64(1000)
	h.evaluateHost(cpu(ts, 95))
	// Ten minutes of held readings — far wider than the round-gap tolerance, but
	// contiguous, so the streak must survive them.
	for i := 0; i < 20; i++ {
		ts += 30
		h.evaluateHost(cpu(ts, 87))
	}
	ts += 30
	h.evaluateHost(cpu(ts, 95))
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("holds abandoned the streak: %d signals, want 1", n)
	}
}

// TestHostGapAbandonsTheStreak is the other half: a genuine silence does break
// consecutiveness, so a machine that was busy twice before its agent vanished for
// a day must not confirm on the reading that arrives when it returns.
func TestHostGapAbandonsTheStreak(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false
	h.set.CPUDurationS = 60 // two readings

	h.evaluateHost(cpu(1000, 95))
	h.evaluateHost(cpu(1000+86400, 95))
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("stitched a streak across a day-long gap")
	}
	if fail, _, _, _ := h.hostState(DetectorHostCPU); fail != 1 {
		t.Fatalf("fail_rounds = %d, want 1 (counting restarted)", fail)
	}
}

// TestHostReplayIsInert pins the watermark: the agent retries an unacked batch,
// and the same readings must not be folded twice.
func TestHostReplayIsInert(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false
	h.set.CPUDurationS = 90 // three readings

	batch := []telemetry.Metric{cpu(1000, 95), cpu(1030, 95)}
	h.evaluateHost(batch...)
	h.evaluateHost(batch...)
	h.evaluateHost(batch...)
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("a replayed batch confirmed a fault")
	}
	if fail, _, _, _ := h.hostState(DetectorHostCPU); fail != 2 {
		t.Fatalf("fail_rounds = %d after three deliveries of two readings, want 2", fail)
	}
}

// TestHostBackfillConfirmsLikeLiveRounds: a WAL backfill delivering a whole
// overload in one packet confirms exactly as if the readings had arrived one at a
// time. The alternative — judging the batch — would let a machine that was pegged
// for an hour pass as one bad reading.
func TestHostBackfillConfirmsLikeLiveRounds(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false

	var batch []telemetry.Metric
	for i := 0; i < 10; i++ {
		batch = append(batch, cpu(1000+int64(i)*30, 95))
	}
	h.evaluateHost(batch...)
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("backfilled overload produced %d signals, want 1", n)
	}
}

// TestHostRevisionResetsTheStreak: four minutes spent above 90% says nothing
// about a threshold of 95%, so an edit restarts counting rather than inheriting
// rounds measured against the value it replaced.
func TestHostRevisionResetsTheStreak(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false
	h.set.CPUDurationS = 90 // three readings

	h.evaluateHost(cpu(1000, 96))
	h.evaluateHost(cpu(1030, 96))
	if fail, _, _, _ := h.hostState(DetectorHostCPU); fail != 2 {
		t.Fatalf("fail_rounds = %d, want 2", fail)
	}

	h.set.Revision = 2
	h.set.CPUPct = 95
	h.evaluateHost(cpu(1060, 96))
	if fail, _, _, _ := h.hostState(DetectorHostCPU); fail != 1 {
		t.Fatalf("fail_rounds = %d after a revision bump, want 1", fail)
	}
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("confirmed on a streak counted under the old threshold")
	}
}

// TestHostLoadNeedsCoreCount: a per-core threshold without a core count is a
// guess about the denominator of an alert, so the family is not judged at all.
func TestHostLoadNeedsCoreCount(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.DiskEnabled = false, false, false

	for i := 0; i < 12; i++ {
		h.evaluateHost(load1(1000+int64(i)*30, 64))
	}
	if _, _, _, exists := h.hostState(DetectorHostLoad); exists {
		t.Fatalf("judged load with no core count")
	}
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("confirmed a load fault with no core count")
	}
}

// TestHostLoadJudgedPerCore: the same load average is a fault on a small machine
// and nothing at all on a large one, which is the whole reason the threshold is
// per core.
func TestHostLoadJudgedPerCore(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.DiskEnabled = false, false, false

	// 16.0 across 16 cores is 1.0 per core: below the 2.0 default.
	for i := 0; i < 12; i++ {
		h.evaluateHost(coresMetric(1000+int64(i)*30, 16), load1(1000+int64(i)*30, 16))
	}
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("16.0 across 16 cores confirmed a fault")
	}

	// The same figure on 4 cores is 4.0 per core.
	h2 := newHostHarness(t)
	h2.set.CPUEnabled, h2.set.MemEnabled, h2.set.DiskEnabled = false, false, false
	for i := 0; i < 10; i++ {
		h2.evaluateHost(coresMetric(1000+int64(i)*30, 4), load1(1000+int64(i)*30, 16))
	}
	sigs := h2.hostSignals()
	if len(sigs) != 1 {
		t.Fatalf("16.0 across 4 cores produced %d signals, want 1", len(sigs))
	}
	if sigs[0].MetricKind != string(telemetry.HostLoadPerCore) {
		t.Errorf("evidence kind = %q, want the derived per-core kind", sigs[0].MetricKind)
	}
	if sigs[0].Value != 4 {
		t.Errorf("evidence value = %v, want 4 (per core), not the raw load average", sigs[0].Value)
	}
	if sigs[0].ReasonDetail == "" {
		t.Errorf("per-core evidence lost the raw load and core count")
	}
}

// TestHostCoresFallBackToTheCachedReading: the count is reported like any other
// series, so a batch that happens not to carry one still gets judged from what
// the machine last said.
func TestHostCoresFallBackToTheCachedReading(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.DiskEnabled = false, false, false

	for i := 0; i < 10; i++ {
		h.evaluateHostAt(30, 4, load1(1000+int64(i)*30, 16))
	}
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("cached core count was not used: %d signals, want 1", n)
	}
}

// TestHostNetJudgedInMbps: the operator sets a link threshold in Mbps and the
// series is bytes per second, so the evidence must speak the unit they authored.
func TestHostNetJudgedInMbps(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false, false
	h.set.NetEnabled, h.set.NetRxMbps = true, 100

	// 25 MB/s = 200 Mbps.
	for i := 0; i < 10; i++ {
		h.evaluateHost(netRx(1000+int64(i)*30, 25e6))
	}
	sigs := h.hostSignals()
	if len(sigs) != 1 {
		t.Fatalf("want one rx signal, got %d", len(sigs))
	}
	if sigs[0].DetectorKey != HostDetectorKey(DetectorHostNet, "rx") {
		t.Errorf("detector = %q, want the rx subject", sigs[0].DetectorKey)
	}
	if sigs[0].Value != 200 {
		t.Errorf("evidence value = %v Mbps, want 200", sigs[0].Value)
	}
	if sigs[0].MetricKind != string(telemetry.HostNetRxMbps) {
		t.Errorf("evidence kind = %q, want the derived Mbps kind", sigs[0].MetricKind)
	}
}

// TestHostNetUnsetDirectionIsNotJudged: a null threshold is how one-directional
// alerting is expressed, and an unset direction must produce nothing at all —
// not a detector row, not a verdict.
func TestHostNetUnsetDirectionIsNotJudged(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false, false
	h.set.NetEnabled, h.set.NetRxMbps = true, 100 // tx deliberately unset

	for i := 0; i < 12; i++ {
		ts := 1000 + int64(i)*30
		h.evaluateHost(netRx(ts, 25e6),
			hostMetric(ts, telemetry.HostNetTxBps, "host", 99e6, telemetry.UnitBps))
	}
	if _, _, _, exists := h.hostState(HostDetectorKey(DetectorHostNet, "tx")); exists {
		t.Fatalf("judged the upload direction with no threshold set")
	}
}

// TestHostDiskJudgesEveryMountIndependently: a machine has many disks, and two
// of them can be full at once. This is what the subject folded into the detector
// key buys — without it the second mount would collide on the open-signal index.
func TestHostDiskJudgesEveryMountIndependently(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.LoadEnabled = false, false, false

	for i := 0; i < hostDiskFailRounds; i++ {
		ts := 1000 + int64(i)*30
		h.evaluateHost(diskPct(ts, "C:", 96), diskPct(ts, "D:", 97), diskPct(ts, "E:", 20))
	}
	sigs := h.hostSignals()
	if len(sigs) != 2 {
		t.Fatalf("want one signal per full mount (2), got %d", len(sigs))
	}
	seen := map[string]bool{}
	for _, s := range sigs {
		family, subject := SplitHostDetectorKey(s.DetectorKey)
		if family != DetectorHostDisk {
			t.Errorf("family = %q, want %q", family, DetectorHostDisk)
		}
		seen[subject] = true
		if s.TargetAddr != subject {
			t.Errorf("signal froze addr %q, want the mount %q", s.TargetAddr, subject)
		}
	}
	if !seen["C:"] || !seen["D:"] {
		t.Errorf("mounts covered = %v, want C: and D:", seen)
	}
	if seen["E:"] {
		t.Errorf("a mount at 20%% raised a fault")
	}
}

// TestHostVanishedMountResolvesWithoutClaimingRecovery: an ejected drive did not
// get emptier, so its fault closes as a termination, never as a recovery that
// would announce good news nobody caused.
func TestHostVanishedMountResolvesWithoutClaimingRecovery(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.LoadEnabled = false, false, false

	for i := 0; i < hostDiskFailRounds; i++ {
		ts := 1000 + int64(i)*30
		h.evaluateHost(diskPct(ts, "C:", 96), diskPct(ts, "E:", 99))
	}
	if n := len(h.hostSignals()); n != 2 {
		t.Fatalf("setup: want 2 firing mounts, got %d", n)
	}

	// Two consecutive disk snapshots that list the machine's disks without E: are
	// evidence it is gone (one alone is a failed read — see the miss-count test).
	h.evaluateHost(diskPct(2000, "C:", 96))
	h.evaluateHost(diskPct(2030, "C:", 96))
	sigs := h.hostSignals()
	if len(sigs) != 1 || sigs[0].TargetAddr != "C:" {
		t.Fatalf("want only C: still firing, got %d signals", len(sigs))
	}
	var reason string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT resolve_reason FROM fault_signals WHERE target_addr='E:'`).Scan(&reason); err != nil {
		t.Fatalf("read E: resolve reason: %v", err)
	}
	if reason != ReasonSubjectGone {
		t.Errorf("resolve reason = %q, want %q", reason, ReasonSubjectGone)
	}
	if IsRecovery(reason) {
		t.Errorf("a removed disk was announced as a recovery")
	}
	if _, _, _, exists := h.hostState(HostDetectorKey(DetectorHostDisk, "E:")); exists {
		t.Errorf("state row for a removed mount survived")
	}
}

// TestHostSilenceDoesNotResolveDiskFaults is the other side of the same rule. An
// Agent that stops reporting disks — offline, or its permission revoked — is
// saying nothing, and reading silence as "every disk was removed" would close
// real faults on no evidence.
func TestHostSilenceDoesNotResolveDiskFaults(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled = false, false

	for i := 0; i < hostDiskFailRounds; i++ {
		h.evaluateHost(diskPct(1000+int64(i)*30, "C:", 96))
	}
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("setup: want 1 firing mount, got %d", n)
	}
	// A batch with CPU but no disk readings at all.
	h.evaluateHost(cpu(2000, 10))
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("silence resolved a disk fault: %d signals, want 1", n)
	}
}

// TestHostFluctuationsPerFamilyShareATimestamp is why the detector is part of the
// fluctuation natural key: one Collect stamps CPU and memory with one instant, so
// two families' dips routinely start at the same second on the same anchor.
func TestHostFluctuationsPerFamilyShareATimestamp(t *testing.T) {
	h := newHostHarness(t)
	h.set.LoadEnabled, h.set.DiskEnabled = false, false

	h.evaluateHost(cpu(1000, 95), memPct(1000, 95))
	h.evaluateHost(cpu(1030, 95), memPct(1030, 95))
	h.evaluateHost(cpu(1060, 10), memPct(1060, 10))

	page, err := h.svc.ListFluctuations(h.ctx, FluctuationFilter{SiteID: "site_default"})
	if err != nil {
		t.Fatalf("list fluctuations: %v", err)
	}
	if page.Total != 2 {
		t.Fatalf("recorded %d fluctuations, want one per family", page.Total)
	}
	keys := map[string]bool{}
	for _, f := range page.Items {
		keys[f.DetectorKey] = true
		if f.FailRounds != 2 {
			t.Errorf("fluctuation fail_rounds = %d, want 2", f.FailRounds)
		}
	}
	if !keys[DetectorHostCPU] || !keys[DetectorHostMem] {
		t.Errorf("detector keys = %v, want both host_cpu and host_mem", keys)
	}
}

// TestHostFaultsAreNotAttributed: the attribution rules reason about a network
// path, and a machine's own resources have none. Left in, a CPU fault on an agent
// whose gateway is flaky would be confidently blamed on the router.
func TestHostFaultsAreNotAttributed(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false

	for i := 0; i < 10; i++ {
		h.evaluateHost(cpu(1000+int64(i)*30, 95))
	}
	sigs := h.hostSignals()
	if len(sigs) != 1 {
		t.Fatalf("setup: want 1 signal, got %d", len(sigs))
	}
	var attribution string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT COALESCE(attribution,'') FROM incidents WHERE id=?`, sigs[0].IncidentID).Scan(&attribution); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	if attribution != "" {
		t.Errorf("attribution = %q, want empty for a system-status incident", attribution)
	}
}

// TestHostIncidentsDoNotMergeIntoAvailability: even inside a merging group, "the
// disk is nearly full" must not sit under a title that says the group is
// unreachable — and, being annotated local, it would also hijack that incident's
// suspected cause.
func TestHostIncidentsDoNotMergeIntoAvailability(t *testing.T) {
	h := newHostHarness(t)
	h.exec(`UPDATE monitor_groups SET merge_enabled=1 WHERE id='mg'`)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false

	det := DefaultDetection()
	for i := 0; i < det.FailRounds; i++ {
		h.evaluate(det, loss(1000+int64(i)*10, 100))
	}
	for i := 0; i < 10; i++ {
		h.evaluateHost(cpu(1000+int64(i)*30, 95))
	}
	if n := h.countOpenIncidents(); n != 2 {
		t.Fatalf("open incidents = %d, want 2 (availability and system status kept apart)", n)
	}
	var title, layer string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT title, suspected_layer FROM incidents WHERE open_key LIKE 'hostm:%'`).Scan(&title, &layer); err != nil {
		t.Fatalf("read host incident: %v", err)
	}
	if title == "Default" {
		t.Errorf("host incident took the bare group title, indistinguishable from the availability one")
	}
	if layer != hostLayer {
		t.Errorf("suspected layer = %q, want %q", layer, hostLayer)
	}
}

// TestHostSignalTitles pins that every family says what was measured, in both
// languages, and that a disk names its mount.
func TestHostSignalTitles(t *testing.T) {
	for _, tc := range []struct {
		key            string
		name, agent    string
		wantZh, wantEn string
	}{
		{DetectorHostCPU, "Server", "node-1", "「Server」CPU 使用率持续过高", "CPU usage on \"Server\" is persistently high"},
		{DetectorHostMem, "", "node-1", "「node-1」内存使用率持续过高", "Memory usage on \"node-1\" is persistently high"},
		{DetectorHostLoad, "", "", "系统负载持续过高", "System load is persistently high"},
		{HostDetectorKey(DetectorHostNet, "tx"), "Server", "", "「Server」上传速率持续超过阈值",
			"Upload rate on \"Server\" is persistently above the threshold"},
		{HostDetectorKey(DetectorHostDisk, "C:"), "Server", "", "「Server」磁盘 C: 空间不足",
			"Disk C: on \"Server\" is almost full"},
	} {
		s := Signal{DetectorKey: tc.key, TargetName: tc.name, AgentName: tc.agent, ProbeKind: "host"}
		if got := SignalTitleLang(s, "zh"); got != tc.wantZh {
			t.Errorf("zh title for %q = %q, want %q", tc.key, got, tc.wantZh)
		}
		if got := SignalTitleLang(s, "en"); got != tc.wantEn {
			t.Errorf("en title for %q = %q, want %q", tc.key, got, tc.wantEn)
		}
	}
}

// TestHostDetectorKeyRoundTrips: mount points carry ':' on Windows and '/'
// everywhere else, so the separator must survive both.
func TestHostDetectorKeyRoundTrips(t *testing.T) {
	for _, subject := range []string{"", "rx", "C:", "/", "/mnt/data", "D:\\vol"} {
		key := HostDetectorKey(DetectorHostDisk, subject)
		family, got := SplitHostDetectorKey(key)
		if family != DetectorHostDisk || got != subject {
			t.Errorf("round trip of %q gave (%q, %q)", subject, family, got)
		}
		if !IsHostDetector(key) {
			t.Errorf("%q not recognized as a host detector", key)
		}
	}
	for _, key := range []string{DetectorAvailability, DetectorAgentConnectivity, DetectorLatencyDegradation} {
		if IsHostDetector(key) {
			t.Errorf("%q wrongly recognized as a host detector", key)
		}
	}
}

// TestHostDisabledFamilyIsInert: a family switched off must leave no trace at
// all, so turning it off cannot leave a half-counted streak behind.
func TestHostDisabledFamilyIsInert(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled = false

	for i := 0; i < 12; i++ {
		h.evaluateHost(cpu(1000+int64(i)*30, 99))
	}
	if _, _, _, exists := h.hostState(DetectorHostCPU); exists {
		t.Fatalf("a disabled family left detector state behind")
	}
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("a disabled family confirmed %d faults", n)
	}
}

// TestHostRecoveryFloorStaysReachable: a percentage threshold at the bottom of
// the range would put a fixed 5-point floor at or below zero, and since readings
// are non-negative and recovery is a strict "<", the fault could never clear.
func TestHostRecoveryFloorStaysReachable(t *testing.T) {
	for _, threshold := range []float64{1, 3, 5, 5.5, 10, 90, 100} {
		floor := hostRecoverPct(threshold)
		if floor <= 0 {
			t.Errorf("threshold %v gave an unreachable floor %v", threshold, floor)
		}
		if floor >= threshold {
			t.Errorf("threshold %v gave a floor %v that is not below it", threshold, floor)
		}
	}
	// At ordinary thresholds the fixed margin still wins: 90 recovers at 85.
	if got := hostRecoverPct(90); got != 85 {
		t.Errorf("hostRecoverPct(90) = %v, want 85", got)
	}
}

// TestHostLowThresholdCanStillRecover walks the whole state machine at a
// threshold the fixed margin cannot serve.
func TestHostLowThresholdCanStillRecover(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false
	h.set.CPUPct, h.set.CPUDurationS = 4, 60 // two readings, floor 3.6

	ts := int64(1000)
	h.evaluateHost(cpu(ts, 50))
	ts += 30
	h.evaluateHost(cpu(ts, 50))
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("setup: want 1 signal at a 4%% threshold, got %d", n)
	}
	for i := 0; i < hostRecoverRounds; i++ {
		ts += 30
		h.evaluateHost(cpu(ts, 0))
	}
	if n := len(h.hostSignals()); n != 0 {
		t.Fatalf("a low threshold left the fault unable to recover")
	}
}

// TestHostGapResetsTheRecoveryStreakToo: a firing fault that banked one healthy
// reading and then went silent must not resolve on the next healthy reading a day
// later — "consecutive" has to mean the same thing in both directions.
func TestHostGapResetsTheRecoveryStreakToo(t *testing.T) {
	h := newHostHarness(t)
	h.set.MemEnabled, h.set.LoadEnabled, h.set.DiskEnabled = false, false, false
	h.set.CPUDurationS = 60 // two readings

	h.evaluateHost(cpu(1000, 95))
	h.evaluateHost(cpu(1030, 95))
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("setup: want 1 firing signal, got %d", n)
	}
	h.evaluateHost(cpu(1060, 10)) // one healthy reading banked
	if _, ok, _, _ := h.hostState(DetectorHostCPU); ok != 1 {
		t.Fatalf("ok_rounds = %d, want 1", ok)
	}
	// A day of silence, then two healthy readings: not three CONSECUTIVE ones.
	h.evaluateHost(cpu(1060+86400, 10))
	if _, ok, _, _ := h.hostState(DetectorHostCPU); ok != 1 {
		t.Fatalf("ok_rounds = %d after a day-long gap, want the streak restarted at 1", ok)
	}
	h.evaluateHost(cpu(1060+86430, 10))
	if n := len(h.hostSignals()); n != 1 {
		t.Fatalf("resolved on non-consecutive healthy readings")
	}
}

// TestHostTransientDiskReadDoesNotResolve: the agent omits a mount whose usage
// read failed, which looks exactly like a removal for one cycle. Terminating on
// that would close a live disk alert on a transient error.
func TestHostTransientDiskReadDoesNotResolve(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.LoadEnabled = false, false, false

	ts := int64(1000)
	for i := 0; i < hostDiskFailRounds; i++ {
		h.evaluateHost(diskPct(ts, "C:", 96), diskPct(ts, "E:", 99))
		ts += 30
	}
	if n := len(h.hostSignals()); n != 2 {
		t.Fatalf("setup: want 2 firing mounts, got %d", n)
	}

	// One cycle without E: — a failed read, not an ejection.
	h.evaluateHost(diskPct(ts, "C:", 96))
	if n := len(h.hostSignals()); n != 2 {
		t.Fatalf("a single missed disk read resolved a fault: %d signals, want 2", n)
	}

	// Missing for long enough that no read failure explains it: now it is gone.
	ts += 86400
	h.evaluateHost(diskPct(ts, "C:", 96))
	sigs := h.hostSignals()
	if len(sigs) != 1 || sigs[0].TargetAddr != "C:" {
		t.Fatalf("a long-gone mount was not resolved: %d signals", len(sigs))
	}
	var reason string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT resolve_reason FROM fault_signals WHERE target_addr='E:'`).Scan(&reason); err != nil {
		t.Fatalf("read E: resolve reason: %v", err)
	}
	if reason != ReasonSubjectGone {
		t.Errorf("resolve reason = %q, want %q", reason, ReasonSubjectGone)
	}
}

// TestHostDurationRoundsUp: duration_s accepts any value in range, not just
// multiples of the cadence, and rounding to nearest would confirm a 40-second
// setting after a single 30-second reading — a third sooner than asked.
func TestHostDurationRoundsUp(t *testing.T) {
	for _, tc := range []struct{ duration, interval, want int }{
		{300, 30, 10},
		{40, 30, 2}, // NOT 1
		{31, 30, 2},
		{30, 30, 1},
		{29, 30, 1}, // never below a single reading
		{300, 60, 5},
	} {
		if got := hostFailRounds(tc.duration, tc.interval); got != tc.want {
			t.Errorf("hostFailRounds(%d, %d) = %d, want %d", tc.duration, tc.interval, got, tc.want)
		}
	}
}

// TestHostLoadUsesContemporaneousCoreCount: a WAL packet can span a VM resize, so
// a load reading taken before a hot-add must not be divided by the count that
// only existed afterwards.
func TestHostLoadUsesContemporaneousCoreCount(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.DiskEnabled = false, false, false

	// One batch: 4 cores at t0 (load 16 → 4.0 per core, a breach), then the VM is
	// resized to 16 cores at t1 (load 16 → 1.0 per core, fine).
	rounds, _ := BuildHostRounds([]telemetry.Metric{
		coresMetric(1000, 4), load1(1000, 16),
		coresMetric(1030, 16), load1(1030, 16),
	}, h.metas(30, 0))

	var perCore []float64
	for _, r := range rounds {
		if r.DetectorKey == DetectorHostLoad {
			perCore = append(perCore, r.Value)
		}
	}
	if len(perCore) != 2 {
		t.Fatalf("want 2 load rounds, got %d", len(perCore))
	}
	if perCore[0] != 4 {
		t.Errorf("the pre-resize reading used %v per core, want 4 (its own core count)", perCore[0])
	}
	if perCore[1] != 1 {
		t.Errorf("the post-resize reading used %v per core, want 1", perCore[1])
	}
}

// TestHostDiskNeedsTwoMissesToBeGone: the agent omits a mount whose usage read
// failed, and an agent returning from an outage presents its first report with a
// wide time gap. Neither is a removal, so absence is counted in OBSERVED disk
// snapshots rather than in elapsed time.
func TestHostDiskNeedsTwoMissesToBeGone(t *testing.T) {
	h := newHostHarness(t)
	h.set.CPUEnabled, h.set.MemEnabled, h.set.LoadEnabled = false, false, false

	ts := int64(1000)
	for i := 0; i < hostDiskFailRounds; i++ {
		h.evaluateHost(diskPct(ts, "C:", 96), diskPct(ts, "E:", 99))
		ts += 30
	}
	if n := len(h.hostSignals()); n != 2 {
		t.Fatalf("setup: want 2 firing mounts, got %d", n)
	}

	// One missed read — even a whole day later, as after an outage.
	ts += 86400
	h.evaluateHost(diskPct(ts, "C:", 96))
	if n := len(h.hostSignals()); n != 2 {
		t.Fatalf("a single miss resolved a fault: %d signals, want 2", n)
	}

	// E: reports again: the miss must leave no residue.
	ts += 30
	h.evaluateHost(diskPct(ts, "C:", 96), diskPct(ts, "E:", 99))
	ts += 30
	h.evaluateHost(diskPct(ts, "C:", 96))
	if n := len(h.hostSignals()); n != 2 {
		t.Fatalf("a miss after a successful read counted toward removal: %d signals", n)
	}

	// Two in a row: gone.
	ts += 30
	h.evaluateHost(diskPct(ts, "C:", 96))
	sigs := h.hostSignals()
	if len(sigs) != 1 || sigs[0].TargetAddr != "C:" {
		t.Fatalf("want only C: firing after two consecutive misses, got %d", len(sigs))
	}
	var reason string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT resolve_reason FROM fault_signals WHERE target_addr='E:'`).Scan(&reason); err != nil {
		t.Fatalf("read E: resolve reason: %v", err)
	}
	if reason != ReasonSubjectGone {
		t.Errorf("resolve reason = %q, want %q", reason, ReasonSubjectGone)
	}
}
