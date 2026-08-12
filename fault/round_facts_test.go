package fault

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// Round-facts tests for DEGRADE-001/002. A size sweep (probe.icmp.size_sweep) and
// a TCP flow fan-out (probe.tcp.flow_fanout) are dedicated classification samples:
// BuildRounds must parse them onto the round so the detectors can freeze them as
// evidence, but never fold them into the judged latencies. The two hooks then
// freeze the facts onto exactly the signals whose claim they support — and no
// other signal.

// sizeSweep builds one size_sweep classification sample. Code per
// telemetry.ICMPSizeSweep: 0 flat, 1 size-correlated, 2 insufficient.
func sizeSweep(ts int64, code, sizeSmall, sizeLarge int, lossSmall, lossLarge float64, countSmall, countLarge int) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPSizeSweep, Target: "192.168.1.1",
		Value: float64(code), Unit: telemetry.UnitCode, MonitorID: "t_icmp", ConfigSerial: 1,
		Labels: map[string]string{
			telemetry.SizeSmallLabel:  strconv.Itoa(sizeSmall),
			telemetry.SizeLargeLabel:  strconv.Itoa(sizeLarge),
			telemetry.LossSmallLabel:  strconv.FormatFloat(lossSmall, 'f', 1, 64),
			telemetry.LossLargeLabel:  strconv.FormatFloat(lossLarge, 'f', 1, 64),
			telemetry.CountSmallLabel: strconv.Itoa(countSmall),
			telemetry.CountLargeLabel: strconv.Itoa(countLarge),
		},
	}
}

// flowFanout builds one flow_fanout classification sample. Code per
// telemetry.TCPFlowFanout: 0 single, 1 uniform, 2 member-level, 3 all failed,
// 4 insufficient.
func flowFanout(ts int64, code, flows, badStable, badNew, ok int) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.TCPFlowFanout, Target: "1.2.3.4:443",
		Value: float64(code), Unit: telemetry.UnitCode, MonitorID: "t_tcp", ConfigSerial: 1,
		Labels: map[string]string{
			telemetry.FlowFanoutFlowsLabel:    strconv.Itoa(flows),
			telemetry.FlowFanoutBadStableLabel: strconv.Itoa(badStable),
			telemetry.FlowFanoutBadNewLabel:    strconv.Itoa(badNew),
			telemetry.FlowFanoutOKLabel:        strconv.Itoa(ok),
		},
	}
}

func tcpOK(ts int64, ok bool) telemetry.Metric {
	v := 1.0
	if !ok {
		v = 0
	}
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.TCPOK, Target: "1.2.3.4:443",
		Value: v, Unit: telemetry.UnitBool, MonitorID: "t_tcp", ConfigSerial: 1,
	}
}

// tcpMeta is the tcp target's evaluation metadata with an explicit round gap,
// mirroring degMeta.
func tcpMeta(det DetectionSettings) map[string]TargetMeta {
	return map[string]TargetMeta{
		"t_tcp": {ID: "t_tcp", Kind: "tcp", GroupID: "mg", Name: "Svc", Addr: "1.2.3.4:443",
			Enabled: true, ConfigSerial: 1, Det: det.Normalize(), MaxRoundGap: degGap},
	}
}

// evaluateMetaMap runs one ingest-equivalent pass over arbitrary target metadata.
func (h *harness) evaluateMetaMap(det DetectionSettings, meta map[string]TargetMeta, ms ...telemetry.Metric) *Outcome {
	h.t.Helper()
	rounds := BuildRounds(ms, meta)
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

func TestBuildRoundsParsesSizeSweepFacts(t *testing.T) {
	det := smartDet()
	ts := time.Now().Unix()
	ms := []telemetry.Metric{
		loss(ts, 0), rtt(ts, 42),
		sizeSweep(ts, 1, 64, 1400, 0, 67.4, 5, 5),
	}
	rounds := BuildRounds(ms, degMeta(det))
	if len(rounds) != 1 {
		t.Fatalf("built %d rounds, want 1", len(rounds))
	}
	f := rounds[0].SizeSweep
	if f == nil {
		t.Fatal("size_sweep sample not parsed onto the round")
	}
	if f.Code != 1 || f.SizeSmall != 64 || f.SizeLarge != 1400 ||
		f.LossSmall != 0 || f.LossLarge != 67.4 || f.CountSmall != 5 || f.CountLarge != 5 {
		t.Fatalf("size sweep facts = %+v", *f)
	}
	// The classification must never leak into the judged latencies.
	if _, ok := rounds[0].Latencies[string(telemetry.ICMPSizeSweep)]; ok {
		t.Fatal("size_sweep folded into latencies")
	}
	// A cycle carrying ONLY the sweep is still not a round: without the primary
	// metric there is no verdict to attach anything to.
	if got := BuildRounds([]telemetry.Metric{sizeSweep(ts, 1, 64, 1400, 0, 67.4, 5, 5)}, degMeta(det)); len(got) != 0 {
		t.Fatalf("built %d rounds from a sweep-only cycle, want 0", len(got))
	}
}

func TestBuildRoundsParsesFlowFanoutFacts(t *testing.T) {
	det := smartDet()
	ts := time.Now().Unix()
	ms := []telemetry.Metric{
		tcpOK(ts, true),
		flowFanout(ts, 2, 6, 4, 1, 1),
	}
	rounds := BuildRounds(ms, tcpMeta(det))
	if len(rounds) != 1 {
		t.Fatalf("built %d rounds, want 1", len(rounds))
	}
	f := rounds[0].FlowFanout
	if f == nil {
		t.Fatal("flow_fanout sample not parsed onto the round")
	}
	if f.Code != 2 || f.Flows != 6 || f.BadStable != 4 || f.BadNew != 1 || f.OK != 1 {
		t.Fatalf("flow fanout facts = %+v", *f)
	}
	if _, ok := rounds[0].Latencies[string(telemetry.TCPFlowFanout)]; ok {
		t.Fatal("flow_fanout folded into latencies")
	}
}

// TestLossDegradationFreezesSizeSweepFacts is the confirmDegradation hook: only a
// LOSS degradation with a size-correlated confirming round freezes the facts.
func TestLossDegradationFreezesSizeSweepFacts(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	// Loss 75 breaches the stdBand loss threshold (67.5) while staying under the
	// availability threshold (default 100), so this is a degradation, not an
	// outage — the premise the hook is about.
	base := time.Now().Unix() - int64(2*need)
	ms := degRoundsFrom(base, need, 42, 75)
	lastTS := base + int64(2*(need-1))
	ms = append(ms, sizeSweep(lastTS, 1, 64, 1400, 0, 67.4, 5, 5))
	h.evalDeg(det, stdBand, ms...)

	if sig := h.degSignal(t, DetectorAvailability); sig != nil {
		t.Fatal("availability confirmed alongside a 75% loss — pick a loss below the availability threshold")
	}
	sig := h.degSignal(t, DetectorLossDegradation)
	if sig == nil {
		t.Fatal("loss degradation did not confirm — the fixture is wrong, not the hook")
	}
	if sig.SizeSweep == nil {
		t.Fatal("a size-correlated loss confirmation must freeze the size sweep facts")
	}
	if sig.SizeSweep.Code != 1 || sig.SizeSweep.SizeSmall != 64 || sig.SizeSweep.SizeLarge != 1400 ||
		sig.SizeSweep.LossSmall != 0 || sig.SizeSweep.LossLarge != 67.4 || sig.SizeSweep.CountSmall != 5 || sig.SizeSweep.CountLarge != 5 {
		t.Fatalf("size sweep facts = %+v", *sig.SizeSweep)
	}
	// The facts survive the DB round-trip: degSignal reads through ListActive.
}

func TestLatencyDegradationDoesNotFreezeSizeSweep(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	// High RTT, no loss: a latency degradation carrying a size-correlated sweep.
	// "latency rises with packet size" is not a fingerprint, so the facts must stay
	// off the signal.
	base := time.Now().Unix() - int64(2*need)
	ms := degRoundsFrom(base, need, 300, 0)
	lastTS := base + int64(2*(need-1))
	ms = append(ms, sizeSweep(lastTS, 1, 64, 1400, 0, 67.4, 5, 5))
	h.evalDeg(det, stdBand, ms...)

	sig := h.degSignal(t, DetectorLatencyDegradation)
	if sig == nil {
		t.Fatal("latency degradation did not confirm — the fixture is wrong, not the hook")
	}
	if sig.SizeSweep != nil {
		t.Fatal("a latency degradation must not freeze the size sweep facts")
	}
}

func TestLossDegradationIgnoresFlatSizeSweep(t *testing.T) {
	h := newHarness(t)
	det := smartDet()
	need := DegradationFailRounds(det.SmartSensitivity)
	// Size-correlation is the claim that freezes the facts; a flat (code 0) sweep
	// is the congestion signature and argues against them.
	base := time.Now().Unix() - int64(2*need)
	ms := degRoundsFrom(base, need, 42, 75)
	lastTS := base + int64(2*(need-1))
	ms = append(ms, sizeSweep(lastTS, 0, 64, 1400, 0, 5, 5, 5))
	h.evalDeg(det, stdBand, ms...)

	sig := h.degSignal(t, DetectorLossDegradation)
	if sig == nil {
		t.Fatal("loss degradation did not confirm — the fixture is wrong, not the hook")
	}
	if sig.SizeSweep != nil {
		t.Fatal("a flat size sweep must not freeze the facts")
	}
}

// TestAvailabilityFreezesFlowFanoutFacts is the confirmSignal hook: only an
// availability fault whose confirming round was member-level (code 2) freezes the
// fan-out facts.
func TestAvailabilityFreezesFlowFanoutFacts(t *testing.T) {
	h := newHarness(t)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('t_tcp','site_default','mg','tcp','Svc','1.2.3.4:443','{}',1,1)`)
	det := smartDet()
	need := det.FailRounds
	base := time.Now().Unix() - int64(2*need)
	var ms []telemetry.Metric
	for i := 0; i < need; i++ {
		ts := base + int64(2*i)
		ms = append(ms, tcpOK(ts, false))
	}
	lastTS := base + int64(2*(need-1))
	ms = append(ms, flowFanout(lastTS, 2, 6, 4, 1, 1))
	h.evaluateMetaMap(det, tcpMeta(det), ms...)

	sig := h.degSignal(t, DetectorAvailability)
	if sig == nil {
		t.Fatal("tcp availability did not confirm — the fixture is wrong, not the hook")
	}
	if sig.FlowFanout == nil {
		t.Fatal("a member-level fan-out confirmation must freeze the flow facts")
	}
	if sig.FlowFanout.Code != 2 || sig.FlowFanout.Flows != 6 || sig.FlowFanout.BadStable != 4 ||
		sig.FlowFanout.BadNew != 1 || sig.FlowFanout.OK != 1 {
		t.Fatalf("flow fanout facts = %+v", *sig.FlowFanout)
	}
}

func TestAvailabilityIgnoresUniformFlowFanout(t *testing.T) {
	h := newHarness(t)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('t_tcp','site_default','mg','tcp','Svc','1.2.3.4:443','{}',1,1)`)
	det := smartDet()
	need := det.FailRounds
	base := time.Now().Unix() - int64(2*need)
	var ms []telemetry.Metric
	for i := 0; i < need; i++ {
		ts := base + int64(2*i)
		ms = append(ms, tcpOK(ts, false))
	}
	lastTS := base + int64(2*(need-1))
	// Uniform (code 1): failures spread across flows, the congestion signature —
	// not an ECMP member fault.
	ms = append(ms, flowFanout(lastTS, 1, 6, 0, 6, 0))
	h.evaluateMetaMap(det, tcpMeta(det), ms...)

	sig := h.degSignal(t, DetectorAvailability)
	if sig == nil {
		t.Fatal("tcp availability did not confirm — the fixture is wrong, not the hook")
	}
	if sig.FlowFanout != nil {
		t.Fatal("a uniform fan-out must not freeze the facts")
	}
}

func TestSignalFactsJSONRoundTrip(t *testing.T) {
	sig := Signal{
		SizeSweep:  &SizeSweepFacts{Code: 1, SizeSmall: 64, SizeLarge: 1400, LossSmall: 0, LossLarge: 67.4, CountSmall: 5, CountLarge: 5},
		FlowFanout: &FlowFanoutFacts{Code: 2, Flows: 6, BadStable: 4, BadNew: 1, OK: 1},
	}
	blob, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ss, ok := got["size_sweep"].(map[string]any)
	if !ok {
		t.Fatalf("size_sweep absent from JSON: %s", blob)
	}
	if ss["code"] != float64(1) || ss["size_small"] != float64(64) || ss["size_large"] != float64(1400) ||
		ss["loss_small"] != float64(0) || ss["loss_large"] != 67.4 || ss["count_small"] != float64(5) || ss["count_large"] != float64(5) {
		t.Fatalf("size_sweep JSON = %v", ss)
	}
	ff, ok := got["flow_fanout"].(map[string]any)
	if !ok {
		t.Fatalf("flow_fanout absent from JSON: %s", blob)
	}
	if ff["code"] != float64(2) || ff["flows"] != float64(6) || ff["bad_stable"] != float64(4) ||
		ff["bad_new"] != float64(1) || ff["ok"] != float64(1) {
		t.Fatalf("flow_fanout JSON = %v", ff)
	}

	// Nil facts must be ABSENT (omitempty), not "null": the store writes NULL for
	// them and a reader must not distinguish "frozen null" from "not the evidence".
	empty, err := json.Marshal(Signal{})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	var em map[string]any
	if err := json.Unmarshal(empty, &em); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	for _, k := range []string{"size_sweep", "flow_fanout"} {
		if _, ok := em[k]; ok {
			t.Fatalf("%s present on a nil-fact signal: %s", k, empty)
		}
	}
}
