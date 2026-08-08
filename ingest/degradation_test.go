package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/baseline"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The one seam the unit tests above cannot reach: a real telemetry packet going
// through the whole Ingest path — provenance filter, pre-tx baseline lookup, in-tx
// round rebuild, detector — and coming out as a degradation incident. Everything
// in between is wired by field names and map keys that compile whether or not
// they agree, so this is the test that would catch them disagreeing.

type degHarness struct {
	t   *testing.T
	db  *store.DB
	svc *Service
	ctx context.Context
	seq uint64
}

func newDegHarness(t *testing.T) *degHarness {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	h := &degHarness{t: t, db: db, ctx: ctx}
	h.exec(`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now)
	h.exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_a','site_default',x'00','h','online')`)
	h.exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents) VALUES('mg','site_default','Default',1,0,1)`)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	        VALUES('t_icmp','site_default','mg','icmp','Router','192.168.1.1','{}',1,1)`)

	m := metrics.New(db)
	faultSvc := fault.New(db, eventbus.New(), nil)
	h.svc = New(db, nil, m, faultSvc, baseline.New(db), nil)
	return h
}

func (h *degHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(h.ctx, q, args...); err != nil {
		h.t.Fatalf("exec %q: %v", q, err)
	}
}

// seedBaseline writes a learned weekday-midday baseline directly, standing in for
// what the hourly fold job would have produced over the past week.
func (h *degHarness) seedBaseline(daypart int, weekend bool, p50, p95 float64) {
	h.t.Helper()
	w := 0
	if weekend {
		w = 1
	}
	now := time.Now().In(time.Local)
	for d := 1; d <= baseline.MinDays; d++ {
		past := now.AddDate(0, 0, -d)
		day := past.Year()*10000 + int(past.Month())*100 + past.Day()
		h.exec(`INSERT INTO baseline_daily(target_id, agent_id, metric_kind, day, daypart, weekend,
		        config_serial, cnt, p50, p95, updated_at)
		        VALUES('t_icmp','agent_a','probe.icmp.rtt_ms',?,?,?,1,?,?,?,?)`,
			day, daypart, w, baseline.MinSamples, p50, p95, time.Now().UTC())
	}
}

// push sends one packet of n consecutive healthy ICMP rounds ending ~now.
// push ingests n consecutive ICMP rounds at the given RTT.
//
// Every round carries probe.icmp.sent, exactly as a real agent's does: loss is a
// ratio over the echoes actually sent, and the server refuses a verdict on a
// round that cannot show it sent everything it was configured to (see
// fault.RoundComplete). A fixture that omitted it would be judged an incomplete
// round and produce no verdict at all — which is the invariant working, not a
// detail to route around.
func (h *degHarness) push(n int, rttMs float64) {
	h.t.Helper()
	base := time.Now().Unix() - int64(2*n)
	var ms []telemetry.Metric
	for i := range n {
		ts := time.Unix(base+int64(2*i), 0).UTC()
		ms = append(ms,
			telemetry.Metric{TS: ts, Kind: telemetry.ICMPLoss, Target: "192.168.1.1",
				Value: 0, Unit: telemetry.UnitPct, MonitorID: "t_icmp", ConfigSerial: 1},
			telemetry.Metric{TS: ts, Kind: telemetry.ICMPSent, Target: "192.168.1.1",
				Value: float64(pcfg.PingCount(pcfg.ProbeParams{})), Unit: telemetry.UnitCount,
				MonitorID: "t_icmp", ConfigSerial: 1},
			telemetry.Metric{TS: ts, Kind: telemetry.ICMPRTTms, Target: "192.168.1.1",
				Value: rttMs, Unit: telemetry.UnitMs, MonitorID: "t_icmp", ConfigSerial: 1},
		)
	}
	h.seq++
	if _, err := h.svc.Ingest(h.ctx, "agent_a", "site_default", telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_a", SiteID: "site_default",
		Sequence: h.seq, SentAt: time.Now().UTC(), Metrics: ms,
	}); err != nil {
		h.t.Fatalf("ingest: %v", err)
	}
}

func (h *degHarness) firingDegradation() (metricKind string, value, p50, p95, threshold float64, severity string, found bool) {
	h.t.Helper()
	err := h.db.Read().QueryRowContext(h.ctx, `
		SELECT metric_kind, value, baseline_p50, baseline_p95, threshold, severity
		FROM fault_signals WHERE detector_key=? AND state='firing'`,
		fault.DetectorLatencyDegradation).
		Scan(&metricKind, &value, &p50, &p95, &threshold, &severity)
	if err != nil {
		return "", 0, 0, 0, 0, "", false
	}
	return metricKind, value, p50, p95, threshold, severity, true
}

// dayparts of the moment the pushed rounds land in, which is what the pre-tx
// lookup will ask for.
func nowBucket() (daypart int, weekend bool) {
	_, daypart, weekend = baseline.BucketOf(time.Now().Unix())
	return daypart, weekend
}

func TestIngestOpensLatencyDegradationAgainstTheLearnedBaseline(t *testing.T) {
	h := newDegHarness(t)
	daypart, weekend := nowBucket()
	h.seedBaseline(daypart, weekend, 40, 45)

	det := fault.DefaultDetection()
	h.push(fault.DegradationFailRounds(det.SmartSensitivity), 300)

	metricKind, value, p50, p95, threshold, severity, found := h.firingDegradation()
	if !found {
		t.Fatal("no degradation signal after a full streak of markedly slow rounds")
	}
	if metricKind != string(telemetry.ICMPRTTms) {
		t.Fatalf("metric kind = %q", metricKind)
	}
	if value != 300 {
		t.Fatalf("value = %v, want the confirming round's 300", value)
	}
	if p50 != 40 || p95 != 45 {
		t.Fatalf("frozen band = (%v, %v), want the seeded (40, 45)", p50, p95)
	}
	want := fault.DegradationThreshold(baseline.Band{P50: 40, P95: 45}, det.SmartSensitivity, metricKind)
	if threshold != want {
		t.Fatalf("threshold = %v, want %v", threshold, want)
	}
	// info keeps it below the default notification policy's floor: recorded in the
	// fault centre, announced to nobody until an operator asks to be told.
	if severity != fault.SeverityInfo {
		t.Fatalf("severity = %q, want %q", severity, fault.SeverityInfo)
	}
}

func TestIngestJudgesNothingWithoutABaseline(t *testing.T) {
	h := newDegHarness(t)
	// No seeded history: every round is wildly slow and none of it is judged,
	// because "worse than usual" needs a usual.
	h.push(fault.DegradationFailRounds(fault.SmartStandard)*2, 5000)
	if _, _, _, _, _, _, found := h.firingDegradation(); found {
		t.Fatal("judged a target with no baseline")
	}
}

func TestIngestLeavesAnInBandTargetAlone(t *testing.T) {
	h := newDegHarness(t)
	daypart, weekend := nowBucket()
	h.seedBaseline(daypart, weekend, 40, 45)

	h.push(fault.DegradationFailRounds(fault.SmartStandard)*2, 44)
	if _, _, _, _, _, _, found := h.firingDegradation(); found {
		t.Fatal("opened a degradation for a target sitting inside its own band")
	}
}

func TestIngestDegradationRespectsTheSmartSwitch(t *testing.T) {
	h := newDegHarness(t)
	daypart, weekend := nowBucket()
	h.seedBaseline(daypart, weekend, 40, 45)
	h.exec(`INSERT INTO probe_detection_settings(target_id, profile, fail_rounds, recover_rounds,
	        icmp_loss_pct, smart_enabled, smart_sensitivity, revision, updated_at)
	        VALUES('t_icmp','balanced',3,2,100,0,'standard',1,?)`, time.Now().UTC())

	h.push(fault.DegradationFailRounds(fault.SmartStandard)*2, 300)
	if _, _, _, _, _, _, found := h.firingDegradation(); found {
		t.Fatal("opened a degradation with smart detection switched off on the target")
	}
}
