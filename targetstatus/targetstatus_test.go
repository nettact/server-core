package targetstatus

import (
	"database/sql"
	"testing"
	"time"

	"github.com/nettact/protocol/wire"
)

func TestAggregateDecisionTable(t *testing.T) {
	online := func(exec, probe, flt string) agentAgg {
		return agentAgg{exec: exec, probe: probe, fault: flt, online: true}
	}
	tests := []struct {
		name     string
		enabled  bool
		agents   []agentAgg
		display  string
		affected int
	}{
		{"disabled", false, []agentAgg{online(execCollecting, probeHealthy, faultNormal)}, displayDisabled, 0},
		{"unassigned", true, nil, displayUnassigned, 0},
		{"faulted wins", true, []agentAgg{online(execCollecting, probeHealthy, faultFaulted)}, displayFaulted, 1},
		{"confirming wins", true, []agentAgg{online(execCollecting, probeHealthy, faultConfirming)}, displayConfirming, 1},
		{"all probes failed", true, []agentAgg{online(execCollecting, probeFailed, faultNormal)}, displayProbeFailed, 1},
		{"partial failure", true, []agentAgg{online(execCollecting, probeFailed, faultNormal), online(execCollecting, probeHealthy, faultNormal)}, displayPartialFailure, 1},
		{"all blocked", true, []agentAgg{online(execPermissionBlocked, probeNoData, faultNormal), online(execUnsupported, probeNoData, faultNormal)}, displayBlocked, 2},
		{"all offline", true, []agentAgg{{exec: execAgentOffline, online: false}, {exec: execAgentOffline, online: false}}, displayAgentOffline, 2},
		{"fresh pending", true, []agentAgg{{exec: execPending, online: true}}, displayPending, 1},
		{"expired pending", true, []agentAgg{{exec: execPending, online: true, pendingExpired: true}}, displayNoData, 1},
		{"healthy with stale minority", true, []agentAgg{online(execCollecting, probeHealthy, faultNormal), online(execCollecting, probeStale, faultNormal)}, displayHealthy, 0},
		{"stale", true, []agentAgg{online(execCollecting, probeStale, faultNormal)}, displayStale, 1},
		{"no data", true, []agentAgg{online(execCollecting, probeNoData, faultNormal)}, displayNoData, 1},
		{"host not applicable", true, []agentAgg{online(execCollecting, probeNotApplicable, faultNormal)}, displayHealthy, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, affected := aggregate(&targetRow{enabled: tt.enabled}, tt.agents)
			if got != tt.display || affected != tt.affected {
				t.Fatalf("aggregate = %s/%d, want %s/%d", got, affected, tt.display, tt.affected)
			}
		})
	}
}

func TestAssignmentCutoffAdmitsSameSecondPostAssignmentSample(t *testing.T) {
	cutoff := time.Unix(1_000, 500_000_000).UTC()
	target := &targetRow{id: "target", kind: "http", enabled: true, configSerial: 2}
	pair := applicablePair{agentID: "agent", agentName: "Agent", online: true}
	status := &msRow{
		status: wire.MonitorStatusActive, source: "reported", targetConfigSerial: 2,
		assignedAt: sql.NullTime{Time: cutoff, Valid: true},
	}
	statusByKey := map[string]*msRow{"target\x00agent": status}
	sampleKey := "target\x00agent\x00probe.http.ok"
	svc := &Service{}

	// samples.ts stores only Unix seconds. A sample in the cutoff's same second
	// must be retained because it may have been observed after the assignment.
	as, _ := svc.deriveAgent(target, pair, cutoff.Add(time.Second), statusByKey,
		map[string]*sampleVal{sampleKey: {kind: "probe.http.ok", unit: "bool", ts: cutoff.Unix(), value: 1}},
		nil, nil)
	if as.ProbeState != probeHealthy {
		t.Fatalf("same-second sample probe_state = %q, want healthy", as.ProbeState)
	}

	as, _ = svc.deriveAgent(target, pair, cutoff.Add(time.Second), statusByKey,
		map[string]*sampleVal{sampleKey: {kind: "probe.http.ok", unit: "bool", ts: cutoff.Unix() - 1, value: 1}},
		nil, nil)
	if as.ProbeState != probeNoData {
		t.Fatalf("pre-assignment sample probe_state = %q, want no_data", as.ProbeState)
	}
}

func TestStaleWindowFoldsReportedUploadInterval(t *testing.T) {
	now := time.Unix(100_000, 0).UTC()
	target := &targetRow{id: "target", kind: "http", enabled: true, configSerial: 2}
	pair := applicablePair{agentID: "agent", online: true}
	svc := &Service{}

	windowFor := func(ms *msRow) int {
		t.Helper()
		as, _ := svc.deriveAgent(target, pair, now, map[string]*msRow{"target\x00agent": ms}, nil, nil, nil)
		if as.StaleAfterSeconds == nil {
			t.Fatalf("stale_after_seconds unset for %+v", ms)
		}
		return *as.StaleAfterSeconds
	}
	confirmed := func(upload sql.NullInt64) *msRow {
		return &msRow{
			status: wire.MonitorStatusActive, source: "reported", targetConfigSerial: 2,
			effInterval:    sql.NullInt64{Int64: 15, Valid: true},
			cycleDeadline:  sql.NullInt64{Int64: 5800, Valid: true},
			uploadInterval: upload,
		}
	}

	// Reported schedule base = max(3×15, 15 + 2×5.8) = 45s. Folding the reported
	// upload (5s) adds 2×5 = 10s: the old two-arg window + 10s = 55s.
	if got := windowFor(confirmed(sql.NullInt64{Int64: 5, Valid: true})); got != 55 {
		t.Fatalf("reported upload=5s window = %ds, want 55", got)
	}
	// A different reported upload flows through (2×8 = 16s → 61s), proving the
	// stored value is used, not a constant.
	if got := windowFor(confirmed(sql.NullInt64{Int64: 8, Valid: true})); got != 61 {
		t.Fatalf("reported upload=8s window = %ds, want 61", got)
	}
	// NULL upload (a pre-STATUS-003 agent, or a frame that reported none) falls back
	// to DefaultUploadInterval (5s) inside StaleAfter → 55s.
	if got := windowFor(confirmed(sql.NullInt64{})); got != 55 {
		t.Fatalf("null upload window = %ds, want 55 (default fallback)", got)
	}
	// Unconfirmed (predicted) uses the desired-config fallback with the default
	// upload: StaleAfter(30s, 10s, 5s) = max(90, 50) + 10 = 100s.
	predicted := &msRow{status: wire.MonitorStatusActive, source: "predicted", targetConfigSerial: 2}
	if got := windowFor(predicted); got != 100 {
		t.Fatalf("desired-config fallback window = %ds, want 100", got)
	}
}

func TestPendingGraceExpiresToNoDataWithoutChangingExecution(t *testing.T) {
	now := time.Unix(10_000, 0).UTC()
	target := &targetRow{id: "target", kind: "http", enabled: true, configSerial: 2}
	pair := applicablePair{agentID: "agent", online: true}
	svc := &Service{}

	// http target, desired-config fallback window = StaleAfter(30s, 10s, default 5s)
	// = max(90, 50) + 2×5 = 100s, so the pending grace boundary sits at 100s.
	for _, tt := range []struct {
		name     string
		assigned time.Time
		display  string
	}{
		{"within grace", now.Add(-99 * time.Second), displayPending},
		{"expired", now.Add(-101 * time.Second), displayNoData},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ms := &msRow{status: wire.MonitorStatusActive, source: "predicted", targetConfigSerial: 2,
				assignedAt: sql.NullTime{Time: tt.assigned, Valid: true}}
			as, agg := svc.deriveAgent(target, pair, now, map[string]*msRow{"target\x00agent": ms}, nil, nil, nil)
			if as.ExecutionState != execPending || as.PendingSince == nil {
				t.Fatalf("execution = %+v, want pending with timestamp", as)
			}
			got, _ := aggregate(target, []agentAgg{agg})
			if got != tt.display {
				t.Fatalf("display = %q, want %q", got, tt.display)
			}
		})
	}
}
