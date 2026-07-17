package targetstatus

import (
	"database/sql"
	"testing"
	"time"

	"github.com/nettact/protocol/wire"
)

func TestAggregateDecisionTable(t *testing.T) {
	online := func(exec, probe, rule string) agentAgg {
		return agentAgg{exec: exec, probe: probe, rule: rule, online: true}
	}
	tests := []struct {
		name     string
		enabled  bool
		agents   []agentAgg
		display  string
		affected int
	}{
		{"disabled", false, []agentAgg{online(execCollecting, probeHealthy, ruleNormal)}, displayDisabled, 0},
		{"unassigned", true, nil, displayUnassigned, 0},
		{"alerting wins", true, []agentAgg{online(execCollecting, probeHealthy, ruleAlerting)}, displayAlerting, 1},
		{"breaching wins", true, []agentAgg{online(execCollecting, probeHealthy, ruleBreaching)}, displayBreaching, 1},
		{"all probes failed", true, []agentAgg{online(execCollecting, probeFailed, ruleNormal)}, displayProbeFailed, 1},
		{"partial failure", true, []agentAgg{online(execCollecting, probeFailed, ruleNormal), online(execCollecting, probeHealthy, ruleNormal)}, displayPartialFailure, 1},
		{"all blocked", true, []agentAgg{online(execPermissionBlocked, probeNoData, ruleNormal), online(execUnsupported, probeNoData, ruleNormal)}, displayBlocked, 2},
		{"all offline", true, []agentAgg{{exec: execAgentOffline, online: false}, {exec: execAgentOffline, online: false}}, displayAgentOffline, 2},
		{"fresh pending", true, []agentAgg{{exec: execPending, online: true}}, displayPending, 1},
		{"expired pending", true, []agentAgg{{exec: execPending, online: true, pendingExpired: true}}, displayNoData, 1},
		{"healthy with stale minority", true, []agentAgg{online(execCollecting, probeHealthy, ruleNormal), online(execCollecting, probeStale, ruleNormal)}, displayHealthy, 1},
		{"stale", true, []agentAgg{online(execCollecting, probeStale, ruleNormal)}, displayStale, 1},
		{"no data", true, []agentAgg{online(execCollecting, probeNoData, ruleNormal)}, displayNoData, 1},
		{"host not applicable", true, []agentAgg{online(execCollecting, probeNotApplicable, ruleNormal)}, displayHealthy, 1},
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
		nil, nil, nil, nil)
	if as.ProbeState != probeHealthy {
		t.Fatalf("same-second sample probe_state = %q, want healthy", as.ProbeState)
	}

	as, _ = svc.deriveAgent(target, pair, cutoff.Add(time.Second), statusByKey,
		map[string]*sampleVal{sampleKey: {kind: "probe.http.ok", unit: "bool", ts: cutoff.Unix() - 1, value: 1}},
		nil, nil, nil, nil)
	if as.ProbeState != probeNoData {
		t.Fatalf("pre-assignment sample probe_state = %q, want no_data", as.ProbeState)
	}
}

func TestPendingGraceExpiresToNoDataWithoutChangingExecution(t *testing.T) {
	now := time.Unix(10_000, 0).UTC()
	target := &targetRow{id: "target", kind: "http", enabled: true, configSerial: 2}
	pair := applicablePair{agentID: "agent", online: true}
	svc := &Service{}

	for _, tt := range []struct {
		name     string
		assigned time.Time
		display  string
	}{
		{"within grace", now.Add(-89 * time.Second), displayPending},
		{"expired", now.Add(-91 * time.Second), displayNoData},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ms := &msRow{status: wire.MonitorStatusActive, source: "predicted", targetConfigSerial: 2,
				assignedAt: sql.NullTime{Time: tt.assigned, Valid: true}}
			as, agg := svc.deriveAgent(target, pair, now, map[string]*msRow{"target\x00agent": ms}, nil, nil, nil, nil, nil)
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
