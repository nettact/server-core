package targetstatus

import (
	"database/sql"
	"testing"
	"time"

	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/metrics"
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
	// to DefaultUploadInterval (30s) inside StaleAfter → 45 + 2×30 = 105s.
	if got := windowFor(confirmed(sql.NullInt64{})); got != 105 {
		t.Fatalf("null upload window = %ds, want 105 (default fallback)", got)
	}
	// Unconfirmed (predicted) uses the desired-config fallback with the default
	// upload: StaleAfter(30s, 10s, 30s) = max(90, 50) + 60 = 150s.
	predicted := &msRow{status: wire.MonitorStatusActive, source: "predicted", targetConfigSerial: 2}
	if got := windowFor(predicted); got != 150 {
		t.Fatalf("desired-config fallback window = %ds, want 150", got)
	}
}

func TestPendingGraceExpiresToNoDataWithoutChangingExecution(t *testing.T) {
	now := time.Unix(10_000, 0).UTC()
	target := &targetRow{id: "target", kind: "http", enabled: true, configSerial: 2}
	pair := applicablePair{agentID: "agent", online: true}
	svc := &Service{}

	// http target, desired-config fallback window = StaleAfter(30s, 10s, default 30s)
	// = max(90, 50) + 2×30 = 150s, so the pending grace boundary sits at 150s.
	for _, tt := range []struct {
		name     string
		assigned time.Time
		display  string
	}{
		{"within grace", now.Add(-149 * time.Second), displayPending},
		{"expired", now.Add(-151 * time.Second), displayNoData},
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

func TestAssembleTargetIncludesPerAgentAvailability(t *testing.T) {
	svc := &Service{}
	target := &targetRow{id: "target", kind: "host", enabled: true}
	pairs := []applicablePair{{agentID: "agent", agentName: "Agent", online: true}}

	got := svc.assembleTarget(target, pairs, time.Now().UTC(), nil, nil, nil, nil,
		metrics.AvailabilityRatio{}, map[string]metrics.AvailabilityRatio{
			"agent": {AgentID: "agent", Rounds: 4, OKRounds: 3, Ratio: 0.75},
		}, nil)
	if len(got.Agents) != 1 || got.Agents[0].Availability24h == nil || *got.Agents[0].Availability24h != 0.75 {
		t.Fatalf("agent availability = %+v, want 0.75", got.Agents)
	}
}

// TestAssembleTargetSumsFluctuationsAcrossAgents: the per-target figure has to be
// the whole target's, or a dip seen only from a second Agent would go unexplained
// on the row that shows the availability it dragged down.
func TestAssembleTargetSumsFluctuationsAcrossAgents(t *testing.T) {
	svc := &Service{}
	target := &targetRow{id: "target", kind: "icmp", enabled: true}
	pairs := []applicablePair{
		{agentID: "agent_a", agentName: "A", online: true},
		{agentID: "agent_b", agentName: "B", online: true},
	}

	got := svc.assembleTarget(target, pairs, time.Now().UTC(), nil, nil, nil, nil,
		metrics.AvailabilityRatio{}, nil, map[string]int{"agent_a": 2, "agent_b": 3})
	if got.Fluctuations24h != 5 {
		t.Fatalf("target fluctuations = %d, want 5 (2 + 3)", got.Fluctuations24h)
	}
	byAgent := map[string]int{}
	for _, a := range got.Agents {
		byAgent[a.AgentID] = a.Fluctuations24h
	}
	if byAgent["agent_a"] != 2 || byAgent["agent_b"] != 3 {
		t.Fatalf("per-agent fluctuations = %v, want a=2 b=3", byAgent)
	}
}

// TestFluctuationTotalTracksTheAvailabilityPopulation: the count explains the ratio
// printed beside it, so the two must be computed over the same agents.
//
// An agent removed from the group's scope keeps its round samples — nothing purges
// them — so it still drags the ratio below 100% for the rest of the window while no
// longer appearing as an applicable pair. Counting only pairs would show "0
// fluctuations" against a dipped ratio: the unexplained state this whole feature
// exists to eliminate.
func TestFluctuationTotalTracksTheAvailabilityPopulation(t *testing.T) {
	svc := &Service{}
	target := &targetRow{id: "target", kind: "icmp", enabled: true}
	pairs := []applicablePair{{agentID: "agent_live", agentName: "Live", online: true}}

	got := svc.assembleTarget(target, pairs, time.Now().UTC(), nil, nil, nil, nil,
		metrics.AvailabilityRatio{Rounds: 100, OKRounds: 97, Ratio: 0.97},
		map[string]metrics.AvailabilityRatio{
			"agent_live":     {AgentID: "agent_live", Rounds: 60, OKRounds: 59, Ratio: 0.983},
			"agent_outscope": {AgentID: "agent_outscope", Rounds: 40, OKRounds: 38, Ratio: 0.95},
		},
		map[string]int{"agent_live": 1, "agent_outscope": 2})
	if got.Fluctuations24h != 3 {
		t.Fatalf("total = %d, want 3: the out-of-scope agent still moves the ratio, so its dips explain it",
			got.Fluctuations24h)
	}

	// A DELETED agent is the mirror case: metrics.Store.PurgeAgent drops its series so
	// it no longer affects the ratio, while its fluctuations are deliberately kept as
	// history. Counting them would explain a dip the ratio no longer shows.
	got = svc.assembleTarget(target, pairs, time.Now().UTC(), nil, nil, nil, nil,
		metrics.AvailabilityRatio{Rounds: 60, OKRounds: 59, Ratio: 0.983},
		map[string]metrics.AvailabilityRatio{
			"agent_live": {AgentID: "agent_live", Rounds: 60, OKRounds: 59, Ratio: 0.983},
		},
		map[string]int{"agent_live": 1, "agent_deleted": 7})
	if got.Fluctuations24h != 1 {
		t.Fatalf("total = %d, want 1: a purged agent no longer moves the ratio, so its history must not explain it",
			got.Fluctuations24h)
	}
}
