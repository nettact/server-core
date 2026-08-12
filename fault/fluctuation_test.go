package fault

import (
	"database/sql"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

// A fluctuation exists to close one specific hole: a dip that is visible in the
// availability figure and explained nowhere. These tests pin both halves of that
// — that a sub-threshold streak IS recorded with the cause of every round, and
// that things which are already explained elsewhere (a confirmed fault
// recovering, a streak an operator's edit cut short) are NOT recorded again here.

// reason builds the error_class sibling an ICMP round carries alongside its loss
// metric, which is where the failure cause comes from.
func reason(ts int64, code int, detail string) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPErrorClass, Target: "192.168.1.1",
		Value: float64(code), Unit: telemetry.UnitCode, MonitorID: "t_icmp", ConfigSerial: 1,
		Labels: map[string]string{telemetry.ProbeReasonDetailLabel: detail},
	}
}

func (h *harness) fluctuations() []Fluctuation {
	h.t.Helper()
	page, err := h.svc.ListFluctuations(h.ctx, FluctuationFilter{SiteID: "site_default"})
	if err != nil {
		h.t.Fatalf("list fluctuations: %v", err)
	}
	return page.Items
}

func (h *harness) countFluctuations() int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM fluctuations`).Scan(&n); err != nil {
		h.t.Fatalf("count fluctuations: %v", err)
	}
	return n
}

// pendingFails returns the staged streak evidence still on the detector row.
func (h *harness) pendingFails() []FailEvidence {
	h.t.Helper()
	var raw string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT pending_fails FROM detector_state WHERE target_id='t_icmp' AND agent_id='agent_a'`).Scan(&raw); err != nil {
		h.t.Fatalf("pending fails: %v", err)
	}
	return decodeRounds(raw)
}

// TestSubThresholdStreakIsRecorded is the whole feature: two failing rounds and a
// recovery leave no fault behind, and previously left nothing at all — now they
// leave a record saying exactly what failed, when, and why no alert fired.
func TestSubThresholdStreakIsRecorded(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection() // 3 to confirm

	h.evaluate(det, loss(1000, 100), reason(1000, telemetry.ProbeReasonTimeout, "i/o timeout"))
	h.evaluate(det, loss(1010, 100), reason(1010, telemetry.ProbeReasonUnreachable, "no route to host"))
	h.evaluate(det, loss(1020, 0), reason(1020, telemetry.ProbeReasonNone, ""))

	if got := h.countSignals(); got != 0 {
		t.Fatalf("a sub-threshold streak must not confirm a fault, got %d signals", got)
	}
	fls := h.fluctuations()
	if len(fls) != 1 {
		t.Fatalf("expected one fluctuation, got %d", len(fls))
	}
	fl := fls[0]
	if fl.FailRounds != 2 || fl.FailThreshold != 3 {
		t.Fatalf("expected 2 of 3 failing rounds, got %d of %d", fl.FailRounds, fl.FailThreshold)
	}
	// The window runs from the first failing round to the round that recovered, so
	// the operator can line it up against the availability chart.
	if fl.StartedAt.Unix() != 1000 || fl.EndedAt.Unix() != 1020 {
		t.Fatalf("window should be [1000,1020], got [%d,%d]", fl.StartedAt.Unix(), fl.EndedAt.Unix())
	}
	if fl.TargetID != "t_icmp" || fl.AgentID != "agent_a" || fl.TargetName != "Router" {
		t.Fatalf("display facts not frozen: %+v", fl)
	}
	// Summary evidence describes the LAST failing round, mirroring a signal's.
	if fl.ReasonCode != telemetry.ProbeReasonUnreachable || fl.ReasonDetail != "no route to host" {
		t.Fatalf("summary should be the last failing round, got %d %q", fl.ReasonCode, fl.ReasonDetail)
	}
	if fl.IncidentID != "" {
		t.Fatalf("an unlinked fluctuation must have no incident, got %q", fl.IncidentID)
	}
	// Both rounds, each with its own cause: "timed out then unreachable" is a
	// different story from "unreachable twice", and only this preserves it.
	if len(fl.Rounds) != 2 {
		t.Fatalf("expected per-round evidence for 2 rounds, got %d", len(fl.Rounds))
	}
	if fl.Rounds[0].TS != 1000 || fl.Rounds[0].ReasonCode != telemetry.ProbeReasonTimeout {
		t.Fatalf("first round evidence wrong: %+v", fl.Rounds[0])
	}
	if fl.Rounds[1].TS != 1010 || fl.Rounds[1].ReasonCode != telemetry.ProbeReasonUnreachable {
		t.Fatalf("second round evidence wrong: %+v", fl.Rounds[1])
	}
	if got := h.pendingFails(); len(got) != 0 {
		t.Fatalf("staged evidence must be cleared after recording, got %d", len(got))
	}
}

// TestStreakEvidenceSurvivesSeparateBatches is why the evidence is staged in the
// row rather than held in memory: each round arrives in its own transaction, and
// the round that ends the streak carries no failure cause of its own.
func TestStreakEvidenceSurvivesSeparateBatches(t *testing.T) {
	h := newHarness(t)
	det := DetectionSettings{Profile: ProfileCustom, FailRounds: 4, RecoverRounds: 1, ICMPLossPct: 100, Revision: 1}

	h.evaluate(det, loss(2000, 100), reason(2000, telemetry.ProbeReasonTimeout, "first"))
	if got := h.pendingFails(); len(got) != 1 || got[0].ReasonDetail != "first" {
		t.Fatalf("evidence should be staged across batches, got %+v", got)
	}
	h.evaluate(det, loss(2010, 100), reason(2010, telemetry.ProbeReasonRefused, "second"))
	h.evaluate(det, loss(2020, 100), reason(2020, telemetry.ProbeReasonReset, "third"))
	h.evaluate(det, loss(2030, 0), reason(2030, telemetry.ProbeReasonNone, ""))

	fls := h.fluctuations()
	if len(fls) != 1 {
		t.Fatalf("expected one fluctuation, got %d", len(fls))
	}
	want := []int{telemetry.ProbeReasonTimeout, telemetry.ProbeReasonRefused, telemetry.ProbeReasonReset}
	if len(fls[0].Rounds) != len(want) {
		t.Fatalf("expected %d rounds of evidence, got %d", len(want), len(fls[0].Rounds))
	}
	for i, code := range want {
		if fls[0].Rounds[i].ReasonCode != code {
			t.Fatalf("round %d: expected reason %d, got %d", i, code, fls[0].Rounds[i].ReasonCode)
		}
	}
}

// TestConfirmedFaultRecoveryIsNotAFluctuation keeps the two records from
// double-counting the same failures. A fault that recovers is already told in
// full by the fault centre; filing it again as a blip would inflate every
// fluctuation count with outages.
func TestConfirmedFaultRecoveryIsNotAFluctuation(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(3000, 100))
	h.evaluate(det, loss(3010, 100))
	h.evaluate(det, loss(3020, 100)) // confirms
	if got := h.pendingFails(); len(got) != 0 {
		t.Fatalf("confirming freezes its own evidence, so staging must clear: %+v", got)
	}
	h.evaluate(det, loss(3030, 0))
	h.evaluate(det, loss(3040, 0)) // resolves

	if len(h.firingSignals()) != 0 {
		t.Fatal("fault should have resolved")
	}
	if got := h.countFluctuations(); got != 0 {
		t.Fatalf("a recovering fault is not a fluctuation, got %d", got)
	}
}

// TestConfirmedFaultFreezesEveryRound is the consistency half of the change: an
// alert must explain itself the same way a fluctuation does. Three rounds that
// failed three different ways point at something a single frozen reason hides.
func TestConfirmedFaultFreezesEveryRound(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(4000, 100), reason(4000, telemetry.ProbeReasonTimeout, "t1"))
	h.evaluate(det, loss(4010, 100), reason(4010, telemetry.ProbeReasonTimeout, "t2"))
	h.evaluate(det, loss(4020, 100), reason(4020, telemetry.ProbeReasonRefused, "r1"))

	sigs := h.firingSignals()
	if len(sigs) != 1 {
		t.Fatalf("expected one signal, got %d", len(sigs))
	}
	if len(sigs[0].Rounds) != 3 {
		t.Fatalf("expected all 3 rounds frozen on the signal, got %d", len(sigs[0].Rounds))
	}
	if sigs[0].Rounds[0].ReasonCode != telemetry.ProbeReasonTimeout ||
		sigs[0].Rounds[2].ReasonCode != telemetry.ProbeReasonRefused {
		t.Fatalf("per-round causes not preserved in order: %+v", sigs[0].Rounds)
	}
	// The summary columns still describe the confirming round.
	if sigs[0].ReasonCode != telemetry.ProbeReasonRefused {
		t.Fatalf("summary should be the confirming round, got %d", sigs[0].ReasonCode)
	}
}

// TestReplayDoesNotDuplicateFluctuation: a re-delivered packet must not turn one
// dip into two, or a flaky uplink would manufacture the very noise this record is
// meant to explain away.
func TestReplayDoesNotDuplicateFluctuation(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	rounds := []telemetry.Metric{
		loss(5000, 100), reason(5000, telemetry.ProbeReasonTimeout, "x"),
		loss(5010, 0), reason(5010, telemetry.ProbeReasonNone, ""),
	}
	h.evaluate(det, rounds...)
	h.evaluate(det, rounds...) // same rounds again, below the watermark

	if got := h.countFluctuations(); got != 1 {
		t.Fatalf("replay must be idempotent, got %d fluctuations", got)
	}
	if n := len(h.fluctuations()[0].Rounds); n != 1 {
		t.Fatalf("expected 1 round of evidence, got %d", n)
	}
}

// TestConfigChangeDoesNotRecordFluctuation: a streak discarded because the
// operator edited the target is an artefact of that edit, not a network event.
func TestConfigChangeDoesNotRecordFluctuation(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(6000, 100), reason(6000, telemetry.ProbeReasonTimeout, "x"))
	h.evaluate(det, loss(6010, 100), reason(6010, telemetry.ProbeReasonTimeout, "y"))

	// Sensitivity revised: the streak measured under the old setting says nothing
	// about the new one, so it is dropped rather than recorded.
	newDet := DetectionSettings{Profile: ProfileCustom, FailRounds: 3, RecoverRounds: 2, ICMPLossPct: 100, Revision: 2}
	h.evaluate(newDet, loss(6020, 0), reason(6020, telemetry.ProbeReasonNone, ""))

	if got := h.countFluctuations(); got != 0 {
		t.Fatalf("a config-reset streak must not be recorded, got %d", got)
	}
	if got := h.pendingFails(); len(got) != 0 {
		t.Fatalf("staged evidence must be dropped with the streak, got %+v", got)
	}
}

// TestTwoDipsAreTwoFluctuations: each dip is its own record, so counting them
// tells the operator how unstable the link actually is.
func TestTwoDipsAreTwoFluctuations(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(7000, 100), reason(7000, telemetry.ProbeReasonTimeout, "a"))
	h.evaluate(det, loss(7010, 0))
	h.evaluate(det, loss(7020, 100), reason(7020, telemetry.ProbeReasonTimeout, "b"))
	h.evaluate(det, loss(7030, 100), reason(7030, telemetry.ProbeReasonTimeout, "c"))
	h.evaluate(det, loss(7040, 0))

	fls := h.fluctuations()
	if len(fls) != 2 {
		t.Fatalf("expected two fluctuations, got %d", len(fls))
	}
	// Newest first.
	if fls[0].FailRounds != 2 || fls[1].FailRounds != 1 {
		t.Fatalf("expected streaks of 2 then 1 (newest first), got %d and %d", fls[0].FailRounds, fls[1].FailRounds)
	}
}

// TestOutOfBandResolveDoesNotFluctuate guards the path where a firing signal is
// resolved without clearing the detector row (ResolveOutOfScope does exactly
// that). Carrying the streak forward would let the next succeeding round file the
// SAME failures a second time — once as an outage, once as a blip.
func TestOutOfBandResolveDoesNotFluctuate(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(8000, 100))
	h.evaluate(det, loss(8010, 100))
	h.evaluate(det, loss(8020, 100)) // confirms

	// Resolve behind the engine's back, leaving detector_state pointing at it.
	h.exec(`UPDATE fault_signals SET state='resolved', resolved_at=?, resolve_reason=? WHERE state='firing'`,
		time.Now().UTC(), ReasonAgentScopeChange)

	h.evaluate(det, loss(8030, 0))

	if got := h.countFluctuations(); got != 0 {
		t.Fatalf("failures already recorded as a fault must not be re-filed as a fluctuation, got %d", got)
	}
	failRounds, _, _ := h.detector()
	if failRounds != 0 {
		t.Fatalf("the terminated streak must not survive, fail_rounds=%d", failRounds)
	}
}

// TestSingleBatchDipRecords: a WAL backfill delivering the whole dip in one
// packet must record exactly what a live trickle would have.
func TestSingleBatchDipRecords(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det,
		loss(9000, 100), reason(9000, telemetry.ProbeReasonTimeout, "a"),
		loss(9010, 100), reason(9010, telemetry.ProbeReasonTimeout, "b"),
		loss(9020, 0), reason(9020, telemetry.ProbeReasonNone, ""),
	)
	fls := h.fluctuations()
	if len(fls) != 1 || fls[0].FailRounds != 2 || len(fls[0].Rounds) != 2 {
		t.Fatalf("one dip, two rounds expected; got %+v", fls)
	}
}

// TestPrecursorsLinkToConfirmedFault: once the target does fail outright, the
// blips that led up to it stop being trivia and become the incident's evidence —
// "it had been flapping first" is a different diagnosis from "it died suddenly".
func TestPrecursorsLinkToConfirmedFault(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	// A dip that recovers.
	h.evaluate(det, loss(10000, 100), reason(10000, telemetry.ProbeReasonTimeout, "pre"))
	h.evaluate(det, loss(10010, 0))
	// Then the real thing, minutes later.
	h.evaluate(det, loss(10100, 100))
	h.evaluate(det, loss(10110, 100))
	h.evaluate(det, loss(10120, 100)) // confirms

	sigs := h.firingSignals()
	if len(sigs) != 1 {
		t.Fatalf("expected one signal, got %d", len(sigs))
	}
	incidentID := sigs[0].IncidentID

	fls := h.fluctuations()
	if len(fls) != 1 {
		t.Fatalf("expected one fluctuation, got %d", len(fls))
	}
	if fls[0].IncidentID != incidentID {
		t.Fatalf("precursor should be linked to %s, got %q", incidentID, fls[0].IncidentID)
	}
	// Filterable as the incident's precursors, which is how the detail view asks.
	page, err := h.svc.ListFluctuations(h.ctx, FluctuationFilter{IncidentID: incidentID})
	if err != nil {
		h.t.Fatalf("list by incident: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("expected 1 precursor for the incident, got %d", page.Total)
	}
	// And announced on the timeline.
	var n int
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT COUNT(*) FROM incident_timeline WHERE incident_id=? AND kind='fluctuation.linked'`,
		incidentID).Scan(&n); err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected one fluctuation.linked timeline entry, got %d", n)
	}
}

// TestPrecursorWindowIsBounded: a blip from long before the fault is not
// presented as a warning sign of it. Claiming otherwise would make the annotation
// worthless, since every target blips eventually.
func TestPrecursorWindowIsBounded(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	base := int64(20000)

	h.evaluate(det, loss(base, 100), reason(base, telemetry.ProbeReasonTimeout, "old"))
	h.evaluate(det, loss(base+10, 0))

	// Well past fluctuationLinkWindow.
	far := base + int64(fluctuationLinkWindow.Seconds()) + 600
	h.evaluate(det, loss(far, 100))
	h.evaluate(det, loss(far+10, 100))
	h.evaluate(det, loss(far+20, 100)) // confirms

	if got := h.fluctuations()[0].IncidentID; got != "" {
		t.Fatalf("a fluctuation outside the lookback window must stay unlinked, got %q", got)
	}
}

// TestPrecursorKeepsItsFirstOwner: a precursor belongs to the outage it preceded.
// Re-pointing it at a later fault would rewrite the earlier incident's evidence.
func TestPrecursorKeepsItsFirstOwner(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(30000, 100), reason(30000, telemetry.ProbeReasonTimeout, "pre"))
	h.evaluate(det, loss(30010, 0))
	h.evaluate(det, loss(30100, 100))
	h.evaluate(det, loss(30110, 100))
	h.evaluate(det, loss(30120, 100)) // first fault
	first := h.firingSignals()[0].IncidentID
	h.evaluate(det, loss(30130, 0))
	h.evaluate(det, loss(30140, 0)) // resolves

	// A second fault soon after, still inside the lookback window.
	h.evaluate(det, loss(30200, 100))
	h.evaluate(det, loss(30210, 100))
	h.evaluate(det, loss(30220, 100))
	second := h.firingSignals()[0].IncidentID
	if first == second {
		t.Fatal("expected a distinct second incident")
	}
	if got := h.fluctuations()[0].IncidentID; got != first {
		t.Fatalf("precursor must stay with its first owner %s, got %q", first, got)
	}
}

// TestLinkedFluctuationSurvivesRetention: retention ages out the noise, but a
// fluctuation promoted to incident evidence is not noise — it is part of the
// record of an outage, and it goes when that record goes, not on a timer.
func TestLinkedFluctuationSurvivesRetention(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	// A dip long before anything else, which stays unlinked.
	h.evaluate(det, loss(45000, 100), reason(45000, telemetry.ProbeReasonTimeout, "lonely"))
	h.evaluate(det, loss(45010, 0))
	// A dip shortly before a fault, which becomes its precursor.
	h.evaluate(det, loss(49800, 100), reason(49800, telemetry.ProbeReasonTimeout, "pre"))
	h.evaluate(det, loss(49810, 0))
	h.evaluate(det, loss(50000, 100))
	h.evaluate(det, loss(50010, 100))
	h.evaluate(det, loss(50020, 100)) // confirms, linking the second dip only
	incidentID := h.firingSignals()[0].IncidentID

	if got := h.countFluctuations(); got != 2 {
		t.Fatalf("expected 2 fluctuations before pruning, got %d", got)
	}
	// Both are far older than any cutoff (they sit at epoch 40k).
	n, err := h.svc.PruneFluctuations(h.ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly the unlinked one pruned, got %d", n)
	}
	fls := h.fluctuations()
	if len(fls) != 1 || fls[0].IncidentID != incidentID {
		t.Fatalf("the linked precursor must survive, got %+v", fls)
	}

	// And it goes with the incident it belongs to (FK cascade).
	h.exec(`DELETE FROM fault_signals WHERE incident_id=?`, incidentID)
	h.exec(`DELETE FROM incidents WHERE id=?`, incidentID)
	if got := h.countFluctuations(); got != 0 {
		t.Fatalf("deleting the incident must cascade to its precursors, got %d", got)
	}
}

// TestEvaluationGapBreaksTheStreak is the "agent died mid-streak" case. Nothing
// else expires a failing streak — an Agent going offline leaves the availability
// detector's counters exactly as they were, because its own connectivity fault
// covers the outage — so a streak could otherwise be stitched across a day-long
// hole and reported as consecutive rounds.
//
// The streak is abandoned, but it is not erased: those rounds really did fail,
// and a target that failed twice and then went unobserved (a rebooting router, a
// replayed backlog) would otherwise leave nothing at all to explain the dip in
// its availability. What must never happen is the dip being recorded as the
// width of the HOLE, so the record ends at the last failing round.
func TestEvaluationGapBreaksTheStreak(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection() // 3 to confirm

	// Two failures, then the Agent goes away.
	h.evaluate(det, loss(200000, 100), reason(200000, telemetry.ProbeReasonTimeout, "before"))
	h.evaluate(det, loss(200010, 100), reason(200010, telemetry.ProbeReasonTimeout, "before"))

	// A day later it comes back and answers.
	h.evaluate(det, loss(200000+86400, 0))

	if got := h.countFluctuations(); got != 1 {
		t.Fatalf("the abandoned streak must be recorded, got %d", got)
	}
	f := h.fluctuations()[0]
	// The decisive assertion: a 19-hour "2 of 3" dip would be a fabrication.
	if got := f.StartedAt.Unix(); got != 200000 {
		t.Fatalf("started_at = %d, want the first failing round (200000)", got)
	}
	if got := f.EndedAt.Unix(); got != 200010 {
		t.Fatalf("ended_at = %d, want the last FAILING round (200010), not the far side of the gap", got)
	}
	if f.FailRounds != 2 {
		t.Fatalf("fail_rounds = %d, want the 2 rounds that were actually observed", f.FailRounds)
	}
	failRounds, _, _ := h.detector()
	if failRounds != 0 {
		t.Fatalf("the abandoned streak must not survive the gap, fail_rounds=%d", failRounds)
	}
}

// TestEvaluationGapDoesNotConfirmAcrossTheHole is the same hazard on the fault
// path: two failures, a long silence, one more failure. Confirming here would
// assert three consecutive rounds over a day and freeze evidence from both sides
// of a hole nobody observed.
func TestEvaluationGapDoesNotConfirmAcrossTheHole(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(300000, 100), reason(300000, telemetry.ProbeReasonTimeout, "before"))
	h.evaluate(det, loss(300010, 100), reason(300010, telemetry.ProbeReasonTimeout, "before"))
	h.evaluate(det, loss(300000+86400, 100), reason(300000+86400, telemetry.ProbeReasonTimeout, "after"))

	if got := h.countSignals(); got != 0 {
		t.Fatalf("rounds either side of a day-long gap are not consecutive, got %d signals", got)
	}
	// Counting restarted, so this round is the first of a new streak.
	failRounds, _, _ := h.detector()
	if failRounds != 1 {
		t.Fatalf("post-gap round should start a fresh streak, fail_rounds=%d", failRounds)
	}
	if got := h.pendingFails(); len(got) != 1 || got[0].ReasonDetail != "after" {
		t.Fatalf("staged evidence should hold only the post-gap round, got %+v", got)
	}
}

// TestNormalCadenceIsNotTreatedAsAGap guards the other direction: the tolerance is
// derived from the target's own schedule, so ordinary jitter — a missed cycle, a
// late WAL flush — must not shred a legitimate streak.
func TestNormalCadenceIsNotTreatedAsAGap(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	// ICMP's window is StaleAfter(10s, 10s, 30s) = 90s, so a 25s stutter between
	// rounds is within tolerance and the streak stands.
	h.evaluate(det, loss(400000, 100))
	h.evaluate(det, loss(400025, 100))
	h.evaluate(det, loss(400050, 100))

	if got := h.countSignals(); got != 1 {
		t.Fatalf("a streak at tolerable cadence must still confirm, got %d signals", got)
	}
}

// TestLongIntervalTargetToleratesItsOwnCadence: the tolerance follows the target's
// configured interval. A NAT target polls every 30 minutes by default, so a
// half-hour gap between its rounds is its normal cadence, not a hole — a fixed
// threshold tuned for ICMP would make such a target unable to ever confirm.
func TestLongIntervalTargetToleratesItsOwnCadence(t *testing.T) {
	h := newHarness(t)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	        VALUES('t_slow','site_default','mg','http','Slow','https://example.test','{"interval_seconds":1800}',1,1)`)
	det := DefaultDetection()
	meta := map[string]TargetMeta{
		"t_slow": {ID: "t_slow", Kind: "http", GroupID: "mg", Name: "Slow", Addr: "https://example.test",
			Enabled: true, ConfigSerial: 1, Det: det.Normalize(),
			MaxRoundGap: roundGapForTest("http", 1800)},
	}
	ok := func(ts int64, v float64) telemetry.Metric {
		return telemetry.Metric{
			TS: time.Unix(ts, 0).UTC(), Kind: telemetry.HTTPOK, Target: "https://example.test",
			Value: v, Unit: telemetry.UnitBool, MonitorID: "t_slow", ConfigSerial: 1,
		}
	}
	for _, ts := range []int64{500000, 500000 + 1800, 500000 + 3600} {
		tx, err := h.db.BeginTx(h.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.svc.EvaluateAgentTx(h.ctx, store.AdaptTx(tx, store.Standalone()), "agent_a", "site_default",
			BuildRounds([]telemetry.Metric{ok(ts, 0)}, meta)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("evaluate: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.countSignals(); got != 1 {
		t.Fatalf("a 30-minute-interval target must confirm on its own cadence, got %d signals", got)
	}
}

// roundGapForTest mirrors what ingest computes for a target, so a test can pin the
// interval-derived tolerance without going through the ingest gate.
func roundGapForTest(kind string, intervalSeconds int) time.Duration {
	p := pcfg.ProbeParams{IntervalSeconds: intervalSeconds}
	return pcfg.StaleAfter(pcfg.EffectiveInterval(kind, p), pcfg.CycleDeadline(kind, p), 0)
}

// addSecondTarget registers another ICMP target under the same agent and returns
// an evaluator for it, so concurrency across targets can be exercised.
func (h *harness) addSecondTarget(det DetectionSettings) func(ms ...telemetry.Metric) {
	h.t.Helper()
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	        VALUES('t_two','site_default','mg','icmp','Uplink','10.0.0.1','{}',1,1)`)
	meta := map[string]TargetMeta{
		"t_two": {ID: "t_two", Kind: "icmp", GroupID: "mg", Name: "Uplink", Addr: "10.0.0.1",
			Enabled: true, ConfigSerial: 1, Det: det.Normalize()},
	}
	return func(ms ...telemetry.Metric) {
		h.t.Helper()
		tx, err := h.db.BeginTx(h.ctx, nil)
		if err != nil {
			h.t.Fatalf("begin: %v", err)
		}
		if _, err := h.svc.EvaluateAgentTx(h.ctx, store.AdaptTx(tx, store.Standalone()), "agent_a", "site_default", BuildRounds(ms, meta)); err != nil {
			_ = tx.Rollback()
			h.t.Fatalf("evaluate second target: %v", err)
		}
		if err := tx.Commit(); err != nil {
			h.t.Fatalf("commit: %v", err)
		}
	}
}

// lossFor builds a loss round for an arbitrary monitor/address.
func lossFor(monitorID, addr string, ts int64, pct float64) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPLoss, Target: addr,
		Value: pct, Unit: telemetry.UnitPct, MonitorID: monitorID, ConfigSerial: 1,
	}
}

// TestConcurrencyDistinguishesLinkFromTarget is the question a single record
// cannot answer: was it the network, or was it this one target? Two targets
// blipping in the same seconds means the link; one blipping alone means the
// target. The read layer has to say which, or the operator is left guessing.
func TestConcurrencyDistinguishesLinkFromTarget(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	evalTwo := h.addSecondTarget(det)

	// Both targets dip at the same time.
	h.evaluate(det, loss(60000, 100), reason(60000, telemetry.ProbeReasonTimeout, "a"))
	evalTwo(lossFor("t_two", "10.0.0.1", 60000, 100))
	h.evaluate(det, loss(60010, 0))
	evalTwo(lossFor("t_two", "10.0.0.1", 60010, 0))

	// Later, only the first target dips.
	h.evaluate(det, loss(70000, 100), reason(70000, telemetry.ProbeReasonTimeout, "b"))
	h.evaluate(det, loss(70010, 0))

	page, err := h.svc.ListFluctuations(h.ctx, FluctuationFilter{TargetID: "t_icmp"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("expected 2 fluctuations for t_icmp, got %d", len(page.Items))
	}
	alone, together := page.Items[0], page.Items[1] // newest first
	if together.ConcurrentFluctuations != 1 {
		t.Fatalf("simultaneous dip should see 1 other target, got %d", together.ConcurrentFluctuations)
	}
	if alone.ConcurrentFluctuations != 0 {
		t.Fatalf("isolated dip should see no other target, got %d", alone.ConcurrentFluctuations)
	}
}

// TestConcurrencyCountsOverlappingFaults: a neighbour in full outage while this
// target merely blipped is the strongest hint of a shared cause there is, so it
// must be counted too, not just other blips.
func TestConcurrencyCountsOverlappingFaults(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	evalTwo := h.addSecondTarget(det)

	// The neighbour fails outright.
	evalTwo(lossFor("t_two", "10.0.0.1", 80000, 100))
	evalTwo(lossFor("t_two", "10.0.0.1", 80010, 100))
	evalTwo(lossFor("t_two", "10.0.0.1", 80020, 100)) // confirms, still firing

	// This target only blips, inside the neighbour's outage.
	h.evaluate(det, loss(80030, 100), reason(80030, telemetry.ProbeReasonTimeout, "x"))
	h.evaluate(det, loss(80040, 0))

	page, err := h.svc.ListFluctuations(h.ctx, FluctuationFilter{TargetID: "t_icmp"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 fluctuation, got %d", len(page.Items))
	}
	if page.Items[0].ConcurrentFaults != 1 {
		t.Fatalf("expected 1 concurrent fault on another target, got %d", page.Items[0].ConcurrentFaults)
	}
}

// TestListTotalIgnoresLimit: the console shows "N fluctuations in 24h" beside an
// availability figure while fetching only a page of them, so the total has to
// count the filter's full match set.
func TestListTotalIgnoresLimit(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	for i := int64(0); i < 4; i++ {
		ts := 90000 + i*100
		h.evaluate(det, loss(ts, 100), reason(ts, telemetry.ProbeReasonTimeout, "x"))
		h.evaluate(det, loss(ts+10, 0))
	}
	page, err := h.svc.ListFluctuations(h.ctx, FluctuationFilter{TargetID: "t_icmp", Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("limit should cap the page at 2, got %d", len(page.Items))
	}
	if page.Total != 4 {
		t.Fatalf("total should count all 4 matches, got %d", page.Total)
	}
	// Newest first.
	if !page.Items[0].EndedAt.After(page.Items[1].EndedAt) {
		t.Fatalf("expected newest-first ordering, got %v then %v", page.Items[0].EndedAt, page.Items[1].EndedAt)
	}
}

// TestListFiltersByTimeRange: the target history page selects a window, and a
// fluctuation outside it must not appear in that window's evidence.
func TestListFiltersByTimeRange(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(100000, 100), reason(100000, telemetry.ProbeReasonTimeout, "old"))
	h.evaluate(det, loss(100010, 0))
	h.evaluate(det, loss(200000, 100), reason(200000, telemetry.ProbeReasonTimeout, "new"))
	h.evaluate(det, loss(200010, 0))

	page, err := h.svc.ListFluctuations(h.ctx, FluctuationFilter{Since: 150000})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("expected only the newer fluctuation, got total=%d items=%d", page.Total, len(page.Items))
	}
	if page.Items[0].EndedAt.Unix() != 200010 {
		t.Fatalf("wrong fluctuation returned: ended at %d", page.Items[0].EndedAt.Unix())
	}
}

// TestReplayAfterDetectorWipeDoesNotDuplicate: the watermark is not the only thing
// protecting against a double record. A sensitivity edit deletes detector_state
// WITHOUT bumping the config serial, so an unacked batch retried afterwards is
// still accepted by the generation filter and re-folds from a watermark of zero.
// The streak's natural key is what makes that harmless.
func TestReplayAfterDetectorWipeDoesNotDuplicate(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	rounds := []telemetry.Metric{
		loss(600000, 100), reason(600000, telemetry.ProbeReasonTimeout, "x"),
		loss(600010, 0),
	}
	h.evaluate(det, rounds...)
	if got := h.countFluctuations(); got != 1 {
		t.Fatalf("expected 1 fluctuation, got %d", got)
	}

	// Sensitivity edit: detector_state is cleared, generation untouched.
	h.exec(`DELETE FROM detector_state WHERE target_id='t_icmp' AND agent_id='agent_a'`)

	h.evaluate(det, rounds...) // the withheld batch is retried
	if got := h.countFluctuations(); got != 1 {
		t.Fatalf("a replay after a detector wipe must not re-file the dip, got %d", got)
	}
}

// TestPrecursorMustPrecede: a merged monitor group shares one incident across many
// members' confirmations, so an incident can be hours old when this target joins
// it. A dip that happened after the incident opened is not a warning sign of it.
func TestPrecursorMustPrecede(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	h.exec(`UPDATE monitor_groups SET merge_enabled=1 WHERE id='mg'`)
	evalTwo := h.addSecondTarget(det)

	// Target two confirms first and opens the group incident.
	evalTwo(lossFor("t_two", "10.0.0.1", 700000, 100))
	evalTwo(lossFor("t_two", "10.0.0.1", 700010, 100))
	evalTwo(lossFor("t_two", "10.0.0.1", 700020, 100))

	// Later, t_icmp dips and recovers — AFTER that incident opened.
	h.evaluate(det, loss(700100, 100), reason(700100, telemetry.ProbeReasonTimeout, "later"))
	h.evaluate(det, loss(700110, 0))

	// Then t_icmp itself confirms and joins the same (merged) incident.
	h.evaluate(det, loss(700200, 100))
	h.evaluate(det, loss(700210, 100))
	h.evaluate(det, loss(700220, 100))

	fls := h.fluctuations()
	if len(fls) != 1 {
		t.Fatalf("expected one fluctuation, got %d", len(fls))
	}
	// It PRECEDED t_icmp's own streak (700200), so it is a legitimate precursor.
	if fls[0].IncidentID == "" {
		t.Fatal("a dip before this target's own streak should link")
	}

	// Now the reverse: a dip after the streak began cannot be linked. Recorded by
	// hand because a dip cannot occur inside an unbroken confirming streak.
	h.exec(`INSERT INTO fluctuations(id, site_id, agent_id, target_id, fail_rounds, fail_threshold,
	          started_at, ended_at)
	        VALUES('flx_after','site_default','agent_a','t_icmp',1,3,?,?)`,
		timeFromUnix(700300), timeFromUnix(700310))
	var linked sql.NullString
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT incident_id FROM fluctuations WHERE id='flx_after'`).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked.Valid {
		t.Fatalf("a dip after the incident opened must not be claimed, got %q", linked.String)
	}
}

// TestConcurrentTargetsIsAUnion: a neighbour that dipped and then failed outright
// appears in both breakdowns and is still ONE other target. The headline count is
// what the operator reads to decide whether to look at the link or at this target,
// so overstating it sends them the wrong way.
func TestConcurrentTargetsIsAUnion(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	evalTwo := h.addSecondTarget(det)

	// The neighbour dips, recovers, then fails outright — all inside one window.
	evalTwo(lossFor("t_two", "10.0.0.1", 800000, 100))
	evalTwo(lossFor("t_two", "10.0.0.1", 800010, 0))
	evalTwo(lossFor("t_two", "10.0.0.1", 800020, 100))
	evalTwo(lossFor("t_two", "10.0.0.1", 800030, 100))
	evalTwo(lossFor("t_two", "10.0.0.1", 800040, 100)) // confirms

	// This target only dips, at its own 10s cadence, overlapping the neighbour's dip;
	// the neighbour's fault is still firing so its span runs to now and overlaps too.
	h.evaluate(det, loss(800005, 100), reason(800005, telemetry.ProbeReasonTimeout, "x"))
	h.evaluate(det, loss(800015, 0))

	page, err := h.svc.ListFluctuations(h.ctx, FluctuationFilter{TargetID: "t_icmp"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 fluctuation, got %d", len(page.Items))
	}
	fl := page.Items[0]
	if fl.ConcurrentFluctuations != 1 || fl.ConcurrentFaults != 1 {
		t.Fatalf("expected both breakdowns to see the neighbour, got %d dips %d faults",
			fl.ConcurrentFluctuations, fl.ConcurrentFaults)
	}
	if fl.ConcurrentTargets != 1 {
		t.Fatalf("one neighbour in both sets is ONE other target, got %d", fl.ConcurrentTargets)
	}
}

// TestPruneReleasesExpiredIncidentEvidence: linking a fluctuation puts it on the
// incident's lifecycle, which must not mean "forever". Nothing in the product
// deletes an incident row, so the cascade alone would never fire; the exemption has
// to end when the incident's other evidence is retired.
func TestPruneReleasesExpiredIncidentEvidence(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(900000, 100), reason(900000, telemetry.ProbeReasonTimeout, "pre"))
	h.evaluate(det, loss(900010, 0))
	h.evaluate(det, loss(900100, 100))
	h.evaluate(det, loss(900110, 100))
	h.evaluate(det, loss(900120, 100)) // confirms, linking the dip
	incidentID := h.firingSignals()[0].IncidentID

	// While the incident still holds its evidence, the precursor is exempt.
	if n, err := h.svc.PruneFluctuations(h.ctx, time.Now().UTC()); err != nil || n != 0 {
		t.Fatalf("linked precursor must survive while the incident holds evidence (n=%d err=%v)", n, err)
	}

	// incidentops.Retention retires the incident's evidence; the precursor goes too.
	h.exec(`UPDATE incidents SET state='resolved', evidence_expired=1 WHERE id=?`, incidentID)
	n, err := h.svc.PruneFluctuations(h.ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected the precursor to go with the incident's evidence, pruned %d", n)
	}
	if got := h.countFluctuations(); got != 0 {
		t.Fatalf("expected no fluctuations left, got %d", got)
	}
}

// TestPruneKeepsRecentFluctuations: the cutoff is on the recovery moment, so a
// dip from this morning survives a 30-day retention while last month's goes.
func TestPruneKeepsRecentFluctuations(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	now := time.Now().UTC()
	recent := now.Add(-time.Hour).Unix()

	h.evaluate(det, loss(recent, 100), reason(recent, telemetry.ProbeReasonTimeout, "recent"))
	h.evaluate(det, loss(recent+10, 0))

	n, err := h.svc.PruneFluctuations(h.ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 0 {
		t.Fatalf("a fluctuation newer than the cutoff must survive, pruned %d", n)
	}
	if got := h.countFluctuations(); got != 1 {
		t.Fatalf("expected the recent fluctuation to remain, got %d", got)
	}
}
