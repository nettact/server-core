package fault

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The built-in detector's contract, in one place: it counts PROBE ROUNDS, not
// ingest batches; it confirms exactly once; it never invents a round it did not
// see; and it distinguishes a recovery from a configuration change. Every test
// below pins one of those.

type harness struct {
	t   *testing.T
	db  *store.DB
	svc *Service
	ctx context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db := storetest.Open(t)
	h := &harness{t: t, db: db, svc: New(db, nil, nil), ctx: context.Background()}
	h.exec(`INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	h.exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status,hostname) VALUES('agent_a','site_default',x'00','h','online','node-1')`)
	h.exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents) VALUES('mg','site_default','Default',1,0,1)`)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('t_icmp','site_default','mg','icmp','Router','192.168.1.1','{}',1,1)`)
	return h
}

func (h *harness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(h.ctx, q, args...); err != nil {
		h.t.Fatalf("exec %q: %v", q, err)
	}
}

// meta returns the icmp target's evaluation metadata with the given sensitivity.
func (h *harness) meta(det DetectionSettings) map[string]TargetMeta {
	return map[string]TargetMeta{
		"t_icmp": {ID: "t_icmp", Kind: "icmp", GroupID: "mg", Name: "Router", Addr: "192.168.1.1",
			Enabled: true, ConfigSerial: 1, Det: det.Normalize()},
	}
}

// loss builds one ICMP round's metrics at ts with the given loss percentage.
func loss(ts int64, pct float64) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPLoss, Target: "192.168.1.1",
		Value: pct, Unit: telemetry.UnitPct, MonitorID: "t_icmp", ConfigSerial: 1,
	}
}

// evaluate runs one ingest-equivalent pass over the given metrics.
func (h *harness) evaluate(det DetectionSettings, ms ...telemetry.Metric) *Outcome {
	h.t.Helper()
	rounds := BuildRounds(ms, h.meta(det))
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	out, err := h.svc.EvaluateAgentTx(h.ctx, store.AdaptTx(tx, store.Standalone()), "agent_a", "site_default", rounds)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("evaluate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
	return out
}

func (h *harness) firingSignals() []Signal {
	h.t.Helper()
	sigs, err := h.svc.ListActive(h.ctx, "site_default")
	if err != nil {
		h.t.Fatalf("list active: %v", err)
	}
	return sigs
}

func (h *harness) countSignals() int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM fault_signals`).Scan(&n); err != nil {
		h.t.Fatalf("count signals: %v", err)
	}
	return n
}

func (h *harness) countOpenIncidents() int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM incidents WHERE state='open'`).Scan(&n); err != nil {
		h.t.Fatalf("count incidents: %v", err)
	}
	return n
}

func (h *harness) detector() (failRounds, okRounds int, lastRoundTS int64) {
	h.t.Helper()
	err := h.db.QueryRowContext(h.ctx,
		`SELECT fail_rounds, ok_rounds, last_round_ts FROM detector_state WHERE target_id='t_icmp' AND agent_id='agent_a'`).
		Scan(&failRounds, &okRounds, &lastRoundTS)
	if err != nil {
		h.t.Fatalf("detector state: %v", err)
	}
	return
}

// TestConfirmsAfterThreeFailingRounds is the zero-config promise: a target that
// stops answering produces a recorded fault with no rule, no channel and no
// configuration of any kind.
func TestConfirmsAfterThreeFailingRounds(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(1000, 100))
	h.evaluate(det, loss(1010, 100))
	if got := h.countSignals(); got != 0 {
		t.Fatalf("two failing rounds must not confirm yet, got %d signals", got)
	}
	h.evaluate(det, loss(1020, 100))

	sigs := h.firingSignals()
	if len(sigs) != 1 {
		t.Fatalf("expected exactly one fault, got %d", len(sigs))
	}
	s := sigs[0]
	if s.TargetID != "t_icmp" || s.AgentID != "agent_a" || s.DetectorKey != DetectorAvailability {
		t.Fatalf("unexpected identity: %+v", s)
	}
	// observed_at is the FIRST failing round, not the confirming one, so the
	// recorded outage covers the whole failure rather than only its tail.
	if !s.ObservedAt.Equal(time.Unix(1000, 0).UTC()) {
		t.Fatalf("observed_at = %v, want the first failing round (1000)", s.ObservedAt)
	}
	if !s.ConfirmedAt.Equal(time.Unix(1020, 0).UTC()) {
		t.Fatalf("confirmed_at = %v, want the confirming round (1020)", s.ConfirmedAt)
	}
	// Display facts are frozen so a later rename cannot rewrite history.
	if s.TargetName != "Router" || s.TargetAddr != "192.168.1.1" || s.AgentName != "node-1" {
		t.Fatalf("display facts not frozen: %+v", s)
	}
	if h.countOpenIncidents() != 1 {
		t.Fatalf("expected the fault to open an incident")
	}
}

// TestOneBatchOfManyRoundsConfirms is the difference between counting rounds and
// counting uploads: an Agent draining its WAL delivers several cycles at once,
// and those are still three consecutive failures.
func TestOneBatchOfManyRoundsConfirms(t *testing.T) {
	h := newHarness(t)
	h.evaluate(DefaultDetection(), loss(1000, 100), loss(1010, 100), loss(1020, 100))
	if got := h.countSignals(); got != 1 {
		t.Fatalf("a backfilled batch of 3 failing rounds must confirm, got %d signals", got)
	}
}

// TestReplayedAndOutOfOrderRoundsDoNotAdvance pins the watermark: re-ingesting
// the same rounds, or receiving an older straggler, must not push the counter or
// re-decide anything.
func TestReplayedAndOutOfOrderRoundsDoNotAdvance(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	h.evaluate(det, loss(1000, 100), loss(1010, 100))
	// Replay the exact same rounds plus an older one.
	h.evaluate(det, loss(1000, 100), loss(1010, 100), loss(990, 100))
	fails, _, ts := h.detector()
	if fails != 2 {
		t.Fatalf("replayed rounds advanced the counter to %d, want 2", fails)
	}
	if ts != 1010 {
		t.Fatalf("watermark = %d, want 1010", ts)
	}
	if got := h.countSignals(); got != 0 {
		t.Fatalf("replay must not confirm a fault, got %d", got)
	}
}

// TestInconclusiveRoundIsNotAFailure: a cycle that emitted no loss metric at all
// is not a verdict. Synthesizing a failure there is what made blocked and
// unsupported targets look unreachable.
func TestInconclusiveRoundIsNotAFailure(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	// A round carrying only the error class, with no primary metric.
	onlyReason := telemetry.Metric{
		TS: time.Unix(1000, 0).UTC(), Kind: telemetry.ICMPErrorClass, Target: "192.168.1.1",
		Value: telemetry.ProbeReasonTimeout, MonitorID: "t_icmp", ConfigSerial: 1,
	}
	h.evaluate(det, onlyReason)
	h.evaluate(det, onlyReason)
	h.evaluate(det, onlyReason)
	if got := h.countSignals(); got != 0 {
		t.Fatalf("rounds with no verdict must not confirm a fault, got %d", got)
	}
}

// TestRecoveryClosesAfterTwoSucceedingRounds and, critically, keeps the history.
func TestRecoveryClosesAfterTwoSucceedingRounds(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	for i, ts := range []int64{1000, 1010, 1020} {
		_ = i
		h.evaluate(det, loss(ts, 100))
	}
	h.evaluate(det, loss(1030, 0))
	if len(h.firingSignals()) != 1 {
		t.Fatal("one succeeding round must not recover a 2-round recovery threshold")
	}
	h.evaluate(det, loss(1040, 0))

	if len(h.firingSignals()) != 0 {
		t.Fatal("expected the fault to resolve after two succeeding rounds")
	}
	// The record survives: a recovered fault is history, not a deletion.
	if h.countSignals() != 1 {
		t.Fatalf("recovered fault must be retained, got %d rows", h.countSignals())
	}
	var state, reason string
	if err := h.db.QueryRowContext(h.ctx, `SELECT state, resolve_reason FROM fault_signals`).Scan(&state, &reason); err != nil {
		t.Fatalf("read signal: %v", err)
	}
	if state != "resolved" || reason != ReasonRecovered {
		t.Fatalf("state=%s reason=%s, want resolved/recovered", state, reason)
	}
	if h.countOpenIncidents() != 0 {
		t.Fatal("expected the incident to close with its last member")
	}
}

// TestRefaultOpensANewSignal: a resolved fault never reopens, so the second
// outage is a second entry in the history rather than an edit of the first.
func TestRefaultOpensANewSignal(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	for _, ts := range []int64{1000, 1010, 1020} {
		h.evaluate(det, loss(ts, 100))
	}
	first := h.firingSignals()[0].ID
	h.evaluate(det, loss(1030, 0))
	h.evaluate(det, loss(1040, 0))
	for _, ts := range []int64{1050, 1060, 1070} {
		h.evaluate(det, loss(ts, 100))
	}
	sigs := h.firingSignals()
	if len(sigs) != 1 || sigs[0].ID == first {
		t.Fatalf("a second outage must be a new fault, got %+v (first %s)", sigs, first)
	}
	if h.countSignals() != 2 {
		t.Fatalf("expected two recorded faults, got %d", h.countSignals())
	}
}

// TestPartialLossThresholdIsHonoured: the one built-in tunable that changes what
// counts as a failure.
func TestPartialLossThresholdIsHonoured(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	det.ICMPLossPct = 30

	for _, ts := range []int64{1000, 1010, 1020} {
		h.evaluate(det, loss(ts, 40)) // 40% loss: below total, above the tuned floor
	}
	sigs := h.firingSignals()
	if len(sigs) != 1 {
		t.Fatalf("40%% loss against a 30%% threshold must confirm, got %d", len(sigs))
	}
	if sigs[0].Threshold != 30 || sigs[0].Value != 40 {
		t.Fatalf("frozen evidence = value %v threshold %v, want 40/30", sigs[0].Value, sigs[0].Threshold)
	}
}

// TestSensitivityChangeRestartsCounting: a streak measured under one threshold
// says nothing under another.
func TestSensitivityChangeRestartsCounting(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	h.evaluate(det, loss(1000, 100), loss(1010, 100))

	stricter := DefaultDetection()
	stricter.FailRounds = 5
	stricter.Revision = 2
	h.evaluate(stricter, loss(1020, 100))
	fails, _, _ := h.detector()
	if fails != 1 {
		t.Fatalf("a sensitivity change must restart the streak, got %d fails", fails)
	}
	if h.countSignals() != 0 {
		t.Fatal("expected no fault under the restarted streak")
	}
}

// TestTerminationIsNotARecovery: deleting or reconfiguring a failing target ends
// the fault under its own reason, so nothing downstream can announce a recovery
// that never happened.
func TestTerminationIsNotARecovery(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	for _, ts := range []int64{1000, 1010, 1020} {
		h.evaluate(det, loss(ts, 100))
	}

	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	ids, pub, err := h.svc.TerminateForTargetsTx(h.ctx, tx, []string{"t_icmp"}, ReasonTargetDeleted)
	if err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if pub != nil {
		pub(h.ctx)
	}
	if len(ids) != 1 || ids[0] != "t_icmp" {
		t.Fatalf("affected targets = %v, want [t_icmp]", ids)
	}

	var state, reason string
	if err := h.db.QueryRowContext(h.ctx, `SELECT state, resolve_reason FROM fault_signals`).Scan(&state, &reason); err != nil {
		t.Fatalf("read signal: %v", err)
	}
	if state != "resolved" || reason != ReasonTargetDeleted {
		t.Fatalf("state=%s reason=%s, want resolved/target_deleted", state, reason)
	}
	if IsRecovery(reason) {
		t.Fatal("a deletion must never be classified as a recovery")
	}
	var incReason string
	if err := h.db.QueryRowContext(h.ctx, `SELECT resolve_reason FROM incidents`).Scan(&incReason); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	if incReason != ReasonTargetDeleted {
		t.Fatalf("incident resolve_reason = %q, want target_deleted", incReason)
	}
	// The detector's counters go with the target.
	var n int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM detector_state`).Scan(&n); err != nil {
		t.Fatalf("count detector state: %v", err)
	}
	if n != 0 {
		t.Fatalf("detector state survived termination: %d rows", n)
	}
}

// TestStatePersistsAcrossRestart: the counters live in the database, so a restart
// mid-streak neither restarts the count nor re-opens a confirmed fault.
func TestStatePersistsAcrossRestart(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	h.evaluate(det, loss(1000, 100), loss(1010, 100))

	// A fresh Service over the same database is what a restart looks like.
	h.svc = New(h.db, nil, nil)
	h.evaluate(det, loss(1020, 100))
	if h.countSignals() != 1 {
		t.Fatalf("a restart must not lose the streak, got %d signals", h.countSignals())
	}

	h.svc = New(h.db, nil, nil)
	h.evaluate(det, loss(1030, 100))
	if h.countSignals() != 1 {
		t.Fatalf("a restart must not re-open a confirmed fault, got %d signals", h.countSignals())
	}
}

// TestReasonPairsOnlyWithinTheSameRound: a failure reason belongs to the cycle
// that produced it. Borrowing one from another round would misattribute a cause.
func TestReasonPairsOnlyWithinTheSameRound(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()
	reason := func(ts int64, code int) telemetry.Metric {
		return telemetry.Metric{
			TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPErrorClass, Target: "192.168.1.1",
			Value: float64(code), MonitorID: "t_icmp", ConfigSerial: 1,
			Labels: map[string]string{telemetry.ProbeReasonDetailLabel: "no route to host"},
		}
	}
	h.evaluate(det, loss(1000, 100), reason(1000, telemetry.ProbeReasonUnreachable))
	h.evaluate(det, loss(1010, 100), reason(1010, telemetry.ProbeReasonUnreachable))
	// The confirming round carries a DIFFERENT reason; that is the one frozen.
	h.evaluate(det, loss(1020, 100), reason(1020, telemetry.ProbeReasonTimeout))

	sigs := h.firingSignals()
	if len(sigs) != 1 {
		t.Fatalf("expected one fault, got %d", len(sigs))
	}
	if sigs[0].ReasonCode != telemetry.ProbeReasonTimeout {
		t.Fatalf("reason_code = %d, want the confirming round's timeout", sigs[0].ReasonCode)
	}
	if sigs[0].ReasonDetail != "no route to host" {
		t.Fatalf("reason_detail = %q, want the raw cause carried alongside", sigs[0].ReasonDetail)
	}
}

// TestAvailabilitySamplesSkipInconclusiveRounds: the availability denominator
// counts rounds that reached a verdict, so an unknown never reads as downtime.
func TestAvailabilitySamplesSkipInconclusiveRounds(t *testing.T) {
	h := newHarness(t)
	meta := h.meta(DefaultDetection())
	ms := []telemetry.Metric{loss(1000, 0), loss(1010, 100)}
	// A round with no primary metric contributes nothing.
	ms = append(ms, telemetry.Metric{
		TS: time.Unix(1020, 0).UTC(), Kind: telemetry.ICMPErrorClass, Target: "192.168.1.1",
		Value: 1, MonitorID: "t_icmp", ConfigSerial: 1,
	})
	samples := AvailabilitySamples(BuildRounds(ms, meta))
	if len(samples) != 2 {
		t.Fatalf("expected 2 availability samples (one per verdict), got %d", len(samples))
	}
	var sum float64
	for _, s := range samples {
		sum += s.Value
	}
	if sum != 1 {
		t.Fatalf("expected exactly one available round, got sum %v", sum)
	}
}

// TestAgentConnectivityFaultIsItsOwnIncident: an offline Agent must never be
// folded into a monitor group's incident, or one Agent's outage would absorb
// unrelated target faults.
func TestAgentConnectivityFaultIsItsOwnIncident(t *testing.T) {
	h := newHarness(t)
	now := time.Unix(2000, 0).UTC()
	id, err := h.svc.OpenAgentSignal(h.ctx, AgentSignalInput{
		AgentID: "agent_a", SiteID: "site_default", Name: "node-1",
		Reason: "unexpected", OfflineSince: now.Add(-time.Minute),
	}, now)
	if err != nil || id == "" {
		t.Fatalf("open agent signal: id=%q err=%v", id, err)
	}
	// Idempotent: a second call while firing changes nothing.
	again, err := h.svc.OpenAgentSignal(h.ctx, AgentSignalInput{
		AgentID: "agent_a", SiteID: "site_default", Name: "node-1", Reason: "unexpected",
	}, now)
	if err != nil || again != "" {
		t.Fatalf("second open should be a no-op, got id=%q err=%v", again, err)
	}

	var openKey, severity, groupID string
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT open_key, severity, group_id FROM incidents`).Scan(&openKey, &severity, &groupID); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	if openKey != "agent:agent_a" || severity != SeverityCritical || groupID != "" {
		t.Fatalf("agent incident = key %q severity %q group %q", openKey, severity, groupID)
	}

	var observed time.Time
	if err := h.db.QueryRowContext(h.ctx, `SELECT observed_at FROM fault_signals WHERE id=?`, id).Scan(&observed); err != nil {
		t.Fatalf("read signal: %v", err)
	}
	if !observed.UTC().Equal(now.Add(-time.Minute)) {
		t.Fatalf("observed_at = %v, want the last-seen time", observed)
	}

	if err := h.svc.ResolveAgentSignal(h.ctx, "agent_a", ReasonRecovered, now.Add(time.Minute)); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var state string
	var resolved sql.NullTime
	if err := h.db.QueryRowContext(h.ctx, `SELECT state, resolved_at FROM fault_signals WHERE id=?`, id).Scan(&state, &resolved); err != nil {
		t.Fatalf("read resolved signal: %v", err)
	}
	if state != "resolved" || !resolved.Valid {
		t.Fatalf("state=%s resolved_at valid=%v", state, resolved.Valid)
	}
}

// TestMergedGroupSharesOneIncident: with merging on, a group's faults are one
// user-facing event; with it off, each is its own.
func TestMergedGroupSharesOneIncident(t *testing.T) {
	h := newHarness(t)
	h.exec(`UPDATE monitor_groups SET merge_enabled=1 WHERE id='mg'`)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('t_dns','site_default','mg','dns','DNS','example.test','{}',1,1)`)

	det := DefaultDetection()
	meta := h.meta(det)
	meta["t_dns"] = TargetMeta{ID: "t_dns", Kind: "dns", GroupID: "mg", Name: "DNS", Addr: "example.test",
		Enabled: true, ConfigSerial: 1, Det: det}
	dnsFail := func(ts int64) telemetry.Metric {
		return telemetry.Metric{TS: time.Unix(ts, 0).UTC(), Kind: telemetry.DNSOK, Target: "example.test",
			Value: 0, Unit: telemetry.UnitBool, MonitorID: "t_dns", ConfigSerial: 1}
	}

	for _, ts := range []int64{1000, 1010, 1020} {
		rounds := BuildRounds([]telemetry.Metric{loss(ts, 100), dnsFail(ts)}, meta)
		tx, err := h.db.BeginTx(h.ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := h.svc.EvaluateAgentTx(h.ctx, store.AdaptTx(tx, store.Standalone()), "agent_a", "site_default", rounds); err != nil {
			_ = tx.Rollback()
			t.Fatalf("evaluate: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	if got := len(h.firingSignals()); got != 2 {
		t.Fatalf("expected two faults, got %d", got)
	}
	if got := h.countOpenIncidents(); got != 1 {
		t.Fatalf("a merging group must produce one incident, got %d", got)
	}
}

// TestConnectivitySignalReadsAsAbnormalWhileOffline pins the read-time overlay
// for the one detector that has no round counters. Agent liveness is driven by
// the connection tick, not by probe rounds, so a streak test would report every
// still-offline Agent as "answering again" — the opposite of the truth.
func TestConnectivitySignalReadsAsAbnormalWhileOffline(t *testing.T) {
	h := newHarness(t)
	now := time.Unix(2000, 0).UTC()
	if _, err := h.svc.OpenAgentSignal(h.ctx, AgentSignalInput{
		AgentID: "agent_a", SiteID: "site_default", Name: "node-1", Reason: "unexpected",
	}, now); err != nil {
		t.Fatalf("open agent signal: %v", err)
	}
	sigs, err := h.svc.ListSignals(h.ctx, SignalFilter{
		SiteID: "site_default", Detector: DetectorAgentConnectivity, State: "firing",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected one connectivity fault, got %d", len(sigs))
	}
	if !sigs[0].CurrentlyAbnormal {
		t.Fatal("a firing connectivity fault means the Agent is offline right now")
	}
	filtered, err := h.svc.ListSignals(h.ctx, SignalFilter{
		SiteID: "site_default", Detector: DetectorAgentConnectivity, Since: now.Add(time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("list with since: %v", err)
	}
	if len(filtered) != 0 {
		t.Fatalf("since after confirmation returned %d signals, want none", len(filtered))
	}
}

// TestSignalTitleIsLiteralInBothLanguages: the product may not upgrade "one probe
// did not answer" into "the device is down", in either language.
func TestSignalTitleIsLiteralInBothLanguages(t *testing.T) {
	icmp := Signal{DetectorKey: DetectorAvailability, ProbeKind: "icmp", TargetName: "Router"}
	for _, lang := range []string{"zh", "en"} {
		got := SignalTitleLang(icmp, lang)
		if got == "" {
			t.Fatalf("%s: empty title", lang)
		}
		if strings.Contains(strings.ToLower(got), "offline") || strings.Contains(got, "离线") {
			t.Fatalf("%s: an unanswered ICMP probe must not be reported as offline: %q", lang, got)
		}
	}
	agent := Signal{DetectorKey: DetectorAgentConnectivity, AgentName: "node-1"}
	if got := SignalTitleLang(agent, "en"); !strings.Contains(got, "offline") {
		t.Fatalf("an Agent-connectivity fault has direct evidence and may say offline, got %q", got)
	}
	if got := SignalTitleLang(agent, "zh"); !strings.Contains(got, "离线") {
		t.Fatalf("zh agent title = %q", got)
	}
}

// TestHealthyRoundsStillPersistTheWatermark guards a write optimization that was
// tried and reverted: skipping the detector row write when a batch was all green
// and only last_round_ts moved. It saves little (rowid table, one agent's rows
// are clustered) and costs correctness, because the un-persisted watermark is
// what the next batch uses to reject rounds it has already folded.
func TestHealthyRoundsStillPersistTheWatermark(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection()

	for _, ts := range []int64{1000, 1010, 1020, 1030} {
		h.evaluate(det, loss(ts, 0))
		if _, _, got := h.detector(); got != ts {
			t.Fatalf("watermark after green round %d = %d, want %d", ts, got, ts)
		}
	}
}

// TestHistoricalRoundsAreNotFoldedTwice is what the persisted watermark buys: a
// round at or before the newest already-folded one is history, not news. Folding
// failures the target has already been observed to recover from is how a dropped
// watermark turns into a fabricated incident — and a notification for it.
func TestHistoricalRoundsAreNotFoldedTwice(t *testing.T) {
	h := newHarness(t)
	det := DefaultDetection() // FailRounds = 3

	for _, ts := range []int64{1000, 1010, 1020, 1030} {
		h.evaluate(det, loss(ts, 0))
	}

	// A delayed packet carrying three failing rounds that are all at or before the
	// newest round already folded. They are history, not news: folding them would
	// confirm a fault for a window that has already been observed healthy.
	h.evaluate(det, loss(1000, 100), loss(1010, 100), loss(1020, 100))

	if got := h.countSignals(); got != 0 {
		t.Fatalf("re-folded historical rounds must not confirm a fault, got %d signals", got)
	}
	if fails, _, _ := h.detector(); fails != 0 {
		t.Fatalf("re-folded historical rounds must not start a streak, failRounds=%d", fails)
	}
}
