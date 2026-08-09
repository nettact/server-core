package fault

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/nettact/server-core/baseline"
)

// The degradation detectors (ALERT-003) answer a question the availability
// detector structurally cannot: the target is answering, and it is worse than it
// normally is.
//
// # Why they ride inside the availability walk
//
// They advance in the SAME per-round loop as availability, over the same Round
// values, inside the same ingest transaction. Not as a separate sweeper, for two
// reasons that are really one:
//
//   - Mutual exclusion has to be exact. A target that is down produces garbage
//     latency (or none), and an outage must never also be reported as "slow". The
//     only way to know whether availability was failing AT THE MOMENT of a given
//     round — rather than "at some point in the batch", or worse "right now" — is
//     to consult the availability counters as that round updates them.
//   - Everything the availability detector already got right about replay is worth
//     inheriting rather than re-deriving: one round at a time in timestamp order,
//     a watermark that makes a replayed packet a no-op, and a gap rule that
//     refuses to call two rounds consecutive across a hole.
//
// # What is deliberately different from availability
//
// Slower to confirm (a trend, not an event), info severity (recorded, not
// announced, until an operator lowers their policy floor), its own incident
// open_key (so "slow" never merges into an "unreachable" incident and muddies its
// attribution), no precursor linking (fluctuations are availability evidence), and
// a freshness gate availability deliberately does not have — see degCheck.advance.

// degCheck is one degradation detector's live state for one target: which metric
// it judges, under which detector key, and the row it is folding into.
type degCheck struct {
	key        string
	metricKind string
	st         detectorState
}

// degradationChecks returns the degradation detectors that should run for a
// target, given its kind and settings. Empty when smart detection is off, when
// the probe kind has no meaningful latency baseline (host, nat), or — for loss
// only — when the operator has already stated their own loss tolerance.
func degradationChecks(det DetectionSettings, probeKind string) []degCheck {
	kinds := DegradationMetricKinds(det, probeKind)
	out := make([]degCheck, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, degCheck{key: DegradationDetectorKey(k), metricKind: k})
	}
	return out
}

// DegradationMetricKinds lists the metric kinds a target's degradation detectors
// will judge. Exported because ingest has to know which baselines to fetch BEFORE
// it opens its write transaction, and asking the detector what it is about to
// need is better than a second copy of the rule that drifts from this one.
func DegradationMetricKinds(det DetectionSettings, probeKind string) []string {
	if !det.SmartEnabled {
		return nil
	}
	var out []string
	if k := baseline.LatencyKind(probeKind); k != "" {
		out = append(out, k)
	}
	if k := baseline.LossKind(probeKind); k != "" && !SmartLossSilenced(det) {
		out = append(out, k)
	}
	return out
}

// loadDegradationChecks builds the runnable check set for a target and loads each
// one's stored counters, applying the same generation/revision pin the
// availability detector uses.
func loadDegradationChecks(ctx context.Context, tx *sql.Tx, targetID, agentID string, cur Round) ([]degCheck, error) {
	checks := degradationChecks(cur.Det, cur.Kind)
	for i := range checks {
		st, err := loadDetectorState(ctx, tx, targetID, agentID, checks[i].key)
		if err != nil {
			return nil, err
		}
		// A streak measured under a different target generation or a different
		// sensitivity says nothing about the current one. The firing signal, if any,
		// was already terminated by the config path that caused the advance.
		if st.exists && (st.configSerial != cur.ConfigSerial || st.detectionRev != cur.Det.Revision) {
			resetDegradationStreak(&st)
			st.lastRoundTS = 0
		}
		checks[i].st = st
	}
	return checks, nil
}

// resetDegradationStreak clears the counters but NOT the active signal. A firing
// degradation ends only by recovering (or by a termination path), never by the
// detector losing track of its streak.
func resetDegradationStreak(st *detectorState) {
	st.failRounds, st.okRounds = 0, 0
	st.firstFailTS = sql.NullInt64{}
	st.pendingFails = nil
}

// availabilityView is the availability detector's verdict for the SAME round,
// read after it updated. Two facts rather than one because they call for
// different responses: a target that is merely stumbling must not contribute
// degradation evidence, while a target the product has actually declared down
// must not be described as "slow" at all.
type availabilityView struct {
	// failing is any failing streak in progress, confirmed or not.
	failing bool
	// confirmed is an availability fault the product has actually opened.
	confirmed bool
}

// advance folds one round into one degradation check.
func (s *Service) advance(ctx context.Context, tx *sql.Tx, c *degCheck,
	agentID, siteID, agentName string, r Round, avail availabilityView, now time.Time, out *txOut) error {
	st := &c.st
	if r.TS <= st.lastRoundTS {
		return nil // duplicate or straggler: never advances, rewinds or re-decides
	}
	gap := int64(r.Meta.maxRoundGap().Seconds())
	skew := now.Unix() - r.TS

	// A round stamped further into the FUTURE than one gap comes from an Agent
	// whose clock runs ahead. It is dropped whole — before the watermark moves —
	// and that ordering is the point: a watermark parked in the future would
	// reject every honest round until wall time caught up with the bad clock,
	// silently disabling degradation detection on that Agent for as long as the
	// skew lasts. Refusing to record it at all leaves the detector exactly where
	// the last real round left it.
	if skew < -gap {
		return nil
	}
	if st.failRounds > 0 && st.lastRoundTS > 0 && r.TS-st.lastRoundTS > gap {
		resetDegradationStreak(st)
	}
	st.lastRoundTS = r.TS

	// An availability fault that has actually confirmed ENDS any degradation
	// firing on this target. The two are mutually exclusive claims: leaving both
	// open tells the operator the target is simultaneously unreachable and merely
	// slow, and the second one stops being something anybody can act on the
	// moment the first is true. Resolved as superseded rather than recovered —
	// nothing recovered, a more fundamental fault took over — so no recovery
	// notice goes out.
	if avail.confirmed && st.signalID.Valid {
		if err := s.resolveSignal(ctx, tx, st.signalID.String, ReasonSuperseded, timeFromUnix(r.TS), now, out); err != nil {
			return err
		}
		st.signalID = sql.NullString{}
	}

	// Three ways a round is unjudgeable, all of which also break the streak,
	// because a streak is a claim of consecutive EVIDENCE and none of these is any:
	//
	//  1. Stale. The round is older than one round-gap, so it arrived through a WAL
	//     backfill after a reconnect. Availability judges backfill on purpose — an
	//     outage that happened, happened, and its incident should exist. Degradation
	//     must not: it is a low-severity observation about how things are going, and
	//     narrating "your network was slow an hour ago, before the Agent came back"
	//     is noise nobody can act on. It would also fire on the recovery pattern
	//     itself, since the rounds around an outage are exactly the slow ones.
	//  2. Availability is failing right now. Down is not slow. The latencies a
	//     failing target reports are meaningless when they exist at all, and letting
	//     them accumulate would confirm a degradation the moment the outage ends.
	//  3. The round itself did not succeed. Same reason, one round earlier.
	if skew > gap || avail.failing || r.Class != RoundSuccess {
		resetDegradationStreak(st)
		return nil
	}

	band, haveBand := r.Baselines[c.metricKind]
	value, haveValue := r.Latencies[c.metricKind]
	if !haveBand || !haveValue {
		// Still learning, or the probe did not report this metric this cycle. Neither
		// is evidence for or against degradation, so the counters are left exactly
		// where they were rather than reset — the watermark above already did the part
		// that matters for replay safety.
		return nil
	}
	st.lastValue = sql.NullFloat64{Float64: value, Valid: true}
	threshold := DegradationThreshold(band, r.Det.SmartSensitivity, c.metricKind)
	if value >= threshold {
		st.failRounds++
		st.okRounds = 0
		if !st.firstFailTS.Valid {
			st.firstFailTS = sql.NullInt64{Int64: r.TS, Valid: true}
		}
		if !st.signalID.Valid {
			st.pendingFails = append(st.pendingFails, FailEvidence{
				TS: r.TS, MetricKind: c.metricKind, Value: value,
			})
		}
		if !st.signalID.Valid && st.failRounds >= DegradationFailRounds(r.Det.SmartSensitivity) {
			id, err := s.confirmDegradation(ctx, tx, agentID, siteID, agentName, *c, r, band, value, threshold, now, out)
			if err != nil {
				return err
			}
			st.signalID = sql.NullString{String: id, Valid: true}
			st.pendingFails = nil
		}
		return nil
	}
	st.okRounds++
	st.failRounds = 0
	st.firstFailTS = sql.NullInt64{}
	st.pendingFails = nil
	// A sub-threshold degradation streak that recovered is NOT recorded as a
	// fluctuation. Fluctuations explain availability dips ("why is this 99%?"), and
	// there is no comparable number a "latency was briefly high" record would be
	// explaining — it would be a log of the weather.
	if st.signalID.Valid && st.okRounds >= DegradationRecoverRounds {
		if err := s.resolveSignal(ctx, tx, st.signalID.String, ReasonRecovered, timeFromUnix(r.TS), now, out); err != nil {
			return err
		}
		st.signalID = sql.NullString{}
	}
	return nil
}

// confirmDegradation opens a degradation signal with the band it was judged
// against frozen alongside the breaching value.
func (s *Service) confirmDegradation(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string,
	c degCheck, r Round, band baseline.Band, value, threshold float64, now time.Time, out *txOut) (string, error) {
	groupName, mergeEnabled, err := groupMeta(ctx, tx, r.GroupID)
	if err != nil {
		return "", err
	}
	signalID := "sig_" + uuid.NewString()
	observed := timeFromUnix(r.TS)
	if c.st.firstFailTS.Valid {
		observed = timeFromUnix(c.st.firstFailTS.Int64)
	}

	sig := Signal{
		ID: signalID, SiteID: siteID, AgentID: agentID, AgentName: agentName,
		TargetID: r.TargetID, TargetName: r.Meta.Name, TargetAddr: r.Meta.Addr,
		DetectorKey: c.key, ProbeKind: r.Kind,
		GroupID: r.GroupID, GroupName: groupName, Layer: r.Layer,
		// Info, not warn. The default notification policy's floor is warn, so a
		// degradation lands in the fault centre and on the console's live stream while
		// announcing itself to nobody. An operator who wants to be told lowers their
		// policy floor; nobody has to be told first to find out they did not want to be.
		Severity:      SeverityInfo,
		FailThreshold: DegradationFailRounds(r.Det.SmartSensitivity), RecoverThreshold: DegradationRecoverRounds,
		MetricKind: c.metricKind, Comparator: ComparatorGteBaseline,
		Value: value, Threshold: threshold,
		BaselineP50: band.P50, BaselineP95: band.P95,
		Rounds:     c.st.pendingFails,
		ObservedAt: observed, ConfirmedAt: timeFromUnix(r.TS),
	}

	// A degradation never joins an availability incident, even inside a merging
	// group: an info-severity "slower than usual" member sitting among "unreachable"
	// ones adds nothing to the diagnosis and drags a noticeably different kind of
	// claim under a title that does not cover it. The "deg:" prefix is what keeps
	// the two families apart in a namespace they otherwise share.
	openKey := "sig:" + signalID
	title := SignalTitle(sig)
	if mergeEnabled && r.GroupID != "" {
		openKey = "deg:grp:" + r.GroupID
		if groupName != "" {
			title = DegradationGroupTitle(groupName, "zh")
		}
	}
	if err := s.openSignal(ctx, tx, sig, r.Meta.Port, openKey, title, time.Time{}, now, r.Meta.maxRoundGap(), out); err != nil {
		return "", err
	}
	return signalID, nil
}

// saveDegradationChecks persists each check's counters, on every pass and for the
// same reason the availability row is written unconditionally: the watermark is
// what rejects an already-folded round, and a watermark left behind re-opens the
// window it closes.
func saveDegradationChecks(ctx context.Context, tx *sql.Tx, targetID, agentID string,
	checks []degCheck, cur Round, now time.Time) error {
	for i := range checks {
		if err := saveDetectorState(ctx, tx, targetID, agentID, checks[i].key,
			cur.ConfigSerial, cur.Det.Revision, checks[i].st, now); err != nil {
			return err
		}
	}
	return nil
}
