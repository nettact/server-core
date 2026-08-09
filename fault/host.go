package fault

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// The system-status detectors: the built-in fault detection over a machine's own
// resources, driven by the host metrics an Agent already reports.
//
// # Why this is not the deleted rule engine
//
// The product used to let an operator write conditions (metric, comparator,
// threshold, AND/OR) and that was removed on purpose: almost nobody can say what
// a good threshold for probe.icmp.loss_pct is, and the ones who tried mostly
// built alerts that either never fired or never stopped. Host resources are the
// one place where the opposite is true — "the disk is nearly full" is a question
// with an obvious shape and an answer only the operator knows, because it depends
// on their machine and their tolerance. So this family takes a threshold and
// nothing else: what to watch, how many rounds confirm it, when it recovers, what
// severity it carries and what it is called are all fixed here.
//
// # Why the detectors live on a host anchor rather than on the agent
//
// A host anchor is an ordinary kind='host' probe_tasks row that is never pushed
// to an agent. Hanging the thresholds off it means the whole surrounding
// machinery — monitor-group agent scope, incident merge policy, notification
// policy resolution (group > site), termination on disable/delete/move — applies
// with no new concepts at all. One anchor in an all-agents group is "watch every
// machine"; an anchor in a group scoped to the servers is "watch the servers,
// tighter".
//
// # Hysteresis, and why a third zone
//
// Every threshold here is a level, not an event, and a machine sitting at exactly
// the threshold crosses it constantly. A two-zone detector (fail at >= T, recover
// at < T) would resolve and re-confirm through every one of those crossings,
// which is how a monitoring product teaches people to ignore it. So there is a
// recovery floor below the threshold, and readings BETWEEN the two advance
// neither streak: they hold whatever the detector already believed.
//
// The hold is where the subtlety is. A held round must still move the watermark,
// or a run of holds looks to the gap rule like the agent went silent, and a live
// streak gets abandoned on the evidence of samples that arrived perfectly.

// Recovery margins. Percentages come down by a fixed 5 points and the unbounded
// families by a tenth, because "90% → 85%" and "2.0 → 1.8 per core" are both
// about a fifth of the way back into normal for their scale, and a fixed
// subtraction on an unbounded quantity is meaningless (5 Mbps below a 1000 Mbps
// threshold is noise; below a 3 Mbps one it is the whole range).
const (
	hostRecoverMarginPct   = 5.0
	hostRecoverFactorRatio = 0.9
)

// hostRecoverPct is the recovery floor for a percentage threshold.
//
// The subtraction alone is not enough at the bottom of the range: an operator who
// sets 5% or less would get a floor at or below zero, and since readings are
// non-negative and recovery is a strict "<", the fault could never clear — it
// would sit firing until someone edited it. Falling back to the proportional
// margin keeps the floor strictly inside the range at every threshold the API
// accepts, and at ordinary thresholds the subtraction still wins (90 → 85, not 81).
func hostRecoverPct(threshold float64) float64 {
	if floor := threshold - hostRecoverMarginPct; floor > threshold*hostRecoverFactorRatio {
		return floor
	}
	return threshold * hostRecoverFactorRatio
}

// Recovery lengths. Three rounds (~90s at the 30s host cadence) for the spiky
// families, two for disk: a disk that is no longer full is not going to flap back
// in the next minute, and a machine that just finished a build might.
const (
	hostRecoverRounds     = 3
	hostDiskRecoverRounds = 2
	// hostDiskFailRounds confirms a full disk after two consecutive readings.
	// Unlike CPU there is no duration to configure: disk usage moves slowly, so a
	// sustained-for-five-minutes rule would only delay the same verdict, and the
	// second round is there purely to debounce one bad read.
	hostDiskFailRounds = 2
)

// HostSettings are one anchor's system-status thresholds, as stored in
// host_detection_settings. A zero value is not valid config — use
// DefaultHostSettings, which is also what a missing row means.
type HostSettings struct {
	CPUEnabled   bool
	CPUPct       float64
	CPUDurationS int

	MemEnabled   bool
	MemPct       float64
	MemDurationS int

	LoadEnabled   bool
	LoadPerCore   float64
	LoadDurationS int

	NetEnabled bool
	// NetRxMbps / NetTxMbps are 0 when that direction has no threshold, which is
	// how one-directional alerting is expressed (a home link's upstream saturates
	// long before its downstream does). Enabling the family with neither set is
	// rejected at the API, not silently treated as "alert on nothing".
	NetRxMbps    float64
	NetTxMbps    float64
	NetDurationS int

	DiskEnabled bool
	DiskPct     float64

	// Revision advances on every edit. Streaks are pinned to it, so an edited
	// threshold restarts confirmation rather than inheriting rounds counted
	// against the value it replaced.
	Revision int
}

// DefaultHostSettings is what a host anchor watches before anyone configures it,
// and what a missing settings row means. Everything but network is on: 90% of
// CPU/memory/disk and 2.0 per core are defensible on any machine, while a network
// threshold depends on a link speed the server does not know.
func DefaultHostSettings() HostSettings {
	return HostSettings{
		CPUEnabled: true, CPUPct: 90, CPUDurationS: 300,
		MemEnabled: true, MemPct: 90, MemDurationS: 300,
		LoadEnabled: true, LoadPerCore: 2.0, LoadDurationS: 300,
		NetEnabled: false, NetDurationS: 300,
		DiskEnabled: true, DiskPct: 90,
		Revision: 1,
	}
}

// HostTargetMeta is what the engine needs to know about one host anchor to judge
// an agent's machine metrics against it. Assembled by ingest inside its
// transaction so the facts match the commit, exactly like TargetMeta.
type HostTargetMeta struct {
	ID      string
	GroupID string
	Name    string
	// ConfigSerial is the anchor's generation. Host samples carry no serial of
	// their own (they belong to no monitor), so this pins the streak rather than
	// filtering the samples: a material edit to the anchor restarts counting.
	ConfigSerial int
	Set          HostSettings
	// IntervalSeconds is the host collection cadence, which is what converts a
	// configured duration into a round count. Passed in rather than read here
	// because config imports this package, not the other way round.
	IntervalSeconds int
	// UploadSeconds is the agent's REPORTED batch-upload cadence, which decides
	// how late a live host reading can legitimately be. Zero means it has not
	// reported one and the protocol default stands. The probe path gets this from
	// the target's own monitor_status row; host anchors belong to no monitor, so
	// it is carried here instead — without it, an install on a deliberately slow
	// upload interval would have every live host fault judged a replay.
	UploadSeconds int
	// Cores is the machine's logical core count, from this batch or the latest
	// cached reading. Zero means unknown, and the load family is then skipped
	// entirely — a per-core judgement without a core count would be a guess, and
	// guessing the denominator of an alert threshold is worse than not alerting.
	Cores float64
}

// HostRound is one system-status reading judged against one threshold: the host
// family's equivalent of a probe Round, and deliberately a separate type. A Round
// carries a probe's verdict, its reason code, the resolver and proxy it used and
// a two-way success/fail class; none of that means anything about a CPU reading,
// and a host round needs a third class a probe round has no use for.
type HostRound struct {
	TargetID string
	// TargetName is the anchor's display name, carried on the round so a frozen
	// record never has to re-read live config to name itself.
	TargetName string
	// DetectorKey already has its subject folded in (see HostDetectorKey).
	DetectorKey string
	Subject     string // "" | "rx" | "tx" | mount point
	MetricKind  string // the EVIDENCE kind, which may be derived (host.load.per_core)
	TS          int64
	// Value is in the unit the operator authored the threshold in — percent, load
	// per core, or Mbps — not necessarily the unit of the series behind it.
	Value        float64
	Threshold    float64
	RecoverBelow float64
	// ReasonDetail carries the machine truth behind a derived value, e.g. the raw
	// load average and core count behind a per-core figure.
	ReasonDetail  string
	FailRounds    int
	RecoverRounds int
	GroupID       string
	ConfigSerial  int
	Revision      int
	IntervalSec   int
	// UploadSec is the agent's reported batch-upload cadence; see
	// HostTargetMeta.UploadSeconds. Zero selects the protocol default.
	UploadSec int
}

// hostRoundZone is what one reading says about the streak.
type hostRoundZone int

const (
	hostZoneFail hostRoundZone = iota
	hostZoneRecover
	// hostZoneHold is the band between the recovery floor and the threshold: not
	// bad enough to count against the machine, not good enough to count for it.
	hostZoneHold
)

func (r HostRound) zone() hostRoundZone {
	switch {
	case r.Value >= r.Threshold:
		return hostZoneFail
	case r.Value < r.RecoverBelow:
		return hostZoneRecover
	default:
		return hostZoneHold
	}
}

// maxRoundGap is how far apart two host readings may be and still count as
// consecutive, derived from the collection cadence by the same StaleAfter formula
// the probe detectors use: past the point where the server would call a reading
// stale, calling two readings adjacent asserts a continuity nobody observed.
func (r HostRound) maxRoundGap() time.Duration {
	interval := time.Duration(r.IntervalSec) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	// The agent's reported upload cadence, not the protocol default: an install
	// that batches every five minutes delivers live readings that late, and
	// judging them against the default would call every one of them a replay.
	// StaleAfter falls back to the default for a zero, which is what an agent
	// that has reported nothing yet should get.
	return pcfg.StaleAfter(interval, 0, time.Duration(r.UploadSec)*time.Second)
}

// hostFailRounds converts a configured duration into the number of consecutive
// readings that confirm it, at the given collection cadence.
//
// The conversion happens here, at evaluation time, rather than in storage: "five
// minutes" has to keep meaning five minutes if the cadence ever changes, and a
// stored round count would silently redefine every existing alert the day it did.
//
// It rounds UP, because the duration is a minimum the operator stated and any
// duration in the accepted range is allowed — not just multiples of the cadence.
// Rounding to nearest would confirm a 40-second setting after a single 30-second
// reading, alerting a third sooner than asked; the ceiling can only ever wait
// slightly longer, which is the side of the trade a threshold should err on.
func hostFailRounds(durationSeconds, intervalSeconds int) int {
	if intervalSeconds <= 0 {
		intervalSeconds = 30
	}
	n := int(math.Ceil(float64(durationSeconds) / float64(intervalSeconds)))
	if n < 1 {
		return 1
	}
	return n
}

// HostMountView is what one batch said about one anchor's disks: the set of
// mounts it reported. A mount missing from it has been missed once — see
// resolveVanishedMounts for why one miss is not a removal.
type HostMountView struct {
	Present map[string]bool
}

// BuildHostRounds turns one batch's host metrics into judged rounds for every
// anchor covering the reporting agent, plus what each anchor saw of the machine's
// disks (nil when the batch carried no disk readings at all — see EvaluateHostTx's
// subject-gone handling, where "no disks reported" and "this disk is gone" must
// not be confused).
//
// Every anchor is judged independently. Two monitor groups both covering one
// machine is two sets of thresholds and two sets of alerts, which is the point:
// that is how "warn me at 90%, and page the on-call at 98%" is expressed with no
// extra concept.
func BuildHostRounds(ms []telemetry.Metric, metas []HostTargetMeta) ([]HostRound, map[string]HostMountView) {
	if len(metas) == 0 {
		return nil, nil
	}
	// Readings per timestamp. Every metric one Collect produces shares one
	// instant, so a timestamp identifies a complete reading of the machine.
	type reading struct {
		cpu, mem, load, netRx, netTx float64
		hasCPU, hasMem, hasLoad      bool
		hasNetRx, hasNetTx           bool
		disks                        map[string]float64
	}
	readings := map[int64]*reading{}
	at := func(ts int64) *reading {
		r := readings[ts]
		if r == nil {
			r = &reading{}
			readings[ts] = r
		}
		return r
	}
	// Cores can arrive in this very batch. A packet drained from the WAL can span
	// a resize, so the count is kept as a TIMELINE rather than a single newest
	// value: a load reading taken before a hot-add must not be divided by the
	// count that only existed after it.
	type coreSample struct {
		ts int64
		n  float64
	}
	var coreTimeline []coreSample
	anyDisk := false

	for _, m := range ms {
		// Host metrics belong to no monitor. Anything carrying a monitor id is a
		// probe sample and is the availability detector's business.
		if m.MonitorID != "" || math.IsNaN(m.Value) || math.IsInf(m.Value, 0) {
			continue
		}
		ts := m.TS.Unix()
		switch m.Kind {
		case telemetry.HostCPUPct:
			r := at(ts)
			r.cpu, r.hasCPU = m.Value, true
		case telemetry.HostMemPct:
			r := at(ts)
			r.mem, r.hasMem = m.Value, true
		case telemetry.HostLoad1:
			r := at(ts)
			r.load, r.hasLoad = m.Value, true
		case telemetry.HostNetRxBps:
			r := at(ts)
			r.netRx, r.hasNetRx = m.Value, true
		case telemetry.HostNetTxBps:
			r := at(ts)
			r.netTx, r.hasNetTx = m.Value, true
		case telemetry.HostDiskPct:
			if m.Target == "" {
				continue
			}
			r := at(ts)
			if r.disks == nil {
				r.disks = map[string]float64{}
			}
			r.disks[m.Target] = m.Value
			anyDisk = true
		case telemetry.HostCPUCores:
			if m.Value > 0 {
				coreTimeline = append(coreTimeline, coreSample{ts: ts, n: m.Value})
			}
		}
	}
	if len(readings) == 0 {
		return nil, nil
	}

	stamps := make([]int64, 0, len(readings))
	for ts := range readings {
		stamps = append(stamps, ts)
	}
	slices.Sort(stamps)

	slices.SortFunc(coreTimeline, func(a, b coreSample) int {
		switch {
		case a.ts < b.ts:
			return -1
		case a.ts > b.ts:
			return 1
		}
		return 0
	})
	// coresAt is the machine's core count as of one reading: the newest count at
	// or before it, falling back to the caller's cached value for readings that
	// predate every count in this batch.
	coresAt := func(ts int64, cached float64) float64 {
		n := cached
		for _, c := range coreTimeline {
			if c.ts > ts {
				break
			}
			n = c.n
		}
		return n
	}

	var rounds []HostRound
	mounts := map[string]HostMountView{}
	for _, meta := range metas {
		set := meta.Set
		if anyDisk && set.DiskEnabled {
			mounts[meta.ID] = HostMountView{Present: map[string]bool{}}
		}
		add := func(family, subject, metricKind string, ts int64, value, threshold, recoverBelow float64,
			failRounds, recoverRounds int, detail string) {
			rounds = append(rounds, HostRound{
				TargetID: meta.ID, TargetName: meta.Name,
				DetectorKey: HostDetectorKey(family, subject), Subject: subject,
				MetricKind: metricKind, TS: ts, Value: value,
				Threshold: threshold, RecoverBelow: recoverBelow, ReasonDetail: detail,
				FailRounds: failRounds, RecoverRounds: recoverRounds,
				GroupID: meta.GroupID, ConfigSerial: meta.ConfigSerial, Revision: set.Revision,
				IntervalSec: meta.IntervalSeconds, UploadSec: meta.UploadSeconds,
			})
		}
		for _, ts := range stamps {
			r := readings[ts]
			if set.CPUEnabled && r.hasCPU {
				add(DetectorHostCPU, "", string(telemetry.HostCPUPct), ts, r.cpu,
					set.CPUPct, hostRecoverPct(set.CPUPct),
					hostFailRounds(set.CPUDurationS, meta.IntervalSeconds), hostRecoverRounds, "")
			}
			if set.MemEnabled && r.hasMem {
				add(DetectorHostMem, "", string(telemetry.HostMemPct), ts, r.mem,
					set.MemPct, hostRecoverPct(set.MemPct),
					hostFailRounds(set.MemDurationS, meta.IntervalSeconds), hostRecoverRounds, "")
			}
			// Load is judged per core, so a machine with no reported core count is
			// not judged at all rather than judged against a made-up denominator.
			if cores := coresAt(ts, meta.Cores); set.LoadEnabled && r.hasLoad && cores > 0 {
				perCore := r.load / cores
				add(DetectorHostLoad, "", string(telemetry.HostLoadPerCore), ts, perCore,
					set.LoadPerCore, set.LoadPerCore*hostRecoverFactorRatio,
					hostFailRounds(set.LoadDurationS, meta.IntervalSeconds), hostRecoverRounds,
					fmt.Sprintf("load1=%.2f cores=%.0f", r.load, cores))
			}
			if set.NetEnabled {
				netFail := hostFailRounds(set.NetDurationS, meta.IntervalSeconds)
				if r.hasNetRx && set.NetRxMbps > 0 {
					add(DetectorHostNet, "rx", string(telemetry.HostNetRxMbps), ts, bpsToMbps(r.netRx),
						set.NetRxMbps, set.NetRxMbps*hostRecoverFactorRatio, netFail, hostRecoverRounds, "")
				}
				if r.hasNetTx && set.NetTxMbps > 0 {
					add(DetectorHostNet, "tx", string(telemetry.HostNetTxMbps), ts, bpsToMbps(r.netTx),
						set.NetTxMbps, set.NetTxMbps*hostRecoverFactorRatio, netFail, hostRecoverRounds, "")
				}
			}
			if set.DiskEnabled {
				for mount, pct := range r.disks {
					mounts[meta.ID].Present[mount] = true
					add(DetectorHostDisk, mount, string(telemetry.HostDiskPct), ts, pct,
						set.DiskPct, hostRecoverPct(set.DiskPct),
						hostDiskFailRounds, hostDiskRecoverRounds, "")
				}
			}
		}
	}
	// One pass per detector needs its rounds contiguous and in time order; the
	// disk loop above iterates a map, so this sort is load-bearing, not tidiness.
	sort.SliceStable(rounds, func(i, j int) bool {
		if rounds[i].TargetID != rounds[j].TargetID {
			return rounds[i].TargetID < rounds[j].TargetID
		}
		if rounds[i].DetectorKey != rounds[j].DetectorKey {
			return rounds[i].DetectorKey < rounds[j].DetectorKey
		}
		return rounds[i].TS < rounds[j].TS
	})
	if len(mounts) == 0 {
		mounts = nil
	}
	return rounds, mounts
}

// bpsToMbps converts a byte rate to the megabits per second an operator sets a
// link threshold in.
func bpsToMbps(bytesPerSec float64) float64 { return bytesPerSec * 8 / 1e6 }

// EvaluateHostTx advances the system-status detectors by the readings this batch
// carries, inside the caller's open write transaction — the sibling of
// EvaluateAgentTx, with the same atomicity contract: samples, detector state,
// signals, incidents and notification plans commit together, and an error
// withholds the agent's ack so it replays.
//
// It is a sibling rather than an extension because advanceDetector exists to walk
// availability and the degradation checks together, so that a target that is down
// is never also reported as slow. A CPU reading takes part in no such
// relationship, and threading it through that walk would put a host branch on
// every line of it for no shared logic. What IS shared is everything below the
// fold: state persistence, signal opening, incident merge, notification planning
// and fluctuation recording are the same calls the probe detectors make.
//
// mounts maps anchor id to what this batch said about that anchor's disks. A nil
// map (or a missing anchor) means the batch carried no disk readings, which is
// silence, not evidence of a removed disk.
func (s *Service) EvaluateHostTx(ctx context.Context, tx *sql.Tx, agentID, siteID string,
	rounds []HostRound, mounts map[string]HostMountView) (*Outcome, error) {
	out := &txOut{}
	if len(rounds) == 0 && len(mounts) == 0 {
		return &Outcome{out: out, siteID: siteID}, nil
	}
	now := time.Now().UTC()
	agentName, err := agentDisplayName(ctx, tx, agentID)
	if err != nil {
		return nil, err
	}

	changed := make([]string, 0, 4)
	seen := map[string]bool{}
	markChanged := func(targetID string) {
		if !seen[targetID] {
			seen[targetID] = true
			changed = append(changed, targetID)
		}
	}

	// rounds are sorted by (target, detector, ts), so one pass walks each
	// detector's readings in order without regrouping.
	for i := 0; i < len(rounds); {
		j := i
		for j < len(rounds) &&
			rounds[j].TargetID == rounds[i].TargetID &&
			rounds[j].DetectorKey == rounds[i].DetectorKey {
			j++
		}
		if err := s.advanceHostDetector(ctx, tx, agentID, siteID, agentName, rounds[i:j], now, out); err != nil {
			return nil, err
		}
		markChanged(rounds[i].TargetID)
		i = j
	}

	for targetID, view := range mounts {
		n, err := s.resolveVanishedMounts(ctx, tx, agentID, targetID, view, now, out)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			markChanged(targetID)
		}
	}
	return &Outcome{out: out, siteID: siteID, ChangedTargetIDs: changed}, nil
}

// advanceHostDetector folds one (anchor, detector) group's readings into its
// state row and drives the confirm/resolve transitions.
func (s *Service) advanceHostDetector(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string,
	rounds []HostRound, now time.Time, out *txOut) error {
	cur := rounds[len(rounds)-1]
	st, err := loadDetectorState(ctx, tx, cur.TargetID, agentID, cur.DetectorKey)
	if err != nil {
		return err
	}
	// Counters are pinned to the generation and threshold revision they were
	// accumulated under: four minutes spent above 90% says nothing about a
	// threshold of 95%, so an edit restarts counting. The active signal (if any)
	// was already terminated by the config path that caused the advance.
	if st.exists && (st.configSerial != cur.ConfigSerial || st.detectionRev != cur.Revision) {
		st.failRounds, st.okRounds = 0, 0
		st.firstFailTS = sql.NullInt64{}
		st.lastRoundTS = 0
		st.pendingFails = nil
	}
	for _, r := range rounds {
		if err := s.advanceHostRound(ctx, tx, agentID, siteID, agentName, r, &st, now, out); err != nil {
			return err
		}
	}
	// Written on every pass, green or not: last_round_ts is the watermark that
	// rejects an already-folded reading, and a watermark left behind re-opens the
	// window it closes. Same reasoning as advanceDetector's unconditional save.
	return saveDetectorState(ctx, tx, cur.TargetID, agentID, cur.DetectorKey,
		cur.ConfigSerial, cur.Revision, st, now)
}

// advanceHostRound folds one reading into a system-status detector's state.
func (s *Service) advanceHostRound(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string,
	r HostRound, st *detectorState, now time.Time, out *txOut) error {
	// Watermark: a reading at or before the newest already-folded one is a
	// duplicate or an out-of-order straggler. Its sample is still stored, but it
	// must not advance, rewind or re-decide current state.
	if r.TS <= st.lastRoundTS {
		return nil
	}
	gap := int64(r.maxRoundGap().Seconds())
	// A reading stamped in the future is a broken agent clock, and folding it
	// would park the watermark ahead of every honest reading that follows,
	// silencing the detector until the clock catches up. Dropped BEFORE the
	// watermark moves, which is the whole point.
	if now.Unix()-r.TS < -gap {
		return nil
	}
	// A streak is N CONSECUTIVE readings, and consecutive has to mean something in
	// wall-clock terms: a machine that was busy twice before its agent went silent
	// for a day must not confirm on the reading that arrives when it comes back.
	//
	// BOTH streaks reset, not just the failing one. A firing fault that collected
	// one healthy reading and then went quiet for a day would otherwise resolve on
	// the second healthy reading a day later — "two consecutive recoveries"
	// spanning a silence nobody observed, which is the same fabrication in the
	// other direction.
	if (st.failRounds > 0 || st.okRounds > 0) && st.lastRoundTS > 0 && r.TS-st.lastRoundTS > gap {
		st.failRounds, st.okRounds = 0, 0
		st.firstFailTS = sql.NullInt64{}
		st.pendingFails = nil
	}
	// The watermark advances for EVERY reading that gets this far, including a
	// held one. A hold that skipped this would leave the watermark behind while
	// readings kept arriving, and the gap rule above would eventually read that as
	// silence and abandon a streak the machine never stopped reporting on.
	st.lastRoundTS = r.TS
	st.lastValue = sql.NullFloat64{Float64: r.Value, Valid: true}

	switch r.zone() {
	case hostZoneHold:
		// Between the recovery floor and the threshold: neither streak advances and
		// a firing signal keeps firing. This is what stops a machine parked at the
		// threshold from resolving and re-confirming all day.
		return nil

	case hostZoneFail:
		st.failRounds++
		st.okRounds = 0
		if !st.firstFailTS.Valid {
			st.firstFailTS = sql.NullInt64{Int64: r.TS, Valid: true}
		}
		if !st.signalID.Valid {
			// Staged only while unconfirmed; once a signal is firing it owns its
			// frozen evidence, so accumulating past that point would grow unbounded
			// through a long overload.
			st.pendingFails = append(st.pendingFails, FailEvidence{
				TS: r.TS, MetricKind: r.MetricKind, Value: r.Value, ReasonDetail: r.ReasonDetail,
			})
		}
		if !st.signalID.Valid && st.failRounds >= r.FailRounds {
			id, err := s.confirmHostSignal(ctx, tx, agentID, siteID, agentName, r, *st, now, out)
			if err != nil {
				return err
			}
			st.signalID = sql.NullString{String: id, Valid: true}
			st.pendingFails = nil // the signal froze its own copy
		}
		return nil
	}

	// Recovery zone. A streak that never confirmed is about to be erased; record
	// it first, for the same reason a probe dip is recorded — a machine that spent
	// four of the five configured minutes pegged is the explanation behind a chart
	// nobody else can account for.
	if st.failRounds > 0 && !st.signalID.Valid {
		started := timeFromUnix(r.TS)
		if st.firstFailTS.Valid {
			started = timeFromUnix(st.firstFailTS.Int64)
		}
		if err := insertFluctuationRow(ctx, tx, fluctuationRow{
			SiteID: siteID, AgentID: agentID, AgentName: agentName,
			TargetID: r.TargetID, TargetName: r.TargetName, TargetAddr: r.Subject,
			ProbeKind: "host", GroupID: r.GroupID, Layer: hostLayer, DetectorKey: r.DetectorKey,
			FailRounds: st.failRounds, FailThreshold: r.FailRounds,
			Comparator: hostComparator, Threshold: r.Threshold,
			Rounds: st.pendingFails, StartedAt: started, EndedAt: timeFromUnix(r.TS),
		}); err != nil {
			return err
		}
	}
	st.okRounds++
	st.failRounds = 0
	st.firstFailTS = sql.NullInt64{}
	st.pendingFails = nil
	if st.signalID.Valid && st.okRounds >= r.RecoverRounds {
		if err := s.resolveSignal(ctx, tx, st.signalID.String, ReasonRecovered, timeFromUnix(r.TS), now, out); err != nil {
			return err
		}
		st.signalID = sql.NullString{}
	}
	return nil
}

// hostComparator is the comparator every system-status detector freezes. All five
// families ask the same question — is this above the level you set — so there is
// nothing to choose and nothing to configure.
const hostComparator = "gte"

// hostLayer annotates every system-status signal as local. The claim is about
// this machine's own resources, which is as local as a fault gets, and it keeps
// a full disk from being ranked as a network-layer cause.
const hostLayer = "local"

// confirmHostSignal opens a system-status fault with its evidence frozen from the
// confirming reading, attaches it to an incident and plans the notification.
func (s *Service) confirmHostSignal(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string,
	r HostRound, st detectorState, now time.Time, out *txOut) (string, error) {
	groupName, mergeEnabled, err := groupMeta(ctx, tx, r.GroupID)
	if err != nil {
		return "", err
	}
	signalID := "sig_" + uuid.NewString()
	observed := timeFromUnix(r.TS)
	if st.firstFailTS.Valid {
		observed = timeFromUnix(st.firstFailTS.Int64)
	}

	sig := Signal{
		ID: signalID, SiteID: siteID, AgentID: agentID, AgentName: agentName,
		TargetID: r.TargetID, TargetName: r.TargetName, TargetAddr: r.Subject,
		DetectorKey: r.DetectorKey, ProbeKind: "host",
		GroupID: r.GroupID, GroupName: groupName, Layer: hostLayer,
		// Warn, like an unreachable target. A machine that has been pegged for the
		// duration its operator chose is exactly as worth telling them about as a
		// monitor that stopped answering, and the notification policy's warn delay
		// already gives it a chance to pass before anyone is disturbed.
		Severity:      SeverityWarn,
		FailThreshold: r.FailRounds, RecoverThreshold: r.RecoverRounds,
		MetricKind: r.MetricKind, Comparator: hostComparator,
		Value: r.Value, Threshold: r.Threshold, ReasonDetail: r.ReasonDetail,
		Rounds:     st.pendingFails,
		ObservedAt: observed, ConfirmedAt: timeFromUnix(r.TS),
	}

	// A system-status fault never joins an availability incident, even inside a
	// merging group. "The disk is nearly full" under a title that says the group is
	// unreachable is a different claim wearing someone else's name — and because
	// this family is annotated local, the deepest layer present, it would also
	// hijack that incident's suspected cause. The "hostm:" prefix keeps the two
	// apart in a namespace they otherwise share, exactly as "deg:" does.
	openKey := "sig:" + signalID
	title := SignalTitle(sig)
	if mergeEnabled && r.GroupID != "" {
		openKey = "hostm:grp:" + r.GroupID
		if groupName != "" {
			title = HostGroupTitle(groupName, "zh")
		}
	}
	// No precursor window: fluctuations are claimed by the availability detector's
	// confirmations, and a CPU dip is not evidence about a disk.
	if err := s.openSignal(ctx, tx, sig, 0, openKey, title, time.Time{}, now, r.maxRoundGap(), out); err != nil {
		return "", err
	}
	return signalID, nil
}

// hostDiskMissesBeforeGone is how many consecutive disk snapshots may omit a
// firing mount before it counts as removed rather than unread. Two, because the
// agent skips a mount whose usage read fails and that failure is per-collection:
// one miss is a bad read, two in a row is a drive that left.
const hostDiskMissesBeforeGone = 2

// resolveVanishedMounts ends disk faults whose mount is no longer reported.
//
// Only called for an anchor that DID report disks in this batch: an agent whose
// disk permission was revoked, or which is simply offline, sends nothing, and
// reading that as "every disk was removed" would close real faults on silence.
//
// Absence alone is still not enough, and neither is elapsed time. The agent omits
// a mount whose usage read fails, which looks exactly like a removal — and an
// agent returning from an hour offline presents its first report with an hour-wide
// gap, which looks like one too. What separates them is how many disk snapshots
// have actually been OBSERVED without the mount, so that is what is counted:
// misses accumulate on the mount's own detector row and reset the moment it
// reports again.
func (s *Service) resolveVanishedMounts(ctx context.Context, tx *sql.Tx, agentID, targetID string,
	view HostMountView, now time.Time, out *txOut) (int, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT s.id, s.detector_key, COALESCE(d.subject_misses, 0)
		FROM fault_signals s
		LEFT JOIN detector_state d
		  ON d.target_id = s.target_id AND d.agent_id = s.agent_id AND d.detector_key = s.detector_key
		WHERE s.agent_id=? AND s.target_id=? AND s.state='firing' AND s.detector_key LIKE ?`,
		agentID, targetID, DetectorHostDisk+hostDetectorSubjectSep+"%")
	if err != nil {
		return 0, err
	}
	type absent struct {
		id, key string
		misses  int
	}
	var missing []absent
	for rows.Next() {
		var a absent
		if err := rows.Scan(&a.id, &a.key, &a.misses); err != nil {
			rows.Close()
			return 0, err
		}
		if _, subject := SplitHostDetectorKey(a.key); !view.Present[subject] {
			missing = append(missing, a)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	// A mount that reported is present by definition; clear any misses it had
	// banked so a bad read followed by a good one leaves no residue.
	if _, err := tx.ExecContext(ctx, `
		UPDATE detector_state SET subject_misses=0
		WHERE target_id=? AND agent_id=? AND detector_key LIKE ? AND subject_misses>0`,
		targetID, agentID, DetectorHostDisk+hostDetectorSubjectSep+"%"); err != nil {
		return 0, err
	}

	var gone int
	for _, a := range missing {
		if a.misses+1 < hostDiskMissesBeforeGone {
			if _, err := tx.ExecContext(ctx, `
				UPDATE detector_state SET subject_misses=?, updated_at=?
				WHERE target_id=? AND agent_id=? AND detector_key=?`,
				a.misses+1, now, targetID, agentID, a.key); err != nil {
				return 0, err
			}
			continue
		}
		if err := s.resolveSignal(ctx, tx, a.id, ReasonSubjectGone, now, now, out); err != nil {
			return 0, err
		}
		// The state row goes with the signal: a mount that comes back is a fresh
		// subject and starts counting from zero, not from a streak measured against
		// a disk that has been out of the machine since.
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM detector_state WHERE target_id=? AND agent_id=? AND detector_key=?`,
			targetID, agentID, a.key); err != nil {
			return 0, err
		}
		gone++
	}
	return gone, nil
}
