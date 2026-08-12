package fault

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/baseline"
	"github.com/nettact/server-core/metrics"
)

// baselineKinds is FoldKinds as a set, for the per-metric test BuildRounds runs
// on every sample of every batch.
var baselineKinds = func() map[string]bool {
	m := make(map[string]bool, len(baseline.FoldKinds))
	for _, k := range baseline.FoldKinds {
		m[k] = true
	}
	return m
}()

// timeFromUnix rebuilds a round's timestamp in UTC. Sample timestamps are stored
// as integer Unix seconds, so this round-trips exactly.
func timeFromUnix(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

// Sensitivity profiles offered by the UI. "custom" carries arbitrary in-range
// values; the three named profiles are fixed so the console can show a label
// instead of two numbers.
const (
	ProfileBalanced = "balanced"
	ProfileFast     = "fast"
	ProfileStable   = "stable"
	ProfileCustom   = "custom"
)

// Smart (baseline-relative) sensitivity levels for the ALERT-003 degradation
// detectors. Unlike the availability profiles these are never expressed to the
// user as numbers: the multipliers and round counts below are an implementation
// detail of "宽松 / 标准 / 敏感".
const (
	SmartLoose     = "loose"
	SmartStandard  = "standard"
	SmartSensitive = "sensitive"
)

// DetectionSettings is one target's built-in detector sensitivity. A target with
// no stored row uses DefaultDetection, so the zero-config path needs no rows at
// all.
type DetectionSettings struct {
	Profile       string `json:"profile"`
	FailRounds    int    `json:"fail_rounds"`
	RecoverRounds int    `json:"recover_rounds"`
	// ICMPLossPct is the loss percentage at or above which an ICMP/gateway round
	// counts as a failure. 100 (the default) means "only total loss is a fault";
	// a lower value turns sustained partial loss into one.
	ICMPLossPct float64 `json:"icmp_loss_pct"`
	// SmartEnabled turns on the baseline-relative degradation detectors, which
	// judge a round against the target's own history instead of a fixed threshold.
	// On by default for every profile, including "stable": their findings are
	// recorded at info severity, which is below the default notification floor, so
	// leaving them on costs a user who chose "stable" precisely nothing in noise.
	SmartEnabled bool `json:"smart_enabled"`
	// SmartSensitivity is how far outside its own baseline a target has to go, and
	// for how long, before a degradation is claimed: loose | standard | sensitive.
	SmartSensitivity string `json:"smart_sensitivity"`
	// Revision advances on every edit. The detector's stored counters are pinned to
	// the revision they accumulated under, so a sensitivity change restarts counting
	// instead of applying a new threshold to an old streak. Shared by every detector
	// on the target: an operator retuning sensitivity means "start over", not "start
	// over for one of the two".
	Revision int `json:"revision"`
}

// DefaultDetection is the balanced profile every target gets for free: confirm
// after 3 consecutive failing rounds, recover after 2 consecutive succeeding
// rounds, treat only 100% ICMP loss as unreachable, and watch for quality
// degradation against the target's own history at standard sensitivity.
func DefaultDetection() DetectionSettings {
	return DetectionSettings{
		Profile: ProfileBalanced, FailRounds: 3, RecoverRounds: 2, ICMPLossPct: 100,
		SmartEnabled: true, SmartSensitivity: SmartStandard, Revision: 1,
	}
}

// Normalize clamps a settings value into the supported range and derives the
// profile label from the numbers, so a hand-built or API-supplied value can never
// persist an out-of-range threshold or a label that contradicts its own numbers.
func (d DetectionSettings) Normalize() DetectionSettings {
	def := DefaultDetection()
	if d.FailRounds < 1 || d.FailRounds > 20 {
		d.FailRounds = def.FailRounds
	}
	if d.RecoverRounds < 1 || d.RecoverRounds > 20 {
		d.RecoverRounds = def.RecoverRounds
	}
	if !(d.ICMPLossPct > 0) || d.ICMPLossPct > 100 || math.IsNaN(d.ICMPLossPct) {
		d.ICMPLossPct = def.ICMPLossPct
	}
	switch d.SmartSensitivity {
	case SmartLoose, SmartStandard, SmartSensitive:
	default:
		d.SmartSensitivity = def.SmartSensitivity
	}
	if d.Revision < 1 {
		d.Revision = 1
	}
	d.Profile = profileFor(d.FailRounds, d.RecoverRounds)
	return d
}

// profileFor names the sensitivity profile matching a (fail, recover) pair.
func profileFor(fail, recover int) string {
	switch {
	case fail == 3 && recover == 2:
		return ProfileBalanced
	case fail == 2 && recover == 2:
		return ProfileFast
	case fail == 5 && recover == 3:
		return ProfileStable
	}
	return ProfileCustom
}

// ProfileRounds returns the (fail, recover) pair of a named profile, and whether
// the name is one of the fixed profiles. "custom" returns false: its numbers come
// from the request.
func ProfileRounds(profile string) (fail, recover int, ok bool) {
	switch profile {
	case ProfileBalanced:
		return 3, 2, true
	case ProfileFast:
		return 2, 2, true
	case ProfileStable:
		return 5, 3, true
	}
	return 0, 0, false
}

// TargetMeta is what the engine needs to know about a target to evaluate its
// rounds: its identity, current generation and detector sensitivity. Assembled by
// ingest inside its transaction so the facts match the commit.
type TargetMeta struct {
	ID           string
	Kind         string
	GroupID      string
	Name         string
	Addr         string
	Port         int
	Enabled      bool
	ConfigSerial int
	Det          DetectionSettings
	// The target's egress pin as it stood when these samples were produced (the
	// generation filter guarantees that). Frozen onto a confirmed signal so a path
	// diagnostic can be aimed at the proxy the probe actually dialed rather than at
	// a target the traffic never reached directly. ProxyID empty means a direct
	// dial; a non-empty id with an empty type means the proxy row is already gone.
	ProxyID   string
	ProxyType string // socks5 | http | wireguard
	// ProxyAddr is "host:port" for socks5/http and the peer endpoint for wireguard.
	ProxyAddr string
	// ProxyConfigSerial is the pin's config generation. Frozen so an in-tunnel
	// diagnostic can demand exactly the generation that carried the failing
	// probes — a key rotated after the fault must never be re-enabled for it.
	ProxyConfigSerial int
	// MaxRoundGap is how far apart two rounds may be and still count as
	// consecutive. Zero falls back to the kind's default schedule (see
	// maxRoundGap), so a caller that does not set it still gets a sane bound
	// rather than an unbounded one.
	MaxRoundGap time.Duration
	// PingCount is how many echoes an icmp/gateway round is configured to send
	// (packet_count, or the protocol default). It is what an incoming round's
	// probe.icmp.sent is measured against to tell a complete round from one the
	// agent's probe budget truncated — see RoundComplete. Zero for every other
	// kind, and for an icmp target whose params could not be read, which disables
	// the check rather than guessing a count.
	PingCount int
}

// RoundComplete reports whether a round measured everything it was configured to
// measure, and so may be trusted with a verdict.
//
// Only ICMP has an incomplete state. Its loss is a ratio over the echoes
// actually SENT (see telemetry.ICMPSent), and the agent sends fewer than
// configured when its probe-concurrency budget could not admit them inside the
// round's timing budget. A round that managed one echo of five reports either 0%
// or 100% — figures indistinguishable from a healthy or a dead target, on
// exactly the metric the availability detector reads. Trusting them would let a
// busy agent invent both recoveries and outages.
//
// So an incomplete round is classified RoundInvalid: it is stored and charted
// like any other sample, but it neither confirms nor clears, and it stays out of
// the availability denominator. What it cannot do is hide the problem — the
// truncation means fewer rounds, the monitor goes stale on its own, and the
// agent's own overload event says why.
//
// # A missing count fails CLOSED
//
// sent <= 0 means the round carried no probe.icmp.sent at all, and that is
// treated as incomplete rather than waved through. Every agent that can connect
// emits it — the schema version was bumped for this contract, so the handshake
// refuses a peer that predates it — which leaves exactly one way to reach here
// without a count: a producer regression. Failing open would let that regression
// silently restore the behaviour this check exists to remove, and it would be an
// old-payload fallback of the kind AGENTS.md rules out.
//
// want <= 0 is the opposite case and deliberately fails OPEN. It means the
// SERVER could not read the target's own configured packet count (an unparseable
// probe_tasks.params). The check is then inapplicable, not failed, and the party
// at fault is the server's own bookkeeping — silencing a monitor whose agent is
// reporting perfectly well would punish the wrong side of the exchange.
func RoundComplete(probeKind string, sent, want int) bool {
	if probeKind != "icmp" && probeKind != "gateway" {
		return true
	}
	if want <= 0 {
		return true
	}
	return sent >= want
}

// ConfiguredPingCount is the packet count an icmp/gateway round is measured
// against, read from a probe_tasks.params blob. It is the `want` argument to
// RoundComplete.
//
// It lives here, next to the predicate, because two independent paths need the
// SAME answer: ingest derives it when building rounds for the detector, and
// targetstatus derives it when deciding the probe_state chip. Computing it twice
// is how those two came to disagree — one defaulting an unparseable blob to five
// while the other returned zero — which put a green chip next to a fault state
// that had deliberately abstained.
//
// Unreadable params yield 0, which disables the check (RoundComplete's fail-open
// branch). That is the safe direction here: the SERVER could not read its own
// bookkeeping, so the comparison is inapplicable rather than failed, and
// silencing a monitor whose agent is reporting fine would punish the wrong side.
func ConfiguredPingCount(probeKind, params string) int {
	if probeKind != "icmp" && probeKind != "gateway" {
		return 0
	}
	var p pcfg.ProbeParams
	if params != "" && json.Unmarshal([]byte(params), &p) != nil {
		return 0
	}
	return pcfg.PingCount(p)
}

// maxRoundGap is the tolerance for calling two rounds consecutive, defaulting to
// the target kind's own schedule when ingest did not supply one.
//
// It reuses StaleAfter, the same formula the server uses to decide a sample is too
// old to describe the present. That is the honest boundary: if the gap between two
// rounds exceeds it, the server would already have called the earlier one stale,
// so treating them as adjacent members of one streak asserts a continuity nobody
// observed. Deriving it from the target's real interval matters because those
// intervals span three orders of magnitude — 10s for ICMP, 30 minutes for NAT — so
// any single flat threshold would either be useless for one or break the other.
func (m TargetMeta) maxRoundGap() time.Duration {
	if m.MaxRoundGap > 0 {
		return m.MaxRoundGap
	}
	var p pcfg.ProbeParams
	return pcfg.StaleAfter(pcfg.EffectiveInterval(m.Kind, p), pcfg.CycleDeadline(m.Kind, p), 0)
}

// RoundClass is a probe round's verdict.
type RoundClass int

const (
	// RoundInvalid is NOT a verdict: a missing or non-finite primary metric, a
	// probe kind with no availability concept, a disabled target. It is never
	// counted as a failure, never counted as a success, and never enters the
	// availability denominator — synthesizing a 0 here is exactly the bug that made
	// permission-blocked and unsupported targets look unreachable.
	RoundInvalid RoundClass = iota
	RoundSuccess
	RoundFail
)

// SizeSweepFacts is the per-cycle classification and supporting evidence of a
// probe.icmp.size_sweep sample: does loss rise with ICMP payload size
// (physical-layer fingerprint) or not. Code semantics: 0 flat, 1 size-correlated,
// 2 insufficient evidence. The compared sizes and per-size loss/counts ride as
// labels on the sample (telemetry.SizeSmallLabel … CountLargeLabel) and are
// frozen here so a signal can render the evidence without re-deriving it.
type SizeSweepFacts struct {
	Code        int     `json:"code"`
	SizeSmall   int     `json:"size_small"`
	SizeLarge   int     `json:"size_large"`
	LossSmall   float64 `json:"loss_small"`
	LossLarge   float64 `json:"loss_large"`
	CountSmall  int     `json:"count_small"`
	CountLarge  int     `json:"count_large"`
}

// FlowFanoutFacts is the per-cycle classification and supporting evidence of a
// probe.tcp.flow_fanout sample: do a deterministic subset of pinned source-port
// flows fail (ECMP/LAG member-level fault) or is loss uniform. Code semantics:
// 0 single flow, 1 uniform, 2 member-level, 3 all flows failed, 4 insufficient.
// The flow counts ride as labels (telemetry.FlowFanoutFlowsLabel … OKLabel) and
// are frozen here so a signal can render the evidence without re-deriving it.
type FlowFanoutFacts struct {
	Code      int `json:"code"`
	Flows     int `json:"flows"`
	BadStable int `json:"bad_stable"`
	BadNew    int `json:"bad_new"`
	OK        int `json:"ok"`
}

// Round is one probe cycle's availability verdict for one target, plus the
// evidence to freeze if it turns out to confirm a fault.
//
// A round is identified by (monitor, config generation, timestamp): every metric
// a probe cycle emits shares one timestamp, which is the contract the reason
// pairing below and the interface-snapshot projection in ingest already rely on.
// The probe interval floor (10s) is far above the one-second timestamp
// resolution, so two rounds of one target can never collide.
type Round struct {
	TargetID     string
	Kind         string
	GroupID      string
	TS           int64
	Class        RoundClass
	MetricKind   string
	Comparator   string
	Value        float64
	Threshold    float64
	ReasonCode   int
	ReasonDetail string
	ConfigSerial int
	Layer        string
	Det          DetectionSettings
	Meta         TargetMeta
	// The endpoint this round's probe actually talked to, as the collector named it
	// on the cycle's own samples. A DNS monitor's queried name and a NAT monitor's
	// resolved STUN endpoint are not dialable/complete addresses on their own, so
	// these are the only record of where the traffic went. Empty for probe kinds
	// that dial their target directly, and for a DNS probe whose platform cannot
	// name the system resolver.
	ResolverAddr     string
	ResolverProtocol string
	StunAddr         string
	StunTransport    string
	// Latencies carries this round's quality metrics (RTT, jitter, loss percentage,
	// connect/resolve time) keyed by metric kind, taken from the same (monitor,
	// timestamp) group as the availability verdict above. It exists so the
	// degradation detectors can judge the same round the availability detector
	// judged, without a second pass over the batch and without any chance of the
	// two disagreeing about which round they are looking at.
	//
	// Nil for a batch that carried no quality metrics. Never consulted by the
	// availability path.
	Latencies map[string]float64
	// Baselines is the historical band for each judged metric, for THIS round's
	// own daypart bucket. Filled by ingest before it opens the write transaction;
	// an absent kind means the target is still learning and nothing is judged.
	//
	// The bucket is chosen from the round's timestamp, not from the wall clock, so
	// a WAL replay of yesterday evening's rounds is measured against yesterday
	// evening's normal.
	Baselines map[string]baseline.Band
	// SizeSweep is the round's probe.icmp.size_sweep classification, set when the
	// round carried one. A loss degradation that confirms on this round freezes it
	// as the physical-layer evidence. These are dedicated round facts, NOT baseline
	// kinds — they are never folded into Latencies or judged by a detector.
	SizeSweep *SizeSweepFacts
	// FlowFanout is the round's probe.tcp.flow_fanout classification, set when the
	// round carried one. An availability fault that confirms on this round freezes
	// it as the ECMP/LAG member-level evidence. A dedicated round fact, not a
	// baseline kind.
	FlowFanout *FlowFanoutFacts
}

// DegradationDetectorKey names the detector that judges a metric kind against a
// baseline, or "" for a kind no degradation detector owns. The two keys are
// separate detectors rather than one because they answer different questions and
// a user can silence one of them (see SmartLossSilenced) without losing the other.
func DegradationDetectorKey(metricKind string) string {
	switch metricKind {
	case string(telemetry.ICMPLoss):
		return DetectorLossDegradation
	case string(telemetry.ICMPRTTms), string(telemetry.HTTPLat),
		string(telemetry.TCPConnectMs), string(telemetry.DNSResolve):
		return DetectorLatencyDegradation
	}
	return ""
}

// SmartLossSilenced reports whether the smart loss detector must stay quiet for a
// target.
//
// A user who moved ICMPLossPct off its default has stated their tolerance for
// packet loss in the plainest way the product offers. Reporting "loss is higher
// than usual" at 15% to somebody who explicitly said "tell me at 30%" is arguing
// with them about a number they already answered. Latency degradation is
// unaffected: they set a loss threshold, not a latency one.
func SmartLossSilenced(det DetectionSettings) bool { return det.ICMPLossPct != 100 }

// degMultiplier is how far past the baseline p95 a value must go, per sensitivity.
func degMultiplier(sensitivity string) float64 {
	switch sensitivity {
	case SmartLoose:
		return 2.0
	case SmartSensitive:
		return 1.25
	}
	return 1.5
}

// degFloor is the ABSOLUTE minimum distance above the baseline p50 that a value
// must also clear, in the metric's own unit (ms for latency, percentage points
// for loss).
//
// Without it the multiplier alone would make a 1ms LAN target report a
// degradation at 2ms — technically "double its usual", and completely worthless
// as a statement about somebody's network. The floor is what makes the claim
// "noticeably slower", not merely "proportionally slower".
func degFloor(sensitivity, metricKind string) float64 {
	loss := metricKind == string(telemetry.ICMPLoss)
	switch sensitivity {
	case SmartLoose:
		if loss {
			return 20
		}
		return 30
	case SmartSensitive:
		if loss {
			return 5
		}
		return 8
	}
	if loss {
		return 10
	}
	return 15
}

// DegradationThreshold is the value a round must reach to count as degraded:
// past the usual worst case (p95 × multiplier) AND far enough above the usual
// typical case (p50 + floor) to be worth a sentence.
//
// Taking the max of the two rather than either alone is what makes one formula
// work across three orders of magnitude of "normal". On a jittery target the p95
// arm dominates and absorbs its ordinary spread; on a metronomic one the p50 arm
// dominates and stops a trivial absolute change from looking dramatic.
//
// A target whose baseline loss is already very high can produce a threshold above
// 100, which simply never fires. That is the right answer: "more loss than usual"
// tells nobody anything about a link that is usually mostly loss, and the
// availability detector already owns that target.
func DegradationThreshold(b baseline.Band, sensitivity, metricKind string) float64 {
	return math.Max(b.P95*degMultiplier(sensitivity), b.P50+degFloor(sensitivity, metricKind))
}

// DegradationFailRounds is how many consecutive degraded rounds confirm, per
// sensitivity.
//
// Deliberately slower than the availability detector's 2..5. Availability claims
// an event ("it stopped answering"); degradation claims a trend ("it has been
// worse than usual for a while"), and a trend asserted from three samples is a
// guess. The recovery count is fixed rather than tuned: how eager somebody is to
// hear about a problem says nothing about how long it should take to believe the
// problem ended.
func DegradationFailRounds(sensitivity string) int {
	switch sensitivity {
	case SmartLoose:
		return 10
	case SmartSensitive:
		return 4
	}
	return 6
}

// DegradationRecoverRounds is how many consecutive in-band rounds clear a
// degradation.
const DegradationRecoverRounds = 5

// SuccessMetricKind maps a probe kind to the metric whose value decides whether
// a round succeeded. This is the single definition shared by the fault engine,
// the availability counter and the target-status probe dimension, so the three
// can never disagree about what "up" means.
//
// ICMP (and gateway, which emits through the ICMP metric set) has no boolean: a
// cycle's health is its loss percentage. Everything else emits an explicit
// probe.<kind>.ok, whose semantics (expected status codes, body keyword, TLS)
// are already decided by the probe from the target's own configuration — so the
// server never re-implements them.
func SuccessMetricKind(probeKind string) string {
	switch probeKind {
	case "icmp", "gateway":
		return string(telemetry.ICMPLoss)
	case "tcp":
		return string(telemetry.TCPOK)
	case "http":
		return string(telemetry.HTTPOK)
	case "dns":
		return string(telemetry.DNSOK)
	case "nat":
		return string(telemetry.NATOK)
	}
	return ""
}

// reasonMetricKind maps a probe kind to the metric carrying its failure-reason
// code, or ("", false) for a kind with no reason concept (nat, host).
func reasonMetricKind(probeKind string) (string, bool) {
	switch probeKind {
	case "icmp", "gateway":
		return string(telemetry.ICMPErrorClass), true
	case "dns":
		return string(telemetry.DNSErrorClass), true
	case "http":
		return string(telemetry.HTTPErrorClass), true
	case "tcp":
		return string(telemetry.TCPErrorClass), true
	}
	return "", false
}

// Comparator returns how a probe kind's primary metric is tested, for the frozen
// evidence and the notification text: ICMP/gateway fail at or above a loss
// threshold, everything else fails below a truthy ok.
func comparatorFor(probeKind string) string {
	if probeKind == "icmp" || probeKind == "gateway" {
		return "gte"
	}
	return "lt"
}

// ComparatorGteBaseline marks evidence whose threshold was DERIVED from the
// target's own history rather than configured. The console renders it as a
// sentence ("well above its usual level") instead of as a symbol, because "≥
// 67.5" is not a number any user chose or would recognise.
const ComparatorGteBaseline = "gte_baseline"

// thresholdFor returns the numeric failure threshold used for a probe kind.
func thresholdFor(probeKind string, det DetectionSettings) float64 {
	if probeKind == "icmp" || probeKind == "gateway" {
		return det.ICMPLossPct
	}
	return 1
}

// Classify decides a round from its primary metric value. A non-finite value is
// not a verdict.
func Classify(probeKind string, value float64, det DetectionSettings) RoundClass {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return RoundInvalid
	}
	if probeKind == "icmp" || probeKind == "gateway" {
		if value >= det.ICMPLossPct {
			return RoundFail
		}
		return RoundSuccess
	}
	if SuccessMetricKind(probeKind) == "" {
		return RoundInvalid
	}
	if value >= 0.5 {
		return RoundSuccess
	}
	return RoundFail
}

// BuildRounds groups an accepted metric batch into probe rounds and classifies
// each one, returning only rounds that reached a verdict, ordered by target then
// timestamp ascending so the engine can advance each detector's state one round
// at a time in the order they happened.
//
// The failure reason is taken from the probe.<kind>.error_class sibling emitted
// in the SAME round; a code from a different round is never borrowed, since a
// metric a probe omits on failure would otherwise be paired with an unrelated
// cause.
func BuildRounds(ms []telemetry.Metric, meta map[string]TargetMeta) []Round {
	if len(ms) == 0 || len(meta) == 0 {
		return nil
	}
	type roundKey struct {
		targetID string
		ts       int64
	}
	type roundAcc struct {
		hasPrimary   bool
		value        float64
		layer        string
		configSerial int
		hasReason    bool
		reasonCode   int
		reasonDetail string
		// sent is this round's probe.icmp.sent, the echoes the agent actually
		// managed. Compared against the target's configured count to reject a
		// truncated round's verdict — see RoundComplete.
		sent int
		// Where the probe actually went. The two families sit on different samples:
		// NAT names its STUN server on the primary metric (it has no reason metric at
		// all), DNS names its resolver on the error_class metric alongside the detail.
		resolverAddr     string
		resolverProtocol string
		stunAddr         string
		stunTransport    string
		// This cycle's quality metrics, for the degradation detectors. Collected
		// alongside the verdict rather than in a second pass so both detectors provably
		// judge the same round.
		latencies map[string]float64
		// sizeSweep and flowFanout are this cycle's dedicated classification samples
		// (probe.icmp.size_sweep / probe.tcp.flow_fanout). They are NOT baseline kinds
		// — never folded into latencies — they are frozen as round evidence only.
		sizeSweep  *SizeSweepFacts
		flowFanout *FlowFanoutFacts
	}
	acc := map[roundKey]*roundAcc{}
	for i := range ms {
		m := &ms[i]
		if m.MonitorID == "" {
			continue // system/host series carry no availability verdict
		}
		tm, ok := meta[m.MonitorID]
		if !ok || !tm.Enabled {
			continue
		}
		primary := SuccessMetricKind(tm.Kind)
		if primary == "" {
			continue
		}
		reason, hasReason := reasonMetricKind(tm.Kind)
		kind := string(m.Kind)
		isPrimary := kind == primary
		isReason := hasReason && kind == reason
		isQuality := baselineKinds[kind]
		isSent := kind == string(telemetry.ICMPSent) && (tm.Kind == "icmp" || tm.Kind == "gateway")
		isSizeSweep := kind == string(telemetry.ICMPSizeSweep) && (tm.Kind == "icmp" || tm.Kind == "gateway")
		isFlowFanout := kind == string(telemetry.TCPFlowFanout) && tm.Kind == "tcp"
		if !isPrimary && !isReason && !isQuality && !isSent && !isSizeSweep && !isFlowFanout {
			continue
		}
		k := roundKey{targetID: m.MonitorID, ts: m.TS.Unix()}
		a := acc[k]
		if a == nil {
			a = &roundAcc{}
			acc[k] = a
		}
		if isSent {
			a.sent = int(m.Value)
			continue
		}
		if isSizeSweep {
			a.sizeSweep = sizeSweepFactsFrom(m)
			continue
		}
		if isFlowFanout {
			a.flowFanout = flowFanoutFactsFrom(m)
			continue
		}
		// A quality metric can also BE the primary one (ICMP loss is both), so this
		// records first and the primary/reason branches below still run for it.
		if isQuality && !math.IsNaN(m.Value) && !math.IsInf(m.Value, 0) {
			if a.latencies == nil {
				a.latencies = map[string]float64{}
			}
			a.latencies[kind] = m.Value
		}
		if isPrimary {
			a.hasPrimary = true
			a.value = m.Value
			a.layer = string(m.Layer)
			a.configSerial = m.ConfigSerial
			a.stunAddr = m.Labels[telemetry.NATServerLabel]
			a.stunTransport = m.Labels[telemetry.NATTransportLabel]
			continue
		}
		if !isReason {
			continue // quality-only sample: recorded above, nothing else to do
		}
		a.hasReason = true
		a.reasonCode = int(m.Value)
		a.reasonDetail = m.Labels[telemetry.ProbeReasonDetailLabel]
		a.resolverAddr = m.Labels[telemetry.DNSResolverLabel]
		a.resolverProtocol = m.Labels[telemetry.DNSResolverProtocolLabel]
	}

	out := make([]Round, 0, len(acc))
	for k, a := range acc {
		if !a.hasPrimary {
			continue // no primary metric this cycle → not a verdict
		}
		tm := meta[k.targetID]
		if !RoundComplete(tm.Kind, a.sent, tm.PingCount) {
			continue // the agent's probe budget truncated it → not a verdict
		}
		class := Classify(tm.Kind, a.value, tm.Det)
		if class == RoundInvalid {
			continue
		}
		r := Round{
			TargetID: k.targetID, Kind: tm.Kind, GroupID: tm.GroupID, TS: k.ts,
			Class: class, MetricKind: SuccessMetricKind(tm.Kind), Comparator: comparatorFor(tm.Kind),
			Value: a.value, Threshold: thresholdFor(tm.Kind, tm.Det),
			ConfigSerial: a.configSerial, Layer: a.layer, Det: tm.Det, Meta: tm,
			StunAddr: a.stunAddr, StunTransport: a.stunTransport,
			Latencies:  a.latencies,
			SizeSweep:  a.sizeSweep,
			FlowFanout: a.flowFanout,
		}
		if r.Layer == "" {
			r.Layer = builtinLayer(tm.Kind)
		}
		if a.hasReason {
			r.ReasonCode = a.reasonCode
			r.ReasonDetail = a.reasonDetail
			r.ResolverAddr = a.resolverAddr
			r.ResolverProtocol = a.resolverProtocol
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetID != out[j].TargetID {
			return out[i].TargetID < out[j].TargetID
		}
		return out[i].TS < out[j].TS
	})
	return out
}

// sizeSweepFactsFrom reads one probe.icmp.size_sweep sample's classification code
// (Metric.Value) and its label evidence. A missing or unparsable label yields its
// zero value — the sample still carries Code, which is what the hooks branch on.
func sizeSweepFactsFrom(m *telemetry.Metric) *SizeSweepFacts {
	return &SizeSweepFacts{
		Code:        int(m.Value),
		SizeSmall:   atoiLabel(m, telemetry.SizeSmallLabel),
		SizeLarge:   atoiLabel(m, telemetry.SizeLargeLabel),
		LossSmall:   parseFloatLabel(m, telemetry.LossSmallLabel),
		LossLarge:   parseFloatLabel(m, telemetry.LossLargeLabel),
		CountSmall:  atoiLabel(m, telemetry.CountSmallLabel),
		CountLarge:  atoiLabel(m, telemetry.CountLargeLabel),
	}
}

// flowFanoutFactsFrom reads one probe.tcp.flow_fanout sample's classification
// code (Metric.Value) and its flow-count labels. Same leniency as
// sizeSweepFactsFrom.
func flowFanoutFactsFrom(m *telemetry.Metric) *FlowFanoutFacts {
	return &FlowFanoutFacts{
		Code:      int(m.Value),
		Flows:     atoiLabel(m, telemetry.FlowFanoutFlowsLabel),
		BadStable: atoiLabel(m, telemetry.FlowFanoutBadStableLabel),
		BadNew:    atoiLabel(m, telemetry.FlowFanoutBadNewLabel),
		OK:        atoiLabel(m, telemetry.FlowFanoutOKLabel),
	}
}

func atoiLabel(m *telemetry.Metric, key string) int {
	v, _ := strconv.Atoi(m.Labels[key])
	return v
}

func parseFloatLabel(m *telemetry.Metric, key string) float64 {
	v, _ := strconv.ParseFloat(m.Labels[key], 64)
	return v
}

// AvailabilitySamples projects rounds onto the derived probe.round.ok series
// (1 = available, 0 = not), one sample per round, stamped with the round's own
// timestamp and generation.
//
// Availability is stored as an ordinary metric rather than a bespoke aggregate
// table so it inherits the whole time-series pipeline for free: the samples
// primary key makes a replayed packet idempotent, the rollup worker turns each
// bucket's (cnt, total) into an exact success ratio, and the tiered retention
// already keeps 30 days of minute buckets and two years of hourly ones — enough
// for the 24h/7d/30d windows the UI asks for. Rounds that reached no verdict
// produce no sample, so they are absent from the denominator instead of being
// counted as failures.
func AvailabilitySamples(rounds []Round) []telemetry.Metric {
	if len(rounds) == 0 {
		return nil
	}
	out := make([]telemetry.Metric, 0, len(rounds))
	for _, r := range rounds {
		v := 0.0
		if r.Class == RoundSuccess {
			v = 1
		}
		out = append(out, telemetry.Metric{
			TS:           timeFromUnix(r.TS),
			Kind:         telemetry.MetricKind(metrics.RoundOKKind),
			Target:       r.Meta.Addr,
			Layer:        telemetry.HealthLayer(r.Layer),
			Value:        v,
			Unit:         telemetry.UnitBool,
			MonitorID:    r.TargetID,
			ConfigSerial: r.ConfigSerial,
		})
	}
	return out
}
