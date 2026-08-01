package fault

import (
	"math"
	"sort"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/metrics"
)

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
	// Revision advances on every edit. The detector's stored counters are pinned to
	// the revision they accumulated under, so a sensitivity change restarts counting
	// instead of applying a new threshold to an old streak.
	Revision int `json:"revision"`
}

// DefaultDetection is the balanced profile every target gets for free: confirm
// after 3 consecutive failing rounds, recover after 2 consecutive succeeding
// rounds, and treat only 100% ICMP loss as unreachable.
func DefaultDetection() DetectionSettings {
	return DetectionSettings{
		Profile: ProfileBalanced, FailRounds: 3, RecoverRounds: 2, ICMPLossPct: 100, Revision: 1,
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
	// MaxRoundGap is how far apart two rounds may be and still count as
	// consecutive. Zero falls back to the kind's default schedule (see
	// maxRoundGap), so a caller that does not set it still gets a sane bound
	// rather than an unbounded one.
	MaxRoundGap time.Duration
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
}

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
		// Where the probe actually went. The two families sit on different samples:
		// NAT names its STUN server on the primary metric (it has no reason metric at
		// all), DNS names its resolver on the error_class metric alongside the detail.
		resolverAddr     string
		resolverProtocol string
		stunAddr         string
		stunTransport    string
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
		if kind != primary && !(hasReason && kind == reason) {
			continue
		}
		k := roundKey{targetID: m.MonitorID, ts: m.TS.Unix()}
		a := acc[k]
		if a == nil {
			a = &roundAcc{}
			acc[k] = a
		}
		if kind == primary {
			a.hasPrimary = true
			a.value = m.Value
			a.layer = string(m.Layer)
			a.configSerial = m.ConfigSerial
			a.stunAddr = m.Labels[telemetry.NATServerLabel]
			a.stunTransport = m.Labels[telemetry.NATTransportLabel]
			continue
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
