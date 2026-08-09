// Package fault is the built-in fault-detection domain (ALERT-002). Detection is
// zero-config and unconditional: every enabled monitoring target gets a built-in
// availability detector on every Agent that executes it, with no user-created
// rule involved. The detector's only tunables are its sensitivity (confirm after
// N consecutive failing rounds, recover after M consecutive succeeding rounds)
// and, for ICMP/gateway, the loss percentage that counts as unreachable.
//
// The package owns:
//
//   - round.go       — the single definition of what a probe round is and whether
//     it succeeded, failed, or is not a verdict at all;
//   - engine.go      — the per-round state machine that confirms and resolves
//     fault signals and maintains their incidents, inside the
//     caller's ingest transaction;
//   - terminate.go   — the configuration-change termination paths;
//   - agent_signal.go — the Agent-connectivity detector's write path;
//   - fluctuation.go — sub-threshold streaks that recovered: the record that
//     explains an availability dip which raised no fault;
//   - signal_read.go / fluctuation_read.go — the read queries the API renders.
//
// Notification is deliberately NOT here. The engine records the fact and plans a
// delivery through the injected Planner; whether, when and where anything is
// actually sent belongs to the notification policy layer. A fault is recorded in
// full even when no channel exists.
package fault

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/store"
)

// Detector keys. A detector is the thing that reaches a verdict about one
// (agent, target) pair; its key is part of the signal's active identity.
const (
	// DetectorAvailability is the built-in per-target availability detector.
	DetectorAvailability = "availability"
	// DetectorAgentConnectivity is the built-in Agent-liveness detector. Its
	// signals carry no target (target_id ''), so they resolve their notification
	// policy straight from the site default.
	DetectorAgentConnectivity = "agent_connectivity"
	// DetectorLatencyDegradation and DetectorLossDegradation are the ALERT-003
	// quality detectors: the target still answers, but noticeably worse than it
	// normally does at this time of day. They are separate keys — and therefore
	// separate detector_state rows, separate signals and separate incidents — from
	// availability because "slow" and "unreachable" are different claims with
	// different remedies, and because the loss one can be silenced on its own when
	// the operator has already stated a loss tolerance of their own.
	DetectorLatencyDegradation = "latency_degradation"
	DetectorLossDegradation    = "loss_degradation"

	// The system-status family: the built-in detectors over a host anchor's own
	// machine metrics. Unlike the probe detectors these DO carry a threshold, and
	// unlike the deleted rule engine the threshold is the only thing an operator
	// states — what to watch, how to confirm it and what to call it are fixed.
	//
	// A machine has one CPU figure and one memory figure but many disks and two
	// directions of traffic, so the two multi-subject families fold their subject
	// into the key after a '|' (see HostDetectorKey): 'host_disk|C:',
	// 'host_net|rx'. That keeps every key-shaped contract in the schema — the
	// detector_state primary key, the open-signal unique index, the target-scoped
	// termination predicates — saying exactly what it said before, while letting
	// two mounts be full at the same time.
	DetectorHostCPU  = "host_cpu"
	DetectorHostMem  = "host_mem"
	DetectorHostLoad = "host_load"
	DetectorHostNet  = "host_net"
	DetectorHostDisk = "host_disk"
)

// hostDetectorSubjectSep separates a system-status family from its subject. It is
// '|' because a subject is a mount point, and mount points contain ':' on Windows
// and '/' everywhere else.
const hostDetectorSubjectSep = "|"

// HostDetectorKey composes a system-status detector key. An empty subject yields
// the bare family, which is what the single-subject families (cpu, mem, load) use.
func HostDetectorKey(family, subject string) string {
	if subject == "" {
		return family
	}
	return family + hostDetectorSubjectSep + subject
}

// SplitHostDetectorKey splits a stored detector key back into its family and
// subject. A key with no subject returns it unchanged and an empty subject, so
// callers can run every key through this unconditionally.
func SplitHostDetectorKey(key string) (family, subject string) {
	if f, s, ok := strings.Cut(key, hostDetectorSubjectSep); ok {
		return f, s
	}
	return key, ""
}

// IsHostDetector reports whether a detector key belongs to the system-status
// family. Used wherever a caller must not treat a machine-resource verdict as a
// network one — most importantly in incident attribution, which reasons about
// what the network path implies and has nothing to say about a full disk.
func IsHostDetector(detectorKey string) bool {
	switch family, _ := SplitHostDetectorKey(detectorKey); family {
	case DetectorHostCPU, DetectorHostMem, DetectorHostLoad, DetectorHostNet, DetectorHostDisk:
		return true
	}
	return false
}

// IsDegradation reports whether a detector key belongs to the baseline-relative
// quality family. Used wherever a caller has to distinguish "measurably worse"
// from "not working", most importantly in the path-diagnostic trigger: a slow
// target does not warrant a traceroute.
func IsDegradation(detectorKey string) bool {
	return detectorKey == DetectorLatencyDegradation || detectorKey == DetectorLossDegradation
}

// Resolve reasons stored on fault_signals.resolve_reason and mirrored onto the
// incident. Only ReasonRecovered means the fault actually went away; every other
// reason is a configuration/lifecycle termination and must never be announced as
// a recovery.
const (
	ReasonRecovered        = "recovered"
	ReasonConfigChanged    = "configuration_changed"
	ReasonTargetDisabled   = "target_disabled"
	ReasonTargetDeleted    = "target_deleted"
	ReasonAgentScopeChange = "agent_scope_changed"
	ReasonAgentDeleted     = "agent_deleted"
	ReasonMuted            = "muted"
	ReasonDisabled         = "disabled"
	// ReasonSuperseded ends a signal that a more fundamental fault took over.
	// Today that is a quality degradation on a target whose availability detector
	// has since confirmed an outage: "markedly slower than usual" is not a claim
	// worth keeping open about a target that has stopped answering, and it is
	// certainly not a recovery.
	ReasonSuperseded = "superseded"
	// ReasonSubjectGone ends a system-status signal whose subject stopped existing:
	// the removable disk carrying a "nearly full" fault was ejected. It is
	// deliberately not a recovery — the disk did not get emptier, it left — so it
	// closes the fault without announcing that anything was fixed.
	ReasonSubjectGone = "subject_gone"
)

// IsRecovery reports whether a resolve reason represents a genuine recovery (the
// only reason that may produce a "resolved" notification).
func IsRecovery(reason string) bool { return reason == ReasonRecovered }

// Severities, ranked. The enum is shared with the notification renderer and the
// target-status aggregation, so it stays exactly as it was under the rule engine.
const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityError    = "error"
	SeverityCritical = "critical"
)

var severityRank = map[string]int{
	SeverityInfo: 0, SeverityWarn: 1, SeverityError: 2, SeverityCritical: 3,
}

// layerPriority orders suspected root-cause layers; the first present layer wins
// an incident's suspected_layer.
var layerPriority = []string{"local", "lan", "wan", "internet", "dns", "service", "wireless"}

// MostFundamentalLayer picks the deepest layer present, which is the one most
// likely to explain the rest: if the LAN is down, the DNS and service failures
// above it are consequences, not independent faults. Returns "" when nothing is
// annotated.
//
// Exported so the layer a storm blames is decided by the same ordering an
// incident's suspected_layer is, rather than by a second copy that can drift.
func MostFundamentalLayer(layers []string) string {
	present := make(map[string]bool, len(layers))
	for _, l := range layers {
		present[l] = true
	}
	for _, l := range layerPriority {
		if present[l] {
			return l
		}
	}
	return ""
}

// WorstSeverity returns the highest-ranked severity in the set.
//
// The floor is SeverityWarn only when NOTHING in the set is recognizable
// (including an empty set): unreadable data is announced rather than swallowed.
// A set that is genuinely all-info stays info — that is what lets an incident or
// a storm made only of quality degradations sit below the default notification
// floor instead of being silently promoted into a notification nobody asked for.
func WorstSeverity(severities []string) string {
	worst := ""
	for _, sev := range severities {
		if _, ok := severityRank[sev]; !ok {
			continue
		}
		if worst == "" || severityRank[sev] > severityRank[worst] {
			worst = sev
		}
	}
	if worst == "" {
		return SeverityWarn
	}
	return worst
}

// builtinLayer maps a probe kind to the network layer a failure of it most likely
// implicates. This is an advisory annotation for grouping and display only — it
// never suppresses a fault.
func builtinLayer(probeKind string) string {
	switch probeKind {
	case "gateway":
		return "lan"
	case "dns":
		return "dns"
	case "http", "tcp":
		return "service"
	case "icmp", "nat":
		return "internet"
	}
	return ""
}

// SnapshotWriter writes an incident's immutable base snapshot synchronously
// inside the incident-open transaction (INCIDENT-002). Injected (satisfied by
// *incidentops.Service) so this package does not import the orchestration layer.
// Nil-safe; a returned error is advisory and never blocks the incident.
type SnapshotWriter interface {
	WriteIncidentBase(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) error
}

// IncidentScope describes the incident a delivery plan is being made for: enough
// for the policy layer to resolve its precedence chain without importing this
// package's types.
//
// AgentID is the vantage point the confirming signal was observed from. This
// package makes no use of it — it is carried purely so the policy layer can
// correlate a burst of simultaneous incidents seen by ONE agent into a single
// announcement (ALERT-001). Detection stays entirely unaware of that grouping.
type IncidentScope struct {
	IncidentID string
	SiteID     string
	GroupID    string
	AgentID    string
	Severity   string
	// AgentConnectivity marks this as an Agent-liveness incident, so the policy
	// layer routes it through the site's Agent-connectivity policy instead of the
	// group chain it has no place in. It is a flag rather than "AgentID is set
	// and GroupID is not" because AgentID means something else entirely here (the
	// vantage point, deliberately left empty on these incidents so an offline
	// Agent never correlates into a storm).
	AgentConnectivity bool

	// ReplayLag is how far the confirming evidence lags the transaction's wall
	// clock, in excess of what this target's own cadence makes normal. It is
	// zero for telemetry arriving live — including from an agent configured with
	// a slow upload interval — and large for a backlog an agent buffered through
	// an outage and uploaded on reconnect.
	//
	// The policy layer needs it because a replayed fault arrives already finished:
	// the rounds that confirm it and the rounds that resolve it are seconds apart
	// on the wire even though they are twenty minutes apart in the evidence. The
	// notification delay is what normally lets a fault that recovered quickly go
	// unannounced, but that delay is configurable down to zero, and at zero the
	// worker can send an alarm about an outage that ended before the message was
	// composed. See notifypolicy for what it does with this.
	ReplayLag time.Duration
}

// ReplayThreshold is the FLOOR on how far behind the wall clock a
// confirmation's evidence has to be before it counts as replayed rather than
// live.
//
// It is only a floor because "late" is a per-target quantity. The lag of live
// telemetry is the probe instant plus batching plus the drain interval plus
// ingest, and an install is free to configure an upload cadence longer than any
// fixed constant here — at which point every honest round would look replayed
// and every notification would inherit the settle delay. Callers therefore take
// the maximum of this and the target's own consecutive-round tolerance
// (TargetMeta.maxRoundGap, which already folds in the agent's REPORTED upload
// interval); see replayLagOf.
//
// Two minutes is comfortably above the default cadence and far below the outage
// lengths this distinction exists for. It is not tunable: it separates two kinds
// of event, not two tastes in alerting.
const ReplayThreshold = 2 * time.Minute

// replayLagOf reports how far behind now a confirmation's evidence is, in excess
// of what this target's own reporting cadence makes normal — zero when it is
// within it.
//
// tolerance is the target's consecutive-round gap, which already folds in the
// probe interval, the cycle deadline and the agent's REPORTED upload interval.
// Using it is what stops a legitimately slow uploader from having every one of
// its live faults classified as a replay: a round that arrived inside the window
// where two rounds still count as consecutive did not come out of a backlog.
//
// A negative lag is clamped to zero. An agent whose clock runs ahead would
// otherwise produce one that compares as "very live", which is the one direction
// that matters: it would let a genuinely replayed fault be treated as live
// because the timestamps are wrong the other way. The agent's own correction
// (agent/internal/clockmon) is what stops it happening in the first place.
func replayLagOf(evidence, now time.Time, tolerance time.Duration) time.Duration {
	if evidence.IsZero() {
		return 0
	}
	floor := ReplayThreshold
	if tolerance > floor {
		floor = tolerance
	}
	d := now.Sub(evidence)
	if d <= floor {
		return 0
	}
	return d
}

// Planner is the notification-policy surface the engine calls inside its write
// transaction. Detection never depends on it succeeding in a user-visible way:
// with no policy, no channel, or a severity below the policy floor, the planner
// simply records nothing and the fault is still fully persisted.
//
// Injected (satisfied by *notifypolicy.Service) so fault does not import the
// policy layer's read models. Nil-safe.
type Planner interface {
	// PlanOpenTx schedules the open notification for a newly-opened incident.
	PlanOpenTx(ctx context.Context, tx *sql.Tx, sc IncidentScope, now time.Time) error
	// EscalateTx tightens an already-planned open notification when a merged
	// incident's severity rises (and plans one that a lower severity had skipped).
	EscalateTx(ctx context.Context, tx *sql.Tx, sc IncidentScope, now time.Time) error
	// RecomputeTx notes that an incident's severity or suspected layer changed
	// while it stayed OPEN — a partial recovery, where one member came back and
	// others are still firing. There is nothing to re-plan for the incident
	// itself, but any aggregate the policy layer maintains over it has to be
	// refreshed, or a notice still waiting out its delay would describe a state
	// that has already passed.
	RecomputeTx(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) error
	// ResolveTx cancels anything still pending and, for a genuine recovery, plans
	// the paired recovery notification for the channels that actually received the
	// open notification.
	ResolveTx(ctx context.Context, tx *sql.Tx, incidentID, reason string, now time.Time) error
}

// Service is the fault engine.
type Service struct {
	db      *store.DB
	bus     *eventbus.Bus
	snap    SnapshotWriter
	planner Planner
}

// New constructs the fault engine. bus/snap/planner may be nil (tests, and the
// bring-up order where the planner is wired after construction).
func New(db *store.DB, bus *eventbus.Bus, snap SnapshotWriter) *Service {
	return &Service{db: db, bus: bus, snap: snap}
}

// SetPlanner injects the notification planner after construction, breaking the
// bring-up cycle between the engine and the policy layer (the policy layer reads
// incidents the engine writes). Call before serving.
func (s *Service) SetPlanner(p Planner) { s.planner = p }

// SetSnapshotWriter injects the incident base-snapshot writer after
// construction, for the same bring-up reason.
func (s *Service) SetSnapshotWriter(w SnapshotWriter) { s.snap = w }

// Signal is a confirmed fault lifecycle for one (agent, target, detector). Every
// display fact is frozen at confirmation time, so renaming or deleting the target
// afterwards can never rewrite what the fault said. CurrentlyAbnormal is the one
// read-time overlay: true while the signal is firing AND its detector still has
// an unbroken failing streak.
type Signal struct {
	ID string `json:"id"`
	// Title is the rendered standard statement (see SignalTitle), computed on read
	// so the stored row keeps only structured facts.
	Title            string  `json:"title"`
	SiteID           string  `json:"site_id"`
	AgentID          string  `json:"agent_id"`
	AgentName        string  `json:"agent_name"`
	TargetID         string  `json:"target_id,omitempty"`
	TargetName       string  `json:"target_name"`
	TargetAddr       string  `json:"target_addr"`
	Port             int     `json:"target_port,omitempty"`
	DetectorKey      string  `json:"detector_key"`
	ProbeKind        string  `json:"probe_kind"`
	GroupID          string  `json:"group_id,omitempty"`
	GroupName        string  `json:"group_name"`
	Layer            string  `json:"layer"`
	Severity         string  `json:"severity"`
	State            string  `json:"state"`
	ResolveReason    string  `json:"resolve_reason,omitempty"`
	FailThreshold    int     `json:"fail_threshold"`
	RecoverThreshold int     `json:"recover_threshold"`
	MetricKind       string  `json:"metric_kind"`
	Comparator       string  `json:"comparator"`
	Value            float64 `json:"value"`
	Threshold        float64 `json:"threshold"`
	ReasonCode       int     `json:"reason_code"`
	ReasonDetail     string  `json:"reason_detail"`
	// BaselineP50/BaselineP95 are the target's own historical band for this
	// metric and time of day, as it stood at confirmation. Only the degradation
	// detectors set them (both 0 elsewhere), and only they make the claim legible:
	// "180ms" is not evidence of anything until it sits next to "usually about
	// 40ms at this hour". Frozen rather than recomputed on read, because by the
	// time anybody reads it the rolling baseline has begun absorbing the very
	// degradation it is meant to explain.
	//
	// Deliberately NOT omitempty: a clean target's packet-loss baseline is
	// legitimately 0/0, and that is the most common loss degradation there is.
	// Omitting it would make "usually 0% loss" indistinguishable from "no baseline
	// evidence at all" — the one distinction a reader of this field needs.
	BaselineP50 float64 `json:"baseline_p50"`
	BaselineP95 float64 `json:"baseline_p95"`
	// The endpoint the failing probe actually talked to, frozen alongside the rest
	// of the evidence. A DNS monitor dials a resolver, a NAT monitor a STUN server,
	// a pinned monitor its proxy — none of which is TargetAddr — so this is what a
	// path diagnostic must be aimed at. Not rendered in any signal view; it exists
	// so the diagnostic can be derived from frozen evidence instead of live config.
	ResolverAddr     string `json:"resolver_addr,omitempty"`
	ResolverProtocol string `json:"resolver_protocol,omitempty"`
	StunAddr         string `json:"stun_addr,omitempty"`
	StunTransport    string `json:"stun_transport,omitempty"`
	ProxyID          string `json:"proxy_id,omitempty"`
	ProxyType        string `json:"proxy_type,omitempty"`
	ProxyAddr        string `json:"proxy_addr,omitempty"`
	// ProxyConfigSerial pins the egress generation the failing probes ran under,
	// so an in-tunnel diagnostic can demand exactly that generation rather than
	// whatever the proxy has been rotated to since.
	ProxyConfigSerial int `json:"proxy_config_serial,omitempty"`

	ObservedAt        time.Time  `json:"observed_at"`
	ConfirmedAt       time.Time  `json:"confirmed_at"`
	ResolvedAt        *time.Time `json:"resolved_at"`
	IncidentID        string     `json:"incident_id"`
	CurrentlyAbnormal bool       `json:"currently_abnormal"`
	// Rounds is the cause of every round of the confirming streak, oldest first,
	// frozen alongside the summary evidence above. Three failing rounds can fail
	// three different ways, and only this tells the reader which. Empty for the
	// agent-connectivity detector, which has no rounds.
	Rounds []FailEvidence `json:"rounds"`
}

// SignalEvent is the bus payload for TopicFaultConfirmed / TopicFaultResolved,
// published post-commit. Consumers (diagnostics, status refresh) re-read what
// they need by id, so the event stays small and stable.
type SignalEvent struct {
	SignalID   string
	IncidentID string
	SiteID     string
	AgentID    string
	TargetID   string
	Severity   string
	// DetectorKey lets a consumer act on what KIND of verdict this was without
	// re-reading the row. The path diagnostic needs it: a degradation signal must
	// not spend an Agent's traceroute budget on a target that is answering fine,
	// just slowly.
	DetectorKey string
	// Reason is set only on TopicFaultResolved.
	Reason string
}
