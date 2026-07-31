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
)

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

// WorstSeverity returns the highest-ranked severity in the set, defaulting to
// SeverityWarn for an empty or wholly unrecognized set (the same floor an
// incident recomputes to).
func WorstSeverity(severities []string) string {
	worst := SeverityWarn
	for _, sev := range severities {
		if severityRank[sev] > severityRank[worst] {
			worst = sev
		}
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
	Title             string     `json:"title"`
	SiteID            string     `json:"site_id"`
	AgentID           string     `json:"agent_id"`
	AgentName         string     `json:"agent_name"`
	TargetID          string     `json:"target_id,omitempty"`
	TargetName        string     `json:"target_name"`
	TargetAddr        string     `json:"target_addr"`
	Port              int        `json:"target_port,omitempty"`
	DetectorKey       string     `json:"detector_key"`
	ProbeKind         string     `json:"probe_kind"`
	GroupID           string     `json:"group_id,omitempty"`
	GroupName         string     `json:"group_name"`
	Layer             string     `json:"layer"`
	Severity          string     `json:"severity"`
	State             string     `json:"state"`
	ResolveReason     string     `json:"resolve_reason,omitempty"`
	FailThreshold     int        `json:"fail_threshold"`
	RecoverThreshold  int        `json:"recover_threshold"`
	MetricKind        string     `json:"metric_kind"`
	Comparator        string     `json:"comparator"`
	Value             float64    `json:"value"`
	Threshold         float64    `json:"threshold"`
	ReasonCode        int        `json:"reason_code"`
	ReasonDetail      string     `json:"reason_detail"`
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
	// Reason is set only on TopicFaultResolved.
	Reason string
}
