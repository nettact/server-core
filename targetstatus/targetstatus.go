// Package targetstatus is the server-authoritative current-status domain service
// (STATUS-001). It answers "what is every monitoring target's current health,
// right now" for a whole site in one read-time aggregation, with no second
// persisted current-status table: every fact is derived at read time from the
// authoritative sources — site targets and their applicable Agents, reported vs
// predicted MonitorStatus (execution eligibility + Agent liveness), the latest
// EXACT-generation probe samples (probe result + freshness), and the built-in
// detectors' live state (confirming / faulted).
//
// The three per-Agent dimensions are independent and all reported:
//
//   - execution_state — is the pair actually collecting, or why not
//     (disabled | agent_offline | pending | collecting | permission_blocked |
//     target_blocked | unsupported);
//   - probe_state — the freshness/result verdict of the latest current-generation
//     sample (no_data | healthy | failed | stale | not_applicable);
//   - fault_state — where the built-in detector stands (normal | confirming |
//     faulted). "confirming" is the honest middle answer the old model could not
//     give: the target is failing right now but has not yet met its confirmation
//     threshold, so it is neither healthy nor a recorded fault.
//
// A target-level display_state rolls the per-Agent facts up through the fixed
// display-priority decision table. Reads run in one read-pool snapshot
// transaction so signals and detector counters — which the fault engine commits
// together — can never be observed inconsistently.
package targetstatus

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
)

// ErrSiteNotFound is returned by SiteStatuses when the requested site does not
// exist, so the API can answer 404 (distinct from a dependency/query failure,
// which is a truthful 500).
var ErrSiteNotFound = errors.New("targetstatus: site not found")

// ---- stable enum values (machine values; only the frontend localizes them) ----

const (
	execDisabled          = "disabled"
	execUnassigned        = "unassigned" // target-only; never per-agent
	execPending           = "pending"
	execCollecting        = "collecting"
	execPermissionBlocked = "permission_blocked"
	execTargetBlocked     = "target_blocked"
	execUnsupported       = "unsupported"
	execAgentOffline      = "agent_offline"

	probeNoData        = "no_data"
	probeHealthy       = "healthy"
	probeFailed        = "failed"
	probeStale         = "stale"
	probeNotApplicable = "not_applicable"

	faultNormal     = "normal"
	faultConfirming = "confirming"
	faultFaulted    = "faulted"

	displayDisabled       = "disabled"
	displayUnassigned     = "unassigned"
	displayFaulted        = "faulted"
	displayConfirming     = "confirming"
	displayPartialFailure = "partial_failure"
	displayProbeFailed    = "probe_failed"
	displayBlocked        = "blocked"
	displayAgentOffline   = "agent_offline"
	displayPending        = "pending"
	displayStale          = "stale"
	displayNoData         = "no_data"
	displayHealthy        = "healthy"

	reasonTargetDisabled    = "target_disabled"
	reasonNoApplicable      = "no_applicable_agents"
	reasonAgentOffline      = "agent_offline"
	reasonPermissionBlocked = "permission_blocked"
	reasonTargetBlocked     = "target_blocked"
	reasonUnsupported       = "unsupported"
	reasonAwaitingStatus    = "awaiting_status_report"
	reasonFaultConfirmed    = "fault_confirmed"
	reasonFaultConfirming   = "fault_confirming"
	reasonProbeFailed       = "probe_failed"
	reasonProbeStale        = "probe_stale"
	reasonProbeNoData       = "probe_no_data"
	reasonNotApplicable     = "not_applicable"
	reasonOK                = "ok"
)

// severityRank orders alert severities (mirrors rules/notify.go). Used to pick a
// target's worst current severity.
var severityRank = map[string]int{"info": 0, "warn": 1, "error": 2, "critical": 3}

// timeRangeToken keeps the response self-describing. Callers validate the
// duration against the API's fixed range set before reaching the service.
func timeRangeToken(window time.Duration) string {
	switch window {
	case 3 * time.Hour:
		return "3h"
	case 7 * 24 * time.Hour:
		return "7d"
	case 30 * 24 * time.Hour:
		return "30d"
	case 90 * 24 * time.Hour:
		return "90d"
	default:
		return "24h"
	}
}

// ---- API DTOs (frozen contract shared with the web-console types) ----

// SiteStatuses is one deterministic batch of every target's current status for a
// site, at a single generated_at snapshot.
type SiteStatuses struct {
	GeneratedAt time.Time      `json:"generated_at"`
	SiteID      string         `json:"site_id"`
	TimeRange   string         `json:"time_range"`
	Targets     []TargetStatus `json:"targets"`
}

// TargetStatus is one target's aggregated current status across every applicable
// Agent. worst_severity is present only for alerting/breaching targets;
// last_observed_at is omitted when no current-generation sample exists anywhere.
type TargetStatus struct {
	TargetID         string     `json:"target_id"`
	GroupID          string     `json:"group_id"`
	Name             string     `json:"name"`
	Kind             string     `json:"kind"`
	Target           string     `json:"target"`
	Enabled          bool       `json:"enabled"`
	DisplayState     string     `json:"display_state"`
	ApplicableAgents int        `json:"applicable_agents"`
	AffectedAgents   int        `json:"affected_agents"`
	WorstSeverity    string     `json:"worst_severity,omitempty"`
	LastObservedAt   *time.Time `json:"last_observed_at,omitempty"`
	// Availability is the share of verdict-reaching probe rounds in the requested
	// window that succeeded, across every Agent. Nil when the window holds no
	// verdict at all — "unknown" and "0%" are different answers and must look it.
	Availability *float64 `json:"availability,omitempty"`
	// AvailabilityRounds and AvailabilityOKRounds expose the exact denominator and
	// numerator behind Availability. Besides making the percentage auditable, the
	// counts make nested windows visibly distinct even when all of them are 100%.
	AvailabilityRounds   int64 `json:"availability_rounds"`
	AvailabilityOKRounds int64 `json:"availability_ok_rounds"`
	// Fluctuations counts the failing streaks that recovered before confirming a
	// fault over the same requested window, across every Agent. It travels with the
	// availability figure because it is the answer to the question that figure
	// raises: a ratio under 100% with no fault to show for it used to be a dead end.
	Fluctuations int           `json:"fluctuations"`
	SignalIDs    []string      `json:"signal_ids"`
	IncidentIDs  []string      `json:"incident_ids"`
	Agents       []AgentStatus `json:"agents"`
}

// AgentStatus is one target's status as seen from one applicable Agent. The three
// dimensions are independent. stale_after_seconds is per-agent (the reported
// effective schedule when confirmed, else the desired-config fallback) and is
// omitted for host targets; pending_since is present iff execution_state=pending.
type AgentStatus struct {
	AgentID            string     `json:"agent_id"`
	AgentName          string     `json:"agent_name"`
	AgentOnline        bool       `json:"agent_online"`
	ExecutionState     string     `json:"execution_state"`
	ProbeState         string     `json:"probe_state"`
	FaultState         string     `json:"fault_state"`
	ReasonCode         string     `json:"reason_code"`
	StaleAfterSeconds  *int       `json:"stale_after_seconds,omitempty"`
	PendingSince       *time.Time `json:"pending_since,omitempty"`
	MissingPermissions []string   `json:"missing_permissions"`
	MatchedSelector    string     `json:"matched_selector"`
	BlockReason        string     `json:"block_reason"`
	LastValue          *float64   `json:"last_value,omitempty"`
	LastMetricKind     string     `json:"last_metric_kind,omitempty"`
	LastUnit           string     `json:"last_unit,omitempty"`
	LastObservedAt     *time.Time `json:"last_observed_at,omitempty"`
	// Confirm reports how far the built-in detector is from confirming a fault.
	// Present whenever a failing streak is in progress, including after a fault is
	// already confirmed (where it shows the streak is unbroken).
	Confirm *ConfirmProgress `json:"confirm,omitempty"`
	// Fault links to the confirmed fault when fault_state is faulted.
	Fault *FaultRef `json:"fault,omitempty"`
	// Availability is this pair's probe-round success ratio over the requested window.
	Availability         *float64 `json:"availability,omitempty"`
	AvailabilityRounds   int64    `json:"availability_rounds"`
	AvailabilityOKRounds int64    `json:"availability_ok_rounds"`
	// Fluctuations is this pair's count of recovered sub-threshold streaks over
	// the same window — what explains the ratio beside it.
	Fluctuations int `json:"fluctuations"`
}

// ConfirmProgress is a detector's live confirmation streak: how many consecutive
// failing rounds have accumulated against how many are needed. It exists so the
// console can say "failing, 2 of 3" instead of showing a failing target as
// simply healthy until the threshold trips.
type ConfirmProgress struct {
	FailRounds  int        `json:"fail_rounds"`
	NeedRounds  int        `json:"need_rounds"`
	FirstFailAt *time.Time `json:"first_fail_at,omitempty"`
}

// FaultRef links a target×Agent pair to its confirmed fault and the incident
// that owns it, so every status row can deep-link into the fault centre.
type FaultRef struct {
	SignalID    string    `json:"signal_id"`
	IncidentID  string    `json:"incident_id"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	ObservedAt  time.Time `json:"observed_at"`
	ConfirmedAt time.Time `json:"confirmed_at"`
	// Attribution is the owning incident's one-line position ('' when none), so
	// the per-agent fault panel can say "likely at the ISP line" without another
	// incident lookup per row.
	Attribution string `json:"attribution,omitempty"`
	// AttributionEvidence is the raw typed JSON behind the attribution, passed
	// through for the console's own rendering.
	AttributionEvidence json.RawMessage `json:"attribution_evidence,omitempty"`
}

// Service reads the authoritative current status. It owns no persisted state.
type Service struct {
	db      *store.DB
	metrics *metrics.Store // nil-safe: availability is then simply omitted
}

// New constructs the service over the shared store.
func New(db *store.DB, m *metrics.Store) *Service { return &Service{db: db, metrics: m} }

// ---- internal read models ----

type targetRow struct {
	id, groupID, name, kind, target string
	enabled                         bool
	configSerial                    int
	configChangedAt                 sql.NullTime
	params                          pcfg.ProbeParams
	// pingCount is the configured ICMP packet count a round's reported sent count
	// is measured against, derived through the same helper ingest uses so the
	// probe_state chip and the detector can never disagree about which rounds
	// count. Zero for every other kind.
	pingCount      int
	detection      fault.DetectionSettings
	groupIsDefault bool
	groupName      string
}

type applicablePair struct {
	agentID, agentName string
	online             bool
}

type msRow struct {
	status, source     string
	targetConfigSerial int
	assignedAt         sql.NullTime
	missing            []string
	matchedSelector    string
	reason             string
	effInterval        sql.NullInt64
	cycleDeadline      sql.NullInt64
	uploadInterval     sql.NullInt64
}

type sampleVal struct {
	kind, unit string
	ts         int64
	value      float64
}

// detState is one (target, agent) built-in detector's live counters.
type detState struct {
	failRounds  int
	needRounds  int
	firstFailTS sql.NullInt64
	updatedAt   sql.NullTime
}

// firingSignal is one (target, agent) confirmed fault.
type firingSignal struct {
	signalID, incidentID, severity, title, attribution, attrEv string
	observedAt, confirmedAt                                    time.Time
}

// agentAgg is the per-agent classification fed to the target-level decision table.
type agentAgg struct {
	exec, probe, fault string
	online             bool
	pendingExpired     bool
}

// SiteStatuses computes the whole site's current target status in one read-pool
// snapshot transaction, with availability and fluctuation evidence over the
// requested window. It returns ErrSiteNotFound for an unknown site; any dependency
// or query failure returns an error (the API answers a truthful 500 and never a
// partial/empty 200).
func (s *Service) SiteStatuses(ctx context.Context, siteID string, timeRange time.Duration) (SiteStatuses, error) {
	now := time.Now().UTC()

	// The snapshot's results, declared out here so the transaction can close
	// before the out-of-snapshot reads below run. Which queries are inside the
	// snapshot and which are deliberately outside it is the whole point of this
	// function's shape, so the boundary is the closure's braces rather than a
	// comment about where it used to end.
	var (
		targets   []targetRow
		pairs     map[string][]applicablePair
		msByKey   map[string]*msRow
		samples   map[string]*sampleVal
		detectors map[string]detState
		signals   map[string]firingSignal
	)
	// One read snapshot: WAL isolation holds for the life of a single read
	// transaction, so fault signals and detector counters (committed together by
	// the fault engine) can never be observed torn across the queries below. The
	// read pool is already query_only, which is the enforcement ReadTx relies on.
	if err := s.db.ReadTx(ctx, store.Standalone(), func(tx store.Executor) error {
		// Site existence (404 boundary).
		var siteSerial int
		if err := tx.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id=?`, siteID).Scan(&siteSerial); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSiteNotFound
			}
			return err
		}

		var err error
		if targets, err = s.loadTargets(ctx, tx, siteID); err != nil {
			return err
		}
		if pairs, err = s.loadApplicablePairs(ctx, tx, siteID); err != nil {
			return err
		}
		if msByKey, err = s.loadMonitorStatus(ctx, tx, siteID); err != nil {
			return err
		}
		if samples, err = s.loadLatestSamples(ctx, tx, siteID); err != nil {
			return err
		}
		if detectors, err = s.loadDetectorState(ctx, tx, siteID); err != nil {
			return err
		}
		if signals, err = s.loadFiringSignals(ctx, tx, siteID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return SiteStatuses{}, err
	}

	// Availability is read outside the snapshot: it aggregates rollup buckets that
	// no other dimension depends on, so an extra query on the read pool is cheaper
	// than widening the snapshot, and a one-round skew in the ratio is not
	// observable.
	avail := map[string]metrics.AvailabilityRatio{}
	availByAgent := map[string]map[string]metrics.AvailabilityRatio{}
	if s.metrics != nil {
		var err error
		avail, availByAgent, err = s.metrics.AvailabilityForSiteWithAgents(ctx, siteID, now.Add(-timeRange).Unix(), now.Unix())
		if err != nil {
			return SiteStatuses{}, err
		}
	}
	// Fluctuation counts ride along for the same reason and on the same read pool:
	// the console shows them next to the availability ratio, and one grouped query
	// keeps that from costing a request per row.
	flux, err := s.loadFluctuationCounts(ctx, siteID, now.Add(-timeRange), now)
	if err != nil {
		return SiteStatuses{}, err
	}

	out := SiteStatuses{
		GeneratedAt: now, SiteID: siteID, TimeRange: timeRangeToken(timeRange),
		Targets: make([]TargetStatus, 0, len(targets)),
	}
	for i := range targets {
		t := &targets[i]
		out.Targets = append(out.Targets, s.assembleTarget(t, pairs[t.id], now,
			msByKey, samples, detectors, signals, avail[t.id], availByAgent[t.id], flux[t.id]))
	}
	sortTargets(out.Targets, targets)
	return out, nil
}

// assembleTarget builds one target's status: derive each applicable Agent's three
// dimensions, then roll them up through the decision table and collect the
// target-level linkage (signals / incidents / worst severity / availability).
func (s *Service) assembleTarget(t *targetRow, pairs []applicablePair, now time.Time,
	msByKey map[string]*msRow, samples map[string]*sampleVal,
	detectors map[string]detState, signals map[string]firingSignal,
	avail metrics.AvailabilityRatio, availByAgent map[string]metrics.AvailabilityRatio,
	fluxByAgent map[string]int) TargetStatus {

	ts := TargetStatus{
		TargetID: t.id, GroupID: t.groupID, Name: t.name, Kind: t.kind, Target: t.target,
		Enabled: t.enabled, ApplicableAgents: len(pairs),
		SignalIDs: []string{}, IncidentIDs: []string{},
		Agents: make([]AgentStatus, 0, len(pairs)),
	}
	if avail.Rounds > 0 {
		r := avail.Ratio
		ts.Availability = &r
		ts.AvailabilityRounds = avail.Rounds
		ts.AvailabilityOKRounds = avail.OKRounds
	}
	// Counted over the SAME agents whose rounds produced the availability figure
	// above, because this number exists to explain that figure and the two are read
	// together. That population is neither "every agent with a fluctuation" nor
	// "currently applicable agents":
	//
	//   - an agent removed from the group's scope keeps its probe.round.ok samples
	//     (nothing purges them), so it still drags the ratio down for the rest of the
	//     window — counting only applicable pairs would show 0 dips against a ratio
	//     under 100%, which is the unexplained state this feature exists to remove;
	//   - a DELETED agent has its series purged (metrics.Store.PurgeAgent) so it no
	//     longer affects the ratio, yet its fluctuations are deliberately kept as
	//     history — counting every agent in the map would then explain a dip that the
	//     ratio no longer shows.
	//
	// availByAgent is exactly the set that contributed, so it is the right key set;
	// applicable pairs are unioned in so a live agent is never silently omitted.
	counted := make(map[string]bool, len(availByAgent)+len(pairs))
	for agentID := range availByAgent {
		counted[agentID] = true
	}
	for _, p := range pairs {
		counted[p.agentID] = true
	}
	for agentID := range counted {
		ts.Fluctuations += fluxByAgent[agentID]
	}

	// Deterministic per-agent order: agent_name, agent_id.
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].agentName != pairs[j].agentName {
			return pairs[i].agentName < pairs[j].agentName
		}
		return pairs[i].agentID < pairs[j].agentID
	})

	aggs := make([]agentAgg, 0, len(pairs))
	signalSet := map[string]bool{}
	incidentSet := map[string]bool{}
	worstRank := -1
	var lastObserved *time.Time

	for _, p := range pairs {
		as, agg := s.deriveAgent(t, p, now, msByKey, samples, detectors, signals)
		if agentAvail := availByAgent[p.agentID]; agentAvail.Rounds > 0 {
			ratio := agentAvail.Ratio
			as.Availability = &ratio
			as.AvailabilityRounds = agentAvail.Rounds
			as.AvailabilityOKRounds = agentAvail.OKRounds
		}
		as.Fluctuations = fluxByAgent[p.agentID]
		ts.Agents = append(ts.Agents, as)
		aggs = append(aggs, agg)

		if as.Fault != nil {
			signalSet[as.Fault.SignalID] = true
			if as.Fault.IncidentID != "" {
				incidentSet[as.Fault.IncidentID] = true
			}
			if r, ok := severityRank[as.Fault.Severity]; ok && r > worstRank {
				worstRank = r
			}
		}
		if as.LastObservedAt != nil && (lastObserved == nil || as.LastObservedAt.After(*lastObserved)) {
			lo := *as.LastObservedAt
			lastObserved = &lo
		}
	}

	display, affected := aggregate(t, aggs)
	ts.DisplayState = display
	ts.AffectedAgents = affected
	ts.SignalIDs = sortedKeys(signalSet)
	ts.IncidentIDs = sortedKeys(incidentSet)
	ts.LastObservedAt = lastObserved
	if display == displayFaulted && worstRank >= 0 {
		ts.WorstSeverity = severityName(worstRank)
	}
	return ts
}

// deriveAgent computes one (target, agent) pair's three independent dimensions,
// reason code, freshness window, pending clock and fault linkage, plus the
// aggregation classification fed to the decision table.
func (s *Service) deriveAgent(t *targetRow, p applicablePair, now time.Time,
	msByKey map[string]*msRow, samples map[string]*sampleVal,
	detectors map[string]detState, signals map[string]firingSignal) (AgentStatus, agentAgg) {

	as := AgentStatus{
		AgentID: p.agentID, AgentName: p.agentName, AgentOnline: p.online,
		MissingPermissions: []string{},
	}

	pairKey := t.id + "\x00" + p.agentID
	ms := msByKey[pairKey]
	confirmed := ms != nil && ms.source == "reported" && ms.targetConfigSerial == t.configSerial

	// Assignment cutoff for current-state reads (SRV-007): the later of the target's
	// material-generation time and this pair's assigned_at. A pair that left a
	// target's scope and re-entered without a material edit keeps the same generation
	// (and thus its stored samples/series and any surviving detector state), so the
	// generation join alone cannot exclude pre-assignment facts. assigned_at is reset
	// to the re-entry time, so any sample or detector verdict observed before it is
	// pre-assignment history and must not surface as current. Historical storage is
	// untouched — only these reads exclude it.
	cutoff := pendingSince(t, ms)

	// Freshness window (per pair). Desired-config fallback is used until the agent
	// reports its actual effective schedule for the current generation; it folds in
	// the default upload cadence since no reported upload interval exists yet.
	graceWindow := pcfg.StaleAfter(pcfg.EffectiveInterval(t.kind, t.params), pcfg.CycleDeadline(t.kind, t.params), pcfg.DefaultUploadInterval)
	staleAfter := graceWindow
	if confirmed && ms.effInterval.Valid && ms.effInterval.Int64 > 0 && ms.cycleDeadline.Valid && ms.cycleDeadline.Int64 > 0 {
		// Reported upload interval folds the probe→arrival link into the window; a
		// NULL/0 value passes 0 so StaleAfter falls back to the default internally.
		var upload time.Duration
		if ms.uploadInterval.Valid && ms.uploadInterval.Int64 > 0 {
			upload = time.Duration(ms.uploadInterval.Int64) * time.Second
		}
		staleAfter = pcfg.StaleAfter(
			time.Duration(ms.effInterval.Int64)*time.Second,
			time.Duration(ms.cycleDeadline.Int64)*time.Millisecond,
			upload)
	}
	if t.kind != "host" {
		secs := int(staleAfter / time.Second)
		as.StaleAfterSeconds = &secs
	}

	// execution_state (ordered: disabled → offline → pending → confirmed status).
	switch {
	case !t.enabled:
		as.ExecutionState = execDisabled
		as.ReasonCode = reasonTargetDisabled
	case !p.online:
		as.ExecutionState = execAgentOffline
		as.ReasonCode = reasonAgentOffline
	case !confirmed:
		as.ExecutionState = execPending
		as.ReasonCode = reasonAwaitingStatus
		as.PendingSince = pendingSince(t, ms)
	default:
		switch ms.status {
		case wire.MonitorStatusActive:
			as.ExecutionState = execCollecting
		case wire.MonitorStatusPermissionBlocked:
			as.ExecutionState = execPermissionBlocked
			as.ReasonCode = reasonPermissionBlocked
			as.MissingPermissions = nonNilStrings(ms.missing)
			as.MatchedSelector = ms.matchedSelector
			as.BlockReason = ms.reason
		case wire.MonitorStatusTargetBlocked:
			as.ExecutionState = execTargetBlocked
			as.ReasonCode = reasonTargetBlocked
			as.MatchedSelector = ms.matchedSelector
			as.BlockReason = ms.reason
		case wire.MonitorStatusUnsupported:
			as.ExecutionState = execUnsupported
			as.ReasonCode = reasonUnsupported
			as.BlockReason = ms.reason
		default:
			// Unknown reported status — treat as not yet confirmed rather than trust it.
			as.ExecutionState = execPending
			as.ReasonCode = reasonAwaitingStatus
			as.PendingSince = pendingSince(t, ms)
		}
	}

	// probe_state (independent of execution). host / disabled → not_applicable.
	// The success verdict comes from fault.Classify, the same function the detector
	// and the availability counter use, so this dimension can never disagree with
	// the fault it is displayed next to — including on a target whose ICMP loss
	// threshold has been tuned below 100%.
	det := detectors[pairKey]
	if t.kind == "host" || !t.enabled {
		as.ProbeState = probeNotApplicable
	} else if sk := fault.SuccessMetricKind(t.kind); sk == "" {
		as.ProbeState = probeNotApplicable
	} else if sv := samples[pairKey+"\x00"+sk]; sv == nil || sampleBeforeCutoff(sv.ts, cutoff) {
		// No current-generation sample, or the only one predates this pair's assignment
		// cutoff (pre-assignment history) → honest no_data.
		as.ProbeState = probeNoData
	} else {
		v := sv.value
		as.LastValue = &v
		as.LastMetricKind = sv.kind
		as.LastUnit = sv.unit
		lo := time.Unix(sv.ts, 0).UTC()
		as.LastObservedAt = &lo
		switch {
		case now.Sub(lo) > staleAfter:
			as.ProbeState = probeStale
		case !roundComplete(t, sv, samples[pairKey+"\x00"+string(telemetry.ICMPSent)]):
			// The agent's probe budget truncated this round, so its loss figure —
			// a ratio over the echoes it managed — cannot be read as health. The
			// detector abstains on exactly the same rounds (fault.RoundComplete);
			// showing a verdict here would put a green or red chip next to a fault
			// state that deliberately did not move.
			as.ProbeState = probeNoData
		case fault.Classify(t.kind, sv.value, t.detection) == fault.RoundFail:
			as.ProbeState = probeFailed
		default:
			as.ProbeState = probeHealthy
		}
	}

	// fault_state: confirmed fault, an in-progress confirmation streak, or normal.
	// Both come from live detector state, never from frozen signal evidence.
	if det.failRounds > 0 && !detectorBeforeCutoff(det, cutoff) {
		need := det.needRounds
		if need <= 0 {
			need = t.detection.FailRounds
		}
		cp := ConfirmProgress{FailRounds: det.failRounds, NeedRounds: need}
		if det.firstFailTS.Valid {
			ff := time.Unix(det.firstFailTS.Int64, 0).UTC()
			cp.FirstFailAt = &ff
		}
		as.Confirm = &cp
	}
	if sig, ok := signals[pairKey]; ok {
		as.FaultState = faultFaulted
		as.Fault = &FaultRef{
			SignalID: sig.signalID, IncidentID: sig.incidentID, Severity: sig.severity,
			Title: sig.title, ObservedAt: sig.observedAt, ConfirmedAt: sig.confirmedAt,
			Attribution: sig.attribution,
		}
		if sig.attrEv != "" && sig.attrEv != "[]" {
			as.Fault.AttributionEvidence = json.RawMessage(sig.attrEv)
		}
	} else if as.Confirm != nil {
		as.FaultState = faultConfirming
	} else {
		as.FaultState = faultNormal
	}

	// Reason code for a collecting pair reflects the most significant live signal.
	if as.ExecutionState == execCollecting {
		switch {
		case as.FaultState == faultFaulted:
			as.ReasonCode = reasonFaultConfirmed
		case as.FaultState == faultConfirming:
			as.ReasonCode = reasonFaultConfirming
		case as.ProbeState == probeFailed:
			as.ReasonCode = reasonProbeFailed
		case as.ProbeState == probeStale:
			as.ReasonCode = reasonProbeStale
		case as.ProbeState == probeNoData:
			as.ReasonCode = reasonProbeNoData
		case as.ProbeState == probeNotApplicable:
			as.ReasonCode = reasonNotApplicable
		default:
			as.ReasonCode = reasonOK
		}
	}

	agg := agentAgg{exec: as.ExecutionState, probe: as.ProbeState, fault: as.FaultState, online: p.online}
	if as.ExecutionState == execPending && as.PendingSince != nil {
		agg.pendingExpired = now.Sub(*as.PendingSince) > graceWindow
	}
	return as, agg
}

// aggregate applies the fixed display-priority decision table to a target's
// per-agent classifications, returning the target display_state and the
// affected_agents count — the number of agents in an abnormal state. A healthy
// display (including host targets and healthy-with-degraded-minority) is not a
// problem, so its affected count is 0. First matching rule wins.
func aggregate(t *targetRow, agents []agentAgg) (string, int) {
	if !t.enabled {
		return displayDisabled, 0
	}
	e := len(agents)
	if e == 0 {
		return displayUnassigned, 0
	}

	var collecting, healthy, failed, stale, nodata, notappl int
	var blocked, offline, pendingFresh, pendingExpired int
	var faulted, confirming int
	onlineAny := false
	for _, a := range agents {
		if a.online {
			onlineAny = true
		}
		switch a.fault {
		case faultFaulted:
			faulted++
		case faultConfirming:
			confirming++
		}
		switch a.exec {
		case execCollecting:
			collecting++
			switch a.probe {
			case probeHealthy:
				healthy++
			case probeFailed:
				failed++
			case probeStale:
				stale++
			case probeNoData:
				nodata++
			case probeNotApplicable:
				notappl++
			}
		case execPermissionBlocked, execTargetBlocked, execUnsupported:
			blocked++
		case execAgentOffline:
			offline++
		case execPending:
			if a.pendingExpired {
				pendingExpired++
			} else {
				pendingFresh++
			}
		}
	}
	x := collecting
	xMinusA := x - notappl // collecting, probe-applicable agents

	switch {
	case faulted > 0:
		return displayFaulted, faulted
	case confirming > 0:
		return displayConfirming, confirming
	case failed > 0 && failed == xMinusA && xMinusA > 0:
		return displayProbeFailed, failed
	case failed > 0:
		return displayPartialFailure, failed
	case x == 0 && blocked == e:
		return displayBlocked, e
	case x == 0 && !onlineAny:
		return displayAgentOffline, e
	case x == 0 && pendingFresh >= 1:
		return displayPending, pendingFresh
	case x == 0 && pendingExpired >= 1:
		return displayNoData, pendingExpired
	case x == 0:
		return displayBlocked, blocked
	case healthy > 0:
		return displayHealthy, 0
	case stale > 0:
		return displayStale, stale
	case nodata > 0:
		return displayNoData, nodata
	default:
		// X non-empty, all not_applicable (host targets collecting normally).
		return displayHealthy, 0
	}
}

// ---- queries (all inside the read snapshot tx; no per-target loop) ----

func (s *Service) loadTargets(ctx context.Context, tx store.Executor, siteID string) ([]targetRow, error) {
	def := fault.DefaultDetection()
	rows, err := tx.QueryContext(ctx, `
		SELECT pt.id, pt.group_id, COALESCE(pt.name,''), pt.kind, COALESCE(pt.target,''),
		       pt.enabled, pt.config_serial, pt.config_changed_at, COALESCE(pt.params,''),
		       mg.is_default, mg.name,
		       COALESCE(ds.fail_rounds, ?), COALESCE(ds.recover_rounds, ?), COALESCE(ds.icmp_loss_pct, ?)
		FROM probe_tasks pt
		JOIN monitor_groups mg ON mg.id = pt.group_id
		LEFT JOIN probe_detection_settings ds ON ds.target_id = pt.id
		WHERE pt.site_id=?`, def.FailRounds, def.RecoverRounds, def.ICMPLossPct, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []targetRow
	for rows.Next() {
		var t targetRow
		var enabled, isDefault int
		var params string
		if err := rows.Scan(&t.id, &t.groupID, &t.name, &t.kind, &t.target,
			&enabled, &t.configSerial, &t.configChangedAt, &params, &isDefault, &t.groupName,
			&t.detection.FailRounds, &t.detection.RecoverRounds, &t.detection.ICMPLossPct); err != nil {
			return nil, err
		}
		t.enabled = enabled == 1
		t.groupIsDefault = isDefault == 1
		t.detection = t.detection.Normalize()
		if params != "" {
			_ = json.Unmarshal([]byte(params), &t.params)
		}
		// Derived from the RAW blob through the same helper ingest uses, not from
		// the parsed struct above: that unmarshal ignores its error, so a
		// malformed blob would silently yield the zero value and the default count
		// of five, while ingest would see the parse fail and disable the check.
		// The two paths would then judge the same round differently.
		t.pingCount = fault.ConfiguredPingCount(t.kind, params)
		out = append(out, t)
	}
	return out, rows.Err()
}

// loadApplicablePairs returns, per target, the non-revoked Agents in the target's
// monitor-group scope (all_agents, or membership of one of the group's agent
// groups). The scope predicate is correlated on a.id (not the shared
// single-placeholder config.AgentScopePredicate).
func (s *Service) loadApplicablePairs(ctx context.Context, tx store.Executor, siteID string) (map[string][]applicablePair, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT pt.id, a.id,
		       COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), a.id), a.status
		FROM probe_tasks pt
		JOIN agents a ON a.site_id = pt.site_id AND a.revoked=0 AND EXISTS(
		    SELECT 1 FROM monitor_groups mg
		    WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
		        SELECT 1 FROM monitor_group_agent_groups mgag
		        JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
		        WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = a.id)))
		WHERE pt.site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]applicablePair{}
	for rows.Next() {
		var targetID, status string
		var p applicablePair
		if err := rows.Scan(&targetID, &p.agentID, &p.agentName, &status); err != nil {
			return nil, err
		}
		p.online = status == "online"
		out[targetID] = append(out[targetID], p)
	}
	return out, rows.Err()
}

func (s *Service) loadMonitorStatus(ctx context.Context, tx store.Executor, siteID string) (map[string]*msRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT ms.monitor_id, ms.agent_id, ms.status, ms.source, ms.target_config_serial,
		       ms.assigned_at, ms.missing_permissions, COALESCE(ms.matched_selector,''),
		       COALESCE(ms.reason,''), ms.effective_interval_seconds, ms.cycle_deadline_ms,
		       ms.upload_interval_seconds
		FROM monitor_status ms JOIN probe_tasks pt ON pt.id = ms.monitor_id
		WHERE pt.site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*msRow{}
	for rows.Next() {
		var monitorID, agentID, missing string
		m := &msRow{}
		if err := rows.Scan(&monitorID, &agentID, &m.status, &m.source, &m.targetConfigSerial,
			&m.assignedAt, &missing, &m.matchedSelector, &m.reason, &m.effInterval, &m.cycleDeadline,
			&m.uploadInterval); err != nil {
			return nil, err
		}
		m.missing = decodeStrings(missing)
		out[monitorID+"\x00"+agentID] = m
	}
	return out, rows.Err()
}

// loadLatestSamples returns the latest CURRENT-GENERATION sample per (monitor,
// agent, kind). The series↔probe_tasks join on config_serial structurally
// excludes every obsolete generation: a target's samples from before its last
// material change are simply not joined, so an old good sample can never surface
// as current (and a pending pair, whose new-generation series does not exist yet,
// yields no row → honest no_data).
//
// The SERIES SET — the config-consistency half — still resolves inside the
// snapshot transaction. The VALUES come from the metrics latest cache: the
// samples themselves live in the time-series data plane now, so an in-tx value
// read stopped being possible, and the cache is the post-commit,
// purge/cutoff-aware truth (a fresh series with no cached value is skipped,
// preserving the honest no_data). The one semantic shift is a sample-vs-config
// race of a single poll's width: a packet committing between this query and
// the cache read can surface a value one beat newer than the snapshot — values
// were never part of the config snapshot's consistency story.
func (s *Service) loadLatestSamples(ctx context.Context, tx store.Executor, siteID string) (map[string]*sampleVal, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT s.id, s.agent_id, s.monitor_id, s.kind, s.unit
		FROM series s
		JOIN probe_tasks pt ON pt.id = s.monitor_id AND s.config_serial = pt.config_serial
		WHERE s.site_id=? AND s.monitor_id <> ''`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type ref struct {
		id                 int64
		agentID, monitorID string
		kind, unit         string
	}
	var refs []ref
	agents := map[string]bool{}
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.id, &r.agentID, &r.monitorID, &r.kind, &r.unit); err != nil {
			return nil, err
		}
		refs = append(refs, r)
		agents[r.agentID] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string]*sampleVal{}
	if s.metrics == nil || len(refs) == 0 {
		return out, nil
	}
	agentIDs := make([]string, 0, len(agents))
	for a := range agents {
		agentIDs = append(agentIDs, a)
	}
	ids := make([]int64, len(refs))
	for i, r := range refs {
		ids[i] = r.id
	}
	vals, err := s.metrics.LatestForSeries(ctx, agentIDs, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range refs {
		lv, ok := vals[r.id]
		if !ok {
			continue // a series with no samples yet
		}
		out[r.monitorID+"\x00"+r.agentID+"\x00"+r.kind] = &sampleVal{
			kind: r.kind, unit: r.unit, ts: lv.TS, value: lv.Value,
		}
	}
	return out, nil
}

// loadDetectorState returns the site's built-in availability detector counters,
// keyed (target, agent). The needed threshold is joined from the target's own
// sensitivity so the console can render "2 of 5" for a target tuned to stable.
func (s *Service) loadDetectorState(ctx context.Context, tx store.Executor, siteID string) (map[string]detState, error) {
	def := fault.DefaultDetection()
	rows, err := tx.QueryContext(ctx, `
		SELECT ds.target_id, ds.agent_id, ds.fail_rounds, ds.first_fail_ts, ds.updated_at,
		       COALESCE(pds.fail_rounds, ?)
		FROM detector_state ds
		JOIN probe_tasks pt ON pt.id = ds.target_id
		LEFT JOIN probe_detection_settings pds ON pds.target_id = ds.target_id
		WHERE pt.site_id=? AND ds.detector_key=?`, def.FailRounds, siteID, fault.DetectorAvailability)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]detState{}
	for rows.Next() {
		var targetID, agentID string
		var d detState
		if err := rows.Scan(&targetID, &agentID, &d.failRounds, &d.firstFailTS, &d.updatedAt, &d.needRounds); err != nil {
			return nil, err
		}
		out[targetID+"\x00"+agentID] = d
	}
	return out, rows.Err()
}

// loadFiringSignals returns the site's confirmed target faults, keyed
// (target, agent). Agent-connectivity signals carry no target and are excluded:
// an offline Agent is its own fault, not every target's.
//
// One (target, agent) pair can now have more than one firing signal — the
// partial unique index is per DETECTOR, and a target can carry a latency and a
// packet-loss degradation at once. This map holds one, so which one it holds
// must be decided rather than left to row order: an arbitrary pick would let the
// console report an info "slower than usual" for a target whose availability
// fault is the thing the operator needs to see. Most severe wins; among equals
// the one that has been firing longest, then by id so the answer is stable
// across refreshes.
func (s *Service) loadFiringSignals(ctx context.Context, tx store.Executor, siteID string) (map[string]firingSignal, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT fs.target_id, fs.agent_id, fs.id, fs.incident_id, fs.severity, fs.target_name, fs.target_addr,
		       fs.target_port, fs.probe_kind, fs.detector_key, fs.agent_name, fs.observed_at, fs.confirmed_at,
		       COALESCE(i.attribution,''), COALESCE(i.attribution_evidence,'[]')
		FROM fault_signals fs
		JOIN incidents i ON i.id = fs.incident_id
		WHERE fs.site_id=? AND fs.state='firing' AND fs.target_id <> ''
		ORDER BY CASE fs.severity
		           WHEN 'critical' THEN 0 WHEN 'error' THEN 1 WHEN 'warn' THEN 2 ELSE 3 END,
		         fs.confirmed_at ASC, fs.id ASC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]firingSignal{}
	for rows.Next() {
		var targetID, agentID string
		var sig fault.Signal
		var f firingSignal
		if err := rows.Scan(&targetID, &agentID, &sig.ID, &sig.IncidentID, &sig.Severity,
			&sig.TargetName, &sig.TargetAddr, &sig.Port, &sig.ProbeKind, &sig.DetectorKey,
			&sig.AgentName, &sig.ObservedAt, &sig.ConfirmedAt, &f.attribution, &f.attrEv); err != nil {
			return nil, err
		}
		key := targetID + "\x00" + agentID
		if _, taken := out[key]; taken {
			continue // the ORDER BY already put the winner first
		}
		out[key] = firingSignal{
			signalID: sig.ID, incidentID: sig.IncidentID, severity: sig.Severity,
			title:       fault.SignalTitle(sig),
			observedAt:  sig.ObservedAt.UTC(),
			confirmedAt: sig.ConfirmedAt.UTC(),
			attribution: f.attribution,
			attrEv:      f.attrEv,
		}
	}
	return out, rows.Err()
}

// loadFluctuationCounts returns how many sub-threshold streaks recovered since
// `since`, grouped target → agent → count.
//
// It reads outside the snapshot transaction for the same reason availability does:
// nothing else in the status batch depends on it, and a count that is one dip
// behind in a 24-hour window is not observable. One grouped query serves the whole
// site, so putting the number beside every availability figure in the list costs a
// single scan rather than a request per row.
func (s *Service) loadFluctuationCounts(ctx context.Context, siteID string, since, until time.Time) (map[string]map[string]int, error) {
	// Half-open [since, until), the same bounds the availability window uses. The
	// upper bound is not decoration: timestamps come from the agent's clock, so one
	// running ahead can write a fluctuation dated in the server's future. Without it
	// that dip would be counted here while its round sample sits outside the
	// availability window — a count explaining a ratio that does not yet include it —
	// and would keep being counted in every refresh until wall time caught up.
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT target_id, agent_id, COUNT(*) FROM fluctuations
		WHERE site_id=? AND ended_at >= ? AND ended_at < ? AND target_id <> ''
		GROUP BY target_id, agent_id`, siteID, since, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var targetID, agentID string
		var n int
		if err := rows.Scan(&targetID, &agentID, &n); err != nil {
			return nil, err
		}
		if out[targetID] == nil {
			out[targetID] = map[string]int{}
		}
		out[targetID][agentID] = n
	}
	return out, rows.Err()
}

// ---- helpers ----

// detectorBeforeCutoff reports whether a detector's counters were last touched
// before this pair's assignment cutoff — pre-assignment state that must not read
// as a current failing streak after scope re-entry (SRV-007).
func detectorBeforeCutoff(d detState, cutoff *time.Time) bool {
	return d.updatedAt.Valid && beforeCutoff(d.updatedAt.Time.UTC(), cutoff)
}

// pendingSince is the per-pair pending clock: the later of the target's material// generation time (config_changed_at) and the row's assigned_at (present once a
// prediction/report exists for the pair). Nil only when neither is known.
func pendingSince(t *targetRow, ms *msRow) *time.Time {
	var best *time.Time
	if t.configChangedAt.Valid {
		v := t.configChangedAt.Time.UTC()
		best = &v
	}
	if ms != nil && ms.assignedAt.Valid {
		v := ms.assignedAt.Time.UTC()
		if best == nil || v.After(*best) {
			best = &v
		}
	}
	return best
}

// beforeCutoff reports whether a fact observed at ts predates the pair's assignment
// cutoff. A nil cutoff (neither config_changed_at nor assigned_at known) excludes
// nothing. Used by the current-state reads so pre-assignment samples/verdicts never
// surface as current (SRV-007).
func beforeCutoff(ts time.Time, cutoff *time.Time) bool {
	return cutoff != nil && ts.Before(*cutoff)
}

// sampleBeforeCutoff reports whether a probe sample predates the pair's assignment
// cutoff, compared at second granularity. samples.ts is stored as integer Unix
// seconds (metrics writes m.TS.Unix()), while the cutoff (config_changed_at /
// assigned_at) retains sub-second precision. Reconstructing the sample as
// time.Unix(ts, 0) floors it to the start of its second, so a genuinely
// post-assignment sample stored in the same Unix second as the cutoff would sort
// Before a fractional cutoff and be dropped as pre-assignment history — leaving the
// pair no_data for a full probe interval (up to ~30 min for NAT) (SRV-017).
// Comparing ts < cutoff.Unix() admits a same-second post-assignment sample while
// still rejecting genuinely earlier seconds; the config_serial join in
// loadLatestSamples already excludes true old-generation samples, so real
// pre-assignment history is not resurrected. This deliberately differs from the
// condition-state path, which keeps full-precision beforeCutoff: last_eval_at is a
// full-precision Go timestamp, not a truncated integer second, so it has no
// granularity mismatch to correct.
func sampleBeforeCutoff(ts int64, cutoff *time.Time) bool {
	return cutoff != nil && ts < cutoff.Unix()
}

// roundComplete reports whether the latest primary sample describes a round that
// measured everything it was configured to, so its value may be read as health.
//
// It defers to fault.RoundComplete with the SAME arguments the detector derives,
// which is the whole point: this chip sits next to the fault state, and the two
// disagreeing is worse than either being wrong alone. An absent sent sample is
// therefore passed through as a count of zero rather than waved through — the
// detector rejects that round, so this must not paint it green. Only ICMP has an
// incomplete state; see fault.RoundComplete for why a truncated round's loss
// figure is unreadable.
//
// A sent sample from a DIFFERENT round than the primary one is also a zero: the
// two are emitted together every round, so a mismatch means the latest round's
// count cannot be established, and an unverifiable round is exactly what the
// gate exists to withhold a verdict from.
func roundComplete(t *targetRow, primary, sent *sampleVal) bool {
	if primary == nil {
		return true
	}
	got := 0
	if sent != nil && sent.ts == primary.ts {
		got = int(sent.value)
	}
	return fault.RoundComplete(t.kind, got, t.pingCount)
}

func severityName(rank int) string {
	for name, r := range severityRank {
		if r == rank {
			return name
		}
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if out == nil {
		return []string{}
	}
	return out
}

func nonNilStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

func decodeStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// sortTargets orders the assembled targets deterministically: monitor group
// (default first, then group name), then target (kind, name, id). It sorts the
// output slice using the parallel targetRow group facts.
func sortTargets(out []TargetStatus, meta []targetRow) {
	facts := make(map[string]targetRow, len(meta))
	for _, t := range meta {
		facts[t.id] = t
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := facts[out[i].TargetID], facts[out[j].TargetID]
		if a.groupIsDefault != b.groupIsDefault {
			return a.groupIsDefault // default group first
		}
		if a.groupName != b.groupName {
			return a.groupName < b.groupName
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].TargetID < out[j].TargetID
	})
}
