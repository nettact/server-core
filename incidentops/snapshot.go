package incidentops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/metrics"
)

// ---- snapshot base (written synchronously in the incident-open transaction) ----

// SnapshotBase is the immutable server-authored part of an incident snapshot,
// frozen once at incident-open time. It carries stable IDs and the display facts
// as they were at trigger time, the trigger/receive timestamps, and each firing
// condition's threshold/current value plus a bounded recent-sample summary — so
// later renames, edits or deletions can never rewrite the scene. Agent-collected
// scene evidence lands separately in incident_snapshot_entries.
type SnapshotBase struct {
	IncidentID     string    `json:"incident_id"`
	SiteID         string    `json:"site_id"`
	Group          baseGroup `json:"group"`
	Severity       string    `json:"severity"`
	SuspectedLayer string    `json:"suspected_layer,omitempty"`
	// Attribution is frozen like the rest of the base: the incident's one-line
	// position at snapshot time, so a snapshot that outlives a later recompute
	// still says what the evidence said when it was taken.
	Attribution         string          `json:"attribution,omitempty"`
	AttributionEvidence json.RawMessage `json:"attribution_evidence,omitempty"`
	TriggeredAt         time.Time       `json:"triggered_at"` // incident opened_at
	ReceivedAt          time.Time       `json:"received_at"`  // server base-write time
	Members             []baseMember    `json:"members"`
	Agents              []baseAgent     `json:"agents"`
	Targets             []baseTarget    `json:"targets"`
}

type baseGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// baseMember is one fault signal frozen into the snapshot. A built-in detector
// reaches its verdict from a single metric, so the evidence is one-to-one with
// the member rather than a list of conditions.
type baseMember struct {
	SignalID    string       `json:"signal_id"`
	DetectorKey string       `json:"detector_key"`
	AgentID     string       `json:"agent_id"`
	AgentName   string       `json:"agent_name,omitempty"`
	Severity    string       `json:"severity"`
	Layer       string       `json:"layer,omitempty"`
	ObservedAt  time.Time    `json:"observed_at"`
	ConfirmedAt time.Time    `json:"confirmed_at"`
	Evidence    baseEvidence `json:"evidence"`
}

type baseEvidence struct {
	TargetID      string       `json:"target_id,omitempty"`
	TargetName    string       `json:"target_name,omitempty"`
	TargetAddr    string       `json:"target_addr,omitempty"`
	ProbeKind     string       `json:"probe_kind,omitempty"`
	MetricKind    string       `json:"metric_kind,omitempty"`
	Comparator    string       `json:"comparator,omitempty"`
	Threshold     float64      `json:"threshold"`
	Value         float64      `json:"value"`
	ReasonCode    int          `json:"reason_code,omitempty"`
	ReasonDetail  string       `json:"reason_detail,omitempty"`
	RecentSamples []baseSample `json:"recent_samples,omitempty"`
}

type baseSample struct {
	TS    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

type baseAgent struct {
	AgentID      string `json:"agent_id"`
	Name         string `json:"name,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Platform     string `json:"platform,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

type baseTarget struct {
	MonitorID string `json:"monitor_id"`
	Kind      string `json:"kind,omitempty"`
	Target    string `json:"target,omitempty"`
	Port      int    `json:"port,omitempty"`
	// Iface is a gateway monitor's NIC selection. It is frozen here for the same
	// reason kind/target/port are — and because the entry target refs are derived
	// from this section, where a gateway ref without its NIC would make the agent
	// resolve the default NIC's gateway instead of the monitored one.
	Iface string `json:"iface,omitempty"`
}

// recentSampleLimit bounds how many recent points the base freezes per condition.
const recentSampleLimit = 12

// recentSampleWindow is how far back the frozen chart reaches. See recentSamples
// for why it is measured from the fault's evidence rather than from now.
const recentSampleWindow = 5 * time.Minute

// recentSampleFetchCap bounds how many points are read before the window is
// narrowed to recentSampleLimit around the failure. It exists only so a
// pathologically dense series cannot make this row large; the bounded window is
// what actually keeps the read small.
const recentSampleFetchCap = 600

// WriteIncidentBase writes the one immutable incident snapshot's server base row
// synchronously, inside the caller's incident-open transaction. It reads the
// just-inserted incident/alert/evidence rows through tx (so it sees uncommitted
// state) and the bounded recent-sample summaries through the read pool (WAL lets
// that run concurrently with the open write tx). The serialized base is hard-capped
// to incident_snapshot_max_bytes here — optional base detail is dropped
// deterministically rather than an oversized base stored — and entry payloads are
// additionally accounted for and truncated at finalize. A build failure records a
// deterministic failed/partial snapshot row instead of aborting: the returned
// error is advisory (the caller logs and continues), and the incident still
// opens. Idempotent via the incident_snapshots.incident_id UNIQUE constraint.
func (s *Service) WriteIncidentBase(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) error {
	base, status, buildErr := s.buildBase(ctx, tx, incidentID, now)
	payload := mustJSON(base)
	truncated := 0
	if capped, changed := truncateBase(payload, s.snapshotMaxBytes(ctx)); changed {
		payload = capped
		truncated = 1
	}
	deadline := now.Add(s.snapshotDeadline(ctx))
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO incident_snapshots(id, incident_id, status, base, total_bytes, truncated, deadline_at, created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		"isnap_"+uuid.NewString(), incidentID, status, payload, len(payload), truncated, deadline, now); err != nil {
		return err
	}
	return buildErr
}

// buildBase assembles the snapshot base and its initial status. status is
// 'collecting' on a clean build (agent scene collection follows post-commit) and
// 'failed' when the incident row itself cannot be read.
func (s *Service) buildBase(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) (SnapshotBase, string, error) {
	base := SnapshotBase{IncidentID: incidentID, ReceivedAt: now}
	var siteID, groupID, groupName, severity, suspected, attribution, attrEv string
	var openedAt time.Time
	err := tx.QueryRowContext(ctx,
		`SELECT site_id, group_id, COALESCE(group_name,''), severity, COALESCE(suspected_layer,''), opened_at,
		        COALESCE(attribution,''), COALESCE(attribution_evidence,'[]')
		 FROM incidents WHERE id=?`, incidentID).
		Scan(&siteID, &groupID, &groupName, &severity, &suspected, &openedAt, &attribution, &attrEv)
	if err != nil {
		return base, statusFailed, err
	}
	base.SiteID = siteID
	base.Group = baseGroup{ID: groupID, Name: groupName}
	base.Severity = severity
	base.SuspectedLayer = suspected
	base.Attribution = attribution
	if attrEv != "" && attrEv != "[]" {
		base.AttributionEvidence = json.RawMessage(attrEv)
	}
	base.TriggeredAt = openedAt

	members, agentIDs, targetIDs, err := s.baseMembers(ctx, tx, incidentID)
	if err != nil {
		// Members unreadable: keep the group/severity base but flag it failed so the
		// scene is deterministically marked incomplete rather than silently empty.
		return base, statusFailed, err
	}
	base.Members = members
	base.Agents = s.baseAgents(ctx, agentIDs)
	base.Targets = s.baseTargets(ctx, tx, targetIDs)
	return base, statusCollecting, nil
}

// baseMembers reads the incident's member fault signals with their frozen
// evidence, attaching a bounded recent-sample summary per member. It also returns
// the distinct agent ids and target ids referenced, for the agent/target sections.
func (s *Service) baseMembers(ctx context.Context, tx *sql.Tx, incidentID string) ([]baseMember, []string, []string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, detector_key, agent_id, COALESCE(agent_name,''), severity, COALESCE(layer,''),
		       observed_at, confirmed_at,
		       COALESCE(target_id,''), COALESCE(target_name,''), COALESCE(target_addr,''),
		       COALESCE(probe_kind,''), COALESCE(metric_kind,''), COALESCE(comparator,''),
		       threshold, value, reason_code, COALESCE(reason_detail,'')
		FROM fault_signals WHERE incident_id=? ORDER BY confirmed_at`, incidentID)
	if err != nil {
		return nil, nil, nil, err
	}
	var members []baseMember
	agentSeen := map[string]bool{}
	targetSeen := map[string]bool{}
	var agentIDs, targetIDs []string
	for rows.Next() {
		var m baseMember
		var e baseEvidence
		if err := rows.Scan(&m.SignalID, &m.DetectorKey, &m.AgentID, &m.AgentName, &m.Severity, &m.Layer,
			&m.ObservedAt, &m.ConfirmedAt,
			&e.TargetID, &e.TargetName, &e.TargetAddr, &e.ProbeKind, &e.MetricKind, &e.Comparator,
			&e.Threshold, &e.Value, &e.ReasonCode, &e.ReasonDetail); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		m.Evidence = e
		if !agentSeen[m.AgentID] {
			agentSeen[m.AgentID] = true
			agentIDs = append(agentIDs, m.AgentID)
		}
		if e.TargetID != "" && !targetSeen[e.TargetID] {
			targetSeen[e.TargetID] = true
			targetIDs = append(targetIDs, e.TargetID)
		}
		members = append(members, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	for i := range members {
		members[i].Evidence.RecentSamples = s.recentSamples(ctx, members[i].AgentID, members[i].Evidence, members[i].ObservedAt)
	}
	return members, agentIDs, targetIDs, nil
}

// recentSamples returns a bounded recent-sample summary for one member's metric
// from the read pool. Best-effort: on any error, a missing metrics store, or a
// member with no metric (Agent connectivity) it returns nil, so a snapshot never
// fails on a chart read.
//
// The window is anchored on the fault's OWN evidence rather than on the wall
// clock, and BOUNDED at both ends. A snapshot is written in the same transaction
// that confirms the fault, so for live telemetry the two are the same thing —
// but a fault confirmed from a backlog an agent replayed on reconnect is
// evidence from twenty minutes ago, and a window measured back from now would
// find nothing at all and freeze an empty chart into the one immutable record of
// what the failure looked like.
//
// The upper bound is not cosmetic. metrics.Query picks its resolution tier from
// the window's WIDTH, so a window left open to now spans the whole replay and an
// hours-long backlog would be served from rollups — coarse buckets describing
// time the snapshot did not ask about. Bounding it keeps a historical range at
// the same resolution a live one gets, and keeps Limit selecting from the
// samples around the failure rather than the oldest points of a long span.
func (s *Service) recentSamples(ctx context.Context, agentID string, e baseEvidence, observedAt time.Time) []baseSample {
	if s.metrics == nil || e.MetricKind == "" || e.TargetID == "" {
		return nil
	}
	// Reach back from the first failing round, not from the confirmation: the
	// samples worth freezing are the ones leading INTO the failure.
	anchor := time.Now()
	if !observedAt.IsZero() && observedAt.Before(anchor) {
		anchor = observedAt
	}
	// Fetch the whole bounded window, then take the points AROUND the anchor.
	//
	// The limit cannot do that job itself: metrics.Query applies it as ORDER BY ts
	// LIMIT n from the start of the range, so asking for twelve points over a
	// ten-minute window of a ten-second series returns the first two minutes of it
	// and the failure — which sits at the anchor — is not in the snapshot at all.
	// The window is small and bounded, so reading it whole costs little; the cap
	// is only there so a pathologically dense series cannot blow the row up.
	q := metrics.Query{AgentID: agentID, Kind: e.MetricKind, MonitorID: e.TargetID,
		Limit:     recentSampleFetchCap,
		SinceUnix: anchor.Add(-recentSampleWindow).Unix(),
		// Past the anchor by one window, so the chart shows the failure itself
		// rather than stopping at its first round.
		UntilUnix: anchor.Add(recentSampleWindow).Unix()}
	pts, err := s.metrics.Query(ctx, q)
	if err != nil || len(pts) == 0 {
		return nil
	}
	pts = aroundAnchor(pts, anchor, recentSampleLimit)
	out := make([]baseSample, 0, len(pts))
	for _, p := range pts {
		out = append(out, baseSample{TS: p.TS, Value: p.Value})
	}
	return out
}

// aroundAnchor keeps at most n points centred on the failure rather than on
// either end of the window.
//
// Weighted towards what came BEFORE: the question a frozen chart answers is
// "what did this look like on the way in", and the rounds after the first
// failing one are the failure repeating itself. Taking the last point at or
// before the anchor as the pivot means the anchor is always included when it
// exists, which is the one sample nothing else in the snapshot carries.
func aroundAnchor(pts []metrics.Point, anchor time.Time, n int) []metrics.Point {
	if len(pts) <= n {
		return pts
	}
	// Points come back in ascending timestamp order.
	pivot := len(pts) - 1
	for i, p := range pts {
		if p.TS.After(anchor) {
			pivot = i - 1
			break
		}
	}
	if pivot < 0 {
		pivot = 0
	}
	after := n / 3 // a third of the budget for the failure itself
	end := pivot + 1 + after
	if end > len(pts) {
		end = len(pts)
	}
	start := end - n
	if start < 0 {
		// The anchor sits at or before the start of the series, so there is
		// nothing earlier to weight towards; spend the whole budget forwards.
		start = 0
		if end = n; end > len(pts) {
			end = len(pts)
		}
	}
	return pts[start:end]
}

// baseAgents freezes the identity/version of each involved agent (read pool).
func (s *Service) baseAgents(ctx context.Context, agentIDs []string) []baseAgent {
	out := make([]baseAgent, 0, len(agentIDs))
	for _, id := range agentIDs {
		var a baseAgent
		a.AgentID = id
		_ = s.db.Read().QueryRowContext(ctx,
			`SELECT COALESCE(NULLIF(display_name,''), hostname, ''), COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,'')
			 FROM agents WHERE id=?`, id).Scan(&a.Name, &a.Hostname, &a.Platform, &a.AgentVersion)
		out = append(out, a)
	}
	return out
}

// baseTargets freezes the involved targets' kind/target/port/iface from
// probe_tasks (read through tx so an in-flight target edit is not seen
// mid-open). A target deleted after the fact simply drops out — the frozen
// evidence still carries its name/address.
func (s *Service) baseTargets(ctx context.Context, tx *sql.Tx, targetIDs []string) []baseTarget {
	out := make([]baseTarget, 0, len(targetIDs))
	for _, id := range targetIDs {
		var t baseTarget
		t.MonitorID = id
		var params string
		if err := tx.QueryRowContext(ctx,
			`SELECT kind, COALESCE(target,''), COALESCE(params,'') FROM probe_tasks WHERE id=?`, id).
			Scan(&t.Kind, &t.Target, &params); err != nil {
			continue
		}
		p := parseParams(params)
		t.Port = p.Port
		if t.Kind == "gateway" {
			t.Iface = p.Interface
		}
		out = append(out, t)
	}
	return out
}

// parseParams decodes a probe_tasks.params JSON blob. An absent or malformed blob
// yields the zero value: params are validated on write, so a decode failure means
// junk, not something worth failing the whole snapshot over.
func parseParams(params string) pcfg.ProbeParams {
	if params == "" {
		return pcfg.ProbeParams{}
	}
	var p pcfg.ProbeParams
	if json.Unmarshal([]byte(params), &p) != nil {
		return pcfg.ProbeParams{}
	}
	return p
}

// ---- post-commit dispatch (one collecting entry + request per involved Agent) ----

// OnIncidentOpened creates one collecting snapshot entry per distinct involved
// Agent and dispatches an IncidentSnapshotRequest to each over the WebSocket.
// It runs post-commit (wired onto TopicIncidentOpened), so it never shares the
// fault transaction. Idempotent: entries are keyed UNIQUE(snapshot_id, agent_id),
// and a re-delivered event re-pushes only to still-collecting in-deadline agents.
func (s *Service) OnIncidentOpened(ctx context.Context, ev eventbus.IncidentEvent) error {
	snapID, deadline, frozen, err := s.ensureSnapshot(ctx, ev.IncidentID)
	if err != nil {
		return err
	}
	// Distinct member agents of the incident (at open there is at least one).
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT DISTINCT agent_id FROM fault_signals WHERE incident_id=?`, ev.IncidentID)
	if err != nil {
		return err
	}
	var agents []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		agents = append(agents, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, agentID := range agents {
		reqID := "isnapreq_" + uuid.NewString()
		// Derive the target refs ONCE, here, and freeze them onto the entry; every
		// later push (reconnect re-delivery) replays these bytes rather than
		// re-reading mutable probe_tasks. The values come from the base frozen
		// inside the incident transaction, so a monitor edit committing between
		// that transaction and this post-commit handler cannot leak in either.
		targets := s.snapshotTargets(ctx, ev.IncidentID, agentID, frozen)
		res, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO incident_snapshot_entries(id, snapshot_id, request_id, agent_id, agent_name, status, targets, requested_at)
			 VALUES(?,?,?,?,?, 'collecting', ?, ?)`,
			"isne_"+uuid.NewString(), snapID, reqID, agentID, s.agentName(ctx, agentID), mustJSON(targets), now)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // entry already exists (idempotent re-delivery)
		}
		s.dispatchSnapshot(agentID, ev.IncidentID, reqID, deadline, targets)
	}
	// A snapshot with no agent entries (should not happen: an incident always has a
	// member alert) is finalized immediately so it never hangs collecting.
	return s.finalizeSnapshot(ctx, snapID, false)
}

// ensureSnapshot returns the snapshot id, deadline and tx-frozen base targets
// for an incident, creating a minimal collecting row when WriteIncidentBase did
// not run (base build failed in the fault tx). Deterministic fallback so scene
// collection can still proceed — on that path (and when truncation dropped the
// base's target section) the returned map is empty and snapshotTargets falls
// back to the live config.
func (s *Service) ensureSnapshot(ctx context.Context, incidentID string) (string, time.Time, map[string]baseTarget, error) {
	var id, base string
	var deadline time.Time
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT id, deadline_at, base FROM incident_snapshots WHERE incident_id=?`, incidentID).Scan(&id, &deadline, &base)
	if err == nil {
		return id, deadline, frozenBaseTargets(base), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, nil, err
	}
	now := time.Now().UTC()
	deadline = now.Add(s.snapshotDeadline(ctx))
	id = "isnap_" + uuid.NewString()
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO incident_snapshots(id, incident_id, status, base, total_bytes, truncated, deadline_at, created_at)
		 VALUES(?,?, 'collecting', '', 0, 0, ?, ?)`, id, incidentID, deadline, now); err != nil {
		return "", time.Time{}, nil, err
	}
	// Re-read to resolve a race where a concurrent writer inserted first.
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT id, deadline_at, base FROM incident_snapshots WHERE incident_id=?`, incidentID).Scan(&id, &deadline, &base); err != nil {
		return "", time.Time{}, nil, err
	}
	return id, deadline, frozenBaseTargets(base), nil
}

// frozenBaseTargets indexes a stored snapshot base's target section by monitor
// id. An empty, truncated-away or (impossible for our own JSON) unparseable
// base yields an empty map, which downgrades snapshotTargets to its live-config
// fallback rather than failing the dispatch.
func frozenBaseTargets(base string) map[string]baseTarget {
	if base == "" {
		return nil
	}
	var b struct {
		Targets []baseTarget `json:"targets"`
	}
	if json.Unmarshal([]byte(base), &b) != nil {
		return nil
	}
	m := make(map[string]baseTarget, len(b.Targets))
	for _, t := range b.Targets {
		m[t.MonitorID] = t
	}
	return m
}

// dispatchSnapshot pushes one agent's IncidentSnapshotRequest. Offline agents
// simply do not receive it (the entry stays collecting until the deadline or a
// reconnect re-push).
//
// targets are the refs frozen onto the entry at creation, passed in rather than
// re-derived: see OnIncidentOpened.
//
// The collection window travels as the remaining budget at push time, never as
// this server's absolute deadline: the agent's clock is independent of ours and
// skew larger than the window would expire the request on arrival, making the
// agent report timeouts for work it was never given time to attempt. We keep the
// absolute deadline_at for our own reaping, so the only slack the agent gains is
// the push latency. An already-spent window is not pushed at all — finalize's
// deadline sweep terminalizes the entry.
func (s *Service) dispatchSnapshot(agentID, incidentID, reqID string, deadline time.Time, targets []pcfg.SnapshotTargetRef) {
	if s.pusher == nil {
		return
	}
	budgetMs := int(time.Until(deadline).Milliseconds())
	if budgetMs <= 0 {
		return
	}
	s.pusher.PushIncidentSnapshotRequest(agentID, pcfg.IncidentSnapshotRequest{
		RequestID:  reqID,
		IncidentID: incidentID,
		BudgetMs:   budgetMs,
		Targets:    targets,
	})
}

// snapshotTargets derives the monitor targets one agent should resolve for the
// scene. It is called EXACTLY ONCE per entry — at creation, in OnIncidentOpened.
// The result is frozen onto the entry and replayed from there on every later
// push; nothing downstream may call this again.
//
// frozen is the base's target section as captured INSIDE the incident-open
// transaction, and it wins over the live probe_tasks row: this runs post-commit,
// so a monitor edit landing in the gap would otherwise be frozen onto the entry
// and the agent would collect evidence for a config that never raised the
// incident (while the base right next to it shows the one that did). The live
// row (then the signal's own frozen columns) remains the fallback for targets
// the base does not carry — a base-less fallback snapshot, or one whose target
// section was truncated away.
//
// Host-anchor monitors are excluded: their target names a metric series ("host",
// "*", a mount like "C:"), not a network destination, so there is nothing to
// resolve and asking the agent to try would only produce a bogus lookup failure.
// The exclusion tests the frozen kind, so a monitor retyped in the gap can
// neither slip in nor knock its target out. Gateway monitors ARE included, but
// carry the NIC selection instead of a resolvable host — the agent reads its
// routing table, not DNS.
func (s *Service) snapshotTargets(ctx context.Context, incidentID, agentID string, frozen map[string]baseTarget) []pcfg.SnapshotTargetRef {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT DISTINCT s.target_id, COALESCE(pt.kind, s.probe_kind), COALESCE(pt.target, s.target_addr), COALESCE(pt.params,'')
		FROM fault_signals s
		LEFT JOIN probe_tasks pt ON pt.id = s.target_id
		WHERE s.incident_id=? AND s.agent_id=? AND s.target_id <> ''`, incidentID, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []pcfg.SnapshotTargetRef
	for rows.Next() {
		var ref pcfg.SnapshotTargetRef
		var params string
		if err := rows.Scan(&ref.MonitorID, &ref.Kind, &ref.Target, &params); err != nil {
			return out
		}
		if bt, ok := frozen[ref.MonitorID]; ok {
			ref.Kind, ref.Target, ref.Port, ref.Iface = bt.Kind, bt.Target, bt.Port, bt.Iface
		} else {
			p := parseParams(params)
			ref.Port = p.Port
			if ref.Kind == "gateway" {
				ref.Iface = p.Interface
			}
		}
		if ref.Kind == "host" {
			continue
		}
		out = append(out, ref)
	}
	return out
}

// ---- ingest ----

// snapshotAllowlist is the set of snapshot field-group ids the server accepts. An
// agent result carrying anything else has that group dropped (validate-only-
// allowlisted), never persisted.
var snapshotAllowlist = map[string]bool{
	telemetry.SnapshotGroupNetwork:   true,
	telemetry.SnapshotGroupAgent:     true,
	telemetry.SnapshotGroupResources: true,
	telemetry.SnapshotGroupTargets:   true,
}

// entryPayload is the persisted per-Agent scene payload (allowlisted groups only).
type entryPayload struct {
	Groups    []telemetry.SnapshotGroupResult  `json:"groups"`
	Network   *telemetry.SnapshotNetwork       `json:"network,omitempty"`
	Agent     *telemetry.SnapshotAgentInfo     `json:"agent,omitempty"`
	Resources *telemetry.SnapshotResources     `json:"resources,omitempty"`
	Targets   []telemetry.SnapshotTargetResult `json:"targets,omitempty"`
}

// clockSkewFlagMs is the agent/server receive-time delta beyond which the entry is
// flagged clock-skewed.
const clockSkewFlagMs = 5000

// IngestSnapshot persists one agent's incident-scene result. It matches by
// request id + incident id + authenticated agent id, requires the entry to still
// be collecting, keeps only allowlisted groups, computes the server receive
// time/clock skew, and finalizes the snapshot when all entries are terminal.
// Duplicate, late, wrong-incident and wrong-agent results are idempotent no-ops.
func (s *Service) IngestSnapshot(ctx context.Context, agentID string, snap telemetry.IncidentSnapshot) error {
	var snapshotID, entryAgent, entryStatus, incidentID string
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT e.snapshot_id, e.agent_id, e.status, sn.incident_id
		FROM incident_snapshot_entries e
		JOIN incident_snapshots sn ON sn.id = e.snapshot_id
		WHERE e.request_id=?`, snap.RequestID).Scan(&snapshotID, &entryAgent, &entryStatus, &incidentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // unknown request id
	}
	if err != nil {
		return err
	}
	if entryAgent != agentID || incidentID != snap.IncidentID || entryStatus != statusCollecting {
		return nil // wrong agent / wrong incident / already terminal (idempotent)
	}

	payload, status := buildEntryPayload(snap)
	now := time.Now().UTC()
	skewMs := now.Sub(snap.CollectedAt).Milliseconds()
	if skewMs < 0 {
		skewMs = -skewMs
	}
	skewed := skewMs > clockSkewFlagMs

	res, err := s.db.ExecContext(ctx, `
		UPDATE incident_snapshot_entries
		SET status=?, reason=?, clock_skew_ms=?, skewed=?, payload=?, received_at=?
		WHERE request_id=? AND status='collecting'`,
		status, entryReason(status), skewMs, boolInt(skewed), mustJSON(payload), now, snap.RequestID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil // lost the idempotency race; already terminal
	}
	return s.finalizeSnapshot(ctx, snapshotID, false)
}

// buildEntryPayload filters an agent result to allowlisted groups and derives the
// entry's terminal status from the collected/denied/unsupported/failed group mix.
func buildEntryPayload(snap telemetry.IncidentSnapshot) (entryPayload, string) {
	var p entryPayload
	collected := map[string]bool{}
	total := 0
	ok := 0
	for _, g := range snap.Groups {
		if !snapshotAllowlist[g.Group] {
			continue // drop non-allowlisted group
		}
		p.Groups = append(p.Groups, g)
		total++
		if g.Status == telemetry.ScopeCollected {
			ok++
			collected[g.Group] = true
		}
	}
	if collected[telemetry.SnapshotGroupNetwork] {
		p.Network = snap.Network
	}
	if collected[telemetry.SnapshotGroupAgent] {
		p.Agent = snap.Agent
	}
	if collected[telemetry.SnapshotGroupResources] {
		p.Resources = snap.Resources
	}
	if collected[telemetry.SnapshotGroupTargets] {
		p.Targets = snap.Targets
	}
	switch {
	case total == 0 || ok == 0:
		return p, statusFailed
	case ok == total:
		return p, statusComplete
	default:
		return p, statusPartial
	}
}

func entryReason(status string) string {
	if status == statusFailed {
		return "no_groups_collected"
	}
	return ""
}

// ---- finalize + truncation ----

// finalizeSnapshot recomputes a snapshot's terminal status once all its entries
// are terminal (or, when force is set by the deadline sweep, immediately —
// terminating any still-collecting entries as timed out). It then enforces the
// serialized-size cap with deterministic truncation. A no-op while entries are
// still legitimately collecting inside the deadline.
func (s *Service) finalizeSnapshot(ctx context.Context, snapshotID string, force bool) error {
	var deadline time.Time
	var curStatus string
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT status, deadline_at FROM incident_snapshots WHERE id=?`, snapshotID).Scan(&curStatus, &deadline); err != nil {
		return err
	}
	if curStatus != statusCollecting {
		return nil // already terminal
	}
	deadlinePassed := force || !time.Now().UTC().Before(deadline)

	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT status FROM incident_snapshot_entries WHERE snapshot_id=?`, snapshotID)
	if err != nil {
		return err
	}
	var total, complete, partial, collecting int
	for rows.Next() {
		var st string
		if err := rows.Scan(&st); err != nil {
			rows.Close()
			return err
		}
		total++
		switch st {
		case statusComplete:
			complete++
		case statusPartial:
			partial++
		case statusCollecting:
			collecting++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if collecting > 0 && !deadlinePassed {
		return nil // still collecting inside the deadline
	}
	if collecting > 0 {
		// Deadline passed: terminate the stragglers deterministically as timed out.
		if _, err := s.db.ExecContext(ctx,
			`UPDATE incident_snapshot_entries SET status='failed', reason='timeout' WHERE snapshot_id=? AND status='collecting'`,
			snapshotID); err != nil {
			return err
		}
	}

	final := statusFailed
	switch {
	case total == 0 || complete == total:
		final = statusComplete
	case complete > 0 || partial > 0:
		final = statusPartial
	}

	totalBytes, truncated, err := s.enforceSizeCap(ctx, snapshotID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE incident_snapshots SET status=?, total_bytes=?, truncated=? WHERE id=? AND status='collecting'`,
		final, totalBytes, boolInt(truncated), snapshotID)
	return err
}

// enforceSizeCap makes incident_snapshot_max_bytes a hard cap on the whole
// serialized snapshot (immutable base + entry payloads). When the total exceeds
// the maximum it truncates deterministically: first optional entry detail (recent
// target-resolution detail, then network interfaces, then the resources summary),
// then the base's optional detail (recent samples, then supplementary sections,
// then trailing members — never the incident identifiers/status), and finally, if
// entry payloads alone still overflow, it drops entry payloads outright. It returns
// the post-truncation byte total (always ≤ max) and whether anything was dropped.
func (s *Service) enforceSizeCap(ctx context.Context, snapshotID string) (int, bool, error) {
	maxBytes := s.snapshotMaxBytes(ctx)
	var baseJSON string
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT COALESCE(base,'') FROM incident_snapshots WHERE id=?`, snapshotID).Scan(&baseJSON); err != nil {
		return 0, false, err
	}
	type entRow struct {
		id      string
		payload string
	}
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT id, COALESCE(payload,'') FROM incident_snapshot_entries WHERE snapshot_id=? ORDER BY agent_id`, snapshotID)
	if err != nil {
		return 0, false, err
	}
	var ents []entRow
	entriesLen := 0
	for rows.Next() {
		var e entRow
		if err := rows.Scan(&e.id, &e.payload); err != nil {
			rows.Close()
			return 0, false, err
		}
		entriesLen += len(e.payload)
		ents = append(ents, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, false, err
	}
	total := len(baseJSON) + entriesLen
	if total <= maxBytes {
		return total, false, nil
	}

	truncated := false
	// Phase 1: strip optional entry detail in priority order across entries.
	for level := 0; level < 3 && total > maxBytes; level++ {
		for i := range ents {
			if total <= maxBytes {
				break
			}
			newPayload, changed := stripEntryLevel(ents[i].payload, level)
			if !changed {
				continue
			}
			delta := len(newPayload) - len(ents[i].payload)
			total += delta
			entriesLen += delta
			ents[i].payload = newPayload
			truncated = true
			if _, err := s.db.ExecContext(ctx,
				`UPDATE incident_snapshot_entries SET payload=? WHERE id=?`, newPayload, ents[i].id); err != nil {
				return 0, false, err
			}
		}
	}

	// Phase 2: reduce the immutable base to fit within the remaining budget.
	if total > maxBytes {
		if newBase, changed := truncateBase(baseJSON, maxBytes-entriesLen); changed {
			if _, err := s.db.ExecContext(ctx,
				`UPDATE incident_snapshots SET base=? WHERE id=?`, newBase, snapshotID); err != nil {
				return 0, false, err
			}
			total += len(newBase) - len(baseJSON)
			baseJSON = newBase
			truncated = true
		}
	}

	// Phase 3 (guarantee): if entry payloads alone still overflow, drop them outright
	// (deterministically by agent order) until the total fits. The immutable base and
	// its identifiers survive.
	for i := 0; i < len(ents) && total > maxBytes; i++ {
		if ents[i].payload == "" {
			continue
		}
		total -= len(ents[i].payload)
		ents[i].payload = ""
		truncated = true
		if _, err := s.db.ExecContext(ctx,
			`UPDATE incident_snapshot_entries SET payload='' WHERE id=?`, ents[i].id); err != nil {
			return 0, false, err
		}
	}

	return total, truncated, nil
}

// truncateBase deterministically reduces a serialized SnapshotBase to at most
// budget bytes, preserving the incident's core identifiers and status. Optional
// detail is dropped in a fixed priority: per-member recent samples first, then
// the supplementary agent/target sections (their identity survives on the members
// and their evidence), and finally trailing members as a guaranteed floor. Returns
// the re-serialized base and whether anything was dropped; valid JSON and field
// ordering are preserved throughout.
func truncateBase(payload string, budget int) (string, bool) {
	if budget < 0 {
		budget = 0
	}
	if len(payload) <= budget {
		return payload, false
	}
	var b SnapshotBase
	if json.Unmarshal([]byte(payload), &b) != nil {
		return payload, false // unparseable (never happens for our own JSON)
	}
	changed := false
	fits := func() bool { return len(mustJSON(b)) <= budget }

	// Tier 1: drop per-member recent samples (the largest optional detail).
	for i := range b.Members {
		if len(b.Members[i].Evidence.RecentSamples) > 0 {
			b.Members[i].Evidence.RecentSamples = nil
			changed = true
		}
	}
	if fits() {
		return mustJSON(b), changed
	}
	// Tier 2: drop the supplementary agent/target sections; their identities remain
	// referenced from the members and evidence.
	if len(b.Agents) > 0 {
		b.Agents = nil
		changed = true
	}
	if len(b.Targets) > 0 {
		b.Targets = nil
		changed = true
	}
	if fits() {
		return mustJSON(b), changed
	}
	// Tier 3 (floor): drop trailing members until the base fits. An empty member list
	// still yields a valid, tiny base carrying the incident identifiers/status.
	for len(b.Members) > 0 && !fits() {
		b.Members = b.Members[:len(b.Members)-1]
		changed = true
	}
	return mustJSON(b), changed
}

// stripEntryLevel removes one tier of optional detail from an entry payload,
// preserving group-status metadata and agent identity. level 0 drops target
// resolution detail, 1 drops network interfaces, 2 drops the resources summary.
// Returns the re-serialized payload and whether it changed.
func stripEntryLevel(payload string, level int) (string, bool) {
	if payload == "" {
		return payload, false
	}
	var p entryPayload
	if json.Unmarshal([]byte(payload), &p) != nil {
		return payload, false
	}
	changed := false
	switch level {
	case 0:
		if len(p.Targets) > 0 {
			p.Targets = nil
			changed = true
		}
	case 1:
		if p.Network != nil && len(p.Network.Interfaces) > 0 {
			p.Network.Interfaces = nil
			changed = true
		}
	case 2:
		if p.Resources != nil {
			p.Resources = nil
			changed = true
		}
	}
	if !changed {
		return payload, false
	}
	return mustJSON(p), true
}
