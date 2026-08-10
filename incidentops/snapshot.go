package incidentops

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/metrics"
)

// ---- snapshot base (written synchronously in the incident-open transaction) ----

// SnapshotBase is the immutable server-authored part of an incident snapshot,
// frozen once at incident-open time. It carries stable IDs and the display facts
// as they were at trigger time, the trigger/receive timestamps, and each firing
// condition's threshold/current value plus a bounded recent-sample summary — so
// later renames, edits or deletions can never rewrite the scene.
//
// It is the SERVER's perspective and only that. What the detecting agent could
// see when it decided something was broken arrives separately and on the agent's
// own initiative, as a scene_report claimed against this incident (see scene.go);
// the two complement each other and neither waits for the other.
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
// deterministically rather than an oversized base stored. A build failure records
// whatever it managed to assemble instead of aborting: the returned error is
// advisory (the caller logs and continues), and the incident still opens.
// Idempotent via the incident_snapshots.incident_id UNIQUE constraint.
func (s *Service) WriteIncidentBase(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) error {
	base, buildErr := s.buildBase(ctx, tx, incidentID, now)
	payload := mustJSON(base)
	truncated := 0
	if capped, changed := truncateBase(payload, s.snapshotMaxBytes(ctx)); changed {
		payload = capped
		truncated = 1
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO incident_snapshots(id, incident_id, base, truncated, created_at)
		 VALUES(?,?,?,?,?)`,
		"isnap_"+uuid.NewString(), incidentID, payload, truncated, now); err != nil {
		return err
	}
	return buildErr
}

// buildBase assembles the snapshot base. An unreadable incident row or member set
// yields a partial base and an error: the row is still written, so the incident
// always has a snapshot, and the caller logs what was missing.
func (s *Service) buildBase(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) (SnapshotBase, error) {
	base := SnapshotBase{IncidentID: incidentID, ReceivedAt: now}
	var siteID, groupID, groupName, severity, suspected, attribution, attrEv string
	var openedAt time.Time
	err := tx.QueryRowContext(ctx,
		`SELECT site_id, group_id, COALESCE(group_name,''), severity, COALESCE(suspected_layer,''), opened_at,
		        COALESCE(attribution,''), COALESCE(attribution_evidence,'[]')
		 FROM incidents WHERE id=?`, incidentID).
		Scan(&siteID, &groupID, &groupName, &severity, &suspected, &openedAt, &attribution, &attrEv)
	if err != nil {
		return base, err
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
		// Members unreadable: keep the group/severity base rather than storing
		// nothing, and let the caller log why it is thin.
		return base, err
	}
	base.Members = members
	base.Agents = s.baseAgents(ctx, agentIDs)
	base.Targets = s.baseTargets(ctx, tx, targetIDs)
	return base, nil
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

// ---- base truncation ----

// truncateBase deterministically reduces a serialized SnapshotBase to at most
// budget bytes, preserving the incident's core identifiers. Optional
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
	// still yields a valid, tiny base carrying the incident identifiers.
	for len(b.Members) > 0 && !fits() {
		b.Members = b.Members[:len(b.Members)-1]
		changed = true
	}
	return mustJSON(b), changed
}
