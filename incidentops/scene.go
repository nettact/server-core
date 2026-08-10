package incidentops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
)

// unreferencedSceneRetention is how long a scene that never found a fault is
// kept. An agent legitimately collects one without a server-side verdict ever
// following (its local streak crossed, the rounds recovered before this server's
// profile confirmed anything; or it lost its session for four seconds), and after
// claimWindow nothing can ever reference such a report — every read path is
// incident-scoped, so it is invisible. A day preserves it for hand debugging;
// past that it is dead weight. Mirrors unreferencedTraceRetention, for the same
// reason and on the same clock.
const unreferencedSceneRetention = 24 * time.Hour

// sceneClaimWindow is how far back a claim looks for a scene, and how old a
// signal may be and still own one. It matches unreferencedSceneRetention on
// purpose: a scene is claimable for exactly as long as it is kept, and a rule
// that expired the claim earlier would keep evidence it had already decided
// nothing may ever look at.
//
// It is deliberately much wider than the traceroute claimWindow. A trace is
// claimed against a fault confirmed on the same rounds that triggered it, so
// fifteen minutes covers the gap; a scene's gap is set by the DIFFERENCE between
// the agent's local threshold (3 failures) and the server's confirmation profile
// (up to 5), multiplied by the target's interval. On a 30-minute NAT monitor —
// a supported, default configuration — that is an hour between the scene
// arriving and the signal that owns it existing. Under a fifteen-minute cutoff
// the exact agent/monitor/generation match would be rejected on age alone and
// the scene could never be claimed at all.
//
// Widening it costs nothing in precision, because precision does not come from
// the window: it comes from the owner rules below, which pick the outage that
// contains the edge. The window only bounds the search.
const sceneClaimWindow = unreferencedSceneRetention

// clockAheadFlagMs is how far an agent's collection time may run PAST this
// server's receipt before the scene is flagged as clock-skewed.
//
// Only the forward direction is evidence of a clock problem, and getting that
// wrong is easy: the obvious implementation takes the absolute gap between
// collected_at and received_at, which for a scene is mostly DELIVERY LAG. A
// scene collected during a twenty-minute outage arrives twenty minutes late by
// design — that is the entire point of routing it through the outbox — so an
// absolute-gap rule would stamp "the clocks disagree by 1200s" on precisely the
// evidence this feature exists to produce, and an operator would go hunting an
// NTP fault that isn't there. Waiting is expected; arriving before it was
// collected is not, and nothing but a fast agent clock explains it.
const clockAheadFlagMs = 5000

// sceneAllowlist is the set of scene field-group ids the server accepts. A group
// the agent invented has its result dropped rather than stored — the collection
// contract is allowlisted at both ends, so an unknown group id means the two ends
// disagree about what may be gathered, and the server's answer to that is no.
var sceneAllowlist = map[string]bool{
	telemetry.SnapshotGroupNetwork:   true,
	telemetry.SnapshotGroupAgent:     true,
	telemetry.SnapshotGroupResources: true,
	telemetry.SnapshotGroupTargets:   true,
}

// scenePayload is the persisted scene body: the per-group outcomes plus the
// typed payload of each group that actually collected. Groups is kept even for a
// denied/unsupported/failed group, because "the agent could not read its
// interfaces" is an answer and an absent section is not.
type scenePayload struct {
	Groups    []telemetry.SnapshotGroupResult  `json:"groups"`
	Network   *telemetry.SnapshotNetwork       `json:"network,omitempty"`
	Agent     *telemetry.SnapshotAgentInfo     `json:"agent,omitempty"`
	Resources *telemetry.SnapshotResources     `json:"resources,omitempty"`
	Targets   []telemetry.SnapshotTargetResult `json:"targets,omitempty"`
}

// ---- ingest (inside the telemetry write transaction) ----

// SceneOutcome is the post-commit work one packet's scene reports left behind:
// the incidents that gained scene evidence and now need the console told. Empty
// for the common case of a scene that matched no open fault, which is not a
// failure — the scene waits to be claimed.
//
// It has no Attributed half, unlike TraceOutcome. A scene carries no reachability
// verdict — it says what the agent could see, not where the path broke — so
// attaching one never moves an incident's attribution and there is nothing to
// recompute. The only thing that changed is what an open incident view shows.
type SceneOutcome struct {
	Touched []eventbus.IncidentEvent
}

// IngestScenesTx persists the scene reports carried by one telemetry packet and
// files each against whatever fault its triggers identify, inside the caller's
// write transaction.
//
// It shares the transaction with the samples and the fault evaluation for the
// same reason IngestTracesTx does: a scene is evidence about the rounds arriving
// beside it, and committing the two separately would leave a stored scene
// attached to nothing after a mid-write failure while the agent's ack said it had
// been received. Failing here withholds the ack, the agent replays, and the
// INSERT OR IGNORE on the agent-minted report id makes the replay a no-op.
//
// A report with no triggers is dropped rather than stored: the trigger IS the
// claim key, so a scene without one could never be filed against anything and
// would sit unreadable until retention removed it.
func (s *Service) IngestScenesTx(ctx context.Context, tx *sql.Tx, agentID, siteID string, reports []telemetry.SceneReport) (*SceneOutcome, error) {
	if len(reports) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	agentName := s.agentName(ctx, agentID)
	maxBytes := s.snapshotMaxBytes(ctx)
	out := &SceneOutcome{}
	changed := map[string]string{} // incident id → site id

	for _, rep := range reports {
		if rep.ReportID == "" || len(rep.Triggers) == 0 {
			continue
		}
		inserted, err := insertSceneReport(ctx, tx, agentID, siteID, agentName, rep, now, maxBytes)
		if err != nil {
			return nil, err
		}
		if !inserted {
			continue // replay, or an id another agent already owns
		}
		if err := insertSceneTriggers(ctx, tx, rep); err != nil {
			return nil, err
		}
		// A scene that matches no firing fault is stored unattached on purpose: the
		// agent collected on its own edge and the fault may not be confirmed here
		// yet, so claimScenes files it later.
		incidents, err := attachScene(ctx, tx, agentID, rep, now)
		if err != nil {
			return nil, err
		}
		for _, id := range incidents {
			changed[id] = siteID
		}
	}

	for incidentID, site := range changed {
		out.Touched = append(out.Touched, eventbus.IncidentEvent{IncidentID: incidentID, SiteID: site})
	}
	if len(out.Touched) == 0 {
		return nil, nil
	}
	return out, nil
}

// PublishSceneOutcome lets the console converge after ingest committed. Called
// post-commit by the caller that ran IngestScenesTx, so nothing here can be
// observed before the evidence it describes is durable.
//
// One incident event per touched incident and nothing else: no target-status
// refresh, because a scene changes no target's verdict, and no attribution
// republish, because it feeds no recompute.
func (s *Service) PublishSceneOutcome(ctx context.Context, out *SceneOutcome) {
	if out == nil || s.bus == nil {
		return
	}
	for _, ev := range out.Touched {
		s.bus.Publish(eventbus.TopicIncidentUpdated, eventbus.IncidentEvent{IncidentID: ev.IncidentID, SiteID: ev.SiteID})
	}
}

// insertSceneReport stores one scene, returning whether it was new. The id is the
// agent's, so an INSERT OR IGNORE covers both idempotency cases at once: a
// replayed packet re-presents an id already stored, and an id claimed by a
// different agent collides with the row that agent owns. Either way the stored
// scene stands and nothing is overwritten.
func insertSceneReport(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string,
	rep telemetry.SceneReport, now time.Time, maxBytes int) (bool, error) {
	payload, truncated := capScenePayload(mustJSON(buildScenePayload(rep)), maxBytes)
	lagMs, clockAhead := deliveryLag(rep.CollectedAt, now)

	r, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO scene_reports(id, site_id, agent_id, agent_name,
			collected_at, received_at, delivery_lag_ms, clock_ahead, payload, truncated)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		rep.ReportID, siteID, agentID, agentName,
		nullTimeOf(rep.CollectedAt), now, lagMs, boolInt(clockAhead), payload, boolInt(truncated))
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n > 0, nil
}

// deliveryLag reports how long a scene waited between the agent collecting it
// and this server receiving it, and whether the agent's clock is provably ahead.
//
// The lag is signed on purpose. Positive is the ordinary case and carries real
// information — a scene that waited out an outage is the feature working — while
// negative means the agent stamped it in this server's future, which delivery
// can never explain and a wrong clock always can. Neither is corrected: an
// agent's clock is its own, and rewriting collected_at would destroy the only
// record of when the agent thought it was looking.
//
// A scene with no collection time at all (a malformed report) reports no lag
// rather than the distance to the zero instant, which would call every such row
// two thousand years early and say nothing true.
func deliveryLag(collectedAt, now time.Time) (int64, bool) {
	if collectedAt.IsZero() {
		return 0, false
	}
	ms := now.Sub(collectedAt).Milliseconds()
	return ms, ms < -clockAheadFlagMs
}

// buildScenePayload filters an agent's report to the allowlisted groups and keeps
// each typed section only when its own group reported collected. A section
// present without its group having collected is a contradiction the agent should
// never produce; dropping it means the stored scene can always be read as "these
// groups succeeded, and here is exactly what they found".
func buildScenePayload(rep telemetry.SceneReport) scenePayload {
	var p scenePayload
	collected := map[string]bool{}
	for _, g := range rep.Groups {
		if !sceneAllowlist[g.Group] {
			continue
		}
		p.Groups = append(p.Groups, g)
		if g.Status == telemetry.ScopeCollected {
			collected[g.Group] = true
		}
	}
	if collected[telemetry.SnapshotGroupNetwork] {
		p.Network = rep.Network
	}
	if collected[telemetry.SnapshotGroupAgent] {
		p.Agent = rep.Agent
	}
	if collected[telemetry.SnapshotGroupResources] {
		p.Resources = rep.Resources
	}
	if collected[telemetry.SnapshotGroupTargets] {
		p.Targets = rep.Targets
	}
	return p
}

// capScenePayload enforces incident_snapshot_max_bytes on one scene BEFORE it is
// stored, rather than reconciling an oversized row afterwards: nothing waits on a
// scene any more, so there is no later moment at which a total could be settled.
//
// Optional detail is shed in a fixed priority — per-target resolution, then the
// interface inventory, then the resource summary — so two scenes of the same size
// are always reduced the same way. The group outcomes survive every tier, because
// they are what makes a reduced scene readable as reduced rather than as empty;
// if even those overflow (they cannot in practice: the allowlist bounds them to
// four entries) the payload is dropped whole, so the cap is a guarantee and not
// an aspiration.
func capScenePayload(payload string, maxBytes int) (string, bool) {
	if len(payload) <= maxBytes {
		return payload, false
	}
	truncated := false
	for level := 0; level < 3 && len(payload) > maxBytes; level++ {
		next, changed := stripSceneLevel(payload, level)
		if !changed {
			continue
		}
		payload = next
		truncated = true
	}
	if len(payload) > maxBytes {
		return "", true
	}
	return payload, truncated
}

// stripSceneLevel removes one tier of optional detail from a serialized scene
// payload, preserving the group-status metadata. level 0 drops the per-target
// resolution results, 1 the network interface inventory, 2 the resource summary.
// Returns the re-serialized payload and whether it changed.
func stripSceneLevel(payload string, level int) (string, bool) {
	if payload == "" {
		return payload, false
	}
	var p scenePayload
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

// insertSceneTriggers stores the fault edges a scene answers for, keyed by their
// position in the agent's own list. The position is part of the key rather than a
// minted id because it is already unique within the report and stable across a
// replay, which is exactly what an idempotent insert needs.
func insertSceneTriggers(ctx context.Context, tx *sql.Tx, rep telemetry.SceneReport) error {
	for i, tr := range rep.Triggers {
		kind := tr.Kind
		if kind != telemetry.SceneTriggerProbeFault && kind != telemetry.SceneTriggerServerDisconnect {
			// The column is CHECKed and the value is an agent's. A malformed trigger
			// must not abort a whole telemetry packet, and it can never be claimed by
			// anything either, so it is simply not recorded.
			continue
		}
		edges := tr.EdgeCount
		if edges < 1 {
			edges = 1
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO scene_report_triggers(report_id, idx, kind, monitor_id, config_serial,
				trigger_streak, first_failed_at, disconnected_at, reason, edge_count)
			VALUES(?,?,?,?,?,?,?,?,?,?)`,
			rep.ReportID, i, kind, tr.MonitorID, tr.ConfigSerial,
			tr.TriggerStreak, nullTimeOf(tr.FirstFailedAt), nullTimeOf(tr.DisconnectedAt), tr.Reason, edges); err != nil {
			return err
		}
	}
	return nil
}

// sceneRef is one signal a scene can be filed under.
type sceneRef struct {
	signalID, incidentID string
}

// attachScene files a freshly stored scene against every firing fault its
// triggers identify, and appends a timeline entry to each affected incident. It
// returns the distinct incident ids the caller needs to tell the console about.
//
// Each trigger is matched on its own, because one scene can legitimately explain
// several unrelated faults: an edge crossed while the scene was already being
// gathered joined it rather than queueing a second copy of the same machine.
func attachScene(ctx context.Context, tx *sql.Tx, agentID string, rep telemetry.SceneReport, now time.Time) ([]string, error) {
	seen := map[string]bool{}
	var incidents []string
	for _, tr := range rep.Triggers {
		var refs []sceneRef
		var err error
		switch tr.Kind {
		case telemetry.SceneTriggerProbeFault:
			refs, err = probeFaultRefs(ctx, tx, agentID, tr, now)
		case telemetry.SceneTriggerServerDisconnect:
			refs, err = disconnectRefs(ctx, tx, agentID, tr, now)
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, r := range refs {
			inserted, err := insertSceneRef(ctx, tx, rep.ReportID, r, now)
			if err != nil {
				return nil, err
			}
			if !inserted || seen[r.incidentID] {
				continue
			}
			seen[r.incidentID] = true
			incidents = append(incidents, r.incidentID)
			if err := addSceneTimeline(ctx, tx, r.incidentID, rep.ReportID, now); err != nil {
				return nil, err
			}
		}
	}
	return incidents, nil
}

// probeFaultRefs finds the signal a probe-fault trigger belongs to, at ingest
// time: this agent's outage on that monitor, frozen at the same material
// generation, that owns the edge.
//
// Degradation signals are excluded outright. Their target is answering, just
// slowly, and the agent's local streak that produced the scene is an
// availability streak; sharing a monitor with a hard failure must not put that
// failure's scene in a latency trend's evidence.
func probeFaultRefs(ctx context.Context, tx *sql.Tx, agentID string, tr telemetry.SceneTrigger, now time.Time) ([]sceneRef, error) {
	if tr.MonitorID == "" {
		return nil, nil
	}
	r, ok, err := ownerOfProbeFault(ctx, tx, agentID, tr.MonitorID, tr.ConfigSerial, tr.FirstFailedAt, now)
	if err != nil || !ok {
		return nil, err
	}
	return []sceneRef{r}, nil
}

// rowQuerier is the multi-row read surface shared by the read pool and an open
// transaction, so the owner rules below run identically on both. That sharing is
// the point: the ingest path and the claim-back path decide which outage a scene
// belongs to, and if they decided it separately they would eventually decide it
// differently.
type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// pickOwner walks candidate outages newest-first and returns the one that owns
// an agent-stamped edge.
//
// Containment wins: the outage observed at or before the edge and not yet
// resolved by then is the one the agent was looking at. Only when nothing
// contains the edge does the nearest outage starting within attachSlack of it
// stand in, which is the clock-skew case — the edge belongs to a real outage
// whose recorded start sits just the wrong side of it.
//
// Ordering the containment test first is the whole correctness argument, and it
// is arithmetic rather than taste. Consecutive outages of one subject can be
// closer together than attachSlack — a connectivity fault repeats after
// grace+recover (~95s on stock settings) and a fast probe monitor can fail again
// about 50s after recovering — so a slack-only rule finds the PREVIOUS outage's
// scene compatible with the next outage as well, and files one drop's evidence
// under two incidents. The slack absorbs disagreement between two records of one
// moment; it was never a licence to span two of them.
func pickOwner(rows *sql.Rows, edge time.Time) (sceneRef, bool, error) {
	var nearest sceneRef
	haveNearest := false
	for rows.Next() {
		var r sceneRef
		var detectorKey string
		var observedAt time.Time
		var resolvedAt sql.NullTime
		if err := rows.Scan(&r.signalID, &r.incidentID, &detectorKey, &observedAt, &resolvedAt); err != nil {
			return sceneRef{}, false, err
		}
		// A degradation signal never owns a scene. Its target is answering, just
		// slowly, while the agent's local streak that produced the scene is an
		// availability streak — putting a hard failure's scene in a latency trend's
		// evidence would misattribute both. Decided by fault.IsDegradation rather
		// than by a SQL pattern so there is one definition of what counts.
		if fault.IsDegradation(detectorKey) {
			continue
		}
		if contains(edge, observedAt, resolvedAt) {
			return r, true, rows.Err()
		}
		if !haveNearest && nearInterval(edge, observedAt, resolvedAt) {
			nearest, haveNearest = r, true
		}
	}
	if err := rows.Err(); err != nil {
		return sceneRef{}, false, err
	}
	return nearest, haveNearest, nil
}

// contains reports whether an outage was in progress at the edge: begun by then
// and not yet ended. An outage still firing has no end, so anything at or after
// its start is inside it.
func contains(edge, observedAt time.Time, resolvedAt sql.NullTime) bool {
	if edge.IsZero() {
		return false
	}
	if observedAt.After(edge) {
		return false
	}
	return !resolvedAt.Valid || !resolvedAt.Time.Before(edge)
}

// nearInterval is the clock-skew fallback: the edge is not inside the outage,
// but it is close enough to its boundaries that the difference is explained by
// the two clocks disagreeing about one moment.
//
// It is bounded on BOTH sides, which the containment test makes easy to forget.
// A one-sided "the edge is not before this outage started" admits an edge half an
// hour after a closed outage ended, which is not skew — it is a different event —
// and that is precisely how a stale outage adopts a fresh scene.
func nearInterval(edge, observedAt time.Time, resolvedAt sql.NullTime) bool {
	if edge.IsZero() || observedAt.IsZero() {
		return true // nothing to compare; not a reason to refuse
	}
	if edge.Before(observedAt.Add(-attachSlack)) {
		return false
	}
	if resolvedAt.Valid && edge.After(resolvedAt.Time.Add(attachSlack)) {
		return false
	}
	return true
}

// ownerOfProbeFault answers which outage of one monitor a probe-fault edge
// belongs to.
//
// Resolved outages are candidates alongside firing ones, for a reason the agent
// side creates: a scene held by the collector's one-minute cooldown is appended
// AFTER the rounds that recovered the target, so a short fault can be confirmed
// and resolved server-side before its scene is even queued. Matching only firing
// signals would strand exactly the scenes the pacing rule delayed — evidence the
// agent collected, delivered, and nothing would ever look at.
func ownerOfProbeFault(ctx context.Context, q rowQuerier, agentID, monitorID string, serial int, edge, now time.Time) (sceneRef, bool, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, incident_id, detector_key, observed_at, resolved_at FROM fault_signals
		WHERE agent_id=? AND target_id=? AND target_config_serial=?
		  AND incident_id IS NOT NULL AND incident_id<>''
		  AND (state='firing' OR (state='resolved' AND resolved_at IS NOT NULL AND resolved_at >= ?))
		ORDER BY observed_at DESC`,
		agentID, monitorID, serial, now.Add(-sceneClaimWindow))
	if err != nil {
		return sceneRef{}, false, err
	}
	defer rows.Close()
	return pickOwner(rows, edge)
}

// ownerOfDisconnect answers the same question for a disconnect edge: which
// agent-connectivity outage was in progress when the agent lost its session?
// That detector is per-agent and carries no target, so the agent id plus the
// edge's timing is the whole key.
//
// Resolved signals are admitted for a different reason than above: the
// connectivity fault resolves once the agent reconnects, and a WAL drain can
// outlast the recover window, so a scene queued behind a backlog lands after its
// own outage closed.
func ownerOfDisconnect(ctx context.Context, q rowQuerier, agentID string, edge, now time.Time) (sceneRef, bool, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, incident_id, detector_key, observed_at, resolved_at FROM fault_signals
		WHERE agent_id=? AND detector_key=? AND incident_id IS NOT NULL AND incident_id<>''
		  AND (state='firing' OR (state='resolved' AND resolved_at IS NOT NULL AND resolved_at >= ?))
		ORDER BY observed_at DESC`,
		agentID, fault.DetectorAgentConnectivity, now.Add(-sceneClaimWindow))
	if err != nil {
		return sceneRef{}, false, err
	}
	defer rows.Close()
	return pickOwner(rows, edge)
}

// disconnectRefs finds the agent-connectivity signal a disconnect trigger
// belongs to, at ingest time. That detector is per-agent and carries no target,
// so the agent id plus the edge's timing is the whole key — there is nothing
// further to discriminate on, and exactly one outage can own an edge.
func disconnectRefs(ctx context.Context, tx *sql.Tx, agentID string, tr telemetry.SceneTrigger, now time.Time) ([]sceneRef, error) {
	r, ok, err := ownerOfDisconnect(ctx, tx, agentID, tr.DisconnectedAt, now)
	if err != nil || !ok {
		return nil, err
	}
	return []sceneRef{r}, nil
}

// orderedWithinSlack reports whether an agent-stamped edge is compatible with a
// signal's first observed failing moment — that is, not from an outage that
// predates it. The two timestamps describe the same fault from two clocks, so a
// small slack absorbs skew and round phasing; what the comparison must reject is
// minutes-to-hours older evidence of the same subject. Either side missing means
// there is nothing to compare, which is not a reason to refuse.
func orderedWithinSlack(agentEdge, observedAt time.Time) bool {
	if agentEdge.IsZero() || observedAt.IsZero() {
		return true
	}
	return !agentEdge.Before(observedAt.Add(-attachSlack))
}

// insertSceneRef files a scene under one signal, reporting whether the reference
// is new. INSERT OR IGNORE is the whole idempotency story here — unlike a trace
// reference there is no active flag to reactivate, because a scene is never
// deactivated (see the scene_report_refs comment in the schema).
func insertSceneRef(ctx context.Context, tx *sql.Tx, reportID string, r sceneRef, now time.Time) (bool, error) {
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO scene_report_refs(report_id, incident_id, signal_id, created_at)
		VALUES(?,?,?,?)`, reportID, r.incidentID, r.signalID, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// addSceneTimeline records that a scene became this incident's evidence, once
// per (incident, report).
//
// The guard is not belt-and-braces. A scene carrying two triggers whose signals
// later merge into ONE incident produces two distinct references — the key
// includes signal_id — and each confirmation would otherwise write its own
// "scene collected" row for a scene the snapshot itself shows only once. The
// reader would count evidence that does not exist.
func addSceneTimeline(ctx context.Context, tx *sql.Tx, incidentID, reportID string, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref)
		SELECT ?,?,?,?,?,?
		WHERE NOT EXISTS(
			SELECT 1 FROM incident_timeline WHERE incident_id=? AND kind='scene.collected' AND ref=?)`,
		"tl_"+uuid.NewString(), incidentID, now, "scene.collected", "", reportID,
		incidentID, reportID)
	return err
}

// ---- claim-back (post-commit, on fault confirmation) ----

// claimScenes files every recent, temporally compatible scene this agent already
// shipped against a newly-confirmed signal.
//
// It is the other half of the handshake ingest's attachScene starts. The agent
// collects when its OWN edge crosses, which is not the instant this server
// finishes confirming the same rounds: a scene routinely lands before its
// incident exists, finds no firing fault, and sits unreferenced. Together the two
// paths cover both orderings, and the reference insert — not either path being
// one-shot — is what makes them idempotent.
//
// No attribution recompute follows, unlike claimTraces: a scene asserts nothing
// about where the path broke, so claiming one adds evidence without changing any
// answer the console derives.
func (s *Service) claimScenes(ctx context.Context, ev fault.SignalEvent) error {
	var targetID string
	var configSerial int
	var observedAt time.Time
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT COALESCE(target_id,''), target_config_serial, observed_at FROM fault_signals WHERE id=?`, ev.SignalID).
		Scan(&targetID, &configSerial, &observedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	reportIDs, err := s.claimableScenes(ctx, ev, targetID, configSerial, observedAt)
	if err != nil || len(reportIDs) == 0 {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	now := time.Now().UTC()
	claimed := 0
	for _, reportID := range reportIDs {
		// RowsAffected is the "was this new" signal, and the timeline entry rides it:
		// without that, every re-confirmation of a signal would repeat the
		// "scene collected" line for evidence the incident already shows.
		inserted, err := insertSceneRef(ctx, tx, reportID, sceneRef{signalID: ev.SignalID, incidentID: ev.IncidentID}, now)
		if err != nil {
			return err
		}
		if !inserted {
			continue
		}
		claimed++
		if err := addSceneTimeline(ctx, tx, ev.IncidentID, reportID, now); err != nil {
			return err
		}
	}
	if claimed == 0 {
		return tx.Rollback()
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	if s.bus != nil {
		s.bus.Publish(eventbus.TopicIncidentUpdated, eventbus.IncidentEvent{IncidentID: ev.IncidentID, SiteID: ev.SiteID})
	}
	return nil
}

// claimableScenes lists the scene ids this signal may claim, on the read pool and
// before any transaction is opened.
//
// The key depends on which detector confirmed: an agent-connectivity signal is
// per-agent and claims disconnect triggers, every other signal claims probe-fault
// triggers on its own monitor AND generation.
//
// Both branches then re-decide OWNERSHIP through the same functions the ingest
// path uses, and that — not the ranges — is what makes the answer right. A range
// test can only ask "is this scene compatible with this signal", and consecutive
// outages of one subject sit closer together than attachSlack, so the previous
// outage's scene answers yes for the next signal too. Asking which outage owns
// the edge is the question that has one answer, and routing both paths through
// one function is what keeps them from drifting apart.
//
// The receipt window is therefore only a bound on the search, which is why it can
// afford to be the full retention period: see sceneClaimWindow for why anything
// shorter strands the scenes of slow monitors outright.
func (s *Service) claimableScenes(ctx context.Context, ev fault.SignalEvent, targetID string, configSerial int, observedAt time.Time) ([]string, error) {
	now := time.Now().UTC()
	cutoff := now.Add(-sceneClaimWindow)

	if ev.DetectorKey == fault.DetectorAgentConnectivity {
		return s.claimableDisconnectScenes(ctx, ev, cutoff, now)
	}
	if targetID == "" {
		return nil, nil
	}
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT sr.id, t.first_failed_at FROM scene_reports sr
		JOIN scene_report_triggers t ON t.report_id = sr.id
		WHERE sr.agent_id=? AND sr.received_at >= ? AND t.kind='probe_fault'
		  AND t.monitor_id=? AND t.config_serial=?
		ORDER BY sr.id`, ev.AgentID, cutoff, targetID, configSerial)
	if err != nil {
		return nil, err
	}
	candidates, err := scanCandidates(rows)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range candidates {
		owner, ok, err := ownerOfProbeFault(ctx, s.db.Read(), ev.AgentID, targetID, configSerial, c.edge, now)
		if err != nil {
			return nil, err
		}
		if ok && owner.signalID == ev.SignalID {
			out = append(out, c.id)
		}
	}
	return out, nil
}

// sceneCandidate is one scene id paired with the agent-stamped edge its trigger
// carries, which is what the owner rules key on.
type sceneCandidate struct {
	id   string
	edge time.Time
}

func scanCandidates(rows *sql.Rows) ([]sceneCandidate, error) {
	defer rows.Close()
	var out []sceneCandidate
	for rows.Next() {
		var c sceneCandidate
		var edge sql.NullTime
		if err := rows.Scan(&c.id, &edge); err != nil {
			return nil, err
		}
		if edge.Valid {
			c.edge = edge.Time
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// claimableDisconnectScenes narrows this agent's recent disconnect scenes to the
// ones this connectivity signal actually owns.
func (s *Service) claimableDisconnectScenes(ctx context.Context, ev fault.SignalEvent, cutoff, now time.Time) ([]string, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT sr.id, t.disconnected_at FROM scene_reports sr
		JOIN scene_report_triggers t ON t.report_id = sr.id
		WHERE sr.agent_id=? AND sr.received_at >= ? AND t.kind='server_disconnect'
		ORDER BY sr.id`, ev.AgentID, cutoff)
	if err != nil {
		return nil, err
	}
	candidates, err := scanCandidates(rows)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range candidates {
		owner, ok, err := ownerOfDisconnect(ctx, s.db.Read(), ev.AgentID, c.edge, now)
		if err != nil {
			return nil, err
		}
		if ok && owner.signalID == ev.SignalID {
			out = append(out, c.id)
		}
	}
	return out, nil
}
