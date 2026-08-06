// Package registry tracks agents: identity, local permission policy, status and
// last-seen. M1 provides dev auto-registration (agent appears on first
// telemetry). Real ed25519 enrollment, enrollment tokens and the max_agents
// quota land in M2.
package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/store"
)

type Agent struct {
	ID           string `json:"id"`
	SiteID       string `json:"site_id"`
	DisplayName  string `json:"display_name"` // operator-set friendly label, editable from the UI
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	AgentVersion string `json:"agent_version"`
	Status       string `json:"status"`
	// Local permission policy the agent reports on every (re)connect: supported =
	// what the build+platform can do, granted = the local policy, effective = the
	// usable intersection. These gate host/process/connection views and drive the
	// monitor pre-check + remediation surface.
	Supported []string `json:"supported"`
	Granted   []string `json:"granted"`
	Effective []string `json:"effective"`
	// UnsupportedReasons explains, per permission ID, why a capability probe
	// concluded the permission is unsupported here — without it "supported: false"
	// leaves the console guessing the one remediation it happens to know. Keys are
	// always absent from Supported; an absent key means the probe never ran, not
	// that nothing is wrong. Replaced wholesale by every report, like the sets
	// above.
	UnsupportedReasons map[string]string `json:"unsupported_reasons,omitempty"`
	PolicySource       string            `json:"policy_source"`
	PolicyHash         string            `json:"policy_hash"`
	LastSeenAt         *time.Time        `json:"last_seen_at"`
	CreatedAt          time.Time         `json:"created_at"`
	// Connectivity provenance (AGENT-001/002): FirstConnectedAt is nil until the
	// agent completes its first Hello (nil = never connected, distinct from
	// offline). LastDisconnectKind annotates why the most recent session ended.
	// ConnectivityAlertsMuted suppresses offline/recovery alerts for this agent.
	FirstConnectedAt        *time.Time `json:"first_connected_at"`
	LastDisconnectKind      string     `json:"last_disconnect_kind"`
	ConnectivityAlertsMuted bool       `json:"connectivity_alerts_muted"`
}

// StatusEvent is one online/offline transition in an agent's history. Reason
// carries the disconnect kind for offline transitions (” for online).
type StatusEvent struct {
	Status    string    `json:"status"` // online | offline
	ChangedAt time.Time `json:"changed_at"`
	Reason    string    `json:"reason,omitempty"`
}

const statusHistoryLimit = 20

type Service struct {
	db        *store.DB
	maxAgents int // 0 = unlimited
	bus       *eventbus.Bus
	// ResetSeqWatermark, when set, clears the ingest service's in-memory per-agent
	// sequence watermark. Reenrollment (AGENT-006) reuses an agent id whose WAL was
	// wiped and restarted at sequence 1; without this the next ack would report the
	// previous installation's high watermark and the agent would fast-forward past
	// un-uploaded batches. A function, not an ingest reference, so registry stays
	// free of an ingest import. Wired at composition (server.Start); nil is a no-op.
	ResetSeqWatermark func(ctx context.Context, agentID string)
	// DisconnectSession, when set, forcibly ends a live agent session. Called at
	// the START of a reenrollment, before any sequence state is cleared: the old
	// session authenticated with a now-rotated credential and, left running, would
	// ingest after the reset and re-create a high watermark. Wired at composition;
	// nil is a no-op (no live session to fence).
	DisconnectSession func(ctx context.Context, agentID string)
}

// New constructs the registry. maxAgents caps enrollment (0 = unlimited). bus may
// be nil in tests (agent-liveness events are then simply not published). The
// quota is a product requirement (default 50); note architecture §7/§15 advise
// against hard-limiting Lite — it is intentionally configurable.
func New(db *store.DB, maxAgents int, bus *eventbus.Bus) *Service {
	return &Service{db: db, maxAgents: maxAgents, bus: bus}
}

// publishLiveness emits a TopicAgentLivenessChanged so a bridge can fan an
// online↔offline flip out to a site-wide target-status refresh (liveness affects
// every target in the agent's scope).
func (s *Service) publishLiveness(siteID, agentID, status string) {
	if s.bus != nil && siteID != "" {
		s.bus.Publish(eventbus.TopicAgentLivenessChanged,
			eventbus.AgentLivenessChanged{SiteID: siteID, AgentID: agentID, Status: status})
	}
}

// publishSiteStatus emits a site-wide TopicTargetStatusChanged (empty TargetIDs =
// whole-site refresh) after a change whose scope is the entire site's target set,
// such as an agent being deleted — its removal changes applicable_agents and the
// aggregation of every target it was in scope for.
func (s *Service) publishSiteStatus(siteID string) {
	if s.bus != nil && siteID != "" {
		s.bus.Publish(eventbus.TopicTargetStatusChanged,
			eventbus.TargetStatusChanged{SiteID: siteID})
	}
}

// TouchLastSeen bumps an agent's last-seen timestamp and marks it online,
// recording an offline→online transition in the status history (and publishing a
// liveness event) when the agent was previously offline.
func (s *Service) TouchLastSeen(ctx context.Context, id string) error {
	now := time.Now().UTC()
	var prev, siteID string
	_ = s.db.QueryRowContext(ctx, `SELECT status, site_id FROM agents WHERE id=?`, id).Scan(&prev, &siteID)
	if _, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen_at=?, status='online' WHERE id=?`, now, id); err != nil {
		return err
	}
	if prev != "online" {
		s.recordStatus(ctx, id, "online", "", now)
		s.publishLiveness(siteID, id, "online")
	}
	return nil
}

// MarkFirstConnected stamps first_connected_at the first time an agent completes
// a Hello; the NULL-only WHERE makes every later connect a no-op, so the value
// records the agent's very first connection and never moves. Until it is set the
// status list reports the agent as never-connected rather than offline.
func (s *Service) MarkFirstConnected(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET first_connected_at=? WHERE id=? AND first_connected_at IS NULL`,
		time.Now().UTC(), id)
	return err
}

// RecordDisconnect stores how an agent's most recent session ended (see the
// last_disconnect_kind vocabulary in the schema). The sweeper reads it when
// it flips the agent offline, and the alert engine maps it to an alert reason.
func (s *Service) RecordDisconnect(ctx context.Context, id, kind string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_disconnect_kind=? WHERE id=?`, kind, id)
	return err
}

// SetConnectivityMuted toggles the per-agent connectivity-alert mute switch.
// Returns sql.ErrNoRows if no live agent has that id.
func (s *Service) SetConnectivityMuted(ctx context.Context, id string, muted bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET connectivity_alerts_muted=? WHERE id=? AND revoked=0`, boolToInt(muted), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// UpdatePermissions refreshes an agent's reported local permission policy
// (supported / granted / effective sets, the per-permission unsupported reasons,
// source, hash) from its WebSocket Hello, so restarting an agent with a different
// NETTACT_AGENT_PERMISSIONS policy — or after fixing a broken capability — is
// reflected server-side (enrollment happens only once). The conditional WHERE
// makes it a no-op write when nothing changed.
func (s *Service) UpdatePermissions(ctx context.Context, id string, report permission.PermissionReport) error {
	sup := marshalStrings(report.Supported)
	gr := marshalStrings(report.Granted)
	eff := marshalStrings(report.Effective)
	reasons := marshalReasons(report.UnsupportedReasons, report.Supported)
	_, err := s.db.ExecContext(ctx, `
		UPDATE agents SET perm_supported=?, perm_granted=?, perm_effective=?, perm_unsupported_reasons=?,
		                  policy_source=?, policy_hash=?
		WHERE id=? AND (perm_supported<>? OR perm_granted<>? OR perm_effective<>? OR perm_unsupported_reasons<>?
		                OR policy_source<>? OR policy_hash<>?)`,
		sup, gr, eff, reasons, report.Source, report.PolicyHash,
		id, sup, gr, eff, reasons, report.Source, report.PolicyHash)
	return err
}

// marshalStrings encodes a string slice as a JSON array, normalizing nil to "[]"
// so a never-set column and an empty report compare equal (no spurious writes).
func marshalStrings(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

// marshalReasons encodes the unsupported-reason map as a JSON object,
// normalizing nil to "{}" like marshalStrings does for the sets. encoding/json
// emits map keys in sorted order, so the same reasons always encode to the same
// text and the conditional UPDATE above stays a true no-op across reconnects.
//
// It also ENFORCES the contract that the map only ever holds ids absent from
// supported, dropping any key that contradicts it. A buggy or version-mismatched
// agent could report a permission as both supported and failed; storing that
// would let List/Get serialize an Agent claiming the capability works AND naming
// why it doesn't, in the same payload. Enforcing it once here, at the write
// boundary, means no reader has to reconcile it — and readers that serialize the
// Agent struct wholesale (the agents list and detail endpoints) get no chance to
// forget.
func marshalReasons(m map[string]string, supported []string) string {
	clean := make(map[string]string, len(m))
	isSupported := make(map[string]bool, len(supported))
	for _, id := range supported {
		isSupported[id] = true
	}
	for id, reason := range m {
		if !isSupported[id] {
			clean[id] = reason
		}
	}
	b, _ := json.Marshal(clean)
	return string(b)
}

// UpdateReportedInfo refreshes the agent-reported identity fields (hostname,
// platform, agent version) from a WebSocket Hello, so a rename or agent upgrade
// is reflected server-side (enrollment happens only once). Empty values are
// written as-is: the agent owns these fields and reports them on every connect.
func (s *Service) UpdateReportedInfo(ctx context.Context, id, hostname, platform, agentVersion string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET hostname=?, platform=?, agent_version=? WHERE id=?`,
		hostname, platform, agentVersion, id)
	return err
}

// SweepStale marks any online agent whose last_seen_at is older than threshold
// as offline and records the transition. Runs on a periodic ticker; returns the
// number of agents flipped offline. exclude lists agent IDs that must never be
// swept regardless of last_seen_at — the caller passes the currently connected
// WebSocket sessions, so a live agent can't be flipped offline by a race
// between its keepalive touch and the sweep threshold.
func (s *Service) SweepStale(ctx context.Context, threshold time.Duration, exclude []string) (int, error) {
	now := time.Now().UTC()
	cutoff := now.Add(-threshold)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, site_id, COALESCE(last_disconnect_kind,'') FROM agents WHERE revoked=0 AND status='online' AND last_seen_at IS NOT NULL AND last_seen_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	excluded := make(map[string]bool, len(exclude))
	for _, id := range exclude {
		excluded[id] = true
	}
	type staleAgent struct{ id, siteID, kind string }
	var stale []staleAgent
	for rows.Next() {
		var a staleAgent
		if err := rows.Scan(&a.id, &a.siteID, &a.kind); err != nil {
			rows.Close()
			return 0, err
		}
		if excluded[a.id] {
			continue
		}
		stale = append(stale, a)
	}
	rows.Close()
	changed := 0
	for _, a := range stale {
		// Re-check the stale condition atomically in the UPDATE: if a keepalive
		// touch marked the agent online (bumping last_seen_at) between the SELECT
		// above and here, the WHERE fails and we neither flip it offline nor write
		// a bogus history row.
		res, err := s.db.ExecContext(ctx,
			`UPDATE agents SET status='offline' WHERE id=? AND status='online' AND last_seen_at < ?`, a.id, cutoff)
		if err != nil {
			return changed, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			s.recordStatus(ctx, a.id, "offline", a.kind, now)
			s.publishLiveness(a.siteID, a.id, "offline")
			changed++
		}
	}
	return changed, nil
}

func (s *Service) recordStatus(ctx context.Context, agentID, status, reason string, at time.Time) {
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO agent_status_history(id, agent_id, status, reason, changed_at) VALUES(?,?,?,?,?)`,
		"ash_"+uuid.NewString(), agentID, status, reason, at)
}

// StatusHistory returns at most 20 online/offline transitions, newest first.
func (s *Service) StatusHistory(ctx context.Context, agentID string) ([]StatusEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, COALESCE(reason,''), changed_at FROM agent_status_history WHERE agent_id=? ORDER BY changed_at DESC LIMIT ?`,
		agentID, statusHistoryLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StatusEvent
	for rows.Next() {
		var e StatusEvent
		if err := rows.Scan(&e.Status, &e.Reason, &e.ChangedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) List(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, site_id, COALESCE(display_name,''), COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,''),
		       status, COALESCE(perm_supported,'[]'), COALESCE(perm_granted,'[]'), COALESCE(perm_effective,'[]'),
		       COALESCE(perm_unsupported_reasons,'{}'),
		       COALESCE(policy_source,''), COALESCE(policy_hash,''), last_seen_at, created_at,
		       first_connected_at, COALESCE(last_disconnect_kind,''), connectivity_alerts_muted
		FROM agents WHERE revoked=0 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		var sup, gr, eff, reasons string
		var lastSeen, firstConn sql.NullTime
		var muted int
		if err := rows.Scan(&a.ID, &a.SiteID, &a.DisplayName, &a.Hostname, &a.Platform, &a.AgentVersion,
			&a.Status, &sup, &gr, &eff, &reasons, &a.PolicySource, &a.PolicyHash, &lastSeen, &a.CreatedAt,
			&firstConn, &a.LastDisconnectKind, &muted); err != nil {
			return nil, err
		}
		unmarshalStrings(sup, &a.Supported)
		unmarshalStrings(gr, &a.Granted)
		unmarshalStrings(eff, &a.Effective)
		unmarshalReasons(reasons, &a.UnsupportedReasons)
		if lastSeen.Valid {
			t := lastSeen.Time
			a.LastSeenAt = &t
		}
		if firstConn.Valid {
			t := firstConn.Time
			a.FirstConnectedAt = &t
		}
		a.ConnectivityAlertsMuted = muted != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, id string) (Agent, error) {
	var a Agent
	var lastSeen, firstConn sql.NullTime
	var sup, gr, eff, reasons string
	var muted int
	err := s.db.QueryRowContext(ctx, `
		SELECT id, site_id, COALESCE(display_name,''), COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,''),
		       status, COALESCE(perm_supported,'[]'), COALESCE(perm_granted,'[]'), COALESCE(perm_effective,'[]'),
		       COALESCE(perm_unsupported_reasons,'{}'),
		       COALESCE(policy_source,''), COALESCE(policy_hash,''), last_seen_at, created_at,
		       first_connected_at, COALESCE(last_disconnect_kind,''), connectivity_alerts_muted
		FROM agents WHERE id=? AND revoked=0`, id).
		Scan(&a.ID, &a.SiteID, &a.DisplayName, &a.Hostname, &a.Platform, &a.AgentVersion, &a.Status,
			&sup, &gr, &eff, &reasons, &a.PolicySource, &a.PolicyHash, &lastSeen, &a.CreatedAt,
			&firstConn, &a.LastDisconnectKind, &muted)
	if err != nil {
		return Agent{}, err
	}
	unmarshalStrings(sup, &a.Supported)
	unmarshalStrings(gr, &a.Granted)
	unmarshalStrings(eff, &a.Effective)
	unmarshalReasons(reasons, &a.UnsupportedReasons)
	if lastSeen.Valid {
		t := lastSeen.Time
		a.LastSeenAt = &t
	}
	if firstConn.Valid {
		t := firstConn.Time
		a.FirstConnectedAt = &t
	}
	a.ConnectivityAlertsMuted = muted != 0
	return a, nil
}

// unmarshalStrings decodes a stored JSON array into dst, leaving it nil on empty.
func unmarshalStrings(s string, dst *[]string) {
	if s != "" {
		_ = json.Unmarshal([]byte(s), dst)
	}
}

// unmarshalReasons decodes the stored JSON object into dst. A stored "{}" yields
// an empty map, which reads the same as nil at every call site: no permission has
// an explanation, because none was ever probed.
func unmarshalReasons(s string, dst *map[string]string) {
	if s != "" {
		_ = json.Unmarshal([]byte(s), dst)
	}
}

// UpdateAgent sets an agent's operator-editable display name. Reported fields
// (hostname/platform/version/permissions) are owned by the agent and not touched
// here. Returns sql.ErrNoRows if no live agent has that id.
func (s *Service) UpdateAgent(ctx context.Context, id, displayName string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET display_name=? WHERE id=? AND revoked=0`, displayName, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteAgent hard-deletes an agent and the rows that belong to it. Foreign keys
// are enforced (store.Open sets foreign_keys=ON), so FK-constrained child rows
// (interfaces, agent_status_history, agent_group_members, monitor_status,
// operational_issues, game_host_seconds) must go before the agent row; the non-FK
// per-agent tables (agent_packets, events, detector_state) are cleared too so no
// orphaned rows survive. detector_state keys on agent_id with no FK cascade, so
// its live counters must be deleted explicitly here.
//
// fault_signals and fluctuations are NOT deleted: they are recorded history
// carrying the agent's frozen name, and a fault (or an availability dip) that
// happened does not stop having happened because the agent was later removed. The
// caller force-resolves the agent's firing signals (reason agent_deleted, so no
// recovery notification) before deleting. Unlinked fluctuations age out on their
// own retention; ones kept as an incident's precursors go with that incident.
// All in one transaction.
// Time-series data (series/samples/rollups, plus the metrics store's in-memory
// cache) is NOT handled here — callers purge it via metrics.Store.PurgeAgent so
// the cache stays consistent. Returns sql.ErrNoRows if no agent has that id.
// After a successful commit it publishes a site-wide target-status refresh so
// batch-driven consoles drop the removed agent (and its per-target contribution)
// immediately instead of at the next unrelated event.
func (s *Service) DeleteAgent(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Capture the agent's site before its row is removed so the post-commit refresh
	// targets the right site. A missing row surfaces as sql.ErrNoRows (not-found).
	var siteID string
	if err := tx.QueryRowContext(ctx, `SELECT site_id FROM agents WHERE id=?`, id).Scan(&siteID); err != nil {
		return err
	}

	for _, stmt := range []string{
		`DELETE FROM interfaces WHERE agent_id=?`,
		`DELETE FROM agent_wifi WHERE agent_id=?`,
		`DELETE FROM agent_status_history WHERE agent_id=?`,
		`DELETE FROM agent_group_members WHERE agent_id=?`,
		`DELETE FROM monitor_status WHERE agent_id=?`,
		`DELETE FROM operational_issues WHERE agent_id=?`,
		`DELETE FROM agent_packets WHERE agent_id=?`,
		`DELETE FROM events WHERE agent_id=?`,
		`DELETE FROM detector_state WHERE agent_id=?`,
		`DELETE FROM game_buckets WHERE run_id IN (SELECT id FROM game_runs WHERE agent_id=?)`,
		`DELETE FROM game_run_gaps WHERE run_id IN (SELECT id FROM game_runs WHERE agent_id=?)`,
		`DELETE FROM game_runs WHERE agent_id=?`,
		// The machine's own seconds. They hang off the AGENT rather than off a run,
		// so deleting the runs above leaves them behind — and their foreign key to
		// agents then blocks the row delete below outright, failing the whole
		// deletion after the caller has already purged the agent's metrics.
		//
		// This is the one game table that survives DeleteRun on purpose (the stream
		// is the machine's, and one run must not blank an overlapping run's curves),
		// which is exactly why deleting the AGENT has to name it explicitly.
		`DELETE FROM game_host_seconds WHERE agent_id=?`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
			return err
		}
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM agents WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.publishSiteStatus(siteID)
	return nil
}
