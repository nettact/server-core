package incidentops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ---- snapshot reads ----

// SnapshotView is one incident's evidence scene for the console: the frozen
// server base, plus every agent-collected scene claimed as this incident's
// evidence.
//
// There is no status field and no deadline, because there is no collection state
// machine left: an agent decides on its own edge, ships the scene through the
// WAL, and the server claims it. A scene has therefore either been claimed by
// this incident or it has not, and "not yet" is indistinguishable from "never" —
// which is the honest answer, since nothing was ever promised.
type SnapshotView struct {
	IncidentID string          `json:"incident_id"`
	Base       json.RawMessage `json:"base"`
	Truncated  bool            `json:"truncated"`
	CreatedAt  time.Time       `json:"created_at"`
	// Scenes are ordered newest received_at first. Receipt order rather than
	// collection order, because that is the order an operator watched them appear
	// and because a scene collected during an outage carries an agent clock that
	// may not be comparable with anything else on the page.
	Scenes []SceneEntry `json:"scenes"`
}

// SceneEntry is one agent-collected scene as this incident references it.
type SceneEntry struct {
	ReportID  string `json:"report_id"`
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	// CollectedAt is the agent's clock and ReceivedAt this server's. They are
	// seconds apart for a live fault and an outage apart for a scene that waited in
	// the agent's outbox — which is the normal case for the network faults this
	// evidence exists for, and therefore NOT a clock complaint. DeliveryLagMs is
	// that wait, signed; ClockAhead is the one shape delivery cannot explain, an
	// agent that stamped the scene in this server's future.
	CollectedAt   *time.Time `json:"collected_at"`
	ReceivedAt    time.Time  `json:"received_at"`
	DeliveryLagMs int64      `json:"delivery_lag_ms"`
	ClockAhead    bool       `json:"clock_ahead"`
	Truncated     bool       `json:"truncated"`
	// Triggers is why the agent collected this scene, in its own words. Nothing
	// server-side asked for it, so without them the scene reads as evidence that
	// appeared from nowhere.
	Triggers []SceneTriggerView `json:"triggers"`
	Payload  json.RawMessage    `json:"payload,omitempty"`
}

// SceneTriggerView is one fault edge a scene answers for. The probe_fault fields
// and the server_disconnect fields are mutually exclusive; Kind says which set is
// meaningful.
type SceneTriggerView struct {
	Kind           string     `json:"kind"`
	MonitorID      string     `json:"monitor_id,omitempty"`
	ConfigSerial   int        `json:"config_serial,omitempty"`
	TriggerStreak  int        `json:"trigger_streak,omitempty"`
	FirstFailedAt  *time.Time `json:"first_failed_at,omitempty"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	EdgeCount      int        `json:"edge_count,omitempty"`
}

// Snapshot returns an incident's snapshot with the scenes claimed for it, or
// ok=false when the incident has none.
func (s *Service) Snapshot(ctx context.Context, incidentID string) (SnapshotView, bool, error) {
	var v SnapshotView
	var base string
	var truncated int
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT COALESCE(base,''), truncated, created_at
		FROM incident_snapshots WHERE incident_id=?`, incidentID).
		Scan(&base, &truncated, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotView{}, false, nil
	}
	if err != nil {
		return SnapshotView{}, false, err
	}
	v.IncidentID = incidentID
	v.Truncated = truncated == 1
	if base != "" {
		v.Base = json.RawMessage(base)
	}

	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT sr.id, sr.agent_id, COALESCE(sr.agent_name,''), sr.collected_at, sr.received_at,
		       sr.delivery_lag_ms, sr.clock_ahead, sr.truncated, COALESCE(sr.payload,'')
		FROM scene_reports sr
		WHERE sr.id IN (SELECT DISTINCT report_id FROM scene_report_refs WHERE incident_id=?)
		ORDER BY sr.received_at DESC, sr.id`, incidentID)
	if err != nil {
		return SnapshotView{}, false, err
	}
	defer rows.Close()
	v.Scenes = []SceneEntry{}
	for rows.Next() {
		var e SceneEntry
		var clockAhead, sceneTrunc int
		var payload string
		var collected sql.NullTime
		if err := rows.Scan(&e.ReportID, &e.AgentID, &e.AgentName, &collected, &e.ReceivedAt,
			&e.DeliveryLagMs, &clockAhead, &sceneTrunc, &payload); err != nil {
			return SnapshotView{}, false, err
		}
		e.CollectedAt = timePtr(collected)
		e.ClockAhead = clockAhead == 1
		e.Truncated = sceneTrunc == 1
		if payload != "" {
			e.Payload = json.RawMessage(payload)
		}
		v.Scenes = append(v.Scenes, e)
	}
	if err := rows.Err(); err != nil {
		return SnapshotView{}, false, err
	}
	for i := range v.Scenes {
		triggers, err := s.sceneTriggers(ctx, v.Scenes[i].ReportID)
		if err != nil {
			return SnapshotView{}, false, err
		}
		v.Scenes[i].Triggers = triggers
	}
	return v, true, nil
}

// sceneTriggers reads one scene's fault edges in the order the agent listed
// them, which is the order they were crossed.
func (s *Service) sceneTriggers(ctx context.Context, reportID string) ([]SceneTriggerView, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT kind, COALESCE(monitor_id,''), config_serial, trigger_streak,
		       first_failed_at, disconnected_at, COALESCE(reason,''), edge_count
		FROM scene_report_triggers WHERE report_id=? ORDER BY idx`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SceneTriggerView{}
	for rows.Next() {
		var t SceneTriggerView
		var firstFailed, disconnected sql.NullTime
		if err := rows.Scan(&t.Kind, &t.MonitorID, &t.ConfigSerial, &t.TriggerStreak,
			&firstFailed, &disconnected, &t.Reason, &t.EdgeCount); err != nil {
			return nil, err
		}
		t.FirstFailedAt = timePtr(firstFailed)
		t.DisconnectedAt = timePtr(disconnected)
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---- trace reads ----

// TraceSummary is one traceroute report as referenced from an incident: the
// Agent-run execution record's identity, status and reached verdict, why the
// Agent ran it, plus how the incident references it (via which fault signals, and
// whether still active).
type TraceSummary struct {
	ReportID   string `json:"report_id"`
	AgentID    string `json:"agent_id"`
	AgentName  string `json:"agent_name"`
	Mode       string `json:"mode"`
	DestHost   string `json:"dest_host"`
	DestIP     string `json:"dest_ip,omitempty"`
	Port       int    `json:"port,omitempty"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Reached    bool   `json:"reached"`
	ReachedTTL int    `json:"reached_ttl,omitempty"`
	// TriggerReason/TriggerStreak/FirstFailedAt say WHY the Agent traced. Nothing
	// server-side asked for the report, so without them it reads as an execution
	// that appeared from nowhere; with them the console can say "the Agent traced
	// this after 3 consecutive failures starting at 14:02".
	TriggerReason string     `json:"trigger_reason,omitempty"`
	TriggerStreak int        `json:"trigger_streak,omitempty"`
	FirstFailedAt *time.Time `json:"first_failed_at,omitempty"`
	// FallbackFrom/FallbackReason surface a derivation-time permission fallback:
	// the report ran in Mode after being downgraded from FallbackFrom ('' when
	// it ran in its natural mode), because of FallbackReason.
	FallbackFrom   string `json:"fallback_from,omitempty"`   // ''|'tcp' — the mode this report fell back from
	FallbackReason string `json:"fallback_reason,omitempty"` // 'raw_socket_unavailable'|'permission_denied'
	// SubjectKind names what DestHost is, which is not always the monitored target:
	// 'target'|'resolver'|'proxy'|'wg_endpoint'|'stun_server'. SubjectReason
	// qualifies a WireGuard trace ('tunnel_unreachable' = the probe never
	// crossed the tunnel; 'tunnel_target_unreachable' = it did and the target
	// failed beyond it). Without these a resolver trace and a target trace read
	// identically.
	SubjectKind   string `json:"subject_kind"`
	SubjectReason string `json:"subject_reason,omitempty"`
	// PathScope says which path the hops describe, orthogonal to the subject:
	// 'direct'|'wireguard_physical'|'wireguard_inner'. An in-tunnel report
	// carries the egress generation it ran through in EgressID/EgressConfigSerial
	// ('' / 0 on every host-stack report) — without the scope, in-tunnel hops and
	// host-stack hops toward the same address would render identically.
	PathScope          string     `json:"path_scope"`
	EgressID           string     `json:"egress_id,omitempty"`
	EgressConfigSerial int        `json:"egress_config_serial,omitempty"`
	ActiveRefs         int        `json:"active_refs"`
	StartedAt          *time.Time `json:"started_at"`
	CompletedAt        *time.Time `json:"completed_at"`
	// ReceivedAt is this server's clock when the report arrived, which can be far
	// later than CompletedAt: a trace collected during an outage waits in the
	// Agent's outbox until the link comes back, which is the whole point of
	// sending it that way.
	ReceivedAt time.Time `json:"received_at"`
}

// TracesForIncident returns the traceroute reports referenced by an incident,
// each summarized with the incident's active-reference count against it.
func (s *Service) TracesForIncident(ctx context.Context, incidentID string) ([]TraceSummary, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT tr.id, tr.agent_id, COALESCE(tr.agent_name,''), tr.mode, tr.dest_host, COALESCE(tr.dest_ip,''),
		       tr.port, tr.status, COALESCE(tr.reason,''), tr.reached, tr.reached_ttl,
		       COALESCE(tr.trigger_reason,''), tr.trigger_streak, tr.first_failed_at,
		       COALESCE(tr.fallback_from,''), COALESCE(tr.fallback_reason,''),
		       COALESCE(tr.subject_kind,''), COALESCE(tr.subject_reason,''),
		       tr.path_scope, tr.egress_id, tr.egress_config_serial,
		       (SELECT COUNT(*) FROM trace_report_refs r2 WHERE r2.report_id=tr.id AND r2.incident_id=? AND r2.active=1),
		       tr.started_at, tr.completed_at, tr.received_at
		FROM trace_reports tr
		WHERE tr.id IN (SELECT DISTINCT report_id FROM trace_report_refs WHERE incident_id=?)
		ORDER BY tr.received_at DESC`, incidentID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TraceSummary{}
	for rows.Next() {
		t, err := scanTraceSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanTraceSummary(rows *sql.Rows) (TraceSummary, error) {
	var t TraceSummary
	var reached int
	var started, completed, firstFailed sql.NullTime
	if err := rows.Scan(&t.ReportID, &t.AgentID, &t.AgentName, &t.Mode, &t.DestHost, &t.DestIP,
		&t.Port, &t.Status, &t.Reason, &reached, &t.ReachedTTL,
		&t.TriggerReason, &t.TriggerStreak, &firstFailed,
		&t.FallbackFrom, &t.FallbackReason,
		&t.SubjectKind, &t.SubjectReason,
		&t.PathScope, &t.EgressID, &t.EgressConfigSerial,
		&t.ActiveRefs, &started, &completed, &t.ReceivedAt); err != nil {
		return TraceSummary{}, err
	}
	t.Reached = reached == 1
	t.StartedAt = timePtr(started)
	t.CompletedAt = timePtr(completed)
	t.FirstFailedAt = timePtr(firstFailed)
	return t, nil
}

// TraceReportView is a full shared traceroute report with its per-attempt hops,
// read by report id so every referencing incident sees the same execution.
type TraceReportView struct {
	TraceSummary
	Hops []TraceHopView `json:"hops"`
}

// TraceHopView is one TTL's per-attempt responses.
type TraceHopView struct {
	TTL      int                `json:"ttl"`
	Attempts []TraceAttemptView `json:"attempts"`
}

// TraceAttemptView is one probe attempt at a hop.
type TraceAttemptView struct {
	Attempt  int     `json:"attempt"`
	Addr     string  `json:"addr,omitempty"`
	Hostname string  `json:"hostname,omitempty"`
	RTTMs    float64 `json:"rtt_ms,omitempty"`
	Timeout  bool    `json:"timeout"`
}

// TraceReport returns one report and all its hops, or ok=false when unknown. The
// returned site id lets the API enforce site ownership.
func (s *Service) TraceReport(ctx context.Context, reportID string) (TraceReportView, string, bool, error) {
	var v TraceReportView
	var siteID string
	var reached int
	var started, completed, firstFailed sql.NullTime
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT id, site_id, agent_id, COALESCE(agent_name,''), mode, dest_host, COALESCE(dest_ip,''), port,
		       status, COALESCE(reason,''), reached, reached_ttl,
		       COALESCE(trigger_reason,''), trigger_streak, first_failed_at,
		       COALESCE(fallback_from,''), COALESCE(fallback_reason,''),
		       COALESCE(subject_kind,''), COALESCE(subject_reason,''),
		       path_scope, egress_id, egress_config_serial,
		       started_at, completed_at, received_at
		FROM trace_reports WHERE id=?`, reportID).
		Scan(&v.ReportID, &siteID, &v.AgentID, &v.AgentName, &v.Mode, &v.DestHost, &v.DestIP, &v.Port,
			&v.Status, &v.Reason, &reached, &v.ReachedTTL,
			&v.TriggerReason, &v.TriggerStreak, &firstFailed,
			&v.FallbackFrom, &v.FallbackReason,
			&v.SubjectKind, &v.SubjectReason,
			&v.PathScope, &v.EgressID, &v.EgressConfigSerial,
			&started, &completed, &v.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TraceReportView{}, "", false, nil
	}
	if err != nil {
		return TraceReportView{}, "", false, err
	}
	v.Reached = reached == 1
	v.StartedAt = timePtr(started)
	v.CompletedAt = timePtr(completed)
	v.FirstFailedAt = timePtr(firstFailed)

	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT ttl, attempt, COALESCE(addr,''), COALESCE(hostname,''), rtt_us, timed_out
		 FROM trace_hops WHERE report_id=? ORDER BY ttl, attempt`, reportID)
	if err != nil {
		return TraceReportView{}, "", false, err
	}
	defer rows.Close()
	v.Hops = []TraceHopView{}
	byTTL := map[int]*TraceHopView{}
	for rows.Next() {
		var ttl, attempt, timedOut int
		var addr, hostname string
		var rttUS sql.NullInt64
		if err := rows.Scan(&ttl, &attempt, &addr, &hostname, &rttUS, &timedOut); err != nil {
			return TraceReportView{}, "", false, err
		}
		h := byTTL[ttl]
		if h == nil {
			v.Hops = append(v.Hops, TraceHopView{TTL: ttl})
			h = &v.Hops[len(v.Hops)-1]
			byTTL[ttl] = h
		}
		a := TraceAttemptView{Attempt: attempt, Addr: addr, Hostname: hostname, Timeout: timedOut == 1}
		if rttUS.Valid {
			a.RTTMs = float64(rttUS.Int64) / 1000
		}
		h.Attempts = append(h.Attempts, a)
	}
	if err := rows.Err(); err != nil {
		return TraceReportView{}, "", false, err
	}
	return v, siteID, true, nil
}
