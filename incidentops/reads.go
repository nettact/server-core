package incidentops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ---- snapshot reads ----

// SnapshotView is one incident's immutable snapshot for the console: the frozen
// server base plus every per-Agent scene entry with its collection status.
type SnapshotView struct {
	IncidentID string          `json:"incident_id"`
	Status     string          `json:"status"`
	Base       json.RawMessage `json:"base"`
	TotalBytes int             `json:"total_bytes"`
	Truncated  bool            `json:"truncated"`
	DeadlineAt time.Time       `json:"deadline_at"`
	CreatedAt  time.Time       `json:"created_at"`
	Entries    []SnapshotEntry `json:"entries"`
}

// SnapshotEntry is one Agent's scene-collection outcome and payload.
type SnapshotEntry struct {
	AgentID     string          `json:"agent_id"`
	AgentName   string          `json:"agent_name"`
	Status      string          `json:"status"`
	Reason      string          `json:"reason,omitempty"`
	ClockSkewMs int64           `json:"clock_skew_ms"`
	Skewed      bool            `json:"skewed"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	RequestedAt time.Time       `json:"requested_at"`
	ReceivedAt  *time.Time      `json:"received_at"`
}

// Snapshot returns an incident's snapshot with its entries, or ok=false when the
// incident has none yet.
func (s *Service) Snapshot(ctx context.Context, incidentID string) (SnapshotView, bool, error) {
	var v SnapshotView
	var snapID, base string
	var truncated int
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT id, status, COALESCE(base,''), total_bytes, truncated, deadline_at, created_at
		FROM incident_snapshots WHERE incident_id=?`, incidentID).
		Scan(&snapID, &v.Status, &base, &v.TotalBytes, &truncated, &v.DeadlineAt, &v.CreatedAt)
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
		SELECT agent_id, COALESCE(agent_name,''), status, COALESCE(reason,''), clock_skew_ms, skewed,
		       COALESCE(payload,''), requested_at, received_at
		FROM incident_snapshot_entries WHERE snapshot_id=? ORDER BY agent_id`, snapID)
	if err != nil {
		return SnapshotView{}, false, err
	}
	defer rows.Close()
	v.Entries = []SnapshotEntry{}
	for rows.Next() {
		var e SnapshotEntry
		var skewed int
		var payload string
		var received sql.NullTime
		if err := rows.Scan(&e.AgentID, &e.AgentName, &e.Status, &e.Reason, &e.ClockSkewMs, &skewed,
			&payload, &e.RequestedAt, &received); err != nil {
			return SnapshotView{}, false, err
		}
		e.Skewed = skewed == 1
		if payload != "" {
			e.Payload = json.RawMessage(payload)
		}
		e.ReceivedAt = timePtr(received)
		v.Entries = append(v.Entries, e)
	}
	return v, true, rows.Err()
}

// ---- trace reads ----

// TraceSummary is one traceroute report as referenced from an incident: the
// shared execution record's identity, status and reached verdict, plus how the
// incident references it (via which alerts/conditions, and whether still active).
type TraceSummary struct {
	ReportID    string     `json:"report_id"`
	AgentID     string     `json:"agent_id"`
	AgentName   string     `json:"agent_name"`
	Mode        string     `json:"mode"`
	DestHost    string     `json:"dest_host"`
	DestIP      string     `json:"dest_ip,omitempty"`
	Port        int        `json:"port,omitempty"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason,omitempty"`
	Reached     bool       `json:"reached"`
	ReachedTTL  int        `json:"reached_ttl,omitempty"`
	ActiveRefs  int        `json:"active_refs"`
	RequestedAt time.Time  `json:"requested_at"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	DeadlineAt  time.Time  `json:"deadline_at"`
}

// TracesForIncident returns the traceroute reports referenced by an incident,
// each summarized with the incident's active-reference count against it.
func (s *Service) TracesForIncident(ctx context.Context, incidentID string) ([]TraceSummary, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT tr.id, tr.agent_id, COALESCE(tr.agent_name,''), tr.mode, tr.dest_host, COALESCE(tr.dest_ip,''),
		       tr.port, tr.status, COALESCE(tr.reason,''), tr.reached, tr.reached_ttl,
		       (SELECT COUNT(*) FROM trace_report_refs r2 WHERE r2.report_id=tr.id AND r2.incident_id=? AND r2.active=1),
		       tr.requested_at, tr.started_at, tr.completed_at, tr.deadline_at
		FROM trace_reports tr
		WHERE tr.id IN (SELECT DISTINCT report_id FROM trace_report_refs WHERE incident_id=?)
		ORDER BY tr.requested_at DESC`, incidentID, incidentID)
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
	var started, completed sql.NullTime
	if err := rows.Scan(&t.ReportID, &t.AgentID, &t.AgentName, &t.Mode, &t.DestHost, &t.DestIP,
		&t.Port, &t.Status, &t.Reason, &reached, &t.ReachedTTL, &t.ActiveRefs,
		&t.RequestedAt, &started, &completed, &t.DeadlineAt); err != nil {
		return TraceSummary{}, err
	}
	t.Reached = reached == 1
	t.StartedAt = timePtr(started)
	t.CompletedAt = timePtr(completed)
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
	var started, completed sql.NullTime
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT id, site_id, agent_id, COALESCE(agent_name,''), mode, dest_host, COALESCE(dest_ip,''), port,
		       status, COALESCE(reason,''), reached, reached_ttl, requested_at, started_at, completed_at, deadline_at
		FROM trace_reports WHERE id=?`, reportID).
		Scan(&v.ReportID, &siteID, &v.AgentID, &v.AgentName, &v.Mode, &v.DestHost, &v.DestIP, &v.Port,
			&v.Status, &v.Reason, &reached, &v.ReachedTTL, &v.RequestedAt, &started, &completed, &v.DeadlineAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TraceReportView{}, "", false, nil
	}
	if err != nil {
		return TraceReportView{}, "", false, err
	}
	v.Reached = reached == 1
	v.StartedAt = timePtr(started)
	v.CompletedAt = timePtr(completed)

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
