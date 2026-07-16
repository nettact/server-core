// Package incident is the group-aware read model over the incident tables. The
// lifecycle write path (open / attach / recompute / resolve) lives in the fault
// engine (package rules), which owns the transaction that maintains incidents
// alongside alerts and evidence; this package serves the console reads: parallel
// incidents per site, member counts, timeline (with entity refs) and overview
// stats.
package incident

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nettact/server-core/store"
)

// Incident is one incident with its frozen group identity and live member counts.
type Incident struct {
	ID                string     `json:"id"`
	SiteID            string     `json:"site_id"`
	GroupID           string     `json:"group_id"`
	GroupName         string     `json:"group_name"`
	Title             string     `json:"title"`
	SuspectedLayer    string     `json:"suspected_layer"`
	State             string     `json:"state"`
	Severity          string     `json:"severity"`
	Summary           string     `json:"summary"`
	ResolveReason     string     `json:"resolve_reason,omitempty"`
	EvidenceExpired   bool       `json:"evidence_expired"`
	SnapshotStatus    string     `json:"snapshot_status"`
	TraceCount        int        `json:"trace_count"`
	MemberCount       int        `json:"member_count"`
	ActiveMemberCount int        `json:"active_member_count"`
	OpenedAt          time.Time  `json:"opened_at"`
	ResolvedAt        *time.Time `json:"resolved_at"`
}

// TimelineEntry is one incident timeline row, including the entity ref the fault
// engine now populates (alert id / incident id).
type TimelineEntry struct {
	TS      time.Time `json:"ts"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
	Ref     string    `json:"ref,omitempty"`
}

// Stats is the site-wide incident rollup used by the overview.
type Stats struct {
	Open        int    `json:"open"`
	Opened24h   int    `json:"opened_24h"`
	Resolved24h int    `json:"resolved_24h"`
	TopLayer    string `json:"top_layer"`
}

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

const incidentCols = `i.id, i.site_id, i.group_id, COALESCE(i.group_name,''), COALESCE(i.title,''),
	COALESCE(i.suspected_layer,''), i.state, i.severity, COALESCE(i.summary,''),
	COALESCE(i.resolve_reason,''), i.evidence_expired, i.opened_at, i.resolved_at,
	(SELECT COUNT(*) FROM alerts a WHERE a.incident_id=i.id),
	(SELECT COUNT(*) FROM alerts a WHERE a.incident_id=i.id AND a.state='firing'),
	COALESCE((SELECT status FROM incident_snapshots sn WHERE sn.incident_id=i.id),''),
	(SELECT COUNT(DISTINCT report_id) FROM trace_report_refs trr WHERE trr.incident_id=i.id)`

// List returns one page of a site's incidents, newest first.
func (s *Service) List(ctx context.Context, siteID string, limit, offset int) ([]Incident, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT `+incidentCols+` FROM incidents i WHERE i.site_id=? ORDER BY i.opened_at DESC LIMIT ? OFFSET ?`,
		siteID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

// Get returns one incident by id.
func (s *Service) Get(ctx context.Context, id string) (Incident, error) {
	row := s.db.Read().QueryRowContext(ctx, `SELECT `+incidentCols+` FROM incidents i WHERE i.id=?`, id)
	return scanIncident(row)
}

// Timeline returns an incident's timeline entries in chronological order.
func (s *Service) Timeline(ctx context.Context, incID string) ([]TimelineEntry, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT ts, kind, COALESCE(message,''), COALESCE(ref,'') FROM incident_timeline WHERE incident_id=? ORDER BY ts`, incID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelineEntry
	for rows.Next() {
		var e TimelineEntry
		if err := rows.Scan(&e.TS, &e.Kind, &e.Message, &e.Ref); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Count returns the total number of incidents for a site (for pagination).
func (s *Service) Count(ctx context.Context, siteID string) (int, error) {
	var n int
	err := s.db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE site_id=?`, siteID).Scan(&n)
	return n, err
}

// OverviewStats returns current and rolling-window incident counts plus the most
// common suspected layer.
func (s *Service) OverviewStats(ctx context.Context, siteID string, since time.Time) (Stats, error) {
	var st Stats
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN state='open' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN opened_at>=? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN resolved_at>=? THEN 1 ELSE 0 END), 0)
		FROM incidents WHERE site_id=?`, since, since, siteID).Scan(&st.Open, &st.Opened24h, &st.Resolved24h)
	if err != nil {
		return Stats{}, err
	}
	err = s.db.Read().QueryRowContext(ctx, `
		SELECT COALESCE(suspected_layer,'')
		FROM incidents
		WHERE site_id=? AND (state='open' OR opened_at>=?) AND COALESCE(suspected_layer,'')<>''
		GROUP BY suspected_layer
		ORDER BY COUNT(*) DESC, suspected_layer
		LIMIT 1`, siteID, since).Scan(&st.TopLayer)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return st, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanIncident(row scanner) (Incident, error) {
	var inc Incident
	var resolved sql.NullTime
	var evidenceExpired int
	err := row.Scan(&inc.ID, &inc.SiteID, &inc.GroupID, &inc.GroupName, &inc.Title, &inc.SuspectedLayer,
		&inc.State, &inc.Severity, &inc.Summary, &inc.ResolveReason, &evidenceExpired,
		&inc.OpenedAt, &resolved, &inc.MemberCount, &inc.ActiveMemberCount, &inc.SnapshotStatus, &inc.TraceCount)
	if err != nil {
		return Incident{}, err
	}
	inc.EvidenceExpired = evidenceExpired == 1
	if resolved.Valid {
		t := resolved.Time
		inc.ResolvedAt = &t
	}
	return inc, nil
}
