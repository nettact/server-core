// Package incident is the group-aware read model over the incident tables. The
// lifecycle write path (open / attach / recompute / resolve) lives in the fault
// engine (package fault), which owns the transaction that maintains incidents
// alongside their fault signals; this package serves the console reads: the
// filtered incident list behind the fault centre, member counts, timeline (with
// entity refs) and overview stats.
package incident

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/nettact/server-core/store"
)

// Incident is one incident with its frozen group identity and live member counts.
type Incident struct {
	ID                string `json:"id"`
	SiteID            string `json:"site_id"`
	GroupID           string `json:"group_id"`
	GroupName         string `json:"group_name"`
	Title             string `json:"title"`
	SuspectedLayer    string `json:"suspected_layer"`
	State             string `json:"state"`
	Severity          string `json:"severity"`
	Summary           string `json:"summary"`
	ResolveReason     string `json:"resolve_reason,omitempty"`
	EvidenceExpired   bool   `json:"evidence_expired"`
	SnapshotStatus    string `json:"snapshot_status"`
	TraceCount        int    `json:"trace_count"`
	MemberCount       int    `json:"member_count"`
	ActiveMemberCount int    `json:"active_member_count"`
	// NotifiedCount / PendingNotifyCount summarize the incident's notification
	// records, so the list can distinguish "announced", "waiting out its delay" and
	// "recorded only" without a second request per row.
	NotifiedCount      int        `json:"notified_count"`
	PendingNotifyCount int        `json:"pending_notify_count"`
	OpenedAt           time.Time  `json:"opened_at"`
	ResolvedAt         *time.Time `json:"resolved_at"`
}

// TimelineEntry is one incident timeline row, including the entity ref the fault
// engine populates (fault signal id / incident id).
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
	(SELECT COUNT(*) FROM fault_signals s WHERE s.incident_id=i.id),
	(SELECT COUNT(*) FROM fault_signals s WHERE s.incident_id=i.id AND s.state='firing'),
	COALESCE((SELECT status FROM incident_snapshots sn WHERE sn.incident_id=i.id),''),
	(SELECT COUNT(DISTINCT report_id) FROM trace_report_refs trr WHERE trr.incident_id=i.id),
	(SELECT COUNT(*) FROM notification_deliveries nd WHERE nd.incident_id=i.id AND nd.status='sent'),
	(SELECT COUNT(*) FROM notification_deliveries nd WHERE nd.incident_id=i.id AND nd.status='pending')`

// Filter narrows an incident listing for the fault centre. Zero values mean "no
// constraint", so the default listing is every incident newest-first.
type Filter struct {
	State     string // open | resolved
	Severity  string
	GroupID   string
	AgentID   string
	TargetID  string
	ProbeKind string // probe kind, or a detector key like agent_connectivity
	Query     string // free text over incident title/summary and member target/agent names
	Since     *time.Time
	Until     *time.Time
}

// where builds the filter's SQL predicate and arguments, correlated to the
// incidents row aliased "i".
func (f Filter) where(siteID string) (string, []any) {
	clauses := []string{"i.site_id=?"}
	args := []any{siteID}
	add := func(sql string, v ...any) {
		clauses = append(clauses, sql)
		args = append(args, v...)
	}
	switch f.State {
	case "open", "resolved":
		add("i.state=?", f.State)
	}
	if f.Severity != "" {
		add("i.severity=?", f.Severity)
	}
	if f.GroupID != "" {
		add("i.group_id=?", f.GroupID)
	}
	// Member-scoped filters go through EXISTS so an incident merging several
	// members matches when ANY member does, without duplicating the incident row.
	if f.AgentID != "" {
		add("EXISTS(SELECT 1 FROM fault_signals s WHERE s.incident_id=i.id AND s.agent_id=?)", f.AgentID)
	}
	if f.TargetID != "" {
		add("EXISTS(SELECT 1 FROM fault_signals s WHERE s.incident_id=i.id AND s.target_id=?)", f.TargetID)
	}
	if f.ProbeKind != "" {
		add(`EXISTS(SELECT 1 FROM fault_signals s WHERE s.incident_id=i.id
		       AND (s.probe_kind=? OR s.detector_key=?))`, f.ProbeKind, f.ProbeKind)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + q + "%"
		add(`(i.title LIKE ? OR i.summary LIKE ? OR EXISTS(
			SELECT 1 FROM fault_signals s WHERE s.incident_id=i.id
			  AND (s.target_name LIKE ? OR s.target_addr LIKE ? OR s.agent_name LIKE ?)))`,
			like, like, like, like, like)
	}
	if f.Since != nil {
		add("i.opened_at>=?", *f.Since)
	}
	if f.Until != nil {
		add("i.opened_at<?", *f.Until)
	}
	return strings.Join(clauses, " AND "), args
}

// List returns one page of a site's incidents matching the filter, newest first.
func (s *Service) List(ctx context.Context, siteID string, f Filter, limit, offset int) ([]Incident, error) {
	where, args := f.where(siteID)
	args = append(args, limit, offset)
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT `+incidentCols+` FROM incidents i WHERE `+where+` ORDER BY i.opened_at DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Incident{}
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

// Count returns how many incidents match the filter (for pagination).
func (s *Service) Count(ctx context.Context, siteID string, f Filter) (int, error) {
	where, args := f.where(siteID)
	var n int
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incidents i WHERE `+where, args...).Scan(&n)
	return n, err
}

// CountOpen returns the number of currently open incidents for a site. It backs
// the desktop tray badge, so the number a user sees there is the same object
// count the fault centre shows.
func (s *Service) CountOpen(ctx context.Context, siteID string) (int, error) {
	var n int
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incidents WHERE site_id=? AND state='open'`, siteID).Scan(&n)
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
		&inc.OpenedAt, &resolved, &inc.MemberCount, &inc.ActiveMemberCount, &inc.SnapshotStatus, &inc.TraceCount,
		&inc.NotifiedCount, &inc.PendingNotifyCount)
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
