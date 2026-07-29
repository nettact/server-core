package incident

import (
	"context"
	"database/sql"
	"time"
)

// The read model over alert_storms (ALERT-001). Storms are written by the
// notification-policy layer, which owns the decision to collapse a burst of
// simultaneous faults into one announcement; this side only reports them, so the
// fault centre can show the burst as one event instead of N unrelated rows.
//
// A storm never hides an incident. Every member is still listed, still
// filterable, still has its own detail and evidence — the storm is a heading
// over them, not a replacement for them.

// Storm is one correlated burst with its live member counts.
type Storm struct {
	ID             string     `json:"id"`
	SiteID         string     `json:"site_id"`
	AgentID        string     `json:"agent_id"`
	AgentName      string     `json:"agent_name"`
	State          string     `json:"state"`
	Severity       string     `json:"severity"`
	SuspectedLayer string     `json:"suspected_layer"`
	FaultCount     int        `json:"fault_count"`
	OpenFaultCount int        `json:"open_fault_count"`
	GroupCount     int        `json:"group_count"`
	NotifiedCount  int        `json:"notified_count"`
	PendingNotify  int        `json:"pending_notify_count"`
	OpenedAt       time.Time  `json:"opened_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
}

const stormCols = `st.id, st.site_id, st.agent_id, COALESCE(st.agent_name,''), st.state,
	st.severity, COALESCE(st.suspected_layer,''), st.opened_at, st.resolved_at,
	(SELECT COUNT(*) FROM incidents i WHERE i.storm_id=st.id),
	(SELECT COUNT(*) FROM incidents i WHERE i.storm_id=st.id AND i.state='open'),
	(SELECT COUNT(DISTINCT i.group_id) FROM incidents i WHERE i.storm_id=st.id),
	(SELECT COUNT(*) FROM notification_deliveries nd WHERE nd.storm_id=st.id AND nd.status='sent'),
	(SELECT COUNT(*) FROM notification_deliveries nd WHERE nd.storm_id=st.id AND nd.status='pending')`

// OpenStorms returns a site's currently-running storms, worst first.
//
// It is deliberately NOT filtered by whatever narrowing the incident list is
// under: the banner answers "is there one thing going on right now", which must
// not change because the reader narrowed the table below it — the same reason
// the overview counters are unfiltered.
func (s *Service) OpenStorms(ctx context.Context, siteID string) ([]Storm, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT `+stormCols+` FROM alert_storms st
		 WHERE st.site_id=? AND st.state='open' ORDER BY st.opened_at DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Storm{}
	for rows.Next() {
		st, err := scanStorm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// GetStorm returns one storm by id, open or resolved, so a deep link from a
// notification still resolves after the event is over.
func (s *Service) GetStorm(ctx context.Context, id string) (Storm, error) {
	row := s.db.Read().QueryRowContext(ctx, `SELECT `+stormCols+` FROM alert_storms st WHERE st.id=?`, id)
	return scanStorm(row)
}

func scanStorm(row scanner) (Storm, error) {
	var st Storm
	var resolved sql.NullTime
	if err := row.Scan(&st.ID, &st.SiteID, &st.AgentID, &st.AgentName, &st.State,
		&st.Severity, &st.SuspectedLayer, &st.OpenedAt, &resolved,
		&st.FaultCount, &st.OpenFaultCount, &st.GroupCount,
		&st.NotifiedCount, &st.PendingNotify); err != nil {
		return Storm{}, err
	}
	if resolved.Valid {
		t := resolved.Time.UTC()
		st.ResolvedAt = &t
	}
	st.OpenedAt = st.OpenedAt.UTC()
	return st, nil
}
