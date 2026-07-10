// Package inventory reads discovered devices/interfaces (written by ingest from
// agent inventory deltas). M3 exposes site device discovery from ARP.
package inventory

import (
	"context"
	"database/sql"
	"time"

	"github.com/nettact/server-core/store"
)

type Device struct {
	MAC       string     `json:"mac"`
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname"`
	Vendor    string     `json:"vendor"`
	FirstSeen *time.Time `json:"first_seen"`
	LastSeen  *time.Time `json:"last_seen"`
}

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

// ListDevices returns discovered devices for a site, most-recently-seen first.
func (s *Service) ListDevices(ctx context.Context, siteID string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT mac, COALESCE(ip,''), COALESCE(hostname,''), COALESCE(vendor,''), first_seen, last_seen
		FROM devices WHERE site_id=? ORDER BY last_seen DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var first, last sql.NullTime
		if err := rows.Scan(&d.MAC, &d.IP, &d.Hostname, &d.Vendor, &first, &last); err != nil {
			return nil, err
		}
		if first.Valid {
			t := first.Time
			d.FirstSeen = &t
		}
		if last.Valid {
			t := last.Time
			d.LastSeen = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
