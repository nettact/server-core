// Package inventory reads discovered devices/interfaces (written by ingest from
// agent inventory deltas and interface snapshots). M3 exposes site device
// discovery from ARP; interfaces carry per-adapter Wi-Fi status.
package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
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

// WiFiCollection is the collection-level Wi-Fi verdict for an agent (from the
// latest InterfaceSnapshot). Stale is computed by the API handler from SampledAt
// and the agent's effective regular interval.
type WiFiCollection struct {
	State     string     `json:"state"`
	Reason    string     `json:"reason,omitempty"`
	SampledAt *time.Time `json:"sampled_at"`
	Stale     bool       `json:"stale"`
}

// InterfaceWiFi is one wireless adapter's current status on an interface row.
// InterfaceWiFi is one wireless adapter's current status on an interface row.
// The numeric fields are the current-round readings (nil when the driver omitted
// them this round or the adapter is not connected) — never an older round's value.
type InterfaceWiFi struct {
	State      string   `json:"state"`
	Reason     string   `json:"reason,omitempty"`
	SSID       string   `json:"ssid,omitempty"`
	Band       string   `json:"band,omitempty"`
	Channel    int      `json:"channel,omitempty"`
	SignalDBm  *int     `json:"signal_dbm"`
	QualityPct *int     `json:"quality_pct"`
	RxMbps     *float64 `json:"rx_mbps"`
	TxMbps     *float64 `json:"tx_mbps"`
}

// Interface is one network interface row (wired rows have WiFi == nil).
type Interface struct {
	Name       string         `json:"name"`
	Addrs      []string       `json:"addrs"`
	Gateway    string         `json:"gateway,omitempty"`
	DNS        []string       `json:"dns"`
	Up         bool           `json:"up"`
	IsWireless bool           `json:"is_wireless"`
	UpdatedAt  *time.Time     `json:"updated_at"`
	WiFi       *InterfaceWiFi `json:"wifi,omitempty"`
}

// ListInterfaces returns the agent's collection-level Wi-Fi state (Stale left
// unset for the caller to compute) and its interface rows, ordered by name.
func (s *Service) ListInterfaces(ctx context.Context, agentID string) (WiFiCollection, []Interface, error) {
	var col WiFiCollection
	var reason sql.NullString
	var sampled sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT state, reason, sampled_at FROM agent_wifi WHERE agent_id=?`, agentID).
		Scan(&col.State, &reason, &sampled)
	if err != nil && err != sql.ErrNoRows {
		return col, nil, err
	}
	if reason.Valid {
		col.Reason = reason.String
	}
	if sampled.Valid {
		t := sampled.Time
		col.SampledAt = &t
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT name, COALESCE(addrs,''), COALESCE(gateway,''), COALESCE(dns,''),
			COALESCE(up,0), COALESCE(is_wireless,0), updated_at,
			wifi_state, wifi_reason, wifi_ssid, wifi_band, wifi_channel,
			wifi_signal_dbm, wifi_quality_pct, wifi_rx_mbps, wifi_tx_mbps
		FROM interfaces WHERE agent_id=? ORDER BY name`, agentID)
	if err != nil {
		return col, nil, err
	}
	defer rows.Close()
	var out []Interface
	for rows.Next() {
		var ifc Interface
		var addrs, dns string
		var up, isw int
		var updated sql.NullTime
		var wState, wReason, wSSID, wBand sql.NullString
		var wChannel, wSignal, wQuality sql.NullInt64
		var wRx, wTx sql.NullFloat64
		if err := rows.Scan(&ifc.Name, &addrs, &ifc.Gateway, &dns, &up, &isw, &updated,
			&wState, &wReason, &wSSID, &wBand, &wChannel,
			&wSignal, &wQuality, &wRx, &wTx); err != nil {
			return col, nil, err
		}
		ifc.Up = up != 0
		ifc.IsWireless = isw != 0
		ifc.Addrs = decodeSlice(addrs)
		ifc.DNS = decodeSlice(dns)
		if updated.Valid {
			t := updated.Time
			ifc.UpdatedAt = &t
		}
		if wState.Valid {
			w := &InterfaceWiFi{State: wState.String}
			if wReason.Valid {
				w.Reason = wReason.String
			}
			if wSSID.Valid {
				w.SSID = wSSID.String
			}
			if wBand.Valid {
				w.Band = wBand.String
			}
			if wChannel.Valid {
				w.Channel = int(wChannel.Int64)
			}
			if wSignal.Valid {
				v := int(wSignal.Int64)
				w.SignalDBm = &v
			}
			if wQuality.Valid {
				v := int(wQuality.Int64)
				w.QualityPct = &v
			}
			if wRx.Valid {
				v := wRx.Float64
				w.RxMbps = &v
			}
			if wTx.Valid {
				v := wTx.Float64
				w.TxMbps = &v
			}
			ifc.WiFi = w
		}
		out = append(out, ifc)
	}
	return col, out, rows.Err()
}

func decodeSlice(s string) []string {
	if s == "" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return []string{}
	}
	return out
}
