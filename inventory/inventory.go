// Package inventory reads discovered devices/interfaces (written by ingest from
// agent inventory deltas and interface snapshots). M3 exposes site device
// discovery from ARP; interfaces carry per-adapter Wi-Fi status.
//
// It also owns device retention (Retention), the only path that removes device
// rows: discovery itself is upsert-only, so age is the sole departure signal.
package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nettact/server-core/settings"
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
	db       *store.DB
	settings *settings.Service
}

// New takes the settings service for the retention windows. It may be nil, in
// which case retention falls back to the registered defaults.
func New(db *store.DB, st *settings.Service) *Service {
	return &Service{db: db, settings: st}
}

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

// randomMACDigits lists the second hex digit of every MAC whose first octet has
// the locally-administered bit (0x02) set — i.e. an address no vendor burned in.
// That bit is exactly what phones and laptops set when they synthesize a private
// MAC per Wi-Fi join, so it separates throwaway addresses from real hardware
// without a lookup table. MACs reach the DB from net.HardwareAddr.String() on
// every platform, so they are always lowercase "aa:bb:cc:dd:ee:ff"; lower() in
// the query guards the format rather than relying on it.
const randomMACDigits = `'2','3','6','7','a','b','e','f'`

// pruneDevicesSQL deletes by age with a per-row cutoff: randomized addresses get
// the first (narrower) cutoff, everything else the second. Building it from a
// constant is not string-built SQL in the injection sense — randomMACDigits is a
// compile-time literal and both cutoffs are bound parameters.
var pruneDevicesSQL = `
	DELETE FROM devices
	WHERE last_seen IS NOT NULL
	  AND last_seen < CASE
	        WHEN lower(substr(mac, 2, 1)) IN (` + randomMACDigits + `) THEN ?
	        ELSE ?
	      END`

// retentionWindows resolves the configured cutoffs. A zero master window means
// retention is off entirely (both returns are zero); a zero random window means
// "don't single out randomized MACs", so they age out on the master window. That
// asymmetry is deliberate: no single key set to 0 can leave throwaway addresses
// outliving real devices.
//
// The random window is also CLAMPED to the master window, which is what makes that
// guarantee hold for non-zero values too. Both keys pass their own generic bounds
// independently, so a 7-day master with a 30-day random window was accepted and left
// randomized addresses — the main driver of table growth — outliving the real devices
// they were supposed to age out ahead of. The knob only ever narrows.
func (s *Service) retentionWindows(ctx context.Context) (stable, random time.Duration) {
	days, _ := s.settings.Int(ctx, settings.KeyDeviceRetentionDays)
	if days <= 0 {
		return 0, 0
	}
	stable = time.Duration(days) * 24 * time.Hour
	randomDays, _ := s.settings.Int(ctx, settings.KeyDeviceRandomMACRetentionDays)
	if randomDays <= 0 || randomDays > days {
		return stable, stable
	}
	return stable, time.Duration(randomDays) * 24 * time.Hour
}

// Retention deletes devices that have not been seen within their configured
// window and reports how many rows went. Discovery is upsert-only — agents never
// report a departure and ingest ignores OpRemove — so this is the only thing that
// ever shrinks the devices table.
func (s *Service) Retention(ctx context.Context) (int64, error) {
	stable, random := s.retentionWindows(ctx)
	if stable <= 0 {
		return 0, nil
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, pruneDevicesSQL, now.Add(-random), now.Add(-stable))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
