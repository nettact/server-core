package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nettact/server-core/fault"

	"github.com/nettact/server-core/store"
)

// System-status thresholds are server-side semantics in exactly the sense
// probe_detection_settings is: they change when the server calls a machine
// overloaded, never what the Agent reports or how often. So they live in their
// own table, do NOT bump the site config serial and do NOT re-push DesiredState
// — an operator raising a CPU threshold must not restart every Agent's schedule.
//
// What an edit does do is invalidate the current streak. Four minutes spent above
// 90% says nothing about a threshold of 95%, so the edit terminates any firing
// system-status signal as a configuration change and clears the detectors'
// counters; the next reading starts a clean streak under the new rule.

// HostFamilyPct is one percentage-threshold family (CPU, memory) as the API
// exchanges it.
type HostFamilyPct struct {
	Enabled bool    `json:"enabled"`
	Pct     float64 `json:"pct"`
	// DurationS is how long the reading must stay at or above Pct before a fault
	// is confirmed, in seconds. Stored as a duration rather than a round count so
	// it keeps its meaning independent of the collection cadence.
	DurationS int `json:"duration_s"`
}

// HostFamilyLoad is the load family, whose threshold is per logical core so one
// setting can be applied to machines of different sizes.
type HostFamilyLoad struct {
	Enabled   bool    `json:"enabled"`
	PerCore   float64 `json:"per_core"`
	DurationS int     `json:"duration_s"`
}

// HostFamilyNet is the network family. Each direction is independent and either
// may be null, which is how one-directional alerting is expressed — a home link's
// upstream saturates long before its downstream does.
type HostFamilyNet struct {
	Enabled   bool     `json:"enabled"`
	RxMbps    *float64 `json:"rx_mbps"`
	TxMbps    *float64 `json:"tx_mbps"`
	DurationS int      `json:"duration_s"`
}

// HostFamilyDisk is the disk family. It covers every mount the Agent reports and
// carries no duration: a filling disk is not a spike, so waiting out a window
// would only delay the same verdict.
type HostFamilyDisk struct {
	Enabled bool    `json:"enabled"`
	Pct     float64 `json:"pct"`
}

// HostDetection is one host anchor's system-status thresholds.
type HostDetection struct {
	TargetID string `json:"target_id"`
	// SiteID is carried so a caller can act on the anchor's site without a second
	// lookup — the permission reevaluation an edit triggers is site-scoped.
	SiteID   string         `json:"site_id"`
	CPU      HostFamilyPct  `json:"cpu"`
	Mem      HostFamilyPct  `json:"mem"`
	Load     HostFamilyLoad `json:"load"`
	Net      HostFamilyNet  `json:"net"`
	Disk     HostFamilyDisk `json:"disk"`
	Revision int            `json:"revision"`
	// UpdatedAt is absent while the anchor still runs on the defaults, which is
	// how the console tells "never configured" from "configured to the defaults".
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// nullableFloat distinguishes the three states a threshold field can arrive in:
// absent (keep what is stored), JSON null (clear this direction) and a number
// (set it).
//
// It exists because pointers cannot express that. encoding/json writes nil into a
// *float64 — and into a **float64 — for BOTH an absent key and an explicit null,
// so a patch that means "stop alerting on uploads" is indistinguishable from one
// that never mentioned uploads, and clearing a direction becomes impossible
// through the API. Presence is therefore recorded by the unmarshaler, which runs
// only when the key is actually there.
type nullableFloat struct {
	Set   bool     // the key was present in the body
	Value *float64 // nil when that value was JSON null
}

func (n *nullableFloat) UnmarshalJSON(b []byte) error {
	n.Set = true
	if string(b) == "null" {
		n.Value = nil
		return nil
	}
	var v float64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	n.Value = &v
	return nil
}

// HostDetectionPatch is a partial update. Every family and every field within it
// is optional, so an omitted one keeps its stored value rather than being reset
// to a zero the caller never sent.
type HostDetectionPatch struct {
	CPU *struct {
		Enabled   *bool    `json:"enabled"`
		Pct       *float64 `json:"pct"`
		DurationS *int     `json:"duration_s"`
	} `json:"cpu"`
	Mem *struct {
		Enabled   *bool    `json:"enabled"`
		Pct       *float64 `json:"pct"`
		DurationS *int     `json:"duration_s"`
	} `json:"mem"`
	Load *struct {
		Enabled   *bool    `json:"enabled"`
		PerCore   *float64 `json:"per_core"`
		DurationS *int     `json:"duration_s"`
	} `json:"load"`
	Net *struct {
		Enabled *bool `json:"enabled"`
		// A present-but-null direction clears that threshold, which is the only way
		// to say "stop alerting on uploads but keep alerting on downloads".
		RxMbps    nullableFloat `json:"rx_mbps"`
		TxMbps    nullableFloat `json:"tx_mbps"`
		DurationS *int          `json:"duration_s"`
	} `json:"net"`
	Disk *struct {
		Enabled *bool    `json:"enabled"`
		Pct     *float64 `json:"pct"`
	} `json:"disk"`
}

// hostDetectionFrom renders the engine's settings shape as the API's.
func hostDetectionFrom(targetID, siteID string, s fault.HostSettings) HostDetection {
	out := HostDetection{
		TargetID: targetID, SiteID: siteID,
		CPU:      HostFamilyPct{Enabled: s.CPUEnabled, Pct: s.CPUPct, DurationS: s.CPUDurationS},
		Mem:      HostFamilyPct{Enabled: s.MemEnabled, Pct: s.MemPct, DurationS: s.MemDurationS},
		Load:     HostFamilyLoad{Enabled: s.LoadEnabled, PerCore: s.LoadPerCore, DurationS: s.LoadDurationS},
		Net:      HostFamilyNet{Enabled: s.NetEnabled, DurationS: s.NetDurationS},
		Disk:     HostFamilyDisk{Enabled: s.DiskEnabled, Pct: s.DiskPct},
		Revision: s.Revision,
	}
	if s.NetRxMbps > 0 {
		v := s.NetRxMbps
		out.Net.RxMbps = &v
	}
	if s.NetTxMbps > 0 {
		v := s.NetTxMbps
		out.Net.TxMbps = &v
	}
	return out
}

// GetHostDetection returns a host anchor's thresholds, falling back to the
// zero-config defaults when it has never been tuned. Returns sql.ErrNoRows when
// the target does not exist, and an error when it is not a host anchor.
func (s *Service) GetHostDetection(ctx context.Context, targetID string) (HostDetection, error) {
	var kind, siteID string
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT kind, site_id FROM probe_tasks WHERE id=?`, targetID).Scan(&kind, &siteID); err != nil {
		return HostDetection{}, err
	}
	if kind != "host" {
		return HostDetection{}, fmt.Errorf("target %s is not a host monitor", targetID)
	}
	set, updated, err := readHostSettings(ctx, s.db.Read(), targetID)
	if err != nil {
		return HostDetection{}, err
	}
	out := hostDetectionFrom(targetID, siteID, set)
	out.UpdatedAt = updated
	return out, nil
}

// readHostSettings loads a stored row, or the defaults when there is none.
func readHostSettings(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, targetID string) (fault.HostSettings, *time.Time, error) {
	set := fault.DefaultHostSettings()
	var cpuOn, memOn, loadOn, netOn, diskOn int
	var rx, tx sql.NullFloat64
	var updated sql.NullTime
	err := q.QueryRowContext(ctx, `
		SELECT cpu_enabled, cpu_pct, cpu_duration_s,
		       mem_enabled, mem_pct, mem_duration_s,
		       load_enabled, load_per_core, load_duration_s,
		       net_enabled, net_rx_mbps, net_tx_mbps, net_duration_s,
		       disk_enabled, disk_pct, revision, updated_at
		FROM host_detection_settings WHERE target_id=?`, targetID).
		Scan(&cpuOn, &set.CPUPct, &set.CPUDurationS,
			&memOn, &set.MemPct, &set.MemDurationS,
			&loadOn, &set.LoadPerCore, &set.LoadDurationS,
			&netOn, &rx, &tx, &set.NetDurationS,
			&diskOn, &set.DiskPct, &set.Revision, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.DefaultHostSettings(), nil, nil
	}
	if err != nil {
		return fault.HostSettings{}, nil, err
	}
	set.CPUEnabled, set.MemEnabled = cpuOn != 0, memOn != 0
	set.LoadEnabled, set.NetEnabled, set.DiskEnabled = loadOn != 0, netOn != 0, diskOn != 0
	set.NetRxMbps, set.NetTxMbps = rx.Float64, tx.Float64
	var at *time.Time
	if updated.Valid {
		t := updated.Time.UTC()
		at = &t
	}
	return set, at, nil
}

// UpdateHostDetection applies a partial threshold update, terminates the anchor's
// firing system-status signals as a configuration change and clears its detector
// counters, all in one transaction.
func (s *Service) UpdateHostDetection(ctx context.Context, targetID string, p HostDetectionPatch) (HostDetection, error) {
	var (
		siteID, kind string
		set          fault.HostSettings
		now          = time.Now().UTC()
	)
	if err := s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		tx := wtx

		if err := tx.QueryRowContext(ctx,
			`SELECT site_id, kind FROM probe_tasks WHERE id=?`, targetID).Scan(&siteID, &kind); err != nil {
			return nil, err
		}
		if kind != "host" {
			return nil, fmt.Errorf("target %s is not a host monitor", targetID)
		}
		var err error
		set, _, err = readHostSettings(ctx, tx, targetID)
		if err != nil {
			return nil, err
		}
		if err := validateHostPatch(p); err != nil {
			return nil, err
		}
		applyHostPatch(&set, p)
		if err := validateHostSettings(set); err != nil {
			return nil, err
		}

		b := func(v bool) int {
			if v {
				return 1
			}
			return 0
		}
		nullable := func(v float64) any {
			if v > 0 {
				return v
			}
			return nil
		}
		// The defaults are revision 1, so the first STORED edit has to be 2 or it would
		// be indistinguishable from them — and a streak pinned to the defaults could
		// then be continued under a threshold that replaced them.
		if _, err := tx.ExecContext(ctx, `
		INSERT INTO host_detection_settings(target_id, cpu_enabled, cpu_pct, cpu_duration_s,
		    mem_enabled, mem_pct, mem_duration_s, load_enabled, load_per_core, load_duration_s,
		    net_enabled, net_rx_mbps, net_tx_mbps, net_duration_s, disk_enabled, disk_pct,
		    revision, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,2,?)
		ON CONFLICT(target_id) DO UPDATE SET
		  cpu_enabled=excluded.cpu_enabled, cpu_pct=excluded.cpu_pct, cpu_duration_s=excluded.cpu_duration_s,
		  mem_enabled=excluded.mem_enabled, mem_pct=excluded.mem_pct, mem_duration_s=excluded.mem_duration_s,
		  load_enabled=excluded.load_enabled, load_per_core=excluded.load_per_core,
		  load_duration_s=excluded.load_duration_s,
		  net_enabled=excluded.net_enabled, net_rx_mbps=excluded.net_rx_mbps,
		  net_tx_mbps=excluded.net_tx_mbps, net_duration_s=excluded.net_duration_s,
		  disk_enabled=excluded.disk_enabled, disk_pct=excluded.disk_pct,
		  revision=host_detection_settings.revision+1, updated_at=excluded.updated_at`,
			targetID, b(set.CPUEnabled), set.CPUPct, set.CPUDurationS,
			b(set.MemEnabled), set.MemPct, set.MemDurationS,
			b(set.LoadEnabled), set.LoadPerCore, set.LoadDurationS,
			b(set.NetEnabled), nullable(set.NetRxMbps), nullable(set.NetTxMbps), set.NetDurationS,
			b(set.DiskEnabled), set.DiskPct, now); err != nil {
			return nil, err
		}

		var termPub PostCommit
		if s.term != nil {
			_, pub, err := s.term.TerminateForTargetsTx(ctx, tx, []string{targetID}, ReasonConfigChanged)
			if err != nil {
				return nil, err
			}
			termPub = pub
			if err := s.term.ClearDetectorStateTx(ctx, tx, []string{targetID}); err != nil {
				return nil, err
			}
		}

		if err := tx.QueryRowContext(ctx,
			`SELECT revision FROM host_detection_settings WHERE target_id=?`, targetID).Scan(&set.Revision); err != nil {
			return nil, err
		}
		return func() {
			if termPub != nil {
				termPub(ctx)
			}
			s.publishTargetStatus(siteID, []string{targetID})
		}, nil
	}); err != nil {
		return HostDetection{}, err
	}

	out := hostDetectionFrom(targetID, siteID, set)
	out.UpdatedAt = &now
	return out, nil
}

// applyHostPatch folds a partial update into the stored settings.
func applyHostPatch(set *fault.HostSettings, p HostDetectionPatch) {
	if c := p.CPU; c != nil {
		setBool(&set.CPUEnabled, c.Enabled)
		setFloat(&set.CPUPct, c.Pct)
		setInt(&set.CPUDurationS, c.DurationS)
	}
	if m := p.Mem; m != nil {
		setBool(&set.MemEnabled, m.Enabled)
		setFloat(&set.MemPct, m.Pct)
		setInt(&set.MemDurationS, m.DurationS)
	}
	if l := p.Load; l != nil {
		setBool(&set.LoadEnabled, l.Enabled)
		setFloat(&set.LoadPerCore, l.PerCore)
		setInt(&set.LoadDurationS, l.DurationS)
	}
	if n := p.Net; n != nil {
		setBool(&set.NetEnabled, n.Enabled)
		setInt(&set.NetDurationS, n.DurationS)
		if n.RxMbps.Set {
			set.NetRxMbps = derefOrZero(n.RxMbps.Value)
		}
		if n.TxMbps.Set {
			set.NetTxMbps = derefOrZero(n.TxMbps.Value)
		}
	}
	if d := p.Disk; d != nil {
		setBool(&set.DiskEnabled, d.Enabled)
		setFloat(&set.DiskPct, d.Pct)
	}
}

func setBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

func setFloat(dst *float64, src *float64) {
	if src != nil {
		*dst = *src
	}
}

func setInt(dst *int, src *int) {
	if src != nil {
		*dst = *src
	}
}

// derefOrZero turns a present-but-null threshold into 0, the engine's "this
// direction is not alerted" value.
func derefOrZero(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// validateHostPatch checks what the REQUEST said, before it is folded into the
// stored settings. One thing can only be caught here: a numeric 0 for a network
// direction. Zero is the engine's internal "this direction is unset" value, so by
// the time the patch has been applied it is indistinguishable from an explicit
// null — and the caller would be told their "0 Mbps" threshold was accepted while
// it had in fact silently switched that direction off. Clearing is spelled null.
func validateHostPatch(p HostDetectionPatch) error {
	if p.Net == nil {
		return nil
	}
	for _, f := range []struct {
		name string
		v    nullableFloat
	}{{"net.rx_mbps", p.Net.RxMbps}, {"net.tx_mbps", p.Net.TxMbps}} {
		if f.v.Set && f.v.Value != nil && *f.v.Value <= 0 {
			return fmt.Errorf("%s must be greater than 0 (send null to stop watching that direction)", f.name)
		}
	}
	return nil
}

// validateHostSettings rejects an out-of-range request rather than clamping it:
// silently storing 90 when the caller asked for 900 would leave them believing
// the machine is watched far more loosely than it is.
func validateHostSettings(s fault.HostSettings) error {
	for _, f := range []struct {
		name string
		pct  float64
	}{{"cpu.pct", s.CPUPct}, {"mem.pct", s.MemPct}, {"disk.pct", s.DiskPct}} {
		if !(f.pct > 0) || f.pct > 100 {
			return fmt.Errorf("%s must be greater than 0 and at most 100", f.name)
		}
	}
	if !(s.LoadPerCore > 0) || s.LoadPerCore > 100 {
		return fmt.Errorf("load.per_core must be greater than 0 and at most 100")
	}
	for _, f := range []struct {
		name string
		secs int
	}{{"cpu.duration_s", s.CPUDurationS}, {"mem.duration_s", s.MemDurationS},
		{"load.duration_s", s.LoadDurationS}, {"net.duration_s", s.NetDurationS}} {
		if f.secs < 30 || f.secs > 3600 {
			return fmt.Errorf("%s must be between 30 and 3600", f.name)
		}
	}
	if s.NetRxMbps < 0 || s.NetTxMbps < 0 {
		return fmt.Errorf("net.rx_mbps and net.tx_mbps must be greater than 0")
	}
	// Enabling the family with neither direction set would be an alert that can
	// never fire — a state the console would render as "on" and the engine would
	// treat as off, which is the worst kind of disagreement to leave storable.
	if s.NetEnabled && s.NetRxMbps == 0 && s.NetTxMbps == 0 {
		return fmt.Errorf("net alerting needs at least one of rx_mbps or tx_mbps")
	}
	return nil
}
