// Package agentstatus is the read-time aggregation behind the Agent status list
// (AGENT-001). It fuses per-agent identity, group membership, liveness, firing
// rule alerts / operational issues (the "abnormal" reasons), the firing
// connectivity alert, and the latest host resource samples into one per-agent
// rollup, computing the single authoritative overall status so the API and UI
// can never drift. It is a pure reader: it never mutates state.
package agentstatus

import (
	"context"
	"database/sql"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// MetricsSource is the slice of the metrics store this package needs (the latest
// per-series snapshot for an agent). *metrics.Store satisfies it; tests inject a
// fake. May be nil, in which case resources are simply absent.
type MetricsSource interface {
	LatestSnapshot(ctx context.Context, agentID string, sinceUnix int64) ([]metrics.Point, error)
}

// Overall status values, highest severity first (also the sort priority).
const (
	StatusOffline        = "offline"
	StatusAbnormal       = "abnormal"
	StatusNeverConnected = "never_connected"
	StatusOK             = "ok"
)

type Service struct {
	db      *store.DB
	metrics MetricsSource
	set     *settings.Service
	now     func() time.Time
}

func New(db *store.DB, m MetricsSource, set *settings.Service) *Service {
	return &Service{db: db, metrics: m, set: set, now: time.Now}
}

// SiteAgentStatuses is the whole-site payload for GET /sites/{id}/agent-statuses.
type SiteAgentStatuses struct {
	GeneratedAt time.Time        `json:"generated_at"`
	SiteID      string           `json:"site_id"`
	Agents      []AgentStatusRow `json:"agents"`
}

type GroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ConnAlertRef struct {
	ID           string    `json:"id"`
	Reason       string    `json:"reason"`
	OpenedAt     time.Time `json:"opened_at"`
	OfflineSince time.Time `json:"offline_since"`
}

// ScalarSample is a single-valued resource reading with its unit + sampling time.
type ScalarSample struct {
	Value float64   `json:"value"`
	Unit  string    `json:"unit"`
	TS    time.Time `json:"ts"`
	Stale bool      `json:"stale"`
}

type MemSample struct {
	Pct   float64   `json:"pct"`
	Used  float64   `json:"used"`  // bytes
	Total float64   `json:"total"` // bytes
	TS    time.Time `json:"ts"`
	Stale bool      `json:"stale"`
}

type DiskSample struct {
	Pct    float64   `json:"pct"`
	Used   float64   `json:"used"`  // bytes
	Total  float64   `json:"total"` // bytes
	Mount  string    `json:"mount"` // worst mount (highest pct)
	Mounts int       `json:"mounts"`
	TS     time.Time `json:"ts"`
	Stale  bool      `json:"stale"`
}

type NetSample struct {
	RxBps float64   `json:"rx_bps"`
	TxBps float64   `json:"tx_bps"`
	TS    time.Time `json:"ts"`
	Stale bool      `json:"stale"`
}

// LoadSample is the system load average (1/5/15 minutes).
type LoadSample struct {
	Load1  float64   `json:"load1"`
	Load5  float64   `json:"load5"`
	Load15 float64   `json:"load15"`
	TS     time.Time `json:"ts"`
	Stale  bool      `json:"stale"`
}

// Resources are the host resource readings; a nil field means no data (the
// permission for that family is denied, or the agent has never reported it).
type Resources struct {
	CPU    *ScalarSample `json:"cpu"`
	Memory *MemSample    `json:"memory"`
	Disk   *DiskSample   `json:"disk"`
	Net    *NetSample    `json:"net"`
	Load   *LoadSample   `json:"load"`
	Uptime *ScalarSample `json:"uptime"` // host uptime, unit "s"
}

type AgentStatusRow struct {
	ID                      string        `json:"id"`
	DisplayName             string        `json:"display_name"`
	Hostname                string        `json:"hostname"`
	Platform                string        `json:"platform"`
	AgentVersion            string        `json:"agent_version"`
	Status                  string        `json:"status"`   // offline|abnormal|never_connected|ok
	Presence                string        `json:"presence"` // online|offline (raw registry status)
	StatusSince             *time.Time    `json:"status_since"`
	LastSeenAt              *time.Time    `json:"last_seen_at"`
	FirstConnectedAt        *time.Time    `json:"first_connected_at"`
	LastDisconnectKind      string        `json:"last_disconnect_kind"`
	ConnectivityAlertsMuted bool          `json:"connectivity_alerts_muted"`
	Groups                  []GroupRef    `json:"groups"`
	FiringAlerts            int           `json:"firing_alerts"`
	ActiveIssues            int           `json:"active_issues"`
	ConnectivityAlert       *ConnAlertRef `json:"connectivity_alert"`
	Resources               Resources     `json:"resources"`
	CreatedAt               time.Time     `json:"created_at"`
}

// SiteAgentStatuses assembles the per-agent rollup for a site. Reads run on the
// read pool + the metrics in-memory latest cache; nothing is mutated.
func (s *Service) SiteAgentStatuses(ctx context.Context, siteID string) (SiteAgentStatuses, error) {
	now := s.now()
	staleSec, _ := s.set.Int(ctx, settings.KeyAgentStatusStaleSeconds)
	staleCutoff := now.Add(-time.Duration(staleSec) * time.Second)

	rows, err := s.loadAgents(ctx, siteID)
	if err != nil {
		return SiteAgentStatuses{}, err
	}
	groups, err := s.loadGroups(ctx, siteID)
	if err != nil {
		return SiteAgentStatuses{}, err
	}
	firing, err := s.countByAgent(ctx, `SELECT agent_id, COUNT(*) FROM alerts WHERE site_id=? AND state='firing' GROUP BY agent_id`, siteID)
	if err != nil {
		return SiteAgentStatuses{}, err
	}
	issues, err := s.countByAgent(ctx, `SELECT agent_id, COUNT(*) FROM operational_issues WHERE site_id=? AND state='active' GROUP BY agent_id`, siteID)
	if err != nil {
		return SiteAgentStatuses{}, err
	}
	connAlerts, err := s.loadConnAlerts(ctx, siteID)
	if err != nil {
		return SiteAgentStatuses{}, err
	}
	statusSince, err := s.loadStatusSince(ctx, siteID)
	if err != nil {
		return SiteAgentStatuses{}, err
	}

	out := SiteAgentStatuses{GeneratedAt: now, SiteID: siteID, Agents: make([]AgentStatusRow, 0, len(rows))}
	for _, a := range rows {
		row := a
		row.Groups = groups[a.ID]
		if row.Groups == nil {
			row.Groups = []GroupRef{}
		}
		row.FiringAlerts = firing[a.ID]
		row.ActiveIssues = issues[a.ID]
		if ca, ok := connAlerts[a.ID]; ok {
			row.ConnectivityAlert = &ca
		}
		if t, ok := statusSince[a.ID]; ok {
			tt := t
			row.StatusSince = &tt
		} else {
			cc := a.CreatedAt
			row.StatusSince = &cc
		}
		row.Status = overallStatus(row)
		if s.metrics != nil {
			pts, err := s.metrics.LatestSnapshot(ctx, a.ID, 0)
			if err != nil {
				return SiteAgentStatuses{}, err
			}
			row.Resources = buildResources(pts, staleCutoff)
		}
		out.Agents = append(out.Agents, row)
	}
	return out, nil
}

// overallStatus computes the single authoritative status from the orthogonal
// facts, highest severity first. never_connected takes precedence over presence
// because an agent that never completed a Hello is not meaningfully "offline".
func overallStatus(r AgentStatusRow) string {
	switch {
	case r.FirstConnectedAt == nil:
		return StatusNeverConnected
	case r.Presence == "offline":
		return StatusOffline
	case r.FiringAlerts > 0 || r.ActiveIssues > 0:
		return StatusAbnormal
	default:
		return StatusOK
	}
}

func (s *Service) loadAgents(ctx context.Context, siteID string) ([]AgentStatusRow, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, COALESCE(display_name,''), COALESCE(hostname,''), COALESCE(platform,''), COALESCE(agent_version,''),
		       status, last_seen_at, first_connected_at, COALESCE(last_disconnect_kind,''), connectivity_alerts_muted, created_at
		FROM agents WHERE revoked=0 AND site_id=? ORDER BY created_at`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentStatusRow
	for rows.Next() {
		var a AgentStatusRow
		var lastSeen, firstConn sql.NullTime
		var muted int
		if err := rows.Scan(&a.ID, &a.DisplayName, &a.Hostname, &a.Platform, &a.AgentVersion,
			&a.Presence, &lastSeen, &firstConn, &a.LastDisconnectKind, &muted, &a.CreatedAt); err != nil {
			return nil, err
		}
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

func (s *Service) loadGroups(ctx context.Context, siteID string) (map[string][]GroupRef, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT m.agent_id, g.id, COALESCE(g.name,'')
		FROM agent_group_members m JOIN agent_groups g ON g.id=m.group_id
		WHERE g.site_id=? ORDER BY g.name`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]GroupRef{}
	for rows.Next() {
		var agentID string
		var g GroupRef
		if err := rows.Scan(&agentID, &g.ID, &g.Name); err != nil {
			return nil, err
		}
		out[agentID] = append(out[agentID], g)
	}
	return out, rows.Err()
}

func (s *Service) countByAgent(ctx context.Context, query, siteID string) (map[string]int, error) {
	rows, err := s.db.Read().QueryContext(ctx, query, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func (s *Service) loadConnAlerts(ctx context.Context, siteID string) (map[string]ConnAlertRef, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT agent_id, id, reason, opened_at, offline_since FROM agent_alerts WHERE site_id=? AND status='firing'`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ConnAlertRef{}
	for rows.Next() {
		var agentID string
		var ca ConnAlertRef
		if err := rows.Scan(&agentID, &ca.ID, &ca.Reason, &ca.OpenedAt, &ca.OfflineSince); err != nil {
			return nil, err
		}
		out[agentID] = ca
	}
	return out, rows.Err()
}

func (s *Service) loadStatusSince(ctx context.Context, siteID string) (map[string]time.Time, error) {
	// Select the direct changed_at column of each agent's latest transition rather
	// than MAX(changed_at): the aggregate strips the column's TIMESTAMP affinity, so
	// the modernc SQLite driver hands it back as a raw string that will not scan into
	// time.Time. A bare column read keeps the affinity (as registry.StatusHistory
	// relies on); the MAX subquery is only a string comparison (timestamps are UTC
	// and lexicographically ordered). Ties on an identical timestamp dedupe in Go.
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT h.agent_id, h.changed_at FROM agent_status_history h
		JOIN agents a ON a.id=h.agent_id
		WHERE a.site_id=?
		  AND h.changed_at = (SELECT MAX(h2.changed_at) FROM agent_status_history h2 WHERE h2.agent_id=h.agent_id)`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var t time.Time
		if err := rows.Scan(&id, &t); err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

// buildResources turns an agent's latest host.* samples into the resource card
// values, marking each stale when its sample predates staleCutoff.
func buildResources(points []metrics.Point, staleCutoff time.Time) Resources {
	var res Resources

	// Disk is per-mount; collect then pick the worst (highest pct).
	type diskAgg struct {
		pct, used, total *float64
		ts               time.Time
	}
	disks := map[string]*diskAgg{}
	var memPct, memUsed, memTotal *float64
	var memTS time.Time
	var netRx, netTx *float64
	var netTS time.Time
	var load1, load5, load15 *float64
	var loadTS time.Time

	for i := range points {
		p := points[i]
		switch telemetry.MetricKind(p.Kind) {
		case telemetry.HostCPUPct:
			res.CPU = &ScalarSample{Value: p.Value, Unit: p.Unit, TS: p.TS, Stale: p.TS.Before(staleCutoff)}
		case telemetry.HostUptime:
			res.Uptime = &ScalarSample{Value: p.Value, Unit: p.Unit, TS: p.TS, Stale: p.TS.Before(staleCutoff)}
		case telemetry.HostLoad1:
			v := p.Value
			load1 = &v
			if p.TS.After(loadTS) {
				loadTS = p.TS
			}
		case telemetry.HostLoad5:
			v := p.Value
			load5 = &v
		case telemetry.HostLoad15:
			v := p.Value
			load15 = &v
		case telemetry.HostMemPct:
			v := p.Value
			memPct = &v
			if p.TS.After(memTS) {
				memTS = p.TS
			}
		case telemetry.HostMemUsed:
			v := p.Value
			memUsed = &v
		case telemetry.HostMemTotal:
			v := p.Value
			memTotal = &v
		case telemetry.HostNetRxBps:
			v := p.Value
			netRx = &v
			if p.TS.After(netTS) {
				netTS = p.TS
			}
		case telemetry.HostNetTxBps:
			v := p.Value
			netTx = &v
			if p.TS.After(netTS) {
				netTS = p.TS
			}
		case telemetry.HostDiskPct, telemetry.HostDiskUsed, telemetry.HostDiskTotal:
			d := disks[p.Target]
			if d == nil {
				d = &diskAgg{}
				disks[p.Target] = d
			}
			v := p.Value
			switch telemetry.MetricKind(p.Kind) {
			case telemetry.HostDiskPct:
				d.pct = &v
			case telemetry.HostDiskUsed:
				d.used = &v
			case telemetry.HostDiskTotal:
				d.total = &v
			}
			if p.TS.After(d.ts) {
				d.ts = p.TS
			}
		}
	}

	if memPct != nil {
		m := &MemSample{Pct: *memPct, TS: memTS, Stale: memTS.Before(staleCutoff)}
		if memUsed != nil {
			m.Used = *memUsed
		}
		if memTotal != nil {
			m.Total = *memTotal
		}
		res.Memory = m
	}
	if netRx != nil || netTx != nil {
		n := &NetSample{TS: netTS, Stale: netTS.Before(staleCutoff)}
		if netRx != nil {
			n.RxBps = *netRx
		}
		if netTx != nil {
			n.TxBps = *netTx
		}
		res.Net = n
	}
	if len(disks) > 0 {
		var worstMount string
		var worst *diskAgg
		var sumUsed, sumTotal float64
		for mount, d := range disks {
			if d.used != nil {
				sumUsed += *d.used
			}
			if d.total != nil {
				sumTotal += *d.total
			}
			if d.pct == nil {
				continue
			}
			if worst == nil || *d.pct > *worst.pct {
				worst, worstMount = d, mount
			}
		}
		if worst != nil {
			// Used/Total are summed across every mount so a multi-disk host can show
			// its total capacity; Pct/Mount stay the worst mount — the most actionable
			// single signal.
			res.Disk = &DiskSample{
				Pct: *worst.pct, Used: sumUsed, Total: sumTotal,
				Mount: worstMount, Mounts: len(disks),
				TS: worst.ts, Stale: worst.ts.Before(staleCutoff),
			}
		}
	}
	if load1 != nil || load5 != nil || load15 != nil {
		l := &LoadSample{TS: loadTS, Stale: loadTS.Before(staleCutoff)}
		if load1 != nil {
			l.Load1 = *load1
		}
		if load5 != nil {
			l.Load5 = *load5
		}
		if load15 != nil {
			l.Load15 = *load15
		}
		res.Load = l
	}
	return res
}
