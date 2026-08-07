// Package agentstatus is the read-time aggregation behind the Agent status list
// (AGENT-001). It fuses per-agent identity, group membership, liveness, the
// agent's firing target faults / operational issues (the "abnormal" reasons), its
// own connectivity fault, and the latest host resource samples into one per-agent
// rollup, computing the single authoritative overall status so the API and UI
// can never drift. It is a pure reader: it never mutates state.
package agentstatus

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
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

// ConnAlertRef links an agent row to its firing connectivity fault. Reason is
// the offline cause frozen on the signal (unexpected | clean_shutdown |
// version_incompatible); OfflineSince is the fault's observed_at (when the agent
// was last seen) and OpenedAt its confirmed_at (when grace expired).
type ConnAlertRef struct {
	ID           string    `json:"id"`
	Reason       string    `json:"reason"`
	OpenedAt     time.Time `json:"opened_at"`
	OfflineSince time.Time `json:"offline_since"`
}

// ProbeOverloadRef reports that this agent recently ran out of probe-concurrency
// budget and skipped probes it was due to run.
//
// It exists to explain a silence. A probe the budget turned away leaves no
// sample, so its monitor goes stale exactly as it would if the network had gone
// away — same badge, same freshness window, entirely different cause and
// entirely different fix. Without this the console can only report the symptom;
// with it, it can name the knob (max_probe_concurrency) and how far short it
// fell.
//
// It is per agent rather than per monitor because the budget is the machine's:
// the probes that lost the race are not the ones that overran it, so attributing
// the shortfall to whichever monitor happened to be skipped would point at the
// wrong target. Only the most recent report is carried — the condition is a
// standing one, not a history to page through.
type ProbeOverloadRef struct {
	// Skipped is how many probe operations the budget refused during Window.
	Skipped int `json:"skipped"`
	// Window is the aggregation window in seconds the count covers.
	Window int `json:"window_s"`
	// Limit is the configured max_probe_concurrency the probes competed for.
	Limit int `json:"limit"`
	// ReportedAt is when the agent reported it.
	ReportedAt time.Time `json:"reported_at"`
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
	ID                      string            `json:"id"`
	DisplayName             string            `json:"display_name"`
	Hostname                string            `json:"hostname"`
	Platform                string            `json:"platform"`
	AgentVersion            string            `json:"agent_version"`
	Status                  string            `json:"status"`   // offline|abnormal|never_connected|ok
	Presence                string            `json:"presence"` // online|offline (raw registry status)
	StatusSince             *time.Time        `json:"status_since"`
	LastSeenAt              *time.Time        `json:"last_seen_at"`
	FirstConnectedAt        *time.Time        `json:"first_connected_at"`
	LastDisconnectKind      string            `json:"last_disconnect_kind"`
	ConnectivityAlertsMuted bool              `json:"connectivity_alerts_muted"`
	Groups                  []GroupRef        `json:"groups"`
	FiringFaults            int               `json:"firing_faults"`
	ActiveIssues            int               `json:"active_issues"`
	ConnectivityAlert       *ConnAlertRef     `json:"connectivity_alert"`
	ProbeOverload           *ProbeOverloadRef `json:"probe_overload"`
	Resources               Resources         `json:"resources"`
	CreatedAt               time.Time         `json:"created_at"`
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
	firing, err := s.countByAgent(ctx, `SELECT agent_id, COUNT(*) FROM fault_signals WHERE site_id=? AND state='firing' AND target_id <> '' GROUP BY agent_id`, siteID)
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
	overloads, err := s.loadProbeOverloads(ctx, siteID, now)
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
		row.FiringFaults = firing[a.ID]
		row.ActiveIssues = issues[a.ID]
		if ca, ok := connAlerts[a.ID]; ok {
			row.ConnectivityAlert = &ca
		}
		if po, ok := overloads[a.ID]; ok {
			row.ProbeOverload = &po
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
	case r.FiringFaults > 0 || r.ActiveIssues > 0:
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
		`SELECT agent_id, id, COALESCE(reason_detail,''), confirmed_at, observed_at FROM fault_signals
		 WHERE site_id=? AND detector_key='agent_connectivity' AND state='firing'`, siteID)
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

// probeOverloadFreshFor is how long a reported overload keeps describing the
// present.
//
// The agent aggregates its refusals into one event per 5-minute window, so a
// single window is the shortest honest answer and would blink off between
// reports on an agent that is still overloaded. Three windows is long enough to
// ride out a missed or delayed upload — the WAL batches on its own cadence — and
// short enough that the notice goes away on its own once the operator has raised
// the limit, instead of accusing a healthy agent for the rest of the day.
const probeOverloadFreshFor = 15 * time.Minute

// loadProbeOverloads returns each agent's most recent probe-overload report,
// dropping ones too old to describe the present.
//
// It is the first and only reader of the events table, which is why it reaches
// into it directly rather than through a general event feed: what the console
// needs here is one standing condition per agent, not a queryable history, and
// a table scan bounded by (site, ts) — the index the table already carries — is
// the whole cost.
//
// # Whose clock this trusts
//
// events.ts is stamped by the AGENT and stored unchanged, so a badly skewed
// agent clock shifts this window by the skew: a slow one can date a live report
// outside it and show nothing, a fast one holds a recovered agent's last report
// inside it for that much longer before it ages out. That is deliberate rather
// than overlooked. Every freshness judgement in the product already reads
// agent-stamped time — targetstatus compares sample timestamps against
// StaleAfter the same way — so correcting skew for this one notice would make it
// disagree with the staleness it exists to explain, which is the one outcome
// worse than either failure mode. Skew is a whole-product concern and belongs to
// a whole-product fix (a server-derived occurrence time at ingest), not to a
// special case here.
//
// A future-dated report is still clamped below, so the timestamp the console
// shows is never one that has not happened yet.
func (s *Service) loadProbeOverloads(ctx context.Context, siteID string, now time.Time) (map[string]ProbeOverloadRef, error) {
	// The cutoff MUST be UTC. The driver renders a time.Time bind parameter with
	// its zone offset and TIMESTAMP columns compare as text, so a local-zone
	// cutoff ("…T15:04+08:00") is compared against a stored UTC instant
	// ("…T07:04Z") as a string — east of Greenwich that silently excludes every
	// row, west of it includes far too many. s.now() is time.Now, which is local.
	utcNow := now.UTC()
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT agent_id, ts, COALESCE(attrs,'') FROM events
		WHERE site_id=? AND type=? AND ts >= ?
		ORDER BY ts ASC`,
		siteID, string(telemetry.EventProbeOverload), utcNow.Add(-probeOverloadFreshFor))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ProbeOverloadRef{}
	for rows.Next() {
		var agentID, attrs string
		var ts time.Time
		if err := rows.Scan(&agentID, &ts, &attrs); err != nil {
			return nil, err
		}
		var a map[string]string
		if attrs != "" && json.Unmarshal([]byte(attrs), &a) != nil {
			continue // an unparseable payload says nothing; do not guess at it
		}
		skipped := atoiOr(a[telemetry.ProbeOverloadAbandonedLabel], 0)
		if skipped <= 0 {
			// A count of zero is not a notice. The producer only emits when it has
			// refused something, so reaching here means an absent or malformed
			// payload — and rendering "0 probes skipped against a limit of 0" as a
			// standing warning would be worse than saying nothing.
			continue
		}
		// Ascending order means a later row overwrites an earlier one, so each
		// agent ends on its most recent report. A future-dated one is clamped so
		// the console never shows a timestamp that has not happened yet.
		reported := ts
		if reported.After(utcNow) {
			reported = utcNow
		}
		out[agentID] = ProbeOverloadRef{
			Skipped:    skipped,
			Window:     atoiOr(a[telemetry.ProbeOverloadWindowLabel], 0),
			Limit:      atoiOr(a[telemetry.ProbeOverloadLimitLabel], 0),
			ReportedAt: reported,
		}
	}
	return out, rows.Err()
}

// atoiOr parses a decimal attribute, falling back to def. An attribute the agent
// could not fill is absent rather than zero, and either way the console renders
// what it got instead of refusing the whole notice.
func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func (s *Service) loadStatusSince(ctx context.Context, siteID string) (map[string]time.Time, error) { // Select the direct changed_at column of each agent's latest transition rather
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
