package routehist

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/store"
)

// ErrSiteNotFound is returned by SiteSummaries for a site that does not exist,
// mapped by a console host to 404.
var ErrSiteNotFound = errors.New("routehist: site not found")

// RouteAgentSummary is one agent's compact route state for one monitor: what
// a status page needs to classify and list the monitor without fetching the
// full overview (hop tables, variants) per target.
//
// Status is the same value, derived by the same agentStatus rule, as
// RouteAgentView.Status, so a page that lists summaries and a page that opens
// the overview can never disagree about one agent. IntervalSeconds is the
// cadence the agent is expected to report at, so a client can judge staleness
// (LastRunAt far behind it) without knowing the per-kind defaults.
type RouteAgentSummary struct {
	AgentID         string   `json:"agent_id"`
	AgentName       string   `json:"agent_name"`
	Status          string   `json:"status"`
	LastRunAt       *string  `json:"last_run_at"`
	CurrentSince    *string  `json:"current_since"`
	ASPath          []ASHop  `json:"as_path"`
	DestIP          string   `json:"dest_ip"`
	ReachedRatio    *float64 `json:"reached_ratio"`
	RTTP50Ms        *float64 `json:"rtt_p50_ms"`
	LastChangeAt    *string  `json:"last_change_at"`
	Changes24h      int      `json:"changes_24h"`
	Changes7d       int      `json:"changes_7d"`
	IntervalSeconds int      `json:"interval_seconds"`
}

// RouteTargetSummary lists one route monitor's agents.
type RouteTargetSummary struct {
	TargetID string              `json:"target_id"`
	Agents   []RouteAgentSummary `json:"agents"`
}

// RouteSummaries is the site-wide batch of route monitor summaries.
type RouteSummaries struct {
	ASNDBVersion string               `json:"asn_db_version"`
	Targets      []RouteTargetSummary `json:"targets"`
}

// SiteSummaries returns a summary of every enabled route monitor of a site,
// one entry per agent currently in the monitor's scope.
//
// Unlike TargetRoute, it does NOT also list agents that merely still hold
// history for the monitor. The overview shows those so their past route stays
// browsable; a summary is what a status page rolls up into the monitor's
// health, and an agent taken out of scope never reports again — its
// last_run_at would freeze and read as stale, marking the monitor abnormal
// for as long as its history is retained.
//
// It is built from a fixed number of site-wide queries inside one read
// snapshot — targets, the agent×monitor join with each current epoch and the
// change counts aggregated in SQL, then one batched AS-name lookup — rather
// than calling TargetRoute per monitor: a status page asks for every monitor
// at once, and per-target reads would grow the query count with
// targets × agents and could tear across concurrent ingest commits.
func (s *Service) SiteSummaries(ctx context.Context, siteID string) (*RouteSummaries, error) {
	return s.siteSummaries(ctx, siteID, time.Now().UTC())
}

type summaryTarget struct {
	serial   int
	interval int
	idx      int
}

func (s *Service) siteSummaries(ctx context.Context, siteID string, now time.Time) (*RouteSummaries, error) {
	out := &RouteSummaries{Targets: []RouteTargetSummary{}}
	if s.asn != nil {
		out.ASNDBVersion = s.asn.Version()
	}
	err := s.db.ReadTx(ctx, store.Standalone(), func(q store.Executor) error {
		var one int
		if err := q.QueryRowContext(ctx, `SELECT 1 FROM sites WHERE id=?`, siteID).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSiteNotFound
			}
			return err
		}

		targets := map[string]*summaryTarget{}
		trows, err := q.QueryContext(ctx, `
			SELECT id, COALESCE(params,''), config_serial FROM probe_tasks
			WHERE site_id=? AND kind=? AND enabled=1
			ORDER BY COALESCE(name,''), id`, siteID, config.KindTrace)
		if err != nil {
			return err
		}
		for trows.Next() {
			var id, params string
			var t summaryTarget
			if err := trows.Scan(&id, &params, &t.serial); err != nil {
				trows.Close()
				return err
			}
			t.interval = traceIntervalSeconds(params)
			t.idx = len(out.Targets)
			targets[id] = &t
			out.Targets = append(out.Targets, RouteTargetSummary{TargetID: id, Agents: []RouteAgentSummary{}})
		}
		trows.Close()
		if err := trows.Err(); err != nil {
			return err
		}
		if len(targets) == 0 {
			return nil
		}

		// The agent selection is TargetRoute's scope rule without its
		// history branch (see SiteSummaries), widened from one monitor to
		// every enabled trace monitor of the site; the change aggregate is
		// per (agent, monitor) over all of that monitor's history.
		day, week := now.Add(-24*time.Hour).Unix(), now.Add(-7*24*time.Hour).Unix()
		rows, err := q.QueryContext(ctx, `
			SELECT pt.id, a.id, COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), a.id),
			       ms.status, COALESCE(ms.reason,''), ms.source, ms.target_config_serial,
			       rs.last_run_at, e.id, e.start_ts, e.run_count, e.reached_runs, e.dest_ip,
			       e.rtt_hist, e.rtt_count, e.rtt_sum, e.rtt_min, e.rtt_max, p.as_path,
			       ch.last_at, COALESCE(ch.c24,0), COALESCE(ch.c7,0)
			FROM probe_tasks pt
			JOIN agents a ON a.site_id = pt.site_id AND a.revoked = 0
			LEFT JOIN monitor_status ms ON ms.agent_id = a.id AND ms.monitor_id = pt.id
			LEFT JOIN route_monitor_state rs ON rs.agent_id = a.id AND rs.monitor_id = pt.id
			LEFT JOIN route_epochs e ON e.id = rs.epoch_id
			LEFT JOIN route_paths p ON p.id = e.path_id
			LEFT JOIN (
			    SELECT c.agent_id, c.monitor_id, MAX(c.confirmed_at) AS last_at,
			           SUM(c.confirmed_at >= ?) AS c24, SUM(c.confirmed_at >= ?) AS c7
			    FROM route_changes c JOIN probe_tasks t ON t.id = c.monitor_id
			    WHERE t.site_id = ? AND t.kind = ? AND t.enabled = 1
			    GROUP BY c.agent_id, c.monitor_id
			) ch ON ch.agent_id = a.id AND ch.monitor_id = pt.id
			WHERE pt.site_id = ? AND pt.kind = ? AND pt.enabled = 1
			  AND EXISTS(
			    SELECT 1 FROM monitor_groups mg
			    WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
			        SELECT 1 FROM monitor_group_agent_groups mgag
			        JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
			        WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = a.id)))
			ORDER BY pt.id, 3, 2`,
			day, week, siteID, config.KindTrace, siteID, config.KindTrace)
		if err != nil {
			return err
		}
		type pending struct {
			target, agent int
			asBlob        []byte
		}
		var blobs []pending
		for rows.Next() {
			var targetID string
			var a RouteAgentSummary
			var status, source, destIP sql.NullString
			var reason string
			var msSerial, lastRun, epochID, startTS, runCount, reached, lastChange sql.NullInt64
			var histBlob, asBlob []byte
			var rttCount sql.NullInt64
			var rttSum, rttMin, rttMax sql.NullFloat64
			if err := rows.Scan(&targetID, &a.AgentID, &a.AgentName, &status, &reason, &source, &msSerial,
				&lastRun, &epochID, &startTS, &runCount, &reached, &destIP,
				&histBlob, &rttCount, &rttSum, &rttMin, &rttMax, &asBlob,
				&lastChange, &a.Changes24h, &a.Changes7d); err != nil {
				rows.Close()
				return err
			}
			t := targets[targetID]
			a.Status = agentStatus(status, reason, source, msSerial, t.serial)
			a.IntervalSeconds = t.interval
			a.ASPath = []ASHop{}
			if lastRun.Valid && lastRun.Int64 > 0 {
				v := rfc3339(lastRun.Int64)
				a.LastRunAt = &v
			}
			if lastChange.Valid {
				v := rfc3339(lastChange.Int64)
				a.LastChangeAt = &v
			}
			if epochID.Valid {
				since := rfc3339(startTS.Int64)
				a.CurrentSince = &since
				a.DestIP = destIP.String
				// Same reading as RouteEpoch.ReachedRatio, which reports 0
				// for an era with no runs counted yet.
				ratio := 0.0
				if runCount.Int64 > 0 {
					ratio = round4(float64(reached.Int64) / float64(runCount.Int64))
				}
				a.ReachedRatio = &ratio
				h := decodeHist(histBlob)
				h.count, h.sum, h.min, h.max = uint64(rttCount.Int64), rttSum.Float64, rttMin.Float64, rttMax.Float64
				if sum := h.summary(); sum != nil {
					p50 := sum.P50Ms
					a.RTTP50Ms = &p50
				}
			}
			tgt := &out.Targets[t.idx]
			tgt.Agents = append(tgt.Agents, a)
			if epochID.Valid {
				blobs = append(blobs, pending{target: t.idx, agent: len(tgt.Agents) - 1, asBlob: asBlob})
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Decode every current AS path, resolve all their names in one query,
		// then render through the shared per-request cache.
		paths := make([][]uint32, len(blobs))
		var asns []uint32
		for i, b := range blobs {
			as, err := decodeASPath(b.asBlob)
			if err != nil {
				return err
			}
			paths[i] = as
			asns = append(asns, as...)
		}
		names := newASNames(q)
		if err := names.prefetch(ctx, asns); err != nil {
			return err
		}
		for i, b := range blobs {
			hops, err := names.hops(ctx, paths[i])
			if err != nil {
				return err
			}
			out.Targets[b.target].Agents[b.agent].ASPath = hops
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// traceIntervalSeconds is a route monitor's effective cadence: the configured
// interval or the kind default, floored at MinTraceInterval — the floor an
// agent enforces whatever it is pushed, so a stored value below it (written
// before validation tightened, or by hand) must not make the monitor look
// stale at a rate it can never report at. Unparseable params read as the
// defaults, as they do when the target is pushed.
func traceIntervalSeconds(params string) int {
	var p pcfg.ProbeParams
	if params != "" {
		_ = json.Unmarshal([]byte(params), &p)
	}
	return int(max(pcfg.EffectiveInterval(config.KindTrace, p), pcfg.MinTraceInterval) / time.Second)
}

// prefetch loads the names of every given AS not yet cached in one query, so
// rendering many paths afterwards issues none. ASes without an asn_info row
// are cached as empty, exactly as get would leave them.
func (n *asNames) prefetch(ctx context.Context, asns []uint32) error {
	var args []any
	seen := map[uint32]bool{}
	for _, a := range asns {
		if _, ok := n.cache[a]; ok || seen[a] {
			continue
		}
		seen[a] = true
		args = append(args, a)
	}
	if len(args) == 0 {
		return nil
	}
	rows, err := n.q.QueryContext(ctx, `SELECT asn, name, country FROM asn_info WHERE asn IN (`+placeholders(len(args))+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var asn int64
		var m asMeta
		if err := rows.Scan(&asn, &m.name, &m.country); err != nil {
			return err
		}
		n.cache[uint32(asn)] = m
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for a := range seen {
		if _, ok := n.cache[a]; !ok {
			n.cache[a] = asMeta{}
		}
	}
	return nil
}
