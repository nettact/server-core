package ingest

import (
	"context"
	"database/sql"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/store"
)

// hasHostMetrics reports whether a batch carries anything the system-status
// detectors could judge. Every probe-only batch — the overwhelming majority —
// answers false here and pays nothing for the host path.
func hasHostMetrics(ms []telemetry.Metric) bool {
	for _, m := range ms {
		if m.MonitorID != "" {
			continue
		}
		switch m.Kind {
		case telemetry.HostCPUPct, telemetry.HostMemPct, telemetry.HostLoad1,
			telemetry.HostNetRxBps, telemetry.HostNetTxBps, telemetry.HostDiskPct:
			return true
		}
	}
	return false
}

// hostMeta loads every host anchor that applies to this agent, with its
// thresholds, in one query.
//
// The anchor set is resolved by the SAME scope predicate the config downlink and
// the operational-issue engine use, so "which machines does this anchor watch"
// has exactly one answer in the codebase. An anchor with no
// host_detection_settings row COALESCEs to the defaults, which is what makes a
// freshly created anchor watch the machine without anyone opening a form.
func hostMeta(ctx context.Context, q store.Executor, agentID, siteID string, cores float64, intervalSeconds, uploadSeconds int) ([]fault.HostTargetMeta, error) {
	def := fault.DefaultHostSettings()
	defCPU, defMem, defLoad, defNet, defDisk := 0, 0, 0, 0, 0
	if def.CPUEnabled {
		defCPU = 1
	}
	if def.MemEnabled {
		defMem = 1
	}
	if def.LoadEnabled {
		defLoad = 1
	}
	if def.NetEnabled {
		defNet = 1
	}
	if def.DiskEnabled {
		defDisk = 1
	}
	rows, err := q.QueryContext(ctx, `
		SELECT pt.id, pt.group_id, COALESCE(pt.name,''), pt.config_serial,
		       COALESCE(h.cpu_enabled, ?), COALESCE(h.cpu_pct, ?), COALESCE(h.cpu_duration_s, ?),
		       COALESCE(h.mem_enabled, ?), COALESCE(h.mem_pct, ?), COALESCE(h.mem_duration_s, ?),
		       COALESCE(h.load_enabled, ?), COALESCE(h.load_per_core, ?), COALESCE(h.load_duration_s, ?),
		       COALESCE(h.net_enabled, ?), COALESCE(h.net_rx_mbps, 0), COALESCE(h.net_tx_mbps, 0),
		       COALESCE(h.net_duration_s, ?),
		       COALESCE(h.disk_enabled, ?), COALESCE(h.disk_pct, ?),
		       COALESCE(h.revision, 1)
		FROM probe_tasks pt
		LEFT JOIN host_detection_settings h ON h.target_id = pt.id
		WHERE pt.site_id = ? AND pt.kind = 'host' AND pt.enabled = 1
		  AND `+config.AgentScopePredicate,
		defCPU, def.CPUPct, def.CPUDurationS,
		defMem, def.MemPct, def.MemDurationS,
		defLoad, def.LoadPerCore, def.LoadDurationS,
		defNet, def.NetDurationS,
		defDisk, def.DiskPct,
		siteID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []fault.HostTargetMeta
	for rows.Next() {
		var m fault.HostTargetMeta
		var cpuOn, memOn, loadOn, netOn, diskOn int
		if err := rows.Scan(&m.ID, &m.GroupID, &m.Name, &m.ConfigSerial,
			&cpuOn, &m.Set.CPUPct, &m.Set.CPUDurationS,
			&memOn, &m.Set.MemPct, &m.Set.MemDurationS,
			&loadOn, &m.Set.LoadPerCore, &m.Set.LoadDurationS,
			&netOn, &m.Set.NetRxMbps, &m.Set.NetTxMbps, &m.Set.NetDurationS,
			&diskOn, &m.Set.DiskPct, &m.Set.Revision); err != nil {
			return nil, err
		}
		m.Set.CPUEnabled = cpuOn != 0
		m.Set.MemEnabled = memOn != 0
		m.Set.LoadEnabled = loadOn != 0
		m.Set.NetEnabled = netOn != 0
		m.Set.DiskEnabled = diskOn != 0
		m.Cores = cores
		m.IntervalSeconds = intervalSeconds
		m.UploadSeconds = uploadSeconds
		out = append(out, m)
	}
	return out, rows.Err()
}

// latestCores reads the agent's last known logical core count from the latest
// cache, as the fallback for a batch that does not carry one of its own.
//
// Resolved before the write transaction opens, like every other read ingest can
// answer off the read path. A batch that DOES carry a core count overrides this
// (BuildHostRounds prefers its own), so the cache only covers the ordinary case
// where the count was reported in some earlier packet. Zero means unknown, and
// the load family is then not judged at all.
func (s *Service) latestCores(ctx context.Context, agentID string) float64 {
	vals, err := s.metrics.LatestPerSeries(ctx, agentID, string(telemetry.HostCPUCores), "host", 0)
	if err != nil || len(vals) == 0 {
		return 0
	}
	return vals[0].Value
}

// reportedUploadSeconds is the agent's own batch-upload cadence, as it last
// attested it in a MonitorStatus frame.
//
// Read from the agents row rather than from monitor_status. The agent reports
// ONE cadence for its whole outbox, and the case this exists for is precisely
// the one where the per-monitor rows cannot carry it: an agent whose only
// subject is a host anchor sends a frame with no entries, so there are no
// per-monitor rows to read. Host anchors belong to no monitor either way.
//
// It decides how late a live host reading can legitimately be — without it an
// install on a deliberately slow upload interval would have every live host
// fault judged a replay and delayed accordingly. Zero (an agent that has not
// reported yet) leaves the protocol default standing.
func reportedUploadSeconds(ctx context.Context, q store.Executor, agentID string) int {
	rows, err := q.QueryContext(ctx,
		`SELECT upload_interval_seconds FROM agents WHERE id=?`, agentID)
	if err != nil {
		return 0
	}
	defer rows.Close()
	var v sql.NullInt64
	if rows.Next() {
		if err := rows.Scan(&v); err != nil {
			return 0
		}
	}
	if !v.Valid || v.Int64 < 0 {
		return 0
	}
	return int(v.Int64)
}
