package fault

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// signalCols is the full projection of a fault signal, with the read-time
// "currently abnormal" overlay computed from the detector's live state rather
// than from the frozen row: a probe fault is still abnormal only while it is
// firing AND its detector has an unbroken failing streak. A firing signal whose
// target has started answering again (but has not yet reached the recovery
// threshold) therefore reads as no-longer-abnormal without its frozen evidence
// changing.
//
// Agent connectivity is exempt: it has no detector_state row (it is driven by the
// liveness tick, not by probe rounds), so the streak test would report every
// still-offline Agent as "answering again". A firing connectivity fault means the
// Agent is offline right now, full stop.
const signalCols = `s.id, s.site_id, s.agent_id, s.agent_name, s.target_id, s.target_name, s.target_addr,
	s.target_port, s.detector_key, s.probe_kind, s.group_id, s.group_name, s.layer, s.severity, s.state,
	s.resolve_reason, s.fail_threshold, s.recover_threshold, s.metric_kind, s.comparator, s.value, s.threshold,
	s.reason_code, s.reason_detail, s.baseline_p50, s.baseline_p95,
	s.rounds_json, s.size_sweep_json, s.flow_fanout_json, s.observed_at, s.confirmed_at, s.resolved_at, s.incident_id,
	CASE WHEN s.state='firing'
	          AND (s.detector_key = '` + DetectorAgentConnectivity + `' OR COALESCE(ds.fail_rounds,0) > 0)
	     THEN 1 ELSE 0 END`

const signalFrom = `FROM fault_signals s
	LEFT JOIN detector_state ds
	  ON ds.target_id = s.target_id AND ds.agent_id = s.agent_id AND ds.detector_key = s.detector_key`

// SignalFilter narrows a signal listing. Zero values mean "no constraint".
type SignalFilter struct {
	SiteID   string
	AgentID  string
	TargetID string
	Detector string
	State    string // firing | resolved | "" (both)
	Since    int64  // confirmed_at lower bound, Unix seconds; 0 = unbounded
	Limit    int
}

// ListSignals returns fault signals matching the filter, newest first.
func (s *Service) ListSignals(ctx context.Context, f SignalFilter) ([]Signal, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var where []string
	var args []any
	if f.SiteID != "" {
		where = append(where, "s.site_id=?")
		args = append(args, f.SiteID)
	}
	if f.AgentID != "" {
		where = append(where, "s.agent_id=?")
		args = append(args, f.AgentID)
	}
	if f.TargetID != "" {
		where = append(where, "s.target_id=?")
		args = append(args, f.TargetID)
	}
	if f.Detector != "" {
		where = append(where, "s.detector_key=?")
		args = append(args, f.Detector)
	}
	if f.Since > 0 {
		where = append(where, "s.confirmed_at >= ?")
		args = append(args, time.Unix(f.Since, 0).UTC())
	}
	switch f.State {
	case "firing", "resolved":
		where = append(where, "s.state=?")
		args = append(args, f.State)
	}
	q := `SELECT ` + signalCols + ` ` + signalFrom
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ")
	}
	q += ` ORDER BY s.confirmed_at DESC, s.id DESC LIMIT ?`
	args = append(args, limit)
	return s.query(ctx, q, args...)
}

// ListActive returns a site's currently firing signals, newest first.
func (s *Service) ListActive(ctx context.Context, siteID string) ([]Signal, error) {
	return s.query(ctx, `SELECT `+signalCols+` `+signalFrom+`
		WHERE s.site_id=? AND s.state='firing' ORDER BY s.confirmed_at DESC`, siteID)
}

// IncidentSignals returns one incident's member signals, firing first then by
// confirmation time.
func (s *Service) IncidentSignals(ctx context.Context, incidentID string) ([]Signal, error) {
	return s.query(ctx, `SELECT `+signalCols+` `+signalFrom+`
		WHERE s.incident_id=?
		ORDER BY CASE WHEN s.state='firing' THEN 0 ELSE 1 END, s.confirmed_at DESC`, incidentID)
}

// CountAbnormalTargets returns how many distinct targets of an incident are still
// abnormal right now — computed from live detector state, deliberately decoupled
// from the member count so a member that recovered but has not yet met its
// recovery threshold is not counted as healthy or as broken twice.
func (s *Service) CountAbnormalTargets(ctx context.Context, incidentID string) (int, error) {
	var n int
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT s.target_id)
		FROM fault_signals s
		JOIN detector_state ds ON ds.target_id = s.target_id AND ds.agent_id = s.agent_id
		                      AND ds.detector_key = s.detector_key
		WHERE s.incident_id=? AND s.state='firing' AND ds.fail_rounds > 0`, incidentID).Scan(&n)
	return n, err
}

// CountActive returns the number of firing signals in a site.
func (s *Service) CountActive(ctx context.Context, siteID string) (int, error) {
	var n int
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM fault_signals WHERE site_id=? AND state='firing'`, siteID).Scan(&n)
	return n, err
}

func (s *Service) query(ctx context.Context, q string, args ...any) ([]Signal, error) {
	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Signal{}
	for rows.Next() {
		var sig Signal
		var resolved sql.NullTime
		var roundsJSON string
		var sizeSweepJSON, flowFanoutJSON sql.NullString
		var abnormal int
		if err := rows.Scan(&sig.ID, &sig.SiteID, &sig.AgentID, &sig.AgentName, &sig.TargetID,
			&sig.TargetName, &sig.TargetAddr, &sig.Port, &sig.DetectorKey, &sig.ProbeKind,
			&sig.GroupID, &sig.GroupName, &sig.Layer, &sig.Severity, &sig.State, &sig.ResolveReason,
			&sig.FailThreshold, &sig.RecoverThreshold, &sig.MetricKind, &sig.Comparator, &sig.Value,
			&sig.Threshold, &sig.ReasonCode, &sig.ReasonDetail, &sig.BaselineP50, &sig.BaselineP95,
			&roundsJSON, &sizeSweepJSON, &flowFanoutJSON, &sig.ObservedAt, &sig.ConfirmedAt,
			&resolved, &sig.IncidentID, &abnormal); err != nil {
			return nil, err
		}
		sig.Rounds = decodeRounds(roundsJSON)
		if sizeSweepJSON.Valid {
			var f SizeSweepFacts
			if err := json.Unmarshal([]byte(sizeSweepJSON.String), &f); err != nil {
				return nil, err
			}
			sig.SizeSweep = &f
		}
		if flowFanoutJSON.Valid {
			var f FlowFanoutFacts
			if err := json.Unmarshal([]byte(flowFanoutJSON.String), &f); err != nil {
				return nil, err
			}
			sig.FlowFanout = &f
		}
		if resolved.Valid {
			t := resolved.Time.UTC()
			sig.ResolvedAt = &t
		}
		sig.ObservedAt = sig.ObservedAt.UTC()
		sig.ConfirmedAt = sig.ConfirmedAt.UTC()
		sig.CurrentlyAbnormal = abnormal == 1
		sig.Title = SignalTitle(sig)
		out = append(out, sig)
	}
	return out, rows.Err()
}
