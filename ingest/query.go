package ingest

import (
	"context"
	"time"
)

// Sample is one stored metric returned by metric queries (feeds the UI charts).
type Sample struct {
	TS     time.Time `json:"ts"`
	Kind   string    `json:"kind"`
	Target string    `json:"target"`
	Layer  string    `json:"layer"`
	Value  float64   `json:"value"`
	Unit   string    `json:"unit"`
}

// MetricQuery filters a metric read.
type MetricQuery struct {
	AgentID string
	Kind    string    // optional
	Target  string    // optional
	Since   time.Time // zero = no lower bound
	Limit   int       // <=0 => default 1000
}

// QueryMetrics returns matching samples ordered by ts ascending (chart-friendly).
// Uses idx_metrics_query(agent_id, kind, target, ts).
func (s *Service) QueryMetrics(ctx context.Context, q MetricQuery) ([]Sample, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 1000
	}
	sqlStr := `SELECT ts, kind, COALESCE(target,''), COALESCE(layer,''), value, COALESCE(unit,'')
	           FROM metrics WHERE agent_id=?`
	args := []any{q.AgentID}
	if q.Kind != "" {
		sqlStr += ` AND kind=?`
		args = append(args, q.Kind)
	}
	if q.Target != "" {
		sqlStr += ` AND target=?`
		args = append(args, q.Target)
	}
	if !q.Since.IsZero() {
		sqlStr += ` AND ts>=?`
		args = append(args, q.Since.UTC())
	}
	// Newest N by ts, then re-sorted ascending for display.
	sqlStr += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var s Sample
		if err := rows.Scan(&s.TS, &s.Kind, &s.Target, &s.Layer, &s.Value, &s.Unit); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// reverse to ascending
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}
