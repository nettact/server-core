package metrics

import (
	"context"
	"strings"
)

// RoundOKKind is the server-derived series that records each probe round's
// availability verdict: 1 when the round succeeded, 0 when it failed, and no
// sample at all when the round reached no verdict (missing metric, blocked
// permission, unsupported platform, Agent offline). Because inconclusive rounds
// are absent rather than zero, they never drag a target's availability down.
//
// Availability rides the ordinary time-series pipeline instead of a bespoke
// aggregate table, which is what makes it cheap and correct for free: the
// samples primary key makes a replayed packet idempotent, the rollup worker
// turns each bucket into (cnt, total) — exactly rounds and successful rounds for
// a 0/1 series — and the tiered retention already keeps 30 days of minute
// buckets, covering every window the console offers.
//
// The kind matches no probe family in telemetry.MetricAllowedForProbeKind, so it
// is automatically excluded from the per-monitor series listing and never shows
// up as a chartable metric.
const RoundOKKind = "probe.round.ok"

// AvailabilityRatio is one subject's availability over a window: how many rounds
// reached a verdict and how many of them were available.
type AvailabilityRatio struct {
	MonitorID string  `json:"monitor_id"`
	AgentID   string  `json:"agent_id,omitempty"`
	Rounds    int64   `json:"rounds"`
	OKRounds  int64   `json:"ok_rounds"`
	Ratio     float64 `json:"ratio"` // 0..1; 0 when Rounds == 0
}

// withRatio fills the derived ratio.
func (a AvailabilityRatio) withRatio() AvailabilityRatio {
	if a.Rounds > 0 {
		a.Ratio = float64(a.OKRounds) / float64(a.Rounds)
	}
	return a
}

// availabilitySQL sums a window from two non-overlapping sources: completed
// minute buckets below each series' own rollup watermark, and raw samples at or
// above it. Splitting per series (rather than at one global watermark) means a
// brand-new series with no watermark yet reads entirely from raw while every
// established series still reads the cheap aggregate — and because a bucket at
// ts covers exactly [ts, ts+60) and the watermark is minute-aligned, the two
// ranges meet without a gap or a double count.
const availabilitySQL = `
SELECT monitor_id, agent_id, SUM(c), SUM(t) FROM (
  SELECT s.monitor_id AS monitor_id, s.agent_id AS agent_id, r.cnt AS c, r.total AS t
  FROM rollup_1m r
  JOIN series s ON s.id = r.series_id
  LEFT JOIN rollup_state st ON st.resolution='1m' AND st.series_id = s.id
  WHERE s.kind = '` + RoundOKKind + `' AND %SCOPE%
    AND r.ts >= ? AND r.ts < ? AND r.ts < COALESCE(st.last_ts, 0)
  UNION ALL
  SELECT s.monitor_id AS monitor_id, s.agent_id AS agent_id, 1 AS c, sa.value AS t
  FROM samples sa
  JOIN series s ON s.id = sa.series_id
  LEFT JOIN rollup_state st ON st.resolution='1m' AND st.series_id = s.id
  WHERE s.kind = '` + RoundOKKind + `' AND %SCOPE%
    AND sa.ts >= ? AND sa.ts < ? AND sa.ts >= COALESCE(st.last_ts, 0)
)
GROUP BY monitor_id, agent_id`

// AvailabilityForSite returns each target's availability across every Agent that
// probed it, for the window [since, until) in Unix seconds. Targets with no
// verdict rounds in the window are absent from the map rather than reported as
// 0% — "unknown" and "down" are different answers.
//
// Samples are summed across config generations: a target edited mid-window keeps
// one continuous availability history, since the edit changed how it is probed,
// not what "available" means.
func (s *Store) AvailabilityForSite(ctx context.Context, siteID string, since, until int64) (map[string]AvailabilityRatio, error) {
	rows, err := s.availability(ctx, `s.site_id = ?`, []any{siteID}, since, until)
	if err != nil {
		return nil, err
	}
	out := make(map[string]AvailabilityRatio, len(rows))
	for _, r := range rows {
		agg := out[r.MonitorID]
		agg.MonitorID = r.MonitorID
		agg.Rounds += r.Rounds
		agg.OKRounds += r.OKRounds
		out[r.MonitorID] = agg
	}
	for id, agg := range out {
		out[id] = agg.withRatio()
	}
	return out, nil
}

// AvailabilityForTarget returns one target's availability over the window, both
// in total and broken down per Agent — so a target that only one Agent cannot
// reach is visibly a path problem rather than a target problem.
func (s *Store) AvailabilityForTarget(ctx context.Context, monitorID string, since, until int64) (AvailabilityRatio, []AvailabilityRatio, error) {
	rows, err := s.availability(ctx, `s.monitor_id = ?`, []any{monitorID}, since, until)
	if err != nil {
		return AvailabilityRatio{}, nil, err
	}
	total := AvailabilityRatio{MonitorID: monitorID}
	perAgent := make([]AvailabilityRatio, 0, len(rows))
	for _, r := range rows {
		total.Rounds += r.Rounds
		total.OKRounds += r.OKRounds
		perAgent = append(perAgent, r.withRatio())
	}
	return total.withRatio(), perAgent, nil
}

// availability runs the two-source sum with the given series scope predicate.
func (s *Store) availability(ctx context.Context, scope string, scopeArgs []any, since, until int64) ([]AvailabilityRatio, error) {
	q := strings.ReplaceAll(availabilitySQL, "%SCOPE%", scope)
	args := make([]any, 0, len(scopeArgs)*2+4)
	args = append(args, scopeArgs...)
	args = append(args, since, until)
	args = append(args, scopeArgs...)
	args = append(args, since, until)
	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AvailabilityRatio
	for rows.Next() {
		var r AvailabilityRatio
		var rounds, ok float64
		if err := rows.Scan(&r.MonitorID, &r.AgentID, &rounds, &ok); err != nil {
			return nil, err
		}
		r.Rounds = int64(rounds)
		r.OKRounds = int64(ok + 0.5) // the 0/1 sum is exact; round defensively
		out = append(out, r)
	}
	return out, rows.Err()
}
