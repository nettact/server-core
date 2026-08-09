package metrics

import (
	"context"
)

// RoundOKKind is the server-derived series that records each probe round's
// availability verdict: 1 when the round succeeded, 0 when it failed, and no
// sample at all when the round reached no verdict (missing metric, blocked
// permission, unsupported platform, Agent offline). Because inconclusive rounds
// are absent rather than zero, they never drag a target's availability down.
//
// Availability rides the ordinary time-series pipeline instead of a bespoke
// aggregate table, which is what makes it cheap and correct for free: replayed
// packets are deduplicated at the packet watermark, the rollup worker turns
// each minute of the 0/1 series into a (cnt, sum) bucket — exactly rounds and
// successful rounds — and the tiered retention already keeps 30 days of minute
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

// AvailabilityForSite returns each target's availability across every Agent that
// probed it, for the window [since, until) in Unix seconds. Targets with no
// verdict rounds in the window are absent from the map rather than reported as
// 0% — "unknown" and "down" are different answers.
//
// Samples are summed across config generations: a target edited mid-window keeps
// one continuous availability history, since the edit changed how it is probed,
// not what "available" means.
func (s *Store) AvailabilityForSite(ctx context.Context, siteID string, since, until int64) (map[string]AvailabilityRatio, error) {
	totals, _, err := s.AvailabilityForSiteWithAgents(ctx, siteID, since, until)
	return totals, err
}

// AvailabilityForSiteWithAgents returns the same per-target totals as
// AvailabilityForSite together with each target's per-Agent breakdown. Both
// views come from one series scan so batch status reads do not introduce an
// N+1 lookup.
func (s *Store) AvailabilityForSiteWithAgents(ctx context.Context, siteID string, since, until int64) (map[string]AvailabilityRatio, map[string]map[string]AvailabilityRatio, error) {
	rows, err := s.availability(ctx, `s.site_id = ?`, []any{siteID}, since, until)
	if err != nil {
		return nil, nil, err
	}
	totals := make(map[string]AvailabilityRatio, len(rows))
	perAgent := make(map[string]map[string]AvailabilityRatio)
	for _, r := range rows {
		agg := totals[r.MonitorID]
		agg.MonitorID = r.MonitorID
		agg.Rounds += r.Rounds
		agg.OKRounds += r.OKRounds
		totals[r.MonitorID] = agg

		agents := perAgent[r.MonitorID]
		if agents == nil {
			agents = make(map[string]AvailabilityRatio)
			perAgent[r.MonitorID] = agents
		}
		agents[r.AgentID] = r.withRatio()
	}
	for id, agg := range totals {
		totals[id] = agg.withRatio()
	}
	return totals, perAgent, nil
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

// availability sums each in-scope round.ok series over [since, until) from two
// non-overlapping sources: completed minute buckets below the series' own 1m
// rollup watermark, and raw samples at or above it. Splitting per series
// (rather than at one global watermark) means a brand-new series with no
// watermark yet reads entirely from raw while every established series still
// reads the cheap aggregate — and because a bucket at ts covers exactly
// [ts, ts+60) and the watermark is minute-aligned, the two ranges meet without
// a gap or a double count. The series set, its per-series watermarks and the
// purge cutoffs come from one SQLite read; the sums come from the data plane.
func (s *Store) availability(ctx context.Context, scope string, scopeArgs []any, since, until int64) ([]AvailabilityRatio, error) {
	q := `SELECT s.id, s.monitor_id, s.agent_id, s.purge_cutoff, COALESCE(st.last_ts, 0)
	      FROM series s
	      LEFT JOIN rollup_state st ON st.resolution='1m' AND st.series_id = s.id
	      WHERE s.kind = '` + RoundOKKind + `' AND ` + scope
	rows, err := s.db.Read().QueryContext(ctx, q, scopeArgs...)
	if err != nil {
		return nil, err
	}
	type roundSeries struct {
		id, cutoff, wm     int64
		monitorID, agentID string
	}
	var series []roundSeries
	for rows.Next() {
		var rs roundSeries
		if err := rows.Scan(&rs.id, &rs.monitorID, &rs.agentID, &rs.cutoff, &rs.wm); err != nil {
			rows.Close()
			return nil, err
		}
		series = append(series, rs)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Sum per (monitor, agent): several config generations of one pair fold
	// into one continuous history.
	type pairKey struct{ monitorID, agentID string }
	sums := make(map[pairKey]*AvailabilityRatio)
	for _, rs := range series {
		lo := since
		if rs.cutoff > lo {
			lo = rs.cutoff
		}
		if lo >= until {
			continue
		}
		key := pairKey{rs.monitorID, rs.agentID}
		agg := sums[key]
		if agg == nil {
			agg = &AvailabilityRatio{MonitorID: rs.monitorID, AgentID: rs.agentID}
			sums[key] = agg
		}
		// Buckets strictly below the watermark…
		bucketHi := until
		if rs.wm < bucketHi {
			bucketHi = rs.wm
		}
		if bucketHi > lo {
			buckets, err := s.ts.ReadBuckets(ctx, tierOf("rollup_1m"), rs.id, lo, bucketHi)
			if err != nil {
				return nil, err
			}
			for _, b := range buckets {
				agg.Rounds += b.Cnt
				agg.OKRounds += int64(b.Sum + 0.5) // the 0/1 sum is exact; round defensively
			}
		}
		// …and raw at or above it.
		rawLo := lo
		if rs.wm > rawLo {
			rawLo = rs.wm
		}
		if until > rawLo {
			samples, err := s.ts.RawRange(ctx, rs.id, rawLo, until, 0)
			if err != nil {
				return nil, err
			}
			for _, smp := range samples {
				agg.Rounds++
				agg.OKRounds += int64(smp.Value + 0.5)
			}
		}
	}

	out := make([]AvailabilityRatio, 0, len(sums))
	for _, agg := range sums {
		if agg.Rounds == 0 {
			continue // no verdicts in window: absent, not 0%
		}
		out = append(out, *agg)
	}
	return out, nil
}
