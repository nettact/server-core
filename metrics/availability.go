package metrics

import (
	"context"
	"time"

	"github.com/nettact/server-core/tsstore"
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
// successful rounds — and every coarser tier keeps summing the same two numbers,
// so a bucket at ANY resolution answers "how many rounds, how many were up".
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

// ---- the series scan ----

// watermarks are one series' three rollup fences, straight out of rollup_state.
//
// Each is an EXCLUSIVE upper bound on that tier's settled buckets, aligned down
// to that tier's OWN bucket width: rollupTier computes upTo = alignDown(now,
// bucket) and CAS-writes exactly that value. Two consequences the cascade below
// depends on, and neither is incidental:
//
//   - d1 <= h1 <= m1, because alignDown with a wider bucket lands lower.
//   - each fence is a bucket start for every tier finer than the one it belongs
//     to, so a range that ends at one fence and a range that begins there meet
//     without a gap and without overlapping.
//
// A zero means "no rollup_state row" — a series the rollup has never reached,
// whose data is therefore entirely in raw.
type watermarks struct{ m1, h1, d1 int64 }

// roundSeries is one probe.round.ok series and everything the scan needs about it.
type roundSeries struct {
	id, cutoff         int64
	wm                 watermarks
	monitorID, agentID string
}

const roundSeriesQuery = `
	SELECT s.id, s.monitor_id, s.agent_id, s.purge_cutoff,
	       COALESCE(m1.last_ts, 0), COALESCE(h1.last_ts, 0), COALESCE(d1.last_ts, 0)
	  FROM series s
	  LEFT JOIN rollup_state m1 ON m1.resolution='1m' AND m1.series_id = s.id
	  LEFT JOIN rollup_state h1 ON h1.resolution='1h' AND h1.series_id = s.id
	  LEFT JOIN rollup_state d1 ON d1.resolution='1d' AND d1.series_id = s.id
	 WHERE s.kind = '` + RoundOKKind + `' AND `

// loadRoundSeries reads the in-scope round.ok series with their rollup fences and
// purge cutoffs in one SQLite query. Everything after this comes from the data
// plane.
func (s *Store) loadRoundSeries(ctx context.Context, scope string, scopeArgs []any) ([]roundSeries, error) {
	rows, err := s.db.Read().QueryContext(ctx, roundSeriesQuery+scope, scopeArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []roundSeries
	for rows.Next() {
		var rs roundSeries
		if err := rows.Scan(&rs.id, &rs.monitorID, &rs.agentID, &rs.cutoff,
			&rs.wm.m1, &rs.wm.h1, &rs.wm.d1); err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}

// scanAvailability walks one series over [lo, until), handing every (bucket
// start, rounds, ok rounds) triple to sink. The 0/1 series makes this exact at
// any resolution: a tier bucket's Cnt IS the number of verdict rounds and its Sum
// IS the number of available ones, so a coarse tier loses granularity but never
// accuracy.
//
// It reads from the coarsest tier that suits the window down to raw, cascading at
// the rollup fences: from the day tier that is 1d over [lo, d1), 1h over [d1, h1),
// 1m over [h1, m1) and raw over [m1, until). Splitting per series rather than at
// one global fence means a brand-new series with no watermark reads entirely from
// raw while every established series still reads the cheap aggregate.
//
// Every boundary is clamped monotonically into [lo, until]. That is the guard
// against a watermark that has been rewound (ingest and the rollup's parent-rewind
// protocol both do it): the worst a clamp can produce is an empty range, i.e. a
// gap, and a gap under-counts. Double counting is the failure that must be
// impossible, because it inflates Rounds against a real OKRounds and invents
// downtime that never happened.
//
// The window's leading edge is quantised UP to the starting tier's bucket width,
// since a bucket is included by its START: at the day tier a "1y" window is the
// last 365 whole days, not the last 31,536,000 seconds. Callers choosing a tier
// per window (see availabilityScans) are choosing that precision.
func (s *Store) scanAvailability(ctx context.Context, sid, lo, until, now int64,
	wm watermarks, sink func(ts, cnt int64, sum float64)) error {

	if lo >= until {
		return nil
	}
	table, raw := pickTierFor(until-lo, lo, now, s.retention)
	if raw {
		// pickTierFor answered "samples". NEVER route that through tierOf, whose
		// default arm returns the DAY tier — raw has no tsstore.Tier at all.
		return s.scanRawAvailability(ctx, sid, lo, until, sink)
	}

	// The ladder from the chosen tier down to the finest, coarsest first.
	type step struct {
		tier  tsstore.Tier
		fence int64
	}
	var ladder []step
	switch table {
	case "rollup_1d":
		ladder = append(ladder, step{tsstore.TierD1, wm.d1})
		fallthrough
	case "rollup_1h":
		ladder = append(ladder, step{tsstore.TierH1, wm.h1})
		fallthrough
	default: // "rollup_1m"
		ladder = append(ladder, step{tsstore.TierM1, wm.m1})
	}

	from := lo
	for _, st := range ladder {
		hi := clampRange(st.fence, from, until)
		if hi > from {
			buckets, err := s.ts.ReadBuckets(ctx, st.tier, sid, from, hi)
			if err != nil {
				return err
			}
			for _, b := range buckets {
				sink(b.TS, b.Cnt, b.Sum)
			}
		}
		from = hi
	}
	return s.scanRawAvailability(ctx, sid, from, until, sink)
}

// scanRawAvailability is the cascade's tail: individual samples, each one round.
func (s *Store) scanRawAvailability(ctx context.Context, sid, from, until int64,
	sink func(ts, cnt int64, sum float64)) error {

	if until <= from {
		return nil
	}
	samples, err := s.ts.RawRange(ctx, sid, from, until, 0)
	if err != nil {
		return err
	}
	for _, smp := range samples {
		sink(smp.TS, 1, smp.Value)
	}
	return nil
}

// clampRange pins x into [lo, hi]. Used on every cascade boundary so the ranges
// can only shrink, never overlap.
func clampRange(x, lo, hi int64) int64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// addRounds folds one scanned triple into an accumulator. The 0/1 sum is exact in
// both float64 and the bucket encoding; the rounding is defensive only.
func (a *AvailabilityRatio) addRounds(cnt int64, sum float64) {
	a.Rounds += cnt
	a.OKRounds += int64(sum + 0.5)
}

// availability sums each in-scope round.ok series over [since, until), per
// (monitor, agent) so several config generations of one pair fold into one
// continuous history.
func (s *Store) availability(ctx context.Context, scope string, scopeArgs []any, since, until int64) ([]AvailabilityRatio, error) {
	series, err := s.loadRoundSeries(ctx, scope, scopeArgs)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()

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
		if err := s.scanAvailability(ctx, rs.id, lo, until, now, rs.wm,
			func(_, cnt int64, sum float64) { agg.addRounds(cnt, sum) }); err != nil {
			return nil, err
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

// ---- the public status page's breakdown ----

// DailyCells is how many UTC days AvailabilityBreakdownForSite reports, one cell
// per day, oldest first. UTC rather than any viewer's timezone because a single
// cached payload serves every reader on earth — and because the day tier's
// buckets are already epoch-day aligned, so the coarse end of the scan drops
// straight into a cell.
const DailyCells = 90

// TargetBreakdown is one target's published reliability: a ratio per requested
// window plus the daily strip.
type TargetBreakdown struct {
	// Windows is parallel to the requested window list. An entry with Rounds == 0
	// reached no verdict at all in that window; it is "unknown", not 0%.
	Windows []AvailabilityRatio
	// Days holds DailyCells availability totals, oldest first. Rounds == 0 means
	// the day reached no verdict at all. Keeping the counts instead of throwing
	// them away lets public readers distinguish a percentage backed by three
	// probes from one backed by thousands without running another scan.
	Days []AvailabilityRatio
}

// SiteAvailabilityBreakdown is every target's breakdown for one site.
type SiteAvailabilityBreakdown struct {
	// DayFrom is the Unix start of the first daily cell (UTC midnight).
	DayFrom int64
	Targets map[string]TargetBreakdown
}

// availabilityScans groups the requested windows so one pass over the data plane
// answers all of them.
//
// The naive shape — one scan per window — re-reads the recent past once per
// window, and the recent past is exactly where the fine tiers live: five windows
// would cost roughly 7,000 buckets per series where three cost 4,000. The grouping
// is by the resolution a window deserves rather than by convenience:
//
//	<= 24h    minute buckets. The headline figure; an hour of slop at the leading
//	          edge would be 4% of the window.
//	<= 90d    hour buckets, and the same pass fills the daily strip. An hour of
//	          slop is 0.6% of a week and less of anything longer.
//	beyond    day buckets. Only the day tier is retained forever, and a day of
//	          slop is 0.3% of a year.
//
// Each group's scan runs over the widest window it holds; scanAvailability then
// picks the tier from that width, so the table above is a consequence of
// pickTier's own ladder rather than a second, drifting copy of it.
func availabilityScans(until int64, windows []time.Duration, dayFrom int64) []availScan {
	groups := []struct {
		max time.Duration
		day bool
	}{
		{max: 24 * time.Hour},
		{max: 90 * 24 * time.Hour, day: true},
		{max: 1<<63 - 1},
	}
	scans := make([]availScan, len(groups))
	for i, g := range groups {
		scans[i] = availScan{lo: until, carriesDays: g.day}
		for w, d := range windows {
			if d <= g.max && (i == 0 || d > groups[i-1].max) {
				scans[i].windows = append(scans[i].windows, w)
				if start := until - int64(d/time.Second); start < scans[i].lo {
					scans[i].lo = start
				}
			}
		}
	}
	// The daily strip may reach further back than the 90d window's own start;
	// whichever is older sets that scan's floor.
	for i := range scans {
		if scans[i].carriesDays && dayFrom < scans[i].lo {
			scans[i].lo = dayFrom
		}
	}
	return scans
}

// availScan is one pass over a series: a range, the window indexes it answers,
// and whether it also fills the daily strip.
type availScan struct {
	lo          int64
	windows     []int
	carriesDays bool
}

// AvailabilityBreakdownForSite returns, per target, one availability ratio per
// requested window plus a DailyCells-long strip of UTC-day ratios — everything
// the public status page publishes about a target's history, from one scan of the
// site's round.ok series.
//
// Windows are ROLLING (the last 7×24h, not the last 7 whole days) while the strip
// is day-aligned, so the 90d figure and the sum of the 90 cells can differ by up
// to the fraction of today that has elapsed. That is deliberate: a rolling figure
// is what "availability over the last week" means, and a day-aligned bar is what a
// reader can point at.
func (s *Store) AvailabilityBreakdownForSite(ctx context.Context, siteID string,
	until time.Time, windows []time.Duration) (SiteAvailabilityBreakdown, error) {

	untilSec := until.Unix()
	dayFrom := alignDown(untilSec, 86400) - int64(DailyCells-1)*86400
	out := SiteAvailabilityBreakdown{DayFrom: dayFrom, Targets: map[string]TargetBreakdown{}}

	series, err := s.loadRoundSeries(ctx, `s.site_id = ?`, []any{siteID})
	if err != nil {
		return SiteAvailabilityBreakdown{}, err
	}
	now := time.Now().Unix()
	scans := availabilityScans(untilSec, windows, dayFrom)

	// Accumulated per TARGET across every Agent and every config generation — the
	// public page publishes a target's reliability, not one Agent's view of it.
	type acc struct {
		windows []AvailabilityRatio
		days    []AvailabilityRatio
	}
	accs := map[string]*acc{}

	for _, rs := range series {
		a := accs[rs.monitorID]
		if a == nil {
			a = &acc{windows: make([]AvailabilityRatio, len(windows)), days: make([]AvailabilityRatio, DailyCells)}
			accs[rs.monitorID] = a
		}
		for _, sc := range scans {
			lo := sc.lo
			if rs.cutoff > lo {
				lo = rs.cutoff
			}
			if lo >= untilSec || (len(sc.windows) == 0 && !sc.carriesDays) {
				continue
			}
			// Window starts are captured per scan so the sink stays a plain
			// range check rather than recomputing them per bucket.
			starts := make([]int64, len(sc.windows))
			for i, w := range sc.windows {
				starts[i] = untilSec - int64(windows[w]/time.Second)
			}
			carriesDays := sc.carriesDays
			err := s.scanAvailability(ctx, rs.id, lo, untilSec, now, rs.wm,
				func(ts, cnt int64, sum float64) {
					for i, w := range sc.windows {
						if ts >= starts[i] {
							a.windows[w].addRounds(cnt, sum)
						}
					}
					// The scan may start before the strip because its 90d window is
					// rolling while the cells start at a UTC midnight. Check the
					// lower bound before dividing: Go truncates negative integer
					// division toward zero, so a timestamp up to one day before
					// dayFrom would otherwise alias into cell zero.
					if carriesDays && ts >= dayFrom {
						if idx := int((ts - dayFrom) / 86400); idx >= 0 && idx < DailyCells {
							a.days[idx].addRounds(cnt, sum)
						}
					}
				})
			if err != nil {
				return SiteAvailabilityBreakdown{}, err
			}
		}
	}

	for monitorID, a := range accs {
		tb := TargetBreakdown{
			Windows: make([]AvailabilityRatio, len(windows)),
			Days:    make([]AvailabilityRatio, DailyCells),
		}
		for i := range a.windows {
			r := a.windows[i]
			r.MonitorID = monitorID
			tb.Windows[i] = r.withRatio()
		}
		for i := range a.days {
			if a.days[i].Rounds == 0 {
				continue // zero rounds is a hole in the bar, not an outage
			}
			tb.Days[i] = a.days[i].withRatio()
		}
		out.Targets[monitorID] = tb
	}
	return out, nil
}
