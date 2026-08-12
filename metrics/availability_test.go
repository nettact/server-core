package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/tsstore"
)

// The availability read is the only aggregation the PUBLIC status page publishes,
// and it is summed across four resolutions that each cover a different slice of
// the same window. So these tests are almost entirely about the seams between
// those slices: every bucket must be counted once, and a bucket counted twice is
// worse than one missed — it inflates Rounds against a real OKRounds and invents
// downtime that never happened.
//
// They fabricate tier buckets directly rather than ingesting raw and rolling up.
// That is not a shortcut around the rollup: tsstore's out-of-order horizon is 75
// hours (tsstore/prom.go oooWindow), so a test that wanted 90 days of history via
// the ingest path could not have it at all. Writing buckets is also what isolates
// the READ contract, which is what changed here.

// availFixture is one probe.round.ok series with direct access to its tiers.
type availFixture struct {
	db  *store.DB
	s   *Store
	sid int64
}

func newAvailFixture(t *testing.T, monitorID string) *availFixture {
	t.Helper()
	db, s := openStore(t)
	ctx := context.Background()

	m := telemetry.Metric{
		TS: time.Now(), Kind: telemetry.MetricKind(RoundOKKind), Target: "1.1.1.1",
		Value: 1, Unit: "", MonitorID: monitorID,
	}
	if _, err := s.EnsureSeries(ctx, "agent_a", "site_default", []telemetry.Metric{m}); err != nil {
		t.Fatalf("EnsureSeries: %v", err)
	}
	var sid int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM series WHERE agent_id='agent_a' AND monitor_id=? AND kind=?`,
		monitorID, RoundOKKind).Scan(&sid); err != nil {
		t.Fatalf("series id: %v", err)
	}
	return &availFixture{db: db, s: s, sid: sid}
}

// putBuckets writes count buckets of `width` seconds starting at `from`, each
// recording cnt rounds of which ok were available. Ascending, so every append is
// in-order and none trips the out-of-order horizon.
func (f *availFixture) putBuckets(t *testing.T, tier tsstore.Tier, from int64, count int, cnt int64, ok float64) {
	t.Helper()
	f.putBucketsVar(t, tier, from, count, func(int64) (int64, float64) { return cnt, ok })
}

// putBucketsVar is putBuckets with the per-bucket values computed from the bucket
// start, for fixtures where some stretch of history was worse than the rest.
func (f *availFixture) putBucketsVar(t *testing.T, tier tsstore.Tier, from int64, count int, val func(ts int64) (int64, float64)) {
	t.Helper()
	width := tier.BucketSeconds()
	bs := make([]tsstore.Bucket, 0, count)
	for i := 0; i < count; i++ {
		ts := from + int64(i)*width
		cnt, ok := val(ts)
		bs = append(bs, tsstore.Bucket{TS: ts, Cnt: cnt, Sum: ok})
	}
	if err := f.s.ts.AppendBuckets(context.Background(), tier, f.sid, bs); err != nil {
		t.Fatalf("AppendBuckets(%v): %v", tier, err)
	}
}

// putRaw writes count raw samples spaced `step` seconds apart from `from`.
func (f *availFixture) putRaw(t *testing.T, from int64, count int, step int64, value float64) {
	t.Helper()
	rs := make([]tsstore.RawSample, 0, count)
	for i := 0; i < count; i++ {
		rs = append(rs, tsstore.RawSample{SID: f.sid, TS: from + int64(i)*step, Value: value})
	}
	res, err := f.s.ts.AppendRaw(context.Background(), rs)
	if err != nil {
		t.Fatalf("AppendRaw: %v", err)
	}
	if res.Dropped > 0 {
		t.Fatalf("AppendRaw dropped %d samples — the fixture is outside the OOO horizon", res.Dropped)
	}
}

// setWatermark parks one tier's rollup fence.
func (f *availFixture) setWatermark(t *testing.T, res string, ts int64) {
	t.Helper()
	if _, err := f.db.ExecContext(context.Background(),
		`INSERT INTO rollup_state(resolution, series_id, last_ts) VALUES(?,?,?)
		 ON CONFLICT(resolution, series_id) DO UPDATE SET last_ts=excluded.last_ts`,
		res, f.sid, ts); err != nil {
		t.Fatalf("set %s watermark: %v", res, err)
	}
}

// TestAvailabilityCascadeCountsEachRoundOnce is the core seam test. The hour tier
// and the minute tier are given OVERLAPPING coverage on purpose: the same wall
// time is described by both, exactly as it is in a live database between rollup
// passes. Only the tier the cascade assigns to that range may be read, so the
// duplicate minute buckets below the hour fence must contribute nothing.
func TestAvailabilityCascadeCountsEachRoundOnce(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Hour)
	until := now.Unix()
	// A ten-day window: wide enough that pickTier chooses the hour tier, so the
	// cascade is h1 -> m1 -> raw and the day fence stays unused.
	since := until - 10*86400
	h1Fence := until - 2*3600 // hour-aligned: `now` is truncated to the hour
	m1Fence := until - 300    // minute-aligned

	// 1h buckets across the whole pre-fence stretch: 10 rounds each, 9 available.
	hours := int((h1Fence - since) / 3600)
	f.putBuckets(t, tsstore.TierH1, since, hours, 10, 9)
	// 1m buckets covering the SAME stretch — the duplicate that must be ignored…
	f.putBuckets(t, tsstore.TierM1, since, hours*60, 10, 9)
	// …and the minute buckets that legitimately serve [h1Fence, m1Fence).
	mins := int((m1Fence - h1Fence) / 60)
	f.putBuckets(t, tsstore.TierM1, h1Fence, mins, 2, 2)
	// Raw tail: five rounds, all up.
	f.putRaw(t, m1Fence, 5, 60, 1)

	f.setWatermark(t, "1h", h1Fence)
	f.setWatermark(t, "1m", m1Fence)

	total, perAgent, err := f.s.AvailabilityForTarget(ctx, "probe_m1", since, until)
	if err != nil {
		t.Fatalf("AvailabilityForTarget: %v", err)
	}

	wantRounds := int64(hours)*10 + int64(mins)*2 + 5
	wantOK := int64(hours)*9 + int64(mins)*2 + 5
	if total.Rounds != wantRounds || total.OKRounds != wantOK {
		t.Fatalf("cascade counted %d/%d rounds, want %d/%d — a seam is double counting or dropping",
			total.OKRounds, total.Rounds, wantOK, wantRounds)
	}
	if len(perAgent) != 1 || perAgent[0].AgentID != "agent_a" {
		t.Fatalf("per-agent breakdown = %+v, want one row for agent_a", perAgent)
	}
	if got, want := total.Ratio, float64(wantOK)/float64(wantRounds); got != want {
		t.Fatalf("ratio = %v, want %v", got, want)
	}
}

// TestAvailabilityRequestedWindowsDiffer proves the three console windows use
// genuinely different lower bounds. The recent day is perfect, days 2-7 have a
// small deficit, and the older part of the month is worse again. A regression
// that reuses the 24h lower bound for every request makes both the ratios and the
// round counts collapse to the same values and fails this test.
func TestAvailabilityRequestedWindowsDiffer(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Hour)
	until := now.Unix()
	since30d := until - 30*86400
	since7d := until - 7*86400
	since24h := until - 24*3600

	f.putBucketsVar(t, tsstore.TierH1, since30d, 30*24, func(ts int64) (int64, float64) {
		switch {
		case ts >= since24h:
			return 60, 60
		case ts >= since7d:
			return 60, 54
		default:
			return 60, 48
		}
	})
	// The 24h query selects the minute tier; mirror the last day's perfect
	// history there, as a live rollup cascade would.
	f.putBuckets(t, tsstore.TierM1, since24h, 24*60, 1, 1)
	f.setWatermark(t, "1h", until)
	f.setWatermark(t, "1m", until)

	result := make(map[time.Duration]AvailabilityRatio)
	for _, window := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour} {
		total, _, err := f.s.AvailabilityForTarget(ctx, "probe_m1", until-int64(window/time.Second), until)
		if err != nil {
			t.Fatalf("AvailabilityForTarget(%s): %v", window, err)
		}
		result[window] = total
	}

	d1 := result[24*time.Hour]
	d7 := result[7*24*time.Hour]
	d30 := result[30*24*time.Hour]
	if !(d1.Rounds < d7.Rounds && d7.Rounds < d30.Rounds) {
		t.Fatalf("round counts did not grow with the window: 24h=%d 7d=%d 30d=%d",
			d1.Rounds, d7.Rounds, d30.Rounds)
	}
	if !(d1.Ratio > d7.Ratio && d7.Ratio > d30.Ratio) {
		t.Fatalf("ratios did not reflect the distinct history: 24h=%v 7d=%v 30d=%v",
			d1.Ratio, d7.Ratio, d30.Ratio)
	}
}

// TestAvailabilityRewoundFenceCannotDoubleCount pins the clamp. Ingest and the
// rollup's parent-rewind protocol both move fences BACKWARDS, so a coarse fence
// ahead of a finer one is a state the reader must survive. The clamp is allowed to
// open a gap (an under-count, which reads as "less evidence"); it must never let
// two tiers describe the same seconds.
func TestAvailabilityRewoundFenceCannotDoubleCount(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Hour)
	until := now.Unix()
	since := until - 10*86400
	// The minute fence has been rewound BEHIND the hour fence — the ordering the
	// cascade normally relies on, inverted.
	h1Fence := until - 2*3600
	m1Fence := until - 6*3600

	hours := int((h1Fence - since) / 3600)
	f.putBuckets(t, tsstore.TierH1, since, hours, 10, 10)
	// Minute buckets that describe the same time as the hour buckets, including
	// the inverted stretch [m1Fence, h1Fence).
	f.putBuckets(t, tsstore.TierM1, since, hours*60, 10, 10)

	f.setWatermark(t, "1h", h1Fence)
	f.setWatermark(t, "1m", m1Fence)

	total, _, err := f.s.AvailabilityForTarget(ctx, "probe_m1", since, until)
	if err != nil {
		t.Fatalf("AvailabilityForTarget: %v", err)
	}
	if want := int64(hours) * 10; total.Rounds != want {
		t.Fatalf("Rounds = %d, want %d (the hour tier alone) — the inverted fence let a range be read twice",
			total.Rounds, want)
	}
}

// TestAvailabilityWithoutRollupStateReadsRaw covers the series the rollup has
// never reached: COALESCE gives it a zero fence for every tier, and every round it
// has is still in raw. The tier buckets present here are unreachable leftovers and
// must not be counted.
func TestAvailabilityWithoutRollupStateReadsRaw(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Minute)
	until := now.Unix()
	since := until - 2*86400 // inside the raw horizon

	f.putRaw(t, since, 48, 3600, 1)
	// Buckets exist but no rollup_state row does; with a zero fence the cascade
	// must not reach them.
	f.putBuckets(t, tsstore.TierM1, since, 100, 7, 7)

	total, _, err := f.s.AvailabilityForTarget(ctx, "probe_m1", since, until)
	if err != nil {
		t.Fatalf("AvailabilityForTarget: %v", err)
	}
	if total.Rounds != 48 || total.OKRounds != 48 {
		t.Fatalf("got %d/%d, want 48/48 from raw alone", total.OKRounds, total.Rounds)
	}
}

// TestAvailabilityPurgeCutoffClampsWindow: a series whose history was purged below
// a cutoff must report only what survives, even when the caller asks for more.
func TestAvailabilityPurgeCutoffClampsWindow(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Hour)
	until := now.Unix()
	since := until - 10*86400
	h1Fence := until - 3600
	cutoff := until - 4*86400

	hours := int((h1Fence - since) / 3600)
	f.putBuckets(t, tsstore.TierH1, since, hours, 1, 1)
	f.setWatermark(t, "1h", h1Fence)
	if _, err := f.db.ExecContext(ctx, `UPDATE series SET purge_cutoff=? WHERE id=?`, cutoff, f.sid); err != nil {
		t.Fatalf("set purge_cutoff: %v", err)
	}

	total, _, err := f.s.AvailabilityForTarget(ctx, "probe_m1", since, until)
	if err != nil {
		t.Fatalf("AvailabilityForTarget: %v", err)
	}
	if want := (h1Fence - cutoff) / 3600; total.Rounds != want {
		t.Fatalf("Rounds = %d, want %d — the window was not clamped to purge_cutoff", total.Rounds, want)
	}
}

// TestAvailabilityNoVerdictStaysAbsent: a window holding no verdict-reaching round
// is "unknown", and unknown must not arrive as 0%.
func TestAvailabilityNoVerdictStaysAbsent(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()

	until := time.Now().UTC().Unix()
	total, perAgent, err := f.s.AvailabilityForTarget(ctx, "probe_m1", until-3600, until)
	if err != nil {
		t.Fatalf("AvailabilityForTarget: %v", err)
	}
	if total.Rounds != 0 || len(perAgent) != 0 {
		t.Fatalf("empty window produced %d rounds / %d agent rows, want none", total.Rounds, len(perAgent))
	}

	site, err := f.s.AvailabilityForSite(ctx, "site_default", until-3600, until)
	if err != nil {
		t.Fatalf("AvailabilityForSite: %v", err)
	}
	if _, ok := site["probe_m1"]; ok {
		t.Fatal("a target with no verdicts appeared in the site map; it must be absent, not 0%")
	}
}

// TestAvailabilityBreakdownWindowsAndDays is the public page's whole payload in one
// assertion: five nested windows and the daily strip, from one scan.
//
// The fixture is what a real rollup would have left behind — the same history
// described at day, hour and minute resolution, each tier consistent with the
// others — because the windows do NOT all read the same tier. A 24h window reads
// minutes and a 1y window reads days, so a fixture that only wrote hour buckets
// would prove nothing about either end.
//
// Two whole days were half down: one 20 days ago (inside 30d/90d/1y) and one 200
// days ago (inside 1y alone). Nested windows dilute a fixed outage, so the useful
// assertion is the absolute deficit each window carries, not its ratio ordering —
// a longer window containing the SAME outage legitimately reads better.
func TestAvailabilityBreakdownWindowsAndDays(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()

	// Minute-aligned so the 24h window is exactly 1440 minute buckets with no
	// raw tail, and the arithmetic below is exact rather than approximate.
	now := time.Now().UTC().Truncate(time.Minute)
	until := now.Unix()
	dayStart := alignDown(until, 86400)
	h1Fence := alignDown(until, 3600)
	windows := []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour, 90 * 24 * time.Hour, 365 * 24 * time.Hour}

	// One round per minute, always up, except two half-down days.
	badDays := map[int64]bool{dayStart - 20*86400: true, dayStart - 200*86400: true}
	dayOf := func(ts int64) int64 { return alignDown(ts, 86400) }

	// A year of day buckets: [dayStart-364d, dayStart).
	f.putBucketsVar(t, tsstore.TierD1, dayStart-364*86400, 364, func(ts int64) (int64, float64) {
		if badDays[ts] {
			return 1440, 720
		}
		return 1440, 1440
	})
	// The last 40 days at hour resolution, up to the hour fence.
	hours := int((h1Fence - (dayStart - 39*86400)) / 3600)
	f.putBucketsVar(t, tsstore.TierH1, dayStart-39*86400, hours, func(ts int64) (int64, float64) {
		if badDays[dayOf(ts)] {
			return 60, 30
		}
		return 60, 60
	})
	// The last three days at minute resolution, up to now.
	f.putBuckets(t, tsstore.TierM1, dayStart-2*86400, int((until-(dayStart-2*86400))/60), 1, 1)

	f.setWatermark(t, "1d", dayStart)
	f.setWatermark(t, "1h", h1Fence)
	f.setWatermark(t, "1m", until)

	br, err := f.s.AvailabilityBreakdownForSite(ctx, "site_default", now, windows)
	if err != nil {
		t.Fatalf("AvailabilityBreakdownForSite: %v", err)
	}
	tb, ok := br.Targets["probe_m1"]
	if !ok {
		t.Fatal("target missing from the breakdown")
	}
	if len(tb.Windows) != len(windows) {
		t.Fatalf("got %d windows, want %d", len(tb.Windows), len(windows))
	}
	if len(tb.Days) != DailyCells {
		t.Fatalf("got %d day cells, want %d", len(tb.Days), DailyCells)
	}
	if want := dayStart - int64(DailyCells-1)*86400; br.DayFrom != want {
		t.Fatalf("DayFrom = %d, want %d", br.DayFrom, want)
	}

	// 24h reads the MINUTE tier: exactly the last 1440 buckets, all up.
	if tb.Windows[0].Rounds != 1440 || tb.Windows[0].Ratio != 1 {
		t.Fatalf("24h = %d/%d rounds (ratio %v), want 1440/1440 at ratio 1 — the minute tier was not read",
			tb.Windows[0].OKRounds, tb.Windows[0].Rounds, tb.Windows[0].Ratio)
	}
	if tb.Windows[1].Ratio != 1 {
		t.Fatalf("7d ratio = %v, want 1 (no bad day within a week)", tb.Windows[1].Ratio)
	}
	// Each window's ABSOLUTE deficit says exactly which outages it reached.
	deficit := func(i int) int64 { return tb.Windows[i].Rounds - tb.Windows[i].OKRounds }
	if got := deficit(2); got != 720 {
		t.Fatalf("30d deficit = %d, want 720 (the day 20 days back)", got)
	}
	if got := deficit(3); got != 720 {
		t.Fatalf("90d deficit = %d, want 720 (the same single day)", got)
	}
	if got := deficit(4); got != 1440 {
		t.Fatalf("1y deficit = %d, want 1440 (both half-down days) — the day tier was not reached", got)
	}
	// Same outage, wider window: the ratio must improve. This is what proves the
	// windows are genuinely different lengths and not five copies of one scan.
	if !(tb.Windows[3].Ratio > tb.Windows[2].Ratio) {
		t.Fatalf("90d ratio %v should dilute the same outage better than 30d %v",
			tb.Windows[3].Ratio, tb.Windows[2].Ratio)
	}

	// The strip: the cell 20 days back is half down, its neighbour is perfect, and
	// the stretch before any hour buckets existed is honestly empty.
	bad := DailyCells - 1 - 20
	if tb.Days[bad].Rounds == 0 || tb.Days[bad].Ratio != 0.5 {
		t.Fatalf("day cell %d = %v, want 0.5", bad, tb.Days[bad])
	}
	if tb.Days[bad].Rounds != 1440 || tb.Days[bad].OKRounds != 720 {
		t.Fatalf("day cell %d = %d/%d rounds, want 720/1440", bad,
			tb.Days[bad].OKRounds, tb.Days[bad].Rounds)
	}
	if tb.Days[bad-1].Rounds == 0 || tb.Days[bad-1].Ratio != 1 {
		t.Fatalf("day cell %d = %v, want 1", bad-1, tb.Days[bad-1])
	}
	if tb.Days[DailyCells-1].Rounds == 0 {
		t.Fatal("today's cell has no rounds but today has data")
	}
	if tb.Days[0].Rounds != 0 {
		t.Fatalf("day cell 0 = %v, want no rounds — the hour tier does not reach back that far", tb.Days[0])
	}
}

// TestAvailabilityBreakdownDailyStripExcludesPreviousUTCDate pins the lower
// edge of the day strip. At 01:00 UTC the rolling 90d scan starts 23 hours
// before Days[0]. Hour buckets in that overlap still belong to the rolling
// window, but must not alias into day cell zero when integer division truncates
// a negative duration toward zero.
func TestAvailabilityBreakdownDailyStripExcludesPreviousUTCDate(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()

	now := time.Date(2026, 8, 11, 1, 0, 0, 0, time.UTC)
	until := now.Unix()
	dayStart := alignDown(until, 86400)
	dayFrom := dayStart - int64(DailyCells-1)*86400
	scanFrom := until - 90*86400

	// The 23 hours before the strip are all down; every hour inside the strip is
	// up. The rolling 90d figure must see both stretches.
	f.putBucketsVar(t, tsstore.TierH1, scanFrom, int((until-scanFrom)/3600), func(ts int64) (int64, float64) {
		if ts < dayFrom {
			return 60, 0
		}
		return 60, 60
	})
	f.setWatermark(t, "1h", until)
	f.setWatermark(t, "1m", until)

	br, err := f.s.AvailabilityBreakdownForSite(ctx, "site_default", now,
		[]time.Duration{90 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("AvailabilityBreakdownForSite: %v", err)
	}
	tb := br.Targets["probe_m1"]
	if tb.Windows[0].Ratio >= 1 {
		t.Fatalf("rolling 90d ratio = %v, want the preceding failed hours included", tb.Windows[0].Ratio)
	}
	if got := tb.Days[0]; got.Rounds != 1440 || got.OKRounds != 1440 || got.Ratio != 1 {
		t.Fatalf("day cell 0 = %+v, want exactly its 1440 successful in-strip rounds", got)
	}
}

// TestAvailabilityBreakdownYoungDeploymentLeavesHoles: a deployment younger than
// the strip must show a short bar, not a fabricated perfect one. A day with no
// verdict is nil — the same "unknown is not 0%" rule the windows follow.
func TestAvailabilityBreakdownYoungDeploymentLeavesHoles(t *testing.T) {
	f := newAvailFixture(t, "probe_m1")
	ctx := context.Background()

	now := time.Now().UTC()
	until := now.Unix()
	dayStart := alignDown(until, 86400)
	h1Fence := alignDown(until, 3600)

	// Three days of history, nothing before it.
	for ts := dayStart - 2*86400; ts < h1Fence; ts += 3600 {
		f.putBuckets(t, tsstore.TierH1, ts, 1, 4, 4)
	}
	f.setWatermark(t, "1h", h1Fence)
	f.setWatermark(t, "1m", h1Fence)

	br, err := f.s.AvailabilityBreakdownForSite(ctx, "site_default", now,
		[]time.Duration{24 * time.Hour, 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("AvailabilityBreakdownForSite: %v", err)
	}
	tb := br.Targets["probe_m1"]
	for i := 0; i < DailyCells-3; i++ {
		if tb.Days[i].Rounds != 0 {
			t.Fatalf("day cell %d = %v, want no rounds — there was no deployment yet", i, tb.Days[i])
		}
	}
	if tb.Days[DailyCells-2].Rounds == 0 {
		t.Fatal("yesterday's cell has no rounds but it has data")
	}
	// The 1y window reports the rounds that exist rather than claiming a year of
	// them; it must not be silently equal to a full year of coverage.
	if tb.Windows[1].Rounds == 0 {
		t.Fatal("1y window reported no rounds despite three days of history")
	}
}
