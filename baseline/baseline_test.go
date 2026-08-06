package baseline

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The baseline's contract: buckets are server-local and tile the timeline without
// gaps or overlaps; a fold is idempotent and recomputes a touched bucket whole; a
// band is a median across DAYS, not a pool; and below the cold-start gate there is
// no band at all rather than a confident guess from three samples.

type bh struct {
	t   *testing.T
	db  *store.DB
	svc *Service
	ctx context.Context
}

func newBH(t *testing.T) *bh {
	t.Helper()
	db := storetest.Open(t)
	h := &bh{t: t, db: db, svc: New(db), ctx: context.Background()}
	h.exec(`INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	h.exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents) VALUES('mg','site_default','Default',1,0,1)`)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	        VALUES('t_icmp','site_default','mg','icmp','Router','192.168.1.1','{}',1,1)`)
	return h
}

func (h *bh) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(h.ctx, q, args...); err != nil {
		h.t.Fatalf("exec %q: %v", q, err)
	}
}

// seriesFor creates (or returns) the ICMP RTT series for the target at the given
// generation.
func (h *bh) seriesFor(configSerial int) int64 {
	h.t.Helper()
	h.exec(`INSERT OR IGNORE INTO series(agent_id, site_id, monitor_id, kind, target, layer, unit, config_serial)
	        VALUES('agent_a','site_default','t_icmp','probe.icmp.rtt_ms','192.168.1.1','internet','ms',?)`, configSerial)
	var id int64
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT id FROM series WHERE monitor_id='t_icmp' AND kind='probe.icmp.rtt_ms' AND config_serial=?`,
		configSerial).Scan(&id); err != nil {
		h.t.Fatalf("series id: %v", err)
	}
	return id
}

// samples writes n samples of value v starting at ts, one second apart.
func (h *bh) samples(seriesID, ts int64, n int, v float64) {
	h.t.Helper()
	for i := range n {
		h.exec(`INSERT OR REPLACE INTO samples(series_id, ts, value) VALUES(?,?,?)`, seriesID, ts+int64(i), v)
	}
}

// localNoon returns noon local time d days before today, which lands squarely
// inside daypart 2 in every timezone.
func localNoon(daysAgo int) time.Time {
	n := time.Now().In(time.Local).AddDate(0, 0, -daysAgo)
	return time.Date(n.Year(), n.Month(), n.Day(), 12, 0, 0, 0, time.Local)
}

// weekdayNoons returns the n most recent past weekday noons. Tests seed weekdays
// specifically because weekday and weekend are DIFFERENT buckets — seeding "the
// last five days" would split across both and produce a band over whichever class
// happened to win, which is a fixture that fails on Mondays.
func weekdayNoons(n int) []time.Time {
	out := make([]time.Time, 0, n)
	for d := 1; len(out) < n && d <= WindowDays; d++ {
		t := localNoon(d)
		if _, _, weekend := BucketOf(t.Unix()); !weekend {
			out = append(out, t)
		}
	}
	return out
}

// weekdayNoonKey is the band the tests ask about: a weekday's midday bucket.
func weekdayNoonKey() BandKey {
	return BandKey{TargetID: "t_icmp", MetricKind: "probe.icmp.rtt_ms", Daypart: 2, Weekend: false}
}

func TestBucketOfSplitsTheLocalDay(t *testing.T) {
	day := time.Date(2026, 3, 4, 0, 0, 0, 0, time.Local) // a Wednesday
	for _, c := range []struct {
		hour int
		want int
	}{{0, 0}, {5, 0}, {6, 1}, {11, 1}, {12, 2}, {17, 2}, {18, 3}, {23, 3}} {
		ts := day.Add(time.Duration(c.hour) * time.Hour).Unix()
		gotDay, gotPart, weekend := BucketOf(ts)
		if gotPart != c.want {
			t.Fatalf("hour %d → daypart %d, want %d", c.hour, gotPart, c.want)
		}
		if gotDay != 20260304 {
			t.Fatalf("hour %d → day %d, want 20260304", c.hour, gotDay)
		}
		if weekend {
			t.Fatalf("hour %d: Wednesday reported as weekend", c.hour)
		}
	}
	sat := time.Date(2026, 3, 7, 9, 0, 0, 0, time.Local)
	if _, _, weekend := BucketOf(sat.Unix()); !weekend {
		t.Fatal("Saturday not reported as weekend")
	}
}

func TestBucketRangesTileWithoutOverlap(t *testing.T) {
	// Every bucket's end must be exactly the next bucket's start, and every instant
	// inside a range must agree with BucketOf about which bucket it is in. A range
	// built by ADDING six hours instead of asking the calendar breaks both of these
	// across a DST transition, folding the same samples into two buckets.
	start := time.Date(2026, 3, 1, 3, 0, 0, 0, time.Local).Unix()
	cursor := start
	for i := range 40 {
		s, e := bucketRange(cursor)
		if e <= s {
			t.Fatalf("step %d: degenerate range [%d, %d)", i, s, e)
		}
		_, wantPart, wantWeekend := BucketOf(s)
		for _, probe := range []int64{s, s + (e-s)/2, e - 1} {
			_, part, weekend := BucketOf(probe)
			if part != wantPart || weekend != wantWeekend {
				t.Fatalf("step %d: ts %d is in daypart %d but its range claims %d", i, probe, part, wantPart)
			}
		}
		ns, _ := bucketRange(e)
		if ns != e {
			t.Fatalf("step %d: bucket ends at %d but the next one starts at %d", i, e, ns)
		}
		cursor = e
	}
}

func TestFoldComputesQuantilesAndIsIdempotent(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	noon := localNoon(1)
	// 100 samples: ninety at 10ms, ten at 500ms. Nearest-rank p50 = 10, p95 = 500.
	h.samples(sid, noon.Unix(), 90, 10)
	h.samples(sid, noon.Unix()+90, 10, 500)

	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("fold: %v", err)
	}
	var cnt int
	var p50, p95 float64
	row := h.db.Read().QueryRowContext(h.ctx,
		`SELECT cnt, p50, p95 FROM baseline_daily WHERE target_id='t_icmp' AND metric_kind='probe.icmp.rtt_ms'`)
	if err := row.Scan(&cnt, &p50, &p95); err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	if cnt != 100 || p50 != 10 || p95 != 500 {
		t.Fatalf("got cnt=%d p50=%v p95=%v, want 100 / 10 / 500", cnt, p50, p95)
	}

	// A second fold with no new samples must change nothing at all.
	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("second fold: %v", err)
	}
	var rows int
	if err := h.db.Read().QueryRowContext(h.ctx, `SELECT COUNT(*) FROM baseline_daily`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("%d baseline rows after a second fold, want 1", rows)
	}
}

func TestFoldRecomputesATouchedBucketWhole(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	noon := localNoon(1)
	h.samples(sid, noon.Unix(), 50, 10)
	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("fold: %v", err)
	}
	// More samples in the SAME bucket. Quantiles are not incrementally updatable, so
	// the bucket has to be recomputed from all 100 — not merged from the old row.
	h.samples(sid, noon.Unix()+50, 50, 20)
	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("second fold: %v", err)
	}
	var cnt int
	var p50 float64
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT cnt, p50 FROM baseline_daily`).Scan(&cnt, &p50); err != nil {
		t.Fatalf("read: %v", err)
	}
	if cnt != 100 || p50 != 10 {
		t.Fatalf("got cnt=%d p50=%v, want the whole bucket recomputed (100 / 10)", cnt, p50)
	}
}

func TestFoldSkipsStaleGenerationSeries(t *testing.T) {
	h := newBH(t)
	// The target has advanced to generation 2; generation 1's history describes a
	// different target and must stop being folded. This join IS the invalidation
	// mechanism — there is no explicit clear-on-edit path.
	old := h.seriesFor(1)
	h.exec(`UPDATE probe_tasks SET config_serial=2 WHERE id='t_icmp'`)
	h.samples(old, localNoon(1).Unix(), 100, 10)
	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("fold: %v", err)
	}
	var rows int
	if err := h.db.Read().QueryRowContext(h.ctx, `SELECT COUNT(*) FROM baseline_daily`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("folded %d rows from an obsolete generation, want 0", rows)
	}
}

// seedDays writes one full midday bucket per weekday for the n most recent
// weekdays, each with `per` samples of the given value, and folds them.
func (h *bh) seedDays(sid int64, days int, per int, v float64) {
	h.t.Helper()
	for _, noon := range weekdayNoons(days) {
		h.samples(sid, noon.Unix(), per, v)
	}
	if err := h.svc.Fold(h.ctx); err != nil {
		h.t.Fatalf("fold: %v", err)
	}
}

func (h *bh) noonBand() (Band, bool) {
	h.t.Helper()
	key := weekdayNoonKey()
	got, err := h.svc.Bands(h.ctx, "agent_a", map[BandKey]int{key: 1})
	if err != nil {
		h.t.Fatalf("bands: %v", err)
	}
	b, ok := got[key]
	return b, ok
}

func TestColdStartGateWithholdsABand(t *testing.T) {
	// Two days is below MinDays: a median needs three points to be a median, and a
	// "normal" from two days is not one. Separate harnesses because a fold never
	// reaches behind its watermark — seeding older history into an already-folded
	// database would be testing the fixture, not the gate.
	short := newBH(t)
	short.seedDays(short.seriesFor(1), MinDays-1, 100, 30)
	if _, ok := short.noonBand(); ok {
		t.Fatalf("produced a band from %d days, MinDays is %d", MinDays-1, MinDays)
	}

	full := newBH(t)
	full.seedDays(full.seriesFor(1), MinDays, 100, 30)
	if _, ok := full.noonBand(); !ok {
		t.Fatalf("no band after %d days of 100 samples each", MinDays)
	}
}

func TestFoldDoesNotReachBehindItsWatermark(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	noons := weekdayNoons(2)
	// Fold the recent day first, then deliver the older one — a WAL replay arriving
	// after the fold has already passed that point.
	h.samples(sid, noons[0].Unix(), 100, 30)
	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("fold: %v", err)
	}
	h.samples(sid, noons[1].Unix(), 100, 30)
	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("second fold: %v", err)
	}
	var rows int
	if err := h.db.Read().QueryRowContext(h.ctx, `SELECT COUNT(*) FROM baseline_daily`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	// Deliberate: late data is overwhelmingly outage-period data, which a median
	// across days is built to discount anyway, so no rewind machinery exists. This
	// test is here so that stays a decision rather than a surprise.
	if rows != 1 {
		t.Fatalf("%d baseline rows, want 1 — the backfilled day must not have been folded", rows)
	}
}

func TestColdStartGateWithholdsOnThinEvidence(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	// Enough days, far too few samples: an Agent that was online for a few seconds a
	// day has not established what normal looks like.
	h.seedDays(sid, MinDays+2, 3, 30)
	if _, ok := h.noonBand(); ok {
		t.Fatal("produced a band from a handful of samples")
	}
}

func TestBandIsAMedianAcrossDaysNotAPool(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	// Four ordinary weekdays at 20ms, then one catastrophic day with ten times the
	// samples at 500ms. A count-weighted pool would let that single day define
	// "normal" for the next fortnight, which is exactly the failure this design
	// exists to avoid.
	noons := weekdayNoons(5)
	for _, noon := range noons[1:] {
		h.samples(sid, noon.Unix(), 100, 20)
	}
	h.samples(sid, noons[0].Unix(), 1000, 500)
	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("fold: %v", err)
	}
	b, ok := h.noonBand()
	if !ok {
		t.Fatal("no band")
	}
	if b.P50 != 20 || b.P95 != 20 {
		t.Fatalf("band = (%v, %v), want the ordinary days' 20 — one bad day must not move it", b.P50, b.P95)
	}
	if b.Days != 5 {
		t.Fatalf("band spans %d days, want 5", b.Days)
	}
}

func TestWeekdayAndWeekendAreDifferentBaselines(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	// A household's Saturday is not its Tuesday, which is the entire reason the
	// bucket key carries a weekend flag. Weekday history must not answer a weekend
	// question.
	h.seedDays(sid, MinDays+1, 100, 30)
	weekendKey := weekdayNoonKey()
	weekendKey.Weekend = true
	got, err := h.svc.Bands(h.ctx, "agent_a", map[BandKey]int{weekendKey: 1})
	if err != nil {
		t.Fatalf("bands: %v", err)
	}
	if _, ok := got[weekendKey]; ok {
		t.Fatal("answered a weekend question with weekday history")
	}
}

func TestBandsIgnoreAnotherGeneration(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	h.seedDays(sid, MinDays+1, 100, 30)
	if _, ok := h.noonBand(); !ok {
		t.Fatal("setup: no band at generation 1")
	}
	// Asking about generation 2 must not be answered with generation 1's history.
	_, daypart, weekend := BucketOf(localNoon(1).Unix())
	key := BandKey{TargetID: "t_icmp", MetricKind: "probe.icmp.rtt_ms", Daypart: daypart, Weekend: weekend}
	got, err := h.svc.Bands(h.ctx, "agent_a", map[BandKey]int{key: 2})
	if err != nil {
		t.Fatalf("bands: %v", err)
	}
	if _, ok := got[key]; ok {
		t.Fatal("answered a generation-2 question with generation-1 history")
	}
}

func TestPruneDropsRowsPastTheHorizon(t *testing.T) {
	h := newBH(t)
	h.exec(`INSERT INTO baseline_daily(target_id, agent_id, metric_kind, day, daypart, weekend,
	        config_serial, cnt, p50, p95, updated_at)
	        VALUES('t_icmp','agent_a','probe.icmp.rtt_ms',?,2,0,1,100,10,20,?)`,
		dayCutoff(time.Now(), WindowDays+30), time.Now().UTC())
	h.exec(`INSERT INTO baseline_daily(target_id, agent_id, metric_kind, day, daypart, weekend,
	        config_serial, cnt, p50, p95, updated_at)
	        VALUES('t_icmp','agent_a','probe.icmp.rtt_ms',?,3,0,1,100,10,20,?)`,
		dayCutoff(time.Now(), 1), time.Now().UTC())
	h.exec(`INSERT INTO baseline_state(series_id, last_ts) VALUES(9999, 1)`) // orphan

	if err := h.svc.Prune(h.ctx, DefaultKeepDays); err != nil {
		t.Fatalf("prune: %v", err)
	}
	var rows, states int
	if err := h.db.Read().QueryRowContext(h.ctx, `SELECT COUNT(*) FROM baseline_daily`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if err := h.db.Read().QueryRowContext(h.ctx, `SELECT COUNT(*) FROM baseline_state`).Scan(&states); err != nil {
		t.Fatalf("count states: %v", err)
	}
	if rows != 1 {
		t.Fatalf("%d daily rows survived, want only the recent one", rows)
	}
	if states != 0 {
		t.Fatalf("%d orphan watermarks survived", states)
	}
}

func TestTargetBaselineReportsLearningHonestly(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	view, err := h.svc.TargetBaseline(h.ctx, "t_icmp", "agent_a", "")
	if err != nil {
		t.Fatalf("target baseline: %v", err)
	}
	if !view.Learning || view.ObservedDays != 0 {
		t.Fatalf("a fresh target reports learning=%v days=%d, want true/0", view.Learning, view.ObservedDays)
	}
	if view.MetricKind != "probe.icmp.rtt_ms" {
		t.Fatalf("defaulted to metric %q", view.MetricKind)
	}

	h.seedDays(sid, MinDays+1, 100, 30)
	view, err = h.svc.TargetBaseline(h.ctx, "t_icmp", "agent_a", "")
	if err != nil {
		t.Fatalf("target baseline: %v", err)
	}
	if view.Learning {
		t.Fatal("still reports learning after the gate was met")
	}
	if view.ObservedDays != MinDays+1 {
		t.Fatalf("observed %d days, want %d", view.ObservedDays, MinDays+1)
	}
	if len(view.Bands) != 1 {
		t.Fatalf("%d bands, want the one noon bucket that has data", len(view.Bands))
	}
}

func TestQuantileSortedIsNearestRank(t *testing.T) {
	vals := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if got := quantileSorted(vals, 0.50); got != 5 {
		t.Fatalf("p50 = %v, want 5", got)
	}
	if got := quantileSorted(vals, 0.95); got != 10 {
		t.Fatalf("p95 = %v, want 10", got)
	}
	if got := quantileSorted([]float64{42}, 0.95); got != 42 {
		t.Fatalf("single-sample p95 = %v, want 42", got)
	}
	if got := quantileSorted(nil, 0.5); got != 0 {
		t.Fatalf("empty p50 = %v, want 0", got)
	}
}

func TestFoldExcludesFutureSamples(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	noons := weekdayNoons(1)
	h.samples(sid, noons[0].Unix(), 100, 30)
	// An Agent whose clock runs ahead by a week. Folding these would park the
	// watermark in the future and stall the baseline until wall time caught up.
	future := time.Now().Add(7 * 24 * time.Hour).Unix()
	h.samples(sid, future, 50, 999)

	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("fold: %v", err)
	}
	var last int64
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT last_ts FROM baseline_state WHERE series_id=?`, sid).Scan(&last); err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	if last >= future {
		t.Fatalf("watermark = %d, want it left behind the future samples at %d", last, future)
	}
	// And no baseline row was created from them.
	var rows int
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT COUNT(*) FROM baseline_daily WHERE p50 = 999`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("%d baseline rows built from future samples", rows)
	}

	// The real point: honest samples arriving afterwards must still fold.
	h.samples(sid, weekdayNoons(2)[1].Unix(), 100, 30)
	h.samples(sid, noons[0].Unix()+100, 100, 30)
	if err := h.svc.Fold(h.ctx); err != nil {
		t.Fatalf("second fold: %v", err)
	}
	var cnt int
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT cnt FROM baseline_daily WHERE p50 = 30 LIMIT 1`).Scan(&cnt); err != nil {
		t.Fatalf("read: %v", err)
	}
	if cnt < 200 {
		t.Fatalf("bucket holds %d samples; the fold stalled behind the bad clock", cnt)
	}
}

func TestFutureDailyRowsAreNeitherReadNorKept(t *testing.T) {
	h := newBH(t)
	sid := h.seriesFor(1)
	h.seedDays(sid, MinDays+1, 100, 30)
	if b, ok := h.noonBand(); !ok || b.P50 != 30 {
		t.Fatalf("setup: band = %+v, ok = %v", b, ok)
	}
	// A row dated in the future, as an older build or a since-corrected clock
	// could have left behind. A baseline is a claim about the past.
	h.exec(`INSERT INTO baseline_daily(target_id, agent_id, metric_kind, day, daypart, weekend,
	        config_serial, cnt, p50, p95, updated_at)
	        VALUES('t_icmp','agent_a','probe.icmp.rtt_ms',?,2,0,1,10000,9999,9999,?)`,
		dayCutoff(time.Now(), -3), time.Now().UTC())

	// Asserted on the DAY COUNT, not the median: four honest days at 30ms plus one
	// absurd future day still medians to 30, so a value check here would pass while
	// the row was quietly being counted as evidence.
	b, ok := h.noonBand()
	if !ok {
		t.Fatal("no band")
	}
	if b.Days != MinDays+1 {
		t.Fatalf("band spans %d days, want %d — a future row was counted as evidence", b.Days, MinDays+1)
	}
	if err := h.svc.Prune(h.ctx, DefaultKeepDays); err != nil {
		t.Fatalf("prune: %v", err)
	}
	var future int
	if err := h.db.Read().QueryRowContext(h.ctx,
		`SELECT COUNT(*) FROM baseline_daily WHERE p50 = 9999`).Scan(&future); err != nil {
		t.Fatalf("count: %v", err)
	}
	if future != 0 {
		t.Fatal("the future row survived pruning; the day floor can never reach it")
	}
}
