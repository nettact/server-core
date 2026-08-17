// Package baseline learns what "normal" looks like for each monitored target
// (ALERT-003), so the fault engine can call a target degraded relative to its own
// history instead of against a number somebody had to guess.
//
// The product reason for existing: a fixed latency threshold is either wrong for
// the LAN gateway or wrong for the transcontinental target, never right for both.
// 20ms → 100ms on a router is an incident; 300ms → 350ms across an ocean is a
// Tuesday. The only honest reference is the target's own past — and past
// separated by time of day, because a household's 21:00 is not its 04:00.
//
// # Why a separate table rather than a derived metric series
//
// The obvious alternative — emit a per-round p95 as a derived series and let the
// existing rollup tiers carry it, the way probe.round.ok works — does not exist
// here. An Agent reports one aggregate per probe cycle (mean/min/max/jitter), not
// the individual echo RTTs, so there is no in-round distribution to take a
// percentile of. Round-level latency IS the raw sample. What is actually missing
// is history: percentiles need raw observations, raw retention is two days, and
// the rollup tiers store (cnt, total, vmin, vmax) — a percentile of bucket
// averages is not a percentile of observations.
//
// So this package folds the raw tier into one row per (target, agent, metric,
// local calendar day, daypart) on an hourly cadence, and the 14-day band is an
// aggregate over at most 14 of those rows. Hourly keeps every fold well inside
// raw retention; daily rows keep pruning a date comparison.
//
// # Why median-across-days rather than pooling the samples
//
// A band is the MEDIAN of the matching daily p50s and of the matching daily p95s,
// not a count-weighted pool. Pooling lets one bad day — an outage, an ISP
// incident, a neighbour's torrent — drag the reference for the next fortnight,
// which defeats the entire point of comparing a target to "its usual self". A
// median across days survives up to half the window being anomalous.
//
// # Robust statistics, not learning
//
// Deliberately no model, no EWMA of an EWMA, no ML. Every judgement this feeds
// has to be explainable in one sentence to somebody who did not ask for it
// ("now 180ms, usually about 40ms at this hour"), and that requires the reference
// to be a number a human could have computed by hand from data the console can
// show them.
package baseline

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/tsstore"
)

const (
	// WindowDays is how far back a band looks. Two weeks covers both weekend
	// patterns without letting a month-old line change dominate the present.
	WindowDays = 14
	// MinDays and MinSamples are the cold-start gate: below either, the target has
	// no baseline and NOTHING is judged. Three days is the shortest span that can
	// have a median at all (and the shortest that has ever seen the same daypart
	// three times); 60 samples is a floor against a daypart that only caught a few
	// rounds because the Agent was mostly offline.
	//
	// A weekend daypart can therefore take until the second weekend to open. That
	// is correct rather than unfortunate: a "normal" derived from one Saturday is
	// not a normal.
	MinDays    = 3
	MinSamples = 60
	// DefaultKeepDays is the retention Prune applies: the window plus the
	// in-progress day.
	DefaultKeepDays = WindowDays + 1
)

// foldSeriesBatch is how many series share one write transaction. Same reasoning
// as the rollup worker: one transaction for the whole catch-up would hold the
// single SQLite write connection for minutes after downtime, stalling every
// write-handle query (and much of the HTTP API) behind it.
const foldSeriesBatch = 32

// foldBucketCap bounds how many day-buckets one series may fold per run, so a
// first fold over a fully-populated raw tier cannot run unboundedly. The
// watermark stops at the cap and the next run continues from there.
const foldBucketCap = 64

// Band is one (target, agent, metric, daypart-class) historical reference: the
// median across the window's days of that day-bucket's p50 and p95, plus how much
// evidence is behind it. A Band only ever exists when the cold-start gate passed,
// so a caller holding one may judge against it without re-checking.
type Band struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	// Days is how many daily rows the medians were taken over, Samples the total
	// raw observations behind them. Both are shown to the user rather than kept
	// internal: "usually about 40ms" is a claim, and this is its evidence.
	Days    int `json:"days"`
	Samples int `json:"samples"`
}

// BandKey identifies one band within an agent's request. The agent is not part of
// the key because a lookup is always scoped to one agent — the same target probed
// from two vantage points has two genuinely different normals.
type BandKey struct {
	TargetID   string
	MetricKind string
	Daypart    int
	Weekend    bool
}

// Service reads and maintains the baseline tables.
type Service struct {
	db *store.DB
	ts tsstore.SeriesStore // raw-sample reads; the fold's writes stay in SQLite
}

func New(db *store.DB, ts tsstore.SeriesStore) *Service { return &Service{db: db, ts: ts} }

// ---- bucketing ----

// BucketOf places a sample timestamp into its baseline bucket: the server-local
// calendar day (yyyymmdd), the 6-hour daypart within it, and whether that day is
// a weekend.
//
// This is the single definition of bucketing. The fold job and the detector both
// call it, and both call it on the SAMPLE's timestamp rather than on the wall
// clock — a WAL replay delivering yesterday evening's rounds must be compared
// against yesterday evening's normal, not against right now's.
//
// Server-local, not UTC: there is no timezone concept anywhere in the product,
// and both deployment shapes (the desktop app, a self-hosted box in the household
// it watches) sit in the user's own timezone — which is the only frame in which
// "evening peak" means anything. A server that changes timezone shifts the
// boundaries once; the rolling window reconverges within a fortnight.
func BucketOf(ts int64) (day, daypart int, weekend bool) {
	t := time.Unix(ts, 0).In(time.Local)
	day = t.Year()*10000 + int(t.Month())*100 + t.Day()
	daypart = t.Hour() / 6
	wd := t.Weekday()
	return day, daypart, wd == time.Saturday || wd == time.Sunday
}

// bucketRange returns the half-open [start, end) unix range of the bucket
// containing ts.
//
// The end is built from the calendar (hour h+6, which time.Date normalizes past
// midnight) rather than by adding six hours to the start. On a DST transition
// those differ, and adding a duration would make one bucket's range overlap the
// next one's — folding the same samples into two buckets, one of which BucketOf
// disagrees with. Deriving both edges the same way BucketOf does keeps the two
// definitions incapable of disagreeing.
func bucketRange(ts int64) (start, end int64) {
	t := time.Unix(ts, 0).In(time.Local)
	h := (t.Hour() / 6) * 6
	s := time.Date(t.Year(), t.Month(), t.Day(), h, 0, 0, 0, time.Local)
	e := time.Date(t.Year(), t.Month(), t.Day(), h+6, 0, 0, 0, time.Local)
	return s.Unix(), e.Unix()
}

// dayCutoff is the oldest yyyymmdd a band or a prune still accepts, counted back
// from now in local days.
func dayCutoff(now time.Time, days int) int {
	t := now.In(time.Local).AddDate(0, 0, -days)
	return t.Year()*10000 + int(t.Month())*100 + t.Day()
}

// ---- metric selection ----

// FoldKinds are the metric kinds a baseline is maintained for. This is the
// superset: it includes kinds that are only ever displayed (jitter) alongside the
// ones a detector judges, because the console's baseline band on a chart is worth
// having for metrics that would make a noisy trigger.
//
// probe.nat.rtt_ms is absent on purpose. NAT probes run on a 30-minute cadence, so
// a daypart holds a handful of samples — below any honest cold-start gate, and a
// "normal" from twelve observations is a rumour.
var FoldKinds = []string{
	string(telemetry.ICMPRTTms),
	string(telemetry.ICMPJitter),
	string(telemetry.ICMPLoss),
	string(telemetry.DNSResolve),
	string(telemetry.HTTPLat),
	string(telemetry.TCPConnectMs),
}

// LatencyKind maps a probe kind to the ONE latency metric its degradation
// detector judges, or "" for a kind with no meaningful latency baseline.
//
// One metric per kind rather than several: the detector's contract is "K
// consecutive rounds outside the band", and a streak whose membership can be
// decided by whichever of three metrics happened to breach this round is not a
// streak anybody can reason about. The single metric is in every case the one the
// probe's own duration is measured by.
func LatencyKind(probeKind string) string {
	switch probeKind {
	case "icmp", "gateway":
		return string(telemetry.ICMPRTTms)
	case "http":
		return string(telemetry.HTTPLat)
	case "tcp":
		return string(telemetry.TCPConnectMs)
	case "dns":
		return string(telemetry.DNSResolve)
	}
	return ""
}

// LossKind maps a probe kind to the loss metric its loss-degradation detector
// judges. Only ICMP-family probes report a continuous loss percentage; every
// other kind's availability is already a boolean, and "the boolean is boolean
// more often than usual" is not a degradation, it is an outage.
func LossKind(probeKind string) string {
	if probeKind == "icmp" || probeKind == "gateway" {
		return string(telemetry.ICMPLoss)
	}
	return ""
}

// ---- fold ----

// foldSeries is one series eligible for folding.
type foldSeries struct {
	seriesID     int64
	targetID     string
	agentID      string
	metricKind   string
	configSerial int
	lastTS       int64
}

// Fold advances every eligible series' baseline from the raw sample tier. Safe to
// call often; each run's work is bounded by the buckets that received samples
// since the last one.
//
// A bucket is recomputed WHOLE whenever it receives a new sample, because
// quantiles are not incrementally updatable — there is no (cnt, total) trick for
// a median. The hourly cadence makes that cheap: the in-progress bucket is
// recomputed six times over its life and then never again.
//
// Samples arriving strictly behind the watermark are only picked up if their
// bucket is later touched again by a fresh sample. That is the deliberate limit
// of not implementing a rewind: late data is overwhelmingly outage-period data,
// which the median-across-days aggregate is designed to discount anyway.
func (s *Service) Fold(ctx context.Context) error {
	series, err := s.eligibleSeries(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for start := 0; start < len(series); start += foldSeriesBatch {
		end := start + foldSeriesBatch
		if end > len(series) {
			end = len(series)
		}
		if err := s.foldBatch(ctx, series[start:end], now); err != nil {
			return err
		}
	}
	return nil
}

// eligibleSeries lists the probe-bound series worth a baseline, joined to their
// target's CURRENT generation.
//
// That join is the whole invalidation story. Series identity includes
// config_serial, so a material target edit starts a fresh series; the old
// generation stops matching this join, stops being folded, and its rows age out
// of the window on their own. Nothing has to remember to clear a baseline when a
// target's address changes, which is the kind of thing that gets forgotten.
func (s *Service) eligibleSeries(ctx context.Context) ([]foldSeries, error) {
	q := `
		SELECT s.id, s.monitor_id, s.agent_id, s.kind, s.config_serial, COALESCE(bs.last_ts, 0)
		FROM series s
		JOIN probe_tasks pt ON pt.id = s.monitor_id AND pt.config_serial = s.config_serial
		LEFT JOIN baseline_state bs ON bs.series_id = s.id
		WHERE s.monitor_id <> '' AND pt.enabled = 1
		  AND s.kind IN (` + placeholders(len(FoldKinds)) + `)
		ORDER BY s.id`
	args := make([]any, 0, len(FoldKinds))
	for _, k := range FoldKinds {
		args = append(args, k)
	}
	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []foldSeries
	for rows.Next() {
		var f foldSeries
		if err := rows.Scan(&f.seriesID, &f.targetID, &f.agentID, &f.metricKind, &f.configSerial, &f.lastTS); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// foldBatch folds one batch of series inside a single write transaction.
func (s *Service) foldBatch(ctx context.Context, batch []foldSeries, now time.Time) error {
	return s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		for _, f := range batch {
			if err := s.foldOne(ctx, wtx, f, now); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
}

func (s *Service) foldOne(ctx context.Context, tx store.Executor, f foldSeries, now time.Time) error {
	// Bounded above by server time, and this is load-bearing rather than tidy.
	// Sample timestamps come from the AGENT's clock. One running ahead writes
	// samples stamped in the future; folding them would park this series'
	// watermark there, and every subsequent honest sample would then fail
	// `ts > last_ts` — the baseline would stop advancing until wall time caught
	// up with the bad clock, which for a badly-set machine can be months.
	//
	// Excluding them instead is self-healing: they stay ABOVE the watermark, so
	// they fold normally once they are no longer in the future (or age out of raw
	// retention first, which is equally fine).
	horizon := now.Unix()
	tail, err := s.ts.RawRange(ctx, f.seriesID, f.lastTS+1, horizon+1, 0)
	if err != nil {
		return err
	}
	if len(tail) == 0 {
		return nil // nothing new; leave the watermark where it is
	}
	minTS, maxTS := tail[0].TS, tail[len(tail)-1].TS

	watermark := maxTS
	cursor, _ := bucketRange(minTS)
	for i := 0; i < foldBucketCap; i++ {
		bStart, bEnd := bucketRange(cursor)
		if bEnd <= bStart {
			break // defensive: a degenerate range would loop forever
		}
		if err := s.foldBucket(ctx, tx, f, bStart, bEnd, now); err != nil {
			return err
		}
		if bEnd > maxTS {
			break
		}
		cursor = bEnd
		if i == foldBucketCap-1 {
			// Hit the cap. Stop at this bucket's edge rather than claiming the whole
			// range was folded; the next run resumes here.
			watermark = bEnd - 1
		}
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO baseline_state(series_id, last_ts) VALUES(?,?)
		 ON CONFLICT(series_id) DO UPDATE SET last_ts=excluded.last_ts`,
		f.seriesID, watermark)
	return err
}

// foldBucket recomputes one day-bucket's quantiles from EVERY raw sample in it
// — the full window, not just the tail above the watermark: an incremental
// re-fold of a partially-folded bucket must not overwrite a 100-sample
// statistic with one computed from the 50 new arrivals — and upserts the row.
// An emptied bucket (every sample aged out of raw retention between two runs)
// leaves any existing row alone: a stale reference is better than silently
// dropping a day out of the median.
func (s *Service) foldBucket(ctx context.Context, tx store.Executor, f foldSeries, bStart, bEnd int64, now time.Time) error {
	samples, err := s.ts.RawRange(ctx, f.seriesID, bStart, bEnd, 0)
	if err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	values := make([]float64, len(samples))
	for i, smp := range samples {
		values[i] = smp.Value
	}
	sort.Float64s(values)
	day, daypart, weekend := BucketOf(bStart)
	weekendInt := 0
	if weekend {
		weekendInt = 1
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO baseline_daily(target_id, agent_id, metric_kind, day, daypart, weekend,
		    config_serial, cnt, p50, p95, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, agent_id, metric_kind, day, daypart) DO UPDATE SET
		    weekend=excluded.weekend, config_serial=excluded.config_serial,
		    cnt=excluded.cnt, p50=excluded.p50, p95=excluded.p95, updated_at=excluded.updated_at`,
		f.targetID, f.agentID, f.metricKind, day, daypart, weekendInt,
		f.configSerial, len(values), quantileSorted(values, 0.50), quantileSorted(values, 0.95), now)
	return err
}

// quantileSorted is nearest-rank over an already-sorted slice, the same
// convention metrics.Summarize uses so a p95 means one thing product-wide.
func quantileSorted(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted))*q+0.999999) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---- prune ----

// Prune drops daily rows past the retention horizon and watermarks whose series no
// longer exists. baseline_daily rows for a deleted target go with the target
// (ON DELETE CASCADE); this covers the rest.
func (s *Service) Prune(ctx context.Context, keepDays int) error {
	if keepDays <= 0 {
		keepDays = DefaultKeepDays
	}
	cutoff := dayCutoff(time.Now(), keepDays)
	return s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		if _, err := wtx.ExecContext(ctx, `DELETE FROM baseline_daily WHERE day < ?`, cutoff); err != nil {
			return nil, err
		}
		// Rows dated in the future are impossible data, not old data: the day bound
		// above can never reach them, so without this they would sit in the table
		// forever. The fold refuses to create them, but one written by an earlier
		// build (or by a clock since corrected) has to be cleaned up rather than
		// merely ignored by readers.
		if _, err := wtx.ExecContext(ctx,
			`DELETE FROM baseline_daily WHERE day > ?`, dayCutoff(time.Now(), -1)); err != nil {
			return nil, err
		}
		if _, err := wtx.ExecContext(ctx,
			`DELETE FROM baseline_state WHERE series_id NOT IN (SELECT id FROM series)`); err != nil {
			return nil, err
		}
		return nil, nil
	})
}

// ---- read ----

// dailyRow is one baseline_daily row as the aggregators consume it.
type dailyRow struct {
	targetID     string
	metricKind   string
	day          int
	daypart      int
	weekend      bool
	configSerial int
	cnt          int
	p50, p95     float64
}

// Bands answers the ingest hot path: for every requested key (at the target's
// current config serial), the historical band, or absent when the cold-start gate
// has not been met.
//
// One query for the whole batch, on the READ pool. Ingest resolves everything it
// can before opening its write transaction, and this follows that rule — a
// baseline lookup must never be a reason the single write connection is held
// longer.
func (s *Service) Bands(ctx context.Context, agentID string, reqs map[BandKey]int) (map[BandKey]Band, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	targets := make([]string, 0, len(reqs))
	seen := map[string]bool{}
	for k := range reqs {
		if !seen[k.TargetID] {
			seen[k.TargetID] = true
			targets = append(targets, k.TargetID)
		}
	}
	now := time.Now()
	rows, err := s.queryDaily(ctx, agentID, targets, dayCutoff(now, WindowDays), dayCutoff(now, 0))
	if err != nil {
		return nil, err
	}
	// Group by key, keeping only rows whose generation matches what the caller is
	// asking about. A previous generation's history describes a different target.
	grouped := map[BandKey][]dailyRow{}
	for _, r := range rows {
		k := BandKey{TargetID: r.targetID, MetricKind: r.metricKind, Daypart: r.daypart, Weekend: r.weekend}
		serial, want := reqs[k]
		if !want || r.configSerial != serial {
			continue
		}
		grouped[k] = append(grouped[k], r)
	}
	out := make(map[BandKey]Band, len(grouped))
	for k, rs := range grouped {
		if b, ok := aggregate(rs); ok {
			out[k] = b
		}
	}
	return out, nil
}

// DaypartBand is one time-of-day class's band, as the console renders it.
type DaypartBand struct {
	Weekend bool    `json:"weekend"`
	Daypart int     `json:"daypart"`
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	Days    int     `json:"days"`
	Samples int     `json:"samples"`
}

// TargetBaselineView is what one target's baseline looks like from one agent: a
// band per time-of-day class, plus enough evidence for the console to say either
// "usually about 40ms at this hour" or "still learning" without inventing either.
type TargetBaselineView struct {
	TargetID   string `json:"target_id"`
	AgentID    string `json:"agent_id"`
	MetricKind string `json:"metric_kind"`
	// Learning is true when NO time-of-day class has met the cold-start gate yet.
	// Individual classes can still be missing from Bands while this is false — a
	// target watched since Wednesday has weekday bands and no weekend ones, and
	// saying so beats extrapolating one from the other.
	Learning bool `json:"learning"`
	// ObservedDays is how many distinct calendar days contributed anything, which
	// is the number a progress indicator should show against MinDays.
	ObservedDays int           `json:"observed_days"`
	MinDays      int           `json:"min_days"`
	Bands        []DaypartBand `json:"bands"`
}

// TargetBaseline answers the console's baseline query for one (target, agent).
// metricKind may be empty, in which case the target's own judged latency metric
// is used. Returns sql.ErrNoRows for an unknown target.
func (s *Service) TargetBaseline(ctx context.Context, targetID, agentID, metricKind string) (TargetBaselineView, error) {
	var probeKind string
	var configSerial int
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT kind, config_serial FROM probe_tasks WHERE id=?`, targetID).Scan(&probeKind, &configSerial); err != nil {
		return TargetBaselineView{}, err
	}
	if metricKind == "" {
		metricKind = LatencyKind(probeKind)
	}
	out := TargetBaselineView{
		TargetID: targetID, AgentID: agentID, MetricKind: metricKind,
		Learning: true, MinDays: MinDays, Bands: []DaypartBand{},
	}
	if metricKind == "" {
		return out, nil // probe kind has no baseline concept; not an error
	}
	now := time.Now()
	rows, err := s.queryDaily(ctx, agentID, []string{targetID}, dayCutoff(now, WindowDays), dayCutoff(now, 0))
	if err != nil {
		return TargetBaselineView{}, err
	}
	grouped := map[BandKey][]dailyRow{}
	days := map[int]bool{}
	for _, r := range rows {
		if r.metricKind != metricKind || r.configSerial != configSerial {
			continue
		}
		days[r.day] = true
		k := BandKey{TargetID: r.targetID, MetricKind: r.metricKind, Daypart: r.daypart, Weekend: r.weekend}
		grouped[k] = append(grouped[k], r)
	}
	out.ObservedDays = len(days)
	for k, rs := range grouped {
		b, ok := aggregate(rs)
		if !ok {
			continue
		}
		out.Learning = false
		out.Bands = append(out.Bands, DaypartBand{
			Weekend: k.Weekend, Daypart: k.Daypart,
			P50: b.P50, P95: b.P95, Days: b.Days, Samples: b.Samples,
		})
	}
	sort.Slice(out.Bands, func(i, j int) bool {
		if out.Bands[i].Weekend != out.Bands[j].Weekend {
			return !out.Bands[i].Weekend
		}
		return out.Bands[i].Daypart < out.Bands[j].Daypart
	})
	return out, nil
}

func (s *Service) queryDaily(ctx context.Context, agentID string, targets []string, sinceDay, untilDay int) ([]dailyRow, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	// Bounded at BOTH ends. The lower bound is the rolling window; the upper one
	// keeps a row dated in the future — written before the fold learned to refuse
	// them, or by a clock that has since been corrected — out of the median. A
	// baseline is a claim about the past, and nothing that has not happened yet
	// belongs in it.
	q := `SELECT target_id, metric_kind, day, daypart, weekend, config_serial, cnt, p50, p95
	      FROM baseline_daily
	      WHERE agent_id=? AND day>=? AND day<=? AND target_id IN (` + placeholders(len(targets)) + `)`
	args := make([]any, 0, len(targets)+3)
	args = append(args, agentID, sinceDay, untilDay)
	for _, t := range targets {
		args = append(args, t)
	}
	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dailyRow
	for rows.Next() {
		var r dailyRow
		var weekend int
		if err := rows.Scan(&r.targetID, &r.metricKind, &r.day, &r.daypart, &weekend,
			&r.configSerial, &r.cnt, &r.p50, &r.p95); err != nil {
			return nil, err
		}
		r.weekend = weekend == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// aggregate collapses one bucket's daily rows into a band, or reports that the
// cold-start gate has not been met.
//
// The medians are taken across DAYS, unweighted. A day that produced ten times the
// samples is still one day: weighting by count would let one long evening of
// congestion outvote a fortnight of ordinary ones, which is the failure mode this
// whole design exists to avoid.
func aggregate(rs []dailyRow) (Band, bool) {
	if len(rs) < MinDays {
		return Band{}, false
	}
	samples := 0
	p50s := make([]float64, 0, len(rs))
	p95s := make([]float64, 0, len(rs))
	for _, r := range rs {
		samples += r.cnt
		p50s = append(p50s, r.p50)
		p95s = append(p95s, r.p95)
	}
	if samples < MinSamples {
		return Band{}, false
	}
	sort.Float64s(p50s)
	sort.Float64s(p95s)
	return Band{P50: median(p50s), P95: median(p95s), Days: len(rs), Samples: samples}, true
}

// median of an already-sorted, non-empty slice; the lower of the two middles for
// an even count, so the result is always an observed daily value rather than a
// synthesized average of two.
func median(sorted []float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[(len(sorted)-1)/2]
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
