package tsstore

import (
	"context"
	"math"
	"sort"
	"strconv"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

// msRange maps a half-open second range to prom's inclusive ms range.
// toSec <= 0 means unbounded above.
func msRange(fromSec, toSec int64) (mint, maxt int64) {
	mint = fromSec * 1000
	if toSec <= 0 {
		return mint, math.MaxInt64
	}
	return mint, toSec*1000 - 1
}

func sidMatchers(name string, sid int64) []*labels.Matcher {
	return []*labels.Matcher{
		labels.MustNewMatcher(labels.MatchEqual, "__name__", name),
		labels.MustNewMatcher(labels.MatchEqual, "sid", strconv.FormatInt(sid, 10)),
	}
}

// iterSeries streams one series' (t, v) pairs in [mint, maxt] ascending
// through fn; fn returning false stops early.
func (p *Prom) iterSeries(ctx context.Context, inst int, name string, sid, mint, maxt int64, fn func(t int64, v float64) bool) error {
	q, err := p.dbs[inst].Querier(mint, maxt)
	if err != nil {
		return err
	}
	defer q.Close()
	ss := q.Select(ctx, true, nil, sidMatchers(name, sid)...)
	for ss.Next() {
		it := ss.At().Iterator(nil)
		for it.Next() != chunkenc.ValNone {
			t, v := it.At()
			if t < mint || t > maxt {
				continue
			}
			if !fn(t, v) {
				return ss.Err()
			}
		}
		if it.Err() != nil {
			return it.Err()
		}
	}
	return ss.Err()
}

// RawRange implements SeriesStore.
func (p *Prom) RawRange(ctx context.Context, sid, fromSec, toSec int64, limit int) ([]Sample, error) {
	mint, maxt := msRange(fromSec, toSec)
	var out []Sample
	err := p.iterSeries(ctx, instRaw, "s", sid, mint, maxt, func(t int64, v float64) bool {
		out = append(out, Sample{TS: t / 1000, Value: v})
		return limit <= 0 || len(out) < limit
	})
	return out, err
}

// RawLatest implements SeriesStore.
func (p *Prom) RawLatest(ctx context.Context, sids []int64, fromSec int64) (map[int64]Sample, error) {
	out := make(map[int64]Sample, len(sids))
	mint, maxt := msRange(fromSec, 0)
	for _, sid := range sids {
		var last Sample
		found := false
		err := p.iterSeries(ctx, instRaw, "s", sid, mint, maxt, func(t int64, v float64) bool {
			last = Sample{TS: t / 1000, Value: v}
			found = true
			return true
		})
		if err != nil {
			return nil, err
		}
		if found {
			out[sid] = last
		}
	}
	return out, nil
}

// RawExtent implements SeriesStore.
func (p *Prom) RawExtent(ctx context.Context, sid int64) (minSec, maxSec int64, ok bool, err error) {
	err = p.iterSeries(ctx, instRaw, "s", sid, math.MinInt64/2, math.MaxInt64, func(t int64, _ float64) bool {
		sec := t / 1000
		if !ok || sec < minSec {
			minSec = sec
		}
		if !ok || sec > maxSec {
			maxSec = sec
		}
		ok = true
		return true
	})
	return
}

// RawCount implements SeriesStore.
func (p *Prom) RawCount(ctx context.Context, sid, fromSec, toSec int64) (int64, error) {
	var mint, maxt int64
	if fromSec == 0 && toSec == 0 {
		mint, maxt = math.MinInt64/2, math.MaxInt64
	} else {
		mint, maxt = msRange(fromSec, toSec)
	}
	var n int64
	err := p.iterSeries(ctx, instRaw, "s", sid, mint, maxt, func(int64, float64) bool {
		n++
		return true
	})
	return n, err
}

// foldBuckets collapses k-encoded samples of ONE name into per-window
// (maxMS, value) — the newest ms in each window is the bucket's current value.
type foldEntry struct {
	ms  int64
	val float64
}

func (p *Prom) foldName(ctx context.Context, inst int, name string, sid int64, width, fromSec, toSec int64) (map[int64]foldEntry, error) {
	mint, maxt := msRange(fromSec, toSec)
	out := map[int64]foldEntry{}
	err := p.iterSeries(ctx, inst, name, sid, mint, maxt, func(t int64, v float64) bool {
		start := t / 1000 / width * width
		if e, ok := out[start]; !ok || t > e.ms {
			out[start] = foldEntry{ms: t, val: v}
		}
		return true
	})
	return out, err
}

// ReadBuckets implements SeriesStore.
func (p *Prom) ReadBuckets(ctx context.Context, tier Tier, sid, fromSec, toSec int64) ([]Bucket, error) {
	width := tier.BucketSeconds()
	inst := instOf(tier)
	// A bucket starting just below toSec may carry k-slots up to
	// (start+width)*1000-1; extend the scan so its repairs are seen, then keep
	// only bucket STARTS inside [fromSec, toSec).
	scanTo := toSec
	if scanTo > 0 {
		scanTo += width
	}
	cnts, err := p.foldName(ctx, inst, "cnt", sid, width, fromSec, scanTo)
	if err != nil {
		return nil, err
	}
	sums, err := p.foldName(ctx, inst, "sum", sid, width, fromSec, scanTo)
	if err != nil {
		return nil, err
	}
	out := make([]Bucket, 0, len(cnts))
	for start, c := range cnts {
		if start < fromSec || (toSec > 0 && start >= toSec) {
			continue
		}
		s, ok := sums[start]
		if !ok {
			continue // half a pair cannot commit; a torn window means tombstoned sum — skip
		}
		out = append(out, Bucket{TS: start, Cnt: int64(c.val + 0.5), Sum: s.val})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	return out, nil
}

// BucketExtent implements SeriesStore.
func (p *Prom) BucketExtent(ctx context.Context, tier Tier, sid int64) (minSec, maxSec int64, ok bool, err error) {
	width := tier.BucketSeconds()
	err = p.iterSeries(ctx, instOf(tier), "cnt", sid, math.MinInt64/2, math.MaxInt64, func(t int64, _ float64) bool {
		start := t / 1000 / width * width
		if !ok || start < minSec {
			minSec = start
		}
		if !ok || start > maxSec {
			maxSec = start
		}
		ok = true
		return true
	})
	return
}

// bucketMaxMS returns, per bucket start in [fromSec, toSec), the current max
// millisecond timestamp among the window's cnt samples (the k source for
// AppendBuckets).
func (p *Prom) bucketMaxMS(ctx context.Context, tier Tier, sid, fromSec, toSec int64) (map[int64]int64, error) {
	folded, err := p.foldName(ctx, instOf(tier), "cnt", sid, tier.BucketSeconds(), fromSec, toSec)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]int64, len(folded))
	for start, e := range folded {
		out[start] = e.ms
	}
	return out, nil
}
