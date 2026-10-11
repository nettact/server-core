package routehist

import (
	"encoding/binary"
	"math"
)

// histBuckets is the RTT histogram resolution: half-octave buckets from 0.5 ms
// to 2048 ms (12 octaves × 2), the last bucket also absorbing anything slower.
//
// Why a fixed log-bucket histogram rather than stored samples or a running
// mean: an era can last a year of runs, so samples are out; a mean hides
// exactly the tail a route change tends to move (p95 doubling while p50 holds
// is the common shape of a worse international exit). Fixed boundaries make
// two histograms add bucket by bucket, so an era's distribution is the exact
// merge of its runs no matter how they were batched, and half-octave buckets
// keep a percentile within ~±19% before the min/max clamp — plenty to tell
// 38 ms from 172 ms.
const histBuckets = 24

type histogram struct {
	counts [histBuckets]uint64
	count  uint64
	sum    float64
	min    float64
	max    float64
}

func bucketOf(ms float64) int {
	if ms < 0.5 {
		return 0
	}
	b := int(math.Floor((math.Log2(ms) + 1) * 2))
	if b < 0 {
		return 0
	}
	if b >= histBuckets {
		return histBuckets - 1
	}
	return b
}

// bucketBounds is the [lo, hi) range of bucket b in ms.
func bucketBounds(b int) (float64, float64) {
	return math.Exp2(float64(b)/2 - 1), math.Exp2(float64(b+1)/2 - 1)
}

func (h *histogram) add(ms float64) {
	if math.IsNaN(ms) || math.IsInf(ms, 0) || ms < 0 {
		return
	}
	h.counts[bucketOf(ms)]++
	if h.count == 0 || ms < h.min {
		h.min = ms
	}
	if h.count == 0 || ms > h.max {
		h.max = ms
	}
	h.count++
	h.sum += ms
}

func (h *histogram) merge(o histogram) {
	if o.count == 0 {
		return
	}
	for i := range h.counts {
		h.counts[i] += o.counts[i]
	}
	if h.count == 0 || o.min < h.min {
		h.min = o.min
	}
	if h.count == 0 || o.max > h.max {
		h.max = o.max
	}
	h.count += o.count
	h.sum += o.sum
}

// quantile estimates the q-quantile: find the bucket holding rank q·count,
// interpolate geometrically inside it (the buckets are log-spaced, so linear
// interpolation would bias every estimate upward), and clamp to the exact
// min/max so a narrow distribution never reports a value it never saw.
func (h *histogram) quantile(q float64) float64 {
	if h.count == 0 {
		return 0
	}
	rank := q * float64(h.count)
	var cum float64
	for b, c := range h.counts {
		if c == 0 {
			continue
		}
		if cum+float64(c) >= rank {
			lo, hi := bucketBounds(b)
			if b == 0 {
				lo = h.min
			}
			if b == histBuckets-1 {
				hi = math.Max(hi, h.max)
			}
			frac := (rank - cum) / float64(c)
			if lo <= 0 {
				lo = math.Min(hi, math.Max(h.min, 0.01))
			}
			v := lo * math.Pow(hi/lo, frac)
			return math.Min(math.Max(v, h.min), h.max)
		}
		cum += float64(c)
	}
	return h.max
}

func encodeHist(h histogram) []byte {
	out := make([]byte, 0, histBuckets)
	for _, c := range h.counts {
		out = binary.AppendUvarint(out, c)
	}
	return out
}

// decodeHist restores the bucket counts; count/sum/min/max live in their own
// columns and are filled by the caller.
func decodeHist(b []byte) histogram {
	var h histogram
	r := reader{b: b}
	for i := 0; i < histBuckets && !r.done(); i++ {
		h.counts[i] = r.uvarint()
	}
	return h
}

// RouteRTT is the destination-RTT summary of an era, as the console renders it.
type RouteRTT struct {
	Count int     `json:"count"`
	MinMs float64 `json:"min_ms"`
	MaxMs float64 `json:"max_ms"`
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
}

func (h *histogram) summary() *RouteRTT {
	if h.count == 0 {
		return nil
	}
	return &RouteRTT{
		Count: int(h.count),
		MinMs: round2(h.min), MaxMs: round2(h.max),
		P50Ms: round2(h.quantile(0.5)), P95Ms: round2(h.quantile(0.95)),
	}
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
