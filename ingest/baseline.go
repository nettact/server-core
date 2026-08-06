package ingest

import (
	"github.com/nettact/server-core/baseline"
	"github.com/nettact/server-core/fault"
)

// bandRequests names every historical band this batch's degradation detectors
// will need: one per (target, judged metric, daypart bucket) the rounds touch,
// pinned to the generation the round was produced under.
//
// The bucket comes from each ROUND's own timestamp, never from the wall clock.
// A WAL backfill after a reconnect delivers rounds from hours ago, and comparing
// last night's latency against this morning's normal would be a comparison
// nobody made. (Those rounds are then refused by the detector's freshness gate
// anyway — but the two guards are independent, and this one is what makes the
// LOOKUP honest rather than merely unused.)
func bandRequests(rounds []fault.Round) map[baseline.BandKey]int {
	if len(rounds) == 0 {
		return nil
	}
	reqs := map[baseline.BandKey]int{}
	for i := range rounds {
		r := &rounds[i]
		kinds := fault.DegradationMetricKinds(r.Det, r.Kind)
		if len(kinds) == 0 {
			continue
		}
		_, daypart, weekend := baseline.BucketOf(r.TS)
		for _, k := range kinds {
			reqs[baseline.BandKey{
				TargetID: r.TargetID, MetricKind: k, Daypart: daypart, Weekend: weekend,
			}] = r.ConfigSerial
		}
	}
	if len(reqs) == 0 {
		return nil
	}
	return reqs
}

// attachBaselines hands each round the bands for its own bucket. A round with no
// matching band is left with none, which the detectors read as "still learning"
// and decline to judge.
func attachBaselines(rounds []fault.Round, bands map[baseline.BandKey]baseline.Band) {
	if len(bands) == 0 {
		return
	}
	for i := range rounds {
		r := &rounds[i]
		kinds := fault.DegradationMetricKinds(r.Det, r.Kind)
		if len(kinds) == 0 {
			continue
		}
		_, daypart, weekend := baseline.BucketOf(r.TS)
		for _, k := range kinds {
			b, ok := bands[baseline.BandKey{
				TargetID: r.TargetID, MetricKind: k, Daypart: daypart, Weekend: weekend,
			}]
			if !ok {
				continue
			}
			if r.Baselines == nil {
				r.Baselines = map[string]baseline.Band{}
			}
			r.Baselines[k] = b
		}
	}
}
