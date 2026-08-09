package tsstore

import (
	"context"
	"math"
)

// DeleteSeries implements SeriesStore. Tombstones the full time range in all
// four instances; safe only because sids are AUTOINCREMENT and never reused
// (see the schema comment on series.id) — nothing will ever append under a
// deleted sid again, so the interval mask can never swallow live data.
func (p *Prom) DeleteSeries(ctx context.Context, sids []int64) error {
	for _, sid := range sids {
		if err := p.dbs[instRaw].Delete(ctx, math.MinInt64/2, math.MaxInt64, sidMatchers("s", sid)...); err != nil {
			return err
		}
		for _, tier := range []Tier{TierM1, TierH1, TierD1} {
			inst := instOf(tier)
			for _, name := range []string{"cnt", "sum"} {
				if err := p.dbs[inst].Delete(ctx, math.MinInt64/2, math.MaxInt64, sidMatchers(name, sid)...); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// DeleteRawRange implements SeriesStore.
func (p *Prom) DeleteRawRange(ctx context.Context, sid, fromSec, toSec int64) error {
	mint, maxt := msRange(fromSec, toSec)
	return p.dbs[instRaw].Delete(ctx, mint, maxt, sidMatchers("s", sid)...)
}

// DeleteBucketRange implements SeriesStore. Bounds must be bucket-aligned;
// the mask covers every k-slot of every bucket starting in the range.
func (p *Prom) DeleteBucketRange(ctx context.Context, tier Tier, sid, alignedFromSec, alignedToSec int64) error {
	if alignedToSec <= alignedFromSec {
		return nil
	}
	mint, maxt := msRange(alignedFromSec, alignedToSec)
	inst := instOf(tier)
	for _, name := range []string{"cnt", "sum"} {
		if err := p.dbs[inst].Delete(ctx, mint, maxt, sidMatchers(name, sid)...); err != nil {
			return err
		}
	}
	return nil
}
