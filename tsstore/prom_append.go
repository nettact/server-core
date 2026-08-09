package tsstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
)

// refCache caches storage.SeriesRef per (name, sid) so the hot append path
// skips label hashing. A ref invalidated by head truncation just falls back to
// the labels (Append with a stale ref and labels re-resolves).
type refCache struct {
	mu sync.Mutex
	m  map[refKey]storage.SeriesRef
}

type refKey struct {
	name byte // 's', 'c'(nt), 'u'(sum)
	sid  int64
}

func (c *refCache) init() { c.m = make(map[refKey]storage.SeriesRef) }

func (c *refCache) get(k refKey) storage.SeriesRef {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[k]
}

func (c *refCache) put(k refKey, r storage.SeriesRef) {
	c.mu.Lock()
	c.m[k] = r
	c.mu.Unlock()
}

func rawLabels(sid int64) labels.Labels {
	return labels.FromStrings("__name__", "s", "sid", strconv.FormatInt(sid, 10))
}

func bucketLabels(name string, sid int64) labels.Labels {
	return labels.FromStrings("__name__", name, "sid", strconv.FormatInt(sid, 10))
}

// permanentAppendErr reports whether an append error can NEVER succeed on
// retry: a conflicting value at an existing timestamp, a timestamp outside the
// out-of-order window, or one ahead of the head's bounds. These are dropped
// and counted — failing the batch would withhold the agent's ack and wedge it
// replaying the same packet forever (the sample cannot become appendable by
// waiting). Everything else (I/O, commit) is a real error and fails the batch;
// the agent replays and the exact-duplicate tolerance makes that idempotent.
func permanentAppendErr(err error) bool {
	return errors.Is(err, storage.ErrOutOfOrderSample) ||
		errors.Is(err, storage.ErrDuplicateSampleForTimestamp) ||
		errors.Is(err, storage.ErrTooOldSample) ||
		errors.Is(err, storage.ErrOutOfBounds)
}

// AppendRaw implements SeriesStore.
func (p *Prom) AppendRaw(ctx context.Context, samples []RawSample) (AppendResult, error) {
	if len(samples) == 0 {
		return AppendResult{}, nil
	}
	db := p.dbs[instRaw]
	app := db.Appender(ctx)
	var res AppendResult
	for _, s := range samples {
		k := refKey{name: 's', sid: s.SID}
		ref := p.refs[instRaw].get(k)
		newRef, err := app.Append(ref, rawLabels(s.SID), s.TS*1000, s.Value)
		if err != nil {
			if permanentAppendErr(err) {
				res.Dropped++
				continue
			}
			_ = app.Rollback()
			return AppendResult{}, err
		}
		if newRef != ref {
			p.refs[instRaw].put(k, newRef)
		}
		res.Appended++
	}
	if err := app.Commit(); err != nil {
		return AppendResult{}, err
	}
	return res, nil
}

// AppendBuckets implements SeriesStore: k-encoded, append-only bucket writes.
// The pair (cnt, sum) always carries the SAME millisecond timestamp, written
// from this one code path, so the fold can never see them desynchronized. Any
// error rolls the whole call back — half a bucket pair must never commit.
func (p *Prom) AppendBuckets(ctx context.Context, tier Tier, sid int64, buckets []Bucket) error {
	if len(buckets) == 0 {
		return nil
	}
	p.bucketMu.Lock()
	defer p.bucketMu.Unlock()

	width := tier.BucketSeconds()
	lo, hi := buckets[0].TS, buckets[0].TS
	for _, b := range buckets[1:] {
		if b.TS < lo {
			lo = b.TS
		}
		if b.TS > hi {
			hi = b.TS
		}
	}
	// One read resolves every touched window's current max ms (the k source).
	// cnt and sum are written together, so cnt alone is authoritative.
	maxMS, err := p.bucketMaxMS(ctx, tier, sid, lo, hi+width)
	if err != nil {
		return err
	}

	inst := instOf(tier)
	db := p.dbs[inst]
	app := db.Appender(ctx)
	ckey := refKey{name: 'c', sid: sid}
	ukey := refKey{name: 'u', sid: sid}
	cref := p.refs[inst].get(ckey)
	uref := p.refs[inst].get(ukey)
	for _, b := range buckets {
		if b.TS%width != 0 {
			_ = app.Rollback()
			return errors.New("tsstore: unaligned bucket start")
		}
		ts := b.TS * 1000
		if prev, ok := maxMS[b.TS]; ok && prev+1 > ts {
			ts = prev + 1
		}
		if ts >= (b.TS+width)*1000 {
			// width*1000 rewrites of one bucket — not a state a working system
			// reaches; refuse rather than bleed into the neighbor window.
			_ = app.Rollback()
			return errors.New("tsstore: bucket repair slots exhausted")
		}
		newC, err := app.Append(cref, bucketLabels("cnt", sid), ts, float64(b.Cnt))
		if err != nil {
			_ = app.Rollback()
			if permanentAppendErr(err) {
				return fmt.Errorf("%w: %v", ErrBucketTooOld, err)
			}
			return err
		}
		cref = newC
		newU, err := app.Append(uref, bucketLabels("sum", sid), ts, b.Sum)
		if err != nil {
			_ = app.Rollback()
			if permanentAppendErr(err) {
				return fmt.Errorf("%w: %v", ErrBucketTooOld, err)
			}
			return err
		}
		uref = newU
	}
	if err := app.Commit(); err != nil {
		return err
	}
	p.refs[inst].put(ckey, cref)
	p.refs[inst].put(ukey, uref)
	return nil
}
