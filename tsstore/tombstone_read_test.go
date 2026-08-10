package tsstore

import (
	"context"
	"testing"
)

// TestDeletedSeriesPartialRangeRead reproduces, at the smallest possible size,
// a panic in prometheus v0.313.2's tombstones.Intervals.Add reached through an
// ordinary read: a series that carries ANY tombstone, read over a window that
// trims both the front and the back of a chunk.
//
// blockBaseSeriesSet.Next appends [MinInt64, mint-1] for the front trim and
// [maxt+1, MaxInt64] for the back one. In Add, the branch that computes maxi is
// skipped when n.Maxt == MaxInt64, leaving maxi = len(in) instead of
// len(in)-mini, so the final in[maxi+mini-1] indexes past the slice as soon as
// mini > 0 — which the front-trim interval guarantees.
func TestDeletedSeriesPartialRangeRead(t *testing.T) {
	dir := t.TempDir()
	p, err := Open(dir, Config{}, "test-uuid")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ctx := context.Background()

	var samples []RawSample
	for i := int64(0); i < 20; i++ {
		samples = append(samples, RawSample{SID: 1, TS: 1_000_000 + i, Value: float64(i)})
	}
	if _, err := p.AppendRaw(ctx, samples); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Any tombstone at all.
	if err := p.DeleteRawRange(ctx, 1, 1_000_015, 1_000_018); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// A window strictly inside the chunk: trims front AND back.
	got, err2 := p.RawRange(ctx, 1, 1_000_005, 1_000_010, 0)
	if err2 != nil {
		t.Fatalf("RawRange: %v", err2)
	}
	if len(got) != 5 {
		t.Fatalf("RawRange returned %d samples, want 5", len(got))
	}
}
