package tsstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// openTest returns a store in a fresh temp dir plus the dir for reopen tests.
// (tsstoretest exists for OTHER packages; these white-box tests manage their
// own lifecycle because half of them reopen or double-open the directory.)
func openTest(t *testing.T) (*Prom, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tsstore-test-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 20; i++ {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
	p, err := Open(dir, Config{}, "test-dataset")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, dir
}

func now() int64 { return time.Now().Unix() }

func TestRawRoundTrip(t *testing.T) {
	p, _ := openTest(t)
	ctx := context.Background()
	base := now() - 3600

	var batch []RawSample
	for i := int64(0); i < 10; i++ {
		batch = append(batch, RawSample{SID: 7, TS: base + i*10, Value: float64(i)})
	}
	res, err := p.AppendRaw(ctx, batch)
	if err != nil || res.Appended != 10 || res.Dropped != 0 {
		t.Fatalf("AppendRaw: res=%+v err=%v", res, err)
	}

	// Half-open [from, to): the sample AT to is excluded, the one at from kept.
	got, err := p.RawRange(ctx, 7, base+10, base+30, 0)
	if err != nil || len(got) != 2 || got[0].TS != base+10 || got[1].TS != base+20 {
		t.Fatalf("RawRange half-open: %+v err=%v", got, err)
	}
	// limit keeps the EARLIEST points.
	got, err = p.RawRange(ctx, 7, base, 0, 3)
	if err != nil || len(got) != 3 || got[2].TS != base+20 {
		t.Fatalf("RawRange limit: %+v err=%v", got, err)
	}
	// Unknown sid: empty, no error.
	if got, err := p.RawRange(ctx, 99, base, 0, 0); err != nil || len(got) != 0 {
		t.Fatalf("RawRange unknown sid: %+v err=%v", got, err)
	}

	latest, err := p.RawLatest(ctx, []int64{7, 99}, base)
	if err != nil || len(latest) != 1 || latest[7].TS != base+90 || latest[7].Value != 9 {
		t.Fatalf("RawLatest: %+v err=%v", latest, err)
	}
	lo, hi, ok, err := p.RawExtent(ctx, 7)
	if err != nil || !ok || lo != base || hi != base+90 {
		t.Fatalf("RawExtent: %d %d %v err=%v", lo, hi, ok, err)
	}
	n, err := p.RawCount(ctx, 7, 0, 0)
	if err != nil || n != 10 {
		t.Fatalf("RawCount all: %d err=%v", n, err)
	}
	n, err = p.RawCount(ctx, 7, base+10, base+30)
	if err != nil || n != 2 {
		t.Fatalf("RawCount range: %d err=%v", n, err)
	}
}

func TestRawReplayIdempotent(t *testing.T) {
	p, _ := openTest(t)
	ctx := context.Background()
	base := now() - 600
	batch := []RawSample{{SID: 1, TS: base, Value: 4.2}, {SID: 1, TS: base + 10, Value: 4.3}}

	if _, err := p.AppendRaw(ctx, batch); err != nil {
		t.Fatalf("first: %v", err)
	}
	// The exact same batch again — a replayed packet — must not error and must
	// not duplicate.
	res, err := p.AppendRaw(ctx, batch)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	_ = res // in-order same-value re-append may count as appended or dropped; only the stored state matters
	n, err := p.RawCount(ctx, 1, 0, 0)
	if err != nil || n != 2 {
		t.Fatalf("count after replay = %d err=%v, want 2", n, err)
	}
}

func TestRawPermanentErrorsDropped(t *testing.T) {
	p, _ := openTest(t)
	ctx := context.Background()
	base := now()

	if _, err := p.AppendRaw(ctx, []RawSample{{SID: 1, TS: base, Value: 1}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A CONFLICTING value at an existing timestamp can never succeed: dropped
	// and counted, batch survives, the good sample lands.
	res, err := p.AppendRaw(ctx, []RawSample{
		{SID: 1, TS: base, Value: 2},      // conflicts
		{SID: 1, TS: base + 10, Value: 3}, // fine
	})
	if err != nil {
		t.Fatalf("mixed batch: %v", err)
	}
	if res.Dropped != 1 || res.Appended != 1 {
		t.Fatalf("mixed batch res=%+v, want 1 dropped 1 appended", res)
	}
	// A sample older than the OOO window is equally permanent.
	res, err = p.AppendRaw(ctx, []RawSample{{SID: 1, TS: base - int64(oooWindow/time.Second) - 3600, Value: 9}})
	if err != nil {
		t.Fatalf("too-old: %v", err)
	}
	if res.Dropped != 1 {
		t.Fatalf("too-old res=%+v, want dropped", res)
	}
}

func TestBucketRepairNewestWins(t *testing.T) {
	p, _ := openTest(t)
	ctx := context.Background()
	start := (now() - 3600) / 60 * 60

	if err := p.AppendBuckets(ctx, TierM1, 5, []Bucket{{TS: start, Cnt: 4, Sum: 100}}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	// Repair: same bucket, corrected values. Append-only — the reader must see
	// only the newer pair.
	if err := p.AppendBuckets(ctx, TierM1, 5, []Bucket{{TS: start, Cnt: 6, Sum: 150}}); err != nil {
		t.Fatalf("repair: %v", err)
	}
	got, err := p.ReadBuckets(ctx, TierM1, 5, start, start+60)
	if err != nil || len(got) != 1 {
		t.Fatalf("ReadBuckets: %+v err=%v", got, err)
	}
	if got[0].Cnt != 6 || got[0].Sum != 150 {
		t.Fatalf("bucket after repair = %+v, want cnt=6 sum=150", got[0])
	}
}

func TestBucketRepairSurvivesReopen(t *testing.T) {
	p, dir := openTest(t)
	ctx := context.Background()
	start := (now() - 3600) / 60 * 60

	if err := p.AppendBuckets(ctx, TierM1, 5, []Bucket{{TS: start, Cnt: 4, Sum: 100}}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := p.AppendBuckets(ctx, TierM1, 5, []Bucket{{TS: start, Cnt: 6, Sum: 150}}); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	p2, err := Open(dir, Config{}, "test-dataset")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer p2.Close()
	got, err := p2.ReadBuckets(ctx, TierM1, 5, start, start+60)
	if err != nil || len(got) != 1 || got[0].Cnt != 6 || got[0].Sum != 150 {
		t.Fatalf("bucket after reopen = %+v err=%v, want cnt=6 sum=150", got, err)
	}
}

// TestOOOBackfillDurableWithoutCompact pins BOTH backfill guarantees at once:
// out-of-order samples 72h behind the head are accepted, and they survive a
// close/reopen purely via WBL replay — no Compact() call flushes them first
// (the M0 benchmark compacted before reopening, which validated less).
func TestOOOBackfillDurableWithoutCompact(t *testing.T) {
	p, dir := openTest(t)
	ctx := context.Background()
	head := now()

	// Establish the head, then backfill an hour of 10s samples from 72h ago.
	if _, err := p.AppendRaw(ctx, []RawSample{{SID: 3, TS: head, Value: 1}}); err != nil {
		t.Fatalf("head: %v", err)
	}
	base := head - 72*3600
	var backfill []RawSample
	for i := int64(0); i < 360; i++ {
		backfill = append(backfill, RawSample{SID: 3, TS: base + i*10, Value: float64(i)})
	}
	res, err := p.AppendRaw(ctx, backfill)
	if err != nil || res.Dropped != 0 || res.Appended != 360 {
		t.Fatalf("backfill: res=%+v err=%v", res, err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	p2, err := Open(dir, Config{}, "test-dataset")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer p2.Close()
	n, err := p2.RawCount(ctx, 3, base, base+3600)
	if err != nil || n != 360 {
		t.Fatalf("backfill after reopen = %d err=%v, want 360", n, err)
	}
}

func TestDeleteSemantics(t *testing.T) {
	p, _ := openTest(t)
	ctx := context.Background()
	base := (now() - 7200) / 60 * 60

	for sid := int64(1); sid <= 2; sid++ {
		var batch []RawSample
		for i := int64(0); i < 60; i++ {
			batch = append(batch, RawSample{SID: sid, TS: base + i*10, Value: 1})
		}
		if _, err := p.AppendRaw(ctx, batch); err != nil {
			t.Fatalf("seed raw: %v", err)
		}
		if err := p.AppendBuckets(ctx, TierM1, sid, []Bucket{{TS: base, Cnt: 6, Sum: 6}, {TS: base + 60, Cnt: 6, Sum: 6}}); err != nil {
			t.Fatalf("seed buckets: %v", err)
		}
	}

	// Range delete on raw is half-open.
	if err := p.DeleteRawRange(ctx, 1, base+100, base+200); err != nil {
		t.Fatalf("DeleteRawRange: %v", err)
	}
	n, _ := p.RawCount(ctx, 1, 0, 0)
	if n != 50 {
		t.Fatalf("raw count after range delete = %d, want 50", n)
	}
	if s, _ := p.RawRange(ctx, 1, base+200, base+210, 0); len(s) != 1 {
		t.Fatalf("sample at exclusive bound deleted: %+v", s)
	}

	// Interior bucket delete.
	if err := p.DeleteBucketRange(ctx, TierM1, 1, base, base+60); err != nil {
		t.Fatalf("DeleteBucketRange: %v", err)
	}
	b, _ := p.ReadBuckets(ctx, TierM1, 1, base, base+120)
	if len(b) != 1 || b[0].TS != base+60 {
		t.Fatalf("buckets after interior delete = %+v", b)
	}

	// Whole-series delete clears every tier; the sibling series is untouched.
	if err := p.DeleteSeries(ctx, []int64{1}); err != nil {
		t.Fatalf("DeleteSeries: %v", err)
	}
	if n, _ := p.RawCount(ctx, 1, 0, 0); n != 0 {
		t.Fatalf("raw survived DeleteSeries: %d", n)
	}
	if b, _ := p.ReadBuckets(ctx, TierM1, 1, base, base+120); len(b) != 0 {
		t.Fatalf("buckets survived DeleteSeries: %+v", b)
	}
	if n, _ := p.RawCount(ctx, 2, 0, 0); n != 60 {
		t.Fatalf("sibling series damaged: %d", n)
	}
}

func TestStatsShape(t *testing.T) {
	p, dir := openTest(t)
	ctx := context.Background()
	base := now() - 7200
	var batch []RawSample
	for i := int64(0); i < 5000; i++ {
		batch = append(batch, RawSample{SID: 1 + i%3, TS: base + i, Value: float64(i)})
	}
	if _, err := p.AppendRaw(ctx, batch); err != nil {
		t.Fatalf("seed: %v", err)
	}
	st, err := p.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Raw.HeadSeries != 3 {
		t.Fatalf("raw head series = %d, want 3", st.Raw.HeadSeries)
	}
	// Disk bytes only settle once the WAL's page buffer flushes — guaranteed by
	// Close, so measure the directory afterwards with the same helper Stats uses.
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := dirBytes(dir + "/raw"); got <= 0 {
		t.Fatalf("raw dir bytes after close = %d, want > 0", got)
	}
}

func TestSecondProcessOpenFails(t *testing.T) {
	_, dir := openTest(t)
	if _, err := Open(dir, Config{}, "test-dataset"); err == nil {
		t.Fatalf("second Open on a live directory succeeded; the lockfile must refuse it")
	}
}

func TestDatasetManifestMismatchRefuses(t *testing.T) {
	p, dir := openTest(t)
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := Open(dir, Config{}, "some-other-dataset"); err == nil {
		t.Fatalf("Open with a foreign dataset uuid succeeded; sids would splice onto dead data")
	}
	// The matching identity still opens.
	p2, err := Open(dir, Config{}, "test-dataset")
	if err != nil {
		t.Fatalf("matching reopen: %v", err)
	}
	_ = p2.Close()
}

// TestCompactionSoakAccelerated drives repeated real head compactions — the
// code path behind the known Windows fragility (mmap handles vs renames). Ten
// two-hour spans are appended and compacted; reads and a final reopen must
// stay coherent throughout. Runs on every OS; it EXISTS for windows-latest.
func TestCompactionSoakAccelerated(t *testing.T) {
	p, dir := openTest(t)
	ctx := context.Background()
	start := now() - 24*3600
	total := 0
	for cycle := 0; cycle < 10; cycle++ {
		var batch []RawSample
		base := start + int64(cycle)*7200
		for i := int64(0); i < 120; i++ {
			batch = append(batch, RawSample{SID: 1, TS: base + i*60, Value: float64(cycle)})
		}
		res, err := p.AppendRaw(ctx, batch)
		if err != nil || res.Dropped != 0 {
			t.Fatalf("cycle %d append: res=%+v err=%v", cycle, res, err)
		}
		total += res.Appended
		if err := p.dbs[instRaw].Compact(ctx); err != nil {
			t.Fatalf("cycle %d compact: %v", cycle, err)
		}
		n, err := p.RawCount(ctx, 1, 0, 0)
		if err != nil || int(n) != total {
			t.Fatalf("cycle %d count = %d err=%v, want %d", cycle, n, err, total)
		}
	}
	if blocks := len(p.dbs[instRaw].Blocks()); blocks == 0 {
		t.Fatalf("soak produced no persisted blocks; compaction never ran")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	p2, err := Open(dir, Config{}, "test-dataset")
	if err != nil {
		t.Fatalf("reopen after soak: %v", err)
	}
	defer p2.Close()
	if n, err := p2.RawCount(ctx, 1, 0, 0); err != nil || int(n) != total {
		t.Fatalf("count after reopen = %d err=%v, want %d", n, err, total)
	}
}

func TestBucketPairAtomicOnError(t *testing.T) {
	p, _ := openTest(t)
	ctx := context.Background()
	start := (now() - 3600) / 60 * 60
	// An unaligned bucket poisons the batch — nothing from it may land, not
	// even the valid first bucket, and especially not half of a cnt/sum pair.
	err := p.AppendBuckets(ctx, TierM1, 9, []Bucket{
		{TS: start, Cnt: 1, Sum: 1},
		{TS: start + 61, Cnt: 1, Sum: 1},
	})
	if err == nil {
		t.Fatalf("unaligned bucket accepted")
	}
	got, err := p.ReadBuckets(ctx, TierM1, 9, start, start+120)
	if err != nil || len(got) != 0 {
		t.Fatalf("partial batch visible after rollback: %+v err=%v", got, err)
	}
}

func TestManifestRefusesUnboundData(t *testing.T) {
	p, dir := openTest(t)
	_ = p.Close()
	// Simulate a partial restore: data present, identity gone.
	if err := os.Remove(fmt.Sprintf("%s/%s", dir, manifestName)); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}
	if _, err := Open(dir, Config{}, "test-dataset"); err == nil {
		t.Fatalf("Open adopted a data directory with no manifest")
	}
}
