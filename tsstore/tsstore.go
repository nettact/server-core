// Package tsstore is the time-series data plane: raw metric samples and their
// downsampled tiers live here, in four embedded Prometheus TSDB instances,
// while everything relational — the series dictionary, rollup watermarks,
// detector state, incidents — stays in SQLite. The split exists because the
// old SQLite layout (samples clustered by (series_id, ts)) rewrote every
// active series' B-tree tail page on every 30s packet commit: ~2.6KB of WAL
// per FLOAT stored at steady state, ~100-400x write amplification, measured at
// 57GiB/22h for 10 agents x 20 targets. An append-only TSDB writes the same
// stream at ~14-30B per sample (benchmarked ÷106).
//
// # Layout
//
// <dir>/raw, /m1, /h1, /d1 — one instance per retention tier so retention is
// pure block drop (no delete churn): raw keeps a few days, m1 30d, h1 2y, d1
// "forever". Raw holds every sample at its native timestamp; the tier
// instances hold downsampled buckets written by the rollup job (which itself
// stays in package metrics, along with the rollup_state watermarks in SQLite).
//
// # Identity
//
// A series is identified by its SQLite series.id (AUTOINCREMENT, NEVER reused
// — DeleteSeries tombstones rely on that). Raw samples are the prom series
// {__name__="s", sid="<id>"}; a tier bucket is the PAIR {__name__="cnt"} /
// {__name__="sum"} under the same sid. vmin/vmax of the old rollup rows are
// gone: nothing ever read them.
//
// The SQLite database and this directory form ONE dataset: sids in here mean
// nothing without the dictionary that minted them. Open enforces that with a
// manifest carrying the dataset UUID stored in the SQLite side — a recreated
// SQLite file re-issues sids from 1, and letting it attach to an old tsdb dir
// would splice new series onto dead data and dead tombstones. Back up (and
// restore) the two together.
//
// # Bucket immutability and the k-encoding
//
// Prometheus samples are immutable and its tombstones are TIME-INTERVAL masks
// applied at query and compaction time — including to samples appended after
// the Delete, as long as they fall inside the interval that was actually
// recorded. That last clause is the trap: Delete CLAMPS the interval it stores
// to the range the series holds at the time (Head.Delete → clampInterval
// against the series' current min/max). So "delete the bucket and re-append the
// corrected value" silently destroys the correction — the re-append lands on
// the same timestamp, inside the clamped interval, and stays masked — while a
// sample appended later BEYOND that clamped edge is not masked at all. Callers
// deleting a range must therefore make sure everything they mean to delete is
// already stored before they call (see metrics.Store.waitForPendingAppends).
//
// Repairs are consequently APPEND-ONLY: a bucket whose window starts at second
// ts stores its (cnt, sum) pair at millisecond timestamp ts*1000+k. The first
// write uses k=0; a repair appends the corrected pair at (window's current max
// ms)+1; a reader folds each window down to the sample with the LARGEST ms.
// Steady state writes one pair per bucket and zero tombstones; slot capacity is
// width*1000 rewrites per bucket, unreachable in practice. Tombstones remain
// only where nothing is ever appended again: whole-series deletion, raw range
// purges, and the interior buckets of a range purge (their source data is
// gone, so the rollup can never recreate them).
//
// # Timestamps
//
// The wire and SQLite side speak unix SECONDS; prom speaks milliseconds. Raw
// samples map exactly to sec*1000 (never folded). All ranges at this API are
// half-open [fromSec, toSec) — callers with inclusive bounds pass until+1.
package tsstore

import (
	"context"
	"errors"
	"time"
)

// ErrBucketTooOld is returned by AppendBuckets when a bucket's window lies
// beyond the out-of-order ingest window — its repair can never be appended.
// Callers fall back to tombstoning the bucket (matching the old whole-bucket
// over-delete semantics for edge buckets of an ancient range purge).
var ErrBucketTooOld = errors.New("tsstore: bucket window beyond the out-of-order horizon")

// Tier names a downsampled resolution. The ladder matches the query planner's
// tierLadder in package metrics: m1 serves windows up to 2 days, h1 up to 90,
// d1 the rest.
type Tier int

const (
	TierM1 Tier = iota
	TierH1
	TierD1
)

// BucketSeconds is the tier's bucket width.
func (t Tier) BucketSeconds() int64 {
	switch t {
	case TierM1:
		return 60
	case TierH1:
		return 3600
	default:
		return 86400
	}
}

func (t Tier) String() string {
	switch t {
	case TierM1:
		return "m1"
	case TierH1:
		return "h1"
	default:
		return "d1"
	}
}

// RawSample is one ingested observation.
type RawSample struct {
	SID   int64
	TS    int64 // unix seconds
	Value float64
}

// Sample is one point read back from the raw tier.
type Sample struct {
	TS    int64 // unix seconds
	Value float64
}

// Bucket is one downsampled window: TS is the bucket start (unix seconds,
// aligned to the tier width), Cnt the observation count, Sum their total.
// Consumers derive the mean as Sum/Cnt; availability reads Cnt as "rounds" and
// Sum as "ok rounds" (the source series is 0/1).
type Bucket struct {
	TS  int64
	Cnt int64
	Sum float64
}

// AppendResult reports what AppendRaw did. Dropped counts samples the store
// can PERMANENTLY never take (conflicting duplicate, outside the out-of-order
// window, ahead of head bounds) — retrying them can only fail again, so they
// are skipped rather than failing the batch: failing would withhold the
// agent's ack and wedge it in an infinite replay loop. Ingest's timestamp
// pre-filter makes a nonzero Dropped an anomaly worth logging, not a routine.
type AppendResult struct {
	Appended int
	Dropped  int
}

// TierStats describes one instance for the console's storage panel.
type TierStats struct {
	DiskBytes  int64  `json:"disk_bytes"`
	HeadSeries uint64 `json:"head_series"`
	Blocks     int    `json:"blocks"`
}

// Stats is the whole data plane's footprint.
type Stats struct {
	Raw TierStats `json:"raw"`
	M1  TierStats `json:"m1"`
	H1  TierStats `json:"h1"`
	D1  TierStats `json:"d1"`
}

// Forever is the retention to pass for a tier that must never drop a block.
// It exists because tsdb.Open reads a nonpositive RetentionDuration as "unset"
// and substitutes its own 15-day default, so "keep forever" has to be spelled
// as a duration long enough to outlive any deployment. 100 years is far below
// the int64 nanosecond ceiling (~292 years), so it survives every conversion
// on the way down.
const Forever = 100 * 365 * 24 * time.Hour

// Config sets each instance's physical retention. Zero means the tier's
// default; pass Forever for a tier that must keep everything (callers whose own
// config spells "forever" as zero MUST translate — see metrics.TSStoreConfig).
// Raw's PHYSICAL retention deliberately exceeds the 2-day window the query
// planner serves from raw: it must cover the 75h out-of-order ingest window
// plus rollup scheduling and compaction slack, or a backfilled block could be
// retention-dropped before the rollup job ever reads it. The logical 2-day cut
// is the reader's job (package metrics clamps query ranges).
type Config struct {
	RawRetention time.Duration // default 5d (physical; logical raw window is 2d)
	M1Retention  time.Duration // default 30d
	H1Retention  time.Duration // default 2y
	D1Retention  time.Duration // default Forever
}

// SeriesStore is the storage interface package metrics programs against. The
// only implementation is *Prom; the seam exists so the engine can be swapped
// (or faked in tests) without re-teaching every consumer.
type SeriesStore interface { // AppendRaw writes a batch in one appender/commit. Per-sample permanent
	// errors are dropped and counted (see AppendResult); any other error rolls
	// the whole batch back. Re-appending an identical (sid, ts, value) is a
	// silent no-op, which is what makes packet replay idempotent.
	AppendRaw(ctx context.Context, samples []RawSample) (AppendResult, error)

	// RawRange returns one series' samples in [fromSec, toSec), ascending.
	// toSec <= 0 means unbounded above (future-stamped samples included).
	// limit <= 0 means unlimited; otherwise the EARLIEST limit points.
	RawRange(ctx context.Context, sid, fromSec, toSec int64, limit int) ([]Sample, error)

	// RawLatest returns each series' newest sample at or after fromSec.
	// Series with no such sample are absent from the map.
	RawLatest(ctx context.Context, sids []int64, fromSec int64) (map[int64]Sample, error)

	// RawExtent returns one series' oldest and newest sample times.
	RawExtent(ctx context.Context, sid int64) (minSec, maxSec int64, ok bool, err error)

	// RawCount counts one series' samples in [fromSec, toSec); from==to==0
	// counts everything.
	RawCount(ctx context.Context, sid, fromSec, toSec int64) (int64, error)

	// ReadBuckets returns one series' buckets with starts in [fromSec, toSec),
	// ascending, k-folded: within each bucket window the newest ms wins.
	ReadBuckets(ctx context.Context, tier Tier, sid, fromSec, toSec int64) ([]Bucket, error)

	// BucketExtent returns the oldest and newest bucket starts.
	BucketExtent(ctx context.Context, tier Tier, sid int64) (minSec, maxSec int64, ok bool, err error)

	// AppendBuckets writes (or repairs) buckets: for each, the cnt/sum pair is
	// appended at max(existing max ms in the window + 1, ts*1000), atomically
	// for the whole call (any error rolls everything back). Callers serialize
	// writers per series (package metrics' rollup mutex) — k allocation reads
	// then appends and is not itself atomic.
	AppendBuckets(ctx context.Context, tier Tier, sid int64, buckets []Bucket) error

	// DeleteSeries tombstones the series' full history in all four instances.
	// Safe ONLY because sids are never reused; callers must never append to a
	// deleted sid again.
	DeleteSeries(ctx context.Context, sids []int64) error

	// DeleteRawRange tombstones one series' raw samples in [fromSec, toSec).
	// Callers must never re-append into the deleted window (a post-purge replay
	// that tries is masked by the tombstone — consistent with purge intent).
	DeleteRawRange(ctx context.Context, sid, fromSec, toSec int64) error

	// DeleteBucketRange tombstones whole buckets in [alignedFromSec,
	// alignedToSec). For interior buckets of a purge (source gone, never
	// recreated) and for edge buckets too old to k-repair.
	DeleteBucketRange(ctx context.Context, tier Tier, sid, alignedFromSec, alignedToSec int64) error

	// SeriesHighWater is the largest series id this data plane has ever stored
	// data for, so the caller can refuse a dictionary that was rolled back
	// behind it (see the manifest's field comment).
	SeriesHighWater() int64

	Stats(ctx context.Context) (Stats, error)
	Close() error
}
