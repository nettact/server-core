package tsstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/tsdb"
)

const (
	// oooWindow is every instance's out-of-order acceptance window. The agent
	// WAL retains at most 72h of unacked data, so 75h covers the deepest
	// legitimate raw backfill with alignment slack — and the tier instances
	// need the same window because a backfill-driven repair rewrites buckets
	// up to that far behind the head.
	oooWindow = 75 * time.Hour

	// walSegmentSize is deliberately far below tsdb's 128MiB default: four
	// instances on a home box would otherwise preallocate half a gigabyte of
	// WAL segments. 16MiB is above the 10MiB floor tsdb.Open enforces.
	walSegmentSize = 16 << 20

	manifestName = "manifest.json"
)

// ManifestName is the dataset-identity file inside a tsstore directory. The
// caller needs it to tell a genuinely fresh data plane from a half-restored one:
// a missing manifest beside a NON-empty series dictionary means the SQLite half
// was restored without its tsdb half, and Open would otherwise happily claim the
// empty directory and start serving a dataset whose history silently vanished.
const ManifestName = manifestName

func defaultRetention(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Prom is the Prometheus-TSDB implementation of SeriesStore: four embedded
// instances under one directory. See the package comment for the design.
//
// It keeps its own lockfiles (NoLockfile=false): SQLite happily lets a second
// process open the same database (multi-handle access is a supported
// deployment shape there), so nothing upstream protects this directory from a
// second server instance scribbling into it.
type Prom struct {
	dir  string
	dbs  [4]*tsdb.DB // indexed instRaw..instD1
	refs [4]refCache

	// bucketMu serializes AppendBuckets' read-k-then-append against itself.
	// Cross-component serialization (rollup vs purge) lives in package metrics.
	bucketMu sync.Mutex

	// hwMu guards the persisted series high-water mark (see manifest).
	hwMu        sync.Mutex
	datasetUUID string
	highWater   int64
}

const (
	instRaw = 0
	instM1  = 1
	instH1  = 2
	instD1  = 3
)

func instOf(t Tier) int {
	switch t {
	case TierM1:
		return instM1
	case TierH1:
		return instH1
	default:
		return instD1
	}
}

type manifest struct {
	DatasetUUID string `json:"dataset_uuid"`
	// SeriesHighWater is the largest series id this data plane has ever stored
	// data for. It exists to catch the one partial restore the UUID cannot: an
	// OLDER SQLite backup restored beside a NEWER tsdb directory. Both halves
	// carry the same dataset identity, but the rolled-back sqlite_sequence
	// re-issues series ids the data plane still holds data for, so a brand-new
	// monitor would silently inherit a dead one's history. Persisted as soon as
	// a never-before-seen id is written (rare — once per new series), so a
	// crash cannot leave it behind the data.
	SeriesHighWater int64 `json:"series_high_water"`
}

// Open opens (creating if needed) the four instances under dir and binds them
// to datasetUUID — the identity minted and stored by the SQLite side. A
// mismatch refuses to start: sids from a different SQLite file would splice
// onto this directory's dead series and tombstones. Delete the tsdb directory
// (or restore the matching SQLite file) to resolve; there is nothing to merge.
func Open(dir string, cfg Config, datasetUUID string) (*Prom, error) {
	if datasetUUID == "" {
		return nil, errors.New("tsstore: empty dataset uuid")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	hw, err := checkManifest(dir, datasetUUID)
	if err != nil {
		return nil, err
	}

	type inst struct {
		name      string
		retention time.Duration
		maxBlock  time.Duration
	}
	insts := [4]inst{
		{"raw", defaultRetention(cfg.RawRetention, 5*24*time.Hour), 2 * time.Hour},
		{"m1", defaultRetention(cfg.M1Retention, 30*24*time.Hour), 24 * time.Hour},
		{"h1", defaultRetention(cfg.H1Retention, 2*365*24*time.Hour), 31 * 24 * time.Hour},
		{"d1", defaultRetention(cfg.D1Retention, 100*365*24*time.Hour), 31 * 24 * time.Hour},
	}

	p := &Prom{dir: dir, datasetUUID: datasetUUID, highWater: hw}
	for i, in := range insts {
		opts := tsdb.DefaultOptions()
		opts.RetentionDuration = in.retention.Milliseconds()
		opts.OutOfOrderTimeWindow = oooWindow.Milliseconds()
		opts.WALSegmentSize = walSegmentSize
		opts.MinBlockDuration = (2 * time.Hour).Milliseconds()
		opts.MaxBlockDuration = in.maxBlock.Milliseconds()
		opts.NoLockfile = false
		db, err := tsdb.Open(filepath.Join(dir, in.name), instLogger(in.name), prometheus.NewRegistry(), opts, tsdb.NewDBStats())
		if err != nil {
			for j := 0; j < i; j++ {
				_ = p.dbs[j].Close()
			}
			return nil, fmt.Errorf("tsstore: open %s: %w", in.name, err)
		}
		p.dbs[i] = db
		p.refs[i].init()
	}
	return p, nil
}

// checkManifest binds dir to the dataset, refusing a mismatch and refusing to
// adopt a pre-existing unbound directory (a half-restored backup, most
// likely). A fresh empty dir is claimed by writing the manifest. Returns the
// recorded series high-water mark (0 for a fresh directory).
func checkManifest(dir, datasetUUID string) (int64, error) {
	path := filepath.Join(dir, manifestName)
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var m manifest
		if jsonErr := json.Unmarshal(raw, &m); jsonErr != nil || m.DatasetUUID == "" {
			return 0, fmt.Errorf("tsstore: unreadable manifest %s (delete the tsdb directory to start fresh)", path)
		}
		if m.DatasetUUID != datasetUUID {
			return 0, fmt.Errorf("tsstore: %s belongs to dataset %s, not %s — the SQLite database and the tsdb directory must be backed up and restored TOGETHER; delete the tsdb directory to start fresh", dir, m.DatasetUUID, datasetUUID)
		}
		return m.SeriesHighWater, nil
	case errors.Is(err, os.ErrNotExist):
		for _, sub := range []string{"raw", "m1", "h1", "d1"} {
			if entries, _ := os.ReadDir(filepath.Join(dir, sub)); len(entries) > 0 {
				return 0, fmt.Errorf("tsstore: %s holds time-series data but no manifest — it predates this database or lost its identity in a partial restore; delete the tsdb directory to start fresh", dir)
			}
		}
		data, _ := json.Marshal(manifest{DatasetUUID: datasetUUID})
		return 0, os.WriteFile(path, data, 0o644)
	default:
		return 0, err
	}
}

// SeriesHighWater is the largest series id this data plane has ever stored
// data for. The caller compares it against the dictionary's own MAX(id) to
// catch a rolled-back database restored beside a newer data plane — see the
// manifest field's comment for why that pairing is dangerous.
func (p *Prom) SeriesHighWater() int64 {
	p.hwMu.Lock()
	defer p.hwMu.Unlock()
	return p.highWater
}

// noteSeriesIDs advances the persisted high-water mark when a batch carries an
// id the data plane has never stored before. The manifest rewrite happens only
// on that advance — once per new series over the store's lifetime — so the hot
// append path pays nothing in steady state, and a crash cannot leave the mark
// behind the data it describes.
func (p *Prom) noteSeriesIDs(maxSID int64) {
	p.hwMu.Lock()
	defer p.hwMu.Unlock()
	if maxSID <= p.highWater {
		return
	}
	p.highWater = maxSID
	data, err := json.Marshal(manifest{DatasetUUID: p.datasetUUID, SeriesHighWater: maxSID})
	if err == nil {
		err = os.WriteFile(filepath.Join(p.dir, manifestName), data, 0o644)
	}
	if err != nil {
		log.Printf("tsstore: could not persist series high-water %d: %v", maxSID, err)
	}
}

// Close flushes and closes all four instances (head state persists via each
// instance's WAL; no explicit compaction needed).
func (p *Prom) Close() error {
	var errs []error
	for i, db := range p.dbs {
		if db != nil {
			if err := db.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close %d: %w", i, err))
			}
		}
	}
	return errors.Join(errs...)
}

// instLogger forwards WARN and above to the server log. Compaction failures —
// the known Windows fragility (antivirus holding a rename hostage) — must be
// visible, not discarded; INFO-level chatter (block loads, WAL replay) stays
// out of the log.
func instLogger(name string) *slog.Logger {
	return slog.New(warnHandler{inst: name})
}

type warnHandler struct{ inst string }

func (h warnHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelWarn
}

func (h warnHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := ""
	r.Attrs(func(a slog.Attr) bool {
		attrs += " " + a.Key + "=" + a.Value.String()
		return true
	})
	log.Printf("tsstore[%s] %s: %s%s", h.inst, r.Level, r.Message, attrs)
	return nil
}

func (h warnHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h warnHandler) WithGroup(string) slog.Handler      { return h }
