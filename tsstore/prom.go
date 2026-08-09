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
	if err := checkManifest(dir, datasetUUID); err != nil {
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

	p := &Prom{dir: dir}
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
// likely). A fresh empty dir is claimed by writing the manifest.
func checkManifest(dir, datasetUUID string) error {
	path := filepath.Join(dir, manifestName)
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var m manifest
		if jsonErr := json.Unmarshal(raw, &m); jsonErr != nil || m.DatasetUUID == "" {
			return fmt.Errorf("tsstore: unreadable manifest %s (delete the tsdb directory to start fresh)", path)
		}
		if m.DatasetUUID != datasetUUID {
			return fmt.Errorf("tsstore: %s belongs to dataset %s, not %s — the SQLite database and the tsdb directory must be backed up and restored TOGETHER; delete the tsdb directory to start fresh", dir, m.DatasetUUID, datasetUUID)
		}
		return nil
	case errors.Is(err, os.ErrNotExist):
		for _, sub := range []string{"raw", "m1", "h1", "d1"} {
			if entries, _ := os.ReadDir(filepath.Join(dir, sub)); len(entries) > 0 {
				return fmt.Errorf("tsstore: %s holds time-series data but no manifest — it predates this database or lost its identity in a partial restore; delete the tsdb directory to start fresh", dir)
			}
		}
		data, _ := json.Marshal(manifest{DatasetUUID: datasetUUID})
		return os.WriteFile(path, data, 0o644)
	default:
		return err
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
