// Package metrics is the time-series store: a series dictionary + narrow raw
// samples + downsampled rollups, sized for months-to-years of history in SQLite
// (see the series/samples/rollup tables in the schema). Ingest writes samples;
// the API and rule engine read via resolution-aware queries so any time range
// returns a bounded number of points.
//
// Series are keyed by (agent, monitor, kind, target, config_serial): monitor_id is
// the user-created monitor (probe_tasks.id) stamped by the agent, and config_serial
// is the target's material generation, so a material edit starts a fresh series and
// old-generation samples never surface as current. System metrics (host.*,
// iface.up, agent.*) carry monitor_id ” and generation 0.
//
// Hot reads (the /latest snapshot and rule evaluation, which runs on every
// ingest) are served from an in-memory latest-value cache updated at ingest —
// no SQL on those paths after the per-agent warm-up.
package metrics

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

// seriesIdent is the in-memory identity of one series row. config_serial is part
// of the identity: a material target edit starts a new generation (new series id)
// even when kind/target/params coincide textually, so old-generation samples
// never surface as current.
type seriesIdent struct {
	id           int64
	monitorID    string
	kind         string
	target       string
	layer        string
	unit         string
	configSerial int
}

type latestVal struct {
	ts    int64 // unix seconds
	value float64
}

type Store struct {
	db *store.DB

	mu      sync.Mutex
	cache   map[string]int64                  // seriesKey -> series id
	byAgent map[string]map[int64]*seriesIdent // agent -> its series identities
	latest  map[int64]latestVal               // series id -> newest sample
	warmed  map[string]bool                   // agent -> identities+latest loaded from DB
	purged  map[int64]purgeWindow             // series id -> last purged range; see UpdateLatest
}

// purgeWindow is a deleted [from, to) sample range. An UpdateLatest fold whose
// ts lands inside it may belong to a batch that committed BEFORE the purge ran
// (the rows are gone), so such folds re-verify against the DB instead of
// resurrecting deleted samples in the latest cache. until bounds the guard in
// wall-clock time; it is stamped when PurgeRange RELEASES s.mu (not when the
// window is recorded), so a fold that spent an arbitrarily long purge blocked
// on the mutex still finds a live guard. Only folds already in flight at purge
// time can race, and those land within milliseconds of the unlock, so entries
// expire quickly instead of forcing DB reads forever (a full-history purge has
// to==maxTS). Expired entries are swept by the next fold or purge.
type purgeWindow struct{ from, to, until int64 }

// purgeGuardSeconds is how long a purge window keeps guarding folds. Generous
// versus the actual commit→fold gap (milliseconds) yet short enough that the
// hot ingest path returns to pure cache hits almost immediately.
const purgeGuardSeconds = 30

func New(db *store.DB) *Store {
	return &Store{
		db:      db,
		cache:   make(map[string]int64),
		byAgent: make(map[string]map[int64]*seriesIdent),
		latest:  make(map[int64]latestVal),
		warmed:  make(map[string]bool),
		purged:  make(map[int64]purgeWindow),
	}
}

func seriesKey(agentID, monitorID, kind, target string, configSerial int) string {
	return agentID + "\x1f" + monitorID + "\x1f" + kind + "\x1f" + target + "\x1f" + strconv.Itoa(configSerial)
}

// registerLocked adds a series identity to the in-memory registry. Caller holds s.mu.
func (s *Store) registerLocked(agentID string, ident *seriesIdent) {
	s.cache[seriesKey(agentID, ident.monitorID, ident.kind, ident.target, ident.configSerial)] = ident.id
	ag := s.byAgent[agentID]
	if ag == nil {
		ag = make(map[int64]*seriesIdent)
		s.byAgent[agentID] = ag
	}
	ag[ident.id] = ident
}

// warmAgentLocked loads an agent's series identities and each one's newest
// sample from the DB, once per process lifetime. In-memory latest values that
// are already newer (samples ingested since startup) are kept. Caller holds s.mu.
func (s *Store) warmAgentLocked(ctx context.Context, agentID string) error {
	if s.warmed[agentID] {
		return nil
	}
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, COALESCE(monitor_id,''), kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,''), config_serial
		FROM series WHERE agent_id=?`, agentID)
	if err != nil {
		return err
	}
	var idents []*seriesIdent
	for rows.Next() {
		var si seriesIdent
		if err := rows.Scan(&si.id, &si.monitorID, &si.kind, &si.target, &si.layer, &si.unit, &si.configSerial); err != nil {
			rows.Close()
			return err
		}
		idents = append(idents, &si)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, si := range idents {
		s.registerLocked(agentID, si)
		if _, ok := s.latest[si.id]; ok {
			continue // fresher value already ingested this process
		}
		var ts int64
		var v float64
		err := s.db.Read().QueryRowContext(ctx,
			`SELECT ts, value FROM samples WHERE series_id=? ORDER BY ts DESC LIMIT 1`, si.id).Scan(&ts, &v)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return err
		}
		s.latest[si.id] = latestVal{ts: ts, value: v}
	}
	s.warmed[agentID] = true
	return nil
}

// EnsureSeries resolves (creating if needed) the series id for every metric,
// returning a key→id map. Each series is keyed by the metric's ConfigSerial (the
// target generation ingest has already verified equals the target's current
// serial), so a material edit lands in a fresh series. System metrics carry
// serial 0. It runs on the write DB directly (autocommit) and MUST be called
// before opening the ingest transaction.
func (s *Store) EnsureSeries(ctx context.Context, agentID, siteID string, ms []telemetry.Metric) (map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string]int64, len(ms))
	for i := range ms {
		m := &ms[i]
		key := seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial)
		if _, ok := out[key]; ok {
			continue
		}
		if id, ok := s.cache[key]; ok {
			out[key] = id
			continue
		}
		if _, err := s.db.ExecContext(ctx, `
			INSERT OR IGNORE INTO series(agent_id, site_id, monitor_id, kind, target, layer, unit, config_serial)
			VALUES(?,?,?,?,?,?,?,?)`, agentID, siteID, m.MonitorID, string(m.Kind), m.Target, string(m.Layer), m.Unit, m.ConfigSerial); err != nil {
			return nil, err
		}
		var id int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT id FROM series WHERE agent_id=? AND monitor_id=? AND kind=? AND target=? AND config_serial=?`,
			agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial).Scan(&id); err != nil {
			return nil, err
		}
		s.registerLocked(agentID, &seriesIdent{
			id: id, monitorID: m.MonitorID, kind: string(m.Kind), target: m.Target,
			layer: string(m.Layer), unit: m.Unit, configSerial: m.ConfigSerial,
		})
		out[key] = id
	}
	return out, nil
}

// InsertSamples writes raw samples inside the caller's transaction using one
// prepared statement for the whole batch. ids comes from EnsureSeries.
// Idempotent: a replayed packet's samples are ignored. The latest cache is NOT
// touched here — the tx may still roll back; call UpdateLatest after commit.
func (s *Store) InsertSamples(ctx context.Context, tx *sql.Tx, agentID string, ids map[string]int64, ms []telemetry.Metric) error {
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO samples(series_id, ts, value) VALUES(?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range ms {
		m := &ms[i]
		id, ok := ids[seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial)]
		if !ok {
			continue
		}
		if _, err := stmt.ExecContext(ctx, id, m.TS.Unix(), m.Value); err != nil {
			return err
		}
	}
	return nil
}

// UpdateLatest folds a committed batch into the in-memory latest cache. Call
// after the ingest transaction commits.
//
// Purge interleaving: ingest can commit its tx, then lose the race for s.mu to
// a PurgeRange that deletes the just-committed rows — after which this fold
// would resurrect a deleted sample as "latest". PurgeRange records the window
// it deleted; any fold whose ts lands inside that window re-reads the actual
// newest row from the DB instead of trusting the batch value. If that re-read
// fails the cache entry is evicted (not left stale): the next reader misses the
// cache and the next successful fold or warm-up repopulates it — a deleted
// sample must never be served as current.
func (s *Store) UpdateLatest(agentID string, ids map[string]int64, ms []telemetry.Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range ms {
		m := &ms[i]
		id, ok := ids[seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial)]
		if !ok {
			continue
		}
		ts := m.TS.Unix()
		if w, purgedOK := s.purged[id]; purgedOK {
			if time.Now().Unix() > w.until {
				delete(s.purged, id) // guard expired; no racing fold can remain in flight
			} else if ts >= w.from && ts < w.to {
				if err := s.refreshLatestLocked(context.Background(), id); err != nil {
					delete(s.latest, id) // never risk serving the purged value; next fold repopulates
				}
				continue
			}
		}
		if cur, ok := s.latest[id]; !ok || ts >= cur.ts {
			s.latest[id] = latestVal{ts: ts, value: m.Value}
		}
	}
}

// refreshLatestLocked re-reads a series' newest surviving sample from the DB
// into the latest cache (or evicts the entry when none remain). Caller holds
// s.mu and decides how to handle a read failure.
func (s *Store) refreshLatestLocked(ctx context.Context, id int64) error {
	var ts int64
	var v float64
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT ts, value FROM samples WHERE series_id=? ORDER BY ts DESC LIMIT 1`, id).Scan(&ts, &v)
	switch err {
	case nil:
		s.latest[id] = latestVal{ts: ts, value: v}
		return nil
	case sql.ErrNoRows:
		delete(s.latest, id)
		return nil
	default:
		return err
	}
}

// Point is a returned time-series point.
type Point struct {
	TS        time.Time `json:"ts"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Layer     string    `json:"layer"`
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"`
	MonitorID string    `json:"monitor_id,omitempty"`
}

// Query filters a read. SinceUnix=0 defaults to the last 2h.
type Query struct {
	AgentID   string
	Kind      string
	Target    string // optional; empty = all targets for the kind
	MonitorID string // optional; set = only that monitor's series
	SinceUnix int64
	Limit     int
}

// pickTier chooses a resolution table for a range (seconds) so the point count
// stays bounded while respecting each tier's retention.
func pickTier(rangeSec int64) (table string, raw bool) {
	switch {
	case rangeSec <= 2*3600:
		return "samples", true
	case rangeSec <= 2*86400:
		return "rollup_1m", false
	case rangeSec <= 90*86400:
		return "rollup_1h", false
	default:
		return "rollup_1d", false
	}
}

type seriesMeta struct {
	id        int64
	monitorID string
	kind      string
	target    string
	layer     string
	unit      string
}

// Query returns points for the matching series at a resolution appropriate to
// the range. Rollup values are bucket averages (total/cnt). Runs on the read
// pool so a long chart query never stalls ingest. Series are matched across ALL
// generations (config_serial is ignored) and the merged points are ordered by
// (kind, target, monitor, ts) so history stays continuous across material edits.
func (s *Store) Query(ctx context.Context, q Query) ([]Point, error) {
	now := time.Now().Unix()
	since := q.SinceUnix
	if since == 0 {
		since = now - 2*3600
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 1000
	}

	sqlSeries := `SELECT id, COALESCE(monitor_id,''), kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,'') FROM series WHERE agent_id=? AND kind=?`
	args := []any{q.AgentID, q.Kind}
	if q.Target != "" {
		sqlSeries += ` AND target=?`
		args = append(args, q.Target)
	}
	if q.MonitorID != "" {
		sqlSeries += ` AND monitor_id=?`
		args = append(args, q.MonitorID)
	}
	rows, err := s.db.Read().QueryContext(ctx, sqlSeries, args...)
	if err != nil {
		return nil, err
	}
	var series []seriesMeta
	for rows.Next() {
		var m seriesMeta
		if err := rows.Scan(&m.id, &m.monitorID, &m.kind, &m.target, &m.layer, &m.unit); err != nil {
			rows.Close()
			return nil, err
		}
		series = append(series, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	table, raw := pickTier(now - since)
	var out []Point
	for _, sm := range series {
		var sqlPts string
		if raw {
			sqlPts = `SELECT ts, value FROM samples WHERE series_id=? AND ts>=? ORDER BY ts LIMIT ?`
		} else {
			sqlPts = `SELECT ts, total/cnt FROM ` + table + ` WHERE series_id=? AND ts>=? ORDER BY ts LIMIT ?`
		}
		prows, err := s.db.Read().QueryContext(ctx, sqlPts, sm.id, since, limit)
		if err != nil {
			return nil, err
		}
		for prows.Next() {
			var tsUnix int64
			var value float64
			if err := prows.Scan(&tsUnix, &value); err != nil {
				prows.Close()
				return nil, err
			}
			out = append(out, Point{
				TS: time.Unix(tsUnix, 0).UTC(), Kind: sm.kind, Target: sm.target,
				Layer: sm.layer, Value: value, Unit: sm.unit, MonitorID: sm.monitorID,
			})
		}
		prows.Close()
		if err := prows.Err(); err != nil {
			return nil, err
		}
	}
	// Merge generations: same (kind, target, monitor) logical series may now span
	// several config_serial rows; order deterministically by ts within each.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		if out[i].MonitorID != out[j].MonitorID {
			return out[i].MonitorID < out[j].MonitorID
		}
		return out[i].TS.Before(out[j].TS)
	})
	return out, nil
}

// summaryDefaultWindowSec is Summarize's default window: the raw tier boundary
// (pickTier's samples cutoff), matching the status page's 2h P95 cards.
const summaryDefaultWindowSec = 2 * 3600

// summaryMaxWindowSec caps Summarize at the raw retention default (2d):
// percentiles are only meaningful over raw observations (rollups store bucket
// averages, and a percentile of averages is not a percentile of observations),
// so summaries always scan the samples table — unlike Query, which switches to
// rollups past 2h to bound the point count of its response. An aggregate
// response is a handful of numbers regardless of window, so the only cost is
// the scan itself, bounded by retention.
const summaryMaxWindowSec = 2 * 86400

// ErrSummaryWindow is returned when a Summarize window exceeds raw retention.
var ErrSummaryWindow = errors.New("metrics: summary window exceeds raw retention (2d)")

// ErrSummaryReduce is returned for an unknown SummaryQuery.Reduce mode.
var ErrSummaryReduce = errors.New("metrics: unknown summary reduce mode")

// ReduceWorstByTS collapses the merged samples to one per timestamp, keeping
// the worst (max) value across series — "how bad was the worst target each
// second". Used by the dashboard quality cards.
const ReduceWorstByTS = "worst"

// SummaryQuery asks for per-kind aggregates over a raw window. The window is a
// length, not an absolute timestamp, so validation can't race the caller's
// clock against Summarize's own time.Now.
type SummaryQuery struct {
	AgentID        string
	Kinds          []string
	MonitorID      string   // optional; set = only that monitor's series
	Target         string   // optional; set = only series for that target string
	ExcludeTargets []string // optional; series with these target strings are skipped
	Reduce         string   // "" = plain merge; ReduceWorstByTS = per-ts max across series
	WindowSeconds  int64    // 0 => 2h; must fit raw retention (≤2d)
}

// LatestPoint is the newest observation inside the window.
type LatestPoint struct {
	TS    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

// KindSummary aggregates one kind's raw samples: newest value, nearest-rank
// P95, mean, and the (post-reduce) sample count the aggregates were computed
// from. LatestNonzero is the newest sample whose value rounds to a nonzero
// integer — categorical code cards (NAT type etc.) use it to fall back past a
// transient "unknown" (code 0) probe to the most recent determinate result.
type KindSummary struct {
	Latest        *LatestPoint `json:"latest"`         // nil when no samples in window
	LatestNonzero *LatestPoint `json:"latest_nonzero"` // nil when no nonzero sample in window
	P95           *float64     `json:"p95"`            // nil when no samples in window
	Avg           *float64     `json:"avg"`            // nil when no samples in window
	Count         int          `json:"count"`
}

// Summarize computes latest/P95 per kind server-side so status cards don't pull
// the raw window into the browser. Series resolution mirrors Query — matched
// across ALL generations, merged in (target, monitor, ts) order — so the numbers
// equal what a client would compute from the same Query results. The result map
// always carries every requested kind; kinds with no samples get a zero summary.
func (s *Store) Summarize(ctx context.Context, q SummaryQuery) (map[string]KindSummary, error) {
	rangeSec := q.WindowSeconds
	if rangeSec == 0 {
		rangeSec = summaryDefaultWindowSec
	}
	if rangeSec < 0 || rangeSec > summaryMaxWindowSec {
		return nil, ErrSummaryWindow
	}
	if q.Reduce != "" && q.Reduce != ReduceWorstByTS {
		return nil, ErrSummaryReduce
	}
	excluded := make(map[string]bool, len(q.ExcludeTargets))
	for _, target := range q.ExcludeTargets {
		excluded[target] = true
	}
	since := time.Now().Unix() - rangeSec
	// The inclusive `ts >= since` predicate admits rangeSec+1 integer timestamps
	// at the fastest supported probe interval (1s); a lower per-series cap would
	// silently drop the NEWEST samples (ORDER BY ts keeps oldest) and skew both
	// latest and P95.
	perSeriesLimit := rangeSec + 1

	out := make(map[string]KindSummary, len(q.Kinds))
	for _, kind := range q.Kinds {
		sqlSeries := `SELECT id, COALESCE(monitor_id,''), COALESCE(target,'') FROM series WHERE agent_id=? AND kind=?`
		args := []any{q.AgentID, kind}
		if q.Target != "" {
			sqlSeries += ` AND target=?`
			args = append(args, q.Target)
		}
		if q.MonitorID != "" {
			sqlSeries += ` AND monitor_id=?`
			args = append(args, q.MonitorID)
		}
		rows, err := s.db.Read().QueryContext(ctx, sqlSeries, args...)
		if err != nil {
			return nil, err
		}
		type seriesRef struct {
			id                int64
			monitorID, target string
		}
		var series []seriesRef
		for rows.Next() {
			var sr seriesRef
			if err := rows.Scan(&sr.id, &sr.monitorID, &sr.target); err != nil {
				rows.Close()
				return nil, err
			}
			if excluded[sr.target] {
				continue
			}
			series = append(series, sr)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}

		type sample struct {
			ts                int64
			value             float64
			target, monitorID string
		}
		var merged []sample
		// The worst reduction folds per-timestamp maxima WHILE scanning so memory
		// scales with distinct timestamps, not series × timestamps: 50 one-second
		// targets over 24h would otherwise materialize ~4.3M rows per kind before
		// collapsing to at most 86401.
		var worst map[int64]float64
		if q.Reduce == ReduceWorstByTS {
			worst = make(map[int64]float64)
		}
		for _, sr := range series {
			prows, err := s.db.Read().QueryContext(ctx,
				`SELECT ts, value FROM samples WHERE series_id=? AND ts>=? ORDER BY ts LIMIT ?`,
				sr.id, since, perSeriesLimit)
			if err != nil {
				return nil, err
			}
			for prows.Next() {
				var ts int64
				var value float64
				if err := prows.Scan(&ts, &value); err != nil {
					prows.Close()
					return nil, err
				}
				if worst != nil {
					if prev, ok := worst[ts]; !ok || value > prev {
						worst[ts] = value
					}
					continue
				}
				merged = append(merged, sample{ts: ts, value: value, target: sr.target, monitorID: sr.monitorID})
			}
			prows.Close()
			if err := prows.Err(); err != nil {
				return nil, err
			}
		}
		if worst != nil {
			merged = make([]sample, 0, len(worst))
			for ts, value := range worst {
				merged = append(merged, sample{ts: ts, value: value})
			}
		}
		if len(merged) == 0 {
			out[kind] = KindSummary{}
			continue
		}
		if worst == nil {
			// Query's merge order with kind fixed; on tied timestamps the latest
			// scan below keeps the earlier entry, matching a strictly-greater
			// reduce over Query output. The worst reduction needs no ordering:
			// its timestamps are unique, so the aggregates below are order-free.
			sort.SliceStable(merged, func(i, j int) bool {
				if merged[i].target != merged[j].target {
					return merged[i].target < merged[j].target
				}
				if merged[i].monitorID != merged[j].monitorID {
					return merged[i].monitorID < merged[j].monitorID
				}
				return merged[i].ts < merged[j].ts
			})
		}

		latest := merged[0]
		var latestNonzero *sample
		var sum float64
		values := make([]float64, len(merged))
		for i, sm := range merged {
			values[i] = sm.value
			sum += sm.value
			if sm.ts > latest.ts {
				latest = sm
			}
			if math.Round(sm.value) != 0 && (latestNonzero == nil || sm.ts > latestNonzero.ts) {
				nz := sm
				latestNonzero = &nz
			}
		}
		sort.Float64s(values)
		idx := int(math.Ceil(float64(len(values))*0.95)) - 1
		if idx < 0 {
			idx = 0
		}
		p95 := values[idx]
		avg := sum / float64(len(merged))
		ks := KindSummary{
			Latest: &LatestPoint{TS: time.Unix(latest.ts, 0).UTC(), Value: latest.value},
			P95:    &p95,
			Avg:    &avg,
			Count:  len(merged),
		}
		if latestNonzero != nil {
			ks.LatestNonzero = &LatestPoint{TS: time.Unix(latestNonzero.ts, 0).UTC(), Value: latestNonzero.value}
		}
		out[kind] = ks
	}
	return out, nil
}

// Stats reports row counts per tier (storage visibility).
type Stats struct {
	Series   int64 `json:"series"`
	Samples  int64 `json:"samples"`
	Rollup1m int64 `json:"rollup_1m"`
	Rollup1h int64 `json:"rollup_1h"`
	Rollup1d int64 `json:"rollup_1d"`
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	for _, c := range []struct {
		table string
		dst   *int64
	}{
		{"series", &st.Series}, {"samples", &st.Samples},
		{"rollup_1m", &st.Rollup1m}, {"rollup_1h", &st.Rollup1h}, {"rollup_1d", &st.Rollup1d},
	} {
		if err := s.db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+c.table).Scan(c.dst); err != nil {
			return st, err
		}
	}
	return st, nil
}

// SeriesInfo describes one stored series, used to populate the console's
// selectors independently of recent activity.
type SeriesInfo struct {
	Kind      string `json:"kind"`
	Target    string `json:"target"`
	Layer     string `json:"layer"`
	Unit      string `json:"unit"`
	MonitorID string `json:"monitor_id,omitempty"`
}

// ListSeries returns every logical series recorded for an agent (from the
// dictionary, regardless of how recently it reported) ordered by kind then target.
// A monitor may now have several stored generations (config_serial) of the same
// (monitor, kind, target); the selector is generation-neutral, so those collapse
// to one row via DISTINCT — the console picks a logical series, not a generation.
//
// A monitor-bound series is listed only when the monitor's CURRENT kind can still
// emit it. Re-typing a monitor in place (dns → http) leaves the old kind's series
// in the dictionary forever; listing them would let a consumer pick a dead
// probe.dns.ok as the monitor's availability band and report a healthy 100% for a
// target whose HTTP probe is failing every cycle. The samples stay in the store —
// they are simply no longer "this monitor's series". A deleted monitor's leftover
// series drop out for the same reason (no owner, no current kind). System series
// (monitor_id=”) have no owning kind and always pass.
func (s *Store) ListSeries(ctx context.Context, agentID string) ([]SeriesInfo, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT DISTINCT s.kind, COALESCE(s.target,''), COALESCE(s.layer,''), COALESCE(s.unit,''),
		       COALESCE(s.monitor_id,''), COALESCE(pt.kind,'')
		FROM series s LEFT JOIN probe_tasks pt ON pt.id = s.monitor_id
		WHERE s.agent_id=? ORDER BY s.kind, s.target`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SeriesInfo
	for rows.Next() {
		var si SeriesInfo
		var probeKind string
		if err := rows.Scan(&si.Kind, &si.Target, &si.Layer, &si.Unit, &si.MonitorID, &probeKind); err != nil {
			return nil, err
		}
		if si.MonitorID != "" && !telemetry.MetricAllowedForProbeKind(probeKind, si.Kind) {
			continue
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// LatestSnapshot returns the newest sample per series for an agent (all kinds)
// within the sinceUnix lower bound — one point per series instead of a full
// range. Served from the in-memory latest cache (warmed from the DB once per
// agent per process), so the dashboard's poll never touches SQLite for samples.
func (s *Store) LatestSnapshot(ctx context.Context, agentID string, sinceUnix int64) ([]Point, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.warmAgentLocked(ctx, agentID); err != nil {
		return nil, err
	}
	// A monitor may now have several stored generations (config_serial). Only its
	// AUTHORITATIVE current generation — probe_tasks.config_serial — may surface as
	// the current value; a cached older-generation sample must never be shown as
	// current even when the current generation has no sample yet (it then yields no
	// value). System series (monitor_id='') are unique per (kind, target) and pass
	// through directly. Resolve the current generation of every monitor referenced
	// by this agent's series from probe_tasks.
	monitorIDs := map[string]bool{}
	for _, si := range s.byAgent[agentID] {
		if si.monitorID != "" {
			monitorIDs[si.monitorID] = true
		}
	}
	currentSerial, err := s.currentSerialsLocked(ctx, monitorIDs)
	if err != nil {
		return nil, err
	}
	var out []Point
	for id, si := range s.byAgent[agentID] {
		// Wi-Fi current values are served from the authoritative interface
		// snapshot (/agents/{id}/interfaces), not this per-series latest cache —
		// a per-series latest could surface an earlier round's value when the
		// current round omitted a field. wifi.* ingestion + Host Metrics history
		// are unaffected; only this snapshot output excludes them.
		if strings.HasPrefix(string(si.kind), "wifi.") {
			continue
		}
		// probe.round.ok is a server-derived bookkeeping series feeding the
		// availability math, not a value any view charts or reads as "current".
		if string(si.kind) == RoundOKKind {
			continue
		}
		if si.monitorID != "" {
			// Drop any generation other than the target's authoritative current one
			// (and any monitor no longer present in probe_tasks).
			cur, ok := currentSerial[si.monitorID]
			if !ok || si.configSerial != cur {
				continue
			}
		}
		lv, ok := s.latest[id]
		if !ok || lv.ts < sinceUnix {
			continue
		}
		out = append(out, Point{
			TS: time.Unix(lv.ts, 0).UTC(), Kind: si.kind, Target: si.target,
			Layer: si.layer, Value: lv.value, Unit: si.unit, MonitorID: si.monitorID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Target < out[j].Target
	})
	return out, nil
}

// currentSerialsLocked resolves each given monitor id to its authoritative current
// generation (probe_tasks.config_serial). A monitor with no probe_tasks row (deleted)
// is absent from the result. Called while s.mu is held (a plain read on the read
// pool, matching warmAgentLocked's pattern).
func (s *Store) currentSerialsLocked(ctx context.Context, monitorIDs map[string]bool) (map[string]int, error) {
	out := make(map[string]int, len(monitorIDs))
	if len(monitorIDs) == 0 {
		return out, nil
	}
	ids := make([]any, 0, len(monitorIDs))
	ph := make([]byte, 0, len(monitorIDs)*2)
	for id := range monitorIDs {
		ids = append(ids, id)
		if len(ph) > 0 {
			ph = append(ph, ',')
		}
		ph = append(ph, '?')
	}
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT id, config_serial FROM probe_tasks WHERE id IN (`+string(ph)+`)`, ids...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var serial int
		if err := rows.Scan(&id, &serial); err != nil {
			return nil, err
		}
		out[id] = serial
	}
	return out, rows.Err()
}

// TargetValue is the latest value of a series (for the rule engine). TS is the
// sample's unix timestamp, used by an in-tx evaluation to merge the accepted
// batch newest-wins over this cached value.
type TargetValue struct {
	Target string
	Value  float64
	TS     int64
}

// LatestPerSeries returns the newest value per matching SYSTEM series
// (monitor_id=”) since sinceUnix — host/interface rules bind by target
// string. Served from the latest cache; glob supports '*' and '?'.
func (s *Store) LatestPerSeries(ctx context.Context, agentID, kind, glob string, sinceUnix int64) ([]TargetValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.warmAgentLocked(ctx, agentID); err != nil {
		return nil, err
	}
	var out []TargetValue
	for id, si := range s.byAgent[agentID] {
		if si.monitorID != "" || si.kind != kind || !globMatch(glob, si.target) {
			continue
		}
		lv, ok := s.latest[id]
		if !ok || lv.ts <= sinceUnix {
			continue
		}
		out = append(out, TargetValue{Target: si.target, Value: lv.value, TS: lv.ts})
	}
	return out, nil
}

// LatestByMonitor returns the newest value of one monitor's series for a kind and
// exact target generation (configSerial) since sinceUnix — probe rules bind by
// monitor id, and requiring the current generation keeps an obsolete generation's
// sample from being read as current. Served from the latest cache.
func (s *Store) LatestByMonitor(ctx context.Context, agentID, kind, monitorID string, configSerial int, sinceUnix int64) ([]TargetValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.warmAgentLocked(ctx, agentID); err != nil {
		return nil, err
	}
	var out []TargetValue
	for id, si := range s.byAgent[agentID] {
		if si.monitorID != monitorID || si.kind != kind || si.configSerial != configSerial {
			continue
		}
		lv, ok := s.latest[id]
		if !ok || lv.ts <= sinceUnix {
			continue
		}
		out = append(out, TargetValue{Target: si.target, Value: lv.value, TS: lv.ts})
	}
	return out, nil
}

// globMatch implements SQLite-GLOB-style matching for '*' (any run) and '?'
// (any one char); other characters match literally. Rule targets are usually
// literal strings, so the no-metacharacter fast path covers almost every call.
func globMatch(pat, s string) bool {
	if !strings.ContainsAny(pat, "*?") {
		return pat == s
	}
	// Iterative wildcard match with backtracking on the last '*'.
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pat) && (pat[pi] == '?' || pat[pi] == s[si]):
			pi++
			si++
		case pi < len(pat) && pat[pi] == '*':
			star = pi
			mark = si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}
