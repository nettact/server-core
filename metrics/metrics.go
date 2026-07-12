// Package metrics is the time-series store: a series dictionary + narrow raw
// samples + downsampled rollups, sized for months-to-years of history in SQLite
// (see migrations 0003/0011). Ingest writes samples; the API and rule engine
// read via resolution-aware queries so any time range returns a bounded number
// of points.
//
// Series are keyed by (agent, monitor, kind, target): monitor_id is the
// user-created monitor (probe_tasks.id) stamped by the agent, so two monitors
// on the same target string keep distinct series. System metrics (host.*,
// iface.up, agent.*, the built-in gateway probe) carry monitor_id ”.
//
// Hot reads (the /latest snapshot and rule evaluation, which runs on every
// ingest) are served from an in-memory latest-value cache updated at ingest —
// no SQL on those paths after the per-agent warm-up.
package metrics

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

// seriesIdent is the in-memory identity of one series row.
type seriesIdent struct {
	id        int64
	monitorID string
	kind      string
	target    string
	layer     string
	unit      string
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
}

func New(db *store.DB) *Store {
	return &Store{
		db:      db,
		cache:   make(map[string]int64),
		byAgent: make(map[string]map[int64]*seriesIdent),
		latest:  make(map[int64]latestVal),
		warmed:  make(map[string]bool),
	}
}

func seriesKey(agentID, monitorID, kind, target string) string {
	return agentID + "\x1f" + monitorID + "\x1f" + kind + "\x1f" + target
}

// registerLocked adds a series identity to the in-memory registry. Caller holds s.mu.
func (s *Store) registerLocked(agentID string, ident *seriesIdent) {
	s.cache[seriesKey(agentID, ident.monitorID, ident.kind, ident.target)] = ident.id
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
		SELECT id, COALESCE(monitor_id,''), kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,'')
		FROM series WHERE agent_id=?`, agentID)
	if err != nil {
		return err
	}
	var idents []*seriesIdent
	for rows.Next() {
		var si seriesIdent
		if err := rows.Scan(&si.id, &si.monitorID, &si.kind, &si.target, &si.layer, &si.unit); err != nil {
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
// returning a key→id map. It runs on the write DB directly (autocommit) and
// MUST be called before opening the ingest transaction.
func (s *Store) EnsureSeries(ctx context.Context, agentID, siteID string, ms []telemetry.Metric) (map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string]int64, len(ms))
	for i := range ms {
		m := &ms[i]
		key := seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target)
		if _, ok := out[key]; ok {
			continue
		}
		if id, ok := s.cache[key]; ok {
			out[key] = id
			continue
		}
		if _, err := s.db.ExecContext(ctx, `
			INSERT OR IGNORE INTO series(agent_id, site_id, monitor_id, kind, target, layer, unit)
			VALUES(?,?,?,?,?,?,?)`, agentID, siteID, m.MonitorID, string(m.Kind), m.Target, string(m.Layer), m.Unit); err != nil {
			return nil, err
		}
		var id int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT id FROM series WHERE agent_id=? AND monitor_id=? AND kind=? AND target=?`,
			agentID, m.MonitorID, string(m.Kind), m.Target).Scan(&id); err != nil {
			return nil, err
		}
		s.registerLocked(agentID, &seriesIdent{
			id: id, monitorID: m.MonitorID, kind: string(m.Kind), target: m.Target,
			layer: string(m.Layer), unit: m.Unit,
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
		id, ok := ids[seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target)]
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
func (s *Store) UpdateLatest(agentID string, ids map[string]int64, ms []telemetry.Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range ms {
		m := &ms[i]
		id, ok := ids[seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target)]
		if !ok {
			continue
		}
		ts := m.TS.Unix()
		if cur, ok := s.latest[id]; !ok || ts >= cur.ts {
			s.latest[id] = latestVal{ts: ts, value: m.Value}
		}
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
// pool so a long chart query never stalls ingest.
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

// ListSeries returns every series recorded for an agent (from the dictionary,
// regardless of how recently it reported) ordered by kind then target.
func (s *Store) ListSeries(ctx context.Context, agentID string) ([]SeriesInfo, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,''), COALESCE(monitor_id,'')
		FROM series WHERE agent_id=? ORDER BY kind, target`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SeriesInfo
	for rows.Next() {
		var si SeriesInfo
		if err := rows.Scan(&si.Kind, &si.Target, &si.Layer, &si.Unit, &si.MonitorID); err != nil {
			return nil, err
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// LatestSnapshot returns the newest sample per series for an agent (all kinds)
// within the sinceUnix lower bound — one point per series instead of a full
// range. Served from the in-memory latest cache (warmed from the DB once per
// agent per process), so the dashboard's poll never touches SQLite.
func (s *Store) LatestSnapshot(ctx context.Context, agentID string, sinceUnix int64) ([]Point, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.warmAgentLocked(ctx, agentID); err != nil {
		return nil, err
	}
	var out []Point
	for id, si := range s.byAgent[agentID] {
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

// TargetValue is the latest value of a series (for the rule engine).
type TargetValue struct {
	Target string
	Value  float64
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
		out = append(out, TargetValue{Target: si.target, Value: lv.value})
	}
	return out, nil
}

// LatestByMonitor returns the newest value of one monitor's series for a kind
// since sinceUnix — probe rules bind by monitor id. Served from the latest cache.
func (s *Store) LatestByMonitor(ctx context.Context, agentID, kind, monitorID string, sinceUnix int64) ([]TargetValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.warmAgentLocked(ctx, agentID); err != nil {
		return nil, err
	}
	var out []TargetValue
	for id, si := range s.byAgent[agentID] {
		if si.monitorID != monitorID || si.kind != kind {
			continue
		}
		lv, ok := s.latest[id]
		if !ok || lv.ts <= sinceUnix {
			continue
		}
		out = append(out, TargetValue{Target: si.target, Value: lv.value})
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
