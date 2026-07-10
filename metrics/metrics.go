// Package metrics is the time-series store: a series dictionary + narrow raw
// samples + downsampled rollups, sized for months-to-years of history in SQLite
// (see migration 0003). Ingest writes samples; the API and rule engine read via
// resolution-aware queries so any time range returns a bounded number of points.
package metrics

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

type Store struct {
	db    *store.DB
	mu    sync.Mutex
	cache map[string]int64 // seriesKey -> series id
}

func New(db *store.DB) *Store {
	return &Store{db: db, cache: make(map[string]int64)}
}

func seriesKey(agentID, kind, target string) string {
	return agentID + "\x1f" + kind + "\x1f" + target
}

// EnsureSeries resolves (creating if needed) the series id for every metric,
// returning a key→id map. It runs on the DB directly (autocommit) and MUST be
// called before opening the ingest transaction (SQLite is single-connection).
func (s *Store) EnsureSeries(ctx context.Context, agentID, siteID string, ms []telemetry.Metric) (map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string]int64, len(ms))
	for i := range ms {
		m := &ms[i]
		key := seriesKey(agentID, string(m.Kind), m.Target)
		if id, ok := out[key]; ok {
			_ = id
			continue
		}
		if id, ok := s.cache[key]; ok {
			out[key] = id
			continue
		}
		if _, err := s.db.ExecContext(ctx, `
			INSERT OR IGNORE INTO series(agent_id, site_id, kind, target, layer, unit)
			VALUES(?,?,?,?,?,?)`, agentID, siteID, string(m.Kind), m.Target, string(m.Layer), m.Unit); err != nil {
			return nil, err
		}
		var id int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT id FROM series WHERE agent_id=? AND kind=? AND target=?`,
			agentID, string(m.Kind), m.Target).Scan(&id); err != nil {
			return nil, err
		}
		s.cache[key] = id
		out[key] = id
	}
	return out, nil
}

// InsertSamples writes raw samples inside the caller's transaction. ids comes
// from EnsureSeries. Idempotent: a replayed packet's samples are ignored.
func (s *Store) InsertSamples(ctx context.Context, tx *sql.Tx, agentID string, ids map[string]int64, ms []telemetry.Metric) error {
	for i := range ms {
		m := &ms[i]
		id, ok := ids[seriesKey(agentID, string(m.Kind), m.Target)]
		if !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO samples(series_id, ts, value) VALUES(?,?,?)`,
			id, m.TS.Unix(), m.Value); err != nil {
			return err
		}
	}
	return nil
}

// Point is a returned time-series point.
type Point struct {
	TS     time.Time `json:"ts"`
	Kind   string    `json:"kind"`
	Target string    `json:"target"`
	Layer  string    `json:"layer"`
	Value  float64   `json:"value"`
	Unit   string    `json:"unit"`
}

// Query filters a read. SinceUnix=0 defaults to the last 2h.
type Query struct {
	AgentID   string
	Kind      string
	Target    string // optional; empty = all targets for the kind
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
	id     int64
	kind   string
	target string
	layer  string
	unit   string
}

// Query returns points for the matching series at a resolution appropriate to
// the range. Rollup values are bucket averages (total/cnt).
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

	sqlSeries := `SELECT id, kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,'') FROM series WHERE agent_id=? AND kind=?`
	args := []any{q.AgentID, q.Kind}
	if q.Target != "" {
		sqlSeries += ` AND target=?`
		args = append(args, q.Target)
	}
	rows, err := s.db.QueryContext(ctx, sqlSeries, args...)
	if err != nil {
		return nil, err
	}
	var series []seriesMeta
	for rows.Next() {
		var m seriesMeta
		if err := rows.Scan(&m.id, &m.kind, &m.target, &m.layer, &m.unit); err != nil {
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
		prows, err := s.db.QueryContext(ctx, sqlPts, sm.id, since, limit)
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
				Layer: sm.layer, Value: value, Unit: sm.unit,
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
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+c.table).Scan(c.dst); err != nil {
			return st, err
		}
	}
	return st, nil
}

// TargetValue is the latest value of a series (for the rule engine).
type TargetValue struct {
	Target string
	Value  float64
}

// LatestPerSeries returns the newest raw value per matching series since
// sinceUnix. Uses SQLite's bare-column-follows-MAX behavior on an INTEGER ts.
func (s *Store) LatestPerSeries(ctx context.Context, agentID, kind, glob string, sinceUnix int64) ([]TargetValue, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.target, sm.value, MAX(sm.ts)
		FROM series s JOIN samples sm ON sm.series_id = s.id
		WHERE s.agent_id=? AND s.kind=? AND s.target GLOB ? AND sm.ts > ?
		GROUP BY s.id`, agentID, kind, glob, sinceUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetValue
	for rows.Next() {
		var tv TargetValue
		var maxTS int64
		if err := rows.Scan(&tv.Target, &tv.Value, &maxTS); err != nil {
			return nil, err
		}
		out = append(out, tv)
	}
	return out, rows.Err()
}
