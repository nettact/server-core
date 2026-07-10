-- Time-series storage optimized for long-term (months–years) retention.
-- Replaces the wide `metrics` table with a narrow, normalized design:
--   * series: dictionary — one row per (agent, kind, target); the big TEXT
--     columns are stored once here, not on every sample.
--   * samples: raw points as (series_id INT, ts INT unix-seconds, value REAL),
--     clustered on (series_id, ts) WITHOUT ROWID → ~24B/row and fast range scans.
--   * rollup_1m/1h/1d: downsampled aggregates (count/sum/min/max) so old data is
--     kept cheaply at coarse resolution instead of full-resolution forever.
--   * rollup_state: per-resolution watermark for incremental downsampling.
-- Integer unix-second timestamps also remove the TEXT-timestamp comparison hazard.

DROP INDEX IF EXISTS idx_metrics_query;
DROP INDEX IF EXISTS idx_metrics_ts;
DROP TABLE IF EXISTS metrics;

CREATE TABLE series(
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL,
  site_id  TEXT NOT NULL,
  kind     TEXT NOT NULL,
  target   TEXT NOT NULL DEFAULT '',
  layer    TEXT NOT NULL DEFAULT '',
  unit     TEXT NOT NULL DEFAULT '',
  UNIQUE(agent_id, kind, target)
);
CREATE INDEX idx_series_agent_kind ON series(agent_id, kind, target);

CREATE TABLE samples(
  series_id INTEGER NOT NULL,
  ts        INTEGER NOT NULL, -- unix seconds
  value     REAL NOT NULL,
  PRIMARY KEY(series_id, ts)
) WITHOUT ROWID;

CREATE TABLE rollup_1m(
  series_id INTEGER NOT NULL,
  ts        INTEGER NOT NULL, -- bucket start (unix seconds, aligned to 60)
  cnt       INTEGER NOT NULL,
  total     REAL NOT NULL,
  vmin      REAL NOT NULL,
  vmax      REAL NOT NULL,
  PRIMARY KEY(series_id, ts)
) WITHOUT ROWID;

CREATE TABLE rollup_1h(
  series_id INTEGER NOT NULL,
  ts        INTEGER NOT NULL,
  cnt       INTEGER NOT NULL,
  total     REAL NOT NULL,
  vmin      REAL NOT NULL,
  vmax      REAL NOT NULL,
  PRIMARY KEY(series_id, ts)
) WITHOUT ROWID;

CREATE TABLE rollup_1d(
  series_id INTEGER NOT NULL,
  ts        INTEGER NOT NULL,
  cnt       INTEGER NOT NULL,
  total     REAL NOT NULL,
  vmin      REAL NOT NULL,
  vmax      REAL NOT NULL,
  PRIMARY KEY(series_id, ts)
) WITHOUT ROWID;

CREATE TABLE rollup_state(
  resolution TEXT PRIMARY KEY, -- '1m' | '1h' | '1d'
  last_ts    INTEGER NOT NULL  -- highest bucket-start already materialized (exclusive upper bound of last run)
);
