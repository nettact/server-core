-- Re-key the time-series store by monitor entity (probe_tasks.id) and rebuild
-- the rollup watermark per series.
--
-- Why: series were UNIQUE(agent_id, kind, target), so two user-created monitors
-- pointing at the same target string merged into one series — their data,
-- rules, alerts and purges were indistinguishable. Samples now carry the
-- monitor_id the agent stamps from DesiredState, and the series dictionary
-- keys on it. System metrics (host.*, iface.up, agent.*, the built-in gateway
-- probe) are not user-created monitors and use monitor_id=''.
--
-- rollup_state moves from one global watermark per resolution to one per
-- (resolution, series): the downsampler now iterates series and range-seeks
-- each one's tail (PK prefix), instead of GROUP-BY-scanning a trailing window
-- of the whole samples table (which has no ts index) every run.
--
-- Pre-release, zero users: a clean rebuild (dev data wiped) beats a migration.

DROP TABLE IF EXISTS samples;
DROP TABLE IF EXISTS rollup_1m;
DROP TABLE IF EXISTS rollup_1h;
DROP TABLE IF EXISTS rollup_1d;
DROP TABLE IF EXISTS rollup_state;
DROP INDEX IF EXISTS idx_series_agent_kind;
DROP TABLE IF EXISTS series;

CREATE TABLE series(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id   TEXT NOT NULL,
  site_id    TEXT NOT NULL,
  monitor_id TEXT NOT NULL DEFAULT '', -- probe_tasks.id; '' = system series
  kind       TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  layer      TEXT NOT NULL DEFAULT '',
  unit       TEXT NOT NULL DEFAULT '',
  UNIQUE(agent_id, monitor_id, kind, target)
);
CREATE INDEX idx_series_agent_kind ON series(agent_id, kind, target);
CREATE INDEX idx_series_monitor ON series(monitor_id);

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
  resolution TEXT NOT NULL,    -- '1m' | '1h' | '1d'
  series_id  INTEGER NOT NULL,
  last_ts    INTEGER NOT NULL, -- exclusive upper bound of the last materialized bucket
  PRIMARY KEY(resolution, series_id)
) WITHOUT ROWID;

-- agent_packets gains retention (it grew forever); the hourly prune deletes by
-- received_at, which needs an index to avoid a full scan.
CREATE INDEX idx_agent_packets_received ON agent_packets(received_at);
