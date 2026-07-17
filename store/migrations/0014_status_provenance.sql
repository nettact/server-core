-- Status provenance & generation-aware storage (STATUS-001).
--
-- Config generation moves from a per-agent counter to a site-level serial, and
-- every probe target carries its own material-change generation. Samples and
-- monitor-status rows are attributed to the generation they were produced under
-- so an obsolete-config packet, replay, or stale report can never roll current
-- target status backward.
--
-- Pre-release, zero users: direct schema edits, no rollback/compat path.

-- Site-level monotonic config serial: the single desired-config axis. Replaces
-- the per-agent agents.config_version (dropped below).
ALTER TABLE sites          ADD COLUMN config_serial INTEGER NOT NULL DEFAULT 0;

-- Per-target material generation: the site serial (and wall time) at creation or
-- last MATERIAL change (kind / target / params / enabled — never name / group).
ALTER TABLE probe_tasks    ADD COLUMN config_serial INTEGER NOT NULL DEFAULT 0;
ALTER TABLE probe_tasks    ADD COLUMN config_changed_at TIMESTAMP;
UPDATE probe_tasks SET config_changed_at = CURRENT_TIMESTAMP;

-- monitor_status provenance: whether a row is an agent-confirmed report or a
-- server-side prediction, which target generation it attests, the per-pair
-- assignment clock (pending grace), and the agent's reported effective schedule.
-- The existing config_version column stays as the whole-frame desired-version
-- watermark only.
ALTER TABLE monitor_status ADD COLUMN source TEXT NOT NULL DEFAULT 'reported'
                           CHECK(source IN ('reported','predicted'));
ALTER TABLE monitor_status ADD COLUMN target_config_serial INTEGER NOT NULL DEFAULT 0;
ALTER TABLE monitor_status ADD COLUMN assigned_at TIMESTAMP;
UPDATE monitor_status SET assigned_at = updated_at;
ALTER TABLE monitor_status ADD COLUMN effective_interval_seconds INTEGER;
ALTER TABLE monitor_status ADD COLUMN cycle_deadline_ms INTEGER;

-- The per-agent desired counter is superseded by sites.config_serial. Before it
-- is dropped, seed each site's new serial at or above the highest watermark any
-- of its agents already reached on the old per-agent axis (applied config_version,
-- reported_config_version, or last_status_config_version). A running agent keeps
-- its applied watermark across a server-restart reconnect, and its DesiredState
-- guard drops any whole-frame version below that watermark; seeding here ensures
-- the very next site serial exceeds every applied value, so post-migration edits
-- are not rejected as stale. Sites with no agents keep the 0 default.
UPDATE sites SET config_serial = (
  SELECT COALESCE(MAX(w), 0) FROM (
    SELECT MAX(config_version)             AS w FROM agents WHERE site_id = sites.id
    UNION ALL
    SELECT MAX(reported_config_version)         FROM agents WHERE site_id = sites.id
    UNION ALL
    SELECT MAX(last_status_config_version)      FROM agents WHERE site_id = sites.id
  )
) WHERE EXISTS(SELECT 1 FROM agents WHERE site_id = sites.id);

-- The per-agent desired counter is superseded by sites.config_serial.
ALTER TABLE agents         DROP COLUMN config_version;   -- modernc bundles SQLite >= 3.40

-- Generation-aware series identity (table rebuild: the UNIQUE is a table
-- constraint SQLite cannot alter in place). Existing rows keep serial 0, which
-- matches probe_tasks.config_serial's 0 default, so current dev data stays
-- "current" until the first material edit. Sample ids are preserved, so samples
-- and rollups (which reference series_id, no FK) stay linked untouched.
CREATE TABLE series_new(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL, site_id TEXT NOT NULL,
  monitor_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', layer TEXT NOT NULL DEFAULT '',
  unit TEXT NOT NULL DEFAULT '', config_serial INTEGER NOT NULL DEFAULT 0,
  UNIQUE(agent_id, monitor_id, kind, target, config_serial));
INSERT INTO series_new(id, agent_id, site_id, monitor_id, kind, target, layer, unit)
  SELECT id, agent_id, site_id, monitor_id, kind, target, layer, unit FROM series;
DROP TABLE series;
ALTER TABLE series_new RENAME TO series;
CREATE INDEX idx_series_agent_kind ON series(agent_id, kind, target);
CREATE INDEX idx_series_monitor   ON series(monitor_id);
CREATE INDEX idx_series_site_kind ON series(site_id, kind);

-- Drop the dead legacy config_versions table (SRV-014 clean cut). Its CREATE was
-- removed from 0001_init.sql, which only affects fresh databases; a database that
-- already applied the former 0001 still carries the orphaned table. IF EXISTS is a
-- no-op on fresh databases (where it was never created) and removes it on in-place
-- upgrades, so both schemas converge with no active reader/writer left behind.
DROP TABLE IF EXISTS config_versions;
