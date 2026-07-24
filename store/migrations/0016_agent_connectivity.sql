-- Agent connectivity provenance + dedicated agent connectivity alerts
-- (AGENT-001 status list, AGENT-002 offline/recovery alerts).
--
-- Connectivity alerts are a SEPARATE stream from the metric-threshold
-- rule/incident engine: they key on the agent's stable identity and liveness,
-- carry their own reason/severity/frozen channels, and never enter the incident
-- merge model. Provenance columns on agents let the status list distinguish
-- never-connected from offline and annotate why the last disconnect happened.
--
-- Pre-release, zero users: direct schema edits, no rollback/compat path.

-- NULL = the agent enrolled but never completed a WebSocket/pipe Hello, so it
-- has never actually connected. Set once on the first Hello and never cleared.
ALTER TABLE agents ADD COLUMN first_connected_at TIMESTAMP;

-- How the agent's most recent session ended, recorded at session teardown:
-- '' | 'clean' | 'error' | 'superseded' | 'revoked' | 'server_shutdown'
-- | 'unsupported_schema'. Drives the connectivity-alert reason mapping
-- (clean -> clean_shutdown, unsupported_schema -> version_incompatible,
-- everything else -> unexpected) and the status-list disconnect annotation.
ALTER TABLE agents ADD COLUMN last_disconnect_kind TEXT NOT NULL DEFAULT '';

-- Operator switch: when set, this agent produces no offline/recovery alerts
-- (the "user-deactivated connectivity alerts" semantic). It still connects and
-- ingests normally; only the alert engine skips it.
ALTER TABLE agents ADD COLUMN connectivity_alerts_muted INTEGER NOT NULL DEFAULT 0;

-- Existing agents that have ever been seen have necessarily connected; backfill
-- so a dev database does not show every pre-migration agent as never-connected.
UPDATE agents SET first_connected_at = last_seen_at WHERE last_seen_at IS NOT NULL;

-- Why each status transition happened (the disconnect kind for offline
-- transitions; '' for online), so the detail-view timeline is self-explanatory.
ALTER TABLE agent_status_history ADD COLUMN reason TEXT NOT NULL DEFAULT '';

-- Agent connectivity alerts: at most one firing row per agent (partial unique
-- index), frozen display fields + channel selection at fire so a later rename or
-- regroup never rewrites history attribution. No FK on agent_id: registry
-- DeleteAgent removes these rows explicitly inside its own transaction.
CREATE TABLE agent_alerts(
  id                 TEXT PRIMARY KEY,                  -- 'aa_' + uuid
  site_id            TEXT NOT NULL,
  agent_id           TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'firing' CHECK(status IN('firing','resolved')),
  reason             TEXT NOT NULL CHECK(reason IN('unexpected','clean_shutdown','version_incompatible')),
  severity           TEXT NOT NULL DEFAULT 'warn',
  agent_display_name TEXT NOT NULL DEFAULT '',          -- frozen at fire
  agent_hostname     TEXT NOT NULL DEFAULT '',          -- frozen at fire
  channel_ids        TEXT NOT NULL DEFAULT '[]',        -- frozen channel selection; [] = all enabled
  offline_since      TIMESTAMP NOT NULL,                -- agents.last_seen_at frozen at fire
  opened_at          TIMESTAMP NOT NULL,
  resolved_at        TIMESTAMP,
  resolve_reason     TEXT NOT NULL DEFAULT '' CHECK(resolve_reason IN('','recovered','muted','disabled'))
);
CREATE UNIQUE INDEX idx_agent_alerts_one_firing ON agent_alerts(agent_id) WHERE status='firing';
CREATE INDEX idx_agent_alerts_site ON agent_alerts(site_id, status, opened_at);
CREATE INDEX idx_agent_alerts_agent ON agent_alerts(agent_id, opened_at);
