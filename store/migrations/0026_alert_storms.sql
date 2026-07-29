-- ALERT-001: alert-storm suppression.
--
-- When an upstream link dies, every monitor group under one Agent breaches at
-- roughly the same moment. Each group merges into its own incident and each
-- incident announces itself, so the operator gets N messages about ONE root
-- cause — and then N more on recovery. That is the fastest way to teach someone
-- to mute notifications entirely, which makes every future alarm worthless.
--
-- A storm is a CORRELATION LAYER ON TOP OF INCIDENTS, never a replacement for
-- them. Each incident is still recorded in full, still has its own members,
-- evidence and timeline; the storm only decides that ONE message goes out
-- instead of N. Nothing about the fault record changes.
--
-- Correlation is per (site, agent): the agent is the vantage point from which
-- the faults were observed, so "everything this agent can see broke at once" is
-- the claim a storm actually supports. Cross-agent / site-level re-aggregation
-- is deliberately out of scope for the first version.

-- ===== storms =====
-- There is deliberately NO channel_ids column. A storm's routing is frozen the
-- same way an incident's is: onto its own notification_deliveries rows, written
-- when the storm forms. One representation of "who was told", not two that can
-- drift apart.
--
-- agent_name is frozen at open time so a later rename cannot rewrite what the
-- notification said, matching fault_signals' treatment of every display fact.
CREATE TABLE alert_storms(
  id              TEXT PRIMARY KEY,              -- 'stm_' + uuid
  site_id         TEXT NOT NULL,
  agent_id        TEXT NOT NULL,
  agent_name      TEXT NOT NULL DEFAULT '',
  state           TEXT NOT NULL CHECK(state IN('open','resolved')),
  severity        TEXT NOT NULL DEFAULT 'warn',  -- worst severity across open members
  suspected_layer TEXT NOT NULL DEFAULT '',      -- most fundamental layer across open members
  opened_at       TIMESTAMP NOT NULL,
  resolved_at     TIMESTAMP
);
-- At most one open storm per (site, agent): a second concurrent storm for the
-- same vantage point would reintroduce exactly the duplication this table exists
-- to remove.
CREATE UNIQUE INDEX idx_alert_storms_open ON alert_storms(site_id, agent_id) WHERE state='open';
CREATE INDEX idx_alert_storms_site ON alert_storms(site_id, opened_at);

-- Membership lives on the incident, not in a join table: an incident belongs to
-- at most one storm, and it keeps that link after the storm closes so the
-- history explains why only one notification was sent.
ALTER TABLE incidents ADD COLUMN storm_id TEXT REFERENCES alert_storms(id);
CREATE INDEX idx_incidents_storm ON incidents(storm_id);

-- ===== per-channel opt-out =====
-- Merging is the default because it is right for the destinations people
-- actually read (a phone, a chat room), where N messages about one outage is the
-- harm. It is a per-CHANNEL switch rather than a global one because the same
-- server usually feeds both those destinations and a machine consumer — a
-- ticketing webhook or a log sink that wants one record per incident and would
-- be made lossy by a summary. Those two needs are not in conflict; they just
-- belong to different channels.
--
-- A channel with merging off keeps receiving one notice per incident, open and
-- recovery alike, exactly as if storms did not exist.
ALTER TABLE notification_channels ADD COLUMN storm_merge INTEGER NOT NULL DEFAULT 1;

-- ===== deliveries: generalize the subject from incident to incident|storm =====
-- Recreated, not ALTERed: SQLite cannot add a CHECK or a foreign key in place.
-- Existing rows are DISCARDED rather than copied — this is pre-release with no
-- deployed data, and a delivery row is a plan or a receipt for a notification
-- that has already been sent or already lost its moment. Carrying them across
-- would buy nothing and cost a migration path to maintain.
--
-- Exactly one of incident_id / storm_id is set (the CHECK). SQLite treats NULLs
-- as distinct inside a UNIQUE index, so each of the two UNIQUE constraints only
-- ever constrains its own kind of row — which is what keeps the INSERT OR IGNORE
-- idempotency guarantee (a replayed event, a reconnect or a restart delivers at
-- most once) intact for storms as well as incidents.
DROP TABLE notification_deliveries;

CREATE TABLE notification_deliveries(
  id               TEXT PRIMARY KEY,                    -- 'nd_' + uuid
  incident_id      TEXT REFERENCES incidents(id) ON DELETE CASCADE,
  storm_id         TEXT REFERENCES alert_storms(id) ON DELETE CASCADE,
  site_id          TEXT NOT NULL,
  event_kind       TEXT NOT NULL CHECK(event_kind IN(
                     'incident.opened','incident.resolved','storm.opened','storm.resolved')),
  channel_id       TEXT NOT NULL,
  policy_id        TEXT NOT NULL DEFAULT '',            -- frozen at plan time
  recovery_enabled INTEGER NOT NULL DEFAULT 1,          -- frozen notify_recovery
  status           TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','sent','failed','canceled')),
  due_at           TIMESTAMP NOT NULL,
  created_at       TIMESTAMP NOT NULL,
  sent_at          TIMESTAMP,
  CHECK((incident_id IS NULL) <> (storm_id IS NULL)),
  UNIQUE(incident_id, event_kind, channel_id),
  UNIQUE(storm_id, event_kind, channel_id)
);
CREATE INDEX idx_nd_due ON notification_deliveries(status, due_at);
CREATE INDEX idx_nd_incident ON notification_deliveries(incident_id);
CREATE INDEX idx_nd_storm ON notification_deliveries(storm_id);
