-- INCIDENT-001 → INCIDENT-002 → DIAG-001 final first-release model.
--
-- Clean cut (pre-release, zero users): the target-level rule/scope model is
-- replaced outright by monitor groups, one-layer AND/OR group rules evaluated
-- per Agent, per-Agent alert instances with frozen evidence, group-aware merged
-- /unmerged incidents, immutable incident snapshots, and independent traceroute
-- reports. Obsolete tables/columns are dropped rather than migrated; dev data is
-- discarded (codebase precedent: 0011/0012 DROP+CREATE rebuilds).
--
-- Drop order is child-first so an FK NO ACTION parent delete never violates
-- (incident_timeline before incidents, alerts before their old rule table, the
-- target-scope join before probe_tasks). monitor_status / operational_issues are
-- intentionally NOT dropped: their rows cascade away when probe_tasks is dropped
-- (ON DELETE CASCADE) and their FK re-resolves by name to the rebuilt table.

DROP TABLE IF EXISTS alert_evidence;
DROP TABLE IF EXISTS trace_report_refs;
DROP TABLE IF EXISTS trace_hops;
DROP TABLE IF EXISTS trace_reports;
DROP TABLE IF EXISTS incident_snapshot_entries;
DROP TABLE IF EXISTS incident_snapshots;
DROP TABLE IF EXISTS incident_timeline;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS alert_rules;
DROP TABLE IF EXISTS rule_condition_state;
DROP TABLE IF EXISTS group_rule_conditions;
DROP TABLE IF EXISTS group_rules;
DROP TABLE IF EXISTS probe_task_groups;
DROP TABLE IF EXISTS probe_tasks;
DROP TABLE IF EXISTS monitor_group_agent_groups;
DROP TABLE IF EXISTS monitor_groups;

-- ===== monitor groups =====
-- A monitor group owns a static set of targets and the Agent execution scope for
-- all of them. Exactly one undeletable default group per site (is_default=1).
-- Scope: all_agents=1 → every site agent; else the union of the referenced agent
-- groups (monitor_group_agent_groups). merge_enabled controls incident merging.
CREATE TABLE monitor_groups(
  id            TEXT PRIMARY KEY,
  site_id       TEXT NOT NULL REFERENCES sites(id),
  name          TEXT NOT NULL,
  is_default    INTEGER NOT NULL DEFAULT 0,
  merge_enabled INTEGER NOT NULL DEFAULT 1,
  all_agents    INTEGER NOT NULL DEFAULT 1,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_monitor_groups_site ON monitor_groups(site_id);
CREATE UNIQUE INDEX idx_monitor_groups_default ON monitor_groups(site_id) WHERE is_default=1;

-- monitor group ↔ agent group scope (consulted only when all_agents=0).
CREATE TABLE monitor_group_agent_groups(
  monitor_group_id TEXT NOT NULL REFERENCES monitor_groups(id) ON DELETE CASCADE,
  agent_group_id   TEXT NOT NULL REFERENCES agent_groups(id)   ON DELETE CASCADE,
  PRIMARY KEY(monitor_group_id, agent_group_id)
);
CREATE INDEX idx_mgag_agent_group ON monitor_group_agent_groups(agent_group_id);

-- ===== monitoring targets (rebuilt) =====
-- Every target belongs to exactly one monitor group (group_id NOT NULL). The
-- old per-target all_agents / probe_task_groups scope is gone — scope lives on
-- the group now.
CREATE TABLE probe_tasks(
  id       TEXT PRIMARY KEY,
  site_id  TEXT NOT NULL REFERENCES sites(id),
  group_id TEXT NOT NULL REFERENCES monitor_groups(id),
  kind     TEXT NOT NULL,
  target   TEXT,
  params   TEXT,
  enabled  INTEGER NOT NULL DEFAULT 1,
  name     TEXT
);
CREATE INDEX idx_probe_tasks_site ON probe_tasks(site_id);
CREATE INDEX idx_probe_tasks_group ON probe_tasks(group_id);

-- ===== group rules and one-layer AND/OR conditions =====
CREATE TABLE group_rules(
  id          TEXT PRIMARY KEY,
  group_id    TEXT NOT NULL REFERENCES monitor_groups(id),
  site_id     TEXT NOT NULL,
  name        TEXT NOT NULL,
  op          TEXT NOT NULL CHECK(op IN('and','or')),
  layer       TEXT NOT NULL DEFAULT '',
  severity    TEXT NOT NULL DEFAULT 'warn',
  channel_ids TEXT NOT NULL DEFAULT '[]',
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_group_rules_group ON group_rules(group_id);
CREATE INDEX idx_group_rules_site ON group_rules(site_id);

-- Each condition references an in-group target and carries the threshold test.
CREATE TABLE group_rule_conditions(
  id             TEXT PRIMARY KEY,
  rule_id        TEXT NOT NULL REFERENCES group_rules(id) ON DELETE CASCADE,
  target_id      TEXT NOT NULL REFERENCES probe_tasks(id),
  metric_kind    TEXT NOT NULL,
  comparator     TEXT NOT NULL,
  threshold      REAL NOT NULL,
  fail_threshold INTEGER NOT NULL DEFAULT 1,
  for_seconds    INTEGER NOT NULL DEFAULT 0,
  position       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_grc_rule ON group_rule_conditions(rule_id);
CREATE INDEX idx_grc_target ON group_rule_conditions(target_id);

-- Per-(condition, Agent) evaluation state, persisted so a restart does not reset
-- consecutive-failure counters or dwell timers.
CREATE TABLE rule_condition_state(
  condition_id      TEXT NOT NULL REFERENCES group_rule_conditions(id) ON DELETE CASCADE,
  agent_id          TEXT NOT NULL,
  consecutive_fails INTEGER NOT NULL DEFAULT 0,
  first_breach_at   TIMESTAMP,
  satisfied         INTEGER NOT NULL DEFAULT 0,
  last_value        REAL,
  last_eval_at      TIMESTAMP,
  PRIMARY KEY(condition_id, agent_id)
);

-- ===== incidents (rebuilt, group-aware) =====
-- open_key is the idempotent open-incident identity: "grp:<group_id>" when the
-- group merges, else "alert:<alert_id>". The partial unique index guarantees at
-- most one OPEN incident per key, so concurrent/replayed raise events cannot
-- duplicate an open incident. Ended incidents never reopen.
CREATE TABLE incidents(
  id              TEXT PRIMARY KEY,
  site_id         TEXT NOT NULL,
  group_id        TEXT NOT NULL,
  group_name      TEXT NOT NULL DEFAULT '',
  open_key        TEXT NOT NULL,
  title           TEXT NOT NULL DEFAULT '',
  suspected_layer TEXT NOT NULL DEFAULT '',
  state           TEXT NOT NULL DEFAULT 'open' CHECK(state IN('open','resolved')),
  severity        TEXT NOT NULL DEFAULT 'warn',
  summary         TEXT NOT NULL DEFAULT '',
  resolve_reason  TEXT NOT NULL DEFAULT '',
  evidence_expired INTEGER NOT NULL DEFAULT 0,
  opened_at       TIMESTAMP NOT NULL,
  resolved_at     TIMESTAMP
);
CREATE UNIQUE INDEX idx_incidents_open_key ON incidents(open_key) WHERE state='open';
CREATE INDEX idx_incidents_site_state ON incidents(site_id, state, opened_at);

-- ===== alert instances (rebuilt, keyed (group rule, Agent)) =====
-- At most one firing alert per (rule_id, agent_id) — the partial unique index
-- enforces it. resolve_reason is 'recovered' or 'configuration_changed'.
--
-- Immutable history: rule_id is NULLABLE with ON DELETE SET NULL, and the rule's
-- and group's display facts are FROZEN onto the row (rule_name / group_name) at
-- fire time. Deleting or editing a rule terminates its active alerts as
-- configuration_changed but leaves the resolved rows (and their alert_evidence)
-- structurally intact — the reference nulls out and the frozen names carry the
-- history, so nothing dangles and no compat path is needed. A firing alert always
-- has a live rule_id (its rule cannot be deleted without first terminating it).
-- channel_ids freezes the rule's notification routing onto the alert at fire time
-- (the same JSON array of channel ids the rule carried). It is the durable routing
-- source for an incident's notifications: final resolution/termination notices are
-- routed by the union of the incident's member alerts' frozen channel_ids, so they
-- reach the configured channels even after every member has resolved (no firing row
-- to join) or the rule was deleted (rule_id nulled) — never falling back to all
-- enabled channels merely because routing could no longer be joined live.
CREATE TABLE alerts(
  id             TEXT PRIMARY KEY,
  rule_id        TEXT REFERENCES group_rules(id) ON DELETE SET NULL,
  rule_name      TEXT NOT NULL DEFAULT '',
  agent_id       TEXT NOT NULL,
  site_id        TEXT NOT NULL,
  group_id       TEXT NOT NULL,
  group_name     TEXT NOT NULL DEFAULT '',
  incident_id    TEXT REFERENCES incidents(id),
  state          TEXT NOT NULL CHECK(state IN('firing','resolved')),
  severity       TEXT NOT NULL DEFAULT 'warn',
  layer          TEXT NOT NULL DEFAULT '',
  channel_ids    TEXT NOT NULL DEFAULT '[]',
  resolve_reason TEXT NOT NULL DEFAULT '',
  started_at     TIMESTAMP NOT NULL,
  resolved_at    TIMESTAMP
);
CREATE UNIQUE INDEX idx_alerts_open ON alerts(rule_id, agent_id) WHERE state='firing';
CREATE INDEX idx_alerts_incident ON alerts(incident_id);
CREATE INDEX idx_alerts_site_state ON alerts(site_id, state);
CREATE INDEX idx_alerts_agent ON alerts(agent_id);

-- Immutable per-condition evidence frozen when a condition contributes to a
-- firing alert (at fire time, and whenever an additional condition becomes
-- satisfied while the alert is already firing). Survives later config edits /
-- target deletion. One row per (alert, condition). target_addr and target_port
-- freeze the exact trigger-time destination and TCP port so the automatic
-- traceroute is derived entirely from this evidence, never from live probe_tasks
-- that may have been edited after the fault.
CREATE TABLE alert_evidence(
  id          TEXT PRIMARY KEY,
  alert_id    TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  condition_id TEXT NOT NULL,
  target_id   TEXT NOT NULL,
  target_name TEXT NOT NULL DEFAULT '',
  target_addr TEXT NOT NULL DEFAULT '',
  target_port INTEGER NOT NULL DEFAULT 0,
  probe_kind  TEXT NOT NULL DEFAULT '',
  metric_kind TEXT NOT NULL,
  comparator  TEXT NOT NULL,
  threshold   REAL NOT NULL,
  value       REAL NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  UNIQUE(alert_id, condition_id)
);
CREATE INDEX idx_alert_evidence_alert ON alert_evidence(alert_id);

-- ===== incident timeline (same shape; ref column now populated) =====
CREATE TABLE incident_timeline(
  id          TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  ts          TIMESTAMP NOT NULL,
  kind        TEXT NOT NULL,
  message     TEXT,
  ref         TEXT
);
CREATE INDEX idx_timeline_incident ON incident_timeline(incident_id, ts);

-- ===== incident snapshots (INCIDENT-002 schema foundation) =====
-- One immutable snapshot per incident. The base part is written synchronously in
-- the incident-open transaction; per-Agent entries are filled asynchronously and
-- idempotently by (request_id, incident, agent). Orchestration lands in a later
-- server-core session; the schema is established here.
CREATE TABLE incident_snapshots(
  id          TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
  status      TEXT NOT NULL DEFAULT 'collecting',   -- collecting | complete | partial | failed
  base        TEXT NOT NULL DEFAULT '',             -- immutable base JSON
  total_bytes INTEGER NOT NULL DEFAULT 0,
  truncated   INTEGER NOT NULL DEFAULT 0,
  deadline_at TIMESTAMP NOT NULL,
  created_at  TIMESTAMP NOT NULL
);

CREATE TABLE incident_snapshot_entries(
  id            TEXT PRIMARY KEY,
  snapshot_id   TEXT NOT NULL REFERENCES incident_snapshots(id) ON DELETE CASCADE,
  request_id    TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  agent_name    TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'collecting', -- collecting | complete | partial | failed
  reason        TEXT NOT NULL DEFAULT '',
  clock_skew_ms INTEGER NOT NULL DEFAULT 0,
  skewed        INTEGER NOT NULL DEFAULT 0,
  payload       TEXT NOT NULL DEFAULT '',           -- field-group JSON
  requested_at  TIMESTAMP NOT NULL,
  received_at   TIMESTAMP,
  UNIQUE(snapshot_id, agent_id)
);
CREATE UNIQUE INDEX idx_snap_entry_req ON incident_snapshot_entries(request_id);

-- ===== traceroute reports (DIAG-001 schema foundation) =====
-- Independent execution records referenced by many incidents/alerts/conditions.
-- Single-flight sharing is scoped to overlapping alert lifecycles: while a key's
-- active reference count is >0 the report's cohort stays open (cohort_open=1) and
-- the partial unique index prevents a second open-cohort report for the same key;
-- once all references deactivate the cohort closes and the next alert creates a
-- fresh report. deadline_at = requested_at + timeout_ms is the only validity
-- bound (no queue grace / freshness / cooldown).
CREATE TABLE trace_reports(
  id           TEXT PRIMARY KEY,
  site_id      TEXT NOT NULL,
  agent_id     TEXT NOT NULL,
  agent_name   TEXT NOT NULL DEFAULT '',
  dest_key     TEXT NOT NULL,                       -- canonical: "ip:1.2.3.4" | "host:example.com"
  dest_host    TEXT NOT NULL,
  dest_ip      TEXT NOT NULL DEFAULT '',
  mode         TEXT NOT NULL CHECK(mode IN('icmp','tcp')),
  port         INTEGER NOT NULL DEFAULT 0,
  status       TEXT NOT NULL DEFAULT 'queued',      -- queued|running|succeeded|partial|timed_out|unsupported|failed|canceled
  reason       TEXT NOT NULL DEFAULT '',
  max_hops     INTEGER NOT NULL,
  attempts     INTEGER NOT NULL,
  timeout_ms   INTEGER NOT NULL,
  resolve_hops INTEGER NOT NULL DEFAULT 0,
  reached      INTEGER NOT NULL DEFAULT 0,
  reached_ttl  INTEGER NOT NULL DEFAULT 0,
  cohort_open  INTEGER NOT NULL DEFAULT 1,
  requested_at TIMESTAMP NOT NULL,
  started_at   TIMESTAMP,
  completed_at TIMESTAMP,
  deadline_at  TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX idx_trace_singleflight
  ON trace_reports(agent_id, dest_key, mode, port) WHERE cohort_open=1;
CREATE INDEX idx_trace_status ON trace_reports(status);

CREATE TABLE trace_hops(
  report_id TEXT NOT NULL REFERENCES trace_reports(id) ON DELETE CASCADE,
  ttl       INTEGER NOT NULL,
  attempt   INTEGER NOT NULL,
  addr      TEXT NOT NULL DEFAULT '',
  hostname  TEXT NOT NULL DEFAULT '',
  rtt_us    INTEGER,
  timed_out INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(report_id, ttl, attempt)
) WITHOUT ROWID;

CREATE TABLE trace_report_refs(
  report_id    TEXT NOT NULL REFERENCES trace_reports(id),
  incident_id  TEXT NOT NULL REFERENCES incidents(id),
  alert_id     TEXT NOT NULL,
  condition_id TEXT NOT NULL DEFAULT '',
  active       INTEGER NOT NULL DEFAULT 1,
  created_at   TIMESTAMP NOT NULL,
  PRIMARY KEY(report_id, incident_id, alert_id, condition_id)
);
CREATE INDEX idx_trr_incident ON trace_report_refs(incident_id);
CREATE INDEX idx_trr_alert ON trace_report_refs(alert_id, active);
