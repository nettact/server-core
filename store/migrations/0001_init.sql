-- NetTact P0 initial schema (architecture §8: metadata / metrics / events /
-- incidents / config-audit). Single-user, no tenant_id. The schema_migrations
-- table is created by the migrator itself, not here.

-- ===== metadata (single user, no tenant) =====
CREATE TABLE users(
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions(
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE sites(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE enrollment_tokens(
  token_hash TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  note TEXT,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP
);

CREATE TABLE agents(
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  public_key BLOB NOT NULL,
  token_hash TEXT NOT NULL,
  hostname TEXT,
  platform TEXT,
  agent_version TEXT,
  -- Local permission policy the agent reports on every (re)connect: supported =
  -- what the build+platform can do, granted = the local policy, effective = the
  -- usable intersection. All three are JSON string arrays of permission IDs.
  perm_supported TEXT NOT NULL DEFAULT '[]',
  perm_granted TEXT NOT NULL DEFAULT '[]',
  perm_effective TEXT NOT NULL DEFAULT '[]',
  policy_source TEXT NOT NULL DEFAULT '',
  policy_hash TEXT NOT NULL DEFAULT '',
  -- Newest MonitorStatus config_version accepted from this agent; -1 = none yet.
  -- Feeds the monotonic guard that drops stale monitor-status frames.
  last_status_config_version INTEGER NOT NULL DEFAULT -1,
  status TEXT NOT NULL DEFAULT 'online',
  config_version INTEGER NOT NULL DEFAULT 0,
  reported_config_version INTEGER NOT NULL DEFAULT 0,
  last_seen_at TIMESTAMP,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_agents_site ON agents(site_id);

CREATE TABLE devices(
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  mac TEXT NOT NULL,
  ip TEXT,
  hostname TEXT,
  vendor TEXT,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  UNIQUE(site_id, mac)
);

CREATE TABLE interfaces(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  name TEXT NOT NULL,
  addrs TEXT,
  gateway TEXT,
  dns TEXT,
  up INTEGER,
  updated_at TIMESTAMP,
  UNIQUE(agent_id, name)
);

-- Monitoring targets (the source Lite pushes down as DesiredState).
-- agent_id NULL = applies to all agents in the site; non-null = per-agent override.
CREATE TABLE probe_tasks(
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  agent_id TEXT REFERENCES agents(id),
  kind TEXT NOT NULL,
  target TEXT,
  params TEXT,
  tier TEXT NOT NULL DEFAULT 'regular',
  enabled INTEGER NOT NULL DEFAULT 1
);

-- ===== dedup (idempotent ingest, §3.3 / §5.1) =====
CREATE TABLE agent_packets(
  agent_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  received_at TIMESTAMP NOT NULL,
  sent_at TIMESTAMP,
  PRIMARY KEY(agent_id, sequence)
);

-- ===== metrics (time series) =====
CREATE TABLE metrics(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  ts TIMESTAMP NOT NULL,
  kind TEXT NOT NULL,
  target TEXT,
  layer TEXT,
  value REAL NOT NULL,
  unit TEXT,
  labels TEXT
);
CREATE INDEX idx_metrics_query ON metrics(agent_id, kind, target, ts);
CREATE INDEX idx_metrics_ts ON metrics(ts);

-- ===== events =====
CREATE TABLE events(
  id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  ts TIMESTAMP NOT NULL,
  type TEXT NOT NULL,
  layer TEXT,
  severity TEXT,
  message TEXT,
  attrs TEXT,
  PRIMARY KEY(agent_id, id)
);
CREATE INDEX idx_events_site_ts ON events(site_id, ts);

-- ===== rules / alerts =====
CREATE TABLE alert_rules(
  id TEXT PRIMARY KEY,
  site_id TEXT REFERENCES sites(id),
  name TEXT NOT NULL,
  metric_kind TEXT NOT NULL,
  target_glob TEXT,
  comparator TEXT NOT NULL,
  threshold REAL NOT NULL,
  for_seconds INTEGER NOT NULL DEFAULT 0,
  layer TEXT,
  severity TEXT NOT NULL DEFAULT 'warn',
  channel_ids TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE alerts(
  id TEXT PRIMARY KEY,
  rule_id TEXT REFERENCES alert_rules(id),
  agent_id TEXT,
  site_id TEXT NOT NULL,
  state TEXT NOT NULL,
  value REAL,
  started_at TIMESTAMP NOT NULL,
  resolved_at TIMESTAMP,
  last_eval_at TIMESTAMP,
  incident_id TEXT
);
CREATE INDEX idx_alerts_state ON alerts(site_id, state);

-- ===== incidents + timeline (§8.4) =====
CREATE TABLE incidents(
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  title TEXT,
  suspected_layer TEXT,
  state TEXT NOT NULL DEFAULT 'open',
  severity TEXT,
  summary TEXT,
  opened_at TIMESTAMP NOT NULL,
  resolved_at TIMESTAMP
);
CREATE INDEX idx_incidents_state ON incidents(site_id, state);

CREATE TABLE incident_timeline(
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  ts TIMESTAMP NOT NULL,
  kind TEXT NOT NULL,
  message TEXT,
  ref TEXT
);
CREATE INDEX idx_timeline_incident ON incident_timeline(incident_id, ts);

-- ===== config / audit =====
CREATE TABLE notification_channels(
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  config TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TIMESTAMP NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT
);

-- ===== agent local-permission policy: monitor status + operational issues =====

-- monitor_status is the server's per-(agent, monitor) view of how a monitor is
-- executing: 'active' when the agent runs it, or permission_blocked /
-- target_blocked / unsupported when it does not. Probe monitors are populated
-- from the agent's MonitorStatus frames (and predicted on target save); host
-- monitors are evaluated server-side from their bound alert rules. It is the
-- complete current state — rows absent from a report are deleted.
CREATE TABLE monitor_status(
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  monitor_id TEXT NOT NULL REFERENCES probe_tasks(id) ON DELETE CASCADE,
  status TEXT NOT NULL,                       -- active | permission_blocked | target_blocked | unsupported
  missing_permissions TEXT NOT NULL DEFAULT '[]',
  matched_selector TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',            -- agent-reported detail (literal_denied, method_requires_extended, …)
  policy_hash TEXT NOT NULL DEFAULT '',
  config_version INTEGER NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  PRIMARY KEY(agent_id, monitor_id)
);

-- operational_issues is the deduplicated, operator-facing list of monitors that
-- are not running. One row per (agent, category, ref, reason); repeat reports
-- bump count/last_seen rather than pile up. Resolved when the monitor recovers,
-- goes out of scope, or is disabled. Never fed into alert/incident evaluation.
CREATE TABLE operational_issues(
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  category TEXT NOT NULL DEFAULT 'monitor',
  ref_id TEXT REFERENCES probe_tasks(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,                        -- permission_blocked | target_blocked | unsupported
  dedupe_key TEXT NOT NULL UNIQUE,             -- agent_id|category|ref_id|reason
  missing_permissions TEXT NOT NULL DEFAULT '[]',
  matched_selector TEXT NOT NULL DEFAULT '',
  policy_hash TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'active',        -- active | resolved
  read INTEGER NOT NULL DEFAULT 0,
  count INTEGER NOT NULL DEFAULT 1,
  first_seen_at TIMESTAMP NOT NULL,
  last_seen_at TIMESTAMP NOT NULL,
  resolved_at TIMESTAMP
);
CREATE INDEX idx_opissues_active ON operational_issues(site_id, state, read);
