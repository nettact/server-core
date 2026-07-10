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
  capabilities TEXT NOT NULL DEFAULT '[]',
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

CREATE TABLE config_versions(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  version INTEGER NOT NULL,
  desired_state TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  UNIQUE(agent_id, version)
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
