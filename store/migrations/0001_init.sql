-- NetTact release baseline schema.
--
-- This is the squashed equivalent of the pre-release migration chain (the old
-- 0001–0026, which carried the development history: tables created then dropped,
-- columns renamed, one-off data repairs). Pre-release with zero users, so that
-- history has no one to migrate and was collapsed into this single baseline.
-- Post-release changes append 0002_*.sql onward and are never squashed again.
--
-- The schema_migrations table is created by the migrator itself, not here.
-- Column ORDER is deliberately preserved from the chain it replaces.

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
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- Site-level monotonic config serial: the single desired-config axis. Every
  -- push stamps it, and every sample/status the agents return echoes the serial
  -- it was produced under, so obsolete-generation data can never roll status back.
  config_serial INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE enrollment_tokens(
  token_hash TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  note TEXT,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP
);

CREATE TABLE app_settings(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TIMESTAMP NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT
);

-- ===== agents =====

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
  reported_config_version INTEGER NOT NULL DEFAULT 0,
  last_seen_at TIMESTAMP,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- Operator-editable label. hostname/platform/version are agent-reported and
  -- stay read-only; display_name lets operators name agents independently.
  display_name TEXT,
  -- Connectivity provenance: when this agent first ever connected (so a
  -- never-connected agent is distinguishable from a currently-offline one), and
  -- how its most recent session ended.
  first_connected_at TIMESTAMP,
  last_disconnect_kind TEXT NOT NULL DEFAULT '',   -- '' | unexpected | clean_shutdown | version_incompatible
  connectivity_alerts_muted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_agents_site ON agents(site_id);

CREATE TABLE agent_status_history(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  status TEXT NOT NULL,          -- online | offline
  changed_at TIMESTAMP NOT NULL,
  reason TEXT NOT NULL DEFAULT ''  -- disconnect kind for offline rows; '' for online
);
CREATE INDEX idx_ash_agent ON agent_status_history(agent_id, changed_at);

CREATE TABLE agent_groups(
  id         TEXT PRIMARY KEY,
  site_id    TEXT NOT NULL REFERENCES sites(id),
  name       TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_agent_groups_site ON agent_groups(site_id);

CREATE TABLE agent_group_members(
  group_id TEXT NOT NULL REFERENCES agent_groups(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  PRIMARY KEY(group_id, agent_id)
);
CREATE INDEX idx_agm_agent ON agent_group_members(agent_id);

CREATE TABLE agent_packets(
  agent_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  received_at TIMESTAMP NOT NULL,
  sent_at TIMESTAMP,
  PRIMARY KEY(agent_id, sequence)
);
CREATE INDEX idx_agent_packets_received ON agent_packets(received_at);

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

-- Authoritative per-round interface set: the agent sends its full interface list
-- every round and the server replaces the rows wholesale.
CREATE TABLE interfaces(
  id           TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL REFERENCES agents(id),
  name         TEXT NOT NULL,
  addrs        TEXT,
  gateway      TEXT,
  dns          TEXT,
  up           INTEGER,
  is_wireless  INTEGER,
  wifi_state   TEXT,    -- NULL on wired rows; connected|disconnected|unreadable on wireless rows
  wifi_reason  TEXT,
  wifi_ssid    TEXT,
  wifi_band    TEXT,
  wifi_channel INTEGER,
  wifi_signal_dbm  INTEGER,  -- current-round numerics, projected from the same round's
  wifi_quality_pct INTEGER,  -- wifi.* metrics (Metric.TS == snapshot.SampledAt); NULL when
  wifi_rx_mbps     REAL,     -- disconnected/unreadable or the driver omitted the field —
  wifi_tx_mbps     REAL,     -- never carried forward from an earlier round
  updated_at   TIMESTAMP,
  UNIQUE(agent_id, name)
);

CREATE TABLE agent_wifi(
  agent_id          TEXT PRIMARY KEY REFERENCES agents(id),
  state             TEXT NOT NULL,           -- ok | unreadable (collection-level)
  reason            TEXT,                    -- permission | driver when unreadable
  sampled_at        TIMESTAMP NOT NULL,      -- freshness only (agent wall-clock)
  last_sequence     INTEGER NOT NULL DEFAULT 0,  -- last applied packet sequence (delivery-order guard)
  default_gateway   TEXT,
  default_interface TEXT
);

-- ===== monitoring configuration =====

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

CREATE TABLE monitor_group_agent_groups(
  monitor_group_id TEXT NOT NULL REFERENCES monitor_groups(id) ON DELETE CASCADE,
  agent_group_id   TEXT NOT NULL REFERENCES agent_groups(id)   ON DELETE CASCADE,
  PRIMARY KEY(monitor_group_id, agent_group_id)
);
CREATE INDEX idx_mgag_agent_group ON monitor_group_agent_groups(agent_group_id);

CREATE TABLE probe_tasks(
  id       TEXT PRIMARY KEY,
  site_id  TEXT NOT NULL REFERENCES sites(id),
  group_id TEXT NOT NULL REFERENCES monitor_groups(id),
  kind     TEXT NOT NULL,
  target   TEXT,
  params   TEXT,
  enabled  INTEGER NOT NULL DEFAULT 1,
  name     TEXT,
  -- This target's material generation: the site serial (and wall time) at
  -- creation or last MATERIAL change (kind / target / params / enabled — never
  -- name / group).
  config_serial INTEGER NOT NULL DEFAULT 0,
  config_changed_at TIMESTAMP,
  -- Pins egress to one proxy. NULL/'' = direct dial; an id the agent cannot
  -- honor makes the monitor un-runnable rather than direct, by design.
  proxy_id TEXT REFERENCES proxies(id)
);
CREATE INDEX idx_probe_tasks_site ON probe_tasks(site_id);
CREATE INDEX idx_probe_tasks_group ON probe_tasks(group_id);
CREATE INDEX idx_probe_tasks_proxy ON probe_tasks(proxy_id);

-- A site-scoped, named, reusable egress path referenced by probe_tasks.proxy_id.
CREATE TABLE proxies(
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  name TEXT NOT NULL,
  type TEXT NOT NULL,                          -- socks5 | http | wireguard
  enabled INTEGER NOT NULL DEFAULT 1,

  -- socks5 / http
  host TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 0,
  username TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',           -- secret: redacted on read
  -- WHERE the target hostname is resolved. 'local' (default) resolves on the
  -- agent so its target-access policy still vets the concrete address and the
  -- approved literal IP is what the proxy is asked to reach; 'remote' hands the
  -- name to the proxy (needed for split-horizon DNS, but the agent can then only
  -- vet the name).
  dns_mode TEXT NOT NULL DEFAULT 'local',      -- local | remote
  -- Budget for reaching the proxy and completing its handshake, kept SEPARATE
  -- from the probe timeout: a proxy that hangs must not consume the whole probe
  -- budget and then be reported as a target timeout. 0 = agent default.
  connect_timeout_ms INTEGER NOT NULL DEFAULT 0,

  -- wireguard (userspace tunnel)
  wg_private_key TEXT NOT NULL DEFAULT '',     -- secret: redacted on read
  wg_peer_public_key TEXT NOT NULL DEFAULT '',
  wg_preshared_key TEXT NOT NULL DEFAULT '',   -- secret: redacted on read
  wg_endpoint TEXT NOT NULL DEFAULT '',        -- remote peer host:port
  wg_allowed_ips TEXT NOT NULL DEFAULT '',     -- CSV of CIDRs routed into the tunnel
  wg_local_addrs TEXT NOT NULL DEFAULT '',     -- CSV of this peer's in-tunnel addresses
  wg_dns TEXT NOT NULL DEFAULT '',             -- CSV of in-tunnel resolvers
  wg_mtu INTEGER NOT NULL DEFAULT 0,           -- 0 = agent default
  wg_keepalive_seconds INTEGER NOT NULL DEFAULT 0,

  -- This proxy's own material generation, bumped only when a field that changes
  -- how the agent dials changes (never on a rename). The agent keys its built
  -- dialer on (id, config_serial), so a bump is what forces the old device/
  -- connection/credentials to be torn down rather than kept alive.
  config_serial INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX idx_proxies_site_name ON proxies(site_id, name);
CREATE INDEX idx_proxies_site ON proxies(site_id);

-- Per-(agent, monitor) assignment status, carrying WHO said so and for WHICH
-- target generation, so a server-side prediction is never mistaken for an
-- agent-confirmed report and a stale report cannot override a current one.
CREATE TABLE monitor_status(
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  monitor_id TEXT NOT NULL REFERENCES probe_tasks(id) ON DELETE CASCADE,
  status TEXT NOT NULL,                       -- active | permission_blocked | target_blocked | unsupported
  missing_permissions TEXT NOT NULL DEFAULT '[]',
  matched_selector TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',            -- agent-reported detail (literal_denied, method_requires_extended, …)
  policy_hash TEXT NOT NULL DEFAULT '',
  config_version INTEGER NOT NULL,            -- whole-frame desired-version watermark
  updated_at TIMESTAMP NOT NULL,
  source TEXT NOT NULL DEFAULT 'reported'
    CHECK(source IN ('reported','predicted')),
  target_config_serial INTEGER NOT NULL DEFAULT 0,
  assigned_at TIMESTAMP,                      -- per-pair assignment clock (pending grace)
  -- Agent-reported effective schedule, so the server's freshness window matches
  -- what the agent actually runs (probe cadence + its upload-link slack).
  effective_interval_seconds INTEGER,
  cycle_deadline_ms INTEGER,
  upload_interval_seconds INTEGER,
  PRIMARY KEY(agent_id, monitor_id)
);

-- Per-target detection sensitivity (how many consecutive rounds confirm a fault
-- and how many clear it). revision is frozen onto each signal it produces.
CREATE TABLE probe_detection_settings(
  target_id      TEXT PRIMARY KEY REFERENCES probe_tasks(id) ON DELETE CASCADE,
  profile        TEXT NOT NULL DEFAULT 'balanced' CHECK(profile IN('balanced','fast','stable','custom')),
  fail_rounds    INTEGER NOT NULL DEFAULT 3 CHECK(fail_rounds BETWEEN 1 AND 20),
  recover_rounds INTEGER NOT NULL DEFAULT 2 CHECK(recover_rounds BETWEEN 1 AND 20),
  icmp_loss_pct  REAL NOT NULL DEFAULT 100 CHECK(icmp_loss_pct > 0 AND icmp_loss_pct <= 100),
  revision       INTEGER NOT NULL DEFAULT 1,
  updated_at     TIMESTAMP NOT NULL
);

-- ===== time series =====
--
-- Narrow, normalized storage sized for months-to-years in SQLite: a series
-- dictionary holds the wide TEXT columns once, samples carry only (series, ts,
-- value), and rollups downsample for long ranges.

CREATE TABLE series(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL, site_id TEXT NOT NULL,
  monitor_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', layer TEXT NOT NULL DEFAULT '',
  unit TEXT NOT NULL DEFAULT '', config_serial INTEGER NOT NULL DEFAULT 0,
  -- Generation-aware identity: a material edit starts a FRESH series, so
  -- old-generation samples can never surface as current.
  UNIQUE(agent_id, monitor_id, kind, target, config_serial)
);
CREATE INDEX idx_series_agent_kind ON series(agent_id, kind, target);
CREATE INDEX idx_series_monitor   ON series(monitor_id);
CREATE INDEX idx_series_site_kind ON series(site_id, kind);

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

-- ===== fault detection & incidents =====

-- Per-(target, agent, detector) streak state driving the built-in availability
-- detectors. Reset when the target's generation or sensitivity revision moves.
CREATE TABLE detector_state(
  target_id        TEXT NOT NULL REFERENCES probe_tasks(id) ON DELETE CASCADE,
  agent_id         TEXT NOT NULL,
  detector_key     TEXT NOT NULL DEFAULT 'availability',
  config_serial    INTEGER NOT NULL DEFAULT 0,
  detection_rev    INTEGER NOT NULL DEFAULT 1,
  fail_rounds      INTEGER NOT NULL DEFAULT 0,
  ok_rounds        INTEGER NOT NULL DEFAULT 0,
  last_round_ts    INTEGER NOT NULL DEFAULT 0,
  first_fail_ts    INTEGER,
  active_signal_id TEXT,
  last_value       REAL,
  updated_at       TIMESTAMP NOT NULL,
  PRIMARY KEY(target_id, agent_id, detector_key)
);
CREATE INDEX idx_detector_state_agent ON detector_state(agent_id);

-- An Agent-level storm: when an upstream link dies every monitor group under one
-- Agent breaches at once, so their incidents merge into a single storm.
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
CREATE UNIQUE INDEX idx_alert_storms_open ON alert_storms(site_id, agent_id) WHERE state='open';
CREATE INDEX idx_alert_storms_site ON alert_storms(site_id, opened_at);

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
  resolved_at     TIMESTAMP,
  storm_id        TEXT REFERENCES alert_storms(id)   -- set when merged into a storm
);
CREATE UNIQUE INDEX idx_incidents_open_key ON incidents(open_key) WHERE state='open';
CREATE INDEX idx_incidents_site_state ON incidents(site_id, state, opened_at);
CREATE INDEX idx_incidents_storm ON incidents(storm_id);

-- One confirmed fault. The sensitivity, the breaching sample and the classified
-- cause are all FROZEN here at confirmation time, so later config edits cannot
-- rewrite the evidence behind a past alert.
CREATE TABLE fault_signals(
  id                TEXT PRIMARY KEY,                   -- 'sig_' + uuid
  site_id           TEXT NOT NULL,
  agent_id          TEXT NOT NULL,
  target_id         TEXT NOT NULL DEFAULT '',
  detector_key      TEXT NOT NULL,                      -- availability | agent_connectivity
  probe_kind        TEXT NOT NULL DEFAULT '',
  group_id          TEXT NOT NULL DEFAULT '',
  group_name        TEXT NOT NULL DEFAULT '',
  target_name       TEXT NOT NULL DEFAULT '',
  target_addr       TEXT NOT NULL DEFAULT '',
  target_port       INTEGER NOT NULL DEFAULT 0,
  agent_name        TEXT NOT NULL DEFAULT '',
  layer             TEXT NOT NULL DEFAULT '',
  severity          TEXT NOT NULL DEFAULT 'warn',
  state             TEXT NOT NULL CHECK(state IN('firing','resolved')),
  resolve_reason    TEXT NOT NULL DEFAULT '',
  fail_threshold    INTEGER NOT NULL DEFAULT 3,         -- frozen sensitivity
  recover_threshold INTEGER NOT NULL DEFAULT 2,
  metric_kind       TEXT NOT NULL DEFAULT '',           -- frozen confirmation evidence
  comparator        TEXT NOT NULL DEFAULT '',           -- how value was tested against threshold
  value             REAL NOT NULL DEFAULT 0,
  threshold         REAL NOT NULL DEFAULT 0,
  reason_code       INTEGER NOT NULL DEFAULT 0,         -- classified cause (telemetry.ProbeReason*)
  reason_detail     TEXT NOT NULL DEFAULT '',           -- which cert/status/OS error was behind it
  observed_at       TIMESTAMP NOT NULL,                 -- first round of the failing streak
  confirmed_at      TIMESTAMP NOT NULL,                 -- round that reached the threshold
  resolved_at       TIMESTAMP,
  incident_id       TEXT NOT NULL REFERENCES incidents(id)
);
CREATE UNIQUE INDEX idx_fault_signals_open
  ON fault_signals(agent_id, target_id, detector_key) WHERE state='firing';
CREATE INDEX idx_fault_signals_incident ON fault_signals(incident_id);
CREATE INDEX idx_fault_signals_site_state ON fault_signals(site_id, state, confirmed_at);
CREATE INDEX idx_fault_signals_target ON fault_signals(target_id, confirmed_at);
CREATE INDEX idx_fault_signals_agent ON fault_signals(agent_id, confirmed_at);

CREATE TABLE incident_timeline(
  id          TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  ts          TIMESTAMP NOT NULL,
  kind        TEXT NOT NULL,
  message     TEXT,
  ref         TEXT
);
CREATE INDEX idx_timeline_incident ON incident_timeline(incident_id, ts);

-- Operator-visible "this monitor cannot run" issues, deduped per
-- (agent, category, ref, reason) rather than re-raised every round.
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
  resolved_at TIMESTAMP,
  detail_reason TEXT NOT NULL DEFAULT ''       -- the agent's DETAILED block reason, beyond the coarse status
);
CREATE INDEX idx_opissues_active ON operational_issues(site_id, state, read);

-- ===== incident diagnostics (scene snapshots + traceroute) =====

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
  deadline_at  TIMESTAMP NOT NULL,
  -- A TCP plan whose agent lacks the TCP-traceroute permission runs as ICMP
  -- instead; these record the mode it was originally requested as and why it
  -- was downgraded, so a fallback reads as a fallback rather than a failure.
  fallback_from   TEXT NOT NULL DEFAULT '',   -- '' | tcp
  fallback_reason TEXT NOT NULL DEFAULT ''    -- raw_socket_unavailable | permission_denied
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
  report_id   TEXT NOT NULL REFERENCES trace_reports(id),
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  signal_id   TEXT NOT NULL,
  active      INTEGER NOT NULL DEFAULT 1,
  created_at  TIMESTAMP NOT NULL,
  PRIMARY KEY(report_id, incident_id, signal_id)
);
CREATE INDEX idx_trr_incident ON trace_report_refs(incident_id);
CREATE INDEX idx_trr_signal ON trace_report_refs(signal_id, active);

-- ===== notifications =====

CREATE TABLE notification_channels(
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  config TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  name TEXT,
  storm_merge INTEGER NOT NULL DEFAULT 1   -- deliver one storm message instead of per-incident ones
);

-- WHO hears about a fault, separate from whether it is RECORDED. Scoped to the
-- site or one monitor group; exactly one row per scope, one default per site.
CREATE TABLE notification_policies(
  id                 TEXT PRIMARY KEY,                  -- 'np_' + uuid
  site_id            TEXT NOT NULL REFERENCES sites(id),
  name               TEXT NOT NULL,
  scope_kind         TEXT NOT NULL CHECK(scope_kind IN('site','group')),
  scope_id           TEXT NOT NULL DEFAULT '',          -- '' for the site scope
  enabled            INTEGER NOT NULL DEFAULT 1,
  min_severity       TEXT NOT NULL DEFAULT 'warn',
  warn_delay_sec     INTEGER NOT NULL DEFAULT 300,
  critical_delay_sec INTEGER NOT NULL DEFAULT 60,
  notify_recovery    INTEGER NOT NULL DEFAULT 1,
  channel_ids        TEXT NOT NULL DEFAULT '[]',
  is_default         INTEGER NOT NULL DEFAULT 0,
  created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_np_scope ON notification_policies(site_id, scope_kind, scope_id);
CREATE UNIQUE INDEX idx_np_default ON notification_policies(site_id) WHERE is_default=1;

-- One planned delivery. The paired UNIQUEs are what make an INSERT OR IGNORE
-- idempotent, so a replayed event, a reconnect or a restart delivers at most
-- once; each UNIQUE only ever constrains its own kind of row.
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

-- ===== maintenance =====

-- Durable history-data cleanup jobs: the API queues one, a worker tick claims it
-- and deletes the selected time-series history asynchronously.
CREATE TABLE cleanup_jobs(
  id            TEXT PRIMARY KEY,                    -- 'cj_' + uuid
  site_id       TEXT NOT NULL,
  client_token  TEXT NOT NULL DEFAULT '',            -- idempotency key (dedupes double-submit)
  mode          TEXT NOT NULL,                       -- 'selection' | 'orphans'
  from_ts       INTEGER NOT NULL DEFAULT 0,          -- inclusive lower bound (unix s); 0/0 = full delete
  to_ts         INTEGER NOT NULL DEFAULT 0,          -- exclusive upper bound (unix s)
  allow_live    INTEGER NOT NULL DEFAULT 0,          -- 1 = permitted to delete a range of a live target
  state         TEXT NOT NULL DEFAULT 'queued'       -- queued|running|done|failed|interrupted
                CHECK(state IN('queued','running','done','failed','interrupted')),
  total_items   INTEGER NOT NULL DEFAULT 0,
  done_items    INTEGER NOT NULL DEFAULT 0,
  failed_items  INTEGER NOT NULL DEFAULT 0,
  del_samples   INTEGER NOT NULL DEFAULT 0,          -- aggregate rows deleted, for the result summary
  del_rollups   INTEGER NOT NULL DEFAULT 0,
  del_series    INTEGER NOT NULL DEFAULT 0,
  error         TEXT NOT NULL DEFAULT '',            -- job-level failure (DB error aborting the loop)
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at    TIMESTAMP,
  finished_at   TIMESTAMP
);
CREATE UNIQUE INDEX idx_cleanup_jobs_token ON cleanup_jobs(client_token) WHERE client_token != '';
CREATE INDEX idx_cleanup_jobs_state ON cleanup_jobs(state);
CREATE INDEX idx_cleanup_jobs_site ON cleanup_jobs(site_id, created_at);

CREATE TABLE cleanup_job_items(
  job_id     TEXT NOT NULL REFERENCES cleanup_jobs(id) ON DELETE CASCADE,
  idx        INTEGER NOT NULL,                       -- stable order within the job
  agent_id   TEXT NOT NULL,
  monitor_id TEXT NOT NULL DEFAULT '',               -- '' = system series
  kind       TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  label      TEXT NOT NULL,                          -- frozen human-readable label for the UI
  state      TEXT NOT NULL DEFAULT 'pending'         -- pending|done|failed
             CHECK(state IN('pending','done','failed')),
  detail     TEXT NOT NULL DEFAULT '',               -- error text (failed) or deleted-count note (done)
  PRIMARY KEY(job_id, idx)
);
