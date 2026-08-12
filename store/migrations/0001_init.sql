-- NetTact release baseline schema.
--
-- The single squashed baseline for the entire pre-release schema history: the
-- original 0001–0026 development chain (tables created then dropped, columns
-- renamed, one-off data repairs) collapsed once into 0001, and then the
-- post-baseline 0002–0005 folded in here too. Pre-release with zero users, so
-- none of that history has anyone to migrate.
--
-- Squashing is safe for a development database that already ran 0002–0005:
-- version 1 is recorded there, so this file is skipped, and the schema it
-- already holds is exactly what this file creates. A database still at version 1
-- that never ran 0002–0005 is NOT caught up by this file and must be recreated.
--
-- The schema_migrations table is created by the migrator itself, not here.
-- Column ORDER is deliberately preserved from the chain it replaces, including
-- the columns that arrived there as ALTER TABLE ADD COLUMN.

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
  -- Site-level monotonic config serial: the probe desired-config axis. Every
  -- push stamps it, and every sample/status the agents return echoes the serial
  -- it was produced under, so obsolete-generation data can never roll status back.
  config_serial INTEGER NOT NULL DEFAULT 0,
  -- The game-capture config's OWN serial, deliberately a second axis rather than
  -- a share of config_serial. The two describe unrelated things: renaming a game
  -- profile has nothing to say to a ping monitor, and bumping the probe serial
  -- for it would make every agent re-evaluate every target and restart the ones
  -- whose generation it cannot prove unchanged. Kept apart, a profile edit
  -- re-pushes DesiredState with an unchanged ConfigVersion (the probe side
  -- no-ops) and a probe edit leaves this one alone (the sensor is not restarted
  -- for a change it cannot see).
  game_config_serial INTEGER NOT NULL DEFAULT 0,
  -- What happens to a presenting process matching no game profile: recorded as
  -- an "other process" run, or ignored. Default 1 = record everything, which is
  -- what makes the feature work out of the box before anyone defines a profile.
  -- A site setting rather than a per-profile one because it is a privacy choice
  -- about the machine, not a measurement choice about a game.
  game_record_unmatched INTEGER NOT NULL DEFAULT 1
);

-- Enrollment tokens: one-time + TTL, only the hash stored. A token may be a
-- plain site enrollment token (agent_id NULL) or a reinstall token bound to an
-- existing agent (AGENT-006): redeeming the latter rejoins the SAME agents row
-- instead of minting a new identity, so history is inherited. agent_id cascades
-- on agent deletion — a reinstall token for a deleted agent is meaningless and
-- must not strand an FK (SQLite defaults to NO ACTION). revoked lets an operator
-- void an unused token without deleting the row.
CREATE TABLE enrollment_tokens(
  token_hash TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  note TEXT,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  agent_id TEXT REFERENCES agents(id) ON DELETE CASCADE,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_enrollment_tokens_agent ON enrollment_tokens(agent_id);

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
  -- The agent's own batch-upload cadence, as attested frame-level in the same
  -- MonitorStatus. It lives here rather than only on the per-monitor rows
  -- because it describes the whole outbox, and because an agent with a host
  -- anchor and no enabled probe monitors sends a frame with no entries at all —
  -- so the per-monitor rows would carry no cadence, and the host detectors would
  -- judge their readings' lateness against the protocol default. 0 = not yet
  -- reported.
  upload_interval_seconds INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'online',
  -- Highest packet sequence ever COMMITTED from this agent's current
  -- installation — the ingest dedup watermark (replaces the old agent_packets
  -- row-per-packet table). The agent's WAL is FIFO per server with a single
  -- in-flight packet resent under its original sequence until acked, and the
  -- ack is cumulative, so "seen before" is exactly sequence <= this. Reset to 0
  -- by reenrollment (AGENT-006): the reinstalled machine's fresh WAL restarts
  -- at sequence 1.
  high_sequence INTEGER NOT NULL DEFAULT 0,
  last_seen_at TIMESTAMP,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- Operator-editable label. hostname/platform/version are agent-reported and
  -- stay read-only; display_name lets operators name agents independently. It is
  -- seeded at enrollment from the enrollment token's note (the operator already
  -- described the machine when minting the token), and NULL when that note was
  -- empty — the console then falls back to the reported hostname.
  display_name TEXT,
  -- Connectivity provenance: when this agent first ever connected (so a
  -- never-connected agent is distinguishable from a currently-offline one), and
  -- how its most recent session ended.
  first_connected_at TIMESTAMP,
  last_disconnect_kind TEXT NOT NULL DEFAULT '',   -- '' | unexpected | clean_shutdown | version_incompatible
  connectivity_alerts_muted INTEGER NOT NULL DEFAULT 0,
  -- WHY a permission is not supported, alongside the three sets above that say
  -- only that it isn't: a JSON OBJECT keyed by permission ID, values stable
  -- reason codes owned by whichever capability probe answered
  -- ({"game.gpu.read":"version_mismatch"}). Reported whole on every Hello like
  -- perm_supported/granted/effective, so each report replaces this column
  -- outright; it carries no history. It only ever holds ids ABSENT from
  -- perm_supported — a supported permission has nothing to explain — and the
  -- registry drops any contradicting key when writing, so no reader has to
  -- reconcile a row that claims both.
  --
  -- An absent key is NOT "no problem": it means the probe never ran, typically
  -- because nothing granted the capability and an agent refuses to probe what it
  -- was not granted. '{}' therefore reads as "nothing was probed", never as
  -- "everything is fine", and a reader must render a missing entry as unprobed
  -- rather than as an unexplained failure. The value vocabulary belongs to the
  -- probes (protocol/gamesense for game capture) and is never validated here, so
  -- readers must tolerate codes they do not know.
  perm_unsupported_reasons TEXT NOT NULL DEFAULT '{}'
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
  default_interface TEXT,
  iface_hash        INTEGER NOT NULL DEFAULT 0   -- content hash of the applied interfaces rows; an
                                                 -- identical next snapshot skips their delete+reinsert
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
--
-- The smart_* columns tune the ALERT-003 degradation detectors, which judge a
-- round against the target's OWN history rather than against a fixed threshold.
-- They share `revision` with the availability columns on purpose: one revision
-- invalidates every detector's streak consistently, and an operator editing
-- sensitivity means "start over", not "start over for one of the two".
CREATE TABLE probe_detection_settings(
  target_id         TEXT PRIMARY KEY REFERENCES probe_tasks(id) ON DELETE CASCADE,
  profile           TEXT NOT NULL DEFAULT 'balanced' CHECK(profile IN('balanced','fast','stable','custom')),
  fail_rounds       INTEGER NOT NULL DEFAULT 3 CHECK(fail_rounds BETWEEN 1 AND 20),
  recover_rounds    INTEGER NOT NULL DEFAULT 2 CHECK(recover_rounds BETWEEN 1 AND 20),
  icmp_loss_pct     REAL NOT NULL DEFAULT 100 CHECK(icmp_loss_pct > 0 AND icmp_loss_pct <= 100),
  smart_enabled     INTEGER NOT NULL DEFAULT 1,
  smart_sensitivity TEXT NOT NULL DEFAULT 'standard' CHECK(smart_sensitivity IN('loose','standard','sensitive')),
  revision          INTEGER NOT NULL DEFAULT 1,
  updated_at        TIMESTAMP NOT NULL
);

-- Per-anchor system-status detection: the thresholds behind the built-in host
-- detectors (CPU / memory / load / network / disk). One row per kind='host'
-- probe_tasks anchor; a MISSING row means the defaults below, so a freshly
-- created anchor already watches the machine without anyone opening a form.
--
-- Purely server-side, like the anchor itself: nothing here is ever pushed to an
-- agent (the agent reports host metrics under its own permissions and knows
-- nothing about thresholds), so an edit neither bumps the site's config serial
-- nor re-pushes DesiredState.
--
-- Durations are stored in SECONDS, not in rounds. The round count a streak needs
-- is derived at evaluation time from the collection cadence, so "5 minutes"
-- keeps meaning five minutes if the cadence ever changes; storing rounds would
-- silently redefine every existing alert.
--
-- Network is the one family off by default and the one with nullable
-- thresholds: "90% CPU" is a defensible universal, "300 Mbps" is not — it
-- depends on a link speed the server cannot know. A NULL direction is not
-- alerted at all, which is how one-directional (upload-only) alerting is
-- expressed. Disk has no duration: a filling disk is not a spike, and waiting
-- five minutes to say so buys nothing.
--
-- revision advances on every edit; detector streaks are pinned to it, so an
-- edited threshold restarts confirmation instead of inheriting a streak counted
-- against the old one.
CREATE TABLE host_detection_settings(
  target_id       TEXT PRIMARY KEY REFERENCES probe_tasks(id) ON DELETE CASCADE,
  cpu_enabled     INTEGER NOT NULL DEFAULT 1,
  cpu_pct         REAL    NOT NULL DEFAULT 90  CHECK(cpu_pct > 0 AND cpu_pct <= 100),
  cpu_duration_s  INTEGER NOT NULL DEFAULT 300 CHECK(cpu_duration_s BETWEEN 30 AND 3600),
  mem_enabled     INTEGER NOT NULL DEFAULT 1,
  mem_pct         REAL    NOT NULL DEFAULT 90  CHECK(mem_pct > 0 AND mem_pct <= 100),
  mem_duration_s  INTEGER NOT NULL DEFAULT 300 CHECK(mem_duration_s BETWEEN 30 AND 3600),
  load_enabled    INTEGER NOT NULL DEFAULT 1,
  load_per_core   REAL    NOT NULL DEFAULT 2.0 CHECK(load_per_core > 0 AND load_per_core <= 100),
  load_duration_s INTEGER NOT NULL DEFAULT 300 CHECK(load_duration_s BETWEEN 30 AND 3600),
  net_enabled     INTEGER NOT NULL DEFAULT 0,
  net_rx_mbps     REAL             CHECK(net_rx_mbps IS NULL OR net_rx_mbps > 0),
  net_tx_mbps     REAL             CHECK(net_tx_mbps IS NULL OR net_tx_mbps > 0),
  net_duration_s  INTEGER NOT NULL DEFAULT 300 CHECK(net_duration_s BETWEEN 30 AND 3600),
  disk_enabled    INTEGER NOT NULL DEFAULT 1,
  disk_pct        REAL    NOT NULL DEFAULT 90  CHECK(disk_pct > 0 AND disk_pct <= 100),
  revision        INTEGER NOT NULL DEFAULT 1,
  updated_at      TIMESTAMP NOT NULL
);

-- ===== time series =====
--
-- The series DICTIONARY: the wide TEXT identity of every time series, stored
-- once. The sample data itself lives OUTSIDE SQLite, in the tsstore data plane
-- (embedded Prometheus TSDB instances keyed by series.id) — the old
-- (series_id, ts) tables rewrote every active series' B-tree tail page on
-- every packet commit, ~100-400x write amplification. See package tsstore.

CREATE TABLE series(
  -- AUTOINCREMENT is load-bearing, not style: ids are NEVER reused, and the
  -- data plane's whole-series delete (tombstones over the id's full history)
  -- is only safe because a deleted id can never write again.
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL, site_id TEXT NOT NULL,
  monitor_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', layer TEXT NOT NULL DEFAULT '',
  unit TEXT NOT NULL DEFAULT '', config_serial INTEGER NOT NULL DEFAULT 0,
  -- A full-history clear of a LIVE series (cleanup's "delete data, keep the
  -- monitor"): reads clamp below this unix-seconds cutoff, the old blocks age
  -- out through ordinary retention. A data-plane tombstone cannot express this
  -- — an interval reaching into the future would also mask the samples the
  -- still-live series keeps appending.
  purge_cutoff INTEGER NOT NULL DEFAULT 0,
  -- Generation-aware identity: a material edit starts a FRESH series, so
  -- old-generation samples can never surface as current.
  UNIQUE(agent_id, monitor_id, kind, target, config_serial)
);
CREATE INDEX idx_series_agent_kind ON series(agent_id, kind, target);
CREATE INDEX idx_series_monitor   ON series(monitor_id);
CREATE INDEX idx_series_site_kind ON series(site_id, kind);

-- Per-(tier, series) downsampling watermarks. The BUCKETS these fence live in
-- the data plane; the watermarks stay relational because the rollup job's
-- correctness hangs on their transactional edges (ingest's backfill rewind,
-- the parent-tier cascade, the CAS advance — see metrics/rollup.go).
CREATE TABLE rollup_state(
  resolution TEXT NOT NULL,    -- '1m' | '1h' | '1d'
  series_id  INTEGER NOT NULL,
  last_ts    INTEGER NOT NULL, -- exclusive upper bound of the last materialized bucket
  PRIMARY KEY(resolution, series_id)
) WITHOUT ROWID;

-- ===== historical baselines (ALERT-003) =====
--
-- What "normal" looks like for one target on one Agent, per time-of-day bucket.
-- The degradation detectors compare a live round against this instead of against
-- a fixed threshold, because a 20ms LAN target reaching 100ms is an incident
-- while a 300ms transcontinental target reaching 350ms is a Tuesday.
--
-- Percentiles cannot come from the rollup tiers: those store (cnt, total, vmin,
-- vmax), and a percentile of bucket averages is not a percentile of
-- observations. They cannot come from a long raw scan either — raw retention is
-- two days. So an hourly job folds the raw tier into one row per calendar day
-- per daypart, and the 14-day band is an aggregate over at most 14 of these
-- rows. Quantiles are not incrementally updatable, so a fold recomputes each
-- touched day-bucket whole from raw; the hourly cadence keeps that well inside
-- raw retention.
--
-- Dayparts are SERVER-LOCAL. There is no timezone concept anywhere in the
-- product, and the two deployment shapes (a desktop app, a self-hosted box in
-- the household it monitors) both sit in the user's own timezone — where "晚高峰
-- vs 凌晨" is the whole point of splitting the day at all. A server that changes
-- timezone shifts the boundaries once and the rolling window reconverges.
--
-- config_serial is part of the row rather than a filter afterthought: a material
-- target edit starts a fresh series generation, reads demand the current serial,
-- and the previous generation's rows simply age out. That IS the baseline
-- invalidation mechanism — no separate clear-on-edit path exists or is needed.
CREATE TABLE baseline_daily(
  target_id     TEXT NOT NULL REFERENCES probe_tasks(id) ON DELETE CASCADE,
  agent_id      TEXT NOT NULL,
  metric_kind   TEXT NOT NULL,
  day           INTEGER NOT NULL,  -- server-local calendar day as yyyymmdd
  daypart       INTEGER NOT NULL,  -- 0: 00-06, 1: 06-12, 2: 12-18, 3: 18-24 local
  weekend       INTEGER NOT NULL,  -- 0/1, derived from `day` (Sat/Sun)
  config_serial INTEGER NOT NULL,
  cnt           INTEGER NOT NULL,  -- raw samples behind this row's quantiles
  p50           REAL NOT NULL,
  p95           REAL NOT NULL,
  updated_at    TIMESTAMP NOT NULL,
  PRIMARY KEY(target_id, agent_id, metric_kind, day, daypart)
) WITHOUT ROWID;
CREATE INDEX idx_baseline_daily_day ON baseline_daily(day);

-- Fold watermark, one row per series (the same shape and job as rollup_state):
-- the newest raw sample timestamp already folded. Samples arriving BEHIND it —
-- a WAL replay after the fold passed — are not re-folded. That is deliberate:
-- late data is overwhelmingly outage-period data, which robust statistics want
-- to discount anyway, and rewinding for it would buy nothing a median across
-- days does not already provide.
CREATE TABLE baseline_state(
  series_id INTEGER PRIMARY KEY,
  last_ts   INTEGER NOT NULL
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

-- ===== game presentation =====
--
-- Frame data deliberately does NOT live in series/samples. A second of rendering
-- is a distribution, not a scalar: the figure a player recognizes — the slowest
-- 1% of frames across a whole session — is a property of every frame, and no
-- average of per-second averages reconstructs it. Histograms can simply be added,
-- so the distribution is what gets stored and whole-run figures are derived from
-- the sum. Runs give those frames the boundary they belong to, because the unit
-- being compared is "this evening's session", not "the last hour of wall clock".
--
-- NULL here means NOT MEASURED, and never zero. Frame sources differ in how far
-- they can see: one follows every frame to the screen, another only knows a frame
-- was handed over. "This game dropped no frames" and "we cannot see dropped
-- frames" are different facts, and storing 0 for both would make the second one
-- unrecoverable — every chart would then render a source's blind spot as a
-- flawless result. Readers must restore the absent value as absent.

-- A named game: the process names that count as it, and how closely it is
-- measured. Profiles are configuration, not history — they are pushed to agents
-- as part of DesiredState (bumping sites.game_config_serial) and are what turns
-- "chrome.exe presented frames" into "this is Counter-Strike".
CREATE TABLE game_profiles(
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  name TEXT NOT NULL,
  exe_match TEXT NOT NULL DEFAULT '[]',   -- JSON array of case-insensitive process names ("cs2.exe")
  target_fps INTEGER,                     -- NULL = unset
  tier TEXT NOT NULL DEFAULT 'diag',      -- base | diag
  -- probe_tasks ids this game is charted against on its run detail. Console-only
  -- and deliberately never pushed to agents: the link changes how a run is drawn,
  -- and an agent carrying the list on every push would never read it.
  monitor_ids TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_game_profiles_site ON game_profiles(site_id);

CREATE TABLE game_runs(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  site_id TEXT NOT NULL,
  proc TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  -- The game profile this session matched; NULL means it matched none and was
  -- recorded as an "other process" run. Plain TEXT with NO foreign key on
  -- purpose: the stamp records what the profile set said WHEN the run happened,
  -- so deleting a profile must not delete history or blank the runs it explains.
  -- Readers join it optionally and show a name only while the profile still exists.
  profile_id TEXT,
  started_at INTEGER NOT NULL,     -- unix seconds, first second captured
  last_seen_at INTEGER NOT NULL,   -- unix seconds, newest second captured
  -- Set only once the run is KNOWN to be over, so a session cut short by an agent
  -- restart stays distinguishable from one whose ending was actually observed.
  ended_at INTEGER,
  source TEXT NOT NULL DEFAULT '',
  -- The sensor's capability list verbatim (JSON array of names), NOT a bitmap: a
  -- capability introduced later must not need a bit assigned to it, and a reader
  -- meeting an unfamiliar name has to be able to ignore that one name rather than
  -- misread every bit after it. Together with source it records how the run was
  -- measured, without which a game that stopped dropping frames is
  -- indistinguishable from a capture that stopped being able to see drops.
  caps TEXT NOT NULL DEFAULT '[]',
  -- The whole-run totals, folded in as each second lands rather than derived from
  -- game_buckets on read. Buckets are kept for days and runs for months, so a
  -- summary recomputed from surviving buckets reports every run older than the
  -- bucket window as zero frames at null FPS — destroying exactly the
  -- cross-session comparison the long run window exists to preserve. It is also
  -- what keeps listing a page of runs off a scan of every second beneath them.
  presented INTEGER NOT NULL DEFAULT 0,
  -- NULL until a second arrives that could actually count them, and NULL forever
  -- for a source that never can: a zero here would report a blind spot as a run
  -- that dropped nothing, which is the one mistake this schema exists to prevent.
  displayed INTEGER,
  dropped INTEGER,
  -- The run's merged frame-time histogram, encoded exactly like game_buckets.hist
  -- and carrying the layout its counts were binned under for the same reason —
  -- see game_buckets.hist_layout. NULL until the first second is folded in, which
  -- is also the only thing that tells a run which recorded no seconds apart from
  -- one whose seconds presented nothing: presented is a count, and a count of
  -- zero cannot say which happened.
  hist_layout TEXT,
  hist BLOB,
  -- The run's long-frame totals, folded from the seconds that carried a stutter
  -- block exactly as displayed/dropped are folded: NULL until the first such
  -- second lands, and NULL forever for a capture that never watched for long
  -- frames. The zero matters more here than anywhere else in this table — "this
  -- session never hitched" is the headline the feature exists to produce — so it
  -- may only ever be written by a second that actually looked.
  stutter_count INTEGER,
  stutter_excess_ms REAL
);
CREATE INDEX idx_game_runs_agent ON game_runs(agent_id, started_at DESC);
-- The index the abandoned-run reaper sweeps (gamedata.CloseAbandonedRuns).
--
-- Partial on ended_at IS NULL, and that is the whole point of it. The reaper asks
-- once a minute which runs have not ended, and on a machine that is not playing
-- anything right now the answer is none — so the index it walks is EMPTY, while a
-- full index on last_seen_at would grow with the ninety-day run history the sweep
-- has no interest in and cost a scan proportional to it every minute. last_seen_at
-- is the key so the staleness bound narrows the walk rather than filtering after
-- it, and entries leave the index the moment a run is ended, which is what keeps
-- it the size of "sessions in progress" (normally zero or one) forever.
CREATE INDEX idx_game_runs_open ON game_runs(last_seen_at) WHERE ended_at IS NULL;

CREATE TABLE game_buckets(
  run_id TEXT NOT NULL REFERENCES game_runs(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,             -- unix seconds, the second this sample closed
  presented INTEGER NOT NULL,      -- the one count every source knows
  displayed INTEGER,               -- NULL unless frames are tracked to the screen
  dropped INTEGER,
  app_frames INTEGER,              -- NULL unless generated frames are told apart
  generated_frames INTEGER,
  ft_avg REAL NOT NULL,
  ft_p50 REAL NOT NULL,
  ft_p95 REAL NOT NULL,
  ft_p99 REAL NOT NULL,
  ft_max REAL NOT NULL,
  ft_sd  REAL NOT NULL,
  -- The frozen bin layout the counts were produced under, stored per bucket
  -- because the NAME is the compatibility contract: a reader that does not know
  -- the layout must refuse the counts rather than apply its own edges, which
  -- would silently turn a bin index into the wrong frame time. hist is the bins
  -- as uint32 little-endian (24 bins = 96 bytes for log24_v1).
  hist_layout TEXT NOT NULL,
  hist BLOB NOT NULL,
  disp_ft_avg REAL,                -- NULL without the displayed capability
  disp_ft_p95 REAL,
  present_mode TEXT,
  sync_interval INTEGER,           -- 0 means vsync off, a real reading; NULL means unobserved
  tearing INTEGER,                 -- 0 means "no tearing", likewise a real reading
  api TEXT,
  -- NULL when no presentation metadata was observed at all. It is what keeps "the
  -- second was uniform" apart from "we never looked": every other column in this
  -- group is legitimately empty on its own, so without a discriminator the two
  -- collapse into one.
  present_changed INTEGER,
  -- The second's long-frame events. The pair is written and left NULL together,
  -- so stutter_count non-NULL is the discriminator for the whole block: a second
  -- that was watched and held no hitch stores 0 / 0.0, which is a real
  -- measurement and the one every smooth second of a run is made of. NULL is
  -- "nothing was watching for long frames", which no count can express.
  stutter_count INTEGER,
  stutter_excess_ms REAL,
  -- The tracked game process's own resource usage, sampled at the second
  -- boundary rather than derived from the frame stream. Unlike the stutter pair
  -- these three are independent: CPU is a delta with no value on the first
  -- observed second of a run, while memory is a level readable at once, so each
  -- column is NULL exactly when its own reading was absent. Read-back rebuilds
  -- the block when ANY of them is non-NULL — a block in which every reading was
  -- missing carried nothing and is not worth telling apart from no block.
  proc_cpu_pct REAL,               -- % of total CPU capacity (all cores), 0-100
  proc_ws_bytes INTEGER,           -- working set
  proc_priv_bytes INTEGER,         -- private (committed) bytes
  -- The diag columns: the deeper per-second breakdowns a diag-tier profile buys.
  -- None of them is folded onto game_runs, and that is deliberate. They exist to
  -- answer "what was this second bound by", which is a question about a moment;
  -- a whole-run average of a bottleneck verdict names no bottleneck, and the
  -- seconds are still there for the window anyone asks it of.
  --
  -- The frame-derived groups (cpu_*, gpu_* splits, lat_*) are group-atomic: the
  -- sensor registers whole metric groups when a session opens and either gets
  -- them all or none, so each group's columns are written and left NULL
  -- together and the group's FIRST column serves as its discriminator. Nothing
  -- inside a group needs a presence flag of its own because a half-filled group
  -- is not a state that can occur.
  cpu_busy_avg REAL,               -- ms of CPU work the game itself did per frame
  cpu_busy_p95 REAL,
  cpu_wait_avg REAL,               -- ms per frame spent waiting on something else
  cpu_wait_p95 REAL,
  -- The frame's GPU side, scoped to the tracked process: this is the game's own
  -- work from the frame events, NOT the card's total load. The other half of
  -- that comparison lives in game_host_seconds below, which is keyed by the
  -- machine rather than by a run because the card is shared.
  gpu_latency_avg REAL,            -- frame start -> GPU work start
  gpu_time_avg REAL,               -- GPU total duration per frame
  gpu_time_p95 REAL,
  gpu_busy_avg REAL,               -- GPU active time per frame
  gpu_busy_p95 REAL,
  gpu_wait_avg REAL,
  gpu_in_present_avg REAL,         -- blocked inside the Present call
  gpu_render_latency_avg REAL,     -- Present -> GPU completion
  -- How long the second's frames took to reach the screen, and how far the
  -- game's pacing drifted from what was shown. lat_display_avg is an estimate
  -- whose error bar depends on present_mode above, so the two are read together.
  lat_display_avg REAL,
  lat_anim_err_avg REAL,           -- |animation error|; the source is signed, the absolute value is stored
  lat_anim_err_p95 REAL,
  -- The game process's own dedicated video memory, which is what the whole-card
  -- figure in game_host_seconds cannot say: a full card says nothing about who
  -- filled it. This one IS per-process and so belongs here rather than there.
  -- used is the discriminator for the block; budget is independently NULL
  -- because the OS does not always expose a per-process budget, and the level is
  -- still the measurement without it.
  --
  -- It is also the block gated by game.gpu.read on this table: it reads the
  -- adapter, not just the game's frames, so ingest NULLs it for an agent that
  -- holds only game.performance.read.
  proc_vram_used INTEGER,
  proc_vram_budget INTEGER,
  quality TEXT,                    -- JSON array of flags; NULL when none apply
  PRIMARY KEY(run_id, ts)
) WITHOUT ROWID;
-- Retention deletes by age across every run at once, and this is by far the
-- fastest-growing table in the store (one row per second of play), so the age
-- sweep gets its own index rather than scanning the whole table hourly.
CREATE INDEX idx_game_buckets_ts ON game_buckets(ts);

-- Machine-level per-second telemetry, keyed by the agent and the second rather
-- than by a run.
--
-- The adapter's load and the processor's describe every process on the machine.
-- Stored per-run-per-second they would exist only for the seconds a diag-tier
-- game happened to win, so a machine-level question — "was something else taking
-- the card" — could only be asked of the seconds one particular game was drawing
-- in. Worse, the seconds with no frames at all (a minimized game, a loading
-- screen) produce no bucket, so the stretch a reader most wants explained would
-- be the stretch with no data.
--
-- Here they are collected for every second the sensor is watching anything,
-- frames or not, and a run reads whichever of them its window covers. Two runs
-- overlapping a second share one row instead of each holding a private copy of
-- one machine's load, and deleting a run does not take the machine's history
-- with it.
--
-- NULL means NOT MEASURED here as everywhere else in this schema.
CREATE TABLE game_host_seconds(
  agent_id TEXT NOT NULL REFERENCES agents(id),
  -- Denormalized from agents exactly as game_runs.site_id is, so the read and
  -- retention queries are self-contained and a site-ownership check costs no join.
  site_id TEXT NOT NULL,
  ts INTEGER NOT NULL,             -- unix seconds, the second this reading closed
  -- The busy share of every logical core, and of the busiest one. Written and
  -- left NULL together: one counter read is differenced into both, so a machine
  -- that answered has both figures and one that did not has neither, and
  -- cpu_total_pct is the pair's discriminator.
  --
  -- Both are stored because either alone misleads. A single-threaded game pins
  -- one core at 100% while a sixteen-thread machine reports 6% busy: the total
  -- alone says the machine is idle while the game is starved, and the busiest
  -- alone says it is saturated while fifteen cores sit free. The GAP between
  -- them is the finding, and a gap is only visible when both are recorded.
  --
  -- Two zeros is a genuinely idle machine and a real measurement. Only NULL
  -- means the counters could not be read.
  cpu_total_pct REAL,
  cpu_busiest_pct REAL,
  -- The processor's clock, MHz, and its nominal maximum. Written and left NULL
  -- together: one power-management call returns both.
  --
  -- cpu_mhz is the HIGHEST clock any logical core is at, not a mean. Processors
  -- boost a few cores well past the all-core clock and the game's own thread is
  -- often one of them, so an average reports a processor coasting at its base
  -- clock while the thread that matters is at its ceiling — the same argument
  -- cpu_busiest_pct makes about utilization, and read alongside it.
  --
  -- The maximum is stored per second rather than once per machine for the reason
  -- mem_total is: 3.2 GHz is a processor coasting on one machine and one pinned
  -- at its ceiling on another, and nothing else in the row says which.
  --
  -- Separate from the pair above because they come from different calls that
  -- fail independently: one differences performance counters, the other reads
  -- power management. Needs no graphics permission — the processor is not the
  -- graphics device.
  cpu_mhz REAL,
  cpu_max_mhz REAL,
  -- Physical memory in use, and installed. The capacity is stored per second
  -- rather than once per machine because it is what makes the level readable: 12
  -- GB in use is comfortable on a 32 GB box and terminal on a 16 GB one, and a
  -- reader looking at a stored second months later has nothing else to tell them
  -- apart. Written and left NULL together; one call returns both, and mem_used
  -- is the pair's discriminator.
  mem_used INTEGER,
  mem_total INTEGER,
  -- Whole-adapter telemetry. These three are EACH independent, unlike the pairs
  -- above: which figures a driver publishes varies by vendor and by metric, so a
  -- card reporting utilization and no memory is an ordinary card rather than a
  -- failed read. Read-back rebuilds the block when ANY of them is non-NULL.
  --
  -- This is the only block here gated by game.gpu.read — it describes the card
  -- every process on the machine shares. The CPU and memory readings above need
  -- no graphics permission at all and are never stripped: the busiest core is a
  -- fact about the processor, and so is the rest of it.
  gpu_util_pct REAL,               -- whole-GPU utilization 0-100
  gpu_mem_used INTEGER,            -- whole-GPU dedicated memory used, bytes
  gpu_mem_size INTEGER,            -- dedicated memory capacity, bytes
  -- The card's two clocks, MHz. Two of them because they throttle for different
  -- reasons and independently: the core drops on power and thermal limits while
  -- memory holds its clock through most of that. A frame rate that fell while
  -- the core clock fell with it is a card that ran out of headroom; one that
  -- fell while both clocks held is not, and that is the fork these decide.
  gpu_core_mhz REAL,
  gpu_mem_mhz REAL,
  -- JSON array of flags; NULL when none apply. A row with every reading NULL and
  -- no flag is never written: an all-NULL row asserts "this second was covered
  -- and nothing was readable", which has to be earned by an explanation, or a
  -- reader is left treating the row as evidence of something with nothing behind
  -- it.
  quality TEXT,
  -- (agent_id, ts) is the identity, so a replayed upload overwrites nothing —
  -- and it is also the read pattern: a run detail asks for one agent's window
  -- and gets a primary-key range scan rather than a filter over every machine.
  PRIMARY KEY(agent_id, ts)
) WITHOUT ROWID;
-- Retention sweeps by age across every agent at once, and this table grows at
-- one row per second of play — faster than game_buckets, since it also covers
-- the frameless seconds. The age sweep gets its own index rather than scanning.
CREATE INDEX idx_game_host_seconds_ts ON game_host_seconds(ts);

-- The stretches of a run that produced no frames, and which silence each was.
--
-- A game that is minimized, alt-tabbed, sitting on a loading screen or building
-- a shader cache presents nothing, and a second with no frames produces no
-- bucket — "nothing was rendering" and "rendering happened at zero" are
-- different facts and only one of them can be plotted. The result was a blank
-- stretch across every chart that a reader could only interpret as lost data.
-- This records what the blank was.
--
-- Two reasons rather than one, because the remedies are opposite. 'background'
-- is time nobody was playing: nothing is wrong and the figures around it must
-- not be read as a stall. 'no_frames' is the player sitting in front of the
-- game waiting for it, which is an experience worth measuring. Recording only
-- "no frames" would be the same as recording nothing — the blank is already
-- visible, and what a reader cannot see is which kind it was. The vocabulary is
-- open: the sensor owns it, and a reader meeting a code it does not know must
-- render the band unlabelled rather than drop it.
CREATE TABLE game_run_gaps(
  -- Minted by the agent, which is the only party that can attribute a silence to
  -- a run: run ids are its to make, and it is what knows a session parked after
  -- thirty frameless seconds is still the same session ten minutes later.
  id TEXT PRIMARY KEY,
  -- CASCADE, unlike game_runs.profile_id's deliberate lack of a foreign key. A
  -- gap is part of the run's own record rather than a stamp of separate
  -- configuration, so deleting the run deletes it — and retention then needs no
  -- sweep of its own here.
  run_id TEXT NOT NULL REFERENCES game_runs(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,            -- 'background' | 'no_frames'; open vocabulary
  -- Unix seconds. started_at is the moment the first frameless second BEGAN and
  -- ended_at the moment the last one closed, so an interval sits on the same
  -- axis a bucket's ts does and a single frameless second spans exactly one.
  --
  -- ended_at is NOT NULL even while the stretch is still growing: the agent
  -- re-sends the interval with a later end as it accumulates, and an "open"
  -- state would add a case no reader would draw differently from "ends here for
  -- now" while costing every reader a branch.
  --
  -- It may fall AFTER the run's own ended_at, and must not be clamped. A run
  -- ends at its last frame; a player who minimized the game and never came back
  -- leaves fifty minutes of silence after it, and "did they stop playing or just
  -- alt-tab" is exactly the question this table answers.
  started_at INTEGER NOT NULL,
  ended_at INTEGER NOT NULL
);
-- The read pattern: one run's gaps in time order, for the bands drawn under its
-- charts.
CREATE INDEX idx_game_run_gaps_run ON game_run_gaps(run_id, started_at);

-- ===== fault detection & incidents =====

-- Per-(target, agent, detector) streak state driving the built-in availability
-- detectors. Reset when the target's generation or sensitivity revision moves.
--
-- detector_key is 'availability' | 'agent_connectivity' | 'latency_degradation' |
-- 'loss_degradation' for probe targets, and for a host anchor one of the
-- system-status families 'host_cpu' | 'host_mem' | 'host_load' | 'host_net' |
-- 'host_disk'. The two families that watch more than one thing per machine carry
-- their subject folded into the key after a '|': 'host_disk|C:', 'host_net|rx'.
-- Folding rather than adding a subject column keeps every key-shaped contract in
-- this schema unchanged — this primary key, fault_signals' open-signal unique
-- index, and the target-scoped termination predicates all still say exactly what
-- they said before, and two mounts can be down at once without colliding.
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
  -- Per-round evidence of the current UNCONFIRMED failing streak: a JSON array of
  -- {ts, metric_kind, value, reason_code, reason_detail}, one entry per failing
  -- round, staged here because a streak spans ingest batches (one transaction
  -- each) and the round that ends it carries no failure cause of its own. It is
  -- what lets a sub-threshold streak be recorded with every round's real reason,
  -- and what a confirming signal freezes as its own per-round evidence. Cleared
  -- on confirm, on recovery, and on any counter reset; bounded by fail_threshold.
  pending_fails    TEXT NOT NULL DEFAULT '[]',
  -- How many disk snapshots in a row did NOT mention this detector's subject.
  -- Only the system-status disk detectors use it, and only to tell an ejected
  -- drive from a mount whose usage read failed this cycle: the agent omits the
  -- mount either way, so absence has to be counted in OBSERVED collections. Wall
  -- time cannot do it — an agent that was offline for an hour comes back with a
  -- gap that looks identical to a removal on its very first report.
  subject_misses   INTEGER NOT NULL DEFAULT 0,
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
  -- INCIDENT-003: user-language fault position + typed evidence, computed by
  -- recomputeIncident / the trace landing hook from firing members + same-agent
  -- detector state + trace reached-points. '' = insufficient evidence (renderers
  -- fall back to layer wording). Never a rendered sentence: attribution renders
  -- per language at read/delivery time. Frozen once resolved (recompute only
  -- runs while firing members exist).
  attribution          TEXT NOT NULL DEFAULT '',   -- router|isp|dns|proxy|service|device
  attribution_evidence TEXT NOT NULL DEFAULT '[]', -- JSON [{kind,count?,targets?,name?,reason_code?}]
  state           TEXT NOT NULL DEFAULT 'open' CHECK(state IN('open','resolved')),
  severity        TEXT NOT NULL DEFAULT 'warn',
  summary         TEXT NOT NULL DEFAULT '',
  resolve_reason  TEXT NOT NULL DEFAULT '',
  evidence_expired INTEGER NOT NULL DEFAULT 0,
  -- Two different times, and the difference is the whole point.
  --
  -- opened_at is when the SERVER recorded the incident — wall clock at the
  -- confirming transaction. Ordering, the since/until filters and the 24h
  -- statistics are all built on it, and all of them want receipt time: an
  -- operator asking "what happened today" means what arrived today, and storm
  -- correlation only works because a burst of faults uploaded together shares a
  -- wall-clock instant.
  --
  -- first_observed_at is when the fault actually STARTED, taken as the running
  -- minimum of observed_at over its member signals. For live telemetry the two
  -- are seconds apart. For a backlog an agent buffered through an outage and
  -- uploaded on reconnect they differ by the length of the outage, and only this
  -- one can say how long the outage was — which is exactly what the fault list
  -- shows.
  --
  -- Nullable because a detector can legitimately have no evidence time to give
  -- (an Agent-connectivity fault whose last-seen is unknown). Readers COALESCE
  -- it to opened_at, so the API still always carries a usable instant and no
  -- consumer needs a fallback of its own.
  opened_at       TIMESTAMP NOT NULL,
  first_observed_at TIMESTAMP,
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
  detector_key      TEXT NOT NULL,                      -- availability | agent_connectivity | latency_degradation | loss_degradation
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
  -- ALERT-003: the historical band this round was judged against, frozen like
  -- everything else. A degradation claim is only readable next to what "usual"
  -- was at the time ("now 180ms, usually about 40ms"), and recomputing the
  -- baseline at read time would answer with a band that has since absorbed the
  -- very degradation it is supposed to explain. Both 0 for the availability and
  -- agent-connectivity detectors, which judge against a fixed threshold.
  baseline_p50      REAL NOT NULL DEFAULT 0,
  baseline_p95      REAL NOT NULL DEFAULT 0,
  -- Frozen DIAGNOSIS SUBJECT: the endpoint the failing probe actually talked to,
  -- which is not always the monitored one. A DNS monitor dials a resolver, a
  -- proxied monitor dials its proxy, a tunnelled one dials a WireGuard peer — so
  -- a path diagnostic aimed at target_addr would measure a path the probe never
  -- used. Frozen here for the same reason as everything above: derivation must
  -- never re-read live config, or an edit between fault and diagnosis silently
  -- redirects the diagnostic. Written from the confirming round's own evidence
  -- (resolver/STUN labels) and the probe's proxy pin at confirmation time.
  resolver_addr     TEXT NOT NULL DEFAULT '',           -- DNS: "host:port" or DoH URL ('' = unnameable)
  resolver_protocol TEXT NOT NULL DEFAULT '',           -- udp | tcp | dot | doh
  stun_addr         TEXT NOT NULL DEFAULT '',           -- NAT: resolved STUN "host:port"
  stun_transport    TEXT NOT NULL DEFAULT '',           -- udp | tcp | tls | dtls
  proxy_id          TEXT NOT NULL DEFAULT '',           -- egress pin at fault time ('' = direct)
  proxy_type        TEXT NOT NULL DEFAULT '',           -- socks5 | http | wireguard
  proxy_addr        TEXT NOT NULL DEFAULT '',           -- socks5/http "host:port"; wireguard peer endpoint
  -- The pinned proxy's config generation at fault time. An in-tunnel trace is
  -- pinned to exactly this generation so a key rotated between fault and
  -- diagnosis can never be re-enabled to carry the probes (0 = no pin).
  proxy_config_serial INTEGER NOT NULL DEFAULT 0,
  -- The MONITORED target's material generation at confirmation time — the server
  -- half of the agent scene claim key (scene_report_triggers.config_serial).
  -- Frozen for the same reason as everything above it: an edit landing between
  -- the fault and the scene would otherwise re-key evidence onto a definition it
  -- never described. Ingest drops samples whose serial does not match the
  -- target's current one, so the confirming round is necessarily the live
  -- generation and this is that number. 0 for the agent-connectivity detector,
  -- which has no target at all.
  target_config_serial INTEGER NOT NULL DEFAULT 0,
  -- Every round of the confirming streak, not just the last one: a JSON array of
  -- {ts, metric_kind, value, reason_code, reason_detail}. The columns above are
  -- the confirming round's summary; a streak that timed out twice and was then
  -- refused says something different from three refusals, and diagnosis needs
  -- both. Same shape as fluctuations.rounds_json. Empty for detectors that have
  -- no rounds (agent connectivity).
  rounds_json       TEXT NOT NULL DEFAULT '[]',
  -- DEGRADE-001/002: the confirming round's dedicated classification facts,
  -- frozen as JSON when the confirming round carried them, NULL otherwise. The
  -- size_sweep block carries {code, size_small, size_large, loss_small,
  -- loss_large, count_small, count_large} and only a loss degradation sets it;
  -- the flow_fanout block carries {code, flows, bad_stable, bad_new, ok} and
  -- only an availability fault sets it. Same freeze-everything rule as the
  -- columns above: an agent that stops sweeping must not rewrite what a past
  -- fault claimed.
  size_sweep_json   TEXT,                                 -- JSON SizeSweepFacts (NULL = not the evidence)
  flow_fanout_json  TEXT,                                 -- JSON FlowFanoutFacts (NULL = not the evidence)
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

-- A sub-threshold failing streak that recovered before confirming a fault: the
-- target failed 1..N-1 consecutive rounds and then answered again. This is the
-- explanation behind a 99% availability figure — without it the dip is visible
-- in the availability series but has no cause anywhere, because the recovering
-- round wipes the streak from detector_state and raw samples only live 2 days.
--
-- Recorded only: never notified, never a member of an incident by itself. Display
-- facts and per-round evidence are frozen at recovery time (fault_signals
-- precedent), so a later rename or deletion cannot rewrite what it said.
CREATE TABLE fluctuations(
  id             TEXT PRIMARY KEY,                    -- 'flx_' + uuid
  site_id        TEXT NOT NULL,
  agent_id       TEXT NOT NULL,
  agent_name     TEXT NOT NULL DEFAULT '',
  target_id      TEXT NOT NULL DEFAULT '',            -- no FK: history outlives the target
  target_name    TEXT NOT NULL DEFAULT '',
  target_addr    TEXT NOT NULL DEFAULT '',
  target_port    INTEGER NOT NULL DEFAULT 0,
  probe_kind     TEXT NOT NULL DEFAULT '',
  group_id       TEXT NOT NULL DEFAULT '',
  layer          TEXT NOT NULL DEFAULT '',
  detector_key   TEXT NOT NULL DEFAULT 'availability',  -- see detector_state.detector_key
  fail_rounds    INTEGER NOT NULL,                    -- streak length, 1..fail_threshold-1
  fail_threshold INTEGER NOT NULL,                    -- the threshold it did NOT reach, frozen
  metric_kind    TEXT NOT NULL DEFAULT '',            -- summary evidence: the LAST failing round
  comparator     TEXT NOT NULL DEFAULT '',
  value          REAL NOT NULL DEFAULT 0,
  threshold      REAL NOT NULL DEFAULT 0,
  reason_code    INTEGER NOT NULL DEFAULT 0,          -- telemetry.ProbeReason*
  reason_detail  TEXT NOT NULL DEFAULT '',
  rounds_json    TEXT NOT NULL DEFAULT '[]',          -- every failing round (see fault_signals.rounds_json)
  started_at     TIMESTAMP NOT NULL,                  -- first failing round of the streak
  ended_at       TIMESTAMP NOT NULL,                  -- the round that recovered
  -- Set when a later confirmed fault on the SAME target+agent claims this
  -- fluctuation as a precursor (it recovered within the lookback window before
  -- the fault was confirmed). A linked fluctuation is that incident's frozen
  -- evidence: exempt from fluctuation retention, and deleted with the incident.
  incident_id    TEXT REFERENCES incidents(id) ON DELETE CASCADE
);
-- One streak on one pair starts exactly once, so this is the natural key. It gives
-- the same replay immunity the samples primary key gives metrics: the detector
-- watermark normally stops a re-delivered packet from re-recording a dip, but a
-- sensitivity edit or a scope change deletes detector_state WITHOUT bumping the
-- config serial, so the watermark can restart at 0 while the agent is still
-- retrying an unacked batch of the same rounds.
--
-- The detector is part of the key because a host anchor's families all read the
-- same collect timestamp: one Collect() stamps CPU and memory with one instant,
-- so their streaks routinely START at the same second on the same anchor, and
-- without the detector the second family's dip would be silently dropped.
CREATE UNIQUE INDEX idx_fluctuations_streak ON fluctuations(target_id, agent_id, detector_key, started_at);
CREATE INDEX idx_fluctuations_target   ON fluctuations(target_id, ended_at);
CREATE INDEX idx_fluctuations_site     ON fluctuations(site_id, ended_at);
CREATE INDEX idx_fluctuations_agent    ON fluctuations(agent_id, ended_at);
CREATE INDEX idx_fluctuations_incident ON fluctuations(incident_id);

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

-- The SERVER's half of an incident's scene, frozen inside the transaction that
-- opened the incident: stable identifiers, the display facts as they stood at
-- trigger time, each firing condition's threshold/value and a bounded
-- recent-sample chart. Written once by WriteIncidentBase and never touched
-- again, so a later rename, edit or deletion cannot rewrite what it said.
--
-- It carries no collection lifecycle — no status, no deadline, no per-agent
-- entries — because nothing is ever pending on it. The AGENT's half used to be
-- commanded from here (an incident opened, a request went down the socket, an
-- entry waited for the answer), which is exactly backwards: the agent most worth
-- asking is the one that just went unreachable, and a push to an offline agent is
-- a no-op, so the scene was missing precisely for the network faults it exists to
-- explain. Agents now collect on their own fault edges and ship the result
-- through the WAL as a scene_report, which this server claims afterwards.
CREATE TABLE incident_snapshots(
  id          TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
  base        TEXT NOT NULL DEFAULT '',             -- immutable base JSON
  truncated   INTEGER NOT NULL DEFAULT 0,           -- optional base detail was dropped to fit incident_snapshot_max_bytes
  created_at  TIMESTAMP NOT NULL
);

-- One agent-collected scene: what an agent could see about itself and its
-- surroundings at the moment IT decided something was broken (INCIDENT-005).
--
-- Every row is TERMINAL on arrival, for the same reason trace_reports is: the
-- agent decided, collected and filed the whole self-describing report through its
-- outbox, so there is no request id, no pending state and no deadline to keep
-- here. What a row is waiting for is not collection but a VERDICT — a scene that
-- matches no confirmed fault yet is stored unattached and claimed later (see
-- scene_report_refs), because evidence recorded before a verdict is still that
-- verdict's evidence.
--
-- A scene therefore describes what the agent saw when it detected the fault,
-- which is an earlier and different statement from the frozen target list the
-- server used to ask for at incident-open time. Nothing server-side can
-- reconstruct it, so the report carries its own reason for existing in
-- scene_report_triggers.
CREATE TABLE scene_reports(
  -- Agent-minted, and the ingest idempotency key on its own: a replayed packet
  -- re-presents the same id and the INSERT OR IGNORE makes it a no-op. The key is
  -- NOT scoped per agent, deliberately — an id an agent invents that collides
  -- with another agent's stored report is dropped rather than allowed to
  -- overwrite it, which is the safe direction for a UUID collision.
  id            TEXT PRIMARY KEY,
  site_id       TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  agent_name    TEXT NOT NULL DEFAULT '',
  collected_at  TIMESTAMP,                          -- agent clock when collection finished
  received_at   TIMESTAMP NOT NULL,                 -- server clock at ingest; the claim window is measured on it
  -- How long the scene waited between the two clocks above, signed, reported
  -- rather than corrected. Positive is the ordinary case and is information, not
  -- a fault: a scene collected during an outage legitimately arrives minutes or
  -- hours after it was taken, which is what routing it through the outbox is FOR.
  -- Only a negative lag says something is wrong — the agent stamped the scene in
  -- this server's future, which delivery cannot explain and a fast agent clock
  -- can — and that is what clock_ahead flags. Reading the absolute gap as skew
  -- instead would put a clock warning on exactly the outage evidence this table
  -- exists to hold. Neither value is rewritten: an agent's clock is its own, and
  -- correcting collected_at would destroy the only record of when the agent
  -- thought it was looking.
  delivery_lag_ms INTEGER NOT NULL DEFAULT 0,
  clock_ahead     INTEGER NOT NULL DEFAULT 0,
  payload       TEXT NOT NULL DEFAULT '',           -- allowlisted field-group JSON
  truncated     INTEGER NOT NULL DEFAULT 0          -- optional detail was shed to fit incident_snapshot_max_bytes
);
-- Claims are always "this agent, recently": a newly-confirmed fault looking for a
-- scene that landed first, and retention aging out the scenes that never found a
-- fault at all.
CREATE INDEX idx_scene_claim ON scene_reports(agent_id, received_at);

-- The fault edges one scene answers for. A table rather than a column because
-- collection takes real time and faults arrive in clusters: an edge crossed while
-- a scene is already being gathered joins that scene instead of queueing a second
-- copy of the same machine. So one report can be filed as evidence under several
-- incidents, on several different keys.
CREATE TABLE scene_report_triggers(
  report_id       TEXT NOT NULL REFERENCES scene_reports(id) ON DELETE CASCADE,
  idx             INTEGER NOT NULL,                 -- position in the agent's own list
  kind            TEXT NOT NULL CHECK(kind IN('probe_fault','server_disconnect')),
  -- probe_fault: the failing monitor and the material generation the agent held
  -- for it. Together with agent_id that is the claim key, matched against
  -- fault_signals(target_id, target_config_serial). The serial is what stops a
  -- scene collected under a target's old definition surfacing under its new one —
  -- the same generation that already participates in metric series identity.
  monitor_id      TEXT NOT NULL DEFAULT '',
  config_serial   INTEGER NOT NULL DEFAULT 0,
  trigger_streak  INTEGER NOT NULL DEFAULT 0,
  first_failed_at TIMESTAMP,
  -- server_disconnect: there is no probe streak — an agent-connectivity fault is
  -- detected server-side by a sweeper noticing the agent is gone, and crosses no
  -- local edge — so the edge is the session ending, the agent's stable
  -- classification of what ended it, and how many flapping edges this one entry
  -- stands for (a link that flaps produces edges faster than a scene is worth
  -- collecting, and the count is what keeps the merge from reading as one clean
  -- drop).
  disconnected_at TIMESTAMP,
  reason          TEXT NOT NULL DEFAULT '',
  edge_count      INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(report_id, idx)
) WITHOUT ROWID;
CREATE INDEX idx_scene_trig ON scene_report_triggers(monitor_id, config_serial);

-- Which incident (through which fault signal) a scene is evidence for.
--
-- There is deliberately NO active flag, unlike trace_report_refs. A trace
-- reference participates in ATTRIBUTION — its reached-point is re-read to answer
-- "where did this break", so a resolved fault's trace has to stop counting as
-- live evidence. A scene asserts no reachability verdict and feeds no recompute:
-- it is a frozen description of one moment, and it reads exactly the same after
-- the incident resolves as it did while the incident was open. A flag nothing
-- would ever consult is a flag that goes stale.
CREATE TABLE scene_report_refs(
  report_id   TEXT NOT NULL REFERENCES scene_reports(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  signal_id   TEXT NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  PRIMARY KEY(report_id, incident_id, signal_id)
);
CREATE INDEX idx_srr_incident ON scene_report_refs(incident_id);

-- One traceroute an Agent decided to run and reported afterwards.
--
-- The server does not command these and holds no plan while one is in flight:
-- the Agent notices a target failing round after round, derives the subject and
-- destination from the target it was pushed, runs the sweep, and files the whole
-- self-describing report through its outbox. So every row here is TERMINAL on
-- arrival — there is no queued, running, claim or deadline state to keep, and no
-- single-flight index, because the Agent already deduplicated by destination
-- before it spent a packet.
CREATE TABLE trace_reports(
  id           TEXT PRIMARY KEY,                    -- Agent-minted; with agent_id it is the ingest idempotency key
  site_id      TEXT NOT NULL,
  agent_id     TEXT NOT NULL,
  agent_name   TEXT NOT NULL DEFAULT '',
  dest_key     TEXT NOT NULL,                       -- canonical: "ip:1.2.3.4" | "host:example.com"
  dest_host    TEXT NOT NULL,
  dest_ip      TEXT NOT NULL DEFAULT '',
  mode         TEXT NOT NULL CHECK(mode IN('icmp','tcp')),
  port         INTEGER NOT NULL DEFAULT 0,
  status       TEXT NOT NULL,                       -- succeeded|partial|timed_out|unsupported|failed|canceled
  reason       TEXT NOT NULL DEFAULT '',
  max_hops     INTEGER NOT NULL,                    -- the bounds the sweep really ran under, reported with it
  attempts     INTEGER NOT NULL,
  reached      INTEGER NOT NULL DEFAULT 0,
  reached_ttl  INTEGER NOT NULL DEFAULT 0,
  -- WHY the Agent ran it. Nothing server-side asked for this trace, so without
  -- the trigger the report would be an unexplained execution: the rule that
  -- fired, how many consecutive failing rounds it took, and when the streak
  -- began (which is also what makes a claim by a later fault defensible).
  trigger_reason  TEXT NOT NULL DEFAULT '',         -- consecutive_failures
  trigger_streak  INTEGER NOT NULL DEFAULT 0,
  first_failed_at TIMESTAMP,
  started_at   TIMESTAMP,
  completed_at TIMESTAMP,
  received_at  TIMESTAMP NOT NULL,                  -- server clock at ingest; the claim window is measured on it
  -- A TCP plan whose Agent lacks the TCP-traceroute permission runs as ICMP
  -- instead; these record the mode it was originally planned as and why it was
  -- downgraded, so a fallback reads as a fallback rather than a failure.
  fallback_from   TEXT NOT NULL DEFAULT '',   -- '' | tcp
  fallback_reason TEXT NOT NULL DEFAULT '',   -- raw_socket_unavailable | permission_denied
  -- WHAT this diagnostic traced, which is not always the monitored target: a DNS
  -- fault traces its resolver, a proxied fault its proxy, a tunnelled fault the
  -- WireGuard peer's physical path. Without it a resolver trace and a target
  -- trace render identically, and the destination alone cannot say which is which.
  subject_kind    TEXT NOT NULL DEFAULT 'target'
                  CHECK(subject_kind IN('target','resolver','proxy','wg_endpoint','stun_server')),
  -- '' | tunnel_unreachable | tunnel_target_unreachable | tunnel_not_attempted.
  -- Empty on a WireGuard subject means the failing round carried no classified
  -- cause, so no verdict is asserted (a NAT monitor never produces one).
  subject_reason  TEXT NOT NULL DEFAULT '',
  -- WHICH PATH the probes travelled, orthogonal to subject_kind (which says who
  -- is being measured): direct host stack, the host-stack path toward a
  -- WireGuard peer's physical endpoint, or hop-by-hop INSIDE the tunnel. An
  -- in-tunnel report and a physical-endpoint report about the same tunnel must
  -- never render alike — their hops describe different networks.
  path_scope           TEXT NOT NULL DEFAULT 'direct'
                       CHECK(path_scope IN('direct','wireguard_physical','wireguard_inner')),
  -- The exact proxy generation an in-tunnel trace ran through, as the Agent
  -- attested it. '' / 0 on every host-stack report.
  egress_id            TEXT NOT NULL DEFAULT '',
  egress_config_serial INTEGER NOT NULL DEFAULT 0
);
-- A report arrives before, during or after the fault it explains, so the fault
-- side looks it up by (agent, destination) within a recent window — both when
-- ingest attaches it to an already-open incident and when a later confirmation
-- claims one that landed first.
CREATE INDEX idx_trace_claim ON trace_reports(agent_id, dest_key, received_at);

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
-- site, one monitor group, or the Agent-connectivity detector; exactly one row
-- per scope, one default per site.
--
-- The 'agent' scope is a per-site singleton (scope_id ''), not one row per
-- Agent: an Agent going offline belongs to no monitor group, so without it the
-- only way to route offline notices differently from probe faults would be to
-- change the site default — which governs everything else too.
CREATE TABLE notification_policies(
  id                 TEXT PRIMARY KEY,                  -- 'np_' + uuid
  site_id            TEXT NOT NULL REFERENCES sites(id),
  name               TEXT NOT NULL,
  scope_kind         TEXT NOT NULL CHECK(scope_kind IN('site','group','agent')),
  scope_id           TEXT NOT NULL DEFAULT '',          -- '' for the site and agent scopes
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

-- ===== public status pages =====

-- A status page is an anonymous, slug-addressed, read-only view over an
-- admin-chosen subset of a site's agent groups and monitoring targets — the only
-- unauthenticated surface in the product that carries monitoring data. Two
-- consequences are baked into the schema. First, membership is explicit and
-- per-page: nothing is published because it exists, only because someone picked
-- it. Second, the visibility toggles live on the row rather than in the
-- frontend, because the public API enforces them server-side (a viewer who calls
-- the endpoint directly must not see what the page's UI would have hidden).
--
-- Agents are selected BY GROUP rather than one at a time. A group is the unit an
-- operator already curates, so publishing one keeps the page in step with the
-- fleet instead of drifting the moment a machine is added. The trade is worth
-- naming: an agent joining a published group becomes public with it, which is
-- why the console says so on the form.
--
-- enabled=0 is a kill switch that reads as "no such page" publicly: the API
-- answers a disabled slug and an unknown slug identically, so taking a page down
-- leaks nothing about whether it ever existed.
CREATE TABLE status_pages(
  id                  TEXT PRIMARY KEY,                    -- 'spg_' + uuid
  site_id             TEXT NOT NULL REFERENCES sites(id),
  -- The public address (/status/#/<slug>). UNIQUE across sites, not per site:
  -- the public route resolves a page by slug alone, with no site in the URL.
  slug                TEXT NOT NULL UNIQUE,
  title               TEXT NOT NULL,
  description         TEXT NOT NULL DEFAULT '',
  enabled             INTEGER NOT NULL DEFAULT 1,
  -- Opt-in reveal of raw probe addresses (IPs, hostnames, URLs). Default off:
  -- a home/SMB network's target list is an internal topology map.
  show_target_address INTEGER NOT NULL DEFAULT 0,
  show_agent_view     INTEGER NOT NULL DEFAULT 1,
  show_target_view    INTEGER NOT NULL DEFAULT 1,
  -- Opt-in publication of the selected resources' recent incident history.
  -- Default off because this is a separate disclosure decision from publishing
  -- current health; the anonymous endpoint enforces the flag server-side.
  show_incidents      INTEGER NOT NULL DEFAULT 0,
  -- How much a published node says about itself: 'off' (up/down only), 'basic'
  -- (CPU, load, memory, disk, network and uptime as percentages and rates) or
  -- 'full' (adds used/total bytes and the busiest mount's name).
  --
  -- An enum rather than two booleans because the third combination — detail
  -- without publication — is not a state that should be representable. 'basic' is
  -- the default: node health is the point of publishing nodes at all, while the
  -- byte totals and mount paths describe the MACHINE rather than its service and
  -- stay opt-in, the same call show_target_address makes above.
  agent_metrics       TEXT NOT NULL DEFAULT 'basic',
  -- This server's front door. When set, a GET / carrying no session redirects to
  -- /status/#/<slug> instead of serving the console shell; an admin with a
  -- session still gets the console, because they asked for the console.
  --
  -- Uniqueness is GLOBAL rather than per site, for the same reason slug is:
  -- there is exactly one root URL, and it resolves without a site in it. Setting
  -- the flag clears it everywhere else inside the same write transaction (see
  -- statuspage.clearHome), and the partial index below is the real guarantee
  -- behind that.
  --
  -- Deliberately independent of `enabled`: a page taken down reads as "no such
  -- page" everywhere else in this feature, and the home lookup requires
  -- enabled=1, so an unpublished home page simply has no effect until it is
  -- published again. That is less surprising than forcing the operator to clear
  -- one flag before they may set the other.
  --
  -- Not to be confused with the DEPLOYMENT-layer default page (`page` in the
  -- status app's config.js, see docs/*/status-page-domain.md). That one serves
  -- the "status page on its own domain" topology and only applies when the URL
  -- carries no #/<slug>; the redirect this column produces always carries an
  -- explicit slug, so the two can never overwrite each other.
  is_home             INTEGER NOT NULL DEFAULT 0,
  created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_status_pages_site ON status_pages(site_id);
-- At most one home page, server-wide. Partial so that the unlimited number of
-- is_home=0 rows stays unconstrained.
CREATE UNIQUE INDEX idx_status_pages_home ON status_pages(is_home) WHERE is_home=1;

-- Membership cascades from both sides: dropping a page takes its selections with
-- it, and deleting an agent group or target removes it from every page that
-- published it. That second direction is the important one — a deleted group
-- must not linger as a published row — and it is why these reference
-- agent_groups(id)/probe_tasks(id) rather than storing loose ids.
CREATE TABLE status_page_agent_groups(
  page_id  TEXT NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES agent_groups(id) ON DELETE CASCADE,
  PRIMARY KEY(page_id, group_id)
);
CREATE INDEX idx_spag_group ON status_page_agent_groups(group_id);

CREATE TABLE status_page_targets(
  page_id   TEXT NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES probe_tasks(id)  ON DELETE CASCADE,
  PRIMARY KEY(page_id, target_id)
);
CREATE INDEX idx_spt_target ON status_page_targets(target_id);
