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
  -- work from the frame events, NOT the card's total load. gpu_util_pct below is
  -- the other half of that comparison and comes from somewhere else entirely.
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
  -- Whole-adapter telemetry, polled once at the second boundary rather than
  -- derived from frames. These three are EACH independent, like the proc_*
  -- readings and unlike the frame-derived groups above: which figures a driver
  -- publishes varies by vendor and by metric, so a card reporting utilization
  -- and no memory is an ordinary card rather than a failed read. Read-back
  -- rebuilds the block when ANY of them is non-NULL.
  --
  -- These two blocks (gpu_* telemetry and proc_vram_*) are also the ones gated
  -- by game.gpu.read: they describe the adapter and every process sharing it,
  -- not just the game whose frames the run is about, so ingest NULLs them for an
  -- agent that holds only game.performance.read.
  gpu_util_pct REAL,               -- whole-GPU utilization 0-100 (NOT this process)
  gpu_mem_used INTEGER,            -- whole-GPU dedicated memory used, bytes
  gpu_mem_size INTEGER,            -- dedicated memory capacity, bytes
  -- The game process's own dedicated video memory, which is what gpu_mem_used
  -- cannot say: a full card says nothing about who filled it. used is the
  -- discriminator for the block; budget is independently NULL because the OS
  -- does not always expose a per-process budget, and the level is still the
  -- measurement without it.
  proc_vram_used INTEGER,
  proc_vram_budget INTEGER,
  -- The busiest logical core, % 0-100. It stands alone rather than joining the
  -- proc_* group because it describes the machine and not the process: a
  -- single-threaded game pins one core while proc_cpu_pct — a share of all
  -- cores — reads low, and that gap is the whole finding.
  busiest_core_pct REAL,
  quality TEXT,                    -- JSON array of flags; NULL when none apply
  PRIMARY KEY(run_id, ts)
) WITHOUT ROWID;
-- Retention deletes by age across every run at once, and this is by far the
-- fastest-growing table in the store (one row per second of play), so the age
-- sweep gets its own index rather than scanning the whole table hourly.
CREATE INDEX idx_game_buckets_ts ON game_buckets(ts);

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
  -- Per-round evidence of the current UNCONFIRMED failing streak: a JSON array of
  -- {ts, metric_kind, value, reason_code, reason_detail}, one entry per failing
  -- round, staged here because a streak spans ingest batches (one transaction
  -- each) and the round that ends it carries no failure cause of its own. It is
  -- what lets a sub-threshold streak be recorded with every round's real reason,
  -- and what a confirming signal freezes as its own per-round evidence. Cleared
  -- on confirm, on recovery, and on any counter reset; bounded by fail_threshold.
  pending_fails    TEXT NOT NULL DEFAULT '[]',
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
  -- Every round of the confirming streak, not just the last one: a JSON array of
  -- {ts, metric_kind, value, reason_code, reason_detail}. The columns above are
  -- the confirming round's summary; a streak that timed out twice and was then
  -- refused says something different from three refusals, and diagnosis needs
  -- both. Same shape as fluctuations.rounds_json. Empty for detectors that have
  -- no rounds (agent connectivity).
  rounds_json       TEXT NOT NULL DEFAULT '[]',
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
CREATE UNIQUE INDEX idx_fluctuations_streak ON fluctuations(target_id, agent_id, started_at);
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
  fallback_reason TEXT NOT NULL DEFAULT '',   -- raw_socket_unavailable | permission_denied
  -- WHAT this diagnostic traced, which is not always the monitored target: a DNS
  -- fault traces its resolver, a proxied fault its proxy, a tunnelled fault the
  -- WireGuard peer's physical path. Without it a resolver trace and a target
  -- trace render identically, and the destination alone cannot say which is which.
  subject_kind    TEXT NOT NULL DEFAULT 'target'
                  CHECK(subject_kind IN('target','resolver','proxy','wg_endpoint','stun_server')),
  -- '' | tunnel_unreachable | tunnel_target_unreachable | tunnel_not_attempted.
  -- Empty on a WireGuard subject means the fault carried no classified cause, so
  -- no verdict is asserted (a NAT monitor never produces one).
  subject_reason  TEXT NOT NULL DEFAULT '',
  -- WHICH PATH the probes travel, orthogonal to subject_kind (which says who is
  -- being measured): direct host stack, the host-stack path toward a WireGuard
  -- peer's physical endpoint, or hop-by-hop INSIDE the tunnel. An in-tunnel
  -- report and a physical-endpoint report about the same tunnel must never
  -- render alike — their hops describe different networks.
  path_scope           TEXT NOT NULL DEFAULT 'direct'
                       CHECK(path_scope IN('direct','wireguard_physical','wireguard_inner')),
  -- The exact proxy generation an in-tunnel trace is pinned to, frozen from the
  -- fault evidence. The agent must match both ID and serial or fail closed —
  -- never a rotated key, never the host stack — and ingest rejects a result
  -- whose attestation disagrees. '' / 0 on every host-stack report.
  egress_id            TEXT NOT NULL DEFAULT '',
  egress_config_serial INTEGER NOT NULL DEFAULT 0
);
-- The subject columns are part of the key: the same host is a different
-- diagnosis as a resolver than as a monitored target, and a WireGuard peer
-- traced because the tunnel is down is a different conclusion from one traced
-- because the tunnel worked. Merging either pair would answer one fault with
-- another fault's evidence, since a report freezes one subject and one reason.
-- The path columns are part of the key for the same reason one level down: two
-- WireGuard tunnels can both contain 10.0.0.10, and the same in-tunnel address
-- traced through different tunnels — or different generations of one tunnel —
-- is a different execution with a different answer.
CREATE UNIQUE INDEX idx_trace_singleflight
  ON trace_reports(agent_id, dest_key, mode, port, subject_kind, subject_reason, path_scope, egress_id, egress_config_serial) WHERE cohort_open=1;
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
