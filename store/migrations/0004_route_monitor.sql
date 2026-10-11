-- Route monitoring: the agent's declared capabilities, and the storage behind
-- periodic traceroute history (route epochs, their dictionaries, run detail
-- and confirmed route changes).
--
-- ---------------------------------------------------------------------------
-- agents.capabilities
-- ---------------------------------------------------------------------------
-- The capability names the agent declared in its last Hello, as a sorted JSON
-- string array. Capabilities used to live only inside the connection that
-- negotiated them; persisting them lets the config downlink and the status
-- prediction (which run without a live session, e.g. on a console save while
-- the agent is offline) know whether an agent can run a probe kind that older
-- builds do not understand. An agent that never connected after this upgrade
-- reads as declaring nothing, which is the safe default: a kind gated on a
-- capability is withheld until the agent proves it on its next Hello.
ALTER TABLE agents ADD COLUMN capabilities TEXT NOT NULL DEFAULT '[]';

-- ---------------------------------------------------------------------------
-- Route history
-- ---------------------------------------------------------------------------
-- Storage is shaped by one observation: a route is the same almost all the
-- time. A naive per-run, per-hop, per-attempt table costs hundreds of MB per
-- monitor per year for rows that mostly repeat. Instead:
--
--   * route_epochs   one row per (agent, monitor, AS path) era; an unchanged
--                    route only bumps counters and a mergeable RTT histogram.
--   * route_paths    content-addressed paths, shared by every monitor and agent
--                    that sees the same hops; the IP path and its AS path are
--                    varint BLOBs of dictionary ids, not text.
--   * route_ips /    dictionaries for hop addresses and AS names, so a hop is
--     asn_info       one small integer wherever it is referenced.
--   * route_runs_detail  full per-attempt detail, kept only for a short rolling
--                    window — except the runs a route change cites as evidence.
--
-- Times are unix seconds (INTEGER), matching the newer tables. Id-keyed tables
-- keep SQLite's rowid (INTEGER PRIMARY KEY is the rowid itself, the cheapest
-- possible key); composite-keyed tables are WITHOUT ROWID so the key IS the
-- row and there is no second b-tree to maintain.

-- asn_info: AS number -> description and registration country, as last
-- reported by the lookup table. A few hundred rows for a whole installation.
CREATE TABLE asn_info (
    asn INTEGER PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);

-- route_ips: one row per distinct (address, reverse name, origin AS, matched
-- prefix). A hop whose mapping changes — a new reverse name, or a corrected
-- lookup table moving it to another AS — gets a NEW row rather than an update,
-- so paths recorded before the change keep describing what was true then.
-- asn = 0 means no AS (private, unannounced, or no table loaded).
-- asn_db_version is the table version that produced the mapping.
CREATE TABLE route_ips (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    asn INTEGER NOT NULL DEFAULT 0,
    prefix TEXT NOT NULL DEFAULT '',
    asn_db_version TEXT NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    UNIQUE (ip, asn, prefix, hostname)
);

-- route_paths: a normalized path, deduplicated by content hash.
--   ip_path  per TTL from 1: varint responder count, then that many route_ips
--            ids (sorted); a count of 0 is a TTL nobody answered.
--   as_path  the derived AS path: varint AS numbers, hops without an AS
--            skipped, adjacent repeats merged. A function of ip_path (each
--            route_ips row fixes its AS), stored so comparisons never decode
--            hops.
--   reached  whether the destination answered; part of the identity because
--            a reached and an unreached sweep over the same prefix of hops
--            say different things.
CREATE TABLE route_paths (
    id INTEGER PRIMARY KEY,
    hash BLOB NOT NULL UNIQUE,
    ip_path BLOB NOT NULL,
    as_path BLOB NOT NULL,
    reached INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL
);

-- route_epochs: one era of one AS path, for one (agent, monitor). A monitor
-- can run on several agents, so both are part of the key. path_id is the
-- representative IP path of the era (its AS path is the era's identity);
-- every IP-level variant seen within it is counted in route_epoch_variants.
-- deviation_count counts runs that disagreed with the era but never
-- confirmed as a change. The destination RTT is kept as a fixed log-bucket
-- histogram (rtt_hist, varint counts) plus count/sum/min/max, which merges
-- exactly and answers percentiles without storing samples. probes/replies are
-- the destination attempts sent and answered, for loss. local_asn/local_prefix
-- describe the first public hop (the local egress); NULL/'' when unknown.
-- config_serial is the monitor generation the era was recorded under: a
-- material edit of the monitor (a new destination) starts a new era rather
-- than reporting the edit as a route change.
CREATE TABLE route_epochs (
    id INTEGER PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    monitor_id TEXT NOT NULL REFERENCES probe_tasks(id) ON DELETE CASCADE,
    config_serial INTEGER NOT NULL DEFAULT 0,
    path_id INTEGER NOT NULL REFERENCES route_paths(id),
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL,
    run_count INTEGER NOT NULL DEFAULT 0,
    deviation_count INTEGER NOT NULL DEFAULT 0,
    reached_runs INTEGER NOT NULL DEFAULT 0,
    probes INTEGER NOT NULL DEFAULT 0,
    replies INTEGER NOT NULL DEFAULT 0,
    dest_ip TEXT NOT NULL DEFAULT '',
    local_asn INTEGER,
    local_prefix TEXT NOT NULL DEFAULT '',
    rtt_hist BLOB,
    rtt_count INTEGER NOT NULL DEFAULT 0,
    rtt_sum REAL NOT NULL DEFAULT 0,
    rtt_min REAL NOT NULL DEFAULT 0,
    rtt_max REAL NOT NULL DEFAULT 0
);
CREATE INDEX idx_route_epochs_monitor ON route_epochs(monitor_id, agent_id, start_ts);
CREATE INDEX idx_route_epochs_agent ON route_epochs(agent_id);

-- route_epoch_variants: how often each IP path occurred within an era (ECMP
-- makes the IP path differ run to run while the AS path holds).
CREATE TABLE route_epoch_variants (
    epoch_id INTEGER NOT NULL REFERENCES route_epochs(id) ON DELETE CASCADE,
    path_id INTEGER NOT NULL REFERENCES route_paths(id),
    count INTEGER NOT NULL DEFAULT 0,
    last_ts INTEGER NOT NULL,
    PRIMARY KEY (epoch_id, path_id)
) WITHOUT ROWID;

-- route_runs_detail: one sweep in full — every attempt's responder and RTT —
-- kept for a short rolling window, except the runs a route change cites.
-- hops is a varint BLOB: per hop the TTL, the attempt count, then per attempt
-- the route_ips id (0 = timed out) and the RTT in hundredths of a ms plus one
-- (0 = none). Every address it names is also in its path's ip_path, so the
-- dictionaries stay reachable through route_paths alone. (agent_id,
-- report_id) is unique: the agent-minted report id makes a replayed sweep a
-- no-op.
CREATE TABLE route_runs_detail (
    id INTEGER PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    monitor_id TEXT NOT NULL REFERENCES probe_tasks(id) ON DELETE CASCADE,
    report_id TEXT NOT NULL,
    run_ts INTEGER NOT NULL,
    path_id INTEGER NOT NULL REFERENCES route_paths(id),
    dest_ip TEXT NOT NULL DEFAULT '',
    reached INTEGER NOT NULL DEFAULT 0,
    hops BLOB NOT NULL,
    UNIQUE (agent_id, report_id)
);
CREATE INDEX idx_route_runs_detail_monitor ON route_runs_detail(monitor_id, agent_id, run_ts);
CREATE INDEX idx_route_runs_detail_ts ON route_runs_detail(run_ts);

-- route_monitor_state: the live detector state of one (agent, monitor) — the
-- open era, the last run, and the not-yet-confirmed candidate route (pending,
-- a small JSON document holding at most the confirmation window's runs).
-- Kept off route_epochs so an era row only changes when the era does.
CREATE TABLE route_monitor_state (
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    monitor_id TEXT NOT NULL REFERENCES probe_tasks(id) ON DELETE CASCADE,
    epoch_id INTEGER REFERENCES route_epochs(id) ON DELETE SET NULL,
    config_serial INTEGER NOT NULL DEFAULT 0,
    last_run_at INTEGER NOT NULL DEFAULT 0,
    last_path_id INTEGER,
    last_run_id INTEGER,
    pending TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (agent_id, monitor_id)
) WITHOUT ROWID;

-- route_changes: a confirmed route change, kept forever. kind is route |
-- destination | local_egress; segment is local_access | isp_backbone |
-- interconnect | destination | unknown; diverge_ttl is the TTL of the first
-- hop on the new route that left the old AS path (NULL when not locatable).
-- before_run_id/after_run_id cite the last run on the old route and the first
-- on the new one; retention never removes a cited run.
CREATE TABLE route_changes (
    id INTEGER PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    monitor_id TEXT NOT NULL REFERENCES probe_tasks(id) ON DELETE CASCADE,
    from_epoch_id INTEGER NOT NULL REFERENCES route_epochs(id) ON DELETE CASCADE,
    to_epoch_id INTEGER NOT NULL REFERENCES route_epochs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    segment TEXT NOT NULL,
    diverge_ttl INTEGER,
    confirmed_at INTEGER NOT NULL,
    before_run_id INTEGER REFERENCES route_runs_detail(id) ON DELETE SET NULL,
    after_run_id INTEGER REFERENCES route_runs_detail(id) ON DELETE SET NULL
);
CREATE INDEX idx_route_changes_monitor ON route_changes(monitor_id, confirmed_at);
CREATE INDEX idx_route_changes_agent ON route_changes(agent_id);
