-- PROBE-001: egress proxies for monitoring targets (SOCKS5 / HTTP / WireGuard).
--
-- A proxy is a site-scoped, NAMED, reusable egress path managed on its own
-- console page. Targets reference one by probe_tasks.proxy_id; the server pushes
-- the referenced specs down inside DesiredState so the agent stores no proxy
-- config of its own.
--
-- Two shapes share one table because they occupy one slot in a target's config
-- and one row in the operator's mental model ("how does this monitor get out?"):
--
--   * socks5 / http  — a relay: the agent dials the proxy and asks it to connect
--     onward. Uses host/port/username/password. SOCKS5 relays TCP (CONNECT) and
--     UDP (UDP ASSOCIATE); HTTP has only CONNECT, so it is TCP-only.
--   * wireguard      — a TUNNEL, not a proxy: the agent runs a userspace
--     WireGuard device and dials the target from inside it. Uses the wg_* keys.
--     Carrying raw IP, it is the only type that can carry ICMP probes.
--
-- Splitting them into two tables would buy nothing (no shared row is ever read
-- without knowing its type) and cost a UNION in every read plus a two-table
-- referential story for proxy_id. The type column decides which column family is
-- meaningful; validation lives in server-core/api/proxyvalidate.go.
--
-- Credentials (password, wg_private_key, wg_preshared_key) are stored as written.
-- They are redacted by the read APIs and never appear in audit detail or logs.

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

-- A proxy is picked from a dropdown by name, so two same-named proxies in one
-- site would be an unresolvable choice.
CREATE UNIQUE INDEX idx_proxies_site_name ON proxies(site_id, name);
CREATE INDEX idx_proxies_site ON proxies(site_id);

-- A target's pinned egress. NULL/'' = direct dial.
--
-- Deliberately NO ON DELETE action: a proxy still referenced by a target cannot
-- be deleted at all (the API refuses with the occupying monitors named). SET NULL
-- would silently convert "monitor through the office proxy" into "monitor
-- directly" — changing where the probe egresses from without anyone asking, which
-- is exactly the failure the fail-closed design exists to prevent. CASCADE would
-- delete the monitors themselves.
ALTER TABLE probe_tasks ADD COLUMN proxy_id TEXT REFERENCES proxies(id);
CREATE INDEX idx_probe_tasks_proxy ON probe_tasks(proxy_id);
