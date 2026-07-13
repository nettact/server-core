-- Re-key interface storage from the old per-interface inventory delta to the
-- authoritative per-round InterfaceSnapshot: the agent now sends the full
-- interface set every round, so the server replaces rows wholesale (semantic
-- re-key ⇒ DROP+CREATE, matching the 0011 precedent). Interfaces gain Wi-Fi
-- columns (wifi_state IS NULL ⇒ a wired row) and a new agent_wifi table holds
-- the collection-level Wi-Fi verdict + sample time + the last applied packet
-- sequence (the monotonic delivery-order guard for current-state replacement;
-- sampled_at is kept only for freshness, never for ordering).
--
-- Pre-release, zero users: a clean rebuild (dev data wiped) beats a migration.

DROP TABLE IF EXISTS interfaces;

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
  agent_id      TEXT PRIMARY KEY REFERENCES agents(id),
  state         TEXT NOT NULL,           -- ok | unreadable (collection-level)
  reason        TEXT,                    -- permission | driver when unreadable
  sampled_at    TIMESTAMP NOT NULL,      -- freshness only (agent wall-clock)
  last_sequence INTEGER NOT NULL DEFAULT 0  -- last applied packet sequence (delivery-order guard)
);
