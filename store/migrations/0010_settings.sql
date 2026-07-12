-- app_settings: a small key/value store for global, UI-editable server settings.
-- First use: console_base_url — the console's externally-reachable origin (e.g.
-- http://localhost:8080), used to build deep links in alert notifications. The
-- server otherwise has no way to know its own public URL from off-request code.
CREATE TABLE app_settings(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
