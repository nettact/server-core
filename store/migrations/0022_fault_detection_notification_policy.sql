-- ALERT-002: zero-config fault detection, notification policies, availability.
--
-- Clean cut (pre-release, zero users). The custom AND/OR group-rule engine is
-- deleted outright and replaced by BUILT-IN per-target availability detectors
-- whose only tunables are sensitivity (confirm N / recover M rounds) and, for
-- ICMP/gateway, the loss threshold. Detection no longer depends on the user
-- having created a rule, and notification routing no longer lives on rules:
--
--   probe round → built-in detector → fault signal → incident → notification policy → channel
--
-- Facts and actions are separate tables: an incident is recorded whether or not
-- any channel is configured, and deleting a channel never deletes history.
--
-- Drop order is child-first so an FK parent delete never violates. incidents,
-- incident_timeline, incident_snapshots* and trace_* keep their schema (the new
-- engine reuses them) but their rows are discarded: every existing row points at
-- an alert id that no longer exists, and there is no meaningful migration of
-- rule-based evidence into single-metric fault signals.

-- ===== drop the rule engine =====
DROP TABLE IF EXISTS alert_evidence;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS rule_condition_state;
DROP TABLE IF EXISTS group_rule_conditions;
DROP TABLE IF EXISTS group_rules;
-- Agent connectivity folds into the unified fault pipeline (detector_key
-- 'agent_connectivity'), so its separate stream and its per-alert channel
-- freeze are gone.
DROP TABLE IF EXISTS agent_alerts;
-- trace_report_refs is rebuilt: its identity was (report, incident, alert,
-- condition); it is now (report, incident, signal).
DROP TABLE IF EXISTS trace_report_refs;

-- ===== discard the old fault history (schema kept) =====
DELETE FROM trace_hops;
DELETE FROM trace_reports;
DELETE FROM incident_snapshot_entries;
DELETE FROM incident_snapshots;
DELETE FROM incident_timeline;
DELETE FROM incidents;

-- Notification routing moved from settings/rules to notification_policies. The
-- Agent-liveness detector keeps its enable/grace/recover knobs; its channel and
-- severity are now the policy's business (and its severity is fixed at critical).
DELETE FROM app_settings WHERE key IN ('agent_alert_channel_ids', 'agent_alert_severity');

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

-- ===== detector state: per (target, agent, detector) round counters =====
-- Counting is per PROBE ROUND, not per ingest batch: last_round_ts is the
-- watermark of the newest round already folded in, so a replayed packet, an
-- out-of-order WAL backfill, or a re-ingest cannot advance (or rewind) the
-- counters, while a batch carrying several genuinely new rounds advances the
-- state once per round. Persisted so a restart neither resets a pending
-- confirmation nor re-opens an already-confirmed fault.
--
-- config_serial / detection_rev pin the counters to the generation they were
-- accumulated under: when either advances the counters reset rather than
-- carrying a stale verdict into a new configuration.
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

-- ===== fault signals =====
-- One confirmed fault lifecycle for one (agent, target, detector). Replaces
-- alerts + alert_evidence: a built-in detector reaches its verdict from a single
-- metric, so the evidence is 1:1 with the signal and is frozen inline.
--
-- target_id is a plain column, NOT a foreign key ('' for agent-connectivity
-- signals): history must survive the target being deleted, carrying the frozen
-- target_name / target_addr / group_name that were true at confirmation time. A
-- later rename or deletion can never rewrite what the fault said.
--
-- At most one firing signal per (agent, target, detector) — the partial unique
-- index enforces it, so a replayed or concurrent confirmation cannot duplicate.
-- A resolved signal never reopens; the next fault gets a new id.
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
  reason_code       INTEGER NOT NULL DEFAULT 0,
  reason_detail     TEXT NOT NULL DEFAULT '',
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

-- ===== per-target detection sensitivity =====
-- Server-side detection semantics only: these never reach the agent (they are
-- not probe params, so changing them neither bumps the site config serial nor
-- re-pushes DesiredState). A target with no row uses the balanced defaults, so
-- rows exist only where the user tuned something.
--
-- There is deliberately NO "disable fault recording" switch: a user who does not
-- want the probe disables the target; a user who does not want to be disturbed
-- edits the notification policy.
CREATE TABLE probe_detection_settings(
  target_id      TEXT PRIMARY KEY REFERENCES probe_tasks(id) ON DELETE CASCADE,
  profile        TEXT NOT NULL DEFAULT 'balanced' CHECK(profile IN('balanced','fast','stable','custom')),
  fail_rounds    INTEGER NOT NULL DEFAULT 3 CHECK(fail_rounds BETWEEN 1 AND 20),
  recover_rounds INTEGER NOT NULL DEFAULT 2 CHECK(recover_rounds BETWEEN 1 AND 20),
  icmp_loss_pct  REAL NOT NULL DEFAULT 100 CHECK(icmp_loss_pct > 0 AND icmp_loss_pct <= 100),
  revision       INTEGER NOT NULL DEFAULT 1,
  updated_at     TIMESTAMP NOT NULL
);

-- ===== notification policies =====
-- A policy consumes incidents; it takes no part in detection. Exactly one policy
-- applies to any incident, resolved by a fixed precedence with no stacking:
--   target policy > monitor-group policy > site default policy
-- Every site has one undeletable (editable) default policy. An empty channel
-- list is a legal, meaningful state: "record every fault, send nothing".
CREATE TABLE notification_policies(
  id                 TEXT PRIMARY KEY,                  -- 'np_' + uuid
  site_id            TEXT NOT NULL REFERENCES sites(id),
  name               TEXT NOT NULL,
  scope_kind         TEXT NOT NULL CHECK(scope_kind IN('site','group','target')),
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

-- ===== notification deliveries =====
-- One row per (incident, event, channel): the UNIQUE constraint is the idempotency
-- guarantee, so a replayed event, an SSE reconnect or a server restart can never
-- deliver twice. due_at is an ABSOLUTE time, so a restart resumes the remaining
-- delay by comparison rather than by re-deriving a countdown (a clock change can
-- neither duplicate nor produce a negative wait).
--
-- Lifecycle: a row is planned 'pending' when the incident opens; it is canceled
-- if the incident resolves before due_at (a fault that recovered inside the
-- notification delay is recorded but never announced); otherwise the worker
-- claims it ('sent') and dispatches. A recovery row is planned ONLY for channels
-- that actually received the open notice, so no channel ever gets a lone
-- "recovered" for a fault it never heard about.
CREATE TABLE notification_deliveries(
  id               TEXT PRIMARY KEY,                    -- 'nd_' + uuid
  incident_id      TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  site_id          TEXT NOT NULL,
  event_kind       TEXT NOT NULL CHECK(event_kind IN('incident.opened','incident.resolved')),
  channel_id       TEXT NOT NULL,
  policy_id        TEXT NOT NULL DEFAULT '',            -- frozen at plan time
  recovery_enabled INTEGER NOT NULL DEFAULT 1,          -- frozen notify_recovery
  status           TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','sent','failed','canceled')),
  due_at           TIMESTAMP NOT NULL,
  created_at       TIMESTAMP NOT NULL,
  sent_at          TIMESTAMP,
  UNIQUE(incident_id, event_kind, channel_id)
);
CREATE INDEX idx_nd_due ON notification_deliveries(status, due_at);
CREATE INDEX idx_nd_incident ON notification_deliveries(incident_id);
