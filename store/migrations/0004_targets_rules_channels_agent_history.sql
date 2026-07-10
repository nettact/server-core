-- M4: per-target protocol params, per-target alarm rules + templates,
-- named/routable notification channels, and agent online/offline history.

-- ── Alarm rules move from site-scoped glob matching to per-target binding, and
-- gain a reusable-template flavor plus consecutive-failure-count triggering.
--   probe_task_id: the target this rule is bound to (NULL for templates).
--   fail_threshold: fire after this many CONSECUTIVE breaching evaluations.
--   is_template: 1 = reusable template (not evaluated), 0 = live per-target rule.
-- channel_ids already exists on alert_rules (0001) — now populated (JSON array).
ALTER TABLE alert_rules ADD COLUMN probe_task_id TEXT;
ALTER TABLE alert_rules ADD COLUMN fail_threshold INTEGER NOT NULL DEFAULT 1;
ALTER TABLE alert_rules ADD COLUMN is_template INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_alert_rules_probe ON alert_rules(probe_task_id);

-- Pre-M4 rules were site-scoped glob rules with no target binding. On upgraded
-- databases keep them usable by turning them into templates (the new engine only
-- evaluates target-bound rules); otherwise they would silently stop firing and
-- also not appear anywhere in the UI. Fresh installs have no rows here.
UPDATE alert_rules SET is_template=1 WHERE probe_task_id IS NULL;

-- Consecutive-failure accumulator for the count-based alert lifecycle.
ALTER TABLE alerts ADD COLUMN fail_count INTEGER NOT NULL DEFAULT 0;

-- Notification channels become first-class: a human label so operators can tell
-- multiple webhooks/emails apart.
ALTER TABLE notification_channels ADD COLUMN name TEXT;

-- Agent online/offline transition history (0001 only kept the current status).
CREATE TABLE agent_status_history(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  status TEXT NOT NULL,          -- online | offline
  changed_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_ash_agent ON agent_status_history(agent_id, changed_at);
