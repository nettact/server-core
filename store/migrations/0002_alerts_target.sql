-- Per-target alerts: an alert is keyed by (rule, agent, target) so e.g. one
-- public target being unreachable is a distinct alert from another.
ALTER TABLE alerts ADD COLUMN target TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_alerts_open ON alerts(site_id, rule_id, agent_id, target, state);
