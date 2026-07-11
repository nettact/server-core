-- Per-agent monitoring targets via agent groups. Previously every target was
-- broadcast to all agents in a site (probe_tasks.agent_id was always NULL and
-- unused). Now a target is either broadcast (all_agents=1, the default) or scoped
-- to one or more agent groups (all_agents=0 + probe_task_groups rows). An agent
-- may belong to multiple groups; a group's agents share the scoped targets.

CREATE TABLE agent_groups(
  id         TEXT PRIMARY KEY,
  site_id    TEXT NOT NULL REFERENCES sites(id),
  name       TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_agent_groups_site ON agent_groups(site_id);

-- agent ↔ group membership (many-to-many: an agent can be in several groups).
CREATE TABLE agent_group_members(
  group_id TEXT NOT NULL REFERENCES agent_groups(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  PRIMARY KEY(group_id, agent_id)
);
CREATE INDEX idx_agm_agent ON agent_group_members(agent_id);

-- Rebuild probe_tasks to drop the unused agent_id column and add the all_agents
-- scope flag. agent_id carries a foreign key, so ALTER TABLE DROP COLUMN is not
-- permitted; a table rebuild is required. No other table has a real FK to
-- probe_tasks (alert_rules.probe_task_id is a plain indexed column, not a declared
-- FK), so the drop-and-rename is safe.
CREATE TABLE probe_tasks_new(
  id         TEXT PRIMARY KEY,
  site_id    TEXT NOT NULL REFERENCES sites(id),
  kind       TEXT NOT NULL,
  target     TEXT,
  params     TEXT,
  enabled    INTEGER NOT NULL DEFAULT 1,
  name       TEXT,
  all_agents INTEGER NOT NULL DEFAULT 1
);
INSERT INTO probe_tasks_new(id, site_id, kind, target, params, enabled, name, all_agents)
  SELECT id, site_id, kind, target, params, enabled, name, 1 FROM probe_tasks;
DROP TABLE probe_tasks;
ALTER TABLE probe_tasks_new RENAME TO probe_tasks;

-- target ↔ group scope (only consulted when a target has all_agents=0).
CREATE TABLE probe_task_groups(
  task_id  TEXT NOT NULL REFERENCES probe_tasks(id),
  group_id TEXT NOT NULL REFERENCES agent_groups(id),
  PRIMARY KEY(task_id, group_id)
);
CREATE INDEX idx_ptg_group ON probe_task_groups(group_id);
