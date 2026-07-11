-- Add a human-friendly display name to monitoring targets.
-- Existing targets keep NULL and fall back to their target string in the UI.
ALTER TABLE probe_tasks ADD COLUMN name TEXT;
