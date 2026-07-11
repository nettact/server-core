-- Operator-editable friendly label for an agent. hostname/platform/version are
-- reported by the agent itself and stay read-only; display_name is set from the
-- Agent management UI so operators can name agents independently of hostname.
ALTER TABLE agents ADD COLUMN display_name TEXT;
