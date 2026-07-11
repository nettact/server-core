-- The per-target scheduling tier was never consumed by the agent (probe cadence
-- is driven entirely by params.interval_seconds), so it is removed. The internal
-- base/regular scheduler tiers and metrics retention tiers are unrelated and stay.
ALTER TABLE probe_tasks DROP COLUMN tier;
