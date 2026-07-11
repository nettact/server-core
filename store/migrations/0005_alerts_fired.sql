-- Record when an alert actually fired (crossed its fail-threshold / dwell). The
-- per-target alarm history filters on this so that pending attempts which
-- resolved WITHOUT ever firing are not presented as real alarms. Currently
-- firing rows are backfilled from started_at; historical resolved rows cannot be
-- reclassified after the fact and are therefore omitted from the history view.
ALTER TABLE alerts ADD COLUMN fired_at TIMESTAMP;
UPDATE alerts SET fired_at=started_at WHERE state='firing';
