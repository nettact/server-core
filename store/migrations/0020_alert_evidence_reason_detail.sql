-- Raw failure detail on frozen alert evidence (ALERT-REASON, detail pass).
--
-- reason_code carries the classified cause (telemetry.ProbeReason*), but the
-- class alone can't say WHICH certificate/status/OS error was behind it. The
-- agent now attaches the raw underlying error (English machine text, ≤256
-- chars, e.g. "dial tcp 1.2.3.4:443: connect: connection refused") as
-- Labels["detail"] on every non-None probe.<kind>.error_class metric; the
-- fault engine freezes it alongside reason_code so notifications and the
-- console can show the machine truth next to the translated class.
--
-- '' = no detail available (store-path evaluation reads the latest cache,
-- which has no labels — the designed degradation, never an error).
--
-- Pre-release, zero users: direct schema edit, no rollback/compat path.

ALTER TABLE alert_evidence ADD COLUMN reason_detail TEXT NOT NULL DEFAULT '';
