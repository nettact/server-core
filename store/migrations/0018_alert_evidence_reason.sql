-- Raw failure reason on frozen alert evidence (ALERT-REASON).
--
-- A fired alert's evidence records the rule breach (metric vs threshold) but not
-- the underlying cause. The agent now classifies DNS/HTTP/ICMP failures into a
-- shared telemetry.ProbeReason* code (mirroring the existing TCP error_class),
-- carried as a probe.<kind>.error_class metric. The fault engine freezes that code
-- alongside the breach value so notifications and the console can state WHY
-- (unreachable / DNS-resolution-failed / timeout), not just "解析失败".
--
-- 0 = ProbeReasonNone (no classified cause: a pure threshold/latency breach, or a
-- host/nat condition that has no reason concept).
--
-- Pre-release, zero users: direct schema edit, no rollback/compat path.

ALTER TABLE alert_evidence ADD COLUMN reason_code INTEGER NOT NULL DEFAULT 0;
