-- PROBE-001 follow-up: carry the agent's DETAILED block reason into the operational
-- issue, not just the coarse status.
--
-- operational_issues.reason holds the monitor STATUS (permission_blocked /
-- target_blocked / unsupported) and is switched on by opissue.Remediate, so it cannot
-- be overloaded. But the status alone is now misleading: an egress-proxy problem is
-- reported by the agent as `unsupported`, which in this product means "your agent or
-- platform cannot do this" — while the actual cause is a disabled or missing proxy the
-- operator can fix in one click.
--
-- monitor_status.reason already stores the detail (proxy_missing, proxy_unsupported,
-- proxy_remote_dns_denied, literal_denied, method_requires_extended, …), and the
-- target-status API exposes it as block_reason. The /issues list — the notification
-- bell and the issues page — did not, so the one surface that proactively tells an
-- operator "this monitor is not running" was the one that could not say why.
ALTER TABLE operational_issues ADD COLUMN detail_reason TEXT NOT NULL DEFAULT '';

-- The dedupe key now includes the detail reason (see opissue.dedupeKey), so an issue
-- that changes cause — proxy_missing becoming proxy_unsupported after a type edit —
-- is a distinct issue rather than a silent mutation of the existing row. Existing
-- rows carry the old key shape, so they are dropped: they would never match a new
-- report again and would linger as un-resolvable actives.
--
-- Safe to discard outright: operational issues are a derived, self-healing view. The
-- next MonitorStatus frame from each agent (sent on connect and on every config
-- change) rebuilds them.
DELETE FROM operational_issues WHERE category = 'monitor';
