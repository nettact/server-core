-- One-time repair: alert conditions orphaned by an in-place monitor kind change.
--
-- Re-typing a monitor (dns → http, …) used to keep its rules untouched, so a
-- condition kept watching a metric family the target can never emit again. The
-- fault engine answers "no sample this pass" by PRESERVING the stored verdict, so
-- such a condition freezes at not-satisfied and its rule can never fire again —
-- the monitor fails every cycle and nothing alerts. config.SetSiteTargets now
-- drops these conditions at the moment the kind changes (and reports them to the
-- console), but that reconcile cannot see kind changes that already happened.
-- This prunes the rows they left behind.
--
-- The kind → metric-family relation below mirrors
-- telemetry.MetricAllowedForProbeKind (gateway probes emit probe.icmp.*; host
-- anchors carry host.* / iface.up / wifi.* / agent.*). A condition whose target
-- no longer exists is left alone: probe_tasks deletion already cascades its rules.
--
-- Pre-release, zero users: a direct data repair, not a compatibility path.

DELETE FROM group_rule_conditions WHERE id IN (
  SELECT c.id
  FROM group_rule_conditions c
  JOIN probe_tasks pt ON pt.id = c.target_id
  WHERE NOT (
       (pt.kind IN ('icmp','gateway') AND c.metric_kind LIKE 'probe.icmp.%')
    OR (pt.kind = 'dns'  AND c.metric_kind LIKE 'probe.dns.%')
    OR (pt.kind = 'http' AND c.metric_kind LIKE 'probe.http.%')
    OR (pt.kind = 'tcp'  AND c.metric_kind LIKE 'probe.tcp.%')
    OR (pt.kind = 'nat'  AND c.metric_kind LIKE 'probe.nat.%')
    OR (pt.kind = 'host' AND (c.metric_kind LIKE 'host.%'
                              OR c.metric_kind = 'iface.up'
                              OR c.metric_kind LIKE 'wifi.%'
                              OR c.metric_kind LIKE 'agent.%'))
  )
);

-- A rule with no conditions left can never evaluate. Remove it so the user sees
-- the alarm is gone and rebuilds it, rather than trusting an inert rule. Rules
-- with a firing alert are kept: dropping one would null out alerts.rule_id
-- (ON DELETE SET NULL) on a still-open alert. Such a rule cannot be firing on a
-- stale condition anyway — a kind change wipes rule_condition_state and resolves
-- its alerts — so this is belt-and-braces, not an expected case.
DELETE FROM group_rules
WHERE NOT EXISTS (SELECT 1 FROM group_rule_conditions c WHERE c.rule_id = group_rules.id)
  AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.rule_id = group_rules.id AND a.state = 'firing');
