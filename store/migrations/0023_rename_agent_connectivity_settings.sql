-- Rename the Agent connectivity knobs from the alert era.
--
-- Since ALERT-002 these settings decide only whether an offline Agent is
-- RECORDED as a fault and how long confirmation takes; who hears about it is a
-- notification policy. Leaving them named agent_alert_* invited the reading that
-- turning them off merely silences a notification, when in fact it stops the
-- fault being recorded at all — the opposite end of the pipeline.
--
-- The rows are renamed rather than dropped so an operator's tuned grace and
-- recovery windows survive; the values and their bounds are unchanged.
UPDATE app_settings SET key = 'agent_connectivity_enabled'         WHERE key = 'agent_alert_enabled';
UPDATE app_settings SET key = 'agent_connectivity_grace_seconds'   WHERE key = 'agent_alert_grace_seconds';
UPDATE app_settings SET key = 'agent_connectivity_recover_seconds' WHERE key = 'agent_alert_recover_seconds';

-- Routing keys from the alert era. 0022 deleted them, but the settings API kept
-- accepting writes to both until this change removed that surface, so a value
-- could have been written back in between. Nothing reads them.
DELETE FROM app_settings WHERE key IN ('agent_alert_severity', 'agent_alert_channel_ids');
