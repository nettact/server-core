-- DIAG-001 traceroute permission fallback.
--
-- A TCP trace plan whose detecting agent lacks the TCP traceroute permission in
-- its effective set — on Windows an unprivileged agent cannot receive the ICMP
-- Time-Exceeded replies TCP tracing needs — is now downgraded to ICMP mode at
-- derivation (when the agent holds the ICMP permission) instead of failing
-- terminally. These columns record that downgrade on the report so the console
-- can explain the reduced diagnostic ("needs Administrator").
--
-- Pre-release, zero users: direct schema edit, no compat path.

-- '' = the report ran in its natural mode; 'tcp' = an ICMP report derived from
-- a TCP/HTTP-monitor fault by the permission fallback.
ALTER TABLE trace_reports ADD COLUMN fallback_from TEXT NOT NULL DEFAULT '';

-- Why the natural mode was unavailable, matching the agent engine's stable
-- codes: 'raw_socket_unavailable' (granted but the runtime lacks the raw
-- socket, i.e. needs Administrator) | 'permission_denied' (policy never
-- granted the mode). '' when fallback_from is ''.
ALTER TABLE trace_reports ADD COLUMN fallback_reason TEXT NOT NULL DEFAULT '';
