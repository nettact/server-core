package incidentops

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/fault"
)

// Server-side pre-terminal trace statuses (never sent by an agent — the agent
// only reports the terminal telemetry.TraceStatus* values).
const (
	traceStatusQueued  = "queued"
	traceStatusRunning = "running"
)

// nonterminalTrace reports whether a report status still accepts a result / can
// be dispatched (i.e. queued or running).
func nonterminalTrace(status string) bool {
	return status == traceStatusQueued || status == traceStatusRunning
}

// TraceEligibleMetric reports whether a firing condition — identified by its
// probe kind and breached metric — is a network-availability fault eligible for
// an automatic traceroute. It is the single source of truth for the eligible
// metric set: icmp/tcp/http/dns/nat probe metrics qualify; gateway, host,
// wireless and pure-resource metrics never trigger a trace.
//
// dns and nat qualify because their probe DOES dial a network endpoint — a
// resolver, a STUN server — even though it is not the monitored target. What
// they diagnose is chosen in deriveTrace; see traceSubject*.
func TraceEligibleMetric(probeKind, metricKind string) bool {
	switch probeKind {
	case "icmp":
		return strings.HasPrefix(metricKind, "probe.icmp.")
	case "tcp":
		return strings.HasPrefix(metricKind, "probe.tcp.")
	case "http":
		return strings.HasPrefix(metricKind, "probe.http.")
	case "dns":
		return strings.HasPrefix(metricKind, "probe.dns.")
	case "nat":
		return strings.HasPrefix(metricKind, "probe.nat.")
	}
	return false
}

// What a trace report diagnoses. The monitored target is only one option: a
// probe reaches its target through a resolver, a proxy or a tunnel, and when the
// fault is on that path, tracing the target measures a path the probe never
// used. Mirrored by the trace_reports.subject_kind CHECK constraint and by the
// console's subject labels.
const (
	traceSubjectTarget     = "target"      // the monitored endpoint itself
	traceSubjectResolver   = "resolver"    // the DNS server a dns monitor queried
	traceSubjectProxy      = "proxy"       // the socks5/http proxy a pinned monitor dialed
	traceSubjectWGEndpoint = "wg_endpoint" // a WireGuard peer's physical endpoint
	traceSubjectSTUNServer = "stun_server" // the STUN server a nat monitor probed
)

// Why a WireGuard fault is diagnosed at the peer endpoint rather than inside the
// tunnel. Both trace the same physical path — the distinction is what the
// operator should conclude from it, and it comes from the frozen reason code, not
// from the trace.
const (
	// subjectTunnelUnreachable: the probe never got through the tunnel (a proxy_*
	// reason), so the peer's reachability IS the fault.
	subjectTunnelUnreachable = "tunnel_unreachable"
	// subjectTunnelTargetUnreachable: the tunnel carried the probe and the TARGET
	// failed. Hop-by-hop tracing inside the tunnel is not implementable on the
	// current userspace stack (see todos/DIAG-004), so the peer path is traced as
	// the nearest useful evidence and must be labelled as exactly that.
	subjectTunnelTargetUnreachable = "tunnel_target_unreachable"
	// An empty subject reason on a WireGuard plan means neither could be
	// established — see wgSubjectReason.
)

// traceModeForKind maps a directly-dialed probe kind to its natural traceroute
// mode. ICMP monitors run ICMP traceroute; TCP and HTTP monitors run TCP
// traceroute. dns/nat are absent on purpose: their mode follows the resolver
// protocol / STUN transport, not the kind (see deriveTrace).
//
// The only automatic mode change happens later, in deriveTrace's permission
// gate: a TCP plan whose agent lacks the TCP permission but holds the ICMP one
// is downgraded to ICMP mode with the fallback recorded (fallbackFrom /
// fallbackReason).
func traceModeForKind(kind string) (string, bool) {
	switch kind {
	case "icmp":
		return pcfg.TraceModeICMP, true
	case "tcp", "http":
		return pcfg.TraceModeTCP, true
	}
	return "", false
}

// Stable denial reason codes shared with the agent traceroute engine's
// capabilityReason, so server-derived and agent-reported outcomes speak one
// vocabulary: permission_denied = the policy never granted the mode;
// raw_socket_unavailable = granted but the runtime lacks the raw socket TCP
// tracing needs (i.e. the agent needs Administrator privileges).
const (
	reasonPermissionDenied     = "permission_denied"
	reasonRawSocketUnavailable = "raw_socket_unavailable"
	// The subject exists but has no traceable address. Distinct from
	// no_destination, which means the monitored target itself was unknown.
	reasonResolverUnknown  = "resolver_unknown"  // the agent could not name the resolver it used
	reasonResolverLoopback = "resolver_loopback" // the resolver is a local stub; the path is zero hops
	reasonProxyUnknown     = "proxy_unknown"     // the pinned proxy has no usable address (deleted/incomplete)
	reasonNoSTUNServer     = "no_stun_server"    // the STUN endpoint was never recorded
)

// derivedTrace is the resolved traceroute plan for one eligible condition.
type derivedTrace struct {
	mode     string
	destKey  string
	destHost string
	destIP   string
	port     int
	// subjectKind names WHAT the destination above is (traceSubject*), and
	// subjectReason why that subject was chosen where the choice is not implied by
	// the kind. Without them a resolver trace and a target trace are
	// indistinguishable on read: same columns, opposite meanings.
	subjectKind   string
	subjectReason string
	// fallbackFrom/fallbackReason record an automatic mode downgrade: a TCP plan
	// whose agent lacks the TCP permission but holds the ICMP one runs as ICMP
	// with fallbackFrom="tcp" and the stable why-code (raw_socket_unavailable |
	// permission_denied). The frozen port is kept — it is trigger-time fault
	// evidence, and it keeps the fallback report's cohort key distinct from a
	// pure ICMP monitor's.
	fallbackFrom   string
	fallbackReason string
	// terminal/reason are set when the inputs are invalid, non-derivable or
	// policy-ineligible: the report is created in that terminal state and never
	// dispatched.
	terminal string
	reason   string
}

// traceEvidence is one fault signal's frozen trigger-time evidence, as far as
// diagnosis derivation is concerned. Every field is read from fault_signals, and
// nothing here is ever re-read from live config.
type traceEvidence struct {
	probeKind  string
	targetAddr string
	targetPort int
	// reasonCode is the frozen telemetry.ProbeReason* classification. It is what
	// separates "the tunnel is down" from "the tunnel is up and the target is down"
	// — two faults with identical destinations and opposite conclusions.
	reasonCode int

	resolverAddr     string
	resolverProtocol string
	stunAddr         string
	stunTransport    string
	proxyID          string
	proxyType        string
	proxyAddr        string
}

// deriveTrace resolves the traceroute plan entirely from a condition's frozen
// trigger-time evidence, gating on the detecting agent's effective traceroute
// permission. It never reads live probe_tasks or proxies, so a target, resolver
// or proxy edited or deleted between the fault and this derivation can never
// redirect the diagnostic to a different endpoint or port.
//
// The plan answers "what carried this probe", not "what was being monitored" —
// those diverge for every indirect probe:
//
//	pinned to socks5/http  → the PROXY (agent→proxy→target; a direct trace to the
//	                         target measures a path the probe never used, and the
//	                         relay protocols cannot carry a hop-by-hop diagnostic)
//	pinned to wireguard    → the peer ENDPOINT's physical path (in-tunnel hop-by-hop
//	                         is not implementable on the userspace stack; DIAG-004)
//	dns                    → the RESOLVER (the queried name is dialed by nobody)
//	nat                    → the STUN SERVER (which is the monitored target, but only
//	                         the probe knows the port and transport it used)
//	otherwise              → the target itself
//
// A TCP plan whose agent lacks the TCP permission falls back to ICMP mode when
// the ICMP permission is held (recorded via fallbackFrom/fallbackReason so the
// console can explain the downgrade); a non-derivable destination/port or a fully
// missing permission yields a terminal failed/unsupported plan rather than a
// dispatch. No auto-elevation, ever.
func (s *Service) deriveTrace(ctx context.Context, agentID string, evd traceEvidence) (derivedTrace, bool) {
	d, ok := planTrace(evd)
	if !ok {
		return derivedTrace{}, false
	}
	if d.terminal != "" {
		return d, true
	}
	mode := d.mode

	// Permission gate: the detecting agent must actually hold the mode's
	// traceroute permission in its effective policy. A TCP plan is never
	// elevated, but it MAY be downgraded: with the ICMP permission held the
	// trace runs in ICMP mode and records the fallback; with neither permission
	// it is terminal unsupported, with the denial reason distinguishing a policy
	// denial from a capability gap (needs Administrator).
	supported, granted, effective := s.agentPermissions(ctx, agentID)
	switch {
	case mode == pcfg.TraceModeTCP && !effective.Has(permission.DiagnosticTracerouteTCP):
		if effective.Has(permission.DiagnosticTracerouteICMP) {
			d.mode = pcfg.TraceModeICMP
			d.fallbackFrom = pcfg.TraceModeTCP
			d.fallbackReason = tcpTraceDenialReason(supported, granted)
		} else {
			d.terminal = telemetry.TraceStatusUnsupported
			d.reason = tcpTraceDenialReason(supported, granted)
		}
	case mode == pcfg.TraceModeICMP && !effective.Has(permission.DiagnosticTracerouteICMP):
		d.terminal = telemetry.TraceStatusUnsupported
		d.reason = reasonPermissionDenied
	}
	return d, true
}

// planTrace picks the diagnosis subject, destination and mode from frozen
// evidence alone — no permissions, no I/O, no clock. deriveTrace layers the
// agent's permissions on top. Returns ok=false for a fault whose kind has no
// diagnosable path at all (gateway, host, wireless, resource), which
// TraceEligibleMetric already excludes.
func planTrace(evd traceEvidence) (derivedTrace, bool) {
	// An egress pin wins over the probe kind: whatever the monitor asked about, the
	// packets went to the proxy first, and a fault on that leg has nothing to do
	// with the target's own path.
	if evd.proxyID != "" {
		return planProxyTrace(evd)
	}
	switch evd.probeKind {
	case "dns":
		return planResolverTrace(evd)
	case "nat":
		return planSTUNTrace(evd)
	}

	mode, ok := traceModeForKind(evd.probeKind)
	if !ok {
		return derivedTrace{}, false
	}
	d := derivedTrace{mode: mode, subjectKind: traceSubjectTarget}
	switch evd.probeKind {
	case "icmp":
		if evd.targetAddr == "" {
			return terminalPlan(mode, traceSubjectTarget, "", "no_destination"), true
		}
		d.destKey, d.destHost, d.destIP = canonicalDest(evd.targetAddr)
	case "tcp":
		if evd.targetAddr == "" {
			return terminalPlan(mode, traceSubjectTarget, "", "no_destination"), true
		}
		if evd.targetPort < 1 || evd.targetPort > 65535 {
			return terminalPlan(mode, traceSubjectTarget, "", "no_tcp_port"), true
		}
		d.destKey, d.destHost, d.destIP = canonicalDest(evd.targetAddr)
		d.port = evd.targetPort
	case "http":
		// The frozen target_addr is the monitored URL; host and port are decoded from
		// it (explicit port, else scheme default) so both are immutable evidence.
		host, hport, derr := hostPortFromURL(evd.targetAddr)
		if derr != nil {
			return terminalPlan(mode, traceSubjectTarget, "", "bad_url"), true
		}
		d.destKey, d.destHost, d.destIP = canonicalDest(host)
		d.port = hport
	}
	return d, true
}

// planProxyTrace diagnoses the egress a pinned monitor dialed.
//
// For socks5/http that is the proxy's own listener: the probe path is
// agent→proxy→target, the relay protocols cannot carry a hop-by-hop diagnostic
// through to the target, and a direct trace from the host would measure a path
// the probe never used. There is deliberately no direct-to-target control trace:
// it reads as "the real path" to anyone skimming the report, which is the exact
// misreading this whole feature exists to prevent.
//
// For wireguard it is the peer's physical endpoint. Tracing INSIDE the tunnel is
// not implementable on the current userspace stack (the netstack ping socket
// exposes no TTL control and its IP layer drops Time-Exceeded outright — see
// todos/DIAG-004), so the endpoint path is traced in both cases and
// subject_reason carries which question it answers.
func planProxyTrace(evd traceEvidence) (derivedTrace, bool) {
	switch evd.proxyType {
	case pcfg.ProxyTypeWireGuard:
		host, _, err := net.SplitHostPort(strings.TrimSpace(evd.proxyAddr))
		if err != nil {
			// A bare host is a legitimate endpoint spelling; only an empty one is undiagnosable.
			host = strings.TrimSpace(evd.proxyAddr)
		}
		if host == "" {
			return terminalPlan(pcfg.TraceModeICMP, traceSubjectWGEndpoint, "", reasonProxyUnknown), true
		}
		// The peer endpoint is a UDP listener, so only its ICMP path is traceable —
		// a TCP trace to it would report a closed port on a perfectly healthy tunnel.
		d := derivedTrace{
			mode:          pcfg.TraceModeICMP,
			subjectKind:   traceSubjectWGEndpoint,
			subjectReason: wgSubjectReason(evd.reasonCode),
		}
		d.destKey, d.destHost, d.destIP = canonicalDest(host)
		return d, true
	case pcfg.ProxyTypeSOCKS5, pcfg.ProxyTypeHTTP:
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(evd.proxyAddr))
		if err != nil {
			return terminalPlan(pcfg.TraceModeTCP, traceSubjectProxy, "", reasonProxyUnknown), true
		}
		port, perr := strconv.Atoi(portStr)
		if host == "" || perr != nil || port < 1 || port > 65535 {
			return terminalPlan(pcfg.TraceModeTCP, traceSubjectProxy, "", reasonProxyUnknown), true
		}
		d := derivedTrace{mode: pcfg.TraceModeTCP, subjectKind: traceSubjectProxy, port: port}
		d.destKey, d.destHost, d.destIP = canonicalDest(host)
		return d, true
	}
	// A pin with no recognizable type — an unrecorded egress, or one this build does
	// not know. The fault is real but its path is unnameable, so say so rather than
	// falling back to a direct trace that would describe a path the probe never took.
	return terminalPlan(pcfg.TraceModeTCP, traceSubjectProxy, "", reasonProxyUnknown), true
}

// wgSubjectReason reads the frozen classification to say which question the peer
// trace answers. The 8x family means the probe never made it through the tunnel,
// so the peer's reachability IS the fault; another classified cause means the
// tunnel carried the probe and the target failed beyond it, where this trace is
// the nearest available evidence rather than the fault's own path.
//
// ProbeReasonNone on a FAILING round means the fault carries no classification at
// all — a NAT monitor never produces one (reasonMetricKind excludes nat), and any
// probe can lose its error_class sample. Neither verdict may be asserted then:
// claiming the tunnel worked would be a fabrication in exactly the case where it
// is most likely to be the culprit. The empty reason renders as "undetermined".
func wgSubjectReason(reasonCode int) string {
	switch {
	case reasonCode >= telemetry.ProbeReasonProxyConnect && reasonCode <= telemetry.ProbeReasonProxyConfig:
		return subjectTunnelUnreachable
	case reasonCode == telemetry.ProbeReasonNone:
		return ""
	}
	return subjectTunnelTargetUnreachable
}

// planResolverTrace diagnoses the DNS server a failing lookup used, which answers
// the question the target's own name cannot: is the resolver unreachable, or
// reachable but not answering? The queried name is dialed by nobody, so it has no
// path to trace.
//
// The mode follows the resolver's protocol, because that is the port the probe's
// own traffic used: plain UDP has no TCP port worth probing (ICMP), DoT/DoH/TCP
// each have theirs.
//
// A conclusive rcode (NXDOMAIN/SERVFAIL) still traces the resolver. That is
// intentional: a clean path to a resolver that answers SERVFAIL is itself the
// finding — the network is fine and the DNS service is not.
func planResolverTrace(evd traceEvidence) (derivedTrace, bool) {
	addr := strings.TrimSpace(evd.resolverAddr)
	if addr == "" {
		// No resolver was named: a system-resolver monitor on a platform that cannot
		// report one. Guessing the host's current resolver could name a server this
		// query never used, so the diagnostic reports itself unavailable instead.
		return terminalPlan(pcfg.TraceModeICMP, traceSubjectResolver, "", reasonResolverUnknown), true
	}

	var host string
	var port int
	switch evd.resolverProtocol {
	case "doh":
		var err error
		host, port, err = hostPortFromURL(addr)
		if err != nil {
			return terminalPlan(pcfg.TraceModeTCP, traceSubjectResolver, "", "bad_url"), true
		}
	default:
		var err error
		host, port, err = splitHostPortDefault(addr, resolverDefaultPort(evd.resolverProtocol))
		if err != nil {
			return terminalPlan(pcfg.TraceModeICMP, traceSubjectResolver, "", "no_destination"), true
		}
	}

	// A local stub resolver (systemd-resolved's 127.0.0.53, a container sidecar)
	// has no path: every hop of it is inside this host. Tracing it would return one
	// meaningless hop and imply the network was examined when it was not — the
	// upstream the stub forwards to is invisible from here.
	if isLoopbackHost(host) {
		return terminalPlan(pcfg.TraceModeICMP, traceSubjectResolver, "", reasonResolverLoopback), true
	}

	mode := pcfg.TraceModeICMP
	if evd.resolverProtocol != "" && evd.resolverProtocol != "udp" {
		mode = pcfg.TraceModeTCP
	}
	d := derivedTrace{mode: mode, subjectKind: traceSubjectResolver}
	d.destKey, d.destHost, d.destIP = canonicalDest(host)
	if mode == pcfg.TraceModeTCP {
		d.port = port
	}
	return d, true
}

// resolverDefaultPort is the port a resolver protocol uses when the probe did not
// record one. Mirrors the agent's DNS collector defaults.
func resolverDefaultPort(protocol string) int {
	if protocol == "dot" {
		return 853
	}
	return 53
}

// planSTUNTrace diagnoses the STUN server a NAT probe exchanged with. Unlike DNS,
// that server IS the monitored target — but only the probe knows which port and
// transport it actually used, so the plan is still built from the frozen endpoint
// rather than from target_addr.
func planSTUNTrace(evd traceEvidence) (derivedTrace, bool) {
	addr := strings.TrimSpace(evd.stunAddr)
	if addr == "" {
		return terminalPlan(pcfg.TraceModeICMP, traceSubjectSTUNServer, "", reasonNoSTUNServer), true
	}
	// UDP and DTLS are datagram transports with no connectable TCP port, so their
	// path is traced with ICMP; TCP/TLS trace to the port the probe connected to.
	mode := pcfg.TraceModeICMP
	switch evd.stunTransport {
	case "tcp", "tls":
		mode = pcfg.TraceModeTCP
	}
	host, port, err := splitHostPortDefault(addr, stunDefaultPort(evd.stunTransport))
	if err != nil {
		return terminalPlan(mode, traceSubjectSTUNServer, "", "no_destination"), true
	}
	d := derivedTrace{mode: mode, subjectKind: traceSubjectSTUNServer}
	d.destKey, d.destHost, d.destIP = canonicalDest(host)
	if mode == pcfg.TraceModeTCP {
		d.port = port
	}
	return d, true
}

// stunDefaultPort mirrors the agent's STUN port defaults (RFC 5389/5928): 5349
// for the TLS-wrapped transports, 3478 otherwise.
func stunDefaultPort(transport string) int {
	switch transport {
	case "tls", "dtls":
		return 5349
	}
	return 3478
}

// terminalPlan is a plan that is created in a terminal state and never
// dispatched. The subject is still recorded: "no path diagnostic for the
// resolver" is a different statement from "no path diagnostic for the target",
// and the console renders the difference.
func terminalPlan(mode, subjectKind, subjectReason, reason string) derivedTrace {
	return derivedTrace{
		mode: mode, subjectKind: subjectKind, subjectReason: subjectReason,
		terminal: telemetry.TraceStatusFailed, reason: reason,
	}
}

// splitHostPortDefault splits a "host:port" endpoint, accepting a bare host and
// supplying def for it. An empty host is an error — the caller must not trace a
// destination it cannot name.
func splitHostPortDefault(addr string, def int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		if addr == "" {
			return "", 0, errors.New("no host")
		}
		return addr, def, nil
	}
	if host == "" {
		return "", 0, errors.New("no host")
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port < 1 || port > 65535 {
		port = def
	}
	return host, port, nil
}

// isLoopbackHost reports whether a destination resolves to this host by
// definition — a loopback literal or the loopback name.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// tcpTraceDenialReason classifies why an agent's effective set lacks the TCP
// traceroute permission, using the same stable codes as the agent engine's
// capabilityReason: granted by policy but absent from the supported view is a
// runtime capability gap — the raw socket TCP tracing needs is unavailable
// without Administrator privileges (raw_socket_unavailable); otherwise the
// policy never granted the mode (permission_denied).
func tcpTraceDenialReason(supported, granted permission.Set) string {
	if granted.Has(permission.DiagnosticTracerouteTCP) && !supported.Has(permission.DiagnosticTracerouteTCP) {
		return reasonRawSocketUnavailable
	}
	return reasonPermissionDenied
}

// hostPortFromURL extracts the host and the correct TCP port from an HTTP monitor
// target: an explicit port when present, else 443 for https and 80 for http.
func hostPortFromURL(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0, errors.New("bad url")
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("no host")
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return "", 0, errors.New("bad port")
		}
		return host, n, nil
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return host, 443, nil
	case "http":
		return host, 80, nil
	}
	return "", 0, errors.New("unsupported scheme")
}

// ---- trigger (single-flight create / attach), post-commit ----

// OnSignalConfirmed reacts to one newly-confirmed fault signal (wired onto
// TopicFaultConfirmed, post-commit). When the fault is an eligible network fault
// it single-flights a traceroute report for the detecting agent: if an open
// cohort already exists for the (agent, destination, mode, port) key it attaches
// an active reference and shares that in-flight/final report, otherwise it
// creates a fresh queued report and reference and dispatches it. Non-eligible
// faults are ignored; non-derivable/policy-ineligible inputs produce a terminal
// report with no dispatch.
//
// It reads the signal's FROZEN address and port rather than live probe_tasks, so
// a target edited after the fault is still traced to where the fault actually
// happened.
func (s *Service) OnSignalConfirmed(ctx context.Context, ev fault.SignalEvent) error {
	if !s.diagEnabled(ctx) {
		return nil
	}
	var evd traceEvidence
	var metricKind string
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT COALESCE(probe_kind,''), COALESCE(target_addr,''), target_port, COALESCE(metric_kind,''),
		        reason_code, resolver_addr, resolver_protocol, stun_addr, stun_transport,
		        proxy_id, proxy_type, proxy_addr
		 FROM fault_signals WHERE id=?`, ev.SignalID).
		Scan(&evd.probeKind, &evd.targetAddr, &evd.targetPort, &metricKind,
			&evd.reasonCode, &evd.resolverAddr, &evd.resolverProtocol, &evd.stunAddr, &evd.stunTransport,
			&evd.proxyID, &evd.proxyType, &evd.proxyAddr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !TraceEligibleMetric(evd.probeKind, metricKind) {
		return nil
	}
	d, ok := s.deriveTrace(ctx, ev.AgentID, evd)
	if !ok {
		return nil
	}

	reportID, created, dispatchable, err := s.singleFlight(ctx, ev, d)
	if err != nil {
		return err
	}
	if created {
		// A fresh report is announced on the incident timeline: started when it will
		// execute, completed immediately when it is terminal-at-creation (a
		// non-derivable input or a policy-ineligible agent).
		if d.terminal != "" {
			s.addTraceTimeline(ctx, ev.IncidentID, "diag.completed", reportID)
		} else {
			s.addTraceTimeline(ctx, ev.IncidentID, "diag.started", reportID)
		}
	}
	if dispatchable {
		s.dispatchAgent(ctx, ev.AgentID)
	}
	return nil
}

// openCohortQuery finds the open-cohort report for a plan's key. It MUST match
// idx_trace_singleflight column for column — both the attach and the lost-race
// re-select go through it, and a key narrower than the index would attach a fault
// to a report diagnosing something else.
//
// subject_reason is part of the key because a report stores exactly one, frozen
// at creation: two faults on the same WireGuard peer, one that never crossed the
// tunnel and one that did, would otherwise share a report that tells the second
// incident the first one's opposite conclusion.
const openCohortQuery = `SELECT id FROM trace_reports
	WHERE agent_id=? AND dest_key=? AND mode=? AND port=? AND subject_kind=? AND subject_reason=? AND cohort_open=1`

// singleFlight attaches a reference to the open-cohort report for the plan's key,
// or creates a fresh report (queued, or terminal when the plan is terminal) and
// reference in one transaction. It returns the report id, whether a new report
// was created, and whether the report is dispatchable (a fresh non-terminal one).
func (s *Service) singleFlight(ctx context.Context, ev fault.SignalEvent, d derivedTrace) (reportID string, created, dispatchable bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	now := time.Now().UTC()

	// Terminal-at-creation reports never share a cohort: create a closed-cohort
	// report so the next eligible evidence starts fresh.
	if d.terminal != "" {
		reportID = s.newReportID()
		if err = s.insertReport(ctx, tx, reportID, ev, d, d.terminal, d.reason, 0, now); err != nil {
			return "", false, false, err
		}
		if err = insertRef(ctx, tx, reportID, ev, now); err != nil {
			return "", false, false, err
		}
		if err = tx.Commit(); err != nil {
			return "", false, false, err
		}
		committed = true
		return reportID, true, false, nil
	}

	// Existing open cohort for this key → attach and share. subject_kind is part of
	// the key: the same host traced as a resolver and as a monitored target are two
	// different diagnostics, and sharing one report between them would answer one
	// fault with the other's evidence.
	err = tx.QueryRowContext(ctx, openCohortQuery,
		ev.AgentID, d.destKey, d.mode, d.port, d.subjectKind, d.subjectReason).Scan(&reportID)
	if err == nil {
		if err = insertRef(ctx, tx, reportID, ev, now); err != nil {
			return "", false, false, err
		}
		if err = tx.Commit(); err != nil {
			return "", false, false, err
		}
		committed = true
		return reportID, false, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, false, err
	}

	// No open cohort → create a fresh queued report (cohort_open=1).
	reportID = s.newReportID()
	if err = s.insertReport(ctx, tx, reportID, ev, d, traceStatusQueued, "", 1, now); err != nil {
		// Lost the unique-index race for this open key: re-select the winner and
		// attach to it instead of creating a duplicate open cohort.
		var winner string
		if e2 := tx.QueryRowContext(ctx, openCohortQuery,
			ev.AgentID, d.destKey, d.mode, d.port, d.subjectKind, d.subjectReason).Scan(&winner); e2 == nil {
			if err = insertRef(ctx, tx, winner, ev, now); err != nil {
				return "", false, false, err
			}
			if err = tx.Commit(); err != nil {
				return "", false, false, err
			}
			committed = true
			return winner, false, false, nil
		}
		return "", false, false, err
	}
	if err = insertRef(ctx, tx, reportID, ev, now); err != nil {
		return "", false, false, err
	}
	if err = tx.Commit(); err != nil {
		return "", false, false, err
	}
	committed = true
	return reportID, true, true, nil
}

func (s *Service) newReportID() string { return "trace_" + uuid.NewString() }

// insertReport persists a trace report row (queued/terminal). The deadline is
// exactly requested_at + diag_total_timeout_ms — the only validity bound.
func (s *Service) insertReport(ctx context.Context, tx *sql.Tx, reportID string, ev fault.SignalEvent, d derivedTrace, status, reason string, cohortOpen int, now time.Time) error {
	deadline := now.Add(s.diagTotalTimeout(ctx))
	var completed any
	if !nonterminalTrace(status) {
		completed = now // terminal-at-creation
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO trace_reports(id, site_id, agent_id, agent_name, dest_key, dest_host, dest_ip, mode, port,
			fallback_from, fallback_reason, subject_kind, subject_reason,
			status, reason, max_hops, attempts, timeout_ms, resolve_hops, cohort_open, requested_at, completed_at, deadline_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		reportID, ev.SiteID, ev.AgentID, s.agentName(ctx, ev.AgentID), d.destKey, d.destHost, d.destIP, d.mode, d.port,
		d.fallbackFrom, d.fallbackReason, d.subjectKind, d.subjectReason,
		status, reason, s.diagMaxHops(ctx), s.diagAttempts(ctx), int(s.diagTotalTimeout(ctx).Milliseconds()),
		boolInt(s.diagResolveHops(ctx)), cohortOpen, now, completed, deadline)
	return err
}

// insertRef attaches an active reference from an incident's fault signal to a
// report (idempotent via the composite primary key).
func insertRef(ctx context.Context, tx *sql.Tx, reportID string, ev fault.SignalEvent, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO trace_report_refs(report_id, incident_id, signal_id, active, created_at)
		VALUES(?,?,?,1,?)
		ON CONFLICT(report_id, incident_id, signal_id) DO UPDATE SET active=1`,
		reportID, ev.IncidentID, ev.SignalID, now)
	return err
}

// ---- dispatch (concurrency-bounded, persist-before-dispatch) ----

// dispatchAgent promotes queued in-deadline reports for one agent to running and
// pushes them, bounded by the per-agent and global concurrency limits. Each
// promotion claims capacity atomically (claimNextTrace), so concurrent dispatchers
// can never exceed the bounds. Offline agents keep their reports queued (reverting
// a report that could not be pushed), to be re-pushed on reconnect. Different keys
// thus execute concurrently up to the limits; the regular probe scheduler is never
// involved.
func (s *Service) dispatchAgent(ctx context.Context, agentID string) {
	if s.pusher == nil {
		return
	}
	agentLimit := s.diagAgentConcurrency(ctx)
	globalLimit := s.diagGlobalConcurrency(ctx)
	for {
		reportID, claimed, err := s.claimNextTrace(ctx, agentID, agentLimit, globalLimit)
		if err != nil || !claimed {
			return // error, nothing eligible, or a limit is already reached
		}
		if !s.pushClaimed(ctx, agentID, reportID) {
			return // offline — reverted to queued; stop this agent's dispatch
		}
	}
}

// claimNextTrace atomically promotes the oldest queued, in-deadline report for an
// agent to running, but only while both the global and per-agent running-trace
// limits still have headroom. The capacity counts and the promotion execute in ONE
// write transaction on SQLite's single writer (MaxOpenConns(1)), so two concurrent
// dispatchers — the per-agent rule-eval goroutine, the periodic Tick, and the hub
// reconnect path — can never both observe free capacity and each promote a
// different row past the bound. It returns the promoted report id with
// claimed=true, or claimed=false when nothing is eligible or a limit is reached.
func (s *Service) claimNextTrace(ctx context.Context, agentID string, agentLimit, globalLimit int) (string, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	now := time.Now().UTC()
	var reportID string
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM trace_reports
		WHERE agent_id=? AND status='queued' AND deadline_at > ?
		ORDER BY requested_at LIMIT 1`, agentID, now).Scan(&reportID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	// Promote only if both limits still have headroom. The count subqueries and the
	// update are one statement on the single writer we hold for this tx, so the
	// counts cannot change between check and act. RowsAffected==0 therefore means a
	// limit was reached (the row we just selected as queued cannot have been claimed
	// by anyone else while we hold the write connection).
	res, err := tx.ExecContext(ctx, `
		UPDATE trace_reports SET status='running', started_at=COALESCE(started_at,?)
		WHERE id=? AND status='queued'
		  AND (SELECT COUNT(*) FROM trace_reports WHERE status='running') < ?
		  AND (SELECT COUNT(*) FROM trace_reports WHERE status='running' AND agent_id=?) < ?`,
		now, reportID, globalLimit, agentID, agentLimit)
	if err != nil {
		return "", false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", false, nil // at capacity
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	committed = true
	return reportID, true, nil
}

// pushClaimed builds and pushes a just-promoted report's request to its agent. If
// the agent is offline/vanished — or the report's window expired between the claim
// and the push — the promotion is reverted to queued (so a reconnect re-dispatches
// it, or the deadline sweep times it out) and false is returned to stop this
// agent's dispatch loop.
func (s *Service) pushClaimed(ctx context.Context, agentID, reportID string) bool {
	req, ok := s.buildTraceRequest(ctx, reportID)
	if !ok || !s.pusher.PushTraceRequest(agentID, req) {
		_, _ = s.db.ExecContext(ctx,
			`UPDATE trace_reports SET status='queued', started_at=NULL WHERE id=? AND status='running'`, reportID)
		return false
	}
	return true
}

// buildTraceRequest reads a report into the wire TraceRequest pushed to the agent.
// The validity window travels as the remaining budget at push time rather than
// this server's deadline_at, so clock skew between server and agent cannot expire
// the request on arrival (see config.BudgetWindow). ok is false for a report whose
// window is already spent; the caller leaves it for the trace deadline sweep to
// terminalize instead of pushing a trace the agent can only report as timed out.
func (s *Service) buildTraceRequest(ctx context.Context, reportID string) (pcfg.TraceRequest, bool) {
	var req pcfg.TraceRequest
	var resolve int
	var deadline time.Time
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT id, mode, dest_host, port, max_hops, attempts, timeout_ms, resolve_hops, deadline_at
		FROM trace_reports WHERE id=?`, reportID).
		Scan(&req.ReportID, &req.Mode, &req.DestinationHost, &req.TCPPort, &req.MaxHops, &req.AttemptsPerHop,
			&req.TotalTimeoutMs, &resolve, &deadline)
	if err != nil {
		return pcfg.TraceRequest{}, false
	}
	req.BudgetMs = int(time.Until(deadline).Milliseconds())
	if req.BudgetMs <= 0 {
		return pcfg.TraceRequest{}, false
	}
	req.ResolveHopHostnames = resolve == 1
	return req, true
}

// ---- ingest ----

// IngestTrace persists one agent's terminal traceroute result. It matches by
// report id + authenticated agent id and requires a nonterminal report, validates
// bounded hops/attempts, transactionally replaces the hop rows and writes the
// terminal state, and emits a timeline completion entry for every referencing
// incident. Duplicate, late and wrong-agent results are idempotent no-ops and can
// never attach elsewhere.
func (s *Service) IngestTrace(ctx context.Context, agentID string, res telemetry.TraceResult) error {
	var reportAgent, status string
	var maxHops, attempts int
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT agent_id, status, max_hops, attempts FROM trace_reports WHERE id=?`, res.ReportID).
		Scan(&reportAgent, &status, &maxHops, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if reportAgent != agentID || !nonterminalTrace(status) {
		return nil // wrong agent or already terminal (idempotent)
	}

	final := res.Status
	if !terminalTraceStatus(final) {
		final = telemetry.TraceStatusFailed
	}
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	// Guard the transition again inside the tx so two concurrent results cannot
	// both write (the second sees a terminal status and no-ops).
	res2, err := tx.ExecContext(ctx, `
		UPDATE trace_reports
		SET status=?, reason=?, dest_ip=CASE WHEN ?<>'' THEN ? ELSE dest_ip END,
		    reached=?, reached_ttl=?, started_at=COALESCE(started_at,?), completed_at=?
		WHERE id=? AND status IN('queued','running')`,
		final, res.Reason, res.DestinationIP, res.DestinationIP, boolInt(res.Reached), res.ReachedTTL,
		firstNonZeroTime(res.StartedAt, now), now, res.ReportID)
	if err != nil {
		return err
	}
	if n, _ := res2.RowsAffected(); n == 0 {
		return nil // lost the race; already terminal
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM trace_hops WHERE report_id=?`, res.ReportID); err != nil {
		return err
	}
	if err := insertHops(ctx, tx, res.ReportID, res.Hops, maxHops, attempts); err != nil {
		return err
	}
	if err := s.emitTraceCompletion(ctx, tx, res.ReportID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// terminalTraceStatus reports whether a status is one of the agent's terminal
// result values.
func terminalTraceStatus(status string) bool {
	switch status {
	case telemetry.TraceStatusSucceeded, telemetry.TraceStatusPartial, telemetry.TraceStatusTimedOut,
		telemetry.TraceStatusUnsupported, telemetry.TraceStatusFailed, telemetry.TraceStatusCanceled:
		return true
	}
	return false
}

func firstNonZeroTime(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t
}

// insertHops writes the per-attempt hop rows, clamped to the report's bounded
// max_hops and attempts-per-hop so a malformed oversized result cannot bloat
// storage. RTT is stored in microseconds; a timed-out attempt stores no address.
func insertHops(ctx context.Context, tx *sql.Tx, reportID string, hops []telemetry.TraceHop, maxHops, attempts int) error {
	for _, h := range hops {
		if h.TTL < 1 || h.TTL > maxHops {
			continue
		}
		for i, a := range h.Attempts {
			if i >= attempts {
				break
			}
			var rtt any
			if !a.Timeout && a.RTTMs > 0 {
				rtt = int64(a.RTTMs * 1000)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO trace_hops(report_id, ttl, attempt, addr, hostname, rtt_us, timed_out)
				VALUES(?,?,?,?,?,?,?)`,
				reportID, h.TTL, i, a.ResponderAddr, a.Hostname, rtt, boolInt(a.Timeout)); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitTraceCompletion appends a diag.completed timeline entry to every incident
// that still references the report, inside the ingest transaction.
func (s *Service) emitTraceCompletion(ctx context.Context, tx *sql.Tx, reportID string, now time.Time) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT incident_id FROM trace_report_refs WHERE report_id=?`, reportID)
	if err != nil {
		return err
	}
	var incs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		incs = append(incs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, incidentID := range incs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref) VALUES(?,?,?,?,?,?)`,
			"tl_"+uuid.NewString(), incidentID, now, "diag.completed", "", reportID); err != nil {
			return err
		}
	}
	return nil
}

// addTraceTimeline appends one trace lifecycle timeline entry (best-effort).
func (s *Service) addTraceTimeline(ctx context.Context, incidentID, kind, reportID string) {
	if incidentID == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref) VALUES(?,?,?,?,?,?)`,
		"tl_"+uuid.NewString(), incidentID, time.Now().UTC(), kind, "", reportID)
}

// ---- reference deactivation (post-commit, on fault resolution) ----

// OnSignalResolved deactivates the trace references a fault signal held and
// closes any cohort whose active reference count has fallen to zero. It never
// cancels or deletes a queued/running execution — a closed cohort only means the
// next fault on the same key will create a fresh report. Wired onto
// TopicFaultResolved, post-commit. Idempotent.
func (s *Service) OnSignalResolved(ctx context.Context, signalID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx,
		`UPDATE trace_report_refs SET active=0 WHERE signal_id=? AND active=1`, signalID); err != nil {
		return err
	}
	// Close the cohort of any report this fault referenced that now has zero active
	// references. The execution itself is untouched.
	if _, err := tx.ExecContext(ctx, `
		UPDATE trace_reports SET cohort_open=0
		WHERE cohort_open=1
		  AND id IN (SELECT report_id FROM trace_report_refs WHERE signal_id=?)
		  AND NOT EXISTS(SELECT 1 FROM trace_report_refs r WHERE r.report_id=trace_reports.id AND r.active=1)`,
		signalID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}
