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
	"github.com/nettact/server-core/eventbus"
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

// Which question a WireGuard fault's trace answers. The verdict comes from the
// frozen reason code, not from the trace itself; together with path_scope it
// tells the operator whether the hops describe the fault's own path or the
// nearest evidence to it.
const (
	// subjectTunnelUnreachable: the probe never got through the tunnel (a proxy_*
	// reason), so the peer's physical reachability IS the fault.
	subjectTunnelUnreachable = "tunnel_unreachable"
	// subjectTunnelTargetUnreachable: the tunnel carried the probe and the TARGET
	// failed beyond it. The fault's own path is the in-tunnel one, so the trace
	// runs INSIDE the tunnel (subject target, path_scope wireguard_inner),
	// pinned to the exact egress generation the evidence froze. Only when the
	// in-tunnel destination cannot be derived from frozen evidence does the
	// peer's physical path stand in as nearest-available evidence, and it must
	// be labelled as exactly that.
	subjectTunnelTargetUnreachable = "tunnel_target_unreachable"
	// subjectTunnelNotAttempted: the tunnel was never used, because the pinned
	// proxy was missing, disabled, unusable for the probe kind or failed to
	// initialize. No packet left the host, so nothing was observed about the
	// tunnel or the target — the peer trace is only a reachability check, and the
	// fault is a configuration problem.
	subjectTunnelNotAttempted = "tunnel_not_attempted"
	// An empty subject reason on a WireGuard plan means none of the above could be
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
	// The result's self-attested execution path (path_scope + egress reference)
	// disagreed with the plan's. The claimed hops describe a path the plan did
	// not ask for, so they are discarded and the report fails with this code
	// instead of rendering them as if they were the planned path.
	reasonAttestationMismatch = "attestation_mismatch"
)

// Which path a trace's probes travel, orthogonal to the subject (who is being
// measured). Local aliases of the wire-shared telemetry.TracePath* values —
// trace_reports.path_scope, the agent's TraceResult attestation and these plans
// must all speak the same vocabulary, so the values are the protocol's own.
const (
	pathScopeDirect     = telemetry.TracePathDirect
	pathScopeWGPhysical = telemetry.TracePathWireGuardPhysical
	pathScopeWGInner    = telemetry.TracePathWireGuardInner
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
	// pathScope says which path the probes travel (pathScope*): the host stack,
	// the host-stack path toward a WireGuard peer's physical endpoint, or
	// hop-by-hop inside the tunnel. For an in-tunnel plan egressID and
	// egressConfigSerial pin the exact proxy generation the fault evidence froze
	// — the agent must match both or fail closed, never a rotated key and never
	// the host stack.
	pathScope          string
	egressID           string
	egressConfigSerial int
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
	// proxyConfigSerial is the pin's config generation at fault time — what an
	// in-tunnel plan pins its egress to, so a proxy rotated between the fault and
	// the diagnostic can never be re-enabled to carry the probes.
	proxyConfigSerial int
}

// deriveTrace resolves the traceroute plan entirely from a condition's frozen
// trigger-time evidence, gating on the detecting agent's effective traceroute
// permission (granted alone for an in-tunnel plan — see the gate below). It
// never reads live probe_tasks or proxies, so a target, resolver or proxy
// edited or deleted between the fault and this derivation can never redirect
// the diagnostic to a different endpoint or port.
//
// The plan answers "what carried this probe", not "what was being monitored" —
// those diverge for every indirect probe:
//
//	pinned to socks5/http  → the PROXY (agent→proxy→target; a direct trace to the
//	                         target measures a path the probe never used, and the
//	                         relay protocols cannot carry a hop-by-hop diagnostic)
//	pinned to wireguard    → INSIDE the tunnel toward the frozen destination when
//	                         the tunnel carried the probe and the target failed
//	                         beyond it; the peer ENDPOINT's physical path when the
//	                         tunnel itself failed, was never attempted, or the
//	                         in-tunnel destination cannot be derived
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

	// An in-tunnel plan is gated on GRANTED, not effective. Its probes never
	// touch the host stack — they are built in userspace and injected into the
	// WireGuard device — so the raw-socket capability that shapes supported (and
	// through it effective) is irrelevant, and demanding it would deny a path
	// the agent can always take. This mirrors the agent engine's own egress
	// gate; a policy that never granted ICMP still terminalizes.
	if d.pathScope == pathScopeWGInner {
		if !granted.Has(permission.DiagnosticTracerouteICMP) {
			d.terminal = telemetry.TraceStatusUnsupported
			d.reason = reasonPermissionDenied
		}
		return d, true
	}
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
	d := derivedTrace{mode: mode, subjectKind: traceSubjectTarget, pathScope: pathScopeDirect}
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
// For wireguard the plan follows the frozen verdict. When the tunnel carried
// the probe and the TARGET failed beyond it, the fault's own path is the
// in-tunnel one, and that is what gets traced: ICMP probes injected inside the
// tunnel toward the frozen destination, pinned to the exact egress generation
// the evidence froze (the agent matches both ID and serial or fails closed —
// never a rotated key, never the host stack). When the tunnel itself failed or
// was never attempted — or, degenerately, the in-tunnel destination cannot be
// derived from the frozen evidence — the peer's physical endpoint is traced
// over the host stack instead, with subject_reason saying which question that
// answers.
func planProxyTrace(evd traceEvidence) (derivedTrace, bool) {
	switch evd.proxyType {
	case pcfg.ProxyTypeWireGuard:
		if wgSubjectReason(evd.reasonCode) == subjectTunnelTargetUnreachable {
			if host, ok := innerTraceDest(evd); ok {
				// The subject is the target itself — path_scope is what marks the hops
				// as in-tunnel ones, so the existing subject vocabulary stays intact.
				d := derivedTrace{
					mode:               pcfg.TraceModeICMP,
					subjectKind:        traceSubjectTarget,
					subjectReason:      subjectTunnelTargetUnreachable,
					pathScope:          pathScopeWGInner,
					egressID:           evd.proxyID,
					egressConfigSerial: evd.proxyConfigSerial,
				}
				d.destKey, d.destHost, d.destIP = canonicalDest(host)
				return d, true
			}
			// No derivable in-tunnel destination: fall through to the physical
			// endpoint trace — coarse, but honestly labelled as the nearest evidence.
		}
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
			pathScope:     pathScopeWGPhysical,
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
		d := derivedTrace{mode: pcfg.TraceModeTCP, subjectKind: traceSubjectProxy, port: port, pathScope: pathScopeDirect}
		d.destKey, d.destHost, d.destIP = canonicalDest(host)
		return d, true
	}
	// A pin with no recognizable type — an unrecorded egress, or one this build does
	// not know. The fault is real but its path is unnameable, so say so rather than
	// falling back to a direct trace that would describe a path the probe never took.
	return terminalPlan(pcfg.TraceModeTCP, traceSubjectProxy, "", reasonProxyUnknown), true
}

// wgSubjectReason reads the frozen classification to say which question a
// WireGuard fault's trace answers.
//
// Codes 81-84 each describe a real attempt that did not get through the tunnel
// (unreachable peer, rejected credentials, a name the far side could not resolve,
// a refused relay), so the peer's reachability IS the fault. ProxyConfig (85) is
// deliberately NOT among them: it means the probe never dialed at all because the
// pinned proxy was absent, disabled, unusable or uninitializable, so no packet
// ever tested the tunnel and calling it unreachable would assert an outage nobody
// observed. Another classified cause means the tunnel carried the probe and the
// target failed beyond it — the fault's own path is the in-tunnel one, which
// planProxyTrace traces from inside the tunnel; only when innerTraceDest cannot
// name that path's destination does the peer trace stand in as the nearest
// available evidence.
//
// ProbeReasonNone on a FAILING round means the fault carries no classification at
// all — a NAT monitor never produces one (reasonMetricKind excludes nat), and any
// probe can lose its error_class sample. No verdict may be asserted then:
// claiming the tunnel worked would be a fabrication in exactly the case where it
// is most likely to be the culprit. The empty reason renders as "undetermined".
func wgSubjectReason(reasonCode int) string {
	switch {
	case reasonCode >= telemetry.ProbeReasonProxyConnect && reasonCode <= telemetry.ProbeReasonProxyRefused:
		return subjectTunnelUnreachable
	case reasonCode == telemetry.ProbeReasonProxyConfig:
		return subjectTunnelNotAttempted
	case reasonCode == telemetry.ProbeReasonNone:
		return ""
	}
	return subjectTunnelTargetUnreachable
}

// innerTraceDest derives the in-tunnel destination for a tunnel_target_unreachable
// fault from frozen evidence alone: the endpoint the probe dialed THROUGH the
// tunnel. It mirrors the per-kind subject selection of the direct planners —
// icmp/tcp dial the target, http its URL's host, dns its resolver, nat its STUN
// server — because that endpoint, not the monitor's nominal name, is where the
// failing packets went. ok=false when the evidence cannot name one (the rare
// degenerate case), which sends planProxyTrace back to the physical peer trace.
func innerTraceDest(evd traceEvidence) (string, bool) {
	switch evd.probeKind {
	case "icmp", "tcp":
		if evd.targetAddr == "" {
			return "", false
		}
		return evd.targetAddr, true
	case "http":
		host, _, err := hostPortFromURL(evd.targetAddr)
		if err != nil {
			return "", false
		}
		return host, true
	case "dns":
		addr := strings.TrimSpace(evd.resolverAddr)
		if addr == "" {
			return "", false
		}
		if evd.resolverProtocol == "doh" {
			host, _, err := hostPortFromURL(addr)
			if err != nil {
				return "", false
			}
			return host, true
		}
		host, _, err := splitHostPortDefault(addr, resolverDefaultPort(evd.resolverProtocol))
		if err != nil {
			return "", false
		}
		return host, true
	case "nat":
		addr := strings.TrimSpace(evd.stunAddr)
		if addr == "" {
			return "", false
		}
		host, _, err := splitHostPortDefault(addr, stunDefaultPort(evd.stunTransport))
		if err != nil {
			return "", false
		}
		return host, true
	}
	return "", false
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
	d := derivedTrace{mode: mode, subjectKind: traceSubjectResolver, pathScope: pathScopeDirect}
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
	d := derivedTrace{mode: mode, subjectKind: traceSubjectSTUNServer, pathScope: pathScopeDirect}
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
// and the console renders the difference. The scope is direct — no probe will
// ever travel, so the honest claim is the zero one.
func terminalPlan(mode, subjectKind, subjectReason, reason string) derivedTrace {
	return derivedTrace{
		mode: mode, subjectKind: subjectKind, subjectReason: subjectReason,
		pathScope: pathScopeDirect,
		terminal:  telemetry.TraceStatusFailed, reason: reason,
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
// cohort already exists for the plan's key (see openCohortQuery) it attaches
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
		        proxy_id, proxy_type, proxy_addr, proxy_config_serial
		 FROM fault_signals WHERE id=?`, ev.SignalID).
		Scan(&evd.probeKind, &evd.targetAddr, &evd.targetPort, &metricKind,
			&evd.reasonCode, &evd.resolverAddr, &evd.resolverProtocol, &evd.stunAddr, &evd.stunTransport,
			&evd.proxyID, &evd.proxyType, &evd.proxyAddr, &evd.proxyConfigSerial)
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
	// INCIDENT-003: this incident may have just attached to a single-flight cohort
	// that is ALREADY terminal (a sibling's trace shared by the same plan key). The
	// incident was confirmed and recomputed before the reference existed, and no
	// further terminal ingest will arrive, so fold the shared evidence in now.
	var status string
	if err := s.db.Read().QueryRowContext(ctx, `SELECT status FROM trace_reports WHERE id=?`, reportID).Scan(&status); err == nil && !nonterminalTrace(status) {
		s.recomputeAfterTerminalTrace(ctx, ev.IncidentID)
	}
	if dispatchable {
		s.dispatchAgent(ctx, ev.AgentID)
	}
	return nil
}

// recomputeAfterTerminalTrace re-reads an incident's attribution after it
// attached to an already-terminal trace cohort, publishing the console-refresh
// events only when the attribution actually changed. Best-effort: a failure here
// leaves the incident at its previous (confirm-time) attribution and is no worse
// than not having the shared trace.
func (s *Service) recomputeAfterTerminalTrace(ctx context.Context, incidentID string) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	changed, siteID, err := fault.RecomputeAttributionTx(ctx, tx, incidentID)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	if err := tx.Commit(); err != nil {
		return
	}
	if changed {
		s.publishAttributionRefresh(ctx, siteID, incidentID)
	}
}

// openCohortQuery finds the open-cohort report for a plan's key. It MUST match
// idx_trace_singleflight column for column — both the attach and the lost-race
// re-select go through it, and a key narrower than the index would attach a fault
// to a report diagnosing something else.
//
// subject_reason is part of the key because a report stores exactly one, frozen
// at creation: two faults on the same WireGuard peer, one that never crossed the
// tunnel and one that did, would otherwise share a report that tells the second
// incident the first one's opposite conclusion. The path columns are part of it
// for the same reason one level down: two WireGuard tunnels can both contain
// 10.0.0.10, and the same in-tunnel address traced through different tunnels —
// or different generations of one tunnel — is a different execution.
const openCohortQuery = `SELECT id FROM trace_reports
	WHERE agent_id=? AND dest_key=? AND mode=? AND port=? AND subject_kind=? AND subject_reason=?
	  AND path_scope=? AND egress_id=? AND egress_config_serial=? AND cohort_open=1`

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
		ev.AgentID, d.destKey, d.mode, d.port, d.subjectKind, d.subjectReason,
		d.pathScope, d.egressID, d.egressConfigSerial).Scan(&reportID)
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
			ev.AgentID, d.destKey, d.mode, d.port, d.subjectKind, d.subjectReason,
			d.pathScope, d.egressID, d.egressConfigSerial).Scan(&winner); e2 == nil {
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
			fallback_from, fallback_reason, subject_kind, subject_reason, path_scope, egress_id, egress_config_serial,
			status, reason, max_hops, attempts, timeout_ms, resolve_hops, cohort_open, requested_at, completed_at, deadline_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		reportID, ev.SiteID, ev.AgentID, s.agentName(ctx, ev.AgentID), d.destKey, d.destHost, d.destIP, d.mode, d.port,
		d.fallbackFrom, d.fallbackReason, d.subjectKind, d.subjectReason, d.pathScope, d.egressID, d.egressConfigSerial,
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
	var pathScope, egressID string
	var egressSerial int
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT id, mode, dest_host, port, max_hops, attempts, timeout_ms, resolve_hops, deadline_at,
		       path_scope, egress_id, egress_config_serial
		FROM trace_reports WHERE id=?`, reportID).
		Scan(&req.ReportID, &req.Mode, &req.DestinationHost, &req.TCPPort, &req.MaxHops, &req.AttemptsPerHop,
			&req.TotalTimeoutMs, &resolve, &deadline, &pathScope, &egressID, &egressSerial)
	if err != nil {
		return pcfg.TraceRequest{}, false
	}
	// Only an in-tunnel plan pins the request to an egress: a wireguard_physical
	// plan is a host-stack trace ABOUT a tunnel, and setting the pin would make
	// the agent run it inside the tunnel instead.
	if pathScope == pathScopeWGInner {
		req.EgressProxyID = egressID
		req.EgressConfigSerial = egressSerial
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
// the result's path attestation against the plan, validates bounded
// hops/attempts, transactionally replaces the hop rows and writes the terminal
// state, and emits a timeline completion entry for every referencing incident.
// Duplicate, late and wrong-agent results are idempotent no-ops and can never
// attach elsewhere. A result whose attestation disagrees with the plan is
// recorded as failed/attestation_mismatch with its claimed status and hops
// discarded — visible, never rendered as if it were the planned path.
func (s *Service) IngestTrace(ctx context.Context, agentID string, res telemetry.TraceResult) error {
	var reportAgent, status, planScope, planEgressID string
	var maxHops, attempts, planEgressSerial int
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT agent_id, status, max_hops, attempts, path_scope, egress_id, egress_config_serial
		 FROM trace_reports WHERE id=?`, res.ReportID).
		Scan(&reportAgent, &status, &maxHops, &attempts, &planScope, &planEgressID, &planEgressSerial)
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
	reason := res.Reason
	if !attestationMatches(planScope, planEgressID, planEgressSerial, res) {
		// The hops describe a path the plan did not ask for — a trace that fell
		// back to the host stack when the tunnel was wanted, or claims a tunnel
		// the plan never named. Nothing the agent asserted about that path can be
		// kept: not the status, not the reached verdict, not the hop list. The
		// agent's own fail-closed results are NOT this case — they attest the
		// planned path and carry their own reason, so they land above as failed
		// with that reason intact.
		final = telemetry.TraceStatusFailed
		reason = reasonAttestationMismatch
		res.Hops = nil
		res.Reached = false
		res.ReachedTTL = 0
		res.DestinationIP = ""
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
		final, reason, res.DestinationIP, res.DestinationIP, boolInt(res.Reached), res.ReachedTTL,
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
	refIncidents, err := s.emitTraceCompletion(ctx, tx, res.ReportID, now)
	if err != nil {
		return err
	}
	// INCIDENT-003 second stage: the trace's reached-point is the strongest
	// attribution evidence, so recompute each referencing incident's attribution
	// in this same tx (the terminal transition above guarantees exactly-once).
	// Only incidents whose attribution actually changed are published after
	// commit, so a trace that confirms the current guess stays quiet.
	var attributed []eventbus.IncidentEvent
	for _, id := range refIncidents {
		changed, siteID, err := fault.RecomputeAttributionTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if changed {
			attributed = append(attributed, eventbus.IncidentEvent{IncidentID: id, SiteID: siteID})
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	for _, ev := range attributed {
		s.publishAttributionRefresh(ctx, ev.SiteID, ev.IncidentID)
	}
	return nil
}

// publishAttributionRefresh lets the console converge after an incident's
// attribution changed. incident.changed refreshes the fault centre AND the open
// incident drawer; target.status.changed refreshes the target-status page, whose
// per-agent FaultRef now carries the same attribution. Both are needed because
// the target-status store only listens to the latter.
func (s *Service) publishAttributionRefresh(ctx context.Context, siteID, incidentID string) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(eventbus.TopicIncidentUpdated, eventbus.IncidentEvent{IncidentID: incidentID, SiteID: siteID})
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT DISTINCT target_id FROM fault_signals WHERE incident_id=? AND state='firing' AND target_id<>''`,
		incidentID)
	if err != nil {
		return
	}
	var targetIDs []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			targetIDs = append(targetIDs, id)
		}
	}
	rows.Close()
	if len(targetIDs) > 0 {
		s.bus.Publish(eventbus.TopicTargetStatusChanged, eventbus.TargetStatusChanged{SiteID: siteID, TargetIDs: targetIDs})
	}
}

// attestationMatches reports whether a result's self-attested execution path is
// the one the plan asked for. An in-tunnel plan demands wireguard_inner plus the
// exact egress generation it pinned — an echo of a different serial means the
// probes ran through a tunnel the evidence never froze. Direct AND
// wireguard_physical plans are both executed on the host stack (physical is a
// host-stack trace ABOUT a tunnel), so they demand a direct attestation — an
// empty PathScope reads as direct, per the wire contract — with empty egress
// fields.
func attestationMatches(planScope, planEgressID string, planEgressSerial int, res telemetry.TraceResult) bool {
	if planScope == pathScopeWGInner {
		return res.PathScope == telemetry.TracePathWireGuardInner &&
			res.EgressProxyID == planEgressID && res.EgressConfigSerial == planEgressSerial
	}
	return (res.PathScope == "" || res.PathScope == telemetry.TracePathDirect) &&
		res.EgressProxyID == "" && res.EgressConfigSerial == 0
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
// that still references the report, inside the ingest transaction, and returns
// those incident ids so the caller can run post-commit work (the second-stage
// attribution recompute) against the same set.
func (s *Service) emitTraceCompletion(ctx context.Context, tx *sql.Tx, reportID string, now time.Time) ([]string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT incident_id FROM trace_report_refs WHERE report_id=?`, reportID)
	if err != nil {
		return nil, err
	}
	var incs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		incs = append(incs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, incidentID := range incs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO incident_timeline(id, incident_id, ts, kind, message, ref) VALUES(?,?,?,?,?,?)`,
			"tl_"+uuid.NewString(), incidentID, now, "diag.completed", "", reportID); err != nil {
			return nil, err
		}
	}
	return incs, nil
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
