package incidentops

import (
	"testing"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
)

// TestPlanTracePicksTheSubjectThatCarriedTheProbe is the table for DIAG-003's
// core decision: a diagnostic must follow the traffic, not the monitor's
// nominal target. Every row states which endpoint the probe actually dialed and
// asserts the plan aims there, in the mode that endpoint can answer.
func TestPlanTracePicksTheSubjectThatCarriedTheProbe(t *testing.T) {
	cases := []struct {
		name        string
		evd         traceEvidence
		wantSubject string
		wantHost    string
		wantMode    string
		wantPort    int
		wantReason  string // subjectReason
		wantScope   string // pathScope; "" asserts direct
		wantEgress  string // egressID; paired with wantSerial on in-tunnel plans
		wantSerial  int
	}{
		// Direct probes keep tracing their own target.
		{
			name:        "icmp monitor traces its target",
			evd:         traceEvidence{probeKind: "icmp", targetAddr: "192.0.2.10"},
			wantSubject: traceSubjectTarget, wantHost: "192.0.2.10", wantMode: pcfg.TraceModeICMP,
		},
		{
			name:        "tcp monitor traces its target on the frozen port",
			evd:         traceEvidence{probeKind: "tcp", targetAddr: "192.0.2.10", targetPort: 443},
			wantSubject: traceSubjectTarget, wantHost: "192.0.2.10", wantMode: pcfg.TraceModeTCP, wantPort: 443,
		},

		// DNS: the queried name is dialed by nobody; the resolver is.
		{
			name: "plain-UDP resolver is traced with ICMP",
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "1.1.1.1:53", resolverProtocol: "udp"},
			wantSubject: traceSubjectResolver, wantHost: "1.1.1.1", wantMode: pcfg.TraceModeICMP,
		},
		{
			name: "DoT resolver is traced with TCP on its own port",
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "dns.example:853", resolverProtocol: "dot"},
			wantSubject: traceSubjectResolver, wantHost: "dns.example", wantMode: pcfg.TraceModeTCP, wantPort: 853,
		},
		{
			name: "DoH resolver URL yields host and port",
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "https://doh.example/dns-query", resolverProtocol: "doh"},
			wantSubject: traceSubjectResolver, wantHost: "doh.example", wantMode: pcfg.TraceModeTCP, wantPort: 443,
		},
		{
			name: "a bracketed IPv6 resolver splits into host and port",
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "[2001:db8::53]:853", resolverProtocol: "dot"},
			wantSubject: traceSubjectResolver, wantHost: "2001:db8::53", wantMode: pcfg.TraceModeTCP, wantPort: 853,
		},
		{
			name: "a bare IPv6 resolver is not mistaken for host:port",
			// net.SplitHostPort rejects it ("too many colons"); the whole string is the
			// host. Splitting on the last colon here would trace 2001:db8: instead.
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "2001:db8::53", resolverProtocol: "udp"},
			wantSubject: traceSubjectResolver, wantHost: "2001:db8::53", wantMode: pcfg.TraceModeICMP,
		},
		{
			name: "a conclusive rcode still traces the resolver",
			// A clean path to a resolver that answers SERVFAIL is itself the finding:
			// the network is fine and the DNS service is not.
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com", reasonCode: telemetry.ProbeReasonDNSServFail,
				resolverAddr: "1.1.1.1:53", resolverProtocol: "udp"},
			wantSubject: traceSubjectResolver, wantHost: "1.1.1.1", wantMode: pcfg.TraceModeICMP,
		},

		// NAT: the STUN server is the target, but only the probe knew its port.
		{
			name: "udp STUN server is traced with ICMP",
			evd: traceEvidence{probeKind: "nat", targetAddr: "stun.example",
				stunAddr: "stun.example:3478", stunTransport: "udp"},
			wantSubject: traceSubjectSTUNServer, wantHost: "stun.example", wantMode: pcfg.TraceModeICMP,
		},
		{
			name: "TLS STUN server is traced with TCP on its own port",
			evd: traceEvidence{probeKind: "nat", targetAddr: "stun.example",
				stunAddr: "stun.example:5349", stunTransport: "tls"},
			wantSubject: traceSubjectSTUNServer, wantHost: "stun.example", wantMode: pcfg.TraceModeTCP, wantPort: 5349,
		},
		{
			name: "a portless STUN endpoint falls back to the transport default",
			evd: traceEvidence{probeKind: "nat", targetAddr: "stun.example",
				stunAddr: "stun.example", stunTransport: "tcp"},
			wantSubject: traceSubjectSTUNServer, wantHost: "stun.example", wantMode: pcfg.TraceModeTCP, wantPort: 3478,
		},

		// An egress pin outranks the probe kind: the packets went to the proxy first.
		{
			name: "socks5-pinned monitor traces the proxy, not the target",
			evd: traceEvidence{probeKind: "tcp", targetAddr: "192.0.2.10", targetPort: 443,
				proxyID: "px_1", proxyType: pcfg.ProxyTypeSOCKS5, proxyAddr: "10.0.0.9:1080"},
			wantSubject: traceSubjectProxy, wantHost: "10.0.0.9", wantMode: pcfg.TraceModeTCP, wantPort: 1080,
		},
		{
			name: "http-pinned DNS monitor traces the proxy, not the resolver",
			// The pin wins over the kind: a dead proxy is why the lookup failed, and the
			// resolver was never reached.
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "1.1.1.1:53", resolverProtocol: "udp",
				proxyID: "px_2", proxyType: pcfg.ProxyTypeHTTP, proxyAddr: "10.0.0.8:8080"},
			wantSubject: traceSubjectProxy, wantHost: "10.0.0.8", wantMode: pcfg.TraceModeTCP, wantPort: 8080,
		},
		{
			name: "a tunnel failure traces the WG peer as the fault's own path",
			evd: traceEvidence{probeKind: "icmp", targetAddr: "10.7.0.5", reasonCode: telemetry.ProbeReasonProxyConnect,
				proxyID: "px_3", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820"},
			wantSubject: traceSubjectWGEndpoint, wantHost: "vpn.example", wantMode: pcfg.TraceModeICMP,
			wantReason: subjectTunnelUnreachable, wantScope: pathScopeWGPhysical,
		},
		{
			name: "a target failure beyond a working tunnel traces INSIDE the tunnel",
			// The tunnel carried the probe, so the fault's own path is the in-tunnel
			// one: subject is the target itself, path_scope marks the hops as
			// in-tunnel, and the plan pins the exact egress generation the fault froze.
			evd: traceEvidence{probeKind: "icmp", targetAddr: "10.7.0.5", reasonCode: telemetry.ProbeReasonTimeout,
				proxyID: "px_3", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820",
				proxyConfigSerial: 7},
			wantSubject: traceSubjectTarget, wantHost: "10.7.0.5", wantMode: pcfg.TraceModeICMP,
			wantReason: subjectTunnelTargetUnreachable, wantScope: pathScopeWGInner,
			wantEgress: "px_3", wantSerial: 7,
		},
		{
			name: "an http fault beyond the tunnel derives its in-tunnel host from the URL",
			evd: traceEvidence{probeKind: "http", targetAddr: "https://app.internal:8443/health",
				reasonCode: telemetry.ProbeReasonTimeout,
				proxyID:    "px_3", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820",
				proxyConfigSerial: 7},
			wantSubject: traceSubjectTarget, wantHost: "app.internal", wantMode: pcfg.TraceModeICMP,
			wantReason: subjectTunnelTargetUnreachable, wantScope: pathScopeWGInner,
			wantEgress: "px_3", wantSerial: 7,
		},
		{
			name: "an underivable in-tunnel destination falls back to the physical peer",
			// The degenerate case: the tunnel worked, but the frozen evidence cannot
			// name what the probe dialed inside it. The peer's physical path is coarse
			// but honest — and it must be labelled as physical, never as in-tunnel.
			evd: traceEvidence{probeKind: "icmp", targetAddr: "", reasonCode: telemetry.ProbeReasonTimeout,
				proxyID: "px_3", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820",
				proxyConfigSerial: 7},
			wantSubject: traceSubjectWGEndpoint, wantHost: "vpn.example", wantMode: pcfg.TraceModeICMP,
			wantReason: subjectTunnelTargetUnreachable, wantScope: pathScopeWGPhysical,
		},
		{
			name: "an unusable proxy pin is not reported as a tunnel outage",
			// ProxyConfig means the probe never dialed: the pin was missing, disabled or
			// uninitializable. Nothing tested the tunnel, so it must not be called down.
			evd: traceEvidence{probeKind: "icmp", targetAddr: "10.7.0.5", reasonCode: telemetry.ProbeReasonProxyConfig,
				proxyID: "px_3", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820"},
			wantSubject: traceSubjectWGEndpoint, wantHost: "vpn.example", wantMode: pcfg.TraceModeICMP,
			wantReason: subjectTunnelNotAttempted, wantScope: pathScopeWGPhysical,
		},
		{
			name: "a rejected relay through the tunnel is a tunnel failure",
			evd: traceEvidence{probeKind: "tcp", targetAddr: "10.7.0.5", targetPort: 443,
				reasonCode: telemetry.ProbeReasonProxyRefused,
				proxyID:    "px_3", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820"},
			wantSubject: traceSubjectWGEndpoint, wantHost: "vpn.example", wantMode: pcfg.TraceModeICMP,
			wantReason: subjectTunnelUnreachable, wantScope: pathScopeWGPhysical,
		},
		{
			name: "an unclassified tunnelled fault asserts neither tunnel verdict",
			// A NAT monitor never carries a reason code (reasonMetricKind excludes nat),
			// so claiming the tunnel worked would be a fabrication in exactly the case
			// where the tunnel is most likely the culprit.
			evd: traceEvidence{probeKind: "nat", targetAddr: "stun.example",
				stunAddr: "stun.example:3478", stunTransport: "udp",
				proxyID: "px_3", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820"},
			wantSubject: traceSubjectWGEndpoint, wantHost: "vpn.example", wantMode: pcfg.TraceModeICMP,
			wantReason: "", wantScope: pathScopeWGPhysical,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := planTrace(c.evd)
			if !ok {
				t.Fatalf("planTrace refused evidence %+v", c.evd)
			}
			if d.terminal != "" {
				t.Fatalf("plan is terminal (%s/%s), want a dispatchable plan", d.terminal, d.reason)
			}
			if d.subjectKind != c.wantSubject || d.destHost != c.wantHost || d.mode != c.wantMode || d.port != c.wantPort {
				t.Fatalf("plan subject=%s host=%s mode=%s port=%d, want %s/%s/%s/%d",
					d.subjectKind, d.destHost, d.mode, d.port, c.wantSubject, c.wantHost, c.wantMode, c.wantPort)
			}
			if d.subjectReason != c.wantReason {
				t.Fatalf("plan subjectReason=%q, want %q", d.subjectReason, c.wantReason)
			}
			wantScope := c.wantScope
			if wantScope == "" {
				wantScope = pathScopeDirect
			}
			if d.pathScope != wantScope {
				t.Fatalf("plan pathScope=%q, want %q", d.pathScope, wantScope)
			}
			if d.egressID != c.wantEgress || d.egressConfigSerial != c.wantSerial {
				t.Fatalf("plan egress=%q/%d, want %q/%d", d.egressID, d.egressConfigSerial, c.wantEgress, c.wantSerial)
			}
		})
	}
}

// TestPlanTraceRefusesUndiagnosableSubjects covers the cases where the subject
// exists but has no traceable address. Each must terminalize with its own code
// and still record the SUBJECT, because "no diagnostic for the resolver" and "no
// diagnostic for the target" are different statements to an operator.
func TestPlanTraceRefusesUndiagnosableSubjects(t *testing.T) {
	cases := []struct {
		name        string
		evd         traceEvidence
		wantSubject string
		wantReason  string
	}{
		{
			name:        "system resolver the agent could not name",
			evd:         traceEvidence{probeKind: "dns", targetAddr: "example.com"},
			wantSubject: traceSubjectResolver, wantReason: reasonResolverUnknown,
		},
		{
			name: "systemd-resolved stub has no path outside this host",
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "127.0.0.53:53", resolverProtocol: "udp"},
			wantSubject: traceSubjectResolver, wantReason: reasonResolverLoopback,
		},
		{
			name: "localhost resolver by name",
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "localhost:53", resolverProtocol: "udp"},
			wantSubject: traceSubjectResolver, wantReason: reasonResolverLoopback,
		},
		{
			name: "IPv6 loopback resolver",
			evd: traceEvidence{probeKind: "dns", targetAddr: "example.com",
				resolverAddr: "[::1]:53", resolverProtocol: "udp"},
			wantSubject: traceSubjectResolver, wantReason: reasonResolverLoopback,
		},
		{
			name: "a pin with no recognizable egress type",
			// Falling back to a direct trace here would describe a path the probe never took.
			evd:         traceEvidence{probeKind: "tcp", targetAddr: "192.0.2.10", targetPort: 443, proxyID: "px_odd"},
			wantSubject: traceSubjectProxy, wantReason: reasonProxyUnknown,
		},
		{
			name: "a proxy with no usable address",
			evd: traceEvidence{probeKind: "tcp", targetAddr: "192.0.2.10", targetPort: 443,
				proxyID: "px_1", proxyType: pcfg.ProxyTypeSOCKS5},
			wantSubject: traceSubjectProxy, wantReason: reasonProxyUnknown,
		},
		{
			name: "a wireguard proxy with no endpoint",
			evd: traceEvidence{probeKind: "icmp", targetAddr: "10.7.0.5",
				proxyID: "px_3", proxyType: pcfg.ProxyTypeWireGuard},
			wantSubject: traceSubjectWGEndpoint, wantReason: reasonProxyUnknown,
		},
		{
			name:        "a NAT fault whose STUN endpoint was never recorded",
			evd:         traceEvidence{probeKind: "nat", targetAddr: "stun.example"},
			wantSubject: traceSubjectSTUNServer, wantReason: reasonNoSTUNServer,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := planTrace(c.evd)
			if !ok {
				t.Fatalf("planTrace refused evidence %+v", c.evd)
			}
			if d.terminal != telemetry.TraceStatusFailed || d.reason != c.wantReason {
				t.Fatalf("plan terminal=%s reason=%s, want failed/%s", d.terminal, d.reason, c.wantReason)
			}
			if d.subjectKind != c.wantSubject {
				t.Fatalf("plan subject=%s, want %s", d.subjectKind, c.wantSubject)
			}
			if d.destHost != "" {
				t.Fatalf("terminal plan carries destination %q, want none", d.destHost)
			}
		})
	}
}

// A resolver trace that needs TCP is subject to the same permission downgrade as
// any other TCP plan — and the downgrade must not change WHAT is diagnosed.
func TestResolverTraceKeepsItsSubjectThroughTheICMPFallback(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a",
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP, permission.DiagnosticTracerouteTCP},
		[]permission.ID{permission.DiagnosticTracerouteICMP})
	seedEvidence(t, db, "sig_1", "dns", "example.com", 0, "probe.dns.ok")
	seedSubjectEvidence(t, db, "sig_1", traceEvidence{resolverAddr: "dns.example:853", resolverProtocol: "dot"})

	svc := New(db, nil, settings.New(db), nil)
	svc.SetPusher(&capturePusher{})
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
	}); err != nil {
		t.Fatalf("on fault confirmed: %v", err)
	}

	var mode, host, subject, from string
	var port int
	if err := db.QueryRowContext(ctx,
		`SELECT mode, dest_host, port, subject_kind, fallback_from FROM trace_reports`).
		Scan(&mode, &host, &port, &subject, &from); err != nil {
		t.Fatalf("read report: %v", err)
	}
	if mode != pcfg.TraceModeICMP || from != pcfg.TraceModeTCP {
		t.Fatalf("report mode=%s fallback_from=%s, want icmp downgraded from tcp", mode, from)
	}
	if subject != traceSubjectResolver || host != "dns.example" || port != 853 {
		t.Fatalf("report subject=%s host=%s port=%d, want resolver/dns.example/853", subject, host, port)
	}
}

// Two faults whose diagnostics land on the same host, mode and port but examine
// DIFFERENT subjects must not share a report: attaching one to the other would
// answer a DNS fault with a ping monitor's evidence.
func TestCohortSeparatesSubjectsOnTheSameDestination(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_2", "sig_2", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_3", "sig_3", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a",
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP})

	// An ICMP monitor of 1.1.1.1, and a DNS monitor that resolves THROUGH 1.1.1.1.
	seedEvidence(t, db, "sig_1", "icmp", "1.1.1.1", 0, "probe.icmp.loss_pct")
	seedEvidence(t, db, "sig_2", "dns", "example.com", 0, "probe.dns.ok")
	seedSubjectEvidence(t, db, "sig_2", traceEvidence{resolverAddr: "1.1.1.1:53", resolverProtocol: "udp"})
	// A second DNS fault on the same resolver DOES share the first one's report.
	seedEvidence(t, db, "sig_3", "dns", "other.example", 0, "probe.dns.ok")
	seedSubjectEvidence(t, db, "sig_3", traceEvidence{resolverAddr: "1.1.1.1:53", resolverProtocol: "udp"})

	svc := New(db, nil, settings.New(db), nil)
	svc.SetPusher(&capturePusher{})
	for _, ev := range []fault.SignalEvent{
		{SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default"},
		{SignalID: "sig_2", IncidentID: "inc_2", AgentID: "agent_a", SiteID: "site_default"},
		{SignalID: "sig_3", IncidentID: "inc_3", AgentID: "agent_a", SiteID: "site_default"},
	} {
		if err := svc.OnSignalConfirmed(ctx, ev); err != nil {
			t.Fatalf("on fault confirmed %s: %v", ev.SignalID, err)
		}
	}

	var reports int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trace_reports`).Scan(&reports); err != nil {
		t.Fatalf("count reports: %v", err)
	}
	if reports != 2 {
		t.Fatalf("created %d reports, want 2 (one per subject, the two resolver faults sharing one)", reports)
	}
	var subjects int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT subject_kind) FROM trace_reports`).Scan(&subjects); err != nil {
		t.Fatalf("count subjects: %v", err)
	}
	if subjects != 2 {
		t.Fatalf("distinct subject kinds = %d, want 2 (target and resolver)", subjects)
	}
	// The resolver report carries both DNS faults' references.
	var refs int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM trace_report_refs r
		JOIN trace_reports t ON t.id = r.report_id
		WHERE t.subject_kind = ?`, traceSubjectResolver).Scan(&refs); err != nil {
		t.Fatalf("count resolver refs: %v", err)
	}
	if refs != 2 {
		t.Fatalf("resolver report has %d references, want 2 shared faults", refs)
	}
}

// Two faults on the SAME WireGuard peer whose evidence says opposite things —
// one never crossed the tunnel, one did — must not share a report. A report
// freezes one subject_reason, so sharing would hand the second incident the
// first one's opposite conclusion.
func TestCohortSeparatesOpposingTunnelVerdicts(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	seedIncidentSignal(t, db, "inc_2", "sig_2", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a",
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP})
	wg := traceEvidence{proxyID: "px_1", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820"}

	seedEvidence(t, db, "sig_1", "icmp", "10.7.0.5", 0, "probe.icmp.loss_pct")
	tunnelDown := wg
	tunnelDown.reasonCode = telemetry.ProbeReasonProxyConnect
	seedSubjectEvidence(t, db, "sig_1", tunnelDown)

	// The target-side fault carries no derivable in-tunnel destination (empty
	// frozen address), so it degenerates to the SAME peer endpoint as sig_1 —
	// which is exactly the collision this test exists to keep apart.
	seedEvidence(t, db, "sig_2", "icmp", "", 0, "probe.icmp.loss_pct")
	targetDown := wg
	targetDown.reasonCode = telemetry.ProbeReasonTimeout
	seedSubjectEvidence(t, db, "sig_2", targetDown)

	svc := New(db, nil, settings.New(db), nil)
	svc.SetPusher(&capturePusher{})
	for _, ev := range []fault.SignalEvent{
		{SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default"},
		{SignalID: "sig_2", IncidentID: "inc_2", AgentID: "agent_a", SiteID: "site_default"},
	} {
		if err := svc.OnSignalConfirmed(ctx, ev); err != nil {
			t.Fatalf("on fault confirmed %s: %v", ev.SignalID, err)
		}
	}

	rows, err := db.QueryContext(ctx, `SELECT subject_reason FROM trace_reports ORDER BY subject_reason`)
	if err != nil {
		t.Fatalf("read reports: %v", err)
	}
	defer rows.Close()
	var reasons []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("scan: %v", err)
		}
		reasons = append(reasons, r)
	}
	if len(reasons) != 2 || reasons[0] != subjectTunnelTargetUnreachable || reasons[1] != subjectTunnelUnreachable {
		t.Fatalf("report reasons = %v, want one of each tunnel verdict in its own report", reasons)
	}
}

// A NAT fault must now produce a diagnostic at all — the eligibility gate used to
// drop dns/nat entirely, leaving those faults with no path evidence.
func TestNATFaultDiagnosesItsSTUNServer(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a",
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP})
	seedEvidence(t, db, "sig_1", "nat", "stun.example", 0, "probe.nat.ok")
	seedSubjectEvidence(t, db, "sig_1", traceEvidence{stunAddr: "stun.example:3478", stunTransport: "udp"})

	svc := New(db, nil, settings.New(db), nil)
	pusher := &capturePusher{}
	svc.SetPusher(pusher)
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
	}); err != nil {
		t.Fatalf("on fault confirmed: %v", err)
	}

	var subject, host, mode string
	if err := db.QueryRowContext(ctx,
		`SELECT subject_kind, dest_host, mode FROM trace_reports`).Scan(&subject, &host, &mode); err != nil {
		t.Fatalf("read report: %v", err)
	}
	if subject != traceSubjectSTUNServer || host != "stun.example" || mode != pcfg.TraceModeICMP {
		t.Fatalf("report subject=%s host=%s mode=%s, want stun_server/stun.example/icmp", subject, host, mode)
	}
	if len(pusher.traces) != 1 {
		t.Fatalf("pushed %d requests, want 1", len(pusher.traces))
	}
}

// The read paths must surface the subject: without it the console renders a
// resolver trace and a target trace identically.
func TestTraceReadsIncludeSubjectFields(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a",
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP})
	seedEvidence(t, db, "sig_1", "icmp", "10.7.0.5", 0, "probe.icmp.loss_pct")
	seedSubjectEvidence(t, db, "sig_1", traceEvidence{
		reasonCode: telemetry.ProbeReasonProxyConnect,
		proxyID:    "px_1", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820",
	})

	svc := New(db, nil, settings.New(db), nil)
	svc.SetPusher(&capturePusher{})
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
	}); err != nil {
		t.Fatalf("on fault confirmed: %v", err)
	}

	sums, err := svc.TracesForIncident(ctx, "inc_1")
	if err != nil || len(sums) != 1 {
		t.Fatalf("TracesForIncident = %+v, err=%v; want exactly one summary", sums, err)
	}
	if sums[0].SubjectKind != traceSubjectWGEndpoint || sums[0].SubjectReason != subjectTunnelUnreachable {
		t.Fatalf("summary subject=%s/%s, want wg_endpoint/tunnel_unreachable",
			sums[0].SubjectKind, sums[0].SubjectReason)
	}
	if sums[0].PathScope != pathScopeWGPhysical || sums[0].EgressID != "" || sums[0].EgressConfigSerial != 0 {
		t.Fatalf("summary path=%s egress=%q/%d, want wireguard_physical with no egress pin",
			sums[0].PathScope, sums[0].EgressID, sums[0].EgressConfigSerial)
	}
	view, _, ok, err := svc.TraceReport(ctx, sums[0].ReportID)
	if err != nil || !ok {
		t.Fatalf("TraceReport ok=%v err=%v", ok, err)
	}
	if view.SubjectKind != traceSubjectWGEndpoint || view.SubjectReason != subjectTunnelUnreachable {
		t.Fatalf("report view subject=%s/%s, want wg_endpoint/tunnel_unreachable",
			view.SubjectKind, view.SubjectReason)
	}
	if view.PathScope != pathScopeWGPhysical || view.EgressID != "" || view.EgressConfigSerial != 0 {
		t.Fatalf("report view path=%s egress=%q/%d, want wireguard_physical with no egress pin",
			view.PathScope, view.EgressID, view.EgressConfigSerial)
	}
}

// A target failure beyond a working tunnel must produce an IN-TUNNEL report end
// to end: the row freezes the frozen target as its own destination with the
// egress generation pinned, and the pushed wire request carries that pin so the
// agent runs the probes inside the tunnel — not toward the peer's public
// endpoint, which DIAG-003 used to trace as the nearest available evidence.
func TestTunnelTargetFaultDispatchesAnInTunnelTrace(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	seedIncidentSignal(t, db, "inc_1", "sig_1", "agent_a", "firing")
	setAgentPerms(t, db, "agent_a",
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP},
		[]permission.ID{permission.DiagnosticTracerouteICMP})
	seedEvidence(t, db, "sig_1", "icmp", "10.7.0.5", 0, "probe.icmp.loss_pct")
	seedSubjectEvidence(t, db, "sig_1", traceEvidence{
		reasonCode: telemetry.ProbeReasonTimeout,
		proxyID:    "px_1", proxyType: pcfg.ProxyTypeWireGuard, proxyAddr: "vpn.example:51820",
		proxyConfigSerial: 7,
	})

	svc := New(db, nil, settings.New(db), nil)
	pusher := &capturePusher{}
	svc.SetPusher(pusher)
	if err := svc.OnSignalConfirmed(ctx, fault.SignalEvent{
		SignalID: "sig_1", IncidentID: "inc_1", AgentID: "agent_a", SiteID: "site_default",
	}); err != nil {
		t.Fatalf("on fault confirmed: %v", err)
	}

	var subject, host, scope, egressID string
	var serial int
	if err := db.QueryRowContext(ctx,
		`SELECT subject_kind, dest_host, path_scope, egress_id, egress_config_serial FROM trace_reports`).
		Scan(&subject, &host, &scope, &egressID, &serial); err != nil {
		t.Fatalf("read report: %v", err)
	}
	if subject != traceSubjectTarget || host != "10.7.0.5" || scope != pathScopeWGInner {
		t.Fatalf("report subject=%s host=%s path=%s, want target/10.7.0.5/wireguard_inner", subject, host, scope)
	}
	if egressID != "px_1" || serial != 7 {
		t.Fatalf("report egress=%q/%d, want the frozen px_1/7", egressID, serial)
	}
	if len(pusher.traces) != 1 {
		t.Fatalf("pushed %d requests, want 1", len(pusher.traces))
	}
	req := pusher.traces[0]
	if req.EgressProxyID != "px_1" || req.EgressConfigSerial != 7 {
		t.Fatalf("wire request egress=%q/%d, want px_1/7", req.EgressProxyID, req.EgressConfigSerial)
	}
	if req.Mode != pcfg.TraceModeICMP || req.DestinationHost != "10.7.0.5" {
		t.Fatalf("wire request mode=%s dest=%s, want icmp/10.7.0.5", req.Mode, req.DestinationHost)
	}
}
