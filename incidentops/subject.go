package incidentops

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// traceEvidence is one fault signal's frozen trigger-time evidence, as far as
// naming its diagnosable destination is concerned. Every field is read from
// fault_signals and nothing here is ever re-read from live config: a target,
// resolver or proxy edited between the fault and this lookup must not be able to
// make an unrelated traceroute report look like this fault's evidence.
type traceEvidence struct {
	probeKind  string
	targetAddr string

	reasonCode int

	resolverAddr     string
	resolverProtocol string
	stunAddr         string
	stunTransport    string

	proxyID   string
	proxyType string
	proxyAddr string
}

// rowScanner is the single-row read surface shared by the read pool and an open
// transaction, so evidence can be looked up on either.
type rowScanner interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// readSignalEvidence loads one fault signal's frozen evidence plus the metric
// kind that breached, for the eligibility test and the destination derivation.
func readSignalEvidence(ctx context.Context, q rowScanner, signalID string) (traceEvidence, string, error) {
	var evd traceEvidence
	var metricKind string
	err := q.QueryRowContext(ctx,
		`SELECT COALESCE(probe_kind,''), COALESCE(target_addr,''), COALESCE(metric_kind,''),
		        reason_code, resolver_addr, resolver_protocol, stun_addr, stun_transport,
		        proxy_id, proxy_type, proxy_addr
		 FROM fault_signals WHERE id=?`, signalID).
		Scan(&evd.probeKind, &evd.targetAddr, &metricKind,
			&evd.reasonCode, &evd.resolverAddr, &evd.resolverProtocol, &evd.stunAddr, &evd.stunTransport,
			&evd.proxyID, &evd.proxyType, &evd.proxyAddr)
	return evd, metricKind, err
}

// signalDestKey names the destination an Agent would have traced for this fault,
// as the canonical key it files reports under.
//
// It deliberately mirrors the Agent's own subject selection rather than reaching
// for the monitored target, because those diverge for every indirect probe: a
// pinned monitor's packets went to the proxy first, a dns monitor's to its
// resolver, a nat monitor's to the STUN endpoint the probe chose. Matching on the
// monitored target would leave a resolver trace attached to nothing while the
// resolver fault it explains waited for evidence that had already arrived.
//
// The two derivations live in two modules and cannot share code, so they share a
// contract instead: same canonical key spelling, same per-kind endpoint choice,
// same tunnel verdict. ok is false for a fault whose destination cannot be named
// from frozen evidence — there is then nothing to match, which is different from
// matching nothing.
func signalDestKey(evd traceEvidence) (string, bool) {
	// An egress pin wins over the probe kind, exactly as it does on the Agent.
	if evd.proxyID != "" {
		return proxyDestKey(evd)
	}
	switch evd.probeKind {
	case "dns":
		return resolverDestKey(evd)
	case "nat":
		return stunDestKey(evd)
	case "icmp", "tcp":
		if evd.targetAddr == "" {
			return "", false
		}
		key, _ := canonicalDest(evd.targetAddr)
		return key, true
	case "http":
		host, _, err := hostPortFromURL(evd.targetAddr)
		if err != nil {
			return "", false
		}
		key, _ := canonicalDest(host)
		return key, true
	}
	return "", false
}

// proxyDestKey names what a pinned monitor's fault was traced toward: the
// in-tunnel destination when the tunnel carried the probe and the target failed
// beyond it, and the peer's own endpoint otherwise (or the relay's listener, for
// socks5/http).
func proxyDestKey(evd traceEvidence) (string, bool) {
	switch evd.proxyType {
	case pcfg.ProxyTypeWireGuard:
		if wgSubjectReason(evd.reasonCode) == telemetry.TraceSubjectTunnelTargetUnreachable {
			if host, ok := innerTraceDest(evd); ok {
				key, _ := canonicalDest(host)
				return key, true
			}
		}
		host, _, err := net.SplitHostPort(strings.TrimSpace(evd.proxyAddr))
		if err != nil {
			host = strings.TrimSpace(evd.proxyAddr)
		}
		if host == "" {
			return "", false
		}
		key, _ := canonicalDest(host)
		return key, true
	case pcfg.ProxyTypeSOCKS5, pcfg.ProxyTypeHTTP:
		host, _, err := net.SplitHostPort(strings.TrimSpace(evd.proxyAddr))
		if err != nil || host == "" {
			return "", false
		}
		key, _ := canonicalDest(host)
		return key, true
	}
	return "", false
}

// wgSubjectReason reads the frozen classification to say which question a
// WireGuard fault's trace answers — see telemetry.TraceSubjectTunnel*. Codes
// 81-84 each describe a real attempt that did not get through the tunnel, so the
// peer's reachability IS the fault; ProxyConfig (85) means the probe never dialed
// at all; ProbeReasonNone means the fault carries no classification and no
// verdict may be asserted.
func wgSubjectReason(reasonCode int) string {
	switch {
	case reasonCode >= telemetry.ProbeReasonProxyConnect && reasonCode <= telemetry.ProbeReasonProxyRefused:
		return telemetry.TraceSubjectTunnelUnreachable
	case reasonCode == telemetry.ProbeReasonProxyConfig:
		return telemetry.TraceSubjectTunnelNotAttempted
	case reasonCode == telemetry.ProbeReasonNone:
		return ""
	}
	return telemetry.TraceSubjectTunnelTargetUnreachable
}

// innerTraceDest derives the in-tunnel destination the failing packets went to,
// mirroring the per-kind subject selection of the direct cases.
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
		return resolverHost(evd)
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

// resolverDestKey names the DNS server a failing lookup used. A local stub
// resolver has no path worth tracing, so an Agent never traces one and there is
// nothing here to match.
func resolverDestKey(evd traceEvidence) (string, bool) {
	host, ok := resolverHost(evd)
	if !ok || isLoopbackHost(host) {
		return "", false
	}
	key, _ := canonicalDest(host)
	return key, true
}

func resolverHost(evd traceEvidence) (string, bool) {
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
}

// stunDestKey names the STUN server a NAT probe exchanged with. That server IS
// the monitored target, but only the probe knew which endpoint it actually used.
func stunDestKey(evd traceEvidence) (string, bool) {
	addr := strings.TrimSpace(evd.stunAddr)
	if addr == "" {
		return "", false
	}
	host, _, err := splitHostPortDefault(addr, stunDefaultPort(evd.stunTransport))
	if err != nil {
		return "", false
	}
	key, _ := canonicalDest(host)
	return key, true
}

// resolverDefaultPort / stunDefaultPort mirror the Agent collectors' defaults, so
// a bare endpoint splits the same way on both sides.
func resolverDefaultPort(protocol string) int {
	if protocol == "dot" {
		return 853
	}
	return 53
}

func stunDefaultPort(transport string) int {
	switch transport {
	case "tls", "dtls":
		return 5349
	}
	return 3478
}

// splitHostPortDefault splits a "host:port" endpoint, accepting a bare host and
// supplying def for it. An empty host is an error — an unnameable destination
// matches nothing rather than matching everything.
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
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostPortFromURL extracts the host and the correct TCP port from an HTTP
// monitor target: an explicit port when present, else 443 for https and 80 for
// http.
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
