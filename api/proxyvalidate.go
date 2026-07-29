package api

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/config"
)

// Validation for egress proxies.
//
// Same principle as probevalidate.go: the agent clamps nothing and cannot report
// "your proxy config is malformed" — it can only fail to build a dialer and mark
// every pinned monitor as proxy_config. So anything the agent could not honor is
// rejected here, at save time, with a message naming the field to fix.
//
// Each field is validated ONLY for the type that consumes it, so a WireGuard key
// left behind after switching a proxy to SOCKS5 (which the agent ignores) never
// blocks the save.

const (
	maxProxyNameLen = 128
	maxProxyCredLen = 512 // username / password (runes), an overall sanity bound
	// maxSOCKS5CredBytes is RFC 1929's hard limit: ULEN and PLEN are one byte each.
	maxSOCKS5CredBytes  = 255
	maxProxyConnectMs   = 120000 // proxy-handshake budget ceiling
	minWireGuardMTU     = 576    // below the IPv4 minimum reassembly buffer nothing useful fits
	maxWireGuardMTU     = 1500   // a tunnel cannot exceed a standard Ethernet MTU
	maxWGKeepaliveSecs  = 65535  // wireguard-go's own persistent-keepalive ceiling
	maxWGListLen        = 4096   // allowed_ips / local_addrs / dns CSV
	wireGuardKeyRawLen  = 32     // Curve25519 key material, base64-encoded on the wire
	maxProxyListEntries = 64     // CIDRs / addresses per CSV field
)

// validateProxy checks a submitted proxy and normalizes it in place (trimmed
// name/host, lower-cased type and dns_mode, canonical CSV lists), so the value
// stored is exactly the value the agent will dial with. Whitespace matters: the
// agent feeds host into net.JoinHostPort and the wg_* fields into a WireGuard
// UAPI config, where a stray space fails silently at runtime.
func validateProxy(p *config.Proxy) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || utf8.RuneCountInString(p.Name) > maxProxyNameLen {
		return errors.New("proxy name is required (max " + strconv.Itoa(maxProxyNameLen) + ")")
	}
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	if !pcfg.KnownProxyType(p.Type) {
		return errors.New("proxy type must be socks5, http or wireguard")
	}
	switch p.Type {
	case pcfg.ProxyTypeSOCKS5, pcfg.ProxyTypeHTTP:
		return validateRelayProxy(p)
	case pcfg.ProxyTypeWireGuard:
		return validateWireGuardProxy(p)
	}
	return nil
}

// validateRelayProxy checks the socks5/http fields and clears the wg_* family.
//
// Clearing rather than ignoring matters: a proxy switched from wireguard to
// socks5 would otherwise keep a stored private key that no code path reads,
// leaving a live secret in the database with no UI to remove it.
func validateRelayProxy(p *config.Proxy) error {
	p.Host = strings.TrimSpace(p.Host)
	if err := validateBareHost("proxy host", p.Host, hostRule{}); err != nil {
		return err
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("proxy port must be a number in 1-65535")
	}
	if utf8.RuneCountInString(p.Username) > maxProxyCredLen {
		return errors.New("proxy username too long (max " + strconv.Itoa(maxProxyCredLen) + ")")
	}
	if utf8.RuneCountInString(p.Password) > maxProxyCredLen {
		return errors.New("proxy password too long (max " + strconv.Itoa(maxProxyCredLen) + ")")
	}
	// SOCKS5 has a HARD protocol limit the rune bound above does not express: RFC 1929
	// frames ULEN and PLEN in a single byte each. A longer credential saves cleanly and
	// then makes every pinned probe fail, because both the agent and x/net/proxy refuse
	// to send it — so the byte length is checked here, where the message can name the
	// field. HTTP Basic has no such limit and keeps only the rune bound.
	if p.Type == pcfg.ProxyTypeSOCKS5 {
		if len(p.Username) > maxSOCKS5CredBytes {
			return errors.New("socks5 username too long (max " + strconv.Itoa(maxSOCKS5CredBytes) + " bytes; RFC 1929 length is one byte)")
		}
		if len(p.Password) > maxSOCKS5CredBytes {
			return errors.New("socks5 password too long (max " + strconv.Itoa(maxSOCKS5CredBytes) + " bytes; RFC 1929 length is one byte)")
		}
	}
	// Control characters would corrupt either handshake (both put the credential on the
	// wire verbatim), so they are refused for both types.
	if strings.ContainsAny(p.Username, "\r\n\x00") {
		return errors.New("proxy username must not contain a newline or NUL")
	}
	if strings.ContainsAny(p.Password, "\r\n\x00") {
		return errors.New("proxy password must not contain a newline or NUL")
	}
	// The remaining two rules are PROTOCOL-SPECIFIC, and applying either to both types
	// rejected valid configurations:
	//
	//   - A colon breaks HTTP Basic, whose user-id and password are colon-delimited
	//     inside one base64 blob (RFC 7617 forbids a colon in the user-id). SOCKS5
	//     length-prefixes UNAME (RFC 1929), so `tenant:user` is perfectly sendable —
	//     and is a real shape for proxies that scope credentials by tenant.
	//   - SOCKS5 sends the password only alongside a username (x/net/proxy refuses an
	//     empty one outright), so a lone password would be silently dropped. HTTP Basic
	//     explicitly permits an empty user-id with a password.
	switch p.Type {
	case pcfg.ProxyTypeHTTP:
		if strings.Contains(p.Username, ":") {
			return errors.New("http proxy username must not contain a colon (HTTP Basic delimits user and password with one)")
		}
	case pcfg.ProxyTypeSOCKS5:
		if p.Password != "" && p.Username == "" {
			return errors.New("socks5 proxy password requires a username (RFC 1929 sends them together)")
		}
	}
	p.DNSMode = strings.ToLower(strings.TrimSpace(p.DNSMode))
	switch p.DNSMode {
	case "":
		p.DNSMode = pcfg.ProxyDNSLocal
	case pcfg.ProxyDNSLocal, pcfg.ProxyDNSRemote:
	default:
		return errors.New("dns_mode must be local or remote")
	}
	if p.ConnectTimeoutMs < 0 || p.ConnectTimeoutMs > maxProxyConnectMs {
		return errors.New("connect_timeout_ms out of range (0-" + strconv.Itoa(maxProxyConnectMs) + ")")
	}
	p.WGPrivateKey, p.WGPeerPublicKey, p.WGPresharedKey = "", "", ""
	p.WGEndpoint, p.WGAllowedIPs, p.WGLocalAddrs, p.WGDNS = "", "", "", ""
	p.WGMTU, p.WGKeepaliveSeconds = 0, 0
	return nil
}

// validateWireGuardProxy checks the tunnel fields and clears the relay family
// (see validateRelayProxy for why stale fields are cleared, not ignored).
func validateWireGuardProxy(p *config.Proxy) error {
	var err error
	if p.WGPrivateKey, err = validateWGKey("wg_private_key", p.WGPrivateKey, true); err != nil {
		return err
	}
	if p.WGPeerPublicKey, err = validateWGKey("wg_peer_public_key", p.WGPeerPublicKey, true); err != nil {
		return err
	}
	if p.WGPresharedKey, err = validateWGKey("wg_preshared_key", p.WGPresharedKey, false); err != nil {
		return err
	}
	// The endpoint is a host:port the agent sends UDP to, so the port is part of
	// the value rather than a separate field.
	p.WGEndpoint = strings.TrimSpace(p.WGEndpoint)
	if p.WGEndpoint == "" {
		return errors.New("wg_endpoint is required (host:port of the WireGuard peer)")
	}
	if !strings.Contains(p.WGEndpoint, ":") {
		return errors.New("wg_endpoint must include the peer port: " + strconv.Quote(p.WGEndpoint))
	}
	if err := validateBareHost("wg_endpoint", p.WGEndpoint, hostRule{allowPort: true}); err != nil {
		return err
	}
	// allowed_ips decides what the tunnel carries at all: an empty list routes
	// nothing, so every pinned probe would fail with no way to tell why from the
	// agent side.
	if p.WGAllowedIPs, err = validateCIDRList("wg_allowed_ips", p.WGAllowedIPs, true); err != nil {
		return err
	}
	// local_addrs are this peer's in-tunnel addresses. netstack needs at least one
	// or it has no source address to send from.
	if p.WGLocalAddrs, err = validateAddrList("wg_local_addrs", p.WGLocalAddrs, true); err != nil {
		return err
	}
	if p.WGDNS, err = validateAddrList("wg_dns", p.WGDNS, false); err != nil {
		return err
	}
	if p.WGMTU != 0 && (p.WGMTU < minWireGuardMTU || p.WGMTU > maxWireGuardMTU) {
		return errors.New("wg_mtu out of range (" + strconv.Itoa(minWireGuardMTU) + "-" + strconv.Itoa(maxWireGuardMTU) + "; 0 = default)")
	}
	if p.WGKeepaliveSeconds < 0 || p.WGKeepaliveSeconds > maxWGKeepaliveSecs {
		return errors.New("wg_keepalive_seconds out of range (0-" + strconv.Itoa(maxWGKeepaliveSecs) + ")")
	}
	p.Host, p.Port, p.Username, p.Password = "", 0, "", ""
	// A tunnel resolves in-tunnel; there is no proxy-side DNS to choose.
	p.DNSMode = pcfg.ProxyDNSLocal
	p.ConnectTimeoutMs = 0
	return nil
}

// validateWGKey checks a base64 Curve25519 key and returns it trimmed. WireGuard
// keys are exactly 32 raw bytes; anything else is rejected here because
// wireguard-go's UAPI would reject it far away from the form field that produced
// it, and the agent could only report a generic init failure.
func validateWGKey(field, raw string, required bool) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		if required {
			return "", errors.New(field + " is required")
		}
		return "", nil
	}
	// A redacted placeholder must never reach here — the handler substitutes the
	// stored value first — so an un-decodable string is a genuine bad key.
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New(field + " must be base64-encoded WireGuard key material")
	}
	if len(b) != wireGuardKeyRawLen {
		return "", errors.New(field + " must decode to " + strconv.Itoa(wireGuardKeyRawLen) +
			" bytes (got " + strconv.Itoa(len(b)) + ")")
	}
	// All-zero key material is WireGuard's "no identity" sentinel, not a key: wireguard-go
	// reads a zero private key as clearing the device's identity (FromMaybeZeroHex skips
	// clamping, and uapi.go gates on !privateKey.IsZero()), and a zero peer public key
	// identifies nothing. Stored, it yields a tunnel that never completes a handshake and
	// reports proxy_connect on every probe — a failure that looks like a network problem
	// and is nearly impossible to trace back to the field. Reject it here instead.
	if required && allZero(b) {
		return "", errors.New(field + " is all zeros, which WireGuard treats as no key at all")
	}
	return s, nil
}

// allZero reports whether every byte is zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// validateCIDRList checks a comma-separated CIDR list and returns it normalized
// (canonical prefixes, comma-joined, no whitespace).
func validateCIDRList(field, raw string, required bool) (string, error) {
	parts, err := splitProxyList(field, raw, required)
	if err != nil {
		return "", err
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		pfx, perr := netip.ParsePrefix(part)
		if perr != nil {
			return "", errors.New(field + " must be a comma-separated list of CIDRs (e.g. 10.7.0.0/24): " + strconv.Quote(part))
		}
		// Masking normalizes 10.7.0.5/24 to 10.7.0.0/24 so the stored route matches
		// what WireGuard actually installs.
		out = append(out, pfx.Masked().String())
	}
	return strings.Join(out, ","), nil
}

// validateAddrList checks a comma-separated address list and returns it
// normalized. A bare address or an address with a prefix length is accepted (a
// tunnel-local address is conventionally written 10.7.0.2/32); the prefix is
// preserved because netstack uses it.
func validateAddrList(field, raw string, required bool) (string, error) {
	parts, err := splitProxyList(field, raw, required)
	if err != nil {
		return "", err
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if pfx, perr := netip.ParsePrefix(part); perr == nil {
			out = append(out, pfx.String())
			continue
		}
		a, perr := netip.ParseAddr(part)
		if perr != nil {
			return "", errors.New(field + " must be a comma-separated list of IP addresses: " + strconv.Quote(part))
		}
		if a.Zone() != "" {
			return "", errors.New(field + " must not carry an IPv6 zone: " + strconv.Quote(part))
		}
		out = append(out, a.Unmap().String())
	}
	return strings.Join(out, ","), nil
}

// splitProxyList splits and trims a CSV field, enforcing the length/entry caps
// shared by every list field.
func splitProxyList(field, raw string, required bool) ([]string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		if required {
			return nil, errors.New(field + " is required")
		}
		return nil, nil
	}
	if len(s) > maxWGListLen {
		return nil, errors.New(field + " too long (max " + strconv.Itoa(maxWGListLen) + " characters)")
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 && required {
		return nil, errors.New(field + " is required")
	}
	if len(out) > maxProxyListEntries {
		return nil, errors.New(field + " has too many entries (max " + strconv.Itoa(maxProxyListEntries) + ")")
	}
	return out, nil
}
