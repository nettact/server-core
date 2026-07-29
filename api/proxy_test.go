package api

import (
	"encoding/base64"
	"strings"
	"testing"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/config"
)

// Valid 32-byte Curve25519 key material, base64-encoded — the only shape
// WireGuard's UAPI accepts.
const (
	testWGPrivKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	testWGPubKey  = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	testWGPSK     = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="
)

func relayProxy() config.Proxy {
	return config.Proxy{
		Name: "office", Type: pcfg.ProxyTypeSOCKS5, Enabled: true,
		Host: "proxy.example.com", Port: 1080,
	}
}

func wgProxy() config.Proxy {
	return config.Proxy{
		Name: "tunnel", Type: pcfg.ProxyTypeWireGuard, Enabled: true,
		WGPrivateKey: testWGPrivKey, WGPeerPublicKey: testWGPubKey, WGPresharedKey: testWGPSK,
		WGEndpoint:   "wg.example.com:51820",
		WGAllowedIPs: "10.7.0.0/24", WGLocalAddrs: "10.7.0.2/32",
	}
}

func TestValidateProxyRelay(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*config.Proxy)
		wantErr string // substring; "" ⇒ must pass
	}{
		{name: "valid socks5", edit: func(*config.Proxy) {}},
		{name: "valid http", edit: func(p *config.Proxy) { p.Type = pcfg.ProxyTypeHTTP }},
		{name: "type is normalized", edit: func(p *config.Proxy) { p.Type = " SOCKS5 " }},
		{name: "name required", edit: func(p *config.Proxy) { p.Name = "  " }, wantErr: "proxy name is required"},
		{name: "unknown type", edit: func(p *config.Proxy) { p.Type = "socks4" }, wantErr: "must be socks5, http or wireguard"},
		{name: "host required", edit: func(p *config.Proxy) { p.Host = "" }, wantErr: "required"},
		// A URL in the host field is the likely paste mistake; it can only fail at
		// dial time with an opaque error, so it is named here instead.
		{name: "url in host", edit: func(p *config.Proxy) { p.Host = "socks5://proxy.example.com" }, wantErr: "not a URL"},
		{name: "port in host", edit: func(p *config.Proxy) { p.Host = "proxy.example.com:1080" }, wantErr: "must not include a port"},
		{name: "port zero", edit: func(p *config.Proxy) { p.Port = 0 }, wantErr: "port must be a number in 1-65535"},
		{name: "port too high", edit: func(p *config.Proxy) { p.Port = 70000 }, wantErr: "port must be a number in 1-65535"},
		// Both protocols put the credential on the wire verbatim, so a control
		// character would corrupt the handshake rather than merely fail it.
		{name: "newline in username", edit: func(p *config.Proxy) { p.Username = "a\nb" }, wantErr: "must not contain a newline"},
		{name: "newline in password", edit: func(p *config.Proxy) { p.Username = "u"; p.Password = "a\nb" }, wantErr: "must not contain a newline"},
		// A colon breaks HTTP Basic, which delimits user-id and password with one…
		{name: "colon in http username", edit: func(p *config.Proxy) { p.Type = pcfg.ProxyTypeHTTP; p.Username = "a:b" }, wantErr: "must not contain a colon"},
		// …but SOCKS5 length-prefixes UNAME (RFC 1929), so a tenant-scoped credential
		// like "tenant:user" is valid and must not be refused.
		{name: "colon in socks5 username is valid", edit: func(p *config.Proxy) { p.Username = "tenant:user" }},
		// SOCKS5 only sends the password alongside a username, so a lone password
		// would be silently dropped — leaving the operator believing it is in use.
		{name: "socks5 password without username", edit: func(p *config.Proxy) { p.Password = "p" }, wantErr: "requires a username"},
		// HTTP Basic explicitly permits an empty user-id with a password.
		{name: "http password without username is valid", edit: func(p *config.Proxy) { p.Type = pcfg.ProxyTypeHTTP; p.Password = "p" }},
		{name: "credentials ok", edit: func(p *config.Proxy) { p.Username = "u"; p.Password = "p" }},
		{name: "bad dns mode", edit: func(p *config.Proxy) { p.DNSMode = "proxy" }, wantErr: "dns_mode must be local or remote"},
		{name: "remote dns mode", edit: func(p *config.Proxy) { p.DNSMode = "remote" }},
		{name: "negative connect timeout", edit: func(p *config.Proxy) { p.ConnectTimeoutMs = -1 }, wantErr: "connect_timeout_ms out of range"},
		{name: "huge connect timeout", edit: func(p *config.Proxy) { p.ConnectTimeoutMs = 999999 }, wantErr: "connect_timeout_ms out of range"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := relayProxy()
			c.edit(&p)
			err := validateProxy(&p)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("validateProxy: unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("validateProxy error = %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}

// An unset dns_mode must become the explicit local default, so the stored value
// says what the agent will actually do rather than leaving it implied.
func TestValidateProxyDefaultsDNSModeToLocal(t *testing.T) {
	p := relayProxy()
	if err := validateProxy(&p); err != nil {
		t.Fatal(err)
	}
	if p.DNSMode != pcfg.ProxyDNSLocal {
		t.Fatalf("dns_mode = %q, want %q", p.DNSMode, pcfg.ProxyDNSLocal)
	}
}

// Switching a proxy between shapes must CLEAR the other shape's fields. Leaving a
// stale wg_private_key behind would keep a live secret in the database that no
// code path reads and no UI can remove.
func TestValidateProxyClearsTheOtherShapesFields(t *testing.T) {
	t.Run("relay clears wireguard", func(t *testing.T) {
		p := wgProxy()
		p.Type = pcfg.ProxyTypeSOCKS5
		p.Host, p.Port = "proxy.example.com", 1080
		if err := validateProxy(&p); err != nil {
			t.Fatal(err)
		}
		if p.WGPrivateKey != "" || p.WGPeerPublicKey != "" || p.WGEndpoint != "" ||
			p.WGAllowedIPs != "" || p.WGLocalAddrs != "" || p.WGMTU != 0 {
			t.Fatalf("wireguard fields survived a switch to socks5: %+v", p)
		}
	})
	t.Run("wireguard clears relay", func(t *testing.T) {
		p := wgProxy()
		p.Host, p.Port, p.Username, p.Password = "proxy.example.com", 1080, "u", "p"
		p.ConnectTimeoutMs = 5000
		if err := validateProxy(&p); err != nil {
			t.Fatal(err)
		}
		if p.Host != "" || p.Port != 0 || p.Username != "" || p.Password != "" || p.ConnectTimeoutMs != 0 {
			t.Fatalf("relay fields survived a switch to wireguard: %+v", p)
		}
		// A tunnel resolves in-tunnel; there is no proxy-side DNS to select.
		if p.DNSMode != pcfg.ProxyDNSLocal {
			t.Fatalf("wireguard dns_mode = %q, want local", p.DNSMode)
		}
	})
}

func TestValidateProxyWireGuard(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*config.Proxy)
		wantErr string
	}{
		{name: "valid", edit: func(*config.Proxy) {}},
		{name: "private key required", edit: func(p *config.Proxy) { p.WGPrivateKey = "" }, wantErr: "wg_private_key is required"},
		{name: "peer key required", edit: func(p *config.Proxy) { p.WGPeerPublicKey = "" }, wantErr: "wg_peer_public_key is required"},
		{name: "preshared key optional", edit: func(p *config.Proxy) { p.WGPresharedKey = "" }},
		{name: "preshared key validated when set", edit: func(p *config.Proxy) { p.WGPresharedKey = "not-base64!" }, wantErr: "base64"},
		// A short-but-valid base64 string is the realistic mistake (a truncated
		// copy/paste); wireguard-go would reject it far from the form field.
		{name: "wrong key length", edit: func(p *config.Proxy) { p.WGPrivateKey = "c2hvcnQ=" }, wantErr: "must decode to 32 bytes"},
		{name: "endpoint required", edit: func(p *config.Proxy) { p.WGEndpoint = "" }, wantErr: "wg_endpoint is required"},
		{name: "endpoint needs a port", edit: func(p *config.Proxy) { p.WGEndpoint = "wg.example.com" }, wantErr: "must include the peer port"},
		{name: "endpoint ipv6 with port", edit: func(p *config.Proxy) { p.WGEndpoint = "[2001:db8::1]:51820" }},
		{name: "allowed ips required", edit: func(p *config.Proxy) { p.WGAllowedIPs = "" }, wantErr: "wg_allowed_ips is required"},
		{name: "allowed ips must be cidrs", edit: func(p *config.Proxy) { p.WGAllowedIPs = "10.7.0.1" }, wantErr: "comma-separated list of CIDRs"},
		{name: "local addrs required", edit: func(p *config.Proxy) { p.WGLocalAddrs = "" }, wantErr: "wg_local_addrs is required"},
		{name: "local addrs bare address ok", edit: func(p *config.Proxy) { p.WGLocalAddrs = "10.7.0.2" }},
		{name: "dns optional", edit: func(p *config.Proxy) { p.WGDNS = "" }},
		{name: "dns validated when set", edit: func(p *config.Proxy) { p.WGDNS = "not-an-ip" }, wantErr: "list of IP addresses"},
		{name: "mtu zero means default", edit: func(p *config.Proxy) { p.WGMTU = 0 }},
		{name: "mtu too small", edit: func(p *config.Proxy) { p.WGMTU = 100 }, wantErr: "wg_mtu out of range"},
		{name: "mtu too large", edit: func(p *config.Proxy) { p.WGMTU = 9000 }, wantErr: "wg_mtu out of range"},
		{name: "keepalive negative", edit: func(p *config.Proxy) { p.WGKeepaliveSeconds = -1 }, wantErr: "wg_keepalive_seconds out of range"},
		{name: "keepalive ok", edit: func(p *config.Proxy) { p.WGKeepaliveSeconds = 25 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := wgProxy()
			c.edit(&p)
			err := validateProxy(&p)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("validateProxy: unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("validateProxy error = %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}

// CIDRs are stored masked so the persisted route matches what WireGuard installs;
// addresses keep their prefix because netstack uses it.
func TestValidateProxyNormalizesLists(t *testing.T) {
	p := wgProxy()
	p.WGAllowedIPs = " 10.7.0.5/24 , 192.168.9.0/24 ,"
	p.WGLocalAddrs = "10.7.0.2/32"
	p.WGDNS = " 10.7.0.53 , ::ffff:10.7.0.54 "
	if err := validateProxy(&p); err != nil {
		t.Fatal(err)
	}
	if p.WGAllowedIPs != "10.7.0.0/24,192.168.9.0/24" {
		t.Fatalf("wg_allowed_ips = %q, want masked and comma-joined", p.WGAllowedIPs)
	}
	if p.WGLocalAddrs != "10.7.0.2/32" {
		t.Fatalf("wg_local_addrs = %q", p.WGLocalAddrs)
	}
	// An IPv4-mapped IPv6 literal is unmapped so the stored resolver matches the
	// address family netstack will actually use.
	if p.WGDNS != "10.7.0.53,10.7.0.54" {
		t.Fatalf("wg_dns = %q, want unmapped and comma-joined", p.WGDNS)
	}
}

// Reads must never carry a stored credential, and must still say that one is set.
func TestRedactProxy(t *testing.T) {
	p := config.Proxy{
		Password: "s3cret", WGPrivateKey: "priv", WGPresharedKey: "psk",
		Username: "u", WGPeerPublicKey: "pub",
	}
	got := redactProxy(p)
	for name, v := range map[string]string{
		"password": got.Password, "wg_private_key": got.WGPrivateKey, "wg_preshared_key": got.WGPresharedKey,
	} {
		if v != redactedSecret {
			t.Fatalf("%s = %q, want the redaction placeholder", name, v)
		}
	}
	// A username and a PUBLIC key are not secrets; blanking them would break the
	// edit form (the user would have to retype them on every save).
	if got.Username != "u" || got.WGPeerPublicKey != "pub" {
		t.Fatalf("non-secret fields were redacted: %+v", got)
	}
	// An unset secret stays empty rather than becoming bullets, so the console can
	// tell "no password" from "a password is set".
	empty := redactProxy(config.Proxy{})
	if empty.Password != "" || empty.WGPrivateKey != "" || empty.WGPresharedKey != "" {
		t.Fatalf("unset secrets were replaced with a placeholder: %+v", empty)
	}
}

// The write-only contract: the placeholder coming back means "keep what is
// stored", an empty value means "clear it", and a new value replaces it. Without
// the first rule, saving an edit form fetched from a read would overwrite every
// password with bullet characters.
func TestKeepRedactedSecrets(t *testing.T) {
	stored := config.Proxy{Password: "s3cret", WGPrivateKey: "priv", WGPresharedKey: "psk"}

	t.Run("placeholder keeps the stored value", func(t *testing.T) {
		next := config.Proxy{Password: redactedSecret, WGPrivateKey: redactedSecret, WGPresharedKey: redactedSecret}
		keepRedactedSecrets(&next, stored)
		if next.Password != "s3cret" || next.WGPrivateKey != "priv" || next.WGPresharedKey != "psk" {
			t.Fatalf("placeholders did not resolve to stored values: %+v", next)
		}
	})
	t.Run("empty clears the credential", func(t *testing.T) {
		next := config.Proxy{}
		keepRedactedSecrets(&next, stored)
		if next.Password != "" || next.WGPrivateKey != "" {
			t.Fatalf("empty submission did not clear: %+v", next)
		}
	})
	t.Run("a new value replaces", func(t *testing.T) {
		next := config.Proxy{Password: "rotated"}
		keepRedactedSecrets(&next, stored)
		if next.Password != "rotated" {
			t.Fatalf("password = %q, want the new value", next.Password)
		}
	})
	t.Run("create drops a placeholder", func(t *testing.T) {
		// On create there is nothing to keep, so a placeholder must not be stored as
		// a literal password made of bullet characters.
		next := config.Proxy{Password: redactedSecret, WGPrivateKey: redactedSecret}
		clearRedactedPlaceholders(&next)
		if next.Password != "" || next.WGPrivateKey != "" {
			t.Fatalf("placeholder survived create: %+v", next)
		}
	})
}

// Audit detail must identify the proxy without ever carrying a credential.
func TestProxyAuditDetailCarriesNoSecrets(t *testing.T) {
	relay := relayProxy()
	relay.Username, relay.Password = "u", "s3cret"
	got := proxyAuditDetail(relay)
	if !strings.Contains(got, "proxy.example.com:1080") {
		t.Fatalf("audit detail = %q, want the endpoint", got)
	}
	if strings.Contains(got, "s3cret") || strings.Contains(got, "u") && strings.Contains(got, "u@") {
		t.Fatalf("audit detail leaked a credential: %q", got)
	}

	wg := wgProxy()
	wg.WGPrivateKey = "verysecretkey"
	got = proxyAuditDetail(wg)
	if !strings.Contains(got, "wg.example.com:51820") {
		t.Fatalf("wireguard audit detail = %q, want the peer endpoint", got)
	}
	if strings.Contains(got, "verysecretkey") {
		t.Fatalf("audit detail leaked the private key: %q", got)
	}
}

// RFC 1929 frames ULEN and PLEN in a single byte, so a credential over 255 BYTES can
// never be sent. The rune bound alone let a 300-byte password save cleanly and then
// fail every pinned probe with a config error nothing pointed at.
func TestValidateProxyRejectsOverlongSOCKS5Credentials(t *testing.T) {
	long := strings.Repeat("a", 256)
	// Multi-byte runes: well inside the 512-RUNE bound, well past 255 BYTES.
	multibyte := strings.Repeat("密", 200) // 600 bytes

	t.Run("socks5 username", func(t *testing.T) {
		p := relayProxy()
		p.Username = long
		if err := validateProxy(&p); err == nil || !strings.Contains(err.Error(), "255 bytes") {
			t.Fatalf("error = %v, want the 255-byte limit", err)
		}
	})
	t.Run("socks5 password", func(t *testing.T) {
		p := relayProxy()
		p.Username, p.Password = "u", long
		if err := validateProxy(&p); err == nil || !strings.Contains(err.Error(), "255 bytes") {
			t.Fatalf("error = %v, want the 255-byte limit", err)
		}
	})
	t.Run("socks5 multibyte password counts bytes not runes", func(t *testing.T) {
		p := relayProxy()
		p.Username, p.Password = "u", multibyte
		if err := validateProxy(&p); err == nil || !strings.Contains(err.Error(), "255 bytes") {
			t.Fatalf("error = %v, want the byte limit to catch a rune-legal value", err)
		}
	})
	t.Run("255 bytes is accepted", func(t *testing.T) {
		p := relayProxy()
		p.Username, p.Password = "u", strings.Repeat("a", 255)
		if err := validateProxy(&p); err != nil {
			t.Fatalf("exactly 255 bytes was rejected: %v", err)
		}
	})
	t.Run("http basic has no such limit", func(t *testing.T) {
		// HTTP Basic does not length-prefix the credential, so only the rune sanity
		// bound applies there.
		p := relayProxy()
		p.Type = pcfg.ProxyTypeHTTP
		p.Username, p.Password = "u", long
		if err := validateProxy(&p); err != nil {
			t.Fatalf("an HTTP proxy was held to the SOCKS5 limit: %v", err)
		}
	})
}

// All-zero key material is WireGuard's "no identity" sentinel, not a key: stored, it
// yields a tunnel that never handshakes and reports proxy_connect forever, with nothing
// pointing back at the field.
func TestValidateProxyRejectsAllZeroWireGuardKeys(t *testing.T) {
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))

	t.Run("private key", func(t *testing.T) {
		p := wgProxy()
		p.WGPrivateKey = zero
		if err := validateProxy(&p); err == nil || !strings.Contains(err.Error(), "all zeros") {
			t.Fatalf("error = %v, want the all-zeros rejection", err)
		}
	})
	t.Run("peer public key", func(t *testing.T) {
		p := wgProxy()
		p.WGPeerPublicKey = zero
		if err := validateProxy(&p); err == nil || !strings.Contains(err.Error(), "all zeros") {
			t.Fatalf("error = %v, want the all-zeros rejection", err)
		}
	})
	t.Run("optional preshared key may be all zeros", func(t *testing.T) {
		// A PSK is optional and an all-zero one is indistinguishable from "unset" to
		// WireGuard, so it is not an error the way a required key is.
		p := wgProxy()
		p.WGPresharedKey = zero
		if err := validateProxy(&p); err != nil {
			t.Fatalf("an all-zero PSK was rejected: %v", err)
		}
	})
}
