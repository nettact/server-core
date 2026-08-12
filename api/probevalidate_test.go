package api

import (
	"strings"
	"testing"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/config"
)

// The reported bug: switching a monitor from http to dns keeps the URL as the
// target, which the DNS probe can only fail on forever. Every kind that takes a
// bare host must reject a URL — and say so in a way the user can act on.
func TestValidateTargetRejectsURLInHostKinds(t *testing.T) {
	for _, kind := range []string{"dns", "icmp", "tcp", "nat"} {
		tgt := config.ProbeTarget{Kind: kind, Name: "probe", Target: "https://www.yahoo.co.jp", Enabled: true}
		tgt.Params.Port = 443 // keep tcp's own port rule satisfied
		err := validateTarget(&tgt)
		if err == nil {
			t.Errorf("kind=%s accepted a URL as its target", kind)
			continue
		}
		if !strings.Contains(err.Error(), "not a URL") {
			t.Errorf("kind=%s error = %v, want it to name the URL mistake", kind, err)
		}
	}
}

func TestValidateTargetRejectsProxiedFanout(t *testing.T) {
	// Fan-out pins the agent's LOCAL source port, which a proxied target cannot
	// honor (the proxy owns the target-facing tuple); the collector would silently
	// run single-flow. The combination is a saved no-op, so it is rejected.
	tgt := config.ProbeTarget{Kind: "tcp", Name: "probe", Target: "1.1.1.1", ProxyID: "prx_socks", Enabled: true}
	tgt.Params.Port = 443
	tgt.Params.FlowFanout = 8
	err := validateTarget(&tgt)
	if err == nil || !strings.Contains(err.Error(), "flow_fanout requires a direct target") {
		t.Fatalf("proxied fan-out = %v, want rejection naming the direct-target requirement", err)
	}
	// Same target without the proxy: fan-out is fine.
	tgt.ProxyID = ""
	if err := validateTarget(&tgt); err != nil {
		t.Fatalf("direct fan-out rejected: %v", err)
	}
	// And a proxied single-flow target stays fine.
	tgt.ProxyID = "prx_socks"
	tgt.Params.FlowFanout = 0
	if err := validateTarget(&tgt); err != nil {
		t.Fatalf("proxied single-flow rejected: %v", err)
	}
}

func TestValidateBareHost(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		rule    hostRule
		wantErr string // substring; "" = must be accepted
	}{
		// Accepted shapes.
		{name: "fqdn", in: "www.yahoo.co.jp"},
		{name: "trailing root dot", in: "example.com."},
		{name: "single label", in: "localhost"},
		{name: "lan name with underscore", in: "my_nas.local"},
		{name: "underscore query name", in: "_dmarc.example.com"},
		{name: "ipv4 literal", in: "1.1.1.1"},
		{name: "ipv6 literal", in: "2001:db8::1"},
		{name: "hyphen inside a label", in: "my-host.example.com"},
		{name: "digit-only label", in: "123.example.com"},

		// The mistakes that used to be accepted and then failed forever.
		{name: "https url", in: "https://www.yahoo.co.jp", wantErr: "not a URL"},
		{name: "http url", in: "http://example.com", wantErr: "not a URL"},
		{name: "scheme only", in: "ftp://example.com", wantErr: "not a URL"},
		{name: "path", in: "example.com/health", wantErr: "without a path"},
		{name: "query", in: "example.com?a=1", wantErr: "without a path"},
		{name: "credentials", in: "user@example.com", wantErr: "credentials"},
		{name: "space", in: "example .com", wantErr: "spaces"},
		{name: "port when not allowed", in: "example.com:443", wantErr: "must not include a port"},
		{name: "empty label", in: "example..com", wantErr: "empty label"},
		{name: "leading dot", in: ".example.com", wantErr: "empty label"},
		{name: "leading hyphen label", in: "-bad.example.com", wantErr: "'-'"},
		{name: "trailing hyphen label", in: "bad-.example.com", wantErr: "'-'"},
		{name: "invalid character", in: "exa mple.com", wantErr: "spaces"},
		{name: "asterisk", in: "*.example.com", wantErr: "invalid character"},
		{name: "unicode name", in: "中文.com", wantErr: "punycode"},
		{name: "label too long", in: strings.Repeat("a", 64) + ".com", wantErr: "63"},
		{name: "name too long", in: strings.Repeat("a.", 130) + "com", wantErr: "too long"},
		{name: "empty", in: "  ", wantErr: "required"},

		// host:port — accepted only where the kind has no separate port field.
		{name: "host port allowed", in: "stun.example.com:3478", rule: hostRule{allowPort: true}},
		{name: "ipv6 with port allowed", in: "[2001:db8::1]:3478", rule: hostRule{allowPort: true}},
		{name: "port out of range", in: "stun.example.com:70000", rule: hostRule{allowPort: true}, wantErr: "1-65535"},
		{name: "non-numeric port", in: "stun.example.com:abc", rule: hostRule{allowPort: true}, wantErr: "must be a number"},
		{name: "double colon garbage", in: "host:3478:extra", rule: hostRule{allowPort: true}, wantErr: "host or host:port"},
		{name: "url even when port allowed", in: "https://stun.example.com", rule: hostRule{allowPort: true}, wantErr: "not a URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateBareHost("target", c.in, c.rule)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("validateBareHost(%q) = %v, want accepted", c.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateBareHost(%q) accepted, want error containing %q", c.in, c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("validateBareHost(%q) = %v, want error containing %q", c.in, err, c.wantErr)
			}
		})
	}
}

func TestValidateProbeParams(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		params  pcfg.ProbeParams
		wantErr string
	}{
		// ICMP cycle shape.
		{name: "icmp defaults", kind: "icmp"},
		{name: "icmp sane cycle", kind: "icmp", params: pcfg.ProbeParams{PacketCount: 5, PacketSize: 56, GlobalTimeoutMs: 5000}},
		{name: "icmp packet_count too high", kind: "icmp", params: pcfg.ProbeParams{PacketCount: 100000}, wantErr: "packet_count"},
		{name: "icmp negative count", kind: "icmp", params: pcfg.ProbeParams{PacketCount: -1}, wantErr: "packet_count"},
		{name: "icmp packet_size too big", kind: "icmp", params: pcfg.ProbeParams{PacketSize: 70000}, wantErr: "packet_size"},
		{name: "icmp global timeout too long", kind: "icmp", params: pcfg.ProbeParams{GlobalTimeoutMs: 999999}, wantErr: "global_timeout_ms"},

		// DEGRADE-001: the size sweep compares smallest against largest payload, so a
		// one-entry list is a comparison with itself; an empty list is the default
		// sweep and stays valid. Sizes are capped at the shared MTU-safe ceiling
		// (config.MaxSweepPayloadSize) and must be distinct.
		{name: "icmp size sweep ok", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true, PayloadSizes: []int{64, 1232}}},
		{name: "icmp size sweep default", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true}},
		{name: "icmp single size rejected", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true, PayloadSizes: []int{1232}}, wantErr: "payload_sizes must list 2-8"},
		{name: "icmp too many sizes", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true, PayloadSizes: []int{64, 128, 256, 384, 512, 640, 768, 896, 1024}}, wantErr: "payload_sizes must list 2-8"},
		{name: "icmp size zero rejected", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true, PayloadSizes: []int{0, 1232}}, wantErr: "payload_sizes entry out of range"},
		{name: "icmp size above MTU ceiling rejected", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true, PayloadSizes: []int{64, 1400}}, wantErr: "payload_sizes entry out of range"},
		{name: "icmp duplicate sizes rejected", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true, PayloadSizes: []int{64, 64}}, wantErr: "payload_sizes must be distinct"},
		{name: "icmp one-echo sweep rejected", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true, PacketCount: 1}, wantErr: "packet_count must be at least 2"},
		{name: "icmp swept cycle over echo cap rejected", kind: "icmp", params: pcfg.ProbeParams{SizeSweep: true, PacketCount: 100, PayloadSizes: []int{64, 128, 256, 384, 512, 640, 768, 896}}, wantErr: "echo cap"},
		{name: "gateway size sweep ok", kind: "gateway", params: pcfg.ProbeParams{SizeSweep: true, PayloadSizes: []int{64, 1232}}},

		// DEGRADE-002: the source-port fan-out is a per-cycle connect budget, so it
		// is bounded; 0 = off.
		{name: "tcp fanout off", kind: "tcp"},
		{name: "tcp fanout ok", kind: "tcp", params: pcfg.ProbeParams{FlowFanout: 6}},
		{name: "tcp fanout at bound", kind: "tcp", params: pcfg.ProbeParams{FlowFanout: 32}},
		{name: "tcp fanout too high", kind: "tcp", params: pcfg.ProbeParams{FlowFanout: 33}, wantErr: "flow_fanout out of range (0-32)"},
		{name: "tcp fanout negative", kind: "tcp", params: pcfg.ProbeParams{FlowFanout: -1}, wantErr: "flow_fanout out of range (0-32)"},

		// DNS record type + resolver endpoint.
		{name: "dns default record", kind: "dns"},
		{name: "dns valid record", kind: "dns", params: pcfg.ProbeParams{RecordType: "MX"}},
		{name: "dns bogus record", kind: "dns", params: pcfg.ProbeParams{RecordType: "SRV"}, wantErr: "record_type"},
		{name: "dns resolver host", kind: "dns", params: pcfg.ProbeParams{ResolverServer: "1.1.1.1"}},
		{name: "dns resolver url rejected", kind: "dns", params: pcfg.ProbeParams{ResolverServer: "https://cloudflare-dns.com/dns-query"}, wantErr: "not a URL"},
		{name: "doh resolver url accepted", kind: "dns", params: pcfg.ProbeParams{ResolverProtocol: "doh", ResolverServer: "https://cloudflare-dns.com/dns-query"}},
		{name: "doh bare host accepted", kind: "dns", params: pcfg.ProbeParams{ResolverProtocol: "doh", ResolverServer: "cloudflare-dns.com"}},
		{name: "doh http url rejected", kind: "dns", params: pcfg.ProbeParams{ResolverProtocol: "doh", ResolverServer: "http://cloudflare-dns.com/dns-query"}, wantErr: "https://"},
		{name: "doh url port out of range", kind: "dns", params: pcfg.ProbeParams{ResolverProtocol: "doh", ResolverServer: "https://resolver.example:70000/dns-query"}, wantErr: "port out of range"},
		{name: "doh url with valid port", kind: "dns", params: pcfg.ProbeParams{ResolverProtocol: "doh", ResolverServer: "https://resolver.example:8443/dns-query"}},

		// The agent uses these strings verbatim (URL building / net.JoinHostPort), so
		// stored whitespace would fail every probe while the save looked clean.
		{name: "resolver_server is trimmed", kind: "dns", params: pcfg.ProbeParams{ResolverServer: "  1.1.1.1  "}},

		// Host is assigned to req.Host for virtual-host probing, and Go silently
		// sends an EMPTY Host rather than erroring on a bad one — so it must hold to
		// authority syntax or the override is dropped without a trace.
		{name: "host header valid", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"Host": "vhost.example.com"}}},
		{name: "host header with port", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"Host": "vhost.example.com:8443"}}},
		{name: "host header with space", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"Host": "bad host"}}, wantErr: "the Host header"},
		{name: "host header with path", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"host": "host/path"}}, wantErr: "the Host header"},
		{name: "host header as url", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"Host": "https://vhost.example.com"}}, wantErr: "not a URL"},

		// HTTP request shape.
		{name: "http defaults", kind: "http"},
		{name: "http valid method", kind: "http", params: pcfg.ProbeParams{Method: "POST"}},
		{name: "http bogus method", kind: "http", params: pcfg.ProbeParams{Method: "FETCH"}, wantErr: "method"},
		{name: "http redirects ok", kind: "http", params: pcfg.ProbeParams{MaxRedirects: 5}},
		{name: "http redirects disabled", kind: "http", params: pcfg.ProbeParams{MaxRedirects: -1}},
		{name: "http redirects absurd", kind: "http", params: pcfg.ProbeParams{MaxRedirects: 1000}, wantErr: "max_redirects"},
		{name: "http read cap absurd", kind: "http", params: pcfg.ProbeParams{MaxResponseBytes: 1 << 30}, wantErr: "max_response_bytes"},
		{name: "http keyword too long", kind: "http", params: pcfg.ProbeParams{Keyword: strings.Repeat("k", 600)}, wantErr: "keyword"},
		{name: "http body too large", kind: "http", params: pcfg.ProbeParams{Body: strings.Repeat("b", 70000)}, wantErr: "body"},
		{name: "http header ok", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"X-Api-Key": "abc"}}},
		{name: "http header crlf injection", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"X-Api-Key": "a\r\nX-Evil: 1"}}, wantErr: "invalid request header value"},
		{name: "http header bad name", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"X Api Key": "abc"}}, wantErr: "invalid request header name"},
		{name: "http header empty name", kind: "http", params: pcfg.ProbeParams{Headers: map[string]string{"": "abc"}}, wantErr: "must not be empty"},

		// A param belonging to another kind is ignored, not rejected: the collector
		// never reads it, so a leftover must not block an unrelated save.
		{name: "stale http method on a dns monitor", kind: "dns", params: pcfg.ProbeParams{Method: "FETCH"}},
		{name: "stale packet count on an http monitor", kind: "http", params: pcfg.ProbeParams{PacketCount: 100000}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.params
			err := validateProbeParams(c.kind, &p)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("validateProbeParams(%s, %+v) = %v, want accepted", c.kind, c.params, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateProbeParams(%s) accepted, want error containing %q", c.kind, c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("validateProbeParams(%s) = %v, want error containing %q", c.kind, err, c.wantErr)
			}
		})
	}
}

// Enum-ish params are normalized so the stored value is the one the agent
// compares against (its switch statements are case-sensitive).
func TestValidateProbeParamsNormalizesEnums(t *testing.T) {
	p := pcfg.ProbeParams{Method: " post "}
	if err := validateProbeParams("http", &p); err != nil {
		t.Fatal(err)
	}
	if p.Method != "POST" {
		t.Fatalf("method = %q, want POST", p.Method)
	}
	d := pcfg.ProbeParams{RecordType: "aaaa"}
	if err := validateProbeParams("dns", &d); err != nil {
		t.Fatal(err)
	}
	if d.RecordType != "AAAA" {
		t.Fatalf("record_type = %q, want AAAA", d.RecordType)
	}
	// The trimmed endpoint must be written BACK, not just validated locally: the
	// agent uses the stored string verbatim.
	r := pcfg.ProbeParams{ResolverServer: "  1.1.1.1\t"}
	if err := validateProbeParams("dns", &r); err != nil {
		t.Fatal(err)
	}
	if r.ResolverServer != "1.1.1.1" {
		t.Fatalf("resolver_server = %q, want the trimmed value", r.ResolverServer)
	}
}

// stun_server2 takes the same verbatim path into net.JoinHostPort, so its stored
// value must be trimmed too.
func TestValidateTargetTrimsSTUNServer2(t *testing.T) {
	tgt := config.ProbeTarget{Kind: "nat", Name: "NAT", Target: "stun.example.com", Enabled: true}
	tgt.Params.STUNServer2 = "  stun2.example.com:3478  "
	if err := validateTarget(&tgt); err != nil {
		t.Fatal(err)
	}
	if tgt.Params.STUNServer2 != "stun2.example.com:3478" {
		t.Fatalf("stun_server2 = %q, want the trimmed value", tgt.Params.STUNServer2)
	}
}

// A gateway monitor has no user-entered address and a host anchor's target is a
// series subject ("host", "*", a mount like "C:"), so neither may be run through
// the bare-host rules.
func TestValidateTargetExemptsAnchorKinds(t *testing.T) {
	gw := config.ProbeTarget{Kind: "gateway", Name: "GW", Enabled: true}
	if err := validateTarget(&gw); err != nil {
		t.Fatalf("gateway: %v", err)
	}
	if gw.Target != "gateway" {
		t.Fatalf("gateway target = %q, want the normalized \"gateway\"", gw.Target)
	}
	for _, subject := range []string{"host", "*", "C:", "/mnt/data"} {
		h := config.ProbeTarget{Kind: "host", Name: "Host", Target: subject, Enabled: true}
		if err := validateTarget(&h); err != nil {
			t.Fatalf("host anchor %q: %v", subject, err)
		}
	}
}
