package api

import (
	"testing"

	"github.com/nettact/server-core/config"
)

// An HTTP monitor's URL must reach the agent with a scheme: Go's HTTP client
// rejects a scheme-less URL outright, so the probe would fail every cycle with a
// generic "other" error and never recover.
func TestValidateTargetHTTPURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string // expected normalized target ("" ⇒ expect an error)
		wantErr bool
	}{
		{name: "scheme-less host normalizes to https", in: "www.yahoo.co.jp", want: "https://www.yahoo.co.jp"},
		{name: "scheme-less host:port normalizes", in: "example.com:8080", want: "https://example.com:8080"},
		{name: "scheme-less with path normalizes", in: "example.com/health", want: "https://example.com/health"},
		{name: "surrounding space is trimmed then normalized", in: "  example.com  ", want: "https://example.com"},
		{name: "https is preserved verbatim", in: "https://example.com/x?y=1", want: "https://example.com/x?y=1"},
		{name: "plain http is preserved", in: "http://192.168.1.5:9000/", want: "http://192.168.1.5:9000/"},
		{name: "non-http scheme rejected", in: "ftp://example.com", wantErr: true},

		// An opaque scheme (":" without "//") must be rejected outright: prefixing it
		// with https:// yields a URL that parses, with the scheme swallowed as
		// userinfo, so the monitor would silently probe a host the user never named
		// ("https://mailto:user@example.com" resolves to host "example.com").
		{name: "mailto scheme rejected", in: "mailto:user@example.com", wantErr: true},
		{name: "ssh scheme rejected", in: "ssh:user@host", wantErr: true},
		// …but a scheme-less "host:port" must NOT be mistaken for one.
		{name: "host port is not an opaque scheme", in: "example.com:8080", want: "https://example.com:8080"},
		{name: "host port with path", in: "example.com:8080/health", want: "https://example.com:8080/health"},
		{name: "malformed scheme without host rejected", in: "http:/example.com", wantErr: true},
		{name: "scheme with no host rejected", in: "https://", wantErr: true},
		{name: "bare trailing colon rejected", in: "https://example.com:/x", wantErr: true},

		// An embedded absolute URL is not a leading scheme: the target itself is
		// still scheme-less and must be normalized, not mistaken for schemed.
		{name: "embedded url in query still normalizes", in: "example.com/login?next=https://idp.example", want: "https://example.com/login?next=https://idp.example"},
		{name: "embedded url in path still normalizes", in: "example.com/r/http://x", want: "https://example.com/r/http://x"},

		// IPv6 literals are colon-dense authorities; the port check must not ban them.
		{name: "ipv6 literal without port", in: "https://[::1]/", want: "https://[::1]/"},
		{name: "ipv6 literal with path", in: "https://[2001:db8::1]/health", want: "https://[2001:db8::1]/health"},
		{name: "ipv6 literal with port", in: "https://[2001:db8::1]:8443/", want: "https://[2001:db8::1]:8443/"},
		{name: "scheme-less ipv6 literal normalizes", in: "[2001:db8::1]:8443", want: "https://[2001:db8::1]:8443"},

		// url.Parse only checks that a port is digits — the range is ours to enforce.
		{name: "in-range port accepted", in: "https://example.com:65535/", want: "https://example.com:65535/"},
		{name: "out-of-range port rejected", in: "https://example.com:70000/", wantErr: true},
		{name: "zero port rejected", in: "https://example.com:0/", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := config.ProbeTarget{Kind: "http", Name: "probe", Target: c.in, Enabled: true}
			err := validateTarget(&tgt)
			if c.wantErr {
				if err == nil {
					t.Fatalf("validateTarget(%q) = nil error, want rejection (target became %q)", c.in, tgt.Target)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateTarget(%q): %v", c.in, err)
			}
			if tgt.Target != c.want {
				t.Fatalf("validateTarget(%q) normalized to %q, want %q", c.in, tgt.Target, c.want)
			}
		})
	}
}

// Only HTTP monitors carry a URL: a hostname target of another kind must not grow
// a scheme.
func TestValidateTargetLeavesNonHTTPKindsAlone(t *testing.T) {
	for _, kind := range []string{"dns", "tcp", "icmp"} {
		tgt := config.ProbeTarget{Kind: kind, Name: "probe", Target: "www.yahoo.co.jp", Enabled: true}
		if kind == "tcp" {
			tgt.Params.Port = 443
		}
		if err := validateTarget(&tgt); err != nil {
			t.Fatalf("validateTarget(kind=%s): %v", kind, err)
		}
		if tgt.Target != "www.yahoo.co.jp" {
			t.Fatalf("kind=%s target rewritten to %q", kind, tgt.Target)
		}
	}
}
