package api

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	pcfg "github.com/nettact/protocol/config"
)

// Address validation for monitoring targets.
//
// Every probe kind consumes its target string in one specific shape, and the
// agent has no way to report "you configured a URL where a hostname belongs" —
// it just fails the probe every cycle and classifies the failure generically. A
// target whose SHAPE is wrong can never succeed, so it is a configuration error
// and must be rejected at save time with a message that says what to fix.
//
// The shapes:
//   - http                → an absolute http(s) URL          (validateTarget)
//   - dns                 → a query name                     (bare host)
//   - icmp, tcp           → a host to dial                   (bare host, port is separate)
//   - nat, stun_server2   → a STUN endpoint                  (bare host, optional :port)
//   - dns resolver_server → a resolver endpoint              (bare host, or a URL for DoH)
//   - gateway, host       → server-side anchors, not addresses (exempt)

// hostRule tunes what a bare-host field accepts beyond the common syntax.
type hostRule struct {
	// allowPort accepts a "host:port" suffix. Off for kinds that carry the port
	// in their own param, so "example.com:443" is reported as the mistake it is
	// rather than silently dialed as a hostname containing a colon.
	allowPort bool
}

// maxHostLen / maxLabelLen are the DNS limits (RFC 1035 §2.3.4), measured on the
// name without its optional trailing root dot.
const (
	maxHostLen  = 253
	maxLabelLen = 63
)

// validateBareHost checks a target that must be a hostname or IP literal — never
// a URL. field names the offending input in the returned error ("dns monitor
// target", "stun_server2", …) so a rejected save says exactly what to fix.
//
// It rejects, in order of how likely the mistake is: a URL pasted into a host
// field (the common one — switching a monitor's kind keeps the old target), a
// path/query/fragment, embedded credentials, whitespace, a port where the kind
// has none, non-ASCII (Go's resolver does no IDNA, so a unicode name can only
// fail — the punycode form is what works), then the DNS label syntax itself.
func validateBareHost(field, raw string, rule hostRule) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return errors.New(field + " is required")
	}
	if leadingSchemeRE.MatchString(s) {
		return errors.New(field + " must be a hostname or IP address, not a URL — remove the scheme prefix from " + strconv.Quote(s))
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return errors.New(field + " must not contain spaces: " + strconv.Quote(s))
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		return errors.New(field + " must be a bare hostname or IP address, without a path: " + strconv.Quote(s))
	}
	if strings.Contains(s, "@") {
		return errors.New(field + " must not contain credentials: " + strconv.Quote(s))
	}

	// An unbracketed IPv6 literal is colon-dense; accept it before the colon is
	// read as a port separator.
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Zone() != "" {
			return errors.New(field + " must not carry an IPv6 zone: " + strconv.Quote(s))
		}
		return nil
	}

	host := s
	if strings.Contains(s, ":") {
		if !rule.allowPort {
			return errors.New(field + " must not include a port: " + strconv.Quote(s))
		}
		h, port, err := net.SplitHostPort(s)
		if err != nil || h == "" {
			return errors.New(field + " must be host or host:port: " + strconv.Quote(s))
		}
		// SplitHostPort accepts any port text ("host:abc"), so the numeric check and
		// the range check are both ours — and the message must cover both.
		n, convErr := strconv.Atoi(port)
		if convErr != nil || n < 1 || n > 65535 {
			return errors.New(field + " port must be a number in 1-65535: " + strconv.Quote(s))
		}
		host = h
		// "[::1]:3478" — the bracketed form only appears with a port.
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			if _, err := netip.ParseAddr(host[1 : len(host)-1]); err == nil {
				return nil
			}
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return nil
		}
	}
	return validateHostname(field, host)
}

// Per-kind ProbeParams bounds.
//
// Same principle as the address shapes above: the agent silently clamps nothing
// and reports nothing, so a value it cannot honor (a 100000-echo ping cycle, a
// header value containing CRLF, a 4 GiB body cap) becomes a probe that fails or
// misbehaves every cycle with no diagnosis. Each field is validated ONLY for the
// kind that consumes it, so a param left over from a previous kind — which the
// collector ignores — never blocks an unrelated save.
const (
	maxPacketCount     = 100      // echoes per cycle; beyond this a cycle outlives any sane interval
	maxPacketSize      = 65500    // ICMP payload ceiling (IPv4 datagram limit, minus headers)
	maxTimeoutMs       = 300000   // mirrors the shared timeout_ms bound
	maxKeywordLen      = 512      // body keyword
	maxHeaderCount     = 32       // request headers
	maxHeaderNameLen   = 128      //
	maxHeaderValueLen  = 2048     //
	maxBodyLen         = 64 << 10 // request body
	maxRedirectHops    = 20       // follow limit; <0 means "never follow"
	maxResponseReadCap = 10 << 20 // body bytes the agent may buffer for a keyword match
	// maxSweepSizes bounds a size_sweep payload list. The sweep compares the
	// smallest against the largest size actually sent, so two entries are the
	// minimum meaningful comparison; beyond eight the round-robin sample per size
	// thins out below statistical usefulness.
	maxSweepSizes = 8
	// maxFlowFanout bounds the TCP/HTTP source-port fan-out count. Each pinned port is
	// a separate connect, so an unbounded fan-out would let one target monopolize
	// the agent's probe budget; 32 is already an aggressive ECMP spread.
	maxFlowFanout = 32
)

var (
	validRecordTypes = map[string]bool{"": true, "A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "NS": true}
	// Mirrors the console's method picker. Anything else needs probe.http.extended
	// AND a collector that can send it; an unknown verb just fails the request.
	validHTTPMethods = map[string]bool{"": true, "GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
)

// validateProbeParams enforces the per-kind ProbeParams bounds. p is a pointer so
// enum-ish fields can be normalized (method upper-cased, record type upper-cased)
// before they are stored and pushed.
func validateProbeParams(kind string, p *pcfg.ProbeParams) error {
	switch kind {
	case "icmp", "gateway":
		if p.PacketCount < 0 || p.PacketCount > maxPacketCount {
			return errors.New("packet_count out of range (0-" + strconv.Itoa(maxPacketCount) + ")")
		}
		if p.PacketSize < 0 || p.PacketSize > maxPacketSize {
			return errors.New("packet_size out of range (0-" + strconv.Itoa(maxPacketSize) + ")")
		}
		if p.GlobalTimeoutMs < 0 || p.GlobalTimeoutMs > maxTimeoutMs {
			return errors.New("global_timeout_ms out of range (0-" + strconv.Itoa(maxTimeoutMs) + ")")
		}
		// The sweep compares smallest against largest payload, so a one-entry list
		// would be a comparison with itself; and the agent dials every entry every
		// cycle, so the list is bounded the way packet_count is.
		if len(p.PayloadSizes) > 0 {
			if len(p.PayloadSizes) < 2 || len(p.PayloadSizes) > maxSweepSizes {
				return errors.New("payload_sizes must list 2-" + strconv.Itoa(maxSweepSizes) + " distinct sizes (empty = default sweep)")
			}
			seen := make(map[int]bool, len(p.PayloadSizes))
			for _, sz := range p.PayloadSizes {
				// A sweep entry above the shared ceiling fragments on a 1420-MTU
				// tunnel and manufactures the size-correlated loss the sweep exists
				// to detect (see config.MaxSweepPayloadSize) — the false diagnosis
				// the feature is built to avoid. Duplicates collapse the smallest
				// and largest to one bucket and permanently report a flat sweep.
				if sz < 1 || sz > pcfg.MaxSweepPayloadSize {
					return errors.New("payload_sizes entry out of range (1-" + strconv.Itoa(pcfg.MaxSweepPayloadSize) + ")")
				}
				if seen[sz] {
					return errors.New("payload_sizes must be distinct: " + strconv.Itoa(sz) + " repeats")
				}
				seen[sz] = true
			}
		}
		// A swept cycle sends PingCount echoes per size, so a one-echo-per-size
		// cycle can never clear the classifier's two-echo minimum and would run the
		// sweep's extra probes forever without ever classifying.
		if p.SizeSweep && p.PacketCount == 1 {
			return errors.New("packet_count must be at least 2 when size_sweep is on (one echo per size is not enough evidence to classify)")
		}
		// The effective total (per-size count × sizes) must stay inside the same
		// cycle cap a plain packet_count is held to: per-dimension bounds alone let
		// packet_count=100 × 8 sizes through as an 800-echo cycle.
		if p.SizeSweep && pcfg.PingCount(*p) > maxPacketCount {
			return errors.New("size_sweep cycle exceeds the " + strconv.Itoa(maxPacketCount) + "-echo cap (per-size count × sizes)")
		}
	case "tcp":
		if p.FlowFanout < 0 || p.FlowFanout > maxFlowFanout {
			return errors.New("flow_fanout out of range (0-" + strconv.Itoa(maxFlowFanout) + ")")
		}
	case "nat":
		if p.GlobalTimeoutMs < 0 || p.GlobalTimeoutMs > maxTimeoutMs {
			return errors.New("global_timeout_ms out of range (0-" + strconv.Itoa(maxTimeoutMs) + ")")
		}
	case "dns":
		p.RecordType = strings.ToUpper(strings.TrimSpace(p.RecordType))
		if !validRecordTypes[p.RecordType] {
			return errors.New("invalid record_type: " + p.RecordType + " (A, AAAA, CNAME, MX, TXT or NS)")
		}
		// The resolver endpoint is dialed by the agent, so its shape matters as much
		// as the target's. DoH takes an https URL (the agent also accepts a bare host
		// and builds the /dns-query URL itself); the others take a bare host, with the
		// port carried by resolver_port.
		//
		// The trimmed value is written BACK: the agent uses this string verbatim in
		// url building and net.JoinHostPort, so stored whitespace would fail every
		// probe while the save looked clean.
		if s := strings.TrimSpace(p.ResolverServer); s != "" {
			if p.ResolverProtocol == "doh" && leadingSchemeRE.MatchString(s) {
				u, err := url.Parse(s)
				if err != nil || u.Scheme != "https" || u.Hostname() == "" {
					return errors.New("doh resolver_server must be an https:// URL or a bare host: " + strconv.Quote(s))
				}
				if err := validateURLPort(u, "resolver_server", s); err != nil {
					return err
				}
			} else if err := validateBareHost("resolver_server", s, hostRule{}); err != nil {
				return err
			}
			p.ResolverServer = s
		}
	case "http":
		p.Method = strings.ToUpper(strings.TrimSpace(p.Method))
		if !validHTTPMethods[p.Method] {
			return errors.New("invalid http method: " + p.Method)
		}
		if p.FlowFanout < 0 || p.FlowFanout > maxFlowFanout {
			return errors.New("flow_fanout out of range (0-" + strconv.Itoa(maxFlowFanout) + ")")
		}
		if p.FlowFanout >= 2 && p.Method != "" && p.Method != http.MethodGet && p.Method != http.MethodHead {
			return errors.New("flow_fanout requires GET or HEAD because every branch repeats the HTTP request")
		}
		if p.FlowFanout >= 2 && p.MaxRedirects >= 0 {
			return errors.New("flow_fanout requires max_redirects=-1 so every branch keeps the same destination")
		}
		if utf8.RuneCountInString(p.Keyword) > maxKeywordLen {
			return errors.New("keyword too long (max " + strconv.Itoa(maxKeywordLen) + " characters)")
		}
		if len(p.Body) > maxBodyLen {
			return errors.New("request body too large (max 64 KiB)")
		}
		if p.MaxRedirects < -1 || p.MaxRedirects > maxRedirectHops {
			return errors.New("max_redirects out of range (-1 to " + strconv.Itoa(maxRedirectHops) + "; -1 = never follow)")
		}
		if p.MaxResponseBytes < 0 || p.MaxResponseBytes > maxResponseReadCap {
			return errors.New("max_response_bytes out of range (0-10485760)")
		}
		if err := validateHTTPHeaders(p.Headers); err != nil {
			return err
		}
	}
	return nil
}

// validateHTTPHeaders checks request headers against what Go's transport will
// actually send. A name that is not an RFC 7230 token, or a value carrying CR/LF
// (header injection) or NUL, makes every request fail inside net/http with an
// opaque error — so it is rejected here, where the user can see why.
func validateHTTPHeaders(h map[string]string) error {
	if len(h) > maxHeaderCount {
		return errors.New("too many request headers (max " + strconv.Itoa(maxHeaderCount) + ")")
	}
	for name, value := range h {
		if name == "" {
			return errors.New("request header name must not be empty")
		}
		if len(name) > maxHeaderNameLen {
			return errors.New("request header name too long (max " + strconv.Itoa(maxHeaderNameLen) + "): " + strconv.Quote(name))
		}
		if !validHeaderName(name) {
			return errors.New("invalid request header name: " + strconv.Quote(name))
		}
		if len(value) > maxHeaderValueLen {
			return errors.New("request header value too long (max " + strconv.Itoa(maxHeaderValueLen) + "): " + strconv.Quote(name))
		}
		if !validHeaderValue(value) {
			return errors.New("invalid request header value for " + strconv.Quote(name) + " (control characters are not allowed)")
		}
		// "Host" is not sent as a header: the agent assigns it to req.Host for
		// virtual-host probing. Go does not reject an invalid Host — it silently
		// sends an EMPTY one (verified: "bad host" and "host/path" both arrive as
		// ""), so the probe quietly tests the default vhost forever while the
		// console shows the override the user configured. Hold it to the authority
		// syntax that actually survives.
		if strings.EqualFold(name, "Host") {
			if err := validateBareHost("the Host header", value, hostRule{allowPort: true}); err != nil {
				return err
			}
		}
	}
	return nil
}

// validHeaderName reports whether name is an RFC 7230 token — the same rule
// net/http applies before it will transmit a header. Hand-rolled rather than
// pulling golang.org/x/net/http/httpguts in for one predicate.
func validHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validHeaderValue mirrors net/http's field-value rule: visible ASCII plus SP and
// HTAB. It is what rejects a CR/LF-carrying value (header injection), which the
// transport would otherwise refuse on every single request.
func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < ' ' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// validateURLPort applies the authority rules a parsed http(s)/DoH URL must
// satisfy: no bare trailing colon (an empty optional port would dial a nonsense
// authority) and, when a port is present, one the agent can actually dial.
// url.Parse only guarantees the port is digits, so the range is ours to enforce.
// Tests the SUFFIX rather than "contains a colon" so an IPv6 literal authority
// ("[::1]", "[2001:db8::1]") — which is colon-dense and ends in "]" — passes.
func validateURLPort(u *url.URL, field, raw string) error {
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("invalid port in " + field + ": " + raw)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return errors.New(field + " port out of range (1-65535): " + raw)
		}
	}
	return nil
}

// validateHostname checks DNS name syntax: ASCII letter/digit/hyphen labels
// (underscore tolerated — "_dmarc.example.com" is a real query name and Windows
// LAN names carry them), 1-63 octets each, 253 total, no empty label, no
// leading/trailing hyphen. A single label is fine: "localhost" and "router" are
// legitimate LAN targets.
func validateHostname(field, host string) error {
	name := strings.TrimSuffix(host, ".") // the root dot is legal and not counted
	if name == "" {
		return errors.New(field + " must be a hostname or IP address: " + strconv.Quote(host))
	}
	if len(name) > maxHostLen {
		return errors.New(field + " is too long (max 253 characters)")
	}
	for _, r := range name {
		if r > 127 {
			return errors.New(field + " must be ASCII — use the punycode (xn--) form of " + strconv.Quote(host))
		}
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return errors.New(field + " has an empty label: " + strconv.Quote(host))
		}
		if len(label) > maxLabelLen {
			return errors.New(field + " has a label longer than 63 characters: " + strconv.Quote(host))
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New(field + " has a label starting or ending with '-': " + strconv.Quote(host))
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return errors.New(field + " contains an invalid character " + strconv.Quote(string(c)) + ": " + strconv.Quote(host))
			}
		}
	}
	return nil
}
