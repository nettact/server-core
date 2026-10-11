// Package asnlookup maps an IPv4 address to the autonomous system that
// announces it, from an offline table loaded into memory.
//
// # Why offline, and why in the server
//
// Route history turns every traceroute hop into an AS number so that a run can
// be compressed into an AS path and compared with the last one. Two other
// placements were rejected. Resolving on the agent would put a ~10 MB table on
// routers that have a few MB to spare, and would have to be redone anyway the
// day the table is corrected. Resolving online (a whois / DNS-based lookup per
// hop) would send every hop of every user's route to a third party, and would
// put a network round trip inside the ingest write transaction. A sorted range
// table answers in microseconds from memory, so the lookup runs synchronously
// in that transaction and the stored path always describes one table version.
//
// # What this package does and does not own
//
// It owns the mechanism: the Resolver contract, an in-memory range table, and
// a parser for the public-domain iptoasn.com "ip2asn-v4" TSV. Fetching,
// caching, verifying and refreshing the file is the host's job — a host may
// read it from a local path, download it periodically, or bundle it — and the
// table it builds is handed to the consumers through a Holder, which can be
// swapped at runtime without the consumers noticing.
//
// A nil or empty Resolver is a supported state, not an error: every lookup
// misses, AS paths come out empty, and route history keeps recording IP-level
// paths without ever reporting an AS-level change.
package asnlookup

import (
	"net/netip"
	"sync/atomic"
)

// Info is what the table knows about the range an address falls in.
type Info struct {
	ASN     uint32
	Name    string // the AS description as published (organisation / network name)
	Country string // ISO 3166 alpha-2 of the AS registration; may be empty
	// Prefix is the matched range, rendered as the smallest CIDR covering it
	// when the range is exactly one CIDR block and as "first-last" otherwise.
	// It is what lets a reader see a hop move to a different block of the same
	// AS (a different POP or a renumbered access network).
	Prefix string
}

// Resolver is the lookup contract consumers depend on.
type Resolver interface {
	// Lookup returns the AS announcing addr. It reports false for anything
	// that has no meaningful public origin: private, CGNAT (100.64/10),
	// loopback, link-local, multicast and other reserved space, an address no
	// range covers, and ranges the table marks as not routed (ASN 0). IPv6 is
	// not covered by this table and always misses.
	Lookup(addr netip.Addr) (Info, bool)
	// Version names the data the answers come from. It is stored beside each
	// resolved address so a mapping can be traced back to the table that
	// produced it when the table is later corrected. Empty when no table is
	// loaded.
	Version() string
}

// IsPublicIPv4 reports whether addr is a globally routable unicast IPv4
// address — the space an AS lookup can say anything about. It is exported
// because route history uses the same definition to find the first public hop
// of a path (the local egress), which must agree with what Lookup refuses.
func IsPublicIPv4(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() || addr.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range reservedV4 {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// reservedV4 is the special-purpose space netip's predicates do not already
// cover (RFC 6890 and successors). CGNAT shared space is the one that matters
// most in practice: a home router behind carrier NAT shows 100.64/10 hops that
// belong to the ISP but are announced by nobody.
var reservedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// Holder is a Resolver whose underlying table can be replaced at any time.
//
// Why a holder rather than handing consumers the table directly: the table is
// refreshed while the server runs (a weekly download, a file the operator
// replaces), and the consumers — ingest and the console API — are wired once
// at startup. Threading a "current table" callback through each of them would
// make every consumer re-implement the same swap; a holder makes the swap one
// atomic store that every consumer observes on its next lookup. The zero value
// is ready to use and resolves nothing.
type Holder struct {
	cur atomic.Pointer[resolverBox]
}

// resolverBox exists because atomic.Pointer needs a concrete type and the
// interface value has to be stored as a unit (type and data together).
type resolverBox struct{ r Resolver }

// NewHolder returns a holder serving r (which may be nil).
func NewHolder(r Resolver) *Holder {
	h := &Holder{}
	h.Store(r)
	return h
}

// Store replaces the served resolver. nil clears it.
func (h *Holder) Store(r Resolver) {
	h.cur.Store(&resolverBox{r: r})
}

// Current returns the served resolver, or nil.
func (h *Holder) Current() Resolver {
	if h == nil {
		return nil
	}
	if b := h.cur.Load(); b != nil {
		return b.r
	}
	return nil
}

// Lookup implements Resolver.
func (h *Holder) Lookup(addr netip.Addr) (Info, bool) {
	r := h.Current()
	if r == nil {
		return Info{}, false
	}
	return r.Lookup(addr)
}

// Version implements Resolver.
func (h *Holder) Version() string {
	r := h.Current()
	if r == nil {
		return ""
	}
	return r.Version()
}
