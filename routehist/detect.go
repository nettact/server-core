package routehist

// The pure decision functions of route change detection, kept free of storage
// so the rules can be read — and tested — on their own.

// ConfirmRuns is how many consecutive runs must agree on the same new AS path
// before it is recorded as a route change. One or two disagreeing runs are
// the normal texture of the internet (a route flapping during maintenance, a
// load balancer briefly steering one sweep elsewhere) and confirming on them
// would bury the real changes in noise; three runs at the default ten-minute
// cadence is half an hour of a new route, which is a change worth knowing about.
const ConfirmRuns = 3

// Change kinds (route_changes.kind).
const (
	KindRoute       = "route"
	KindDestination = "destination"
	KindLocalEgress = "local_egress"
)

// Change segments (route_changes.segment): where along the path the old and
// new routes part ways, which is what answers "is it my side or theirs".
const (
	SegmentLocalAccess = "local_access"
	SegmentISPBackbone = "isp_backbone"
	SegmentInterconn   = "interconnect"
	SegmentDestination = "destination"
	SegmentUnknown     = "unknown"
)

// pathShape is what comparisons need of a path: its AS path and whether the
// destination answered.
type pathShape struct {
	as      []uint32
	reached bool
}

func equalAS(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isPrefix(p, of []uint32) bool {
	return len(p) <= len(of) && equalAS(p, of[:len(p)])
}

func commonPrefix(a, b []uint32) int {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return i
}

// consistent reports whether two observations can be the same route.
//
// Equal AS paths always are. Beyond that, an observation whose destination
// never answered only saw a PREFIX of the route — the sweep ran out of TTL,
// the destination filters probes, or the tail timed out — so it is consistent
// with any route it is a prefix of. That is applied in both directions,
// because the reference may be the partial one: an era first seen from a
// sweep that stopped short must not read the first complete sweep as a new
// route. A complete (reached) observation is never a prefix of anything but
// itself: if it is shorter, the route really did get shorter.
//
// An empty AS path carries no AS-level information at all — nothing public
// answered, or no lookup table was loaded when it was recorded — so it is
// consistent with everything. Without this, a lookup table that went missing
// would make every run read as a new, AS-less route and confirm a "change"
// that is only the absence of data.
func consistent(a, b pathShape) bool {
	if equalAS(a.as, b.as) || len(a.as) == 0 || len(b.as) == 0 {
		return true
	}
	if !a.reached && isPrefix(a.as, b.as) {
		return true
	}
	if !b.reached && isPrefix(b.as, a.as) {
		return true
	}
	return false
}

// refines reports whether observation x, consistent with reference ref, says
// more about the route than ref does — it saw further, or it reached the
// destination ref never did — so the era's representative path should become
// x's. Representative paths therefore only ever grow toward the full route.
func refines(x, ref pathShape) bool {
	if len(x.as) > len(ref.as) {
		return true
	}
	return x.reached && !ref.reached && len(x.as) == len(ref.as)
}

// endpointFacts are the per-era facts the change classification needs beyond
// the AS path.
type endpointFacts struct {
	destIP      string
	localASN    uint32 // 0 = unknown
	localPrefix string
}

// classifyChange derives a confirmed change's kind and segment, and the index
// of the first AS where the routes diverge (len of the common prefix).
//
// Kind, in the order the rules are tried:
//   - destination: the destination address moved (DNS steering, a CDN node
//     swap) and the AS paths agree on everything before the destination's own
//     AS — the route to the network did not change, the endpoint did;
//   - local_egress: the first public hop's AS or prefix changed — a second
//     WAN line, a failover link, a new access network — so the change starts
//     on this side before any route decision upstream is involved;
//   - route: anything else; a real path change somewhere upstream.
//
// Segment, from where the AS paths part:
//   - unknown: either path has no AS at all (no lookup table, or nothing
//     public answered), so there is nothing to locate the change against;
//   - local_access: they differ from the very first AS (the local ISP side);
//   - destination: they agree up to the destination's AS and differ only there
//     (or one path is the other plus a final AS), both having reached it;
//   - isp_backbone: they part right after the local ISP's AS — the local
//     ISP's choice of backbone or upstream changed;
//   - interconnect: they part deeper, between transit networks or at an
//     international exchange.
func classifyChange(old, new pathShape, oldF, newF endpointFacts) (kind, segment string, diverge int) {
	diverge = commonPrefix(old.as, new.as)

	switch {
	case oldF.destIP != "" && newF.destIP != "" && oldF.destIP != newF.destIP &&
		diverge >= max(len(old.as), len(new.as))-1:
		kind = KindDestination
	case oldF.localASN != 0 && newF.localASN != 0 && oldF.localASN != newF.localASN,
		oldF.localPrefix != "" && newF.localPrefix != "" && oldF.localPrefix != newF.localPrefix:
		kind = KindLocalEgress
	default:
		kind = KindRoute
	}

	switch {
	case len(old.as) == 0 || len(new.as) == 0:
		segment = SegmentUnknown
	case diverge == 0:
		segment = SegmentLocalAccess
	case old.reached && new.reached &&
		(diverge >= len(old.as) || diverge >= len(new.as) ||
			(diverge == len(old.as)-1 && diverge == len(new.as)-1)):
		segment = SegmentDestination
	case diverge == 1:
		segment = SegmentISPBackbone
	default:
		segment = SegmentInterconn
	}
	return kind, segment, diverge
}
