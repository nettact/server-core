package routehist

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// Bounds on what one sweep may contribute. The payload is agent-controlled,
// so it is bounded rather than trusted: the TTL ceiling matches the largest
// sweep the console lets a monitor configure, and the attempt cap is above the
// largest per-TTL attempt count it allows.
const (
	maxTTL         = 64
	maxAttempts    = 8
	maxHostnameLen = 253
	// futureSlack tolerates ack-anchored clock jitter on a run's timestamp; a
	// run stamped further ahead is clamped to the server clock rather than
	// allowed to sort after runs that have not happened yet.
	futureSlack = 2 * time.Minute
)

// normRun is one sweep, validated and normalized.
type normRun struct {
	reportID string
	ts       int64
	destIP   string
	reached  bool
	// hops holds every TTL from 1 to the deepest one reported, gaps filled
	// with empty (all-silent) hops, so index = TTL-1.
	hops []normHop
}

type normHop struct {
	attempts []normAttempt
}

type normAttempt struct {
	ip     string // canonical address text; "" = timed out
	host   string
	rttMs  float64
	hasRTT bool
}

// responders returns the TTL's distinct responder addresses, sorted.
func (h normHop) responders() []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range h.attempts {
		if a.ip != "" && !seen[a.ip] {
			seen[a.ip] = true
			out = append(out, a.ip)
		}
	}
	sort.Strings(out)
	return out
}

// pathLen is how many TTLs the normalized IP path keeps: up to the last TTL
// anybody answered. Trailing silence is trimmed because its length says only
// how far the sweep was allowed to go (the configured hop ceiling), not where
// the route goes — keeping it would split one route into as many paths as
// there are ceilings and budget overruns.
func (r normRun) pathLen() int {
	n := 0
	for i, h := range r.hops {
		if len(h.responders()) > 0 {
			n = i + 1
		}
	}
	return n
}

// normalize validates one scheduled TraceResult. ok is false for a result
// that carries no route observation at all — the sweep was unsupported,
// failed before probing, was canceled, or had no responding hop — those are
// skipped (no detail, no effect on the detector), not recorded as an empty
// route.
func normalize(tr telemetry.TraceResult, now time.Time) (normRun, bool) {
	switch tr.Status {
	case telemetry.TraceStatusUnsupported, telemetry.TraceStatusFailed, telemetry.TraceStatusCanceled:
		return normRun{}, false
	}
	if tr.ReportID == "" || len(tr.ReportID) > 128 {
		return normRun{}, false
	}
	r := normRun{reportID: tr.ReportID}
	switch {
	case !tr.StartedAt.IsZero():
		r.ts = tr.StartedAt.Unix()
	case !tr.CompletedAt.IsZero():
		r.ts = tr.CompletedAt.Unix()
	default:
		r.ts = now.Unix()
	}
	if r.ts > now.Add(futureSlack).Unix() {
		r.ts = now.Unix()
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(tr.DestinationIP)); err == nil {
		r.destIP = a.Unmap().String()
	}

	byTTL := map[int][]normAttempt{}
	deepest := 0
	for _, h := range tr.Hops {
		if h.TTL < 1 || h.TTL > maxTTL {
			continue
		}
		for _, a := range h.Attempts {
			if len(byTTL[h.TTL]) >= maxAttempts {
				break
			}
			na := normAttempt{}
			if !a.Timeout {
				if addr, err := netip.ParseAddr(strings.TrimSpace(a.ResponderAddr)); err == nil {
					na.ip = addr.Unmap().String()
					na.host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.Hostname), "."))
					if len(na.host) > maxHostnameLen {
						na.host = ""
					}
					if a.RTTMs > 0 && a.RTTMs < 600000 {
						na.rttMs, na.hasRTT = a.RTTMs, true
					}
				}
			}
			byTTL[h.TTL] = append(byTTL[h.TTL], na)
		}
		if h.TTL > deepest {
			deepest = h.TTL
		}
	}
	r.hops = make([]normHop, deepest)
	for ttl, as := range byTTL {
		r.hops[ttl-1].attempts = as
	}

	// A sweep in which nobody answered at any TTL observed no route at all —
	// the engine timed out end to end, or refused to probe and reported it as
	// a bare result. Counting it as evidence would let a stretch of local
	// outage extend (or, as a candidate, break into) an era it says nothing
	// about, so it is skipped like an unsupported or failed sweep.
	if r.pathLen() == 0 {
		return normRun{}, false
	}

	// "Reached" is believed only when the destination's own address answered:
	// a flag from the agent with no hop to show for it would make an
	// unreached sweep compare as complete.
	if tr.Reached && r.destIP != "" {
		for _, h := range r.hops {
			for _, a := range h.attempts {
				if a.ip == r.destIP {
					r.reached = true
				}
			}
		}
	}
	return r, true
}

// destSamples returns the destination's RTT samples and the attempts sent and
// answered at the TTL where it answered (zero when unreached).
func (r normRun) destSamples() (rtts []float64, probes, replies int) {
	if !r.reached {
		return nil, 0, 0
	}
	for _, h := range r.hops {
		hit := false
		for _, a := range h.attempts {
			if a.ip == r.destIP {
				hit = true
			}
		}
		if !hit {
			continue
		}
		for _, a := range h.attempts {
			probes++
			if a.ip == r.destIP {
				replies++
				if a.hasRTT {
					rtts = append(rtts, a.rttMs)
				}
			}
		}
		break
	}
	return rtts, probes, replies
}
