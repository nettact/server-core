package routehist

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

// Compact encodings for the BLOB columns. Varints because nearly every value
// stored is a small integer (dictionary ids, counts, AS numbers), and a hop
// that costs two or three bytes instead of a text row is what keeps years of
// history inside a few hundred KB per monitor.

var errCorrupt = errors.New("routehist: corrupt encoded value")

type reader struct {
	b   []byte
	err error
}

func (r *reader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = errCorrupt
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) done() bool { return r.err != nil || len(r.b) == 0 }

// ipPath is the normalized responder sets, index = TTL-1, each set sorted
// ascending by route_ips id; an empty set is a TTL nobody answered.
type ipPath [][]int64

func encodeIPPath(p ipPath) []byte {
	var out []byte
	for _, hop := range p {
		out = binary.AppendUvarint(out, uint64(len(hop)))
		for _, id := range hop {
			out = binary.AppendUvarint(out, uint64(id))
		}
	}
	return out
}

func decodeIPPath(b []byte) (ipPath, error) {
	r := reader{b: b}
	var p ipPath
	for !r.done() {
		n := r.uvarint()
		if n > 1024 {
			return nil, errCorrupt
		}
		hop := make([]int64, 0, n)
		for i := uint64(0); i < n; i++ {
			hop = append(hop, int64(r.uvarint()))
		}
		p = append(p, hop)
	}
	return p, r.err
}

func encodeASPath(as []uint32) []byte {
	out := make([]byte, 0, len(as)*3)
	for _, a := range as {
		out = binary.AppendUvarint(out, uint64(a))
	}
	return out
}

func decodeASPath(b []byte) ([]uint32, error) {
	r := reader{b: b}
	var as []uint32
	for !r.done() {
		as = append(as, uint32(r.uvarint()))
	}
	return as, r.err
}

// pathHash is the content identity of a path: the IP path plus whether the
// destination answered. The AS path is not hashed — it is a function of the IP
// path, since every route_ips row fixes its AS.
func pathHash(reached bool, ip []byte) []byte {
	h := sha256.New()
	if reached {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	h.Write(ip)
	return h.Sum(nil)[:16]
}

// detailHop is one TTL of a run in full.
type detailHop struct {
	ttl      int
	attempts []detailAttempt
}

type detailAttempt struct {
	ipID  int64   // 0 = timed out
	rttMs float64 // valid only when hasRTT
	rtt   bool
}

// encodeDetail: per hop the TTL and attempt count, then per attempt the
// route_ips id (0 = timed out) and the RTT in hundredths of a ms plus one
// (0 = none).
func encodeDetail(hops []detailHop) []byte {
	var out []byte
	for _, h := range hops {
		out = binary.AppendUvarint(out, uint64(h.ttl))
		out = binary.AppendUvarint(out, uint64(len(h.attempts)))
		for _, a := range h.attempts {
			out = binary.AppendUvarint(out, uint64(a.ipID))
			var rtt uint64
			if a.rtt {
				rtt = uint64(math.Round(a.rttMs*100)) + 1
			}
			out = binary.AppendUvarint(out, rtt)
		}
	}
	return out
}

func decodeDetail(b []byte) ([]detailHop, error) {
	r := reader{b: b}
	var hops []detailHop
	for !r.done() {
		h := detailHop{ttl: int(r.uvarint())}
		n := r.uvarint()
		if n > 64 {
			return nil, errCorrupt
		}
		for i := uint64(0); i < n; i++ {
			a := detailAttempt{ipID: int64(r.uvarint())}
			if v := r.uvarint(); v > 0 {
				a.rtt = true
				a.rttMs = float64(v-1) / 100
			}
			h.attempts = append(h.attempts, a)
		}
		hops = append(hops, h)
	}
	return hops, r.err
}
