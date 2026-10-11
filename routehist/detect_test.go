package routehist

import (
	"math"
	"reflect"
	"testing"
)

func TestConsistentComparesPartialObservationsByPrefix(t *testing.T) {
	full := pathShape{as: []uint32{1, 2, 3}, reached: true}
	cases := []struct {
		name string
		a, b pathShape
		want bool
	}{
		{"equal", full, full, true},
		{"unreached prefix", pathShape{as: []uint32{1, 2}}, full, true},
		{"unreached prefix, either side", full, pathShape{as: []uint32{1, 2}}, true},
		{"empty unreached", pathShape{}, full, true},
		{"reached but shorter", pathShape{as: []uint32{1, 2}, reached: true}, full, false},
		{"unreached, not a prefix", pathShape{as: []uint32{1, 4}}, full, false},
		{"unreached runs further than a reached era", pathShape{as: []uint32{1, 2, 3, 4}}, full, false},
		{"both unreached, one longer", pathShape{as: []uint32{1}}, pathShape{as: []uint32{1, 2}}, true},
		{"reached but no AS data", pathShape{reached: true}, full, true},
	}
	for _, c := range cases {
		if got := consistent(c.a, c.b); got != c.want {
			t.Errorf("%s: consistent = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestClassifyChange(t *testing.T) {
	r := func(as ...uint32) pathShape { return pathShape{as: as, reached: true} }
	local := endpointFacts{destIP: "1.1.1.1", localASN: 100, localPrefix: "11.0.0.0/8"}
	cases := []struct {
		name          string
		old, new      pathShape
		oldF, newF    endpointFacts
		kind, segment string
		diverge       int
	}{
		{"destination AS moved with the address", r(100, 300, 500), r(100, 300, 600), local,
			endpointFacts{destIP: "2.2.2.2", localASN: 100, localPrefix: "11.0.0.0/8"}, KindDestination, SegmentDestination, 2},
		{"same address, destination AS differs", r(100, 300, 500), r(100, 300, 600), local, local, KindRoute, SegmentDestination, 2},
		{"local line swapped", r(100, 300, 500), r(200, 300, 500), local,
			endpointFacts{destIP: "1.1.1.1", localASN: 200, localPrefix: "12.0.0.0/8"}, KindLocalEgress, SegmentLocalAccess, 0},
		{"same local AS, new access prefix", r(100, 300, 500), r(100, 400, 500), local,
			endpointFacts{destIP: "1.1.1.1", localASN: 100, localPrefix: "11.1.0.0/16"}, KindLocalEgress, SegmentISPBackbone, 1},
		{"backbone choice", r(100, 300, 500), r(100, 400, 500), local, local, KindRoute, SegmentISPBackbone, 1},
		{"deeper transit", r(100, 300, 500), r(100, 300, 400, 500), local, local, KindRoute, SegmentInterconn, 2},
		{"one extends the other", r(100, 300), r(100, 300, 500), local, local, KindRoute, SegmentDestination, 2},
		{"no AS data", r(), r(100), local, local, KindRoute, SegmentUnknown, 0},
		{"unreached tails are not the destination", pathShape{as: []uint32{100, 300, 500}}, pathShape{as: []uint32{100, 300, 600}},
			local, local, KindRoute, SegmentInterconn, 2},
	}
	for _, c := range cases {
		k, s, d := classifyChange(c.old, c.new, c.oldF, c.newF)
		if k != c.kind || s != c.segment || d != c.diverge {
			t.Errorf("%s: = %s/%s/%d, want %s/%s/%d", c.name, k, s, d, c.kind, c.segment, c.diverge)
		}
	}
}

func TestHistogramQuantilesAndMerge(t *testing.T) {
	var a, b histogram
	for i := 0; i < 90; i++ {
		a.add(38)
	}
	for i := 0; i < 10; i++ {
		b.add(172)
	}
	if got := a.quantile(0.5); got != 38 {
		t.Errorf("single-valued p50 = %v, want exactly 38 (clamped to min/max)", got)
	}
	a.merge(b)
	if a.count != 100 || a.min != 38 || a.max != 172 {
		t.Fatalf("merged = %+v", a)
	}
	p50, p95 := a.quantile(0.5), a.quantile(0.95)
	if math.Abs(p50-38) > 38*0.2 {
		t.Errorf("p50 = %v, want ~38", p50)
	}
	if math.Abs(p95-172) > 172*0.2 {
		t.Errorf("p95 = %v, want ~172", p95)
	}
	// Round trip through the stored form.
	got := decodeHist(encodeHist(a))
	if got.counts != a.counts {
		t.Errorf("hist round trip lost counts")
	}
	if s := (&histogram{}).summary(); s != nil {
		t.Error("an empty histogram must summarize as nil")
	}
	var edge histogram
	edge.add(0.1)
	edge.add(5000)
	if edge.counts[0] != 1 || edge.counts[histBuckets-1] != 1 {
		t.Errorf("out-of-range samples not clamped into the end buckets: %v", edge.counts)
	}
}

func TestCodecsRoundTrip(t *testing.T) {
	ip := ipPath{{1}, {}, {2, 300000}, {7}}
	got, err := decodeIPPath(encodeIPPath(ip))
	if err != nil || !reflect.DeepEqual(got, ip) {
		t.Errorf("ip path = %v %v", got, err)
	}
	as := []uint32{4134, 4809, 4294967295}
	if got, err := decodeASPath(encodeASPath(as)); err != nil || !reflect.DeepEqual(got, as) {
		t.Errorf("as path = %v %v", got, err)
	}
	hops := []detailHop{{ttl: 1, attempts: []detailAttempt{{ipID: 3, rttMs: 1.23, rtt: true}, {ipID: 0}}}, {ttl: 2}}
	gotHops, err := decodeDetail(encodeDetail(hops))
	if err != nil || !reflect.DeepEqual(gotHops, hops) {
		t.Errorf("detail = %+v %v", gotHops, err)
	}
	if _, err := decodeIPPath([]byte{0x80}); err == nil {
		t.Error("truncated varint accepted")
	}
	if string(pathHash(true, encodeIPPath(ip))) == string(pathHash(false, encodeIPPath(ip))) {
		t.Error("reached must be part of a path's identity")
	}
}
