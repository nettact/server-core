package incidentops

import (
	"testing"
	"time"

	"github.com/nettact/server-core/metrics"
)

// The frozen chart has to contain the failure. metrics.Query applies its limit
// as ORDER BY ts LIMIT n from the START of the range, so simply asking for
// twelve points over a ten-minute window of a ten-second series returns the
// first two minutes of it — and the fault, which sits at the anchor, is absent
// from the one immutable record of what it looked like.
func TestAroundAnchorKeepsTheFailureInTheWindow(t *testing.T) {
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	// Ten minutes of a ten-second series: 60 points, the anchor halfway through.
	pts := make([]metrics.Point, 0, 60)
	for i := 0; i < 60; i++ {
		pts = append(pts, metrics.Point{TS: base.Add(time.Duration(i) * 10 * time.Second)})
	}
	anchor := base.Add(5 * time.Minute) // pts[30]

	got := aroundAnchor(pts, anchor, recentSampleLimit)
	if len(got) != recentSampleLimit {
		t.Fatalf("kept %d points, want %d", len(got), recentSampleLimit)
	}
	var hasAnchor bool
	for _, p := range got {
		if p.TS.Equal(anchor) {
			hasAnchor = true
		}
	}
	if !hasAnchor {
		t.Fatalf("the anchor sample is missing; kept %s..%s",
			got[0].TS, got[len(got)-1].TS)
	}
	// Weighted towards what led INTO the failure.
	before := 0
	for _, p := range got {
		if p.TS.Before(anchor) {
			before++
		}
	}
	if before < recentSampleLimit/2 {
		t.Fatalf("only %d of %d points precede the failure; the chart is meant to "+
			"show the way in", before, len(got))
	}
}

func TestAroundAnchorEdgeCases(t *testing.T) {
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	mk := func(n int) []metrics.Point {
		out := make([]metrics.Point, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, metrics.Point{TS: base.Add(time.Duration(i) * time.Second)})
		}
		return out
	}
	// Fewer points than the budget: everything is kept.
	if got := aroundAnchor(mk(5), base.Add(2*time.Second), 12); len(got) != 5 {
		t.Fatalf("kept %d of 5", len(got))
	}
	// Anchor before every point (a fault whose evidence predates the retained
	// series): the earliest points are the closest thing to it.
	got := aroundAnchor(mk(40), base.Add(-time.Hour), 12)
	if len(got) != 12 || !got[0].TS.Equal(base) {
		t.Fatalf("kept %d starting %s, want the earliest 12", len(got), got[0].TS)
	}
	// Anchor after every point: the latest ones.
	got = aroundAnchor(mk(40), base.Add(time.Hour), 12)
	if len(got) != 12 || !got[len(got)-1].TS.Equal(base.Add(39*time.Second)) {
		t.Fatalf("kept %d ending %s, want the latest 12", len(got), got[len(got)-1].TS)
	}
}
