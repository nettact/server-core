package notification

import (
	"strings"
	"testing"
)

// A storm notice is the ONE message that replaces N, so its wording carries more
// weight than usual: it has to say how bad it is, where to look, and — on
// recovery — that everything really is back. These tests pin that in both
// languages.

func stormPayload(event string) Payload {
	return Payload{
		Event:          event,
		StormID:        "stm_1",
		SiteID:         "site_default",
		State:          "open",
		Severity:       "critical",
		SuspectedLayer: "wan",
		Scope:          "single",
		AgentCount:     1,
		Storm: &StormDetail{
			AgentName:  "imini",
			FaultCount: 4,
			GroupCount: 3,
			Groups: []StormGroup{
				{Name: "Websites", Severity: "warn", Layer: "service"},
				{Name: "NAT", Severity: "critical", Layer: "wan"},
				{Name: "DNS", Severity: "warn", Layer: "dns"},
			},
		},
	}
}

func TestStormTitleLeadsWithTheSuspectedLayer(t *testing.T) {
	p := stormPayload("storm.opened")
	zh := RenderTitle(p, "zh")
	for _, want := range []string{"WAN", "4"} {
		if !strings.Contains(zh, want) {
			t.Fatalf("zh title %q missing %q", zh, want)
		}
	}
	en := RenderTitle(p, "en")
	for _, want := range []string{"WAN", "4"} {
		if !strings.Contains(en, want) {
			t.Fatalf("en title %q missing %q", en, want)
		}
	}
}

// The scope line must name BOTH counts. Saying only "3 groups" would hide that
// four separate messages were replaced; saying only "4 faults" would hide how
// far the damage spread.
func TestStormScopeNamesBothCountsAndTheAgent(t *testing.T) {
	p := stormPayload("storm.opened")
	for _, lang := range []string{"zh", "en"} {
		s := RenderScope(p, lang)
		for _, want := range []string{"4", "3", "imini"} {
			if !strings.Contains(s, want) {
				t.Fatalf("%s scope %q missing %q", lang, s, want)
			}
		}
	}
}

// Worst-first, so the line that matters is never the one truncated away.
func TestStormLinesAreWorstFirst(t *testing.T) {
	lines := RenderStormLines(stormPayload("storm.opened"), "zh")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	if !strings.Contains(lines[0], "NAT") {
		t.Fatalf("first line = %q, want the critical group first", lines[0])
	}
}

// A site-wide outage must not produce a wall of text on someone's phone.
func TestStormLinesTruncate(t *testing.T) {
	p := stormPayload("storm.opened")
	p.Storm.Groups = nil
	for _, name := range []string{"g1", "g2", "g3", "g4", "g5", "g6", "g7"} {
		p.Storm.Groups = append(p.Storm.Groups, StormGroup{Name: name, Severity: "warn", Layer: "service"})
	}
	lines := RenderStormLines(p, "zh")
	if len(lines) != maxDetailLines+1 {
		t.Fatalf("lines = %d, want %d capped lines plus a tail", len(lines), maxDetailLines)
	}
	if !strings.Contains(lines[len(lines)-1], "2") {
		t.Fatalf("tail line %q must say how many were left out", lines[len(lines)-1])
	}
}

func TestStormRecoveryStatesDuration(t *testing.T) {
	p := stormPayload("storm.resolved")
	p.State = "resolved"
	p.Storm.DurationS = 743
	zh := RenderScope(p, "zh")
	if !strings.Contains(zh, "12 分钟") {
		t.Fatalf("zh recovery %q must state how long it lasted", zh)
	}
	en := RenderScope(p, "en")
	if !strings.Contains(en, "12m") {
		t.Fatalf("en recovery %q must state how long it lasted", en)
	}
	// The recovery lines name what came back, not what is broken.
	for _, line := range RenderStormLines(p, "zh") {
		if !strings.Contains(line, "已恢复") {
			t.Fatalf("recovery line %q must read as a recovery", line)
		}
	}
}

// RenderLines is the single entry point webhook / email / native notifications
// share, so a storm has to route through it or two of the three channels would
// silently render nothing.
func TestStormRoutesThroughRenderLines(t *testing.T) {
	for _, event := range []string{"storm.opened", "storm.resolved"} {
		if got := RenderLines(stormPayload(event), "zh"); len(got) == 0 {
			t.Fatalf("RenderLines(%s) returned nothing", event)
		}
	}
}

// Templates authored against incident events must still render something true
// for a storm rather than an empty string.
func TestStormFillsTemplateVars(t *testing.T) {
	vars := buildVars(stormPayload("storm.opened"), "zh")
	if vars["event"] != "storm.opened" {
		t.Fatalf("event var = %q", vars["event"])
	}
	if vars["storm_id"] != "stm_1" {
		t.Fatalf("storm_id var = %q", vars["storm_id"])
	}
	if !strings.Contains(vars["targets"], "Websites") {
		t.Fatalf("targets var = %q, want the monitor group names", vars["targets"])
	}
	if vars["agents"] != "imini" {
		t.Fatalf("agents var = %q, want the observing agent", vars["agents"])
	}
	if vars["target"] == "" || vars["lines"] == "" || vars["title"] == "" {
		t.Fatalf("core vars are empty for a storm: %+v", vars)
	}
}

func TestDurationLabel(t *testing.T) {
	cases := []struct {
		secs   int
		zh, en string
	}{
		{45, "45 秒", "45s"},
		{743, "12 分钟", "12m"},
		{7200, "2 小时", "2h"},
		{180000, "2.1 天", "2.1d"},
	}
	for _, c := range cases {
		if got := durationLabel(c.secs, "zh"); got != c.zh {
			t.Errorf("durationLabel(%d, zh) = %q, want %q", c.secs, got, c.zh)
		}
		if got := durationLabel(c.secs, "en"); got != c.en {
			t.Errorf("durationLabel(%d, en) = %q, want %q", c.secs, got, c.en)
		}
	}
}
