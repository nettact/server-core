package notification

import (
	"strings"
	"testing"
	"time"
)

// Attribution rendering (INCIDENT-003): every location produces a one-line
// "problem most likely at …" sentence in both languages, and RenderScope
// prefers it over the engineering layer wording whenever one exists.

func TestRenderAttributionAllLocations(t *testing.T) {
	labelZh := map[string]string{
		"router":  "路由器",
		"isp":     "运营商线路",
		"dns":     "DNS",
		"proxy":   "代理",
		"service": "对方服务",
		"device":  "本机",
	}
	labelEn := map[string]string{
		"router":  "Router",
		"isp":     "ISP line",
		"dns":     "DNS",
		"proxy":   "Proxy",
		"service": "Remote service",
		"device":  "This computer",
	}
	for loc := range labelZh {
		p := Payload{Attribution: loc}
		if s := RenderAttribution(p, "zh"); s == "" {
			t.Fatalf("RenderAttribution(%q, zh) is empty", loc)
		}
		if s := RenderAttribution(p, "en"); s == "" {
			t.Fatalf("RenderAttribution(%q, en) is empty", loc)
		}
		if got := AttributionLocationLabel(loc, "zh"); got != labelZh[loc] {
			t.Fatalf("AttributionLocationLabel(%q, zh) = %q want %q", loc, got, labelZh[loc])
		}
		if got := AttributionLocationLabel(loc, "en"); got != labelEn[loc] {
			t.Fatalf("AttributionLocationLabel(%q, en) = %q want %q", loc, got, labelEn[loc])
		}
	}
	// '' must render as "" — the fallback signal.
	if s := RenderAttribution(Payload{}, "zh"); s != "" {
		t.Fatalf("empty attribution must render empty, got %q", s)
	}
}

func TestRenderAttributionProxyWording(t *testing.T) {
	relay := Payload{Attribution: "proxy", AttributionEvidence: []AttributionClue{
		{Kind: ClueProxyFail, Type: "socks5", Name: "egress", Count: 3},
	}}
	if s := RenderAttribution(relay, "zh"); !strings.Contains(s, "代理") {
		t.Fatalf("relay proxy zh = %q want proxy wording", s)
	}
	tunnel := Payload{Attribution: "proxy", AttributionEvidence: []AttributionClue{
		{Kind: ClueProxyFail, Type: "wireguard", Name: "wg0", Count: 2},
	}}
	if s := RenderAttribution(tunnel, "zh"); !strings.Contains(s, "隧道") {
		t.Fatalf("tunnel zh = %q want tunnel wording", s)
	}
}

func TestRenderAttributionServiceRespondedVariant(t *testing.T) {
	p := Payload{Attribution: "service", AttributionEvidence: []AttributionClue{{Kind: ClueTargetResponded}}}
	if s := RenderAttribution(p, "zh"); !strings.Contains(s, "可以连通") {
		t.Fatalf("responded variant zh = %q want 可以连通", s)
	}
	plain := Payload{Attribution: "service"}
	if s := RenderAttribution(plain, "zh"); !strings.Contains(s, "仅该服务") {
		t.Fatalf("plain variant zh = %q want 仅该服务", s)
	}
}

func TestRenderScopePrefersAttribution(t *testing.T) {
	// A single-host incident WITH an attribution must lead with the user-language
	// sentence, not "疑似 service 层".
	p := Payload{
		Event: "incident.opened", State: "open", Scope: "single", AgentCount: 1,
		SuspectedLayer: "service", Attribution: "service",
		AttributionEvidence: []AttributionClue{{Kind: ClueTargetResponded}},
	}
	zh := RenderScope(p, "zh")
	if !strings.Contains(zh, "可以连通") || strings.Contains(zh, "单机故障") {
		t.Fatalf("RenderScope zh = %q want the attribution sentence, not the layer wording", zh)
	}
	// Without attribution, the existing layer wording must be unchanged.
	p.Attribution = ""
	if s := RenderScope(p, "zh"); s != "单机故障：疑似 服务层。" {
		t.Fatalf("no-attribution RenderScope zh = %q want the original layer wording", s)
	}
}

func TestRenderScopeLeavesNonIncidentBranchesAlone(t *testing.T) {
	// resolved / storm / agent-offline wording must ignore any stray attribution.
	resolved := Payload{Event: "incident.resolved", State: "resolved", GroupName: "g", GroupMerged: true, Attribution: "isp"}
	if s := RenderScope(resolved, "zh"); !strings.Contains(s, "已全部恢复") {
		t.Fatalf("resolved branch = %q must keep recovery wording", s)
	}
	offline := Payload{Event: "agent.offline", AgentCount: 1, Attribution: "router"}
	if s := RenderScope(offline, "zh"); !strings.Contains(s, "已离线") {
		t.Fatalf("agent.offline branch = %q must keep offline wording", s)
	}
	storm := Payload{Event: "storm.opened", State: "open", Storm: &StormDetail{}, Attribution: "isp"}
	if s := RenderScope(storm, "zh"); strings.Contains(s, "运营商线路") {
		t.Fatalf("storm branch = %q must keep storm wording in v1", s)
	}
}

func TestRenderAttributionClues(t *testing.T) {
	clues := []AttributionClue{
		{Kind: ClueGatewayOK},
		{Kind: ClueConcurrentPublic, Count: 2, Targets: []string{"a", "b"}},
		{Kind: ClueReason, ReasonCode: 71},
		{Kind: ClueNoReference},
	}
	lines := RenderAttributionClues(clues, "zh")
	if len(lines) != 4 {
		t.Fatalf("clue lines = %d, want 4", len(lines))
	}
	if !strings.HasPrefix(lines[0], "✓") || !strings.Contains(lines[0], "网关探测正常") {
		t.Fatalf("gateway_ok line = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "✗") || !strings.Contains(lines[1], "2 个公网目标同时失败") {
		t.Fatalf("concurrent line = %q", lines[1])
	}
	if !strings.Contains(lines[2], "状态码不符合预期") {
		t.Fatalf("reason line = %q want the probe-reason translation", lines[2])
	}
	en := RenderAttributionClues(clues, "en")
	if len(en) != 4 || !strings.Contains(en[2], "status") {
		t.Fatalf("en clue lines = %v", en)
	}
	// An unknown clue must degrade to nothing (never a raw code or a crash).
	if s := RenderAttributionClues([]AttributionClue{{Kind: "bogus"}}, "zh"); len(s) != 0 {
		t.Fatalf("unknown clue rendered %v, want none", s)
	}
}

func TestAttributionTemplateVar(t *testing.T) {
	p := Payload{Event: "incident.opened", State: "open", Scope: "single", Severity: "error",
		SuspectedLayer: "internet", Attribution: "isp", At: testTime}
	vars := buildVars(p, "zh")
	if vars["attribution"] != "isp" {
		t.Fatalf("{{attribution}} = %q want isp", vars["attribution"])
	}
	if vars["text"] != RenderScope(p, "zh") {
		t.Fatalf("{{text}} must equal RenderScope")
	}
}

var testTime = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

func TestClueLinesOmittedOnResolution(t *testing.T) {
	resolved := Payload{Event: "incident.resolved", State: "resolved",
		AttributionEvidence: []AttributionClue{{Kind: ClueGatewayDown}}}
	if lines := clueLines(resolved, "zh"); len(lines) != 0 {
		t.Fatalf("resolved event must not lead a recovery notice with outage clues, got %v", lines)
	}
	open := Payload{Event: "incident.opened", State: "open",
		AttributionEvidence: []AttributionClue{{Kind: ClueGatewayDown}}}
	if lines := clueLines(open, "zh"); len(lines) != 1 {
		t.Fatalf("open event should lead with its clues, got %v", lines)
	}
}
