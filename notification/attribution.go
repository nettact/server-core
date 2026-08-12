package notification

import (
	"fmt"
)

// AttributionClue is one typed piece of evidence behind an incident attribution
// ("problem most likely at the router / ISP line / DNS / proxy / remote
// service"). Produced by fault.computeAttribution, frozen onto
// incidents.attribution_evidence as JSON, and rendered per language at
// delivery/read time — never pre-rendered. The console mirrors this shape and
// the polarity/vocabulary in web-console/src/composables/useIncidentLabels.ts;
// keep the two in step (same situation as layerLabel).
type AttributionClue struct {
	// Kind is one of the Clue* constants below.
	Kind string `json:"kind"`
	// Count is a target/host count for aggregate clues (concurrent_public_failures
	// etc.), 0 otherwise.
	Count int `json:"count,omitempty"`
	// Targets are up to 3 display names for aggregate clues; the last entry may
	// be "+N more" (only the renderer computes that, never the producer).
	Targets []string `json:"targets,omitempty"`
	// Name is a single-value parameter: proxy/tunnel name or address (proxy_fail),
	// last public hop IP (trace_public_then_lost).
	Name string `json:"name,omitempty"`
	// Type is the proxy type (socks5|http|wireguard) for proxy_fail, so the
	// renderer can choose "proxy" vs "tunnel" wording.
	Type string `json:"type,omitempty"`
	// ReasonCode is telemetry.ProbeReason* for kind=="reason" clues; the label
	// comes from the existing probeReasonZh/En translations.
	ReasonCode int `json:"reason_code,omitempty"`
	// SizeCorrelated evidence for a size_correlated clue: the two payload sizes
	// the sweep compared and the loss percent at each. Rendered as the
	// "(64B 0.0% → 1400B 67.0%)" fragment; zero when the clue is not a
	// size_correlated one.
	SizeSmall int     `json:"size_small,omitempty"`
	SizeLarge int     `json:"size_large,omitempty"`
	LossSmall float64 `json:"loss_small,omitempty"`
	LossLarge float64 `json:"loss_large,omitempty"`
	// Flow counts for an ecmp_member clue: flows actually attempted and how the
	// deterministic bad subset split across cycles (bad_stable/bad_new/ok).
	// Zero when the clue is not an ecmp_member one.
	Flows     int `json:"flows,omitempty"`
	BadStable int `json:"bad_stable,omitempty"`
	BadNew    int `json:"bad_new,omitempty"`
	OK        int `json:"ok,omitempty"`
}

const (
	ClueGatewayDown        = "gateway_down"
	ClueGatewayOK          = "gateway_ok"
	ClueGatewayUnconfirmed = "gateway_unconfirmed"
	ClueConcurrentPublic   = "concurrent_public_failures"
	ClueDNSFail            = "dns_fail"
	ClueIPOK               = "ip_ok"
	ClueOnlyTargetFailing  = "only_target_failing"
	ClueOthersOK           = "others_ok"
	ClueReason             = "reason"
	ClueNoReference        = "no_reference"
	ClueTargetResponded    = "target_responded"
	ClueProxyFail          = "proxy_fail"
	ClueDirectOK           = "direct_ok"
	ClueViaProxy           = "via_proxy"
	ClueTraceDiedInLAN     = "trace_died_in_lan"
	ClueTracePublicLost    = "trace_public_then_lost"
	ClueTraceReached       = "trace_reached"
	ClueTraceProxyUnreach  = "trace_proxy_unreachable"
	ClueTraceProxyReached  = "trace_proxy_reachable"
	// ClueSizeCorrelated fires on a loss degradation whose confirming round
	// classified size-correlated (SizeSweepFacts.Code == 1): loss rises with
	// packet size, the fingerprint of physical-layer degradation.
	ClueSizeCorrelated = "size_correlated"
	// ClueEcmpMember fires on an availability fault whose confirming round
	// classified member-level (FlowFanoutFacts.Code == 2): a deterministic bad
	// subset of pinned source-port flows, the fingerprint of an ECMP/LAG member
	// fault.
	ClueEcmpMember = "ecmp_member"
)

// CluePolarity classifies a clue as "ok" (a ✓), "fail" (a ✗) or "info" (no
// mark). The console mirrors this table in useIncidentLabels.ts; a clue the
// console does not recognise must degrade to info (no mark, no hidden data).
func CluePolarity(kind string) string {
	switch kind {
	case ClueGatewayOK, ClueIPOK, ClueOthersOK, ClueDirectOK,
		ClueTargetResponded, ClueTraceReached, ClueTraceProxyReached:
		return "ok"
	case ClueGatewayDown, ClueConcurrentPublic, ClueDNSFail,
		ClueOnlyTargetFailing, ClueReason, ClueProxyFail, ClueTraceDiedInLAN:
		return "fail"
	default:
		return "info"
	}
}

// RenderAttribution returns the one-line "problem is most likely at …" sentence
// for an incident, or "" when there is no attribution (p.Attribution == "").
// It is the first line of a notification's scope text (see RenderScope); the
// desktop system toast reuses it automatically via sendNative.
func RenderAttribution(p Payload, lang string) string {
	switch p.Attribution {
	case "router":
		return attributionSentence(lang, "router")
	case "isp":
		return attributionSentence(lang, "isp")
	case "dns":
		return attributionSentence(lang, "dns")
	case "proxy":
		return renderProxyAttribution(p, lang)
	case "service":
		if hasClue(p.AttributionEvidence, ClueTargetResponded) {
			return attributionSentence(lang, "service_responded")
		}
		return attributionSentence(lang, "service")
	case "device":
		return attributionSentence(lang, "device")
	default:
		return ""
	}
}

func renderProxyAttribution(p Payload, lang string) string {
	tunnel := false
	single := false
	for _, c := range p.AttributionEvidence {
		if c.Kind != ClueProxyFail {
			continue
		}
		if c.Type == "wireguard" {
			tunnel = true
		}
		if c.Count == 1 {
			single = true
		}
	}
	key := "proxy"
	if tunnel {
		key = "proxy_tunnel"
	}
	if single {
		key += "_one"
	}
	return attributionSentence(lang, key)
}

func hasClue(clues []AttributionClue, kind string) bool {
	for _, c := range clues {
		if c.Kind == kind {
			return true
		}
	}
	return false
}

func attributionSentence(lang, kind string) string {
	en := normLang(lang) == "en"
	switch kind {
	case "router":
		if en {
			return "Gateway unreachable — the problem is most likely at the router (or this machine's link to it)."
		}
		return "网关不可达——问题最可能出在路由器或本机到路由器的链路。"
	case "isp":
		if en {
			return "Gateway probe OK but multiple public targets are unreachable — the problem is most likely on the ISP line."
		}
		return "网关探测正常,多个公网目标同时不可达——问题最可能出在运营商线路。"
	case "dns":
		if en {
			return "Name lookups are failing while direct-IP probes succeed — the problem is most likely at DNS."
		}
		return "域名解析失败但 IP 直连正常——问题最可能出在 DNS。"
	case "proxy":
		if en {
			return "Multiple probes through a proxy failed on the egress path — the problem is most likely at that proxy (or the link to it)."
		}
		return "多个经由代理的探测失败,失败原因指向代理自身——问题最可能出在该代理或到它的链路。"
	case "proxy_one":
		if en {
			return "A probe through a proxy failed on the egress path — the problem is most likely at that proxy (or the link to it)."
		}
		return "经由代理的探测失败,失败原因指向代理自身——问题最可能出在该代理或到它的链路。"
	case "proxy_tunnel":
		if en {
			return "Multiple probes through a tunnel failed on the egress path — the problem is most likely at that tunnel (or the link to it)."
		}
		return "多个经由隧道的探测失败,失败原因指向隧道自身——问题最可能出在该隧道或到它的链路。"
	case "proxy_tunnel_one":
		if en {
			return "A probe through a tunnel failed on the egress path — the problem is most likely at that tunnel (or the link to it)."
		}
		return "经由隧道的探测失败,失败原因指向隧道自身——问题最可能出在该隧道或到它的链路。"
	case "service_responded":
		if en {
			return "The target is reachable but returns errors — the network link is fine, the problem is most likely at the remote service itself."
		}
		return "目标可以连通但返回错误——网络链路正常,问题最可能出在对方服务本身。"
	case "service":
		if en {
			return "Other targets are fine and only this service is failing — the problem is most likely at the remote service."
		}
		return "其余目标均正常,仅该服务失败——问题最可能出在对方服务。"
	case "device":
		if en {
			return "The problem is most likely at this computer."
		}
		return "问题最可能出在本机。"
	}
	return ""
}

// AttributionLocationLabel is the short user-language position label used in
// table cells (「运营商线路」/"ISP line"), a friendlier replacement for the
// engineering layer label once an attribution exists.
func AttributionLocationLabel(loc, lang string) string {
	en := normLang(lang) == "en"
	switch loc {
	case "router":
		if en {
			return "Router"
		}
		return "路由器"
	case "isp":
		if en {
			return "ISP line"
		}
		return "运营商线路"
	case "dns":
		if en {
			return "DNS"
		}
		return "DNS"
	case "proxy":
		if en {
			return "Proxy"
		}
		return "代理"
	case "service":
		if en {
			return "Remote service"
		}
		return "对方服务"
	case "device":
		if en {
			return "This computer"
		}
		return "本机"
	}
	return layerLabel(loc, lang)
}

// RenderAttributionClues renders each evidence clue as one short human line
// (with ✓/✗ marks), used as the webhook's lead lines so a recipient sees the
// reasoning without parsing the JSON. reason clues reuse the probe reason
// translations. A clue with no template degrades to "" and is skipped.
func RenderAttributionClues(clues []AttributionClue, lang string) []string {
	var out []string
	for _, c := range clues {
		if s := renderClue(c, lang); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// clueLines is RenderAttributionClues gated to the events that can still be
// describing an ongoing fault: a resolved/recovered event's payload retains the
// frozen outage evidence, and leading a recovery notice with "gateway
// unreachable ✗" would contradict the recovery it announces.
func clueLines(p Payload, lang string) []string {
	if p.Event == "incident.resolved" || p.Event == "storm.resolved" ||
		p.Event == "agent.recovered" || p.State == "resolved" {
		return nil
	}
	return RenderAttributionClues(p.AttributionEvidence, lang)
}

func renderClue(c AttributionClue, lang string) string {
	en := normLang(lang) == "en"
	if c.Kind == ClueReason {
		if en {
			return probeReasonEn(c.ReasonCode)
		}
		return probeReasonZh(c.ReasonCode)
	}
	var mark string
	switch CluePolarity(c.Kind) {
	case "ok":
		mark = "✓ "
	case "fail":
		mark = "✗ "
	}
	switch c.Kind {
	case ClueGatewayDown:
		return mark + clueStr("gateway_down", en)
	case ClueGatewayOK:
		return mark + clueStr("gateway_ok", en)
	case ClueGatewayUnconfirmed:
		return mark + clueStr("gateway_unconfirmed", en)
	case ClueConcurrentPublic:
		return mark + fmt.Sprintf(clueStr("concurrent_public_failures", en), c.Count)
	case ClueDNSFail:
		return mark + fmt.Sprintf(clueStr("dns_fail", en), c.Count)
	case ClueIPOK:
		return mark + clueStr("ip_ok", en)
	case ClueOnlyTargetFailing:
		return mark + clueStr("only_target_failing", en)
	case ClueOthersOK:
		return mark + fmt.Sprintf(clueStr("others_ok", en), c.Count)
	case ClueNoReference:
		return mark + clueStr("no_reference", en)
	case ClueTargetResponded:
		return mark + clueStr("target_responded", en)
	case ClueProxyFail:
		if c.Count == 1 {
			return mark + fmt.Sprintf(clueStr("proxy_fail_one", en), c.Name)
		}
		return mark + fmt.Sprintf(clueStr("proxy_fail", en), c.Count, c.Name)
	case ClueDirectOK:
		return mark + clueStr("direct_ok", en)
	case ClueViaProxy:
		return mark + clueStr("via_proxy", en)
	case ClueTraceDiedInLAN:
		return mark + clueStr("trace_died_in_lan", en)
	case ClueTracePublicLost:
		return mark + fmt.Sprintf(clueStr("trace_public_then_lost", en), c.Name)
	case ClueTraceReached:
		return mark + clueStr("trace_reached", en)
	case ClueTraceProxyUnreach:
		return mark + clueStr("trace_proxy_unreachable", en)
	case ClueTraceProxyReached:
		return mark + clueStr("trace_proxy_reachable", en)
	case ClueSizeCorrelated:
		return mark + fmt.Sprintf(clueStr("size_correlated", en), c.SizeSmall, c.LossSmall, c.SizeLarge, c.LossLarge)
	case ClueEcmpMember:
		return mark + clueStr("ecmp_member", en)
	}
	return ""
}

func clueStr(key string, en bool) string {
	if en {
		switch key {
		case "gateway_down":
			return "gateway unreachable"
		case "gateway_ok":
			return "gateway probe OK"
		case "gateway_unconfirmed":
			return "gateway failing (unconfirmed)"
		case "concurrent_public_failures":
			return "%d public targets failing at once"
		case "dns_fail":
			return "%d DNS failures"
		case "ip_ok":
			return "direct-IP probes OK"
		case "only_target_failing":
			return "only this target is failing"
		case "others_ok":
			return "%d other targets OK"
		case "no_reference":
			return "no gateway or reference target to compare"
		case "target_responded":
			return "target answered — network link OK"
		case "proxy_fail":
			return "%d probes via proxy %q failed on the egress path"
		case "proxy_fail_one":
			return "a probe via proxy %q failed on the egress path"
		case "direct_ok":
			return "direct targets OK"
		case "via_proxy":
			return "this target is probed via a proxy"
		case "trace_died_in_lan":
			return "traceroute never left the local network"
		case "trace_public_then_lost":
			return "traceroute lost after public hop %s"
		case "trace_reached":
			return "traceroute reached the target"
		case "trace_proxy_unreachable":
			return "proxy address unreachable"
		case "trace_proxy_reachable":
			return "proxy address reachable"
		case "size_correlated":
			return "Packet loss rises with packet size (%dB %.1f%% → %dB %.1f%%); suggests physical-layer degradation (optics/CRC/FEC)"
		case "ecmp_member":
			return "A fixed subset of source-port flows fails while others stay clean; suggests an ECMP/LAG member-level fault"
		}
		return ""
	}
	switch key {
	case "gateway_down":
		return "网关不可达"
	case "gateway_ok":
		return "网关探测正常"
	case "gateway_unconfirmed":
		return "网关探测失败中（未确认）"
	case "concurrent_public_failures":
		return "%d 个公网目标同时失败"
	case "dns_fail":
		return "%d 项域名解析失败"
	case "ip_ok":
		return "IP 直连正常"
	case "only_target_failing":
		return "仅该目标失败"
	case "others_ok":
		return "其余 %d 个目标正常"
	case "no_reference":
		return "缺少网关或参照目标，无法对比"
	case "target_responded":
		return "目标有应答，网络链路正常"
	case "proxy_fail":
		return "%d 个经由代理「%s」的探测失败，原因指向代理自身"
	case "proxy_fail_one":
		return "经由代理「%s」的探测失败，原因指向代理自身"
	case "direct_ok":
		return "直连目标正常"
	case "via_proxy":
		return "该目标经代理探测"
	case "trace_died_in_lan":
		return "trace 未出本地网络"
	case "trace_public_then_lost":
		return "trace 在公网跳 %s 之后中断"
	case "trace_reached":
		return "trace 可达目标"
	case "trace_proxy_unreachable":
		return "代理地址不可达"
	case "trace_proxy_reachable":
		return "代理地址可达"
	case "size_correlated":
		return "丢包随包长上升（%dB %.1f%% → %dB %.1f%%），疑似物理层劣化（光模块/CRC/FEC）"
	case "ecmp_member":
		return "固定的一组源端口流确定性失败、其余正常，疑似 ECMP/LAG 成员级故障"
	}
	return ""
}
