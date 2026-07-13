package notification

import (
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/nettact/protocol/telemetry"
)

// AlertDetail is one firing alert's structured facts — enough to render a
// human sentence ("website example.com returned HTTP 503") in any supported
// language at delivery time. The incident correlator collects these from the DB
// (alerts ⨝ alert_rules ⨝ probe_tasks ⨝ agents) and hands them to Notify, so
// the language decision stays at the channel boundary rather than being baked
// into a pre-rendered string.
type AlertDetail struct {
	ProbeKind  string  `json:"probe_kind"`  // "icmp" | "dns" | "http" | "tcp" | "host" | ""
	MetricKind string  `json:"metric_kind"` // telemetry.MetricKind, e.g. "probe.http.status"
	Comparator string  `json:"comparator"`  // gt | gte | lt | lte | eq
	Threshold  float64 `json:"threshold"`
	Value      float64 `json:"value"`
	TargetName string  `json:"target_name"` // operator-set friendly name, optional
	Target     string  `json:"target"`      // address ("1.1.1.1", "https://…", "host:port")
	Layer      string  `json:"layer"`       // local|lan|wan|internet|dns|service|wireless
	Severity   string  `json:"severity"`    // info|warn|error|critical
	AgentHost  string  `json:"agent_host"`  // display_name or hostname of the detecting agent
}

// maxDetailLines caps how many specific fault lines a single notification lists;
// the rest are summarized as "+N more" so a site-wide outage can't produce a
// wall of text.
const maxDetailLines = 5

func normLang(lang string) string {
	if lang == "en" {
		return "en"
	}
	return "zh"
}

var severityRank = map[string]int{"info": 0, "warn": 1, "error": 2, "critical": 3}
var layerOrder = map[string]int{"local": 0, "lan": 1, "wan": 2, "internet": 3, "dns": 4, "service": 5, "wireless": 6}

// RenderTitle is the human headline (no machine event strings like
// "incident.opened").
func RenderTitle(p Payload, lang string) string {
	resolved := p.Event == "incident.resolved" || p.State == "resolved"
	if normLang(lang) == "en" {
		switch {
		case resolved:
			return "Alert resolved"
		case p.Event == "incident.opened":
			return "Network alert"
		default:
			return "Network alert (updated)"
		}
	}
	switch {
	case resolved:
		return "告警已恢复"
	case p.Event == "incident.opened":
		return "网络告警"
	default:
		return "网络告警更新"
	}
}

// RenderScope is the one-line diagnosis: single-host vs site-wide and the
// suspected root-cause layer.
func RenderScope(p Payload, lang string) string {
	en := normLang(lang) == "en"
	if p.Event == "incident.resolved" || p.State == "resolved" {
		if en {
			return "All alerts resolved."
		}
		return "所有告警已恢复。"
	}
	layer := layerLabel(p.SuspectedLayer, lang)
	if p.Scope == "site" {
		if en {
			return fmt.Sprintf("Site-wide fault: %d nodes alerting, likely at the %s layer.", p.AgentCount, layer)
		}
		return fmt.Sprintf("站点级故障：%d 个节点告警，疑似 %s层。", p.AgentCount, layer)
	}
	if en {
		return fmt.Sprintf("Single-host fault: likely at the %s layer.", layer)
	}
	return fmt.Sprintf("单机故障：疑似 %s层。", layer)
}

// LinkLine renders the "view details" line pointing at the incident in the
// console, or "" when no URL is configured.
func LinkLine(url, lang string) string {
	if url == "" {
		return ""
	}
	if normLang(lang) == "en" {
		return "View details: " + url
	}
	return "查看详情：" + url
}

// sortedDetails returns a copy of details ordered worst-first: higher severity
// first, then more fundamental layer.
func sortedDetails(details []AlertDetail) []AlertDetail {
	sorted := make([]AlertDetail, len(details))
	copy(sorted, details)
	sort.SliceStable(sorted, func(i, j int) bool {
		if a, b := severityRank[sorted[i].Severity], severityRank[sorted[j].Severity]; a != b {
			return a > b // more severe first
		}
		return layerOrder[sorted[i].Layer] < layerOrder[sorted[j].Layer] // more fundamental layer first
	})
	return sorted
}

// RenderDetails sorts the firing alerts worst-first, renders up to maxDetailLines
// human sentences, and appends a "+N more" line when truncated.
func RenderDetails(details []AlertDetail, lang string) []string {
	sorted := sortedDetails(details)
	limit := len(sorted)
	if limit > maxDetailLines {
		limit = maxDetailLines
	}
	out := make([]string, 0, limit+1)
	for _, d := range sorted[:limit] {
		out = append(out, DescribeDetail(d, lang))
	}
	if rest := len(sorted) - limit; rest > 0 {
		if normLang(lang) == "en" {
			out = append(out, fmt.Sprintf("+%d more", rest))
		} else {
			out = append(out, fmt.Sprintf("另有 %d 项", rest))
		}
	}
	return out
}

// RenderSummary is the one-line incident summary stored for the console list and
// timeline. Unlike RenderScope (which only says "single/site fault, likely layer
// X"), it leads with the specific top fault so the summary column is readable at
// a glance, e.g. "网站 商城 返回状态码 503（来自 客厅主机）（共 3 项）". Falls back to the
// scope line when there are no per-target details (e.g. a resolved incident).
func RenderSummary(p Payload, lang string) string {
	sorted := sortedDetails(p.Details)
	if len(sorted) == 0 {
		return RenderScope(p, lang)
	}
	top := DescribeDetail(sorted[0], lang)
	if len(sorted) == 1 {
		return top
	}
	if normLang(lang) == "en" {
		return fmt.Sprintf("%s (%d issues in total)", top, len(sorted))
	}
	return fmt.Sprintf("%s（共 %d 项）", top, len(sorted))
}

// DescribeDetail turns one alert's facts into a single human sentence stating
// which target, what failed, and the measured value vs threshold.
func DescribeDetail(d AlertDetail, lang string) string {
	if normLang(lang) == "en" {
		return describeEn(d)
	}
	return describeZh(d)
}

// --- Chinese ---

func describeZh(d AlertDetail) string {
	subj := subjectZh(d)
	var s string
	switch telemetry.MetricKind(d.MetricKind) {
	case telemetry.ICMPLoss:
		if d.Value >= 99.5 {
			s = subj + " 完全不可达（丢包 100%）"
		} else {
			s = fmt.Sprintf("%s 丢包率 %s%%%s", subj, num(d.Value), thrZh(d, "%"))
		}
	case telemetry.ICMPRTTms:
		s = fmt.Sprintf("%s 延迟 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.ICMPJitter:
		s = fmt.Sprintf("%s 抖动 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.DNSOK:
		s = subj + " 解析失败"
	case telemetry.DNSResolve:
		s = fmt.Sprintf("%s 解析耗时 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.HTTPOK:
		s = subj + " 不可用"
	case telemetry.HTTPStatus:
		s = fmt.Sprintf("%s 返回状态码 %s", subj, num(d.Value))
	case telemetry.HTTPLat:
		s = fmt.Sprintf("%s 响应延迟 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.TCPOK:
		s = subj + " 端口连接失败"
	case telemetry.TCPConnectMs:
		s = fmt.Sprintf("%s 连接耗时 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.HostCPUPct:
		s = fmt.Sprintf("%s CPU 使用率 %s%%%s", subj, num(d.Value), thrZh(d, "%"))
	case telemetry.HostMemPct:
		s = fmt.Sprintf("%s 内存使用率 %s%%%s", subj, num(d.Value), thrZh(d, "%"))
	case telemetry.HostDiskPct:
		s = fmt.Sprintf("%s 磁盘使用率 %s%%%s", subj, num(d.Value), thrZh(d, "%"))
	case telemetry.IfaceUp:
		s = fmt.Sprintf("网卡 %s 已断开", d.Target)
	case telemetry.WiFiUp:
		s = fmt.Sprintf("Wi-Fi 网卡 %s 已断开连接", d.Target)
	case telemetry.WiFiSignalDBm:
		s = fmt.Sprintf("Wi-Fi 网卡 %s 信号强度 %s dBm%s", d.Target, num(d.Value), thrZh(d, " dBm"))
	case telemetry.WiFiQualityPct:
		s = fmt.Sprintf("Wi-Fi 网卡 %s 链路质量 %s%%%s", d.Target, num(d.Value), thrZh(d, "%"))
	default:
		s = fmt.Sprintf("%s：%s = %s%s", subj, d.MetricKind, num(d.Value), thrZh(d, ""))
	}
	if d.AgentHost != "" {
		s += fmt.Sprintf("（来自 %s）", d.AgentHost)
	}
	return s
}

func subjectZh(d AlertDetail) string {
	name := d.Target
	if d.TargetName != "" && d.TargetName != d.Target {
		name = fmt.Sprintf("%s（%s）", d.TargetName, d.Target)
	}
	return kindNoun(d.ProbeKind, "zh") + " " + name
}

// thrZh renders the threshold clause "（阈值 ≥ 50%）", or "" when there is no
// meaningful numeric threshold to show.
func thrZh(d AlertDetail, unit string) string {
	sym := cmpSymbol(d.Comparator)
	if sym == "" {
		return ""
	}
	return fmt.Sprintf("（阈值 %s %s%s）", sym, num(d.Threshold), unit)
}

// --- English ---

func describeEn(d AlertDetail) string {
	subj := subjectEn(d)
	var s string
	switch telemetry.MetricKind(d.MetricKind) {
	case telemetry.ICMPLoss:
		if d.Value >= 99.5 {
			s = subj + " is completely unreachable (100% packet loss)"
		} else {
			s = fmt.Sprintf("%s has %s%% packet loss%s", subj, num(d.Value), thrEn(d, "%"))
		}
	case telemetry.ICMPRTTms:
		s = fmt.Sprintf("%s latency is %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.ICMPJitter:
		s = fmt.Sprintf("%s jitter is %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.DNSOK:
		s = subj + " failed to resolve"
	case telemetry.DNSResolve:
		s = fmt.Sprintf("%s resolved in %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.HTTPOK:
		s = subj + " is unavailable"
	case telemetry.HTTPStatus:
		s = fmt.Sprintf("%s returned HTTP %s", subj, num(d.Value))
	case telemetry.HTTPLat:
		s = fmt.Sprintf("%s responded in %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.TCPOK:
		s = subj + " port connection failed"
	case telemetry.TCPConnectMs:
		s = fmt.Sprintf("%s connected in %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.HostCPUPct:
		s = fmt.Sprintf("%s CPU usage is %s%%%s", subj, num(d.Value), thrEn(d, "%"))
	case telemetry.HostMemPct:
		s = fmt.Sprintf("%s memory usage is %s%%%s", subj, num(d.Value), thrEn(d, "%"))
	case telemetry.HostDiskPct:
		s = fmt.Sprintf("%s disk usage is %s%%%s", subj, num(d.Value), thrEn(d, "%"))
	case telemetry.IfaceUp:
		s = fmt.Sprintf("interface %s is down", d.Target)
	case telemetry.WiFiUp:
		s = fmt.Sprintf("Wi-Fi adapter %s is disconnected", d.Target)
	case telemetry.WiFiSignalDBm:
		s = fmt.Sprintf("Wi-Fi adapter %s signal strength is %s dBm%s", d.Target, num(d.Value), thrEn(d, " dBm"))
	case telemetry.WiFiQualityPct:
		s = fmt.Sprintf("Wi-Fi adapter %s link quality is %s%%%s", d.Target, num(d.Value), thrEn(d, "%"))
	default:
		s = fmt.Sprintf("%s: %s = %s%s", subj, d.MetricKind, num(d.Value), thrEn(d, ""))
	}
	if d.AgentHost != "" {
		s += fmt.Sprintf(" (on %s)", d.AgentHost)
	}
	return s
}

func subjectEn(d AlertDetail) string {
	name := d.Target
	if d.TargetName != "" && d.TargetName != d.Target {
		name = fmt.Sprintf("%s (%s)", d.TargetName, d.Target)
	}
	return kindNoun(d.ProbeKind, "en") + " " + name
}

func thrEn(d AlertDetail, unit string) string {
	sym := cmpSymbol(d.Comparator)
	if sym == "" {
		return ""
	}
	return fmt.Sprintf(" (threshold %s %s%s)", sym, num(d.Threshold), unit)
}

// --- shared label maps ---

func kindNoun(kind, lang string) string {
	if normLang(lang) == "en" {
		switch kind {
		case "icmp":
			return "target"
		case "dns":
			return "domain"
		case "http":
			return "site"
		case "tcp":
			return "service"
		case "host":
			return "host"
		}
		return "target"
	}
	switch kind {
	case "icmp":
		return "目标"
	case "dns":
		return "域名"
	case "http":
		return "网站"
	case "tcp":
		return "服务"
	case "host":
		return "主机"
	}
	return "目标"
}

// layerLabel mirrors the HealthLayer labels used in web-console/src/locales.
func layerLabel(layer, lang string) string {
	if normLang(lang) == "en" {
		switch layer {
		case "local":
			return "local"
		case "lan":
			return "LAN"
		case "wan":
			return "WAN"
		case "internet":
			return "Internet"
		case "dns":
			return "DNS"
		case "service":
			return "service"
		case "wireless":
			return "Wi-Fi"
		}
		return "network"
	}
	switch layer {
	case "local":
		return "本机"
	case "lan":
		return "局域网"
	case "wan":
		return "WAN"
	case "internet":
		return "互联网"
	case "dns":
		return "DNS"
	case "service":
		return "服务"
	case "wireless":
		return "无线"
	}
	return "网络"
}

func cmpSymbol(c string) string {
	switch c {
	case "gt":
		return ">"
	case "gte":
		return "≥"
	case "lt":
		return "<"
	case "lte":
		return "≤"
	case "eq":
		return "="
	}
	return ""
}

// num formats a metric value without a trailing ".0" for whole numbers.
func num(v float64) string {
	if v == math.Trunc(v) && !math.IsInf(v, 0) {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}
