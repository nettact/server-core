package notification

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// AlertDetail is one firing alert's structured facts — enough to render a
// human sentence ("website example.com returned HTTP 503") in any supported
// language at delivery time. The incident layer collects these from the frozen
// per-condition evidence (alert_evidence ⨝ alerts ⨝ agents) and hands them to
// Notify, so the language decision stays at the channel boundary rather than
// being baked into a pre-rendered string.
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
	// ReasonCode is the frozen probe failure-reason (telemetry.ProbeReason*): the
	// underlying cause (unreachable / DNS-failed / timeout) rendered as "（原因：…）".
	// 0 (ProbeReasonNone) ⇒ a pure threshold breach with no classified cause.
	ReasonCode int `json:"reason_code"`
}

// AgentDetail is one agent's facts for a connectivity event (agent.offline /
// agent.recovered). Name is frozen at fire (display name → hostname fallback);
// LastSeenAt is the agent's last-seen time when it went offline; Reason is the
// offline cause (unexpected | clean_shutdown | version_incompatible), empty on
// recovery.
type AgentDetail struct {
	AgentID    string    `json:"agent_id"`
	Name       string    `json:"name"`
	LastSeenAt time.Time `json:"last_seen_at"`
	Reason     string    `json:"reason,omitempty"`
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
	if p.Event == "test" {
		if normLang(lang) == "en" {
			return "NetTact test notification"
		}
		return "NetTact 测试通知"
	}
	if p.Event == "agent.offline" {
		if normLang(lang) == "en" {
			return "Agent offline"
		}
		return "Agent 离线告警"
	}
	if p.Event == "agent.recovered" {
		if normLang(lang) == "en" {
			return "Agent connection recovered"
		}
		return "Agent 已恢复连接"
	}
	terminated := p.Event == "incident.terminated" || p.State == "terminated"
	resolved := p.Event == "incident.resolved" || p.State == "resolved"
	if normLang(lang) == "en" {
		switch {
		case terminated:
			return "Monitored object removed"
		case resolved:
			// A group-wide claim is only honest for a merged incident (one incident =
			// the whole group). An unmerged group's incident is a single alert, whose
			// siblings may still be firing — name the group without speaking for it.
			switch {
			case p.GroupName != "" && p.GroupMerged:
				return fmt.Sprintf("Alert group %q recovered", p.GroupName)
			case p.GroupName != "":
				return fmt.Sprintf("Alert recovered (%s)", p.GroupName)
			}
			return "Alert resolved"
		case p.Event == "incident.opened":
			return "Network alert"
		default:
			return "Network alert (updated)"
		}
	}
	switch {
	case terminated:
		return "监控对象已删除"
	case resolved:
		switch {
		case p.GroupName != "" && p.GroupMerged:
			return fmt.Sprintf("告警组「%s」已恢复", p.GroupName)
		case p.GroupName != "":
			return fmt.Sprintf("告警已恢复（%s）", p.GroupName)
		}
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
	if p.Event == "test" {
		if en {
			return "This is a test notification from NetTact."
		}
		return "这是一条来自 NetTact 的测试通知。"
	}
	if p.Event == "agent.offline" {
		n := p.AgentCount
		if n == 0 {
			n = len(p.Agents)
		}
		if en {
			if n == 1 {
				return "1 agent went offline."
			}
			return fmt.Sprintf("%d agents went offline.", n)
		}
		return fmt.Sprintf("%d 个 Agent 已离线。", n)
	}
	if p.Event == "agent.recovered" {
		n := p.AgentCount
		if n == 0 {
			n = len(p.Agents)
		}
		if en {
			if n == 1 {
				return "1 agent reconnected."
			}
			return fmt.Sprintf("%d agents reconnected.", n)
		}
		return fmt.Sprintf("%d 个 Agent 已恢复连接。", n)
	}
	if p.Event == "incident.terminated" || p.State == "terminated" {
		if en {
			return "Monitored object removed; incident terminated."
		}
		return "监控对象已删除，事故终止。"
	}
	if p.Event == "incident.resolved" || p.State == "resolved" {
		// Only a merged incident spans the whole group; an unmerged group's incident
		// is one alert, so "all alerts recovered" would be a false group-wide claim
		// while sibling incidents may still be firing.
		switch {
		case p.GroupName != "" && p.GroupMerged:
			if en {
				return fmt.Sprintf("All alerts in group %q have recovered.", p.GroupName)
			}
			return fmt.Sprintf("告警组「%s」的告警已全部恢复。", p.GroupName)
		case p.GroupName != "":
			if en {
				return fmt.Sprintf("An alert in group %q has recovered.", p.GroupName)
			}
			return fmt.Sprintf("告警组「%s」的一项告警已恢复。", p.GroupName)
		}
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

// RenderLines dispatches to the right per-item renderer for the payload's event:
// agent connectivity events render per-agent lines, everything else renders the
// per-target firing facts. This is the single entry point the webhook / email /
// native channels use, so a new event shape works across all three at once.
func RenderLines(p Payload, lang string) []string {
	switch p.Event {
	case "agent.offline", "agent.recovered":
		return RenderAgentLines(p, lang)
	case "incident.resolved", "incident.terminated":
		return RenderRecoveredLines(p, lang)
	default:
		return RenderDetails(p.Details, lang)
	}
}

// RenderRecoveredLines renders one line per target in a resolved/terminated
// notice, up to maxDetailLines with a "+N more" tail — so the terminal notice
// names the group AND the affected targets, instead of a bare "所有告警已恢复".
// A terminated close is a configuration removal, not a recovery, so its lines say
// the monitoring stopped rather than claiming the target came back healthy.
func RenderRecoveredLines(p Payload, lang string) []string {
	en := normLang(lang) == "en"
	terminated := p.Event == "incident.terminated"
	limit := len(p.RecoveredTargets)
	if limit > maxDetailLines {
		limit = maxDetailLines
	}
	out := make([]string, 0, limit+1)
	for _, rt := range p.RecoveredTargets[:limit] {
		subj := recoveredSubject(rt, lang)
		switch {
		case terminated && en:
			out = append(out, subj+" is no longer monitored")
		case terminated:
			out = append(out, subj+" 已停止监控")
		case en:
			out = append(out, subj+" recovered")
		default:
			out = append(out, subj+" 已恢复")
		}
	}
	if rest := len(p.RecoveredTargets) - limit; rest > 0 {
		if en {
			out = append(out, fmt.Sprintf("+%d more", rest))
		} else {
			out = append(out, fmt.Sprintf("另有 %d 项", rest))
		}
	}
	return out
}

// recoveredSubject names a recovered target as "<kind> <name>（<addr>）", reusing the
// same kind noun / name+addr shape as the firing detail lines.
func recoveredSubject(rt RecoveredTarget, lang string) string {
	name := rt.Addr
	if rt.Name != "" && rt.Name != rt.Addr {
		if normLang(lang) == "en" {
			name = fmt.Sprintf("%s (%s)", rt.Name, rt.Addr)
		} else {
			name = fmt.Sprintf("%s（%s）", rt.Name, rt.Addr)
		}
	}
	return kindNoun(rt.ProbeKind, lang) + " " + name
}

// RenderAgentLines renders one human line per agent in a connectivity event, up
// to maxDetailLines, with a "+N more" tail when truncated. Offline lines carry
// the cause and last-seen time; recovery lines just state the reconnection.
func RenderAgentLines(p Payload, lang string) []string {
	en := normLang(lang) == "en"
	limit := len(p.Agents)
	if limit > maxDetailLines {
		limit = maxDetailLines
	}
	out := make([]string, 0, limit+1)
	for _, a := range p.Agents[:limit] {
		name := a.Name
		if name == "" {
			name = a.AgentID
		}
		if p.Event == "agent.recovered" {
			if en {
				out = append(out, fmt.Sprintf("%s: reconnected", name))
			} else {
				out = append(out, fmt.Sprintf("%s：已恢复连接", name))
			}
			continue
		}
		lastSeen := a.LastSeenAt.Format("2006-01-02 15:04")
		if en {
			out = append(out, fmt.Sprintf("%s: %s, last seen %s", name, offlineReasonLabel(a.Reason, lang), lastSeen))
		} else {
			out = append(out, fmt.Sprintf("%s：%s，最后在线 %s", name, offlineReasonLabel(a.Reason, lang), lastSeen))
		}
	}
	if rest := len(p.Agents) - limit; rest > 0 {
		if en {
			out = append(out, fmt.Sprintf("+%d more", rest))
		} else {
			out = append(out, fmt.Sprintf("另有 %d 个", rest))
		}
	}
	return out
}

// offlineReasonLabel renders a connectivity-alert offline reason as a short
// human phrase.
func offlineReasonLabel(reason, lang string) string {
	en := normLang(lang) == "en"
	switch reason {
	case "clean_shutdown":
		if en {
			return "shut down normally"
		}
		return "正常关机"
	case "version_incompatible":
		if en {
			return "version incompatible"
		}
		return "版本不兼容"
	default: // "unexpected" or ""
		if en {
			return "unexpectedly lost"
		}
		return "意外失联"
	}
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
	case telemetry.ICMPRTTMin:
		s = fmt.Sprintf("%s 最小延迟 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.ICMPRTTMax:
		s = fmt.Sprintf("%s 最大延迟 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.ICMPJitter:
		s = fmt.Sprintf("%s 抖动 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.ICMPSamples:
		s = fmt.Sprintf("%s 有效采样数 %s%s", subj, num(d.Value), thrZh(d, ""))
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
	case telemetry.TCPDNSms:
		s = fmt.Sprintf("%s DNS 解析耗时 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.TCPTLSms:
		s = fmt.Sprintf("%s TLS 握手耗时 %sms%s", subj, num(d.Value), thrZh(d, "ms"))
	case telemetry.TCPErrorClass:
		s = fmt.Sprintf("%s 连接错误：%s", subj, probeReasonZh(int(d.Value)))
	case telemetry.ICMPErrorClass, telemetry.DNSErrorClass, telemetry.HTTPErrorClass:
		// A rule placed directly on a reason series renders the class as its whole
		// sentence (the appended "（原因：…）" clause is suppressed for these kinds).
		s = fmt.Sprintf("%s 探测错误：%s", subj, probeReasonZh(int(d.Value)))
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
	if r := reasonClause(d); r != "" {
		s += fmt.Sprintf("（原因：%s）", r)
	}
	if d.AgentHost != "" {
		s += fmt.Sprintf("（来自 %s）", d.AgentHost)
	}
	return s
}

// reasonClause returns the localized failure reason to append as "（原因：…）", or ""
// when there is no classified cause. It is suppressed for a rule placed directly on
// an *.error_class metric — that sentence already states the class, so appending it
// again would double-render.
func reasonClause(d AlertDetail) string {
	if d.ReasonCode == telemetry.ProbeReasonNone || isErrorClassKind(d.MetricKind) {
		return ""
	}
	return probeReasonZh(d.ReasonCode)
}

func reasonClauseEn(d AlertDetail) string {
	if d.ReasonCode == telemetry.ProbeReasonNone || isErrorClassKind(d.MetricKind) {
		return ""
	}
	return probeReasonEn(d.ReasonCode)
}

// isErrorClassKind reports whether the metric is itself a probe failure-reason
// series, whose sentence already carries the class.
func isErrorClassKind(metricKind string) bool {
	switch telemetry.MetricKind(metricKind) {
	case telemetry.TCPErrorClass, telemetry.ICMPErrorClass, telemetry.DNSErrorClass, telemetry.HTTPErrorClass:
		return true
	}
	return false
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
	case telemetry.ICMPRTTMin:
		s = fmt.Sprintf("%s min latency is %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.ICMPRTTMax:
		s = fmt.Sprintf("%s max latency is %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.ICMPJitter:
		s = fmt.Sprintf("%s jitter is %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.ICMPSamples:
		s = fmt.Sprintf("%s valid samples is %s%s", subj, num(d.Value), thrEn(d, ""))
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
	case telemetry.TCPDNSms:
		s = fmt.Sprintf("%s DNS resolved in %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.TCPTLSms:
		s = fmt.Sprintf("%s TLS handshake in %sms%s", subj, num(d.Value), thrEn(d, "ms"))
	case telemetry.TCPErrorClass:
		s = fmt.Sprintf("%s connection error: %s", subj, probeReasonEn(int(d.Value)))
	case telemetry.ICMPErrorClass, telemetry.DNSErrorClass, telemetry.HTTPErrorClass:
		// A rule placed directly on a reason series renders the class as its whole
		// sentence (the appended " (reason: …)" clause is suppressed for these kinds).
		s = fmt.Sprintf("%s probe error: %s", subj, probeReasonEn(int(d.Value)))
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
	if r := reasonClauseEn(d); r != "" {
		s += fmt.Sprintf(" (reason: %s)", r)
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

// probeReasonZh/En render a probe.*.error_class code (telemetry.ProbeReason*) as a
// short human reason, shared by the TCP error-class sentence and the appended
// "（原因：…）" clause on every probe. The wording is probe-neutral: a timeout may be
// a lost ICMP echo, not a "connection", and a refusal may be a DNS server
// declining a query, not a closed port. Unknown codes fall back to the raw number.
func probeReasonZh(code int) string {
	switch code {
	case telemetry.ProbeReasonNone:
		return "无"
	case telemetry.ProbeReasonTimeout:
		return "超时无响应"
	case telemetry.ProbeReasonRefused:
		return "请求被拒绝"
	case telemetry.ProbeReasonUnreachable:
		return "网络不可达"
	case telemetry.ProbeReasonDNS:
		return "DNS 解析失败"
	case telemetry.ProbeReasonTLS:
		return "TLS 握手失败"
	case telemetry.ProbeReasonOther:
		return "其它错误"
	}
	return fmt.Sprintf("未知错误（%d）", code)
}

func probeReasonEn(code int) string {
	switch code {
	case telemetry.ProbeReasonNone:
		return "none"
	case telemetry.ProbeReasonTimeout:
		return "timed out (no response)"
	case telemetry.ProbeReasonRefused:
		return "refused by peer"
	case telemetry.ProbeReasonUnreachable:
		return "network unreachable"
	case telemetry.ProbeReasonDNS:
		return "DNS resolution failed"
	case telemetry.ProbeReasonTLS:
		return "TLS handshake failed"
	case telemetry.ProbeReasonOther:
		return "other error"
	}
	return fmt.Sprintf("unknown error (%d)", code)
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
