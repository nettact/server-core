package notification

import (
	"strings"
	"testing"
)

// TestDescribeDetail checks that each probe/metric produces a human sentence
// naming the target, the fault, and the measured value vs threshold, in both
// languages.
func TestDescribeDetail(t *testing.T) {
	cases := []struct {
		name   string
		d      FaultDetail
		wantZh []string // all must be substrings
		wantEn []string
	}{
		{
			name:   "icmp total loss",
			d:      FaultDetail{ProbeKind: "icmp", MetricKind: "probe.icmp.loss_pct", Comparator: "gte", Threshold: 50, Value: 100, Target: "1.1.1.1"},
			wantZh: []string{"目标 1.1.1.1", "完全不可达", "100%"},
			wantEn: []string{"target 1.1.1.1", "completely unreachable"},
		},
		{
			name:   "icmp partial loss",
			d:      FaultDetail{ProbeKind: "icmp", MetricKind: "probe.icmp.loss_pct", Comparator: "gte", Threshold: 50, Value: 70, Target: "8.8.8.8"},
			wantZh: []string{"目标 8.8.8.8", "丢包率 70%", "阈值 ≥ 50%"},
			wantEn: []string{"target 8.8.8.8", "70% packet loss", "threshold ≥ 50%"},
		},
		{
			name:   "icmp rtt",
			d:      FaultDetail{ProbeKind: "icmp", MetricKind: "probe.icmp.rtt_ms", Comparator: "gt", Threshold: 200, Value: 250, Target: "gateway", TargetName: "网关"},
			wantZh: []string{"目标 网关（gateway）", "延迟 250ms", "阈值 > 200ms"},
			wantEn: []string{"target 网关 (gateway)", "latency is 250ms", "threshold > 200ms"},
		},
		{
			name:   "dns fail",
			d:      FaultDetail{ProbeKind: "dns", MetricKind: "probe.dns.ok", Comparator: "lt", Threshold: 1, Value: 0, Target: "example.com"},
			wantZh: []string{"域名 example.com", "解析失败"},
			wantEn: []string{"domain example.com", "failed to resolve"},
		},
		{
			name:   "http status",
			d:      FaultDetail{ProbeKind: "http", MetricKind: "probe.http.status", Comparator: "eq", Threshold: 200, Value: 503, Target: "https://a.test", AgentHost: "node-1"},
			wantZh: []string{"网站 https://a.test", "返回状态码 503", "来自 node-1"},
			wantEn: []string{"site https://a.test", "returned HTTP 503", "on node-1"},
		},
		{
			name:   "tcp fail",
			d:      FaultDetail{ProbeKind: "tcp", MetricKind: "probe.tcp.ok", Comparator: "lt", Threshold: 1, Value: 0, Target: "db:5432"},
			wantZh: []string{"服务 db:5432", "端口连接失败"},
			wantEn: []string{"service db:5432", "port connection failed"},
		},
		{
			name:   "host cpu",
			d:      FaultDetail{ProbeKind: "host", MetricKind: "host.cpu.pct", Comparator: "gt", Threshold: 90, Value: 95, Target: "host", TargetName: "web01"},
			wantZh: []string{"主机 web01（host）", "CPU 使用率 95%", "阈值 > 90%"},
			wantEn: []string{"host web01 (host)", "CPU usage is 95%", "threshold > 90%"},
		},
		{
			// A system-status fault about the whole machine has no sub-target, so the
			// subject must not render an empty parenthetical.
			name:   "host load per core",
			d:      FaultDetail{ProbeKind: "host", MetricKind: "host.load.per_core", Comparator: "gte", Threshold: 2, Value: 4, TargetName: "web01"},
			wantZh: []string{"主机 web01", "每核负载 4", "阈值 ≥ 2"},
			wantEn: []string{"host web01", "load per core is 4", "threshold ≥ 2"},
		},
		{
			name:   "host download rate",
			d:      FaultDetail{ProbeKind: "host", MetricKind: "host.net.rx_mbps", Comparator: "gte", Threshold: 100, Value: 200, TargetName: "web01"},
			wantZh: []string{"下载速率 200 Mbps", "阈值 ≥ 100 Mbps"},
			wantEn: []string{"download rate is 200 Mbps", "threshold ≥ 100 Mbps"},
		},
		{
			name:   "host upload rate",
			d:      FaultDetail{ProbeKind: "host", MetricKind: "host.net.tx_mbps", Comparator: "gte", Threshold: 20, Value: 45, TargetName: "web01"},
			wantZh: []string{"上传速率 45 Mbps"},
			wantEn: []string{"upload rate is 45 Mbps"},
		},
		{
			// A disk names its mount, which is what makes one of four full disks a
			// legible sentence rather than "a disk is full".
			name:   "host disk mount",
			d:      FaultDetail{ProbeKind: "host", MetricKind: "host.disk.pct", Comparator: "gte", Threshold: 90, Value: 97, Target: "C:", TargetName: "web01"},
			wantZh: []string{"主机 web01（C:）", "磁盘使用率 97%"},
			wantEn: []string{"host web01 (C:)", "disk usage is 97%"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zh := DescribeDetail(tc.d, "zh")
			for _, w := range tc.wantZh {
				if !strings.Contains(zh, w) {
					t.Errorf("zh %q missing %q", zh, w)
				}
			}
			en := DescribeDetail(tc.d, "en")
			for _, w := range tc.wantEn {
				if !strings.Contains(en, w) {
					t.Errorf("en %q missing %q", en, w)
				}
			}
		})
	}
}

// TestRenderDetailsTruncation checks the "top N + more" behavior and worst-first
// ordering.
func TestRenderDetailsTruncation(t *testing.T) {
	var details []FaultDetail
	for i := 0; i < 7; i++ {
		details = append(details, FaultDetail{
			ProbeKind: "tcp", MetricKind: "probe.tcp.ok", Comparator: "lt", Threshold: 1,
			Target: "svc" + string(rune('0'+i)), Layer: "service", Severity: "warn",
		})
	}
	// A single critical alert must sort to the front.
	details = append(details, FaultDetail{
		ProbeKind: "http", MetricKind: "probe.http.ok", Comparator: "lt", Threshold: 1,
		Target: "critical.test", Layer: "service", Severity: "critical",
	})

	lines := RenderDetails(details, "zh")
	if len(lines) != maxDetailLines+1 {
		t.Fatalf("got %d lines, want %d", len(lines), maxDetailLines+1)
	}
	if !strings.Contains(lines[0], "critical.test") {
		t.Errorf("critical alert should sort first, got %q", lines[0])
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, "另有") || !strings.Contains(last, "3") { // 8 total - 5 shown = 3
		t.Errorf("expected '另有 3 项' summary line, got %q", last)
	}

	en := RenderDetails(details, "en")
	if !strings.Contains(en[len(en)-1], "+3 more") {
		t.Errorf("expected '+3 more', got %q", en[len(en)-1])
	}
}

// TestRenderSummary checks the stored/console summary leads with the concrete
// top fault, counts extras, and falls back to the scope line when empty.
func TestRenderSummary(t *testing.T) {
	http503 := FaultDetail{ProbeKind: "http", MetricKind: "probe.http.status", Comparator: "eq", Threshold: 200, Value: 503, Target: "https://a.test", Severity: "critical", Layer: "service"}
	tcpDown := FaultDetail{ProbeKind: "tcp", MetricKind: "probe.tcp.ok", Comparator: "lt", Threshold: 1, Value: 0, Target: "db:5432", Severity: "warn", Layer: "service"}

	// Single fault: summary is exactly that fault line.
	one := Payload{Event: "incident.opened", State: "open", Scope: "single", Details: []FaultDetail{http503}}
	if got := RenderSummary(one, "zh"); !strings.Contains(got, "返回状态码 503") || strings.Contains(got, "共") {
		t.Errorf("single summary = %q", got)
	}

	// Multiple: leads with worst (critical http) and counts the total.
	many := Payload{Event: "incident.opened", State: "open", Scope: "site", Details: []FaultDetail{tcpDown, http503}}
	got := RenderSummary(many, "zh")
	if !strings.Contains(got, "返回状态码 503") || !strings.Contains(got, "共 2 项") {
		t.Errorf("multi summary = %q, want top fault + count", got)
	}

	// Resolved / no details: fall back to the scope line.
	resolved := Payload{Event: "incident.resolved", State: "resolved"}
	if got := RenderSummary(resolved, "zh"); !strings.Contains(got, "已恢复") {
		t.Errorf("resolved summary = %q", got)
	}
}

// TestRenderTitleAndScope checks headline + diagnosis wording, including resolved.
func TestRenderTitleAndScope(t *testing.T) {
	open := Payload{Event: "incident.opened", State: "open", Scope: "site", AgentCount: 3, SuspectedLayer: "internet"}
	if got := RenderTitle(open, "zh"); got != "网络故障" {
		t.Errorf("zh title = %q", got)
	}
	if got := RenderTitle(open, "en"); got != "Network fault" {
		t.Errorf("en title = %q", got)
	}
	if got := RenderScope(open, "zh"); !strings.Contains(got, "站点级") || !strings.Contains(got, "3 个节点") || !strings.Contains(got, "互联网") {
		t.Errorf("zh scope = %q", got)
	}
	if got := RenderScope(open, "en"); !strings.Contains(got, "Site-wide") || !strings.Contains(got, "3 nodes") || !strings.Contains(got, "Internet") {
		t.Errorf("en scope = %q", got)
	}

	resolved := Payload{Event: "incident.resolved", State: "resolved"}
	if got := RenderTitle(resolved, "zh"); got != "故障已恢复" {
		t.Errorf("zh resolved title = %q", got)
	}
	if got := RenderScope(resolved, "en"); !strings.Contains(got, "recovered") {
		t.Errorf("en resolved scope = %q", got)
	}
}
