package notification

import (
	"strings"
	"testing"

	"github.com/nettact/protocol/telemetry"
)

// TestReasonClause verifies the "（原因：…）" / " (reason: …)" suffix is appended to a
// firing detail when a failure reason is frozen, and suppressed both when there is
// no reason and when the metric is itself an error_class series (no double-render).
func TestReasonClause(t *testing.T) {
	// ICMP 100% loss with a frozen "unreachable" reason.
	loss := FaultDetail{
		ProbeKind: "icmp", MetricKind: string(telemetry.ICMPLoss), Target: "1.1.1.1",
		Comparator: "gte", Threshold: 50, Value: 100, ReasonCode: telemetry.ProbeReasonUnreachable,
	}
	if got := DescribeDetail(loss, "zh"); !strings.Contains(got, "（原因：网络不可达）") {
		t.Errorf("zh reason suffix missing: %q", got)
	}
	if got := DescribeDetail(loss, "en"); !strings.Contains(got, "(reason: network unreachable)") {
		t.Errorf("en reason suffix missing: %q", got)
	}

	// No reason (pure threshold breach) → no suffix.
	noReason := FaultDetail{ProbeKind: "icmp", MetricKind: string(telemetry.ICMPRTTms), Target: "1.1.1.1", Value: 40, ReasonCode: telemetry.ProbeReasonNone}
	if got := DescribeDetail(noReason, "zh"); strings.Contains(got, "原因") {
		t.Errorf("unexpected reason suffix: %q", got)
	}

	// A rule ON an error_class metric already states the class → must not double-render.
	onClass := FaultDetail{
		ProbeKind: "tcp", MetricKind: string(telemetry.TCPErrorClass), Target: "host:443",
		Value: float64(telemetry.ProbeReasonRefused), ReasonCode: telemetry.ProbeReasonRefused,
	}
	if got := DescribeDetail(onClass, "zh"); strings.Contains(got, "（原因") || !strings.Contains(got, "请求被拒绝") {
		t.Errorf("error_class detail = %q, want the class once, no reason suffix", got)
	}
	// The non-TCP error_class kinds render the class too instead of a raw "kind = 3".
	onICMPClass := FaultDetail{
		ProbeKind: "icmp", MetricKind: string(telemetry.ICMPErrorClass), Target: "1.1.1.1",
		Value: float64(telemetry.ProbeReasonUnreachable), ReasonCode: telemetry.ProbeReasonUnreachable,
	}
	if got := DescribeDetail(onICMPClass, "zh"); !strings.Contains(got, "探测错误：网络不可达") || strings.Contains(got, "error_class") {
		t.Errorf("icmp error_class detail = %q, want a rendered class, not the raw kind", got)
	}
}

// TestReasonDetailRendering verifies the frozen raw detail is appended to the
// localized class as "<label> · <detail>" — in the "（原因：…）"/" (reason: …)" clause
// and inline in the error_class direct sentence — plus the HTTPStatus
// double-statement suppression and the new code labels.
func TestReasonDetailRendering(t *testing.T) {
	// Reason clause carries the raw detail after the localized label.
	loss := FaultDetail{
		ProbeKind: "icmp", MetricKind: string(telemetry.ICMPLoss), Target: "1.1.1.1",
		Comparator: "gte", Threshold: 50, Value: 100,
		ReasonCode: telemetry.ProbeReasonUnreachable, ReasonDetail: "sendto: network is unreachable",
	}
	if got := DescribeDetail(loss, "zh"); !strings.Contains(got, "（原因：网络不可达 · sendto: network is unreachable）") {
		t.Errorf("zh detail clause missing: %q", got)
	}
	if got := DescribeDetail(loss, "en"); !strings.Contains(got, "(reason: network unreachable · sendto: network is unreachable)") {
		t.Errorf("en detail clause missing: %q", got)
	}

	// probe.http.status already states the code in its own sentence: an HTTPStatus
	// reason on it must not double-state ("返回状态码 503（原因：状态码不符合预期 · HTTP 503）").
	status := FaultDetail{
		ProbeKind: "http", MetricKind: string(telemetry.HTTPStatus), Target: "https://example.com",
		Comparator: "eq", Value: 503,
		ReasonCode: telemetry.ProbeReasonHTTPStatus, ReasonDetail: "HTTP 503",
	}
	if got := DescribeDetail(status, "zh"); strings.Contains(got, "原因") || !strings.Contains(got, "返回状态码 503") {
		t.Errorf("zh http.status detail = %q, want the status once, no reason clause", got)
	}
	if got := DescribeDetail(status, "en"); strings.Contains(got, "reason:") {
		t.Errorf("en http.status detail = %q, want no reason clause", got)
	}
	// …but the same reason on a DIFFERENT metric (probe.http.ok) still renders it.
	okDown := FaultDetail{
		ProbeKind: "http", MetricKind: string(telemetry.HTTPOK), Target: "https://example.com",
		Comparator: "lt", Threshold: 1, Value: 0,
		ReasonCode: telemetry.ProbeReasonHTTPStatus, ReasonDetail: "HTTP 503",
	}
	if got := DescribeDetail(okDown, "zh"); !strings.Contains(got, "（原因：状态码不符合预期 · HTTP 503）") {
		t.Errorf("zh http.ok detail clause missing: %q", got)
	}

	// A rule ON an error_class series carries the detail inline, exactly once.
	onClass := FaultDetail{
		ProbeKind: "tcp", MetricKind: string(telemetry.TCPErrorClass),
		TargetName: "db", Target: "db.example.test:5432",
		Value:      float64(telemetry.ProbeReasonRefused),
		ReasonCode: telemetry.ProbeReasonRefused, ReasonDetail: "dial tcp 10.0.0.5:5432: connect: connection refused",
	}
	if got := DescribeDetail(onClass, "zh"); !strings.Contains(got, "连接错误：请求被拒绝 · dial tcp 10.0.0.5:5432: connect: connection refused") ||
		strings.Contains(got, "（原因") {
		t.Errorf("zh error_class detail = %q, want inline detail once", got)
	}
	if got := DescribeDetail(onClass, "en"); !strings.Contains(got, "connection error: refused by peer · dial tcp 10.0.0.5:5432: connect: connection refused") {
		t.Errorf("en error_class detail = %q, want inline detail", got)
	}

	// New code labels (spot checks).
	for _, tc := range []struct {
		code   int
		zh, en string
	}{
		{telemetry.ProbeReasonDNSNXDomain, "域名不存在", "domain does not exist (NXDOMAIN)"},
		{telemetry.ProbeReasonTLSExpired, "证书已过期", "certificate expired"},
		{telemetry.ProbeReasonHTTPStatus, "状态码不符合预期", "unexpected HTTP status"},
	} {
		if got := probeReasonZh(tc.code); got != tc.zh {
			t.Errorf("probeReasonZh(%d) = %q, want %q", tc.code, got, tc.zh)
		}
		if got := probeReasonEn(tc.code); got != tc.en {
			t.Errorf("probeReasonEn(%d) = %q, want %q", tc.code, got, tc.en)
		}
	}
}

// TestEveryReasonCodeHasBothLabels is the guard that keeps failure causes readable
// as the enum grows. A probe classifies a failure into one of these codes and the
// code is frozen onto the fault (and onto a fluctuation), so a code added without
// labels does not fail loudly — it renders as "未知错误（84）" in the very place the
// operator went to find out what broke. The list is maintained by hand on purpose:
// adding a constant should make someone add its two sentences.
func TestEveryReasonCodeHasBothLabels(t *testing.T) {
	codes := []int{
		telemetry.ProbeReasonNone,
		telemetry.ProbeReasonTimeout,
		telemetry.ProbeReasonRefused,
		telemetry.ProbeReasonUnreachable,
		telemetry.ProbeReasonDNS,
		telemetry.ProbeReasonTLS,
		telemetry.ProbeReasonReset,
		telemetry.ProbeReasonOther,
		telemetry.ProbeReasonDNSNXDomain,
		telemetry.ProbeReasonDNSServFail,
		telemetry.ProbeReasonDNSNoRecord,
		telemetry.ProbeReasonTLSExpired,
		telemetry.ProbeReasonTLSUntrusted,
		telemetry.ProbeReasonTLSHostname,
		telemetry.ProbeReasonHTTPStatus,
		telemetry.ProbeReasonHTTPKeyword,
		telemetry.ProbeReasonProxyConnect,
		telemetry.ProbeReasonProxyAuth,
		telemetry.ProbeReasonProxyDNS,
		telemetry.ProbeReasonProxyRefused,
		telemetry.ProbeReasonProxyConfig,
	}
	for _, code := range codes {
		zh, en := probeReasonZh(code), probeReasonEn(code)
		if zh == "" || strings.Contains(zh, "未知错误") {
			t.Errorf("probeReasonZh(%d) = %q: every classified cause needs a Chinese label", code, zh)
		}
		if en == "" || strings.Contains(en, "unknown error") {
			t.Errorf("probeReasonEn(%d) = %q: every classified cause needs an English label", code, en)
		}
	}
	// The fallback still has to work, since an older server can meet a newer agent.
	if got := probeReasonZh(9999); !strings.Contains(got, "9999") {
		t.Errorf("unknown zh code should name the number, got %q", got)
	}
	if got := probeReasonEn(9999); !strings.Contains(got, "9999") {
		t.Errorf("unknown en code should name the number, got %q", got)
	}
}

// TestResolvedWithGroup verifies the recovery notice wording: a MERGED incident may
// claim the whole group recovered and lists the recovered targets; an UNMERGED
// (per-alert) incident names the group without a group-wide claim; and a payload
// with no group name falls back to the original anonymous wording.
func TestResolvedWithGroup(t *testing.T) {
	merged := Payload{
		Event: "incident.resolved", State: "resolved", GroupName: "客厅网络", GroupMerged: true,
		RecoveredTargets: []RecoveredTarget{
			{Name: "商城", Addr: "https://example.com", ProbeKind: "http"},
			{Addr: "1.1.1.1", ProbeKind: "icmp"},
		},
	}
	if got := RenderTitle(merged, "zh"); got != "监控组「客厅网络」故障已恢复" {
		t.Errorf("zh merged title = %q", got)
	}
	if got := RenderTitle(merged, "en"); got != `Fault group "客厅网络" recovered` {
		t.Errorf("en merged title = %q", got)
	}
	if got := RenderScope(merged, "zh"); !strings.Contains(got, "客厅网络") || !strings.Contains(got, "已全部恢复") {
		t.Errorf("zh merged scope = %q", got)
	}
	lines := RenderLines(merged, "zh")
	if len(lines) != 2 {
		t.Fatalf("want 2 recovered lines, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "商城") || !strings.Contains(lines[0], "已恢复") {
		t.Errorf("recovered line = %q", lines[0])
	}

	// Unmerged: each fault has its own incident, so no "all recovered" claim.
	unmerged := Payload{Event: "incident.resolved", State: "resolved", GroupName: "客厅网络"}
	if got := RenderTitle(unmerged, "zh"); got != "故障已恢复（客厅网络）" {
		t.Errorf("zh unmerged title = %q", got)
	}
	if got := RenderScope(unmerged, "zh"); !strings.Contains(got, "一项故障已恢复") || strings.Contains(got, "全部") {
		t.Errorf("zh unmerged scope = %q", got)
	}
	if got := RenderScope(unmerged, "en"); !strings.Contains(got, "A fault in group") {
		t.Errorf("en unmerged scope = %q", got)
	}

	// No group name → falls back to the original anonymous wording.
	bare := Payload{Event: "incident.resolved", State: "resolved"}
	if got := RenderTitle(bare, "zh"); got != "故障已恢复" {
		t.Errorf("bare title = %q", got)
	}
	if got := RenderScope(bare, "zh"); got != "所有故障已恢复。" {
		t.Errorf("bare scope = %q", got)
	}
}

// TestRecoveryNoticeOnlyClaimsRecovery pins the wording contract that survives
// the termination path being removed entirely: a recovery notice is the only
// terminal notice the system sends, and every line it renders must describe a
// target that actually came back. A configuration termination sends nothing, so
// there is no path by which "已恢复" can be attached to a deleted monitor.
func TestRecoveryNoticeOnlyClaimsRecovery(t *testing.T) {
	p := Payload{
		Event: "incident.resolved", State: "resolved", GroupName: "客厅网络", GroupMerged: true,
		RecoveredTargets: []RecoveredTarget{{Name: "商城", Addr: "https://example.com", ProbeKind: "http"}},
	}
	zh := RenderLines(p, "zh")
	if len(zh) != 1 || !strings.Contains(zh[0], "已恢复") || !strings.Contains(zh[0], "商城") {
		t.Errorf("zh recovery lines = %v, want the recovered target named", zh)
	}
	en := RenderLines(p, "en")
	if len(en) != 1 || !strings.Contains(en[0], "recovered") {
		t.Errorf("en recovery lines = %v, want 'recovered'", en)
	}
}
