package notification

import (
	"strings"
	"testing"
)

func TestDescribeWiFiAlertDetails(t *testing.T) {
	cases := []struct {
		name   string
		detail AlertDetail
		zh     []string
		en     []string
	}{
		{
			name:   "disconnected",
			detail: AlertDetail{ProbeKind: "host", MetricKind: "wifi.up", Comparator: "lt", Threshold: 1, Value: 0, Target: "wlan0", AgentHost: "node-wifi"},
			zh:     []string{"Wi-Fi 网卡 wlan0", "断开连接", "来自 node-wifi"},
			en:     []string{"Wi-Fi adapter wlan0", "disconnected", "on node-wifi"},
		},
		{
			name:   "low signal",
			detail: AlertDetail{ProbeKind: "host", MetricKind: "wifi.signal_dbm", Comparator: "lt", Threshold: -70, Value: -75, Target: "en0"},
			zh:     []string{"Wi-Fi 网卡 en0", "信号强度 -75 dBm", "阈值 < -70 dBm"},
			en:     []string{"Wi-Fi adapter en0", "signal strength is -75 dBm", "threshold < -70 dBm"},
		},
		{
			name:   "low quality",
			detail: AlertDetail{ProbeKind: "host", MetricKind: "wifi.quality_pct", Comparator: "lt", Threshold: 60, Value: 45, Target: "Wi-Fi"},
			zh:     []string{"Wi-Fi 网卡 Wi-Fi", "链路质量 45%", "阈值 < 60%"},
			en:     []string{"Wi-Fi adapter Wi-Fi", "link quality is 45%", "threshold < 60%"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.zh {
				if got := DescribeDetail(tc.detail, "zh"); !strings.Contains(got, want) {
					t.Errorf("zh %q missing %q", got, want)
				}
			}
			for _, want := range tc.en {
				if got := DescribeDetail(tc.detail, "en"); !strings.Contains(got, want) {
					t.Errorf("en %q missing %q", got, want)
				}
			}
		})
	}
}
