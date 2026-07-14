package notification

import "testing"

// TestRenderTerminatedVsResolved verifies the deletion-termination close renders
// as a termination — not a healthy recovery — in both languages, while a normal
// resolved close keeps its recovery wording. Guards the P2 fix: a payload with
// event/state "terminated" must never be titled/described as "resolved".
func TestRenderTerminatedVsResolved(t *testing.T) {
	terminated := Payload{Event: "incident.terminated", State: "terminated"}
	resolved := Payload{Event: "incident.resolved", State: "resolved"}

	cases := []struct {
		name       string
		p          Payload
		lang       string
		wantTitle  string
		wantScope  string
	}{
		{"terminated zh", terminated, "zh", "监控对象已删除", "监控对象已删除，事故终止。"},
		{"terminated en", terminated, "en", "Monitored object removed", "Monitored object removed; incident terminated."},
		{"resolved zh", resolved, "zh", "告警已恢复", "所有告警已恢复。"},
		{"resolved en", resolved, "en", "Alert resolved", "All alerts resolved."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RenderTitle(c.p, c.lang); got != c.wantTitle {
				t.Errorf("RenderTitle = %q, want %q", got, c.wantTitle)
			}
			if got := RenderScope(c.p, c.lang); got != c.wantScope {
				t.Errorf("RenderScope = %q, want %q", got, c.wantScope)
			}
		})
	}
}
