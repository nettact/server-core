package incidentops

import "testing"

// TestHostFaultsNeverTriggerATrace: a traceroute answers "where on the path did
// this break". A full disk or a pegged CPU has no path, so dispatching a
// diagnostic for one would spend an agent's probe budget measuring something the
// fault was never about. The guard is structural (probe_kind "host" matches no
// case), which is exactly the kind of thing a later refactor can lose silently.
func TestHostFaultsNeverTriggerATrace(t *testing.T) {
	for _, kind := range []string{
		"host.cpu.pct", "host.mem.pct", "host.disk.pct",
		"host.load.per_core", "host.net.rx_mbps", "host.net.tx_mbps",
	} {
		if TraceEligibleMetric("host", kind) {
			t.Errorf("TraceEligibleMetric(host, %q) = true, want false", kind)
		}
	}
	// The probe families are unaffected.
	if !TraceEligibleMetric("icmp", "probe.icmp.loss_pct") {
		t.Error("icmp probes stopped qualifying for a trace")
	}
}
