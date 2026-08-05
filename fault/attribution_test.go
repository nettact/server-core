package fault

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// Attribution rule-table tests (INCIDENT-003). Every rule is exercised against
// the real store: the incident's firing members, the agent-wide sibling set and
// the reference detector states are all seeded rows, so the SQL and the Go
// logic are both under test.

func (h *harness) seedIncident(id string) {
	h.t.Helper()
	h.exec(`INSERT INTO incidents(id, site_id, group_id, open_key, opened_at)
		VALUES(?, 'site_default', 'mg', 'key_'||?, ?)`, id, id, time.Now().UTC())
}

// seedFiringSignal inserts one firing fault signal on agent_a, creating the
// owning incident if needed (open_key unique per incident id).
func (h *harness) seedFiringSignal(incidentID, targetID, targetName, targetAddr, probeKind string, reasonCode int, proxy memberFact) {
	h.t.Helper()
	now := time.Now().UTC()
	h.exec(`INSERT OR IGNORE INTO incidents(id, site_id, group_id, open_key, opened_at)
		VALUES(?, 'site_default', 'mg', 'key_'||?, ?)`, incidentID, incidentID, now)
	h.exec(`INSERT INTO fault_signals(id, site_id, agent_id, detector_key, probe_kind, target_id, group_id,
		group_name, target_name, target_addr, layer, severity, state, reason_code,
		proxy_id, proxy_type, proxy_addr, observed_at, confirmed_at, incident_id)
		VALUES(?, 'site_default', 'agent_a', 'availability', ?, ?, 'mg', 'Default', ?, ?, '', 'warn', 'firing', ?,
		       ?, ?, ?, ?, ?, ?)`,
		targetID+"_sig", probeKind, targetID, targetName, targetAddr, reasonCode,
		proxy.proxyID, proxy.proxyType, proxy.proxyAddr, now, now, incidentID)
}

func (h *harness) seedProxy(id, name, typ string) {
	h.t.Helper()
	now := time.Now().UTC()
	h.exec(`INSERT INTO proxies(id, site_id, name, type, created_at, updated_at)
		VALUES(?, 'site_default', ?, ?, ?, ?)`, id, name, typ, now, now)
}

// seedRef creates a healthy-or-failing reference detector for agent_a: the
// target, its active monitor_status row and its detector_state counters.
// lastRoundAgo == 0 uses now (fresh); a negative value forces staleness.
func (h *harness) seedRef(targetID, kind, name, target string, failRounds int64, lastRoundAgo time.Duration, proxyID string) {
	h.t.Helper()
	now := time.Now().UTC()
	lastTS := now.Unix()
	if lastRoundAgo != 0 {
		lastTS = now.Add(-lastRoundAgo).Unix()
	}
	h.exec(`INSERT INTO probe_tasks(id, site_id, group_id, kind, name, target, params, enabled, config_serial, proxy_id)
		VALUES(?, 'site_default', 'mg', ?, ?, ?, '{}', 1, 1, NULLIF(?,''))`, targetID, kind, name, target, proxyID)
	h.exec(`INSERT INTO monitor_status(agent_id, monitor_id, status, config_version, updated_at)
		VALUES('agent_a', ?, 'active', 1, ?)`, targetID, now)
	h.exec(`INSERT INTO detector_state(target_id, agent_id, fail_rounds, ok_rounds, last_round_ts, pending_fails, updated_at)
		VALUES(?, 'agent_a', ?, 0, ?, '[]', ?)`, targetID, failRounds, lastTS, now)
}

func attributionFor(t *testing.T, db *store.DB, incidentID string, traces []traceFact) (string, []notification.AttributionClue) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	members, err := loadMembers(ctx, tx, incidentID)
	if err != nil {
		t.Fatalf("loadMembers: %v", err)
	}
	loc, clues, err := computeAttribution(ctx, tx, members, traces)
	if err != nil {
		t.Fatalf("computeAttribution: %v", err)
	}
	return loc, clues
}

func clueKinds(clues []notification.AttributionClue) []string {
	var out []string
	for _, c := range clues {
		out = append(out, c.Kind)
	}
	return out
}

func hasClueKinds(clues []notification.AttributionClue, kinds ...string) bool {
	got := map[string]bool{}
	for _, c := range clues {
		got[c.Kind] = true
	}
	for _, k := range kinds {
		if !got[k] {
			return false
		}
	}
	return true
}

func noProxy() memberFact { return memberFact{} }

func TestAttributionGatewayDownIsRouter(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_gw", "Gateway", "gateway", "gateway", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_2", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationRouter {
		t.Fatalf("location=%q want %q", loc, LocationRouter)
	}
	if !hasClueKinds(clues, notification.ClueGatewayDown, notification.ClueConcurrentPublic) {
		t.Fatalf("clues=%v want gateway_down + concurrent_public_failures", clueKinds(clues))
	}
}

func TestAttributionGatewayDownOnly(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_gw", "Gateway", "gateway", "gateway", telemetry.ProbeReasonTimeout, noProxy())
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationRouter {
		t.Fatalf("location=%q want %q", loc, LocationRouter)
	}
	if len(clues) != 1 || clues[0].Kind != notification.ClueGatewayDown {
		t.Fatalf("clues=%v want only gateway_down", clueKinds(clues))
	}
}

func TestAttributionISPHostDedupAcrossKinds(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	// Two failing "public" targets, same host 1.2.3.4: an ICMP literal and an
	// HTTPS URL must dedupe to ONE host, so this is not an ISP event.
	h.seedFiringSignal("inc_1", "t_a", "SrvA", "1.2.3.4", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_2", "t_b", "SrvB", "https://1.2.3.4/health", "http", telemetry.ProbeReasonTimeout, noProxy())
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc == LocationISP {
		t.Fatalf("same host deduped to one public failure but got isp")
	}
	// A second distinct public host tips it over.
	h.seedFiringSignal("inc_3", "t_c", "SrvC", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationISP {
		t.Fatalf("location=%q want isp", loc)
	}
	if !hasClueKinds(clues, notification.ClueGatewayOK, notification.ClueConcurrentPublic) {
		t.Fatalf("clues=%v want gateway_ok + concurrent_public_failures", clueKinds(clues))
	}
}

func TestAttributionISPPrivateIPDoesNotCount(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	h.seedFiringSignal("inc_1", "t_lan", "Printer", "192.168.1.50", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_2", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc == LocationISP {
		t.Fatalf("private IP counted toward public failures, got isp")
	}
}

func TestAttributionDNSServiceLevel(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	// A DNS-shaped failure with a NON-respond reason (family DNS code) — a respond
	// code like NXDOMAIN would be service-level by the respond rule.
	h.seedFiringSignal("inc_1", "t_dns", "Resolver", "dns.example.com", "dns", telemetry.ProbeReasonDNS, noProxy())
	h.seedRef("t_ip", "icmp", "PublicIP", "9.9.9.9", 0, 0, "")
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationDNS {
		t.Fatalf("location=%q want dns", loc)
	}
	if !hasClueKinds(clues, notification.ClueDNSFail, notification.ClueIPOK) {
		t.Fatalf("clues=%v want dns_fail + ip_ok", clueKinds(clues))
	}
}

func TestAttributionRespondFamilyIsService(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	// An HTTP 500 proves the path works: no gateway, no reference, no trace — the
	// response itself is the evidence, so it must still resolve to the service.
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonHTTPStatus, noProxy())
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationService {
		t.Fatalf("location=%q want service", loc)
	}
	if !hasClueKinds(clues, notification.ClueTargetResponded, notification.ClueReason) {
		t.Fatalf("clues=%v want target_responded + reason", clueKinds(clues))
	}
}

func TestAttributionTLSAttestationResponds(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTLSExpired, noProxy())
	loc, _ := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationService {
		t.Fatalf("TLSExpired (completed cert exchange) should be service, got %q", loc)
	}
}

func TestAttributionNoReferenceFallsBack(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != "" {
		t.Fatalf("location=%q want empty (no reference to compare)", loc)
	}
	if !hasClueKinds(clues, notification.ClueNoReference) {
		t.Fatalf("clues=%v want no_reference advisory", clueKinds(clues))
	}
}

func TestAttributionServiceSingleWithOthersOK(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	h.seedRef("t_pub", "icmp", "PublicIP", "8.8.8.8", 0, 0, "")
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationService {
		t.Fatalf("location=%q want service", loc)
	}
	if !hasClueKinds(clues, notification.ClueOnlyTargetFailing, notification.ClueOthersOK) {
		t.Fatalf("clues=%v want only_target_failing + others_ok", clueKinds(clues))
	}
}

func TestAttributionGatewayUnconfirmedBlocksISP(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	// Gateway mid-streak: failing but unconfirmed — neither healthy nor down.
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 2, 0, "")
	h.seedFiringSignal("inc_1", "t_a", "SrvA", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_2", "t_b", "SrvB", "1.1.1.1", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc == LocationISP {
		t.Fatalf("unconfirmed gateway must not support isp")
	}
	if !hasClueKinds(clues, notification.ClueGatewayUnconfirmed) {
		t.Fatalf("clues=%v want gateway_unconfirmed advisory", clueKinds(clues))
	}
}

func TestAttributionStaleReferenceIsNotHealthy(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	// Reference went silent 30 minutes ago — must not count as healthy.
	h.seedRef("t_pub", "icmp", "PublicIP", "8.8.8.8", 0, 30*time.Minute, "")
	loc, _ := attributionFor(t, h.db, "inc_1", nil)
	if loc == LocationService {
		t.Fatalf("stale reference counted as healthy, got service")
	}
}

func TestAttributionSameProxyFailureIsProxy(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedProxy("px_1", "egress", "socks5")
	proxy := memberFact{proxyID: "px_1", proxyType: "socks5", proxyName: "egress"}
	for i, target := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4", "4.2.2.2"} {
		incID := "inc_1"
		if i > 0 {
			incID = "inc_sib_" + target
		}
		h.seedFiringSignal(incID, "t_tcp_"+target, "ViaProxy", "https://"+target, "tcp", telemetry.ProbeReasonProxyConnect, proxy)
	}
	// A healthy direct reference proves the failure is on the egress path only.
	h.seedRef("t_direct", "icmp", "Direct", "1.0.0.1", 0, 0, "")
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationProxy {
		t.Fatalf("same-proxy egress failures should be proxy, got %q", loc)
	}
	if !hasClueKinds(clues, notification.ClueProxyFail, notification.ClueDirectOK) {
		t.Fatalf("clues=%v want proxy_fail + direct_ok", clueKinds(clues))
	}
	var pf notification.AttributionClue
	for _, c := range clues {
		if c.Kind == notification.ClueProxyFail {
			pf = c
		}
	}
	if pf.Name != "egress" || pf.Type != "socks5" || pf.Count != 5 {
		t.Fatalf("proxy_fail clue=%+v want name=egress type=socks5 count=5", pf)
	}
}

func TestAttributionProxiedFailureDoesNotCountAsPublic(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	// One direct public failure + two proxied egress failures: the proxied ones
	// travel a different path, so there is only ONE public-unreachability signal.
	h.seedFiringSignal("inc_1", "t_direct", "Direct", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	proxy := memberFact{proxyID: "px_1", proxyType: "http"}
	for _, target := range []string{"1.1.1.1", "9.9.9.9"} {
		h.seedIncident("inc_sib_" + target)
		h.seedFiringSignal("inc_sib_"+target, "t_px_"+target, "Proxied", "https://"+target, "http", telemetry.ProbeReasonProxyConnect, proxy)
	}
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc == LocationISP {
		t.Fatalf("proxied failures must not count toward isp")
	}
}

func TestAttributionProxyTargetRefusedIsService(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	// SOCKS5 0x05 (AtTarget) maps to ProbeReasonRefused: the proxy relayed fine and
	// the TARGET refused — service-side, not proxy-side.
	proxy := memberFact{proxyID: "px_1", proxyType: "socks5", proxyName: "egress"}
	h.seedFiringSignal("inc_1", "t_tcp", "Site", "https://example.com", "tcp", telemetry.ProbeReasonRefused, proxy)
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationService {
		t.Fatalf("target-refused through a healthy proxy should be service, got %q", loc)
	}
	if !hasClueKinds(clues, notification.ClueTargetResponded, notification.ClueViaProxy) {
		t.Fatalf("clues=%v want target_responded + via_proxy", clueKinds(clues))
	}
}

func TestAttributionMultiAgentGetsNothing(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_a", "SiteA", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	// A second member on a different agent: the claim boundary is one agent.
	now := time.Now().UTC()
	h.exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status,hostname) VALUES('agent_b','site_default',x'01','h','online','node-2')`)
	h.exec(`INSERT INTO fault_signals(id, site_id, agent_id, detector_key, probe_kind, target_id, group_id,
		group_name, target_name, target_addr, state, observed_at, confirmed_at, incident_id)
		VALUES('sig_b', 'site_default', 'agent_b', 'availability', 'icmp', 't_b', 'mg', 'Default', 'SiteB', '1.1.1.1',
		'firing', ?, ?, 'inc_1')`, now, now)
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc != "" {
		t.Fatalf("multi-agent incident must not get an attribution, got %q", loc)
	}
}

func TestAttributionAgentConnectivityGetsNothing(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	now := time.Now().UTC()
	h.exec(`INSERT INTO fault_signals(id, site_id, agent_id, detector_key, probe_kind, target_id, state,
		observed_at, confirmed_at, incident_id)
		VALUES('sig_ac', 'site_default', 'agent_a', 'agent_connectivity', '', '', 'firing', ?, ?, 'inc_1')`, now, now)
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc != "" {
		t.Fatalf("agent-connectivity incident must not get an attribution, got %q", loc)
	}
}

func TestAttributionTraceUpgradeToISP(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	h.seedFiringSignal("inc_1", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	// Without a trace: one failing public target + healthy gateway → single-service
	// guess, which is the honest first stage.
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc != LocationService {
		t.Fatalf("first stage = %q want service", loc)
	}
	// The trace answers only the LAN (no public hop): the failure sits between the
	// router and the ISP — upgraded to isp.
	traces := []traceFact{{subjectKind: "target", targetID: "t_pub", status: "partial", reached: false, sawAnyHop: true, sawPublicHop: false}}
	loc, clues := attributionFor(t, h.db, "inc_1", traces)
	if loc != LocationISP {
		t.Fatalf("trace died in LAN should upgrade to isp, got %q", loc)
	}
	if !hasClueKinds(clues, notification.ClueGatewayOK, notification.ClueTraceDiedInLAN) {
		t.Fatalf("clues=%v want gateway_ok + trace_died_in_lan", clueKinds(clues))
	}
}

func TestAttributionTraceReachedKeepsService(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	h.seedFiringSignal("inc_1", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	traces := []traceFact{{subjectKind: "target", targetID: "t_pub", status: "succeeded", reached: true, sawAnyHop: true, sawPublicHop: true}}
	loc, clues := attributionFor(t, h.db, "inc_1", traces)
	if loc != LocationService {
		t.Fatalf("trace reached the target → service, got %q", loc)
	}
	if !hasClueKinds(clues, notification.ClueTraceReached) {
		t.Fatalf("clues=%v want trace_reached", clueKinds(clues))
	}
}

func TestAttributionTracePublicThenLost(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	h.seedFiringSignal("inc_1", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	traces := []traceFact{{subjectKind: "target", targetID: "t_pub", status: "partial", reached: false, sawAnyHop: true, sawPublicHop: true, lastPublicHop: "203.0.113.9"}}
	loc, clues := attributionFor(t, h.db, "inc_1", traces)
	if loc != LocationService {
		t.Fatalf("trace lost after a public hop → service, got %q", loc)
	}
	if !hasClueKinds(clues, notification.ClueTracePublicLost) {
		t.Fatalf("clues=%v want trace_public_then_lost", clueKinds(clues))
	}
}

func TestAttributionProxyTraceNoHopsIsNotUnreachable(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedProxy("px_1", "egress", "socks5")
	proxy := memberFact{proxyID: "px_1", proxyType: "socks5", proxyName: "egress"}
	h.seedFiringSignal("inc_1", "t_tcp", "ViaProxy", "https://1.1.1.1", "tcp", telemetry.ProbeReasonProxyConnect, proxy)
	// A proxy trace that was REFUSED before it ran (egress not available,
	// generation mismatch, attestation mismatch): no hops, never reached. It is
	// not evidence the proxy address is unreachable.
	noHops := []traceFact{{subjectKind: "proxy", targetID: "t_tcp", status: "failed", reached: false, sawAnyHop: false, sawPublicHop: false}}
	loc, clues := attributionFor(t, h.db, "inc_1", noHops)
	if loc != LocationProxy {
		t.Fatalf("location=%q want proxy", loc)
	}
	for _, c := range clues {
		if c.Kind == notification.ClueTraceProxyUnreach {
			t.Fatalf("failed proxy trace without hops must not emit trace_proxy_unreachable")
		}
	}
	// A trace that actually ran (hops) and never reached the proxy listener IS
	// unreachable evidence.
	ran := []traceFact{{subjectKind: "proxy", targetID: "t_tcp", status: "partial", reached: false, sawAnyHop: true, sawPublicHop: true, lastPublicHop: "203.0.113.9"}}
	_, clues = attributionFor(t, h.db, "inc_1", ran)
	if !hasClueKinds(clues, notification.ClueTraceProxyUnreach) {
		t.Fatalf("clues=%v want trace_proxy_unreachable for a trace that ran", clueKinds(clues))
	}
}

func TestAttributionNoRunTraceIsNotDiedInLAN(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	// Gateway down + a target trace that never ran (no hops): the target trace
	// says nothing about where the path died, so no trace_died_in_lan clue.
	h.seedFiringSignal("inc_1", "t_gw", "Gateway", "gateway", "gateway", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_2", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	traces := []traceFact{{subjectKind: "target", targetID: "t_pub", status: "failed", reached: false, sawAnyHop: false, sawPublicHop: false}}
	_, clues := attributionFor(t, h.db, "inc_1", traces)
	for _, c := range clues {
		if c.Kind == notification.ClueTraceDiedInLAN {
			t.Fatalf("target trace that never ran must not emit trace_died_in_lan")
		}
	}
}

func TestRecomputeAgentAttributionsUpgradesSibling(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_a")
	h.seedIncident("inc_b")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	// A alone → single-target "service". Then B confirms on the same agent; the
	// agent-wide firing set becomes an ISP-wide outage, so A's attribution must
	// upgrade even though A's own members did not move.
	h.seedFiringSignal("inc_a", "t_a", "SrvA", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())

	ctx := context.Background()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, _, err := RecomputeAttributionTx(ctx, tx, "inc_a"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("recompute A: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var loc string
	if err := h.db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_a'`).Scan(&loc); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if loc != LocationService {
		t.Fatalf("A alone = %q want service", loc)
	}

	// B confirms in a later batch → the batch-end refresh must upgrade A.
	h.seedFiringSignal("inc_b", "t_b", "SrvB", "1.1.1.1", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	tx, err = h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	changed, changedTargets, err := recomputeAgentAttributions(ctx, tx, "agent_a")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("recomputeAgentAttributions: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := h.db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_a'`).Scan(&loc); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if loc != LocationISP {
		t.Fatalf("A after sibling confirm = %q want isp", loc)
	}
	var hasA bool
	for _, id := range changed {
		if id == "inc_a" {
			hasA = true
		}
	}
	if !hasA {
		t.Fatalf("changed incidents = %v, want inc_a reported", changed)
	}
	var hasTargetA bool
	for _, tid := range changedTargets {
		if tid == "t_a" {
			hasTargetA = true
		}
	}
	if !hasTargetA {
		t.Fatalf("changed targets = %v, want t_a reported", changedTargets)
	}
}

// seedTraceForRecompute wires a terminal report + active ref onto the incident
// so RecomputeAttributionTx's own trace load sees it.
func (h *harness) seedTraceForRecompute(reportID, incidentID, signalID, subjectKind string, reached bool) {
	h.t.Helper()
	now := time.Now().UTC()
	h.exec(`INSERT INTO trace_reports(id, site_id, agent_id, dest_key, dest_host, mode, status, max_hops, attempts,
		timeout_ms, subject_kind, reached, cohort_open, requested_at, deadline_at)
		VALUES(?, 'site_default', 'agent_a', 'ip:8.8.8.8', '8.8.8.8', 'icmp', 'partial', 30, 3, 30000, ?, ?, 0, ?, ?)`,
		reportID, subjectKind, boolToInt(reached), now, now.Add(time.Minute))
	h.exec(`INSERT INTO trace_report_refs(report_id, incident_id, signal_id, active, created_at)
		VALUES(?, ?, ?, 1, ?)`, reportID, incidentID, signalID, now)
	h.exec(`INSERT INTO trace_hops(report_id, ttl, attempt, addr, rtt_us, timed_out)
		VALUES(?, 1, 1, '192.168.1.1', 1000, 0)`, reportID)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestRecomputeAttributionTxSecondStage(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	h.seedFiringSignal("inc_1", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())

	ctx := context.Background()
	recompute := func() (bool, string) {
		t.Helper()
		tx, err := h.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		changed, siteID, err := RecomputeAttributionTx(ctx, tx, "inc_1")
		if err != nil {
			_ = tx.Rollback()
			t.Fatalf("RecomputeAttributionTx: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
		return changed, siteID
	}
	var loc string
	// First recompute establishes the honest first-stage guess (single public
	// target + healthy gateway → service).
	if changed, _ := recompute(); !changed {
		t.Fatalf("first recompute must set the service attribution")
	}
	if err := h.db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_1'`).Scan(&loc); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	if loc != LocationService {
		t.Fatalf("first stage attribution = %q want service", loc)
	}
	// A LAN-only trace lands → second stage upgrades to isp and reports a change.
	h.seedTraceForRecompute("tr_1", "inc_1", "t_pub_sig", "target", false)
	changed, siteID := recompute()
	if !changed || siteID != "site_default" {
		t.Fatalf("changed=%v site=%q, want true/site_default", changed, siteID)
	}
	if err := h.db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_1'`).Scan(&loc); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	if loc != LocationISP {
		t.Fatalf("second stage attribution = %q want isp", loc)
	}
	// Re-running with no new evidence is a no-op (no change reported).
	changed, _ = recompute()
	if changed {
		t.Fatalf("recompute with same evidence must not report a change")
	}
}

func TestRecomputeAttributionTxFrozenOnResolve(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	ctx := context.Background()
	// Resolve every member, then a late trace must not rewrite the incident.
	h.exec(`UPDATE fault_signals SET state='resolved', resolved_at=? WHERE incident_id='inc_1'`, time.Now().UTC())
	h.seedTraceForRecompute("tr_1", "inc_1", "t_pub_sig", "target", false)
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	changed, _, err := RecomputeAttributionTx(ctx, tx, "inc_1")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("RecomputeAttributionTx: %v", err)
	}
	_ = tx.Rollback()
	if changed {
		t.Fatalf("resolved incident must stay frozen, but a change was reported")
	}
}

// ---- round-2 regressions (Codex review) ----

func TestAttributionDNSPublicCountExcluded(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	// Two failing DNS monitors (generic resolution failure) + healthy gateway: a
	// generic resolution failure says nothing about whether the queried hosts are
	// reachable, so this must NOT read as an ISP-wide outage.
	h.seedFiringSignal("inc_1", "t_dns_a", "DNS A", "a.example.com", "dns", telemetry.ProbeReasonDNS, noProxy())
	h.seedFiringSignal("inc_2", "t_dns_b", "DNS B", "b.example.com", "dns", telemetry.ProbeReasonDNS, noProxy())
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc == LocationISP {
		t.Fatalf("DNS failures must not count toward isp")
	}
}

func TestAttributionFiringTargetIsNotOwnReference(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	// The just-confirmed target's detector row still shows a healthy streak (the
	// confirm path recomputes before saveDetectorState marks it failing). It must
	// not double as its own healthy reference — with no other reference, the
	// attribution stays empty rather than claiming "service, others OK".
	h.seedRef("t_pub", "icmp", "Public", "8.8.8.8", 0, 0, "")
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc == LocationService {
		t.Fatalf("a firing target must not count as its own healthy reference")
	}
	if !hasClueKinds(clues, notification.ClueNoReference) {
		t.Fatalf("clues=%v want no_reference", clueKinds(clues))
	}
}

func TestAttributionPredictedStatusIsNotHealthy(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	// A predicted-active reference (no agent report yet) must not read as healthy.
	now := time.Now().UTC()
	h.exec(`INSERT INTO probe_tasks(id, site_id, group_id, kind, name, target, params, enabled, config_serial)
		VALUES('t_pred', 'site_default', 'mg', 'icmp', 'Predicted', '9.9.9.9', '{}', 1, 1)`)
	h.exec(`INSERT INTO monitor_status(agent_id, monitor_id, status, config_version, updated_at, source)
		VALUES('agent_a', 't_pred', 'active', 1, ?, 'predicted')`, now)
	h.exec(`INSERT INTO detector_state(target_id, agent_id, fail_rounds, ok_rounds, last_round_ts, pending_fails, updated_at)
		VALUES('t_pred', 'agent_a', 0, 0, ?, '[]', ?)`, now.Unix(), now)
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc == LocationService {
		t.Fatalf("a predicted-active reference must not be treated as healthy evidence")
	}
}

func TestLoadTraceFactsSkipsResolvedSignals(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_a", "SrvA", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_1", "t_b", "SrvB", "1.1.1.1", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	h.seedTraceForRecompute("tr_1", "inc_1", "t_a_sig", "target", false)
	// Member A resolves: its trace is evidence of a fault that is no longer part
	// of the incident and must not load for member B's attribution.
	h.exec(`UPDATE fault_signals SET state='resolved', resolved_at=? WHERE id='t_a_sig'`, time.Now().UTC())
	ctx := context.Background()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	traces, err := loadTraceFacts(ctx, tx, "inc_1")
	if err != nil {
		t.Fatalf("loadTraceFacts: %v", err)
	}
	if len(traces) != 0 {
		t.Fatalf("a resolved signal's trace must be excluded, got %d", len(traces))
	}
}

func TestAttributionTraceStaysWithItsTarget(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	// A merged incident with one private-target member (whose trace died in the
	// LAN) and one public member (whose trace reached). The private trace must not
	// be applied to the public member — otherwise R4 would misread this as an ISP
	// outage.
	h.seedFiringSignal("inc_1", "t_priv", "Printer", "192.168.1.50", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_1", "t_pub", "Public", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	traces := []traceFact{
		{subjectKind: "target", targetID: "t_priv", status: "partial", reached: false, sawAnyHop: true, sawPublicHop: false},
		{subjectKind: "target", targetID: "t_pub", status: "succeeded", reached: true, sawAnyHop: true, sawPublicHop: true},
	}
	if loc, _ := attributionFor(t, h.db, "inc_1", traces); loc == LocationISP {
		t.Fatalf("the private member's LAN-only trace must not upgrade the public member's incident to isp")
	}
}

func TestAttributionFreshnessFollowsSchedule(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	// A NAT reference last answering 20 minutes ago is well within its 30-min
	// cadence's stale window (~91 min) — it must still count as healthy evidence.
	h.seedRef("t_nat", "nat", "NAT", "stun.example.com", 0, 20*time.Minute, "")
	loc, clues := attributionFor(t, h.db, "inc_1", nil)
	if loc != LocationService {
		t.Fatalf("20-min-old NAT reference must be healthy → service, got %q", loc)
	}
	if !hasClueKinds(clues, notification.ClueOnlyTargetFailing, notification.ClueOthersOK) {
		t.Fatalf("clues=%v want only_target_failing + others_ok", clueKinds(clues))
	}
}

func TestAttributionFreshnessShortIntervalIsStale(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	// A 10s-cadence ICMP reference last answering 5 minutes ago is long past its
	// ~90s stale window and must NOT read as healthy evidence.
	h.seedRef("t_icmp_ref", "icmp", "PublicIP", "8.8.8.8", 0, 5*time.Minute, "")
	loc, _ := attributionFor(t, h.db, "inc_1", nil)
	if loc == LocationService {
		t.Fatalf("stale 10s-cadence reference must not support service")
	}
}

func TestAttributionPreAssignmentEvidenceExcluded(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	// The reference was re-assigned 30s ago, but its last round is 60s old —
	// inside the 10s-cadence freshness window (~90s) yet predating the new
	// assignment. Green evidence from the PREVIOUS assignment must not read as
	// current healthy evidence.
	now := time.Now().UTC()
	h.exec(`INSERT INTO probe_tasks(id, site_id, group_id, kind, name, target, params, enabled, config_serial)
		VALUES('t_ref', 'site_default', 'mg', 'icmp', 'Ref', '9.9.9.9', '{}', 1, 1)`)
	h.exec(`INSERT INTO monitor_status(agent_id, monitor_id, status, config_version, updated_at, assigned_at)
		VALUES('agent_a', 't_ref', 'active', 1, ?, ?)`, now, now.Add(-30*time.Second))
	h.exec(`INSERT INTO detector_state(target_id, agent_id, fail_rounds, ok_rounds, last_round_ts, pending_fails, updated_at)
		VALUES('t_ref', 'agent_a', 0, 0, ?, '[]', ?)`, now.Add(-60*time.Second).Unix(), now)
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc == LocationService {
		t.Fatalf("pre-assignment evidence must not count as healthy")
	}
}

func TestAttributionHostnamesNotPublic(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	// Two timed-out LAN hostnames (fault_signals carries only the configured
	// address, no resolved IP) must not count as public targets — otherwise R4
	// would mislabel this as an ISP-wide outage.
	h.seedFiringSignal("inc_1", "t_nas", "NAS", "nas.local", "http", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_2", "t_printer", "Printer", "printer.local", "http", telemetry.ProbeReasonTimeout, noProxy())
	if loc, _ := attributionFor(t, h.db, "inc_1", nil); loc == LocationISP {
		t.Fatalf("unresolved hostnames must not count toward isp")
	}
}

func TestRecomputeOpenAttributionsOnExpiry(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_1")
	h.seedFiringSignal("inc_1", "t_http", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	// A gateway reference whose last round is long stale (gateway's ICMP cadence
	// is seconds). Persist a "service" conclusion as if it was computed while the
	// gateway was still fresh — then the wall-clock sweep must clear it, because
	// no telemetry batch will ever arrive to trigger the recompute.
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 30*time.Minute, "")
	h.exec(`UPDATE incidents SET attribution='service', attribution_evidence='[]' WHERE id='inc_1'`)
	h.svc.RecomputeOpenAttributions(h.ctx)
	var loc string
	if err := h.db.QueryRowContext(h.ctx, `SELECT attribution FROM incidents WHERE id='inc_1'`).Scan(&loc); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	if loc != "" {
		t.Fatalf("stale gateway reference must clear the attribution, got %q", loc)
	}
}

func TestTerminationRecomputesSiblingAttribution(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_a")
	h.seedIncident("inc_b")
	h.seedRef("t_gw", "gateway", "Gateway", "gateway", 0, 0, "")
	h.seedFiringSignal("inc_a", "t_a", "SrvA", "8.8.8.8", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	h.seedFiringSignal("inc_b", "t_b", "SrvB", "1.1.1.1", "icmp", telemetry.ProbeReasonTimeout, noProxy())
	// Both firing + healthy gateway → each incident reads as ISP. Disabling one of
	// the two public failures must downgrade the survivor to service WITHOUT
	// waiting for unrelated telemetry.
	ctx := context.Background()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	_, pub, err := h.svc.TerminateForTargetsTx(ctx, tx, []string{"t_b"}, ReasonConfigChanged)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("terminate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	pub(ctx)
	var loc string
	if err := h.db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_a'`).Scan(&loc); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if loc != LocationService {
		t.Fatalf("surviving incident after sibling termination = %q want service", loc)
	}
}

func TestRecomputeOpenAttributionsPublishesTargetStatus(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	execs := [][]any{
		{`INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now},
		{`INSERT INTO agents(id,site_id,public_key,token_hash,status,hostname) VALUES('agent_a','site_default',x'00','h','online','node-1')`, nil},
		{`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents) VALUES('mg','site_default','Default',1,0,1)`, nil},
		{`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('t_gw','site_default','mg','gateway','GW','gateway','{}',1,1)`, nil},
		{`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('t_http','site_default','mg','http','Site','https://example.com','{}',1,1)`, nil},
	}
	for _, e := range execs {
		if _, err := db.ExecContext(ctx, e[0].(string), e[1:]...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO incidents(id,site_id,group_id,open_key,opened_at) VALUES('inc_1','site_default','mg','key_1',?)`, now); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO fault_signals(id,site_id,agent_id,detector_key,probe_kind,target_id,group_id,group_name,target_name,target_addr,state,reason_code,observed_at,confirmed_at,incident_id)
		VALUES('sig_1','site_default','agent_a','availability','http','t_http','mg','Default','Site','https://example.com','firing',?,?,?, 'inc_1')`,
		telemetry.ProbeReasonTimeout, now, now); err != nil {
		t.Fatalf("seed signal: %v", err)
	}
	// Stale gateway reference (ICMP cadence, ~90s window) with a persisted
	// "service" conclusion as if computed while the gateway was fresh.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id,monitor_id,status,config_version,updated_at)
		VALUES('agent_a','t_gw','active',1,?)`, now); err != nil {
		t.Fatalf("seed monitor status: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO detector_state(target_id,agent_id,fail_rounds,ok_rounds,last_round_ts,pending_fails,updated_at)
		VALUES('t_gw','agent_a',0,0,?, '[]', ?)`, now.Add(-30*time.Minute).Unix(), now); err != nil {
		t.Fatalf("seed detector state: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE incidents SET attribution='service' WHERE id='inc_1'`); err != nil {
		t.Fatalf("persist attribution: %v", err)
	}

	bus := eventbus.New()
	evCount := map[string]int{}
	bus.Subscribe(eventbus.TopicIncidentUpdated, func(m eventbus.Message) { evCount["incident"]++ })
	bus.Subscribe(eventbus.TopicTargetStatusChanged, func(m eventbus.Message) { evCount["target"]++ })
	svc := New(db, bus, nil)
	svc.RecomputeOpenAttributions(ctx)
	if evCount["incident"] != 1 || evCount["target"] != 1 {
		t.Fatalf("published incident=%d target=%d, want 1/1", evCount["incident"], evCount["target"])
	}
}

func TestTerminationClearsReferenceAttribution(t *testing.T) {
	h := newHarness(t)
	h.seedIncident("inc_a")
	h.seedFiringSignal("inc_a", "t_a", "Site", "https://example.com", "http", telemetry.ProbeReasonTimeout, noProxy())
	// A healthy direct reference (public IP) is what keeps the single failing
	// target's conclusion "service". t_ref has NO firing signal — it is only a
	// reference.
	h.seedRef("t_ref", "icmp", "PublicIP", "8.8.8.8", 0, 0, "")
	if loc, _ := attributionFor(t, h.db, "inc_a", nil); loc != LocationService {
		t.Fatalf("with healthy reference = %q want service", loc)
	}
	h.exec(`UPDATE incidents SET attribution='service', attribution_evidence='[]' WHERE id='inc_a'`)
	// Deleting/clearing t_ref (a target with no firing signal) removes the healthy
	// reference; the incident must lose its service conclusion immediately, not on
	// the next telemetry batch.
	ctx := context.Background()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	_, pub, err := h.svc.TerminateForTargetsTx(ctx, tx, []string{"t_ref"}, ReasonConfigChanged)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("terminate reference: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	pub(ctx)
	var loc string
	if err := h.db.QueryRowContext(ctx, `SELECT attribution FROM incidents WHERE id='inc_a'`).Scan(&loc); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if loc == LocationService {
		t.Fatalf("a cleared reference must not keep the service conclusion, got %q", loc)
	}
}
