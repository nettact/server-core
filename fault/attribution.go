package fault

// Attribution (INCIDENT-003): a deterministic, evidence-based guess at where a
// fault most likely lives, phrased for a user ("problem most likely at the
// router / ISP line / DNS / proxy / remote service") rather than as an
// engineering layer. It is computed inside the write transaction from the
// incident's firing members plus the same agent's other detectors, and frozen
// onto incidents.attribution (code) + incidents.attribution_evidence (typed
// JSON clues) — never a pre-rendered sentence; every renderer picks its own
// wording and language at read/delivery time.
//
// Honesty contract (inherited from title.go): every conclusion is a
// "most likely", every conclusion ships its evidence as clues, and when the
// evidence is insufficient the attribution is empty ('') so the UI falls back
// to the layer wording instead of inventing a story. A conclusion is only ever
// claimed for ONE agent's vantage point (the same claim boundary storms use:
// correlation is per (site, agent)); an incident whose firing members span
// agents gets no attribution.
//
// The reference "health" claim is deliberately strict: a detector counts as
// healthy only when its streak counters say zero failing rounds, no signal is
// currently firing for it, its last round is fresh, and the agent confirmed the
// monitor is active. A gateway mid-streak (failing but unconfirmed) is neither
// healthy nor down — it blocks the rules that need a healthy gateway and yields
// an advisory clue instead.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
)

// Location codes (incidents.attribution). The user-language positions map onto
// HealthLayer but are NOT the same vocabulary: a layer is an engineering bucket,
// a location is what a user should look at. the empty string is the no-attribution
// code, so renderers fall back to the layer wording.
const (
	LocationRouter  = "router"  // gateway (or its link) is down
	LocationISP     = "isp"     // gateway healthy, multiple public targets failing
	LocationDNS     = "dns"     // resolution fails while direct-IP probes succeed
	LocationProxy   = "proxy"   // a pinned egress proxy/tunnel is failing
	LocationService = "service" // the monitored remote service itself
	// LocationDevice is reserved: no v1 rule emits it (an Agent-offline incident
	// has its own wording and never reaches attribution).
	LocationDevice = "device"
)

// maxClueTargets caps the target names attached to one evidence clue; the count
// field always carries the true total.
const maxClueTargets = 3

// memberFact is the frozen evidence of one firing fault signal, projected the
// same way for the incident's own members and for the agent-wide sibling set.
type memberFact struct {
	agentID     string
	siteID      string
	detectorKey string
	probeKind   string
	targetID    string
	targetName  string
	targetAddr  string
	proxyID     string
	proxyType   string
	proxyAddr   string
	proxyName   string
	reasonCode  int
	severity    string
	layer       string
	// sizeSweep / flowFanout are the signal's frozen classification facts,
	// loaded for the attribution rules to emit as evidence clues (DEGRADE-001/002).
	sizeSweep  *SizeSweepFacts
	flowFanout *FlowFanoutFacts
}

// traceFact is a terminal traceroute report's reaching evidence for one subject.
// targetID is the fault signal the report diagnosed (trace_report_refs.signal_id
// → fault_signals.target_id), so a merged incident never applies one member's
// trace to another member. sawAnyHop/sawPublicHop are derived from the report's
// hop IPs; Reached is true only when the destination itself answered
// (Reached=false ⇒ ReachedTTL==0, so the hop table is the only way to say how
// far the trace got).
type traceFact struct {
	subjectKind   string
	targetID      string
	status        string
	reached       bool
	sawAnyHop     bool
	sawPublicHop  bool
	lastPublicHop string
}

// refState is one of the agent's currently-active detector rows (the "what else
// is working" reference set).
type refState struct {
	targetID string
	kind     string
	target   string
	name     string
	proxyID  string
	healthy  bool
}

// memberFactCols projects a fault signal's frozen facts in the shape the
// attribution rules consume, joined to the proxies table for the display name.
const memberFactCols = `fs.agent_id, fs.site_id, fs.detector_key, fs.probe_kind, fs.target_id, fs.target_name,
	fs.target_addr, fs.proxy_id, fs.proxy_type, fs.proxy_addr, fs.reason_code, COALESCE(px.name,''), fs.severity, COALESCE(fs.layer,''),
	fs.size_sweep_json, fs.flow_fanout_json`

func scanMemberFacts(rows *sql.Rows) ([]memberFact, error) {
	defer rows.Close()
	var out []memberFact
	for rows.Next() {
		var m memberFact
		var sizeSweepJSON, flowFanoutJSON sql.NullString
		if err := rows.Scan(&m.agentID, &m.siteID, &m.detectorKey, &m.probeKind, &m.targetID,
			&m.targetName, &m.targetAddr, &m.proxyID, &m.proxyType, &m.proxyAddr, &m.reasonCode,
			&m.proxyName, &m.severity, &m.layer, &sizeSweepJSON, &flowFanoutJSON); err != nil {
			return nil, err
		}
		if sizeSweepJSON.Valid {
			var f SizeSweepFacts
			if err := json.Unmarshal([]byte(sizeSweepJSON.String), &f); err != nil {
				return nil, err
			}
			m.sizeSweep = &f
		}
		if flowFanoutJSON.Valid {
			var f FlowFanoutFacts
			if err := json.Unmarshal([]byte(flowFanoutJSON.String), &f); err != nil {
				return nil, err
			}
			m.flowFanout = &f
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// loadMembers reads an incident's currently-firing members. Used by both
// recomputeIncident and RecomputeAttributionTx so the two can never diverge.
func loadMembers(ctx context.Context, tx *sql.Tx, incidentID string) ([]memberFact, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT `+memberFactCols+` FROM fault_signals fs LEFT JOIN proxies px ON px.id=fs.proxy_id
		 WHERE fs.incident_id=? AND fs.state='firing'`, incidentID)
	if err != nil {
		return nil, err
	}
	return scanMemberFacts(rows)
}

// loadAgentFiring returns every availability signal currently firing on one
// agent — the incident's own members plus sibling signals in other incidents —
// so the rules can see what else this vantage point observed.
func loadAgentFiring(ctx context.Context, tx *sql.Tx, agentID string) ([]memberFact, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT `+memberFactCols+` FROM fault_signals fs LEFT JOIN proxies px ON px.id=fs.proxy_id
		 WHERE fs.agent_id=? AND fs.state='firing' AND fs.detector_key='availability'`, agentID)
	if err != nil {
		return nil, err
	}
	return scanMemberFacts(rows)
}

// loadReferences returns the agent's active detector rows for enabled targets
// the agent reports as running — the evidence behind "gateway is healthy" and
// "the other N targets are fine". A row whose active signal is firing is not
// healthy even when its streak counters were reset by another path.
func loadReferences(ctx context.Context, tx *sql.Tx, agentID string) ([]refState, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT pt.id, pt.kind, COALESCE(pt.target,''), COALESCE(pt.name,''), COALESCE(pt.proxy_id,''),
		       ds.fail_rounds, ds.last_round_ts,
		       CASE WHEN fs.state='firing' THEN 1 ELSE 0 END,
		       COALESCE(pt.params,'{}'), ms.effective_interval_seconds, ms.cycle_deadline_ms,
		       ms.upload_interval_seconds, pt.config_changed_at, ms.assigned_at
		FROM detector_state ds
		JOIN probe_tasks pt ON pt.id = ds.target_id
		JOIN monitor_status ms ON ms.monitor_id = ds.target_id AND ms.agent_id = ds.agent_id
		LEFT JOIN fault_signals fs ON fs.id = ds.active_signal_id
		WHERE ds.agent_id=? AND ds.detector_key='availability' AND pt.enabled=1
		  AND ms.status='active' AND ms.source='reported'`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []refState
	now := time.Now().UTC()
	for rows.Next() {
		var r refState
		var failRounds int64
		var lastRoundTS int64
		var firing int
		var paramsJSON string
		var eff, cycle, upload sql.NullInt64
		var configChanged, assignedAt sql.NullTime
		if err := rows.Scan(&r.targetID, &r.kind, &r.target, &r.name, &r.proxyID,
			&failRounds, &lastRoundTS, &firing, &paramsJSON, &eff, &cycle, &upload,
			&configChanged, &assignedAt); err != nil {
			return nil, err
		}
		stale := referenceStaleAfter(r.kind, paramsJSON, eff, cycle, upload)
		r.healthy = firing == 0 && failRounds == 0 &&
			lastRoundTS > 0 && time.Unix(lastRoundTS, 0).After(now.Add(-stale))
		// A target that left and re-entered this agent's scope without a material
		// generation change keeps its detector row but gets a fresh assigned_at. A
		// green round from the PREVIOUS assignment predates the cutoff and must not
		// count as current healthy evidence (mirrors targetstatus.pendingSince).
		if cut := assignmentCutoff(configChanged, assignedAt); cut != nil && time.Unix(lastRoundTS, 0).Before(*cut) {
			r.healthy = false
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// assignmentCutoff is the later of the target's material-generation time and the
// pair's assigned_at — the earliest wall time at which detector evidence for the
// CURRENT assignment can have been produced. Nil when neither is known.
func assignmentCutoff(configChanged, assignedAt sql.NullTime) *time.Time {
	var best *time.Time
	if configChanged.Valid {
		v := configChanged.Time.UTC()
		best = &v
	}
	if assignedAt.Valid {
		v := assignedAt.Time.UTC()
		if best == nil || v.After(*best) {
			best = &v
		}
	}
	return best
}

// referenceStaleAfter is a detector's freshness window, mirroring targetstatus's
// per-pair model: the agent-reported effective schedule when present, else the
// desired-config fallback. A fixed ten-minute window would misclassify real
// schedules — a NAT monitor legitimately goes half an hour between rounds, while
// a 10s ICMP reference is already stale after ~90s — so freshness must come from
// the monitor's own cadence, not a constant.
func referenceStaleAfter(kind, paramsJSON string, eff, cycle, upload sql.NullInt64) time.Duration {
	var p pcfg.ProbeParams
	_ = json.Unmarshal([]byte(paramsJSON), &p)
	stale := pcfg.StaleAfter(pcfg.EffectiveInterval(kind, p), pcfg.CycleDeadline(kind, p), 0)
	if eff.Valid && eff.Int64 > 0 && cycle.Valid && cycle.Int64 > 0 {
		var up time.Duration
		if upload.Valid && upload.Int64 > 0 {
			up = time.Duration(upload.Int64) * time.Second
		}
		stale = pcfg.StaleAfter(time.Duration(eff.Int64)*time.Second, time.Duration(cycle.Int64)*time.Millisecond, up)
	}
	return stale
}

// loadTraceFacts reads the incident's terminal traceroute reports that still
// diagnose a FIRING member (a just-resolved signal's trace is evidence of a fault
// that is no longer part of this incident), keeps the latest report per
// (subject, target), and classifies each one's hop table.
//
// local_no_route reports are excluded outright. That reason means the Agent's own
// host could not send the probes at all, so the report describes the agent's
// machine and not the path — but a route that vanished mid-sweep leaves the real
// hops measured before it did, and a truncated private-only hop table is exactly
// the shape R4 reads as "the trace died in the LAN". Left in, an agent-side NIC
// or route failure would argue for an ISP verdict. The hops stay on the report
// for the console to show; they simply are not path evidence.
func loadTraceFacts(ctx context.Context, tx *sql.Tx, incidentID string) ([]traceFact, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT tr.id, tr.subject_kind, tr.status, tr.reached, fs.target_id
		FROM trace_report_refs r
		JOIN trace_reports tr ON tr.id = r.report_id
		JOIN fault_signals fs ON fs.id = r.signal_id
		WHERE r.incident_id=? AND r.active=1 AND fs.state='firing'
		  AND tr.status IN('succeeded','partial','failed','timed_out')
		  AND tr.reason <> 'local_no_route'
		ORDER BY tr.received_at DESC`, incidentID)
	if err != nil {
		return nil, err
	}
	var cands []traceFact
	seen := map[string]bool{}
	for rows.Next() {
		var t traceFact
		var reportID string
		var reached int
		if err := rows.Scan(&reportID, &t.subjectKind, &t.status, &reached, &t.targetID); err != nil {
			rows.Close()
			return nil, err
		}
		t.reached = reached != 0
		key := t.subjectKind + "\x00" + t.targetID
		if seen[key] {
			continue // a later report for the same subject+target is irrelevant; keep the newest
		}
		seen[key] = true
		hops, hopErr := queryTraceHops(ctx, tx, reportID)
		if hopErr != nil {
			rows.Close()
			return nil, hopErr
		}
		for _, addr := range hops {
			t.sawAnyHop = true
			h := attributionHost(addr)
			if h != "" && !isPrivateHost(h) {
				t.sawPublicHop = true
				t.lastPublicHop = h
			}
		}
		cands = append(cands, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cands, nil
}

func queryTraceHops(ctx context.Context, tx *sql.Tx, reportID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT addr FROM trace_hops WHERE report_id=? AND addr<>'' ORDER BY ttl, attempt`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, rows.Err()
}

// traceForTarget returns the latest trace of the given subject that diagnosed
// the given target, or nil. A trace is only evidence for the member it
// diagnosed, never for a sibling in a merged incident.
func traceForTarget(traces []traceFact, subject, targetID string) *traceFact {
	for i := range traces {
		if traces[i].subjectKind == subject && traces[i].targetID == targetID {
			return &traces[i]
		}
	}
	return nil
}

// factClues turns a member's frozen classification facts into evidence clues
// (DEGRADE-001/002): a size-correlated loss signal (SizeSweep.Code == 1) argues
// physical-layer degradation; a TCP member-level flow signal (code 2) argues an
// ECMP/LAG member fault. Produced once from the incident's own members
// and appended to EVERY rule's clue list, so the facts ship as evidence even
// when the rule that concluded the attribution does not rest on them — and the
// console can render them whether or not the conclusion named the cause.
func factClues(members []memberFact) []notification.AttributionClue {
	var out []notification.AttributionClue
	for _, m := range members {
		if m.sizeSweep != nil && m.sizeSweep.Code == 1 {
			out = append(out, notification.AttributionClue{
				Kind:      notification.ClueSizeCorrelated,
				SizeSmall: m.sizeSweep.SizeSmall,
				SizeLarge: m.sizeSweep.SizeLarge,
				LossSmall: m.sizeSweep.LossSmall,
				LossLarge: m.sizeSweep.LossLarge,
			})
		}
		// HTTP fan-out code 2 is useful service-layer evidence (a repeatable
		// source-port branch differs), but it does not prove an ECMP/LAG member
		// fault: status/content differences may come from application routing.
		if m.probeKind == "tcp" && m.flowFanout != nil && m.flowFanout.Code == 2 {
			out = append(out, notification.AttributionClue{
				Kind:      notification.ClueEcmpMember,
				Flows:     m.flowFanout.Flows,
				BadStable: m.flowFanout.BadStable,
				BadNew:    m.flowFanout.BadNew,
				OK:        m.flowFanout.OK,
			})
		}
	}
	return out
}

// computeAttribution runs the rule set. members are the incident's firing
// members; traces are the incident's terminal reports. Returns (empty, nil) when
// the evidence is insufficient — the renderers then fall back to layer wording.
func computeAttribution(ctx context.Context, tx *sql.Tx, members []memberFact, traces []traceFact) (string, []notification.AttributionClue, error) {
	if len(members) == 0 {
		return "", nil, nil
	}
	agentID := members[0].agentID
	for _, m := range members {
		if m.detectorKey == DetectorAgentConnectivity {
			return "", nil, nil // agent-offline incidents have their own wording
		}
		// The rules below reason about the network path — which hop failed, what a
		// healthy reference proves — and a system-status member has no path. Left in,
		// a CPU fault on a machine whose gateway happens to be flaky would satisfy
		// the "everything through the router is failing" rule and get blamed on the
		// router, which is a confident answer to a question nobody asked.
		if IsHostDetector(m.detectorKey) {
			return "", nil, nil
		}
		if m.agentID != agentID {
			return "", nil, nil // claim boundary is one agent's vantage point
		}
	}

	firing, err := loadAgentFiring(ctx, tx, agentID)
	if err != nil {
		return "", nil, err
	}
	refs, err := loadReferences(ctx, tx, agentID)
	if err != nil {
		return "", nil, err
	}

	// Frozen classification facts ride alongside whichever rule concludes — see
	// factClues.
	facts := factClues(members)

	g := gatewayState(firing, refs)
	firingTargets := map[string]bool{}
	for _, m := range firing {
		firingTargets[m.targetID] = true
	}
	pubFails := publicFails(firing)
	pubCount := len(pubFails)
	pubNames := pubFailNames(pubFails)
	allHosts := dedupHosts(allFailingHosts(firing))

	// R1 — gateway down → router. The strongest, most local signal outranks
	// everything else: any failure on this agent is most likely a consequence.
	if g == "down" {
		clues := []notification.AttributionClue{{Kind: notification.ClueGatewayDown}}
		if pubCount > 0 {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueConcurrentPublic, Count: pubCount, Targets: pubNames})
		}
		// A target trace that never ran (no hops — e.g. the agent refused the plan)
		// says nothing about where the path died; only hop evidence does.
		if pubCount > 0 {
			if tf := traceForTarget(traces, "target", pubFails[0].targetID); tf != nil && !tf.reached && tf.sawAnyHop && !tf.sawPublicHop {
				clues = append(clues, notification.AttributionClue{Kind: notification.ClueTraceDiedInLAN})
			}
		}
		return LocationRouter, append(clues, facts...), nil
	}

	// R2 — every member pinned to the same proxy and at least one failed on the
	// egress path (8x) → the proxy/tunnel. The 8x family's contract is "never at
	// the target", so this outranks the respond-family rule below.
	if allSameProxy(members) {
		var x []memberFact
		for _, m := range members {
			if reasonIsProxy(m.reasonCode) {
				x = append(x, m)
			}
		}
		if len(x) > 0 {
			count, names := proxyFails(firing, x[0].proxyID)
			clues := []notification.AttributionClue{{
				Kind:    notification.ClueProxyFail,
				Name:    proxyDisplayName(x[0]),
				Type:    x[0].proxyType,
				Count:   count,
				Targets: names,
			}}
			if len(healthyDirectRefs(refs, firingTargets)) > 0 {
				clues = append(clues, notification.AttributionClue{Kind: notification.ClueDirectOK})
			}
			if tf := traceForTarget(traces, "proxy", x[0].targetID); tf != nil {
				if tf.reached {
					clues = append(clues, notification.AttributionClue{Kind: notification.ClueTraceProxyReached})
				} else if tf.sawAnyHop {
					// A proxy trace with actual hop data that never reached the proxy
					// listener is unreachable evidence; a "failed" report with no hops
					// (egress generation mismatch, attestation mismatch, refused plan)
					// never ran and says nothing about the proxy's reachability.
					clues = append(clues, notification.AttributionClue{Kind: notification.ClueTraceProxyUnreach})
				}
			}
			return LocationProxy, append(clues, facts...), nil
		}
	}

	// R3 — every member's reason code PROVES the target answered (an HTTP status,
	// a cert exchange, a TCP refusal, a resolver reply): the network link demonstrably
	// works, so the fault is at the remote service itself. The evidence is the
	// response itself, stronger than neighbour comparison.
	if allResponded(members) {
		clues := []notification.AttributionClue{{Kind: notification.ClueTargetResponded}}
		for _, m := range dedupeRespondedByHost(members) {
			if len(clues) >= maxClueTargets+1 {
				break
			}
			if m.reasonCode != telemetry.ProbeReasonNone {
				clues = append(clues, notification.AttributionClue{Kind: notification.ClueReason, ReasonCode: m.reasonCode})
			}
		}
		if hasProxied(members) {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueViaProxy})
		}
		return LocationService, append(clues, facts...), nil
	}

	// R4 — gateway healthy + several distinct public targets unreachable → ISP
	// line. A single failing public target qualifies when its OWN traceroute died
	// before any public hop answered (the failure sits between the router and the
	// ISP, not at the service).
	if g == "healthy" {
		traceLostInLAN := false
		if pubCount == 1 {
			if tf := traceForTarget(traces, "target", pubFails[0].targetID); tf != nil && !tf.reached && tf.sawAnyHop && !tf.sawPublicHop {
				traceLostInLAN = true
			}
		}
		if pubCount >= 2 || traceLostInLAN {
			clues := []notification.AttributionClue{{Kind: notification.ClueGatewayOK}}
			if pubCount > 0 {
				clues = append(clues, notification.AttributionClue{Kind: notification.ClueConcurrentPublic, Count: pubCount, Targets: pubNames})
			}
			if traceLostInLAN {
				clues = append(clues, notification.AttributionClue{Kind: notification.ClueTraceDiedInLAN})
			}
			return LocationISP, append(clues, facts...), nil
		}
	}

	// R5 — all members DNS-shaped, nothing else non-DNS failing on this agent,
	// and a healthy public IP-literal reference: resolution fails while direct-IP
	// connectivity works → DNS. NXDOMAIN-style members never reach here — they
	// answered, so R3 already called them a service-side problem.
	if allDNSShaped(members) && !hasOtherNonDNSFiring(firing) && len(healthyPublicIPRefs(refs, firingTargets)) > 0 {
		dnsCount, dnsNames := dnsFailing(members)
		clues := []notification.AttributionClue{{Kind: notification.ClueDNSFail, Count: dnsCount, Targets: dnsNames}}
		for _, r := range healthyPublicIPRefs(refs, firingTargets) {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueIPOK, Targets: []string{refName(r)}})
		}
		if g == "healthy" {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueGatewayOK})
		}
		return LocationDNS, append(clues, facts...), nil
	}

	// R6 — exactly one distinct failing host agent-wide, and either a healthy
	// gateway or at least one healthy direct reference: everyone else is fine,
	// this one service is not.
	if len(allHosts) == 1 && (g == "healthy" || (g == "absent" && len(healthyDirectRefs(refs, firingTargets)) > 0)) {
		m := members[0]
		clues := []notification.AttributionClue{{
			Kind: notification.ClueOnlyTargetFailing, Targets: []string{displayName(m)},
		}}
		if g == "healthy" {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueGatewayOK})
		} else {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueOthersOK, Count: len(healthyDirectRefs(refs, firingTargets))})
		}
		if reasonIsTLS(m.reasonCode) || m.reasonCode == telemetry.ProbeReasonHTTPStatus || m.reasonCode == telemetry.ProbeReasonHTTPKeyword {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueReason, ReasonCode: m.reasonCode})
		}
		if m.proxyID != "" {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueViaProxy})
		}
		if tf := traceForTarget(traces, "target", m.targetID); tf != nil {
			switch {
			case tf.reached:
				clues = append(clues, notification.AttributionClue{Kind: notification.ClueTraceReached})
			case tf.sawPublicHop:
				clues = append(clues, notification.AttributionClue{Kind: notification.ClueTracePublicLost, Name: tf.lastPublicHop})
			}
		}
		return LocationService, append(clues, facts...), nil
	}

	// R7 — insufficient evidence: no conclusion, but ship the advisory clues so
	// the UI can hint at what would sharpen future attribution.
	var clues []notification.AttributionClue
	switch g {
	case "unconfirmed":
		clues = append(clues, notification.AttributionClue{Kind: notification.ClueGatewayUnconfirmed})
	case "absent":
		if len(healthyDirectRefs(refs, firingTargets)) == 0 {
			clues = append(clues, notification.AttributionClue{Kind: notification.ClueNoReference})
		}
	}
	return "", append(clues, facts...), nil
}

// RecomputeAttributionTx recomputes an incident's attribution from its firing
// members + trace reports inside an open write tx, returning whether the stored
// attribution changed (and the incident's site id, so the caller can publish a
// refresh). No firing members ⇒ no change — a resolved incident's attribution
// is frozen and a late trace cannot rewrite it.
func RecomputeAttributionTx(ctx context.Context, tx *sql.Tx, incidentID string) (changed bool, siteID string, err error) {
	members, err := loadMembers(ctx, tx, incidentID)
	if err != nil {
		return false, "", err
	}
	if len(members) == 0 {
		return false, "", nil
	}
	siteID = members[0].siteID
	traces, err := loadTraceFacts(ctx, tx, incidentID)
	if err != nil {
		return false, siteID, err
	}
	loc, clues, err := computeAttribution(ctx, tx, members, traces)
	if err != nil {
		return false, siteID, err
	}
	var cur, curEv string
	if err := tx.QueryRowContext(ctx,
		`SELECT attribution, attribution_evidence FROM incidents WHERE id=?`, incidentID).Scan(&cur, &curEv); err != nil {
		return false, siteID, err
	}
	newEv := marshalClues(clues)
	if loc == cur && newEv == curEv {
		return false, siteID, nil
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE incidents SET attribution=?, attribution_evidence=? WHERE id=?`, loc, newEv, incidentID); err != nil {
		return false, siteID, err
	}
	return true, siteID, nil
}

// RecomputeOpenAttributions recomputes the attribution of every open incident
// that still has a firing availability member, so a reference that expired by
// the wall clock (an agent that stopped reporting leaves its gateway/reference
// detectors stale) does not leave a stale conclusion persisted. Publishes an
// incident refresh only for the incidents whose attribution actually changed.
// Best-effort and callable on a slow tick — no return value, no hard failure.
func (s *Service) RecomputeOpenAttributions(ctx context.Context) {
	if s.db == nil {
		return
	}
	type target struct{ incidentID, siteID string }
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT DISTINCT fs.incident_id, i.site_id
		FROM fault_signals fs
		JOIN incidents i ON i.id = fs.incident_id
		WHERE fs.state='firing' AND fs.detector_key='availability'`)
	if err != nil {
		return
	}
	var all []target
	for rows.Next() {
		var t target
		if rows.Scan(&t.incidentID, &t.siteID) == nil {
			all = append(all, t)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return
	}
	var changed []target
	for _, t := range all {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			continue
		}
		c, siteID, err := RecomputeAttributionTx(ctx, tx, t.incidentID)
		if err != nil {
			_ = tx.Rollback()
			continue
		}
		if err := tx.Commit(); err != nil {
			continue
		}
		if c {
			changed = append(changed, target{t.incidentID, siteID})
		}
	}
	if s.bus == nil || len(changed) == 0 {
		return
	}
	for _, t := range changed {
		s.bus.Publish(eventbus.TopicIncidentUpdated, eventbus.IncidentEvent{IncidentID: t.incidentID, SiteID: t.siteID})
		// The target-status FaultRef carries the same attribution, so refresh those
		// targets too or an open target panel keeps the pre-expiry conclusion.
		rows, err := s.db.Read().QueryContext(ctx,
			`SELECT DISTINCT target_id FROM fault_signals
			 WHERE incident_id=? AND state='firing' AND target_id<>''`, t.incidentID)
		if err != nil {
			continue
		}
		var ids []string
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		if len(ids) > 0 {
			s.bus.Publish(eventbus.TopicTargetStatusChanged, eventbus.TargetStatusChanged{SiteID: t.siteID, TargetIDs: ids})
		}
	}
}

// recomputeAgentAttributions refreshes the attribution of every open incident
// that still has a firing availability member on the agent, returning the ids
// whose attribution actually changed and every firing target belonging to those
// incidents. Called after every ingest batch, so an incident whose own members
// did not move this batch still converges to the agent-wide firing set (a
// sibling confirm can turn a single-target "service" into an ISP-wide outage; a
// sibling resolve reverses it). The changed targets let the caller publish
// target-status refreshes for the SIBLINGS too, not just the batch's own
// targets — their FaultRef attribution moved even though no round ran for them.
func recomputeAgentAttributions(ctx context.Context, tx *sql.Tx, agentID string) (changedIncidents, changedTargets []string, err error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT incident_id FROM fault_signals
		 WHERE agent_id=? AND state='firing' AND detector_key='availability'`, agentID)
	if err != nil {
		return nil, nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, id := range ids {
		c, _, err := RecomputeAttributionTx(ctx, tx, id)
		if err != nil {
			return nil, nil, err
		}
		if !c {
			continue
		}
		changedIncidents = append(changedIncidents, id)
		tRows, err := tx.QueryContext(ctx,
			`SELECT DISTINCT target_id FROM fault_signals
			 WHERE incident_id=? AND state='firing' AND target_id<>''`, id)
		if err != nil {
			return nil, nil, err
		}
		for tRows.Next() {
			var tid string
			if tRows.Scan(&tid) == nil {
				changedTargets = append(changedTargets, tid)
			}
		}
		tRows.Close()
		if err := tRows.Err(); err != nil {
			return nil, nil, err
		}
	}
	return changedIncidents, changedTargets, nil
}

func marshalClues(clues []notification.AttributionClue) string {
	if len(clues) == 0 {
		return "[]"
	}
	b, err := json.Marshal(clues)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ---- gateway / reference predicates ----

const (
	gatewayDown        = "down"
	gatewayHealthy     = "healthy"
	gatewayUnconfirmed = "unconfirmed"
	gatewayAbsent      = "absent"
)

func gatewayState(firing []memberFact, refs []refState) string {
	for _, m := range firing {
		if m.probeKind == "gateway" {
			return gatewayDown
		}
	}
	for _, r := range refs {
		if r.kind == "gateway" && r.healthy {
			return gatewayHealthy
		}
	}
	for _, r := range refs {
		if r.kind == "gateway" {
			return gatewayUnconfirmed
		}
	}
	return gatewayAbsent
}

// healthyDirectRefs are the agent's healthy, direct-dial (unproxied),
// non-gateway references — the honest basis for "the other N targets are fine"
// and "direct targets still work while the proxy path fails". A target that is
// itself currently firing is excluded: during the very batch that confirms it,
// its detector row may still show zero failures and a NULL active signal, and
// counting a faulting target as its own healthy reference would be circular.
func healthyDirectRefs(refs []refState, firingTargets map[string]bool) []refState {
	var out []refState
	for _, r := range refs {
		if r.kind == "gateway" || r.proxyID != "" || !r.healthy || firingTargets[r.targetID] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// healthyPublicIPRefs are healthy direct references whose target is a public IP
// literal — the evidence for "direct-IP probes succeed while DNS fails".
func healthyPublicIPRefs(refs []refState, firingTargets map[string]bool) []refState {
	var out []refState
	for _, r := range healthyDirectRefs(refs, firingTargets) {
		if r.kind == "dns" {
			continue
		}
		h := attributionHost(r.target)
		if h == "" || !isIPLiteral(h) || isPrivateHost(h) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func refName(r refState) string {
	if r.name != "" {
		return r.name
	}
	return r.target
}

// ---- failing-host accounting ----

// publicFail is one distinct failing public host, with the target it maps back
// to (so a traceroute can be matched to the exact member it diagnosed).
type publicFail struct {
	targetID string
	name     string
}

// publicFails returns the distinct DIRECT, unreachable-class PUBLIC IP-literal
// hosts failing on this agent. Proxied targets travel a different egress path
// and never count as an ISP-signal; a reason code that proves the target
// answered ("HTTP 500") is likewise not an unreachability signal; and DNS-shaped
// members are excluded because a generic resolution failure says nothing about
// whether the queried host is reachable. Only IP literals count as public: a
// hostname that has not been resolved (fault_signals carries the configured
// address, no resolved IP) could be a LAN name (nas.local, a split-horizon
// record) and must not be presumed reachable over the public internet.
func publicFails(firing []memberFact) []publicFail {
	seen := map[string]bool{}
	var out []publicFail
	for _, m := range firing {
		if m.probeKind == "gateway" || m.proxyID != "" || reasonProvesConnectivity(m.reasonCode) || dnsShaped(m) {
			continue
		}
		h := attributionHost(m.targetAddr)
		if h == "" || !isIPLiteral(h) || isPrivateHost(h) || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, publicFail{targetID: m.targetID, name: displayName(m)})
	}
	return out
}

// pubFailNames is the ≤3 display names of the failing public hosts, for the
// evidence clue (the count always carries the true total).
func pubFailNames(fails []publicFail) []string {
	var names []string
	for _, f := range fails {
		if len(names) >= maxClueTargets {
			break
		}
		names = append(names, f.name)
	}
	return names
}

// allFailingHosts is every distinct failing host (public or private, direct or
// proxied) on this agent — the input to the "only this one thing is failing"
// rule.
func allFailingHosts(firing []memberFact) []string {
	var out []string
	for _, m := range firing {
		if m.probeKind == "gateway" {
			continue
		}
		if h := attributionHost(m.targetAddr); h != "" {
			out = append(out, h)
		}
	}
	return dedupHosts(out)
}

func dnsFailing(members []memberFact) (count int, names []string) {
	seen := map[string]bool{}
	for _, m := range members {
		h := attributionHost(m.targetAddr)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		count++
		if len(names) < maxClueTargets {
			names = append(names, displayName(m))
		}
	}
	return count, names
}

func dedupeRespondedByHost(members []memberFact) []memberFact {
	seen := map[string]bool{}
	var out []memberFact
	for _, m := range members {
		h := attributionHost(m.targetAddr)
		if h != "" {
			if seen[h] {
				continue
			}
			seen[h] = true
		}
		out = append(out, m)
	}
	return out
}

func allResponded(members []memberFact) bool {
	for _, m := range members {
		if !reasonProvesConnectivity(m.reasonCode) {
			return false
		}
	}
	return true
}

func hasProxied(members []memberFact) bool {
	for _, m := range members {
		if m.proxyID != "" {
			return true
		}
	}
	return false
}

func allSameProxy(members []memberFact) bool {
	if len(members) == 0 {
		return false
	}
	pid := members[0].proxyID
	if pid == "" {
		return false
	}
	for _, m := range members {
		if m.proxyID != pid {
			return false
		}
	}
	return true
}

func allDNSShaped(members []memberFact) bool {
	for _, m := range members {
		if !dnsShaped(m) {
			return false
		}
	}
	return true
}

func dnsShaped(m memberFact) bool {
	return m.probeKind == "dns" || reasonIsDNS(m.reasonCode)
}

// hasOtherNonDNSFiring reports whether anything else on this agent (outside the
// members, which are all DNS-shaped by the caller's check) is failing on a
// non-DNS path.
func hasOtherNonDNSFiring(firing []memberFact) bool {
	for _, m := range firing {
		if m.probeKind == "gateway" {
			continue
		}
		if !dnsShaped(m) {
			return true
		}
	}
	return false
}

func proxyDisplayName(m memberFact) string {
	switch {
	case m.proxyName != "":
		return m.proxyName
	case m.proxyAddr != "":
		return m.proxyAddr
	}
	return m.proxyID
}

// proxyFails counts every egress-path (8x) failure on this agent that shares
// the proxy pin, so a dead proxy carrying five monitors reads as "5 probes
// failed through it" even when they merged into separate incidents.
func proxyFails(firing []memberFact, proxyID string) (count int, names []string) {
	for _, m := range firing {
		if m.proxyID != proxyID || !reasonIsProxy(m.reasonCode) {
			continue
		}
		count++
		if len(names) < maxClueTargets {
			names = append(names, displayName(m))
		}
	}
	return count, names
}

func displayName(m memberFact) string {
	if m.targetName != "" {
		return m.targetName
	}
	return m.targetAddr
}

func dedupHosts(hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		h = strings.ToLower(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// ---- reason-code classification ----

// reasonProvesConnectivity reports whether the probe received a response that
// proves the network path to (or through) the target works: an HTTP response, a
// completed certificate exchange, a TCP RST (host up, port closed), or a
// resolver reply. Such a failure is an application/service problem, never an
// unreachability signal. Generic TLS and DNS (family codes) are deliberately
// excluded — an unclassified handshake failure or stub "no such host" can be an
// on-path middlebox, and a timeout/route failure proves nothing.
func reasonProvesConnectivity(code int) bool {
	switch code {
	case telemetry.ProbeReasonRefused,
		telemetry.ProbeReasonDNSNXDomain,
		telemetry.ProbeReasonDNSServFail,
		telemetry.ProbeReasonDNSNoRecord,
		telemetry.ProbeReasonTLSExpired,
		telemetry.ProbeReasonTLSUntrusted,
		telemetry.ProbeReasonTLSHostname,
		telemetry.ProbeReasonHTTPStatus,
		telemetry.ProbeReasonHTTPKeyword:
		return true
	}
	return false
}

func reasonIsDNS(code int) bool {
	switch code {
	case telemetry.ProbeReasonDNS, telemetry.ProbeReasonDNSNXDomain,
		telemetry.ProbeReasonDNSServFail, telemetry.ProbeReasonDNSNoRecord:
		return true
	}
	return false
}

func reasonIsTLS(code int) bool {
	switch code {
	case telemetry.ProbeReasonTLS, telemetry.ProbeReasonTLSExpired,
		telemetry.ProbeReasonTLSUntrusted, telemetry.ProbeReasonTLSHostname:
		return true
	}
	return false
}

func reasonIsProxy(code int) bool {
	return code >= telemetry.ProbeReasonProxyConnect && code <= telemetry.ProbeReasonProxyConfig
}

// ---- address normalization ----

// attributionHost reduces a target address to a comparable host: the URL
// hostname when an URL, the host of a host:port pair, otherwise the raw address.
// Lowercased and IPv6 brackets stripped, so "HTTPS://Example.COM:443" and
// "https://example.com/health" dedupe to one host.
func attributionHost(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return ""
	}
	if strings.Contains(a, "://") {
		if u, err := url.Parse(a); err == nil && u.Hostname() != "" {
			return strings.ToLower(strings.Trim(u.Hostname(), "[]"))
		}
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return strings.ToLower(strings.Trim(h, "[]"))
	}
	return strings.ToLower(strings.Trim(a, "[]"))
}

func isIPLiteral(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

// isPrivateHost reports whether a host is a private, loopback, link-local,
// unspecified or CGNAT IP literal. A hostname (unresolvable at this layer, where
// the agent already resolved it) counts as public.
func isPrivateHost(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || isCGNAT(ip)
}

func isCGNAT(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}
