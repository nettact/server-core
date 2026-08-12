package fault

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

// The diagnosis subject must be frozen from the confirming round's own samples,
// not looked up later: a probe names the endpoint it dialed on its metrics, and
// by the time a diagnostic runs that config may have changed.
//
// The two families sit on DIFFERENT samples, which is the trap these tests exist
// to catch: NAT labels its STUN server on the PRIMARY metric (it emits no reason
// metric at all), DNS labels its resolver on the error_class metric next to the
// detail. Reading either from the wrong branch silently loses the subject.

func dnsMetrics(ts int64, ok float64, labels map[string]string) []telemetry.Metric {
	t := time.Unix(ts, 0).UTC()
	return []telemetry.Metric{
		{TS: t, Kind: telemetry.DNSOK, Target: "example.com", Value: ok, Unit: telemetry.UnitBool,
			MonitorID: "t_dns", ConfigSerial: 1},
		{TS: t, Kind: telemetry.DNSErrorClass, Target: "example.com", Value: float64(telemetry.ProbeReasonTimeout),
			Unit: telemetry.UnitCode, Labels: labels, MonitorID: "t_dns", ConfigSerial: 1},
	}
}

func natMetrics(ts int64, ok float64, labels map[string]string) []telemetry.Metric {
	return []telemetry.Metric{{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.NATOK, Target: "stun.example", Value: ok,
		Unit: telemetry.UnitBool, Labels: labels, MonitorID: "t_nat", ConfigSerial: 1,
	}}
}

func TestBuildRoundsCapturesTheDialedEndpoint(t *testing.T) {
	meta := map[string]TargetMeta{
		"t_dns": {ID: "t_dns", Kind: "dns", GroupID: "mg", Addr: "example.com", Enabled: true, ConfigSerial: 1},
		"t_nat": {ID: "t_nat", Kind: "nat", GroupID: "mg", Addr: "stun.example", Enabled: true, ConfigSerial: 1},
	}

	t.Run("dns resolver comes off the error_class sample", func(t *testing.T) {
		rounds := BuildRounds(dnsMetrics(100, 0, map[string]string{
			telemetry.DNSResolverLabel:         "1.1.1.1:53",
			telemetry.DNSResolverProtocolLabel: "udp",
			telemetry.ProbeReasonDetailLabel:   "i/o timeout",
		}), meta)
		if len(rounds) != 1 {
			t.Fatalf("built %d rounds, want 1", len(rounds))
		}
		r := rounds[0]
		if r.ResolverAddr != "1.1.1.1:53" || r.ResolverProtocol != "udp" {
			t.Fatalf("round resolver=%q/%q, want 1.1.1.1:53/udp", r.ResolverAddr, r.ResolverProtocol)
		}
		if r.ReasonDetail != "i/o timeout" {
			t.Fatalf("round detail=%q, want the existing detail label to survive alongside", r.ReasonDetail)
		}
	})

	t.Run("nat STUN server comes off the primary sample", func(t *testing.T) {
		rounds := BuildRounds(natMetrics(100, 0, map[string]string{
			telemetry.NATServerLabel:    "stun.example:3478",
			telemetry.NATTransportLabel: "udp",
		}), meta)
		if len(rounds) != 1 {
			t.Fatalf("built %d rounds, want 1", len(rounds))
		}
		if rounds[0].StunAddr != "stun.example:3478" || rounds[0].StunTransport != "udp" {
			t.Fatalf("round stun=%q/%q, want stun.example:3478/udp", rounds[0].StunAddr, rounds[0].StunTransport)
		}
	})

	t.Run("an unlabelled round carries no subject rather than a stale one", func(t *testing.T) {
		rounds := BuildRounds(dnsMetrics(100, 0, nil), meta)
		if len(rounds) != 1 {
			t.Fatalf("built %d rounds, want 1", len(rounds))
		}
		if rounds[0].ResolverAddr != "" || rounds[0].ResolverProtocol != "" {
			t.Fatalf("round invented a resolver: %q/%q", rounds[0].ResolverAddr, rounds[0].ResolverProtocol)
		}
	})
}

// A confirmed signal must carry the subject columns through to the row the
// diagnostic derives from — the freeze is the whole point, and a value that
// stops at Round is a value the diagnostic never sees.
func TestConfirmedSignalFreezesTheDiagnosisSubject(t *testing.T) {
	h := newHarness(t)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	        VALUES('t_dns','site_default','mg','dns','Lookup','example.com','{}',1,1)`)
	det := DetectionSettings{FailRounds: 1, RecoverRounds: 1}.Normalize()
	meta := map[string]TargetMeta{
		"t_dns": {ID: "t_dns", Kind: "dns", GroupID: "mg", Name: "Lookup", Addr: "example.com",
			Enabled: true, ConfigSerial: 1, Det: det,
			// The egress pin, as ingest read it under the same config generation.
			ProxyID: "px_1", ProxyType: "wireguard", ProxyAddr: "vpn.example:51820",
			ProxyConfigSerial: 7},
	}
	rounds := BuildRounds(dnsMetrics(time.Now().Unix(), 0, map[string]string{
		telemetry.DNSResolverLabel:         "1.1.1.1:53",
		telemetry.DNSResolverProtocolLabel: "udp",
	}), meta)

	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := h.svc.EvaluateAgentTx(h.ctx, store.AdaptTx(tx, store.Standalone()), "agent_a", "site_default", rounds); err != nil {
		_ = tx.Rollback()
		t.Fatalf("evaluate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var resolver, proto, proxyID, proxyType, proxyAddr string
	var proxySerial int
	if err := h.db.QueryRowContext(h.ctx, `
		SELECT resolver_addr, resolver_protocol, proxy_id, proxy_type, proxy_addr, proxy_config_serial
		FROM fault_signals WHERE target_id='t_dns'`).
		Scan(&resolver, &proto, &proxyID, &proxyType, &proxyAddr, &proxySerial); err != nil {
		t.Fatalf("read frozen subject: %v", err)
	}
	if resolver != "1.1.1.1:53" || proto != "udp" {
		t.Fatalf("frozen resolver=%q/%q, want 1.1.1.1:53/udp", resolver, proto)
	}
	if proxyID != "px_1" || proxyType != "wireguard" || proxyAddr != "vpn.example:51820" || proxySerial != 7 {
		t.Fatalf("frozen proxy=%q/%q/%q serial=%d, want px_1/wireguard/vpn.example:51820/7",
			proxyID, proxyType, proxyAddr, proxySerial)
	}
}

// The agent-connectivity detector has no probe behind it, so its signal must
// still insert cleanly with every subject column empty.
func TestAgentSignalInsertsWithoutASubject(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	if _, err := h.svc.OpenAgentSignal(h.ctx, AgentSignalInput{
		AgentID: "agent_a", SiteID: "site_default", Name: "node-1",
		Reason: "unexpected", OfflineSince: now.Add(-time.Minute),
	}, now); err != nil {
		t.Fatalf("open agent signal: %v", err)
	}
	var n int
	if err := h.db.QueryRowContext(h.ctx, `
		SELECT COUNT(*) FROM fault_signals
		WHERE detector_key='agent_connectivity' AND resolver_addr='' AND proxy_id='' AND stun_addr=''`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("agent-connectivity signals with empty subject columns = %d, want 1", n)
	}
}
