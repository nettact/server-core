package config

import (
	"testing"

	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/registry"
)

// A capability-gated kind reaches only agents whose stored Hello capabilities
// declare it; every other kind is unaffected, and a later Hello that adds the
// capability makes the next DesiredState carry the target.
func TestDesiredStateWithholdsGatedKindsFromAgentsWithoutTheCapability(t *testing.T) {
	db, ctx := openConfigTestDB(t)
	reg := registry.New(db, 0, nil)
	svc := New(db, reg, nil, nil, nil)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t_trace", GroupID: group, Kind: KindTrace, Target: "example.com", Enabled: true},
		{ID: "t_icmp", GroupID: group, Kind: "icmp", Target: "example.com", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	pushed := func(agent string) map[string]bool {
		t.Helper()
		ds, err := svc.DesiredStateFor(ctx, agent)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, tg := range ds.ProbeTargets {
			out[tg.MonitorID] = true
		}
		return out
	}
	if got := pushed("agent_a"); got["t_trace"] || !got["t_icmp"] {
		t.Fatalf("agent without capabilities got %v, want only t_icmp", got)
	}
	if err := reg.UpdateCapabilities(ctx, "agent_a", []string{wire.CapProbeTraceV1, wire.CapSequenceFloorV1, wire.CapProbeTraceV1}); err != nil {
		t.Fatal(err)
	}
	if got := pushed("agent_a"); !got["t_trace"] || !got["t_icmp"] {
		t.Fatalf("capable agent got %v, want both", got)
	}
	if got := pushed("agent_b"); got["t_trace"] {
		t.Fatalf("another agent inherited the capability: %v", got)
	}
	var stored string
	db.QueryRow(`SELECT capabilities FROM agents WHERE id='agent_a'`).Scan(&stored)
	if stored != `["probe_trace_v1","sequence_floor_v1"]` {
		t.Errorf("stored capabilities = %s, want sorted and de-duplicated", stored)
	}
	// A downgrade (Hello without the capability) withdraws it again.
	if err := reg.UpdateCapabilities(ctx, "agent_a", []string{wire.CapSequenceFloorV1}); err != nil {
		t.Fatal(err)
	}
	if got := pushed("agent_a"); got["t_trace"] {
		t.Fatalf("downgraded agent still gets the trace target")
	}
}

func TestCapabilityHelpers(t *testing.T) {
	if RequiredCapability("icmp") != "" || RequiredCapability(KindTrace) != wire.CapProbeTraceV1 {
		t.Error("RequiredCapability")
	}
	if !KindSupportedBy("http", nil) || KindSupportedBy(KindTrace, nil) || !KindSupportedBy(KindTrace, []string{wire.CapProbeTraceV1}) {
		t.Error("KindSupportedBy")
	}
	if DecodeCapabilities("not json") != nil || DecodeCapabilities("") != nil {
		t.Error("malformed capabilities must decode as none")
	}
}
