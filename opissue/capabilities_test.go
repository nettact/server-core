package opissue

import (
	"context"
	"testing"

	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/store/storetest"
)

// An agent whose build does not declare the capability a monitor's kind needs
// is predicted unsupported / agent_upgrade_required — by both prediction
// paths — and the verdict survives the agent's own status frames, which can
// never mention a monitor it was never sent.
func TestCapabilityGatedMonitorsArePredictedUpgradeRequired(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name,config_serial) VALUES('site_default','Default',3)`)
	perms := `["probe.traceroute","probe.icmp"]`
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,display_name,status,perm_supported,perm_granted,perm_effective,capabilities)
		VALUES('agent_old','site_default',x'00','h','Old','online',?,?,?,'["sequence_floor_v1"]'),
		      ('agent_new','site_default',x'01','h2','New','online',?,?,?,'["probe_trace_v1","sequence_floor_v1"]')`,
		perms, perms, perms, perms, perms, perms)
	exec(`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('g','site_default','All',1)`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,name,config_serial)
		VALUES('m_trace','site_default','g','trace','example.com','{}',1,'Route',2),
		      ('m_icmp','site_default','g','icmp','example.com','{}',1,'Ping',2)`)

	svc := New(db, nil)
	warnings, err := svc.PredictProbeMonitors(ctx, "site_default")
	if err != nil {
		t.Fatal(err)
	}
	var trace *SaveWarning
	for i := range warnings {
		if warnings[i].MonitorID == "m_trace" {
			trace = &warnings[i]
		}
		if warnings[i].MonitorID == "m_icmp" {
			t.Errorf("icmp monitor warned: %+v", warnings[i])
		}
	}
	if trace == nil || trace.Status != wire.MonitorStatusUnsupported || trace.AffectedAgents != 1 || trace.CapableAgents != 1 {
		t.Fatalf("trace warning = %+v", trace)
	}
	if len(trace.BlockedAgents) != 1 || trace.BlockedAgents[0].AgentID != "agent_old" || trace.BlockedAgents[0].Reason != config.ReasonAgentUpgradeRequired {
		t.Fatalf("blocked agents = %+v", trace.BlockedAgents)
	}

	row := func(agent, monitor string) (status, reason, source string) {
		t.Helper()
		if err := db.QueryRow(`SELECT status, reason, source FROM monitor_status WHERE agent_id=? AND monitor_id=?`, agent, monitor).
			Scan(&status, &reason, &source); err != nil {
			t.Fatalf("row %s/%s: %v", agent, monitor, err)
		}
		return
	}
	if s, r, _ := row("agent_old", "m_trace"); s != wire.MonitorStatusUnsupported || r != config.ReasonAgentUpgradeRequired {
		t.Errorf("old agent trace row = %s/%s", s, r)
	}
	if s, _, _ := row("agent_new", "m_trace"); s != wire.MonitorStatusActive {
		t.Errorf("new agent trace row = %s, want predicted active", s)
	}

	// The old agent reports its frame (only the icmp monitor). The server's
	// verdict on the trace monitor must survive it, and an entry forging the
	// trace monitor must be ignored.
	if err := svc.ApplyMonitorStatus(ctx, "agent_old", "site_default", wire.MonitorStatus{
		ConfigVersion: 3,
		Statuses: []wire.MonitorStatusEntry{
			{MonitorID: "m_icmp", Status: wire.MonitorStatusActive, TargetConfigSerial: 2},
			{MonitorID: "m_trace", Status: wire.MonitorStatusActive, TargetConfigSerial: 2},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if s, r, src := row("agent_old", "m_trace"); s != wire.MonitorStatusUnsupported || r != config.ReasonAgentUpgradeRequired || src != "predicted" {
		t.Errorf("after the old agent's frame: %s/%s/%s", s, r, src)
	}

	// A downgraded agent: a reported active row from its newer build is
	// overwritten by the hello-time prediction once the capability is gone.
	if err := svc.ApplyMonitorStatus(ctx, "agent_new", "site_default", wire.MonitorStatus{
		ConfigVersion: 3,
		Statuses: []wire.MonitorStatusEntry{
			{MonitorID: "m_icmp", Status: wire.MonitorStatusActive, TargetConfigSerial: 2},
			{MonitorID: "m_trace", Status: wire.MonitorStatusActive, TargetConfigSerial: 2},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, src := row("agent_new", "m_trace"); src != "reported" {
		t.Fatalf("capable agent's report not recorded")
	}
	exec(`UPDATE agents SET capabilities='["sequence_floor_v1"]' WHERE id='agent_new'`)
	if err := svc.PredictProbeMonitorsForAgent(ctx, "agent_new"); err != nil {
		t.Fatal(err)
	}
	if s, r, _ := row("agent_new", "m_trace"); s != wire.MonitorStatusUnsupported || r != config.ReasonAgentUpgradeRequired {
		t.Errorf("downgraded agent = %s/%s", s, r)
	}
	if s, _, src := row("agent_new", "m_icmp"); s != wire.MonitorStatusActive || src != "reported" {
		t.Errorf("an ungated monitor's report was disturbed: %s/%s", s, src)
	}

	// And an upgrade flips it back to an ordinary prediction.
	exec(`UPDATE agents SET capabilities='["probe_trace_v1"]' WHERE id='agent_old'`)
	if err := svc.PredictProbeMonitorsForAgent(ctx, "agent_old"); err != nil {
		t.Fatal(err)
	}
	if s, r, _ := row("agent_old", "m_trace"); s != wire.MonitorStatusActive || r != "" {
		t.Errorf("upgraded agent = %s/%s, want predicted active", s, r)
	}
}
