package opissue

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nettact/server-core/store"
)

func TestPredictProbeMonitorsClassifiesAgentsAndIncludesOfflineGroupMembers(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "opissue.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("exec %q: %v", query, err)
		}
	}

	exec(`INSERT INTO sites(id,name) VALUES('site_default','Default')`)
	insertAgent := func(id, name, status, supported, granted, effective string) {
		exec(`INSERT INTO agents(
			id,site_id,public_key,token_hash,display_name,status,config_version,
			perm_supported,perm_granted,perm_effective,policy_hash
		) VALUES(?,'site_default',x'00','h',?,?,7,?,?,?,'policy')`,
			id, name, status, supported, granted, effective)
	}
	insertAgent("agent-capable", "Capable", "online", `["probe.http"]`, `["probe.http"]`, `["probe.http"]`)
	insertAgent("agent-blocked", "Blocked Offline", "offline", `["probe.http"]`, `[]`, `[]`)
	insertAgent("agent-unsupported", "Unsupported", "online", `[]`, `["probe.http"]`, `[]`)

	exec(`INSERT INTO probe_tasks(id,site_id,kind,target,params,enabled,name,all_agents)
		VALUES('mon-all','site_default','http','https://example.com','{}',1,'All agents',1)`)
	exec(`INSERT INTO agent_groups(id,site_id,name) VALUES('group-1','site_default','Offline group')`)
	exec(`INSERT INTO agent_group_members(group_id,agent_id) VALUES('group-1','agent-blocked')`)
	exec(`INSERT INTO probe_tasks(id,site_id,kind,target,params,enabled,name,all_agents)
		VALUES('mon-group','site_default','http','https://example.net','{}',1,'Group monitor',0)`)
	exec(`INSERT INTO probe_task_groups(task_id,group_id) VALUES('mon-group','group-1')`)

	warnings, err := New(db, nil).PredictProbeMonitors(ctx, "site_default")
	if err != nil {
		t.Fatalf("PredictProbeMonitors: %v", err)
	}
	byMonitor := make(map[string]SaveWarning, len(warnings))
	for _, warning := range warnings {
		byMonitor[warning.MonitorID] = warning
	}
	all, ok := byMonitor["mon-all"]
	if !ok {
		t.Fatalf("warnings = %+v, missing mon-all", warnings)
	}
	if all.CapableAgents != 1 || all.AffectedAgents != 2 {
		t.Fatalf("mon-all counts = capable %d affected %d, want 1/2", all.CapableAgents, all.AffectedAgents)
	}
	if len(all.CapableAgentList) != 1 || all.CapableAgentList[0].AgentID != "agent-capable" || all.CapableAgentList[0].Status != "active" {
		t.Fatalf("capable identities = %+v", all.CapableAgentList)
	}
	blocked := map[string]string{}
	for _, agent := range all.BlockedAgents {
		blocked[agent.AgentID] = agent.Status
	}
	if blocked["agent-blocked"] != "permission_blocked" || blocked["agent-unsupported"] != "unsupported" {
		t.Fatalf("blocked classifications = %+v", blocked)
	}

	group, ok := byMonitor["mon-group"]
	if !ok || len(group.BlockedAgents) != 1 || group.BlockedAgents[0].AgentID != "agent-blocked" {
		t.Fatalf("offline group prediction = %+v", group)
	}
	rows, err := New(db, nil).MonitorStatuses(ctx, "mon-group")
	if err != nil {
		t.Fatalf("MonitorStatuses: %v", err)
	}
	if len(rows) != 1 || rows[0].AgentID != "agent-blocked" || rows[0].Status != "permission_blocked" {
		t.Fatalf("offline group monitor rows = %+v", rows)
	}
}
