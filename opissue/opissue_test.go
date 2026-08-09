package opissue

import (
	"context"
	"github.com/nettact/protocol/wire"
	"testing"

	"github.com/nettact/server-core/store/storetest"
)

func TestPredictProbeMonitorsClassifiesAgentsAndIncludesOfflineGroupMembers(t *testing.T) {
	db := storetest.Open(t)
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
			id,site_id,public_key,token_hash,display_name,status,
			perm_supported,perm_granted,perm_effective,policy_hash
		) VALUES(?,'site_default',x'00','h',?,?,?,?,?,'policy')`,
			id, name, status, supported, granted, effective)
	}
	insertAgent("agent-capable", "Capable", "online", `["probe.http"]`, `["probe.http"]`, `["probe.http"]`)
	insertAgent("agent-blocked", "Blocked Offline", "offline", `["probe.http"]`, `[]`, `[]`)
	insertAgent("agent-unsupported", "Unsupported", "online", `[]`, `["probe.http"]`, `[]`)

	exec(`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('mgrp-all','site_default','All',1)`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,name)
		VALUES('mon-all','site_default','mgrp-all','http','https://example.com','{}',1,'All agents')`)
	exec(`INSERT INTO agent_groups(id,site_id,name) VALUES('group-1','site_default','Offline group')`)
	exec(`INSERT INTO agent_group_members(group_id,agent_id) VALUES('group-1','agent-blocked')`)
	exec(`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('mgrp-scoped','site_default','Scoped',0)`)
	exec(`INSERT INTO monitor_group_agent_groups(monitor_group_id,agent_group_id) VALUES('mgrp-scoped','group-1')`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,name)
		VALUES('mon-group','site_default','mgrp-scoped','http','https://example.net','{}',1,'Group monitor')`)

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
	statusRows, err := db.QueryContext(ctx,
		`SELECT agent_id, status FROM monitor_status WHERE monitor_id=?`, "mon-group")
	if err != nil {
		t.Fatalf("query monitor_status: %v", err)
	}
	defer statusRows.Close()
	type predRow struct{ agentID, status string }
	var predicted []predRow
	for statusRows.Next() {
		var pr predRow
		if err := statusRows.Scan(&pr.agentID, &pr.status); err != nil {
			t.Fatalf("scan monitor_status: %v", err)
		}
		predicted = append(predicted, pr)
	}
	if len(predicted) != 1 || predicted[0].agentID != "agent-blocked" || predicted[0].status != "permission_blocked" {
		t.Fatalf("offline group monitor rows = %+v", predicted)
	}
}

func TestAgentStatusesExposeExecutionProvenanceAndSchedule(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec: %v", err)
		}
	}
	exec(`INSERT INTO sites(id,name) VALUES('site_default','Default')`)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent','site_default',x'00','h','online')`)
	exec(`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('group','site_default','All',1)`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,config_serial)
		VALUES('monitor','site_default','group','http','https://example.test','{}',1,17)`)
	exec(`INSERT INTO monitor_status(
		agent_id,monitor_id,status,config_version,updated_at,source,target_config_serial,
		effective_interval_seconds,cycle_deadline_ms,upload_interval_seconds)
		VALUES('agent','monitor','active',23,CURRENT_TIMESTAMP,'reported',17,45,10000,5)`)

	rows, err := New(db, nil).AgentStatuses(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("statuses = %+v", rows)
	}
	got := rows[0]
	if got.Source != "reported" || got.TargetConfigSerial != 17 || got.ConfigVersion != 23 {
		t.Fatalf("provenance = %+v", got)
	}
	if got.EffectiveIntervalSeconds == nil || *got.EffectiveIntervalSeconds != 45 ||
		got.CycleDeadlineMs == nil || *got.CycleDeadlineMs != 10000 ||
		got.UploadIntervalSeconds == nil || *got.UploadIntervalSeconds != 5 {
		t.Fatalf("schedule = %+v", got)
	}
}

// The upload cadence describes the whole outbox, so it is recorded on the agent
// row and not only on the per-monitor ones.
//
// The case that forces it: an agent whose only subject is a host anchor sends a
// MonitorStatus frame with NO entries, so there are no per-monitor rows to carry
// it — and the host detectors would then judge how late a live reading may be
// against the protocol default, classifying every one of a slow uploader's live
// faults as a replay.
func TestFrameLevelUploadCadenceIsRecordedWithoutAnyMonitorRows(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec: %v", err)
		}
	}
	exec(`INSERT INTO sites(id,name) VALUES('site_default','Default')`)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent','site_default',x'00','h','online')`)

	// A frame with no statuses at all — the host-anchor-only agent.
	if err := New(db, nil).ApplyMonitorStatus(ctx, "agent", "site_default", wire.MonitorStatus{
		ConfigVersion: 1, UploadIntervalSeconds: 300,
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	var got int
	if err := db.Read().QueryRowContext(ctx,
		`SELECT upload_interval_seconds FROM agents WHERE id='agent'`).Scan(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != 300 {
		t.Fatalf("agents.upload_interval_seconds = %d, want the frame's 300", got)
	}

	// A later frame that omits it must not reset what is known.
	if err := New(db, nil).ApplyMonitorStatus(ctx, "agent", "site_default", wire.MonitorStatus{
		ConfigVersion: 2,
	}); err != nil {
		t.Fatalf("apply second: %v", err)
	}
	if err := db.Read().QueryRowContext(ctx,
		`SELECT upload_interval_seconds FROM agents WHERE id='agent'`).Scan(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != 300 {
		t.Fatalf("upload_interval_seconds = %d after a frame that omitted it, want 300 kept", got)
	}
}
