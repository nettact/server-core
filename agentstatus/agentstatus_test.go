package agentstatus

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// fakeMetrics returns canned latest points per agent.
type fakeMetrics struct{ byAgent map[string][]metrics.Point }

func (f *fakeMetrics) LatestSnapshot(_ context.Context, agentID string, _ int64) ([]metrics.Point, error) {
	return f.byAgent[agentID], nil
}

func mustExec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.Open(t)
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	return db
}

func seedAgent(t *testing.T, db *store.DB, id, status string, firstConn *time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO agents(id, site_id, public_key, token_hash, status, hostname, first_connected_at, last_seen_at, created_at)
		VALUES(?, 'site_default', x'00', ?, ?, ?, ?, ?, ?)`,
		id, "h_"+id, status, id+"-host", firstConn, time.Now().UTC(), time.Now().UTC())
}

// seedFault inserts a firing target-availability fault for an agent, with the
// incident row its foreign key requires.
func seedFault(t *testing.T, db *store.DB, id, agentID, targetID string, now time.Time) {
	t.Helper()
	inc := "inc_" + id
	mustExec(t, db, `INSERT INTO incidents(id,site_id,group_id,open_key,state,severity,opened_at)
		VALUES(?,'site_default','mg',?, 'open','warn',?)`, inc, "sig:"+id, now)
	mustExec(t, db, `INSERT INTO fault_signals(id,site_id,agent_id,target_id,detector_key,state,observed_at,confirmed_at,incident_id)
		VALUES(?,'site_default',?,?,'availability','firing',?,?,?)`, id, agentID, targetID, now, now, inc)
}

// seedAgentFault inserts a firing agent-connectivity fault (no target).
func seedAgentFault(t *testing.T, db *store.DB, id, agentID, reason string, now time.Time) {
	t.Helper()
	inc := "inc_" + id
	mustExec(t, db, `INSERT INTO incidents(id,site_id,group_id,open_key,state,severity,opened_at)
		VALUES(?,'site_default','',?, 'open','critical',?)`, inc, "agent:"+agentID, now)
	mustExec(t, db, `INSERT INTO fault_signals(id,site_id,agent_id,target_id,detector_key,severity,state,
		reason_detail,observed_at,confirmed_at,incident_id)
		VALUES(?,'site_default',?,'','agent_connectivity','critical','firing',?,?,?,?)`,
		id, agentID, reason, now, now, inc)
}

func find(rows []AgentStatusRow, id string) AgentStatusRow {
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	return AgentStatusRow{}
}

func TestStatusPriority(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	seedAgent(t, db, "agent_off", "offline", &now)
	seedAgent(t, db, "agent_abn", "online", &now)
	seedAgent(t, db, "agent_ok", "online", &now)
	seedAgent(t, db, "agent_new", "offline", nil) // never connected

	// agent_abn is online but has a firing target fault and an active issue.
	mustExec(t, db, `INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('mg','site_default','all',1)`)
	seedFault(t, db, "sig1", "agent_abn", "probe_a", now)
	mustExec(t, db, `INSERT INTO operational_issues(id,site_id,agent_id,reason,dedupe_key,state,first_seen_at,last_seen_at) VALUES('oi1','site_default','agent_abn','permission_blocked','k1','active',?,?)`, now, now)
	// A firing fault on the OFFLINE agent must not demote it to abnormal.
	seedFault(t, db, "sig2", "agent_off", "probe_b", now)

	svc := New(db, nil, settings.New(db))
	got, err := svc.SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	checks := map[string]string{
		"agent_off": StatusOffline,
		"agent_abn": StatusAbnormal,
		"agent_ok":  StatusOK,
		"agent_new": StatusNeverConnected,
	}
	for id, want := range checks {
		if r := find(got.Agents, id); r.Status != want {
			t.Fatalf("agent %s: want status %s, got %s", id, want, r.Status)
		}
	}
	// The offline agent still reports its firing count as a reason.
	if r := find(got.Agents, "agent_off"); r.FiringFaults != 1 {
		t.Fatalf("expected offline agent to report firing_faults=1, got %d", r.FiringFaults)
	}
}

func TestResourcesStaleAndWorstMount(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedAgent(t, db, "agent_a", "online", &now)

	set := settings.New(db)
	_ = set.Set(ctx, settings.KeyAgentStatusStaleSeconds, "120")

	fresh := now.Add(-10 * time.Second) // within 120s
	old := now.Add(-10 * time.Minute)   // stale
	fm := &fakeMetrics{byAgent: map[string][]metrics.Point{
		"agent_a": {
			{TS: fresh, Kind: string(telemetry.HostCPUPct), Target: "host", Value: 42, Unit: "pct"},
			{TS: old, Kind: string(telemetry.HostMemPct), Target: "host", Value: 55, Unit: "pct"},
			{TS: old, Kind: string(telemetry.HostMemUsed), Target: "host", Value: 8e9},
			{TS: old, Kind: string(telemetry.HostMemTotal), Target: "host", Value: 16e9},
			// two mounts; C: is worse (higher pct) → picked for Pct/Mount, but Used/Total
			// are summed across both.
			{TS: fresh, Kind: string(telemetry.HostDiskPct), Target: "D:", Value: 30, Unit: "pct"},
			{TS: fresh, Kind: string(telemetry.HostDiskUsed), Target: "D:", Value: 1e11},
			{TS: fresh, Kind: string(telemetry.HostDiskTotal), Target: "D:", Value: 5e11},
			{TS: fresh, Kind: string(telemetry.HostDiskPct), Target: "C:", Value: 88, Unit: "pct"},
			{TS: fresh, Kind: string(telemetry.HostDiskUsed), Target: "C:", Value: 4e11},
			{TS: fresh, Kind: string(telemetry.HostDiskTotal), Target: "C:", Value: 5e11},
			{TS: fresh, Kind: string(telemetry.HostNetRxBps), Target: "host", Value: 1000},
			{TS: fresh, Kind: string(telemetry.HostNetTxBps), Target: "host", Value: 2000},
			{TS: fresh, Kind: string(telemetry.HostUptime), Target: "host", Value: 123456, Unit: "s"},
			{TS: fresh, Kind: string(telemetry.HostLoad1), Target: "host", Value: 1.5},
			{TS: fresh, Kind: string(telemetry.HostLoad5), Target: "host", Value: 0.9},
			{TS: fresh, Kind: string(telemetry.HostLoad15), Target: "host", Value: 0.4},
		},
	}}
	svc := New(db, fm, set)
	svc.now = func() time.Time { return now }

	got, err := svc.SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	r := find(got.Agents, "agent_a")
	if r.Resources.CPU == nil || r.Resources.CPU.Value != 42 || r.Resources.CPU.Stale {
		t.Fatalf("cpu: %+v", r.Resources.CPU)
	}
	if r.Resources.Memory == nil || r.Resources.Memory.Pct != 55 || !r.Resources.Memory.Stale {
		t.Fatalf("mem should be present and stale: %+v", r.Resources.Memory)
	}
	if r.Resources.Disk == nil || r.Resources.Disk.Mount != "C:" || r.Resources.Disk.Pct != 88 || r.Resources.Disk.Mounts != 2 {
		t.Fatalf("disk worst-mount: %+v", r.Resources.Disk)
	}
	if r.Resources.Disk.Used != 5e11 || r.Resources.Disk.Total != 1e12 {
		t.Fatalf("disk used/total should be summed across mounts, got used=%v total=%v", r.Resources.Disk.Used, r.Resources.Disk.Total)
	}
	if r.Resources.Net == nil || r.Resources.Net.RxBps != 1000 || r.Resources.Net.TxBps != 2000 {
		t.Fatalf("net: %+v", r.Resources.Net)
	}
	if r.Resources.Uptime == nil || r.Resources.Uptime.Value != 123456 {
		t.Fatalf("uptime: %+v", r.Resources.Uptime)
	}
	if r.Resources.Load == nil || r.Resources.Load.Load1 != 1.5 || r.Resources.Load.Load5 != 0.9 || r.Resources.Load.Load15 != 0.4 {
		t.Fatalf("load: %+v", r.Resources.Load)
	}
}

func TestNullResourcesWhenNoData(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedAgent(t, db, "agent_a", "online", &now)
	fm := &fakeMetrics{byAgent: map[string][]metrics.Point{}} // no points
	svc := New(db, fm, settings.New(db))

	got, err := svc.SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	r := find(got.Agents, "agent_a")
	if r.Resources.CPU != nil || r.Resources.Memory != nil || r.Resources.Disk != nil || r.Resources.Net != nil ||
		r.Resources.Load != nil || r.Resources.Uptime != nil {
		t.Fatalf("expected all resources nil, got %+v", r.Resources)
	}
}

// TestStatusSinceFromHistory guards the loadStatusSince query against the modernc
// aggregate-affinity trap: MAX(changed_at) returns a raw string, so the latest
// transition time must be read from a direct column instead.
func TestStatusSinceFromHistory(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedAgent(t, db, "agent_a", "offline", &now)

	earlier := now.Add(-2 * time.Hour)
	latest := now.Add(-5 * time.Minute)
	mustExec(t, db, `INSERT INTO agent_status_history(id,agent_id,status,changed_at) VALUES('h1','agent_a','online',?)`, earlier)
	mustExec(t, db, `INSERT INTO agent_status_history(id,agent_id,status,reason,changed_at) VALUES('h2','agent_a','offline','clean',?)`, latest)

	svc := New(db, nil, settings.New(db))
	got, err := svc.SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	r := find(got.Agents, "agent_a")
	if r.StatusSince == nil {
		t.Fatal("expected status_since from history")
	}
	if !r.StatusSince.Equal(latest) {
		t.Fatalf("status_since = %v, want latest transition %v", r.StatusSince, latest)
	}
}

func TestConnectivityAlertAndGroups(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedAgent(t, db, "agent_a", "offline", &now)

	mustExec(t, db, `INSERT INTO agent_groups(id,site_id,name) VALUES('g1','site_default','Living Room')`)
	mustExec(t, db, `INSERT INTO agent_group_members(group_id,agent_id) VALUES('g1','agent_a')`)
	seedAgentFault(t, db, "aa1", "agent_a", "clean_shutdown", now)

	svc := New(db, nil, settings.New(db))
	got, err := svc.SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	r := find(got.Agents, "agent_a")
	if len(r.Groups) != 1 || r.Groups[0].Name != "Living Room" {
		t.Fatalf("groups: %+v", r.Groups)
	}
	if r.ConnectivityAlert == nil || r.ConnectivityAlert.Reason != "clean_shutdown" {
		t.Fatalf("connectivity alert: %+v", r.ConnectivityAlert)
	}
}
