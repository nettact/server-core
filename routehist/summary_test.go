package routehist

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSiteSummaries(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, q := range []string{
		`INSERT INTO sites(id,name) VALUES('site_empty','Empty')`,
		`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,display_name,status) VALUES('agent_c','site_default',x'02','h3','box-c','Blocked box','online')`,
		// A second trace monitor with a sub-floor interval, never run.
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m2','site_default','g1','trace','Second','example.org','{"interval_seconds":60}',1,1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m3','site_default','g1','icmp','Ping','example.org','{}',1,1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m4','site_default','g1','trace','Off','example.net','{}',0,1)`,
	} {
		if _, err := f.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := f.db.ExecContext(ctx, `INSERT INTO monitor_status(agent_id,monitor_id,status,missing_permissions,matched_selector,reason,policy_hash,config_version,target_config_serial,source,assigned_at,updated_at)
		VALUES('agent_a','m1','active','[]','','','',1,1,'reported',?,?),
		      ('agent_b','m1','unsupported','[]','','agent_upgrade_required','',1,1,'predicted',?,?),
		      ('agent_c','m1','permission_blocked','["probe.traceroute"]','','','',1,1,'reported',?,?)`,
		now, now, now, now, now, now); err != nil {
		t.Fatal(err)
	}

	// A → B → A → B on agent_a: three confirmed changes, re-dated to sit one
	// inside 24h, one inside 7d, and one older than both.
	f.apply("agent_a", f.pathA(), f.pathA(), f.pathB(), f.pathB(), f.pathB(),
		f.pathA(), f.pathA(), f.pathA(), f.pathB(), f.pathB(), f.pathB())
	if n := f.count(`SELECT COUNT(*) FROM route_changes`); n != 3 {
		t.Fatalf("changes = %d, want 3", n)
	}
	for i, at := range []time.Time{now.Add(-10 * 24 * time.Hour), now.Add(-3 * 24 * time.Hour), now.Add(-time.Hour)} {
		if _, err := f.db.ExecContext(ctx, `UPDATE route_changes SET confirmed_at=? WHERE id=(SELECT id FROM route_changes ORDER BY id LIMIT 1 OFFSET ?)`, at.Unix(), i); err != nil {
			t.Fatal(err)
		}
	}

	// agent_d ran m1 while in scope, then left it: the overview keeps
	// showing its history, the summary must not list it.
	if _, err := f.db.ExecContext(ctx, `INSERT INTO agents(id,site_id,public_key,token_hash,hostname,status) VALUES('agent_d','site_default',x'03','h4','box-d','online')`); err != nil {
		t.Fatal(err)
	}
	f.apply("agent_d", f.pathA())
	for _, q := range []string{
		`INSERT INTO agent_groups(id,site_id,name) VALUES('ag1','site_default','Some')`,
		`INSERT INTO agent_group_members(group_id,agent_id) VALUES('ag1','agent_a'),('ag1','agent_b'),('ag1','agent_c')`,
		`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('g2','site_default','Some',0)`,
		`INSERT INTO monitor_group_agent_groups(monitor_group_id,agent_group_id) VALUES('g2','ag1')`,
		`UPDATE probe_tasks SET group_id='g2' WHERE id='m1'`,
	} {
		if _, err := f.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	s := New(f.db, f.res)
	out, err := s.siteSummaries(ctx, "site_default", now)
	if err != nil {
		t.Fatal(err)
	}
	if out.ASNDBVersion != "test-1" {
		t.Errorf("asn_db_version = %q", out.ASNDBVersion)
	}
	if len(out.Targets) != 2 || out.Targets[0].TargetID != "m1" || out.Targets[1].TargetID != "m2" {
		t.Fatalf("targets = %+v, want m1 and m2 only", out.Targets)
	}

	by := map[string]RouteAgentSummary{}
	for _, a := range out.Targets[0].Agents {
		by[a.AgentID] = a
	}
	if len(by) != 3 {
		t.Fatalf("m1 agents = %+v", out.Targets[0].Agents)
	}
	a := by["agent_a"]
	if a.Status != StatusActive || a.LastRunAt == nil || a.CurrentSince == nil {
		t.Errorf("agent_a = %+v", a)
	}
	var asns []uint32
	for _, h := range a.ASPath {
		asns = append(asns, h.ASN)
	}
	if fmt.Sprint(asns) != "[100 400 500]" || a.ASPath[0].ASName != "NET-100" || a.ASPath[0].ASCountry != "CN" {
		t.Errorf("agent_a as_path = %+v", a.ASPath)
	}
	if a.DestIP != dest1 || a.ReachedRatio == nil || *a.ReachedRatio != 1 || a.RTTP50Ms == nil || *a.RTTP50Ms < 160 {
		t.Errorf("agent_a epoch facts = %+v", a)
	}
	if a.Changes24h != 1 || a.Changes7d != 2 {
		t.Errorf("agent_a changes = %d/%d, want 1/2", a.Changes24h, a.Changes7d)
	}
	if a.LastChangeAt == nil || *a.LastChangeAt != rfc3339(now.Add(-time.Hour).Unix()) {
		t.Errorf("agent_a last_change_at = %v", a.LastChangeAt)
	}
	if a.IntervalSeconds != 600 {
		t.Errorf("agent_a interval = %d, want the 600s default", a.IntervalSeconds)
	}

	// The summary status must read exactly as the overview's.
	ov, err := s.TargetRoute(ctx, "m1")
	if err != nil {
		t.Fatal(err)
	}
	sawD := false
	for _, v := range ov.Agents {
		if v.AgentID == "agent_d" {
			sawD = true
			continue
		}
		if by[v.AgentID].Status != v.Status {
			t.Errorf("%s: summary status %q, overview %q", v.AgentID, by[v.AgentID].Status, v.Status)
		}
	}

	if !sawD {
		t.Errorf("overview should still list out-of-scope agent_d with history")
	}
	if _, ok := by["agent_d"]; ok {
		t.Errorf("summary lists out-of-scope agent_d")
	}

	b := by["agent_b"]
	if b.Status != StatusAgentUpgradeRequired || b.CurrentSince != nil || b.LastRunAt != nil || b.LastChangeAt != nil ||
		b.ReachedRatio != nil || b.RTTP50Ms != nil || b.ASPath == nil || len(b.ASPath) != 0 || b.Changes7d != 0 {
		t.Errorf("agent_b = %+v", b)
	}
	if c := by["agent_c"]; c.Status != StatusPermissionBlocked || c.AgentName != "Blocked box" || c.CurrentSince != nil {
		t.Errorf("agent_c = %+v", c)
	}

	if len(out.Targets[1].Agents) != 4 { // m2 stays all-agents, agent_d included
		t.Fatalf("m2 agents = %+v", out.Targets[1].Agents)
	}
	for _, a := range out.Targets[1].Agents {
		if a.Status != StatusPending || a.CurrentSince != nil || a.IntervalSeconds != 300 {
			t.Errorf("m2 %s = %+v, want pending at the 300s floor", a.AgentID, a)
		}
	}

	empty, err := s.siteSummaries(ctx, "site_empty", now)
	if err != nil || empty.Targets == nil || len(empty.Targets) != 0 {
		t.Errorf("empty site = %+v, %v", empty, err)
	}
	if _, err := s.SiteSummaries(ctx, "nope"); !errors.Is(err, ErrSiteNotFound) {
		t.Errorf("unknown site err = %v", err)
	}
}

func TestTraceIntervalSeconds(t *testing.T) {
	for params, want := range map[string]int{
		``:                          600,
		`{}`:                        600,
		`not json`:                  600,
		`{"interval_seconds":60}`:   300,
		`{"interval_seconds":1800}`: 1800,
	} {
		if got := traceIntervalSeconds(params); got != want {
			t.Errorf("%q = %d, want %d", params, got, want)
		}
	}
}
