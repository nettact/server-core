package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// Telemetry provenance is not just "is this the current generation": a target's
// generation is deliberately unchanged by a scope-only edit, so the generation
// gate alone would still accept metrics from an agent that has just been removed
// from the group. Those metrics would open a fault that no later round can ever
// recover, because that agent has stopped probing the target. The same hole lets
// one site's agent submit under another site's target id.

func seedScopeFixture(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name,created_at) VALUES('site_a','A',?)`, now)
	exec(`INSERT INTO sites(id,name,created_at) VALUES('site_b','B',?)`, now)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_in','site_a',x'00','h1','online')`)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_out','site_a',x'00','h2','online')`)
	exec(`INSERT INTO agent_groups(id,site_id,name) VALUES('ag_in','site_a','In scope')`)
	exec(`INSERT INTO agent_group_members(group_id,agent_id) VALUES('ag_in','agent_in')`)
	// A scoped group: only agents in ag_in execute its targets.
	exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
	      VALUES('mg_scoped','site_a','Scoped',0,0,0)`)
	exec(`INSERT INTO monitor_group_agent_groups(monitor_group_id,agent_group_id) VALUES('mg_scoped','ag_in')`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	      VALUES('t_scoped','site_a','mg_scoped','icmp','Router','192.168.1.1','{}',1,1)`)
	// A target owned by the OTHER site, reachable only by that site's agents.
	exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
	      VALUES('mg_b','site_b','B group',1,0,1)`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	      VALUES('t_foreign','site_b','mg_b','icmp','Foreign','10.0.0.1','{}',1,1)`)
}

func TestProbeMetaExcludesOutOfScopeAndForeignTargets(t *testing.T) {
	db := storetest.Open(t)
	seedScopeFixture(t, db)
	svc := New(db, nil, nil, nil, nil)
	ctx := context.Background()

	meta, err := svc.probeMeta(ctx, db.Read(), "agent_in", "site_a", []string{"t_scoped", "t_foreign"})
	if err != nil {
		t.Fatalf("probeMeta(in scope): %v", err)
	}
	if _, ok := meta["t_scoped"]; !ok {
		t.Fatal("an in-scope target must be evaluated")
	}
	if _, ok := meta["t_foreign"]; ok {
		t.Fatal("a target owned by another site must never be evaluated under this one")
	}

	meta, err = svc.probeMeta(ctx, db.Read(), "agent_out", "site_a", []string{"t_scoped"})
	if err != nil {
		t.Fatalf("probeMeta(out of scope): %v", err)
	}
	if _, ok := meta["t_scoped"]; ok {
		t.Fatal("an agent outside the group's scope must not evaluate its targets")
	}
}

// TestOutOfScopeTelemetryIsDropped is the end-to-end consequence: the samples of
// an out-of-scope agent are rejected outright, so no detector state, fault or
// availability data is ever attributed to it.
func TestOutOfScopeTelemetryIsDropped(t *testing.T) {
	db := storetest.Open(t)
	seedScopeFixture(t, db)
	svc := New(db, nil, nil, nil, nil)
	ctx := context.Background()

	meta, err := svc.probeMeta(ctx, db.Read(), "agent_out", "site_a", []string{"t_scoped"})
	if err != nil {
		t.Fatalf("probeMeta: %v", err)
	}
	metrics := []telemetry.Metric{{
		TS: time.Unix(1000, 0).UTC(), Kind: telemetry.ICMPLoss, Target: "192.168.1.1",
		Value: 100, MonitorID: "t_scoped", ConfigSerial: 1,
	}}
	accepted, dropped := filterByGeneration(metrics, meta)
	if len(accepted) != 0 || dropped != 1 {
		t.Fatalf("accepted=%d dropped=%d, want the out-of-scope sample rejected", len(accepted), dropped)
	}
}
