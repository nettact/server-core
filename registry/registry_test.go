package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func mustExec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// TestUpdateAndDeleteAgent exercises the operator-facing agent CRUD: renaming an
// agent, and the hard delete that must clear every table referencing the agent
// (FK-constrained and not) in one transaction without tripping foreign_keys=ON.
func TestUpdateAndDeleteAgent(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed a site, an agent, and one row in every table that references the agent.
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_x','site_default',x'00','h','online')`)
	mustExec(t, db, `INSERT INTO interfaces(id,agent_id,name) VALUES('if1','agent_x','eth0')`)
	mustExec(t, db, `INSERT INTO agent_wifi(agent_id,state,sampled_at,last_sequence) VALUES('agent_x','ok',?,1)`, now)
	mustExec(t, db, `INSERT INTO agent_status_history(id,agent_id,status,changed_at) VALUES('ash1','agent_x','online',?)`, now)
	mustExec(t, db, `INSERT INTO agent_groups(id,site_id,name) VALUES('grp1','site_default','g')`)
	mustExec(t, db, `INSERT INTO agent_group_members(group_id,agent_id) VALUES('grp1','agent_x')`)
	mustExec(t, db, `INSERT INTO agent_packets(agent_id,sequence,received_at) VALUES('agent_x',1,?)`, now)
	mustExec(t, db, `INSERT INTO events(id,agent_id,site_id,ts,type) VALUES('e1','agent_x','site_default',?,'t')`, now)
	mustExec(t, db, `INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('mg1','site_default','all',1)`)
	mustExec(t, db, `INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled) VALUES('mon1','site_default','mg1','http','https://example.test','{}',1)`)
	mustExec(t, db, `INSERT INTO detector_state(target_id,agent_id,detector_key,fail_rounds,updated_at) VALUES('mon1','agent_x','availability',2,?)`, now)
	// A recorded fault is history, not agent-owned state: it must SURVIVE the
	// delete, carrying the frozen names that make it readable afterwards.
	mustExec(t, db, `INSERT INTO incidents(id,site_id,group_id,open_key,state,severity,opened_at) VALUES('inc1','site_default','mg1','sig:sig1','open','warn',?)`, now)
	mustExec(t, db, `INSERT INTO fault_signals(id,site_id,agent_id,agent_name,target_id,detector_key,state,observed_at,confirmed_at,incident_id)
		VALUES('sig1','site_default','agent_x','My Agent','mon1','availability','firing',?,?,'inc1')`, now, now)

	bus := eventbus.New()
	var statusEvents []eventbus.TargetStatusChanged
	bus.Subscribe(eventbus.TopicTargetStatusChanged, func(m eventbus.Message) {
		statusEvents = append(statusEvents, m.Payload.(eventbus.TargetStatusChanged))
	})
	reg := New(db, 0, bus)

	// UpdateAgent sets the operator-editable display name and Get reflects it.
	if err := reg.UpdateAgent(ctx, "agent_x", "My Agent"); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	a, err := reg.Get(ctx, "agent_x")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if a.DisplayName != "My Agent" {
		t.Fatalf("DisplayName = %q, want %q", a.DisplayName, "My Agent")
	}

	// DeleteAgent removes the agent and every referencing row, no FK error.
	if err := reg.DeleteAgent(ctx, "agent_x"); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	if len(statusEvents) != 1 || statusEvents[0].SiteID != "site_default" || len(statusEvents[0].TargetIDs) != 0 {
		t.Fatalf("delete status events = %+v, want one site-wide refresh", statusEvents)
	}
	for _, tbl := range []string{
		"interfaces", "agent_wifi", "agent_status_history", "agent_group_members",
		"agent_packets", "events", "detector_state",
	} {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+tbl+` WHERE agent_id='agent_x'`).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows for deleted agent", tbl, n)
		}
	}
	// The fault history survives, still naming the agent that detected it.
	var frozenName string
	if err := db.QueryRowContext(ctx, `SELECT agent_name FROM fault_signals WHERE id='sig1'`).Scan(&frozenName); err != nil {
		t.Fatalf("fault history must survive an agent delete: %v", err)
	}
	if frozenName != "My Agent" {
		t.Errorf("frozen agent_name = %q, want the name recorded at fault time", frozenName)
	}
	var agentN int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE id='agent_x'`).Scan(&agentN); err != nil {
		t.Fatalf("count agents: %v", err)
	}
	if agentN != 0 {
		t.Errorf("agents still has %d rows for deleted agent", agentN)
	}

	// Missing-agent mutations report sql.ErrNoRows (handlers map this to 404).
	if err := reg.DeleteAgent(ctx, "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("DeleteAgent(missing) = %v, want sql.ErrNoRows", err)
	}
	if err := reg.UpdateAgent(ctx, "nope", "x"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UpdateAgent(missing) = %v, want sql.ErrNoRows", err)
	}
}

// TestConnectivityProvenance covers the AGENT-001/002 registry additions:
// first-connected is stamped once and never moves, disconnect kind is recorded
// and surfaced by SweepStale into the history reason, and the mute switch flips.
func TestConnectivityProvenance(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	stale := time.Now().UTC().Add(-time.Hour)

	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, stale)
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status,last_seen_at) VALUES('agent_c','site_default',x'00','h','online',?)`, stale)
	reg := New(db, 0, nil)

	// first_connected_at is nil until the first Hello, then stamped once.
	a, _ := reg.Get(ctx, "agent_c")
	if a.FirstConnectedAt != nil {
		t.Fatalf("expected nil first_connected_at, got %v", a.FirstConnectedAt)
	}
	if err := reg.MarkFirstConnected(ctx, "agent_c"); err != nil {
		t.Fatalf("MarkFirstConnected: %v", err)
	}
	a, _ = reg.Get(ctx, "agent_c")
	if a.FirstConnectedAt == nil {
		t.Fatalf("expected first_connected_at set")
	}
	first := *a.FirstConnectedAt
	if err := reg.MarkFirstConnected(ctx, "agent_c"); err != nil { // idempotent
		t.Fatalf("MarkFirstConnected 2: %v", err)
	}
	a, _ = reg.Get(ctx, "agent_c")
	if !a.FirstConnectedAt.Equal(first) {
		t.Fatalf("first_connected_at moved: %v -> %v", first, *a.FirstConnectedAt)
	}

	// RecordDisconnect feeds the offline transition's history reason.
	if err := reg.RecordDisconnect(ctx, "agent_c", "clean"); err != nil {
		t.Fatalf("RecordDisconnect: %v", err)
	}
	if _, err := reg.SweepStale(ctx, 10*time.Second, nil); err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	hist, _ := reg.StatusHistory(ctx, "agent_c")
	if len(hist) == 0 || hist[0].Status != "offline" || hist[0].Reason != "clean" {
		t.Fatalf("expected offline/clean history, got %+v", hist)
	}

	// Mute switch flips and surfaces on Get.
	if err := reg.SetConnectivityMuted(ctx, "agent_c", true); err != nil {
		t.Fatalf("SetConnectivityMuted: %v", err)
	}
	if a, _ = reg.Get(ctx, "agent_c"); !a.ConnectivityAlertsMuted {
		t.Fatalf("expected muted=true")
	}
	if err := reg.SetConnectivityMuted(ctx, "nope", true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("SetConnectivityMuted(missing) = %v, want sql.ErrNoRows", err)
	}
}

// TestSweepStaleExcludesConnected verifies the sweep's exclusion list: an agent
// with a stale last_seen_at but a live WebSocket session (its ID is in exclude)
// must stay online, while an equally stale, non-excluded agent flips offline
// with a history row.
func TestSweepStaleExcludesConnected(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	stale := time.Now().UTC().Add(-time.Hour)

	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, stale)
	for _, id := range []string{"agent_connected", "agent_gone"} {
		mustExec(t, db,
			`INSERT INTO agents(id,site_id,public_key,token_hash,status,last_seen_at) VALUES(?,'site_default',x'00','h','online',?)`,
			id, stale)
	}

	reg := New(db, 0, nil)
	n, err := reg.SweepStale(ctx, 10*time.Second, []string{"agent_connected"})
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if n != 1 {
		t.Errorf("SweepStale flipped %d agents, want 1", n)
	}
	for id, want := range map[string]string{"agent_connected": "online", "agent_gone": "offline"} {
		a, err := reg.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get(%s): %v", id, err)
		}
		if a.Status != want {
			t.Errorf("%s status = %q, want %q", id, a.Status, want)
		}
	}
	// Only the flipped agent gets an offline history row.
	if hist, _ := reg.StatusHistory(ctx, "agent_gone"); len(hist) != 1 || hist[0].Status != "offline" {
		t.Errorf("agent_gone history = %+v, want one offline event", hist)
	}
	if hist, _ := reg.StatusHistory(ctx, "agent_connected"); len(hist) != 0 {
		t.Errorf("agent_connected history = %+v, want none", hist)
	}
}

func TestStatusHistoryReturnsOnlyNewestTwentyEvents(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)

	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, base)
	mustExec(t, db,
		`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_history','site_default',x'00','h','online')`)
	for i := 0; i < 25; i++ {
		mustExec(t, db,
			`INSERT INTO agent_status_history(id,agent_id,status,changed_at) VALUES(?,'agent_history',?,?)`,
			fmt.Sprintf("ash_%02d", i), []string{"offline", "online"}[i%2], base.Add(time.Duration(i)*time.Minute))
	}

	history, err := New(db, 0, nil).StatusHistory(ctx, "agent_history")
	if err != nil {
		t.Fatalf("StatusHistory: %v", err)
	}
	if len(history) != statusHistoryLimit {
		t.Fatalf("history length = %d, want %d", len(history), statusHistoryLimit)
	}
	if want := base.Add(24 * time.Minute); !history[0].ChangedAt.Equal(want) {
		t.Errorf("newest event = %v, want %v", history[0].ChangedAt, want)
	}
	if want := base.Add(5 * time.Minute); !history[len(history)-1].ChangedAt.Equal(want) {
		t.Errorf("oldest returned event = %v, want %v", history[len(history)-1].ChangedAt, want)
	}
}
