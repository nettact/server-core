package registry

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/permission"
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
	// The game tables, all three. game_host_seconds is the one that matters most
	// here: it references agents directly and does NOT cascade, so leaving it out
	// of the purge makes the final DELETE FROM agents fail on the foreign key —
	// after the caller has already purged the agent's metrics, which leaves the
	// agent on screen with part of its history gone.
	mustExec(t, db, `INSERT INTO game_runs(id,agent_id,site_id,started_at,last_seen_at) VALUES('run1','agent_x','site_default',1,2)`)
	mustExec(t, db, `INSERT INTO game_buckets(run_id,ts,presented,ft_avg,ft_p50,ft_p95,ft_p99,ft_max,ft_sd,hist_layout,hist)
		VALUES('run1',1,60,16.6,16.5,17.2,18.1,20,0.4,'log24_v1',x'00')`)
	mustExec(t, db, `INSERT INTO game_run_gaps(id,run_id,reason,started_at,ended_at) VALUES('gap1','run1','background',2,9)`)
	mustExec(t, db, `INSERT INTO game_host_seconds(agent_id,site_id,ts,cpu_total_pct,cpu_busiest_pct) VALUES('agent_x','site_default',1,20,80)`)
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
		"agent_packets", "events", "detector_state", "game_runs", "game_host_seconds",
	} {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+tbl+` WHERE agent_id='agent_x'`).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows for deleted agent", tbl, n)
		}
	}
	// The two that hang off the run rather than off the agent go with it.
	for _, q := range []string{
		`SELECT COUNT(*) FROM game_buckets WHERE run_id='run1'`,
		`SELECT COUNT(*) FROM game_run_gaps WHERE run_id='run1'`,
	} {
		var n int
		if err := db.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if n != 0 {
			t.Errorf("%s left %d rows behind", q, n)
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

// TestUpdatePermissionsStoresUnsupportedReasons round-trips the per-permission
// "why not supported" map. It is full-state like the three sets beside it, so a
// later report that explains nothing must ERASE what an earlier one explained —
// otherwise a fixed sensor would keep reporting its old failure forever.
func TestUpdatePermissionsStoresUnsupportedReasons(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()

	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_p','site_default',x'00','h','online')`)
	reg := New(db, 0, nil)

	// Nothing reported yet: the column defaults to an empty object, which reads
	// back as "no permission has an explanation".
	a, err := reg.Get(ctx, "agent_p")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(a.UnsupportedReasons) != 0 {
		t.Fatalf("fresh agent reasons = %v, want none", a.UnsupportedReasons)
	}

	// A multi-entry report: two permissions, two different causes.
	reasons := map[string]string{
		"game.performance.read": gamesense.ReasonVersionMismatch,
		"game.gpu.read":         gamesense.ReasonGPUTelemetryUnavailable,
	}
	if err := reg.UpdatePermissions(ctx, "agent_p", permission.PermissionReport{
		Supported: []string{"probe.dns"}, Granted: []string{"probe.dns"}, Effective: []string{"probe.dns"},
		Source: "environment", PolicyHash: "h1", UnsupportedReasons: reasons,
	}); err != nil {
		t.Fatalf("UpdatePermissions: %v", err)
	}
	a, err = reg.Get(ctx, "agent_p")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(a.UnsupportedReasons) != len(reasons) {
		t.Fatalf("reasons = %v, want %v", a.UnsupportedReasons, reasons)
	}
	for id, want := range reasons {
		if got := a.UnsupportedReasons[id]; got != want {
			t.Errorf("reason[%s] = %q, want %q", id, got, want)
		}
	}
	// List reads the same column, so the agents list carries the reasons too.
	list, err := reg.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].UnsupportedReasons["game.gpu.read"] != gamesense.ReasonGPUTelemetryUnavailable {
		t.Fatalf("List reasons = %+v, want the stored map", list)
	}

	// Full-state replacement: an empty report clears them, and a nil map is stored
	// identically (both mean "nothing to explain").
	for name, report := range map[string]permission.PermissionReport{
		"empty map": {Source: "environment", PolicyHash: "h2", UnsupportedReasons: map[string]string{}},
		"nil map":   {Source: "environment", PolicyHash: "h3"},
	} {
		if err := reg.UpdatePermissions(ctx, "agent_p", report); err != nil {
			t.Fatalf("UpdatePermissions(%s): %v", name, err)
		}
		if a, err = reg.Get(ctx, "agent_p"); err != nil {
			t.Fatalf("Get after %s: %v", name, err)
		}
		if len(a.UnsupportedReasons) != 0 {
			t.Errorf("%s left reasons = %v, want cleared", name, a.UnsupportedReasons)
		}
		var stored string
		if err := db.QueryRowContext(ctx, `SELECT perm_unsupported_reasons FROM agents WHERE id='agent_p'`).Scan(&stored); err != nil {
			t.Fatalf("read column after %s: %v", name, err)
		}
		if stored != "{}" {
			t.Errorf("%s stored %q, want the empty object", name, stored)
		}
	}
}

// TestUpdatePermissionsDropsContradictoryReasons: a buggy or version-mismatched
// agent can report a permission as supported AND explain why it failed. Storing
// that would let the agents list and detail endpoints — which serialize
// registry.Agent wholesale — emit a payload claiming the capability works and
// naming why it doesn't at once. The contract is enforced once, here at the
// write boundary, so no reader has to reconcile it.
func TestUpdatePermissionsDropsContradictoryReasons(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()

	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_q','site_default',x'00','h','online')`)
	reg := New(db, 0, nil)

	if err := reg.UpdatePermissions(ctx, "agent_q", permission.PermissionReport{
		Supported: []string{"probe.dns", "game.process.detect"},
		Granted:   []string{"probe.dns", "game.process.detect"},
		Effective: []string{"probe.dns", "game.process.detect"},
		Source:    "environment", PolicyHash: "h1",
		UnsupportedReasons: map[string]string{
			"game.process.detect":   gamesense.ReasonInternalError,   // contradicts Supported
			"game.performance.read": gamesense.ReasonVersionMismatch, // legitimate
		},
	}); err != nil {
		t.Fatalf("UpdatePermissions: %v", err)
	}

	a, err := reg.Get(ctx, "agent_q")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, ok := a.UnsupportedReasons["game.process.detect"]; ok {
		t.Errorf("a supported permission must carry no reason, got %v", a.UnsupportedReasons)
	}
	if got := a.UnsupportedReasons["game.performance.read"]; got != gamesense.ReasonVersionMismatch {
		t.Errorf("the legitimate reason must survive, got %q", got)
	}

	// The agents list/detail endpoints marshal this struct directly, so the
	// contradiction must be impossible in the serialized form too.
	blob, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal agent: %v", err)
	}
	var payload struct {
		Supported          []string          `json:"supported"`
		UnsupportedReasons map[string]string `json:"unsupported_reasons"`
	}
	if err := json.Unmarshal(blob, &payload); err != nil {
		t.Fatalf("decode agent: %v", err)
	}
	for _, id := range payload.Supported {
		if reason, ok := payload.UnsupportedReasons[id]; ok {
			t.Errorf("serialized agent claims %s is supported and failed (%q)", id, reason)
		}
	}
}

// TestEnrollStoresUnsupportedReasons: the very first report is when a broken
// sensor is most likely to be what an operator is staring at, so enrollment must
// persist the reasons rather than leave the agent unexplained until it reconnects.
func TestEnrollStoresUnsupportedReasons(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()

	mustExec(t, db, `INSERT INTO sites(id,name,created_at,config_serial) VALUES('site_default','def',?,3)`, time.Now().UTC())
	reg := New(db, 0, nil)
	token, err := reg.CreateEnrollmentToken(ctx, "site_default", "test", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const nonce = "nonce-1"
	resp, err := reg.Enroll(ctx, enroll.EnrollRequest{
		SchemaVersion:   protocol.SchemaVersion,
		PublicKey:       pub,
		Nonce:           nonce,
		Signature:       ed25519.Sign(priv, []byte(nonce)),
		EnrollmentToken: token,
		Hostname:        "host-1",
		Platform:        "windows",
		AgentVersion:    "0.1.0",
		Permissions: permission.PermissionReport{
			Supported: []string{"probe.dns"}, Granted: []string{"probe.dns"}, Effective: []string{"probe.dns"},
			Source:             "environment",
			UnsupportedReasons: map[string]string{"game.performance.read": gamesense.ReasonVersionMismatch},
		},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	a, err := reg.Get(ctx, resp.AgentID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := a.UnsupportedReasons["game.performance.read"]; got != gamesense.ReasonVersionMismatch {
		t.Fatalf("enrolled reason = %q, want %q", got, gamesense.ReasonVersionMismatch)
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
