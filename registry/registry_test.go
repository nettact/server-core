package registry

import (
	"bytes"
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
		"events", "detector_state", "game_runs", "game_host_seconds",
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
	hist, _ := reg.StatusHistory(ctx, "agent_c", time.Time{})
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
	if hist, _ := reg.StatusHistory(ctx, "agent_gone", time.Time{}); len(hist) != 1 || hist[0].Status != "offline" {
		t.Errorf("agent_gone history = %+v, want one offline event", hist)
	}
	if hist, _ := reg.StatusHistory(ctx, "agent_connected", time.Time{}); len(hist) != 0 {
		t.Errorf("agent_connected history = %+v, want none", hist)
	}
}

func TestStatusHistoryFiltersBySince(t *testing.T) {
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

	since := base.Add(20 * time.Minute)
	history, err := New(db, 0, nil).StatusHistory(ctx, "agent_history", since)
	if err != nil {
		t.Fatalf("StatusHistory: %v", err)
	}
	if len(history) != 5 {
		t.Fatalf("history length = %d, want 5", len(history))
	}
	if want := base.Add(24 * time.Minute); !history[0].ChangedAt.Equal(want) {
		t.Errorf("newest event = %v, want %v", history[0].ChangedAt, want)
	}
	if want := since; !history[len(history)-1].ChangedAt.Equal(want) {
		t.Errorf("oldest returned event = %v, want %v", history[len(history)-1].ChangedAt, want)
	}
}

// enrollReq builds a signed EnrollRequest for the given keypair. The nonce is
// fixed per call site (Enroll verifies the signature, never the nonce value), so
// a helper with a single nonce is enough — the point is to vary the KEY.
func enrollReq(priv ed25519.PrivateKey, pub ed25519.PublicKey, token, hostname string, perms permission.PermissionReport) enroll.EnrollRequest {
	const nonce = "nonce-1"
	return enroll.EnrollRequest{
		SchemaVersion:   protocol.SchemaVersion,
		PublicKey:       pub,
		Nonce:           nonce,
		Signature:       ed25519.Sign(priv, []byte(nonce)),
		EnrollmentToken: token,
		Hostname:        hostname,
		Platform:        "windows",
		AgentVersion:    "0.1.0",
		Permissions:     perms,
	}
}

// TestReinstallTokenRejoinsSameAgent: AGENT-006. A reinstall token redeemed
// against an existing agent rejoins that SAME agents row — fresh bearer token and
// public key, same agent_id — so metrics/incident/status history is inherited and
// no "old offline + new online" pair is produced.
func TestReinstallTokenRejoinsSameAgent(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at,config_serial) VALUES('site_default','def',?,3)`, time.Now().UTC())
	reg := New(db, 0, nil)
	// Reenrollment must notify ingest to drop its in-memory sequence watermark
	// (the fresh WAL restarts at sequence 1) and fence the old session first; a
	// plain first enrollment must do neither.
	var resetCalls, disconnectCalls int
	reg.ResetSeqWatermark = func(context.Context, string) { resetCalls++ }
	reg.DisconnectSession = func(context.Context, string) { disconnectCalls++ }

	// First enrollment, machine A.
	siteToken, err := reg.CreateEnrollmentToken(ctx, "site_default", "first", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	pubA, privA, _ := ed25519.GenerateKey(nil)
	resp1, err := reg.Enroll(ctx, enrollReq(privA, pubA, siteToken, "host-a", permission.PermissionReport{
		Supported: []string{"probe.dns"}, Granted: []string{"probe.dns"}, Effective: []string{"probe.dns"},
		Source: "environment",
	}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if resp1.EnrollmentEpoch != 1 {
		t.Fatalf("fresh enrollment epoch = %d, want 1", resp1.EnrollmentEpoch)
	}
	if resetCalls != 0 {
		t.Fatalf("first enrollment reset the watermark %d times, want 0", resetCalls)
	}
	if disconnectCalls != 0 {
		t.Fatalf("first enrollment disconnected %d sessions, want 0", disconnectCalls)
	}
	agentID := resp1.AgentID
	var siteBefore, createdAt string
	if err := db.QueryRowContext(ctx, `SELECT site_id, created_at FROM agents WHERE id=?`, agentID).Scan(&siteBefore, &createdAt); err != nil {
		t.Fatalf("snapshot agent: %v", err)
	}
	// The old installation left state behind: agents.high_sequence is the ingest
	// dedup watermark that must NOT carry across a reinstall (the fresh WAL
	// starts again at sequence 1), and an agent_wifi row carries a SECOND
	// sequence guard that would reject the fresh snapshots until the new WAL
	// out-paces the old one. Also flip the agent offline, the state the
	// reinstall target is in.
	mustExec(t, db, `UPDATE agents SET high_sequence=4321 WHERE id=?`, agentID)
	mustExec(t, db, `INSERT INTO agent_wifi(agent_id, state, sampled_at, last_sequence) VALUES(?,'ok',?,999)`, agentID, time.Now().UTC())
	mustExec(t, db, `UPDATE agents SET status='offline' WHERE id=?`, agentID)
	// The old installation also attested a batch-upload cadence. A MonitorStatus
	// frame that omits the value deliberately keeps the last known one, so without
	// a reset here an older replacement would inherit this indefinitely and the
	// host detectors would judge its readings against a window it never reported.
	mustExec(t, db, `UPDATE agents SET upload_interval_seconds=300 WHERE id=?`, agentID)

	// Mint a reinstall token bound to this agent and redeem it as a fresh machine
	// (a NEW ed25519 key — this is the "key lost with the old disk" scenario).
	reToken, err := reg.CreateReinstallToken(ctx, agentID, time.Hour)
	if err != nil {
		t.Fatalf("CreateReinstallToken: %v", err)
	}
	pubB, privB, _ := ed25519.GenerateKey(nil)
	resp2, err := reg.Enroll(ctx, enrollReq(privB, pubB, reToken, "host-b", permission.PermissionReport{
		Supported: []string{"probe.tcp"}, Granted: []string{"probe.tcp"}, Effective: []string{"probe.tcp"},
		Source: "file",
	}))
	if err != nil {
		t.Fatalf("reinstall Enroll: %v", err)
	}
	if resp2.AgentID != agentID {
		t.Fatalf("reinstall agent_id = %q, want %q", resp2.AgentID, agentID)
	}
	if resp2.EnrollmentEpoch != 2 {
		t.Fatalf("reinstall epoch = %d, want 2 — a reinstall replaces an install and must never reuse a generation", resp2.EnrollmentEpoch)
	}
	if resetCalls != 1 {
		t.Errorf("reinstall reset the watermark %d times, want 1", resetCalls)
	}
	if disconnectCalls != 1 {
		t.Errorf("reinstall disconnected %d sessions, want 1", disconnectCalls)
	}
	// The row itself carries the advanced generation, and no rotation is staged
	// (a reinstall invalidates any outstanding rotation of the dead lineage).
	var storedEpoch uint64
	var pendingEpoch uint64
	var pendingUntil int64
	if err := db.QueryRowContext(ctx,
		`SELECT enrollment_epoch, pending_next_epoch, pending_next_until FROM agents WHERE id=?`,
		agentID).Scan(&storedEpoch, &pendingEpoch, &pendingUntil); err != nil {
		t.Fatalf("read epoch columns: %v", err)
	}
	if storedEpoch != 2 {
		t.Errorf("stored enrollment_epoch = %d, want 2", storedEpoch)
	}
	if pendingEpoch != 0 || pendingUntil != 0 {
		t.Errorf("pending rotation after reinstall = %d/%d, want none staged", pendingEpoch, pendingUntil)
	}

	// Still exactly one agent row: the reinstall re-bound it, it did not add one.
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("agent rows = %d (err %v), want 1", n, err)
	}

	// The row was updated in place: new public key, operator/site provenance kept.
	var pubNow []byte
	var siteAfter, createdAtAfter string
	if err := db.QueryRowContext(ctx, `SELECT public_key, site_id, created_at FROM agents WHERE id=?`, agentID).Scan(&pubNow, &siteAfter, &createdAtAfter); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	var cadenceAfter int
	if err := db.QueryRowContext(ctx, `SELECT upload_interval_seconds FROM agents WHERE id=?`, agentID).Scan(&cadenceAfter); err != nil {
		t.Fatalf("read cadence: %v", err)
	}
	if cadenceAfter != 0 {
		t.Errorf("upload_interval_seconds = %d after a reinstall, want 0: a new "+
			"installation must not inherit its predecessor's cadence", cadenceAfter)
	}
	if !bytes.Equal(pubNow, pubB) {
		t.Errorf("public_key = %x, want the new machine's %x", pubNow, pubB)
	}
	if siteAfter != siteBefore {
		t.Errorf("site_id moved from %q to %q on reinstall", siteBefore, siteAfter)
	}
	if createdAtAfter != createdAt {
		t.Errorf("created_at moved from %q to %q on reinstall", createdAt, createdAtAfter)
	}

	// The freshly issued bearer token authenticates; the old one no longer does.
	if _, err := reg.AuthenticateAgent(ctx, resp2.AgentToken); err != nil {
		t.Errorf("new bearer token rejected: %v", err)
	}
	if _, err := reg.AuthenticateAgent(ctx, resp1.AgentToken); err == nil {
		t.Errorf("old bearer token still authenticates after reinstall")
	}

	// The reinstall token was consumed. The reinstall itself records NO online
	// transition — the agent stays offline until its new session connects, so the
	// liveness event fires then (TouchLastSeen).
	var used sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT used_at FROM enrollment_tokens WHERE token_hash=?`, sha256hex(reToken)).Scan(&used); err != nil {
		t.Fatalf("read reinstall token: %v", err)
	}
	if !used.Valid {
		t.Errorf("reinstall token not consumed")
	}
	// The dedup watermark is reset: the fresh WAL's sequence 1 will be accepted.
	var high int
	if err := db.QueryRowContext(ctx, `SELECT high_sequence FROM agents WHERE id=?`, agentID).Scan(&high); err != nil {
		t.Fatalf("read high_sequence: %v", err)
	}
	if high != 0 {
		t.Errorf("high_sequence = %d after reinstall, want 0", high)
	}
	// The interface-snapshot sequence guard is gone with it, so the first fresh
	// snapshot is no longer rejected as older than the previous installation's.
	var wifi int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_wifi WHERE agent_id=?`, agentID).Scan(&wifi); err != nil {
		t.Fatalf("count wifi: %v", err)
	}
	if wifi != 0 {
		t.Errorf("agent_wifi has %d rows after reinstall, want 0", wifi)
	}
	// Still offline (no pre-connect liveness claim).
	var statusAfter string
	if err := db.QueryRowContext(ctx, `SELECT status FROM agents WHERE id=?`, agentID).Scan(&statusAfter); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if statusAfter != "offline" {
		t.Errorf("status after reinstall = %q, want offline until the session connects", statusAfter)
	}
	var joins int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_status_history WHERE agent_id=? AND status='online'`, agentID).Scan(&joins); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if joins != 1 {
		t.Errorf("online history rows = %d, want 1 (first enroll only; reinstall defers to the session)", joins)
	}

	// The new session's Hello flips the agent online through the normal path.
	if err := reg.TouchLastSeen(ctx, agentID); err != nil {
		t.Fatalf("TouchLastSeen: %v", err)
	}
	var statusLive string
	if err := db.QueryRowContext(ctx, `SELECT status FROM agents WHERE id=?`, agentID).Scan(&statusLive); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if statusLive != "online" {
		t.Errorf("status after TouchLastSeen = %q, want online", statusLive)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_status_history WHERE agent_id=? AND status='online'`, agentID).Scan(&joins); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if joins != 2 {
		t.Errorf("online history rows after reconnect = %d, want 2", joins)
	}

	// The permission mirror reflects the NEW machine's report, not the old one.
	a, err := reg.Get(ctx, agentID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(a.Supported) != 1 || a.Supported[0] != "probe.tcp" {
		t.Errorf("supported = %v, want the new machine's [probe.tcp]", a.Supported)
	}
}

// TestReinstallTokenCascadeOnDelete: the reinstall token references its agent with
// ON DELETE CASCADE, so hard-deleting the agent removes the token with it — a
// stale token then reads as a plain invalid token rather than stranding a
// reference to nothing.
func TestReinstallTokenCascadeOnDelete(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	pub, priv, _ := ed25519.GenerateKey(nil)
	siteToken, err := reg.CreateEnrollmentToken(ctx, "site_default", "first", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	resp, err := reg.Enroll(ctx, enrollReq(priv, pub, siteToken, "host", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	reToken, err := reg.CreateReinstallToken(ctx, resp.AgentID, time.Hour)
	if err != nil {
		t.Fatalf("CreateReinstallToken: %v", err)
	}

	if err := reg.DeleteAgent(ctx, resp.AgentID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	var left int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM enrollment_tokens WHERE agent_id=?`, resp.AgentID).Scan(&left); err != nil {
		t.Fatalf("count reinstall tokens: %v", err)
	}
	if left != 0 {
		t.Fatalf("delete left %d reinstall tokens behind", left)
	}

	// The stale token is now indistinguishable from a bogus one.
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	if _, err := reg.Enroll(ctx, enrollReq(priv2, pub2, reToken, "host2", permission.PermissionReport{})); !errors.Is(err, ErrEnrollToken) {
		t.Fatalf("Enroll after delete = %v, want ErrEnrollToken", err)
	}
}

// TestReinstallTokenRejectedForRevokedAgent: the reenroll guard refuses a
// soft-revoked (revoked=1) agent too. That state is not produced by the console
// yet (only hard delete exists), but the token can reference such an agent and
// the guard must not silently bind a revoked row.
func TestReinstallTokenRejectedForRevokedAgent(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	mustExec(t, db,
		`INSERT INTO agents(id,site_id,public_key,token_hash,status,revoked) VALUES('agent_r','site_default',x'00','h','offline',1)`)
	reg := New(db, 0, nil)

	// CreateReinstallToken itself demands a live agent, so the token is written by
	// hand — it references a row that exists but is revoked.
	token := "reinstall-token-handwritten"
	mustExec(t, db,
		`INSERT INTO enrollment_tokens(token_hash,site_id,note,expires_at,agent_id)
		 VALUES(?,'site_default','reinstall:agent_r',?,'agent_r')`,
		sha256hex(token), time.Now().UTC().Add(time.Hour))

	pub, priv, _ := ed25519.GenerateKey(nil)
	if _, err := reg.Enroll(ctx, enrollReq(priv, pub, token, "host", permission.PermissionReport{})); !errors.Is(err, ErrReinstallAgent) {
		t.Fatalf("Enroll for revoked agent = %v, want ErrReinstallAgent", err)
	}
	// The failure rolled back with the transaction, so the token stays unused.
	var used sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT used_at FROM enrollment_tokens WHERE token_hash=?`, sha256hex(token)).Scan(&used); err != nil {
		t.Fatalf("read reinstall token: %v", err)
	}
	if used.Valid {
		t.Errorf("token consumed despite its agent being revoked")
	}
}

// TestReinstallTokenRevoked: a revoked token is rejected at enrollment, and
// revoking an unknown or already-used token is a 404-shaped sql.ErrNoRows.
func TestReinstallTokenRevoked(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	pub, priv, _ := ed25519.GenerateKey(nil)
	siteToken, err := reg.CreateEnrollmentToken(ctx, "site_default", "first", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	// Enroll with the site token (consuming it), then revoke it: used tokens are
	// no-ops for revoke.
	resp, err := reg.Enroll(ctx, enrollReq(priv, pub, siteToken, "host", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := reg.RevokeEnrollmentToken(ctx, sha256hex(siteToken)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("revoking a used token = %v, want sql.ErrNoRows", err)
	}
	if err := reg.RevokeEnrollmentToken(ctx, "deadbeef"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("revoking an unknown token = %v, want sql.ErrNoRows", err)
	}

	// An unused token revokes cleanly, then enrollment rejects it.
	reToken, err := reg.CreateReinstallToken(ctx, resp.AgentID, time.Hour)
	if err != nil {
		t.Fatalf("CreateReinstallToken: %v", err)
	}
	if err := reg.RevokeEnrollmentToken(ctx, sha256hex(reToken)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	if _, err := reg.Enroll(ctx, enrollReq(priv2, pub2, reToken, "host2", permission.PermissionReport{})); !errors.Is(err, ErrEnrollToken) {
		t.Fatalf("Enroll with revoked token = %v, want ErrEnrollToken", err)
	}
}

// TestReinstallSkipsQuota: a reinstall reuses an existing row, so it must NOT be
// blocked by a full agent quota the way a fresh enrollment would.
func TestReinstallSkipsQuota(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 1, nil)

	pub, priv, _ := ed25519.GenerateKey(nil)
	siteToken, err := reg.CreateEnrollmentToken(ctx, "site_default", "first", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	resp, err := reg.Enroll(ctx, enrollReq(priv, pub, siteToken, "host", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Quota is now full (maxAgents=1). A fresh enroll would 403; the reinstall
	// must sail through because it adds no row.
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	siteToken2, _ := reg.CreateEnrollmentToken(ctx, "site_default", "second", time.Hour)
	if _, err := reg.Enroll(ctx, enrollReq(priv2, pub2, siteToken2, "host2", permission.PermissionReport{})); !errors.Is(err, ErrQuota) {
		t.Fatalf("fresh enroll at quota = %v, want ErrQuota", err)
	}

	reToken, err := reg.CreateReinstallToken(ctx, resp.AgentID, time.Hour)
	if err != nil {
		t.Fatalf("CreateReinstallToken: %v", err)
	}
	pub3, priv3, _ := ed25519.GenerateKey(nil)
	re, err := reg.Enroll(ctx, enrollReq(priv3, pub3, reToken, "host3", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("reinstall at quota = %v, want success", err)
	}
	if re.AgentID != resp.AgentID {
		t.Fatalf("reinstall agent_id = %q, want %q", re.AgentID, resp.AgentID)
	}
}

// TestReinstallTokenSupersedesEarlierOnes: minting a reinstall token revokes the
// agent's other unused reinstall tokens, so a console that opened the dialog
// several times cannot leave a pile of valid credentials for one identity — an
// earlier exposed one could otherwise rebind the agent after a fresh token was
// handed out.
func TestReinstallTokenSupersedesEarlierOnes(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	pub, priv, _ := ed25519.GenerateKey(nil)
	siteToken, err := reg.CreateEnrollmentToken(ctx, "site_default", "first", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	resp, err := reg.Enroll(ctx, enrollReq(priv, pub, siteToken, "host", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	first, err := reg.CreateReinstallToken(ctx, resp.AgentID, time.Hour)
	if err != nil {
		t.Fatalf("first CreateReinstallToken: %v", err)
	}
	second, err := reg.CreateReinstallToken(ctx, resp.AgentID, time.Hour)
	if err != nil {
		t.Fatalf("second CreateReinstallToken: %v", err)
	}

	var revoked int
	if err := db.QueryRowContext(ctx, `SELECT revoked FROM enrollment_tokens WHERE token_hash=?`, sha256hex(first)).Scan(&revoked); err != nil {
		t.Fatalf("read first token: %v", err)
	}
	if revoked == 0 {
		t.Errorf("first reinstall token still usable after a fresh mint")
	}

	pub2, priv2, _ := ed25519.GenerateKey(nil)
	if _, err := reg.Enroll(ctx, enrollReq(priv2, pub2, first, "host2", permission.PermissionReport{})); !errors.Is(err, ErrEnrollToken) {
		t.Fatalf("Enroll with superseded token = %v, want ErrEnrollToken", err)
	}
	pub3, priv3, _ := ed25519.GenerateKey(nil)
	re, err := reg.Enroll(ctx, enrollReq(priv3, pub3, second, "host3", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll with latest token: %v", err)
	}
	if re.AgentID != resp.AgentID {
		t.Fatalf("agent_id = %q, want %q", re.AgentID, resp.AgentID)
	}
}

// TestEnrollAppliesTokenNoteAsDisplayName: the note an operator types when
// minting a token describes the machine they are about to install on, so a fresh
// enrollment must come up already carrying that name instead of a bare hostname
// the operator has to rename by hand.
func TestEnrollAppliesTokenNoteAsDisplayName(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at,config_serial) VALUES('site_default','def',?,1)`, time.Now().UTC())
	reg := New(db, 0, nil)

	token, err := reg.CreateEnrollmentToken(ctx, "site_default", "  客厅路由器  ", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	resp, err := reg.Enroll(ctx, enrollReq(priv, pub, token, "host-a", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	a, err := reg.Get(ctx, resp.AgentID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Trimmed: the note is free text an operator typed into a form, and a name
	// with stray padding sorts and reads wrong everywhere it is shown.
	if a.DisplayName != "客厅路由器" {
		t.Fatalf("display name = %q, want %q", a.DisplayName, "客厅路由器")
	}

	// An empty note leaves the name UNSET rather than empty-but-present, so the
	// console's display_name || hostname fallback still names the device.
	blank, err := reg.CreateEnrollmentToken(ctx, "site_default", "   ", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken(blank): %v", err)
	}
	pubB, privB, _ := ed25519.GenerateKey(nil)
	respB, err := reg.Enroll(ctx, enrollReq(privB, pubB, blank, "host-b", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll(blank note): %v", err)
	}
	var name sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT display_name FROM agents WHERE id=?`, respB.AgentID).Scan(&name); err != nil {
		t.Fatalf("read display_name: %v", err)
	}
	if name.Valid {
		t.Fatalf("display_name = %q, want NULL for a blank token note", name.String)
	}

	// A reinstall keeps the name the operator gave the agent: its token note is
	// the server's own "reinstall:<id>" bookkeeping, which must never surface as a
	// device name.
	if err := reg.UpdateAgent(ctx, resp.AgentID, "改名后"); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	reToken, err := reg.CreateReinstallToken(ctx, resp.AgentID, time.Hour)
	if err != nil {
		t.Fatalf("CreateReinstallToken: %v", err)
	}
	pubC, privC, _ := ed25519.GenerateKey(nil)
	reResp, err := reg.Enroll(ctx, enrollReq(privC, pubC, reToken, "host-a", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll(reinstall): %v", err)
	}
	if reResp.AgentID != resp.AgentID {
		t.Fatalf("reinstall agent_id = %q, want %q", reResp.AgentID, resp.AgentID)
	}
	again, err := reg.Get(ctx, reResp.AgentID)
	if err != nil {
		t.Fatalf("Get after reinstall: %v", err)
	}
	if again.DisplayName != "改名后" {
		t.Fatalf("display name after reinstall = %q, want %q", again.DisplayName, "改名后")
	}
}
