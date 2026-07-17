package agentws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/hostlive"
	"github.com/nettact/server-core/ingest"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/opissue"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/site"
	"github.com/nettact/server-core/store"
)

// testEnv wires the real services the hub needs against a throwaway SQLite DB
// and serves HandleUpgrade from an httptest.Server, so tests drive the same
// code path an agent does (upgrade, subprotocol negotiation, frames).
type testEnv struct {
	srv      *httptest.Server
	hub      *Hub
	db       *store.DB
	reg      *registry.Service
	cfg      *config.Service
	hostLive *hostlive.Store
	bus      *eventbus.Bus
	groupID  string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := site.New(db).EnsureDefault(ctx); err != nil {
		t.Fatalf("ensure default site: %v", err)
	}
	reg := registry.New(db, 0, nil)
	bus := eventbus.New()
	cfg := config.New(db, reg, bus, nil)
	groupID, err := cfg.EnsureDefaultGroup(ctx, site.DefaultSiteID)
	if err != nil {
		t.Fatalf("ensure default monitor group: %v", err)
	}
	hostLive := hostlive.New()
	hub := New(Deps{
		Registry: reg,
		Ingest:   ingest.New(db, bus, metrics.New(db), nil),
		Config:   cfg,
		HostLive: hostLive,
		OpIssue:  opissue.New(db, bus),
		Bus:      bus,
	})

	srv := httptest.NewServer(http.HandlerFunc(hub.HandleUpgrade))
	t.Cleanup(srv.Close)
	return &testEnv{srv: srv, hub: hub, db: db, reg: reg, cfg: cfg, hostLive: hostLive, bus: bus, groupID: groupID}
}

// setTargets replaces the default site's broadcast targets, bumping every
// seeded agent's config_version by one (call AFTER seedAgent for the bump to
// reach the agent).
func (e *testEnv) setTargets(t *testing.T, targets ...string) {
	t.Helper()
	pts := make([]config.ProbeTarget, 0, len(targets))
	for _, tgt := range targets {
		pts = append(pts, config.ProbeTarget{GroupID: e.groupID, Kind: "icmp", Target: tgt, Enabled: true})
	}
	if err := e.cfg.SetSiteTargets(context.Background(), site.DefaultSiteID, pts); err != nil {
		t.Fatalf("set targets: %v", err)
	}
}

// seedAgent inserts an enrolled agent directly (skipping the ed25519 dance —
// enrollment has its own coverage) and returns its bearer token. Status starts
// 'offline' so the tests can observe the connect flipping it online.
func (e *testEnv) seedAgent(t *testing.T, id, token string) {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	if _, err := e.db.ExecContext(context.Background(),
		`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES(?,?,x'00',?,'offline')`,
		id, site.DefaultSiteID, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
}

// dial opens a client WebSocket to the test server with the agent bearer token.
func (e *testEnv) dial(t *testing.T, token string, subprotocols ...string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, e.srv.URL, &websocket.DialOptions{
		Subprotocols: subprotocols,
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
	conn.SetReadLimit(maxFrameBytes)
	return conn
}

func sendFrame(t *testing.T, conn *websocket.Conn, f wire.Frame) {
	t.Helper()
	ct := wire.SubprotocolContentType(conn.Subprotocol())
	data, err := wire.MarshalFrame(f, ct)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	msgType := websocket.MessageText
	if ct == wire.ContentTypeProtobuf {
		msgType = websocket.MessageBinary
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, msgType, data); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func readFrame(t *testing.T, conn *websocket.Conn) wire.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	f, err := wire.UnmarshalFrame(data, wire.SubprotocolContentType(conn.Subprotocol()))
	if err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	return f
}

func testHello() wire.Frame {
	return wire.Frame{Hello: &wire.Hello{
		SchemaVersion: protocol.SchemaVersion,
		Hostname:      "ws-host",
		Platform:      "linux",
		AgentVersion:  "test",
		Permissions: permission.PermissionReport{
			Supported:  []string{"probe.icmp"},
			Granted:    []string{"probe.icmp"},
			Effective:  []string{"probe.icmp"},
			Source:     "environment",
			PolicyHash: "h1",
		},
	}}
}

func testPacket(seq uint64) wire.Frame {
	now := time.Now().UTC().Truncate(time.Second)
	return wire.Frame{Packet: &telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion,
		Sequence:      seq,
		SentAt:        now,
		Metrics: []telemetry.Metric{
			{TS: now, Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Value: 11.2, Unit: telemetry.UnitMs},
		},
	}}
}

// expectClose asserts the next read fails with the given close status.
func expectClose(t *testing.T, conn *websocket.Conn, want wire.CloseCode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := conn.Read(ctx)
	if err == nil {
		t.Fatalf("expected close %d, got a frame", want)
	}
	if got := websocket.CloseStatus(err); got != websocket.StatusCode(want) {
		t.Fatalf("close status = %d (%v), want %d", got, err, want)
	}
}

// TestConnectHelloOnline covers the connect path: hello marks the agent online
// immediately (with its reported info refreshed), the current DesiredState is
// pushed unconditionally, and the hub tracks the session.
func TestConnectHelloOnline(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	e.setTargets(t, "1.1.1.1") // config_version 0 -> 1

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())

	f := readFrame(t, conn)
	if f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}
	if f.DesiredState.ConfigVersion != 1 || len(f.DesiredState.ProbeTargets) != 1 {
		t.Errorf("DesiredState = version %d with %d targets, want version 1 with 1",
			f.DesiredState.ConfigVersion, len(f.DesiredState.ProbeTargets))
	}

	a, err := e.reg.Get(context.Background(), "agent_a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if a.Status != "online" {
		t.Errorf("status = %q, want online", a.Status)
	}
	if a.LastSeenAt == nil {
		t.Error("last_seen_at not stamped on connect")
	}
	if a.Hostname != "ws-host" || a.Platform != "linux" || a.AgentVersion != "test" {
		t.Errorf("reported info not refreshed: %q/%q/%q", a.Hostname, a.Platform, a.AgentVersion)
	}
	if len(a.Effective) != 1 || a.Effective[0] != "probe.icmp" || a.PolicySource != "environment" {
		t.Errorf("permissions = effective %v source %q, want [probe.icmp]/environment", a.Effective, a.PolicySource)
	}
	if !e.hub.IsConnected("agent_a") {
		t.Error("hub does not report agent connected")
	}
}

// TestDisconnectEvicts covers the agent-delete eviction path: Disconnect must
// synchronously close the live session with wire.CloseRevoked (telling the agent
// not to reconnect) and drop it from the hub's tracking.
func TestDisconnectEvicts(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}

	e.hub.Disconnect("agent_a", wire.CloseRevoked, "agent deleted")
	expectClose(t, conn, wire.CloseRevoked)
	// The session's teardown unregisters asynchronously to Disconnect's close;
	// poll briefly rather than race it.
	deadline := time.Now().Add(5 * time.Second)
	for e.hub.IsConnected("agent_a") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.hub.IsConnected("agent_a") {
		t.Error("hub still reports agent connected after Disconnect")
	}
	// Idempotent: disconnecting an agent with no session is a no-op.
	e.hub.Disconnect("agent_a", wire.CloseRevoked, "agent deleted")
}

// TestPacketAckRoundTrip streams packets over the protobuf subprotocol and
// asserts acks come back in FIFO order with the advancing watermark.
func TestPacketAckRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolProtobuf)
	if got := conn.Subprotocol(); got != wire.SubprotocolProtobuf {
		t.Fatalf("negotiated subprotocol = %q, want %q", got, wire.SubprotocolProtobuf)
	}
	sendFrame(t, conn, testHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}

	// Send a burst, then read the acks: the single reader + ordered write queue
	// must return them FIFO with a monotonic watermark.
	for seq := uint64(1); seq <= 3; seq++ {
		sendFrame(t, conn, testPacket(seq))
	}
	for seq := uint64(1); seq <= 3; seq++ {
		f := readFrame(t, conn)
		if f.Ack == nil {
			t.Fatalf("frame %d = %+v, want Ack", seq, f)
		}
		if f.Ack.HighestSequence != seq {
			t.Errorf("ack %d: highest_sequence = %d", seq, f.Ack.HighestSequence)
		}
		if f.Ack.ServerTime.IsZero() {
			t.Errorf("ack %d: server_time is zero", seq)
		}
	}

	// A replayed sequence still acks the watermark (idempotent dedup).
	sendFrame(t, conn, testPacket(2))
	if f := readFrame(t, conn); f.Ack == nil || f.Ack.HighestSequence != 3 {
		t.Errorf("replay ack = %+v, want watermark 3", f.Ack)
	}
}

// TestConfigChangePush proves the bus wiring: editing targets publishes
// TopicConfigChanged and the hub pushes fresh DesiredState to the live session.
func TestConfigChangePush(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	e.setTargets(t, "1.1.1.1") // config_version 0 -> 1

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}

	e.setTargets(t, "1.1.1.1", "8.8.8.8") // config_version 1 -> 2

	f := readFrame(t, conn)
	if f.DesiredState == nil {
		t.Fatalf("config-change push = %+v, want DesiredState", f)
	}
	if f.DesiredState.ConfigVersion != 2 || len(f.DesiredState.ProbeTargets) != 2 {
		t.Errorf("pushed DesiredState = version %d with %d targets, want version 2 with 2",
			f.DesiredState.ConfigVersion, len(f.DesiredState.ProbeTargets))
	}
}

// TestKickSuperseded connects the same agent twice: the first session must be
// closed with wire.CloseSuperseded, and its (later) unregister must not evict the
// replacement from the hub.
func TestKickSuperseded(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn1 := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn1, testHello())
	if f := readFrame(t, conn1); f.DesiredState == nil {
		t.Fatalf("conn1 first push = %+v, want DesiredState", f)
	}

	conn2 := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn2, testHello())
	if f := readFrame(t, conn2); f.DesiredState == nil {
		t.Fatalf("conn2 first push = %+v, want DesiredState", f)
	}

	expectClose(t, conn1, wire.CloseSuperseded)

	// Give the kicked session's deferred unregister time to run, then confirm
	// the identity compare kept the NEW session registered.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !e.hub.IsConnected("agent_a") {
			t.Fatal("kicked session evicted its replacement from the hub")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The replacement session must still be usable end to end.
	sendFrame(t, conn2, testPacket(1))
	if f := readFrame(t, conn2); f.Ack == nil || f.Ack.HighestSequence != 1 {
		t.Errorf("post-kick ack = %+v, want watermark 1", f.Ack)
	}
}

// TestSnapshotRequestPush covers the live-snapshot round trip: a pushed request
// reaches the agent, and the answering HostSnapshot frame lands in hostlive.
func TestSnapshotRequestPush(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	if e.hub.PushSnapshotRequest("agent_a", e.hostLive.Request("agent_a", []string{"host.process.basic.read", "host.connection.summary.read"})) {
		t.Fatal("push to a disconnected agent must return false")
	}

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}
	// The request registered before the connect is still pending, so the hub
	// re-pushed it right after DesiredState (the reconnect-blip path).
	f := readFrame(t, conn)
	if f.SnapshotRequest == nil {
		t.Fatalf("second push = %+v, want re-pushed SnapshotRequest", f)
	}

	// A fresh request while connected pushes directly.
	req := e.hostLive.Request("agent_a", []string{"host.process.basic.read"})
	if !e.hub.PushSnapshotRequest("agent_a", req) {
		t.Fatal("push to a connected agent returned false")
	}
	f = readFrame(t, conn)
	if f.SnapshotRequest == nil || f.SnapshotRequest.RequestID != req.RequestID {
		t.Fatalf("pushed frame = %+v, want SnapshotRequest %s", f, req.RequestID)
	}
	if len(f.SnapshotRequest.Scopes) != 1 || f.SnapshotRequest.Scopes[0] != "host.process.basic.read" {
		t.Errorf("request scopes = %+v, want [host.process.basic.read]", f.SnapshotRequest.Scopes)
	}

	// Answer it; the snapshot is stored (and the pending entry cleared) without
	// any ack coming back.
	total := 42
	sendFrame(t, conn, wire.Frame{HostSnapshot: &telemetry.HostSnapshot{
		TS: time.Now().UTC(), RequestID: req.RequestID, ProcessTotal: &total,
	}})
	deadline := time.Now().Add(2 * time.Second)
	for {
		snap, ok, pending := e.hostLive.Latest("agent_a")
		if ok && !pending {
			if snap.ProcessTotal == nil || *snap.ProcessTotal != 42 {
				t.Errorf("stored snapshot ProcessTotal = %v, want 42", snap.ProcessTotal)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("snapshot never stored (ok=%v pending=%v)", ok, pending)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestBadFirstFrame rejects a connection whose first frame is not a Hello.
func TestBadFirstFrame(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testPacket(1))
	expectClose(t, conn, wire.CloseProtocolError)
}

// TestServerToAgentFrameRejected closes the session when the agent sends a
// frame kind that only flows server->agent.
func TestServerToAgentFrameRejected(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}
	sendFrame(t, conn, wire.Frame{Ack: &wire.Ack{HighestSequence: 1}})
	expectClose(t, conn, wire.CloseProtocolError)
}

// TestMissingSubprotocol closes a client that offered neither nettact.v1
// subprotocol, since no Frame encoding was ever agreed on.
func TestMissingSubprotocol(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a") // no subprotocols offered
	expectClose(t, conn, wire.CloseUnsupportedSubprotocol)
}

// TestMalformedFrameAfterHello sends undecodable bytes once the session is live
// and expects a protocol-error close (4003), not a generic normal closure — the
// codec error must be classified even though the transport is otherwise healthy.
func TestMalformedFrameAfterHello(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}
	// Garbage that is neither valid JSON nor a valid Frame.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte("{not a frame")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	expectClose(t, conn, wire.CloseProtocolError)
}

// TestUnauthorized rejects a bad bearer token with a plain 401 before any
// upgrade happens.
func TestUnauthorized(t *testing.T) {
	e := newTestEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, e.srv.URL, &websocket.DialOptions{
		Subprotocols: []string{wire.SubprotocolJSON},
		HTTPHeader:   http.Header{"Authorization": {"Bearer nope"}},
	})
	if err == nil {
		t.Fatal("dial succeeded with a bad token")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("response = %+v, want 401", resp)
	}
}

// TestDialLocal covers the in-process desktop path: DialLocal authenticates the
// token, serves the server end over a pipe (same lifecycle as a WS session), and
// returns the agent end. It must run the full Hello→DesiredState→Packet→Ack flow
// with no WebSocket, kick a duplicate dial with CloseSuperseded, close on
// CloseAll, and reject a bad token.
func TestDialLocal(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	e.setTargets(t, "1.1.1.1") // config_version 0 -> 1

	ctx := context.Background()

	// Bad token: a dial error, before any session exists.
	if _, err := e.hub.DialLocal(ctx, "wrong"); err == nil {
		t.Fatal("DialLocal with a bad token succeeded")
	}

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	// Hello up, DesiredState down.
	if err := c.WriteFrame(ctx, testHello()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	f, err := c.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("read desired state: %v", err)
	}
	if f.DesiredState == nil || f.DesiredState.ConfigVersion != 1 || len(f.DesiredState.ProbeTargets) != 1 {
		t.Fatalf("first push = %+v, want DesiredState v1 with 1 target", f)
	}

	// Packet up, Ack down.
	if err := c.WriteFrame(ctx, testPacket(1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	f, err = c.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if f.Ack == nil || f.Ack.HighestSequence != 1 {
		t.Fatalf("ack = %+v, want HighestSequence 1", f)
	}

	// The hub tracks the pipe session like any other.
	deadline := time.Now().Add(2 * time.Second)
	for !e.hub.IsConnected("agent_a") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !e.hub.IsConnected("agent_a") {
		t.Fatal("hub does not report the local agent connected")
	}

	// A second dial supersedes the first: the original agent end sees 4000.
	c2, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("second DialLocal: %v", err)
	}
	if err := c2.WriteFrame(ctx, testHello()); err != nil {
		t.Fatalf("write hello 2: %v", err)
	}
	if _, err := c2.ReadFrame(ctx); err != nil {
		t.Fatalf("read desired state 2: %v", err)
	}
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	if _, err := c.ReadFrame(rctx); wire.CloseStatus(err) != wire.CloseSuperseded {
		t.Fatalf("first session close = %v, want CloseSuperseded", err)
	}

	// CloseAll tears the live session down with CloseGoingAway.
	e.hub.CloseAll("shutting down")
	gctx, gcancel := context.WithTimeout(ctx, 5*time.Second)
	defer gcancel()
	if _, err := c2.ReadFrame(gctx); wire.CloseStatus(err) != wire.CloseGoingAway {
		t.Fatalf("CloseAll close = %v, want CloseGoingAway", err)
	}
}
