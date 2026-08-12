package agentws

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/enroll"
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
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/tsstore/tsstoretest"
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
	db := storetest.Open(t)

	ctx := context.Background()
	if err := site.New(db).EnsureDefault(ctx); err != nil {
		t.Fatalf("ensure default site: %v", err)
	}
	reg := registry.New(db, 0, nil)
	bus := eventbus.New()
	cfg := config.New(db, reg, bus, nil, nil)
	groupID, err := cfg.EnsureDefaultGroup(ctx, site.DefaultSiteID)
	if err != nil {
		t.Fatalf("ensure default monitor group: %v", err)
	}
	hostLive := hostlive.New()
	hub := New(Deps{
		Registry: reg,
		Ingest:   ingest.New(db, bus, metrics.New(db, tsstoretest.Open(t)), nil, nil, nil),
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

// readFrameUntilAck reads from an in-process session until an Ack arrives,
// discarding DesiredState pushes. The server may push DesiredState at any
// moment — a config edit made before the agent connected still fans out on the
// hub's own goroutine, which can land mid-session — so a test that wants the
// Ack must not assume it is the next frame on the wire.
func readFrameUntilAck(ctx context.Context, c wire.Conn) (wire.Frame, error) {
	for {
		f, err := c.ReadFrame(ctx)
		if err != nil {
			return wire.Frame{}, err
		}
		if f.Ack != nil {
			return f, nil
		}
		if f.DesiredState == nil {
			return wire.Frame{}, fmt.Errorf("waiting for an Ack, got %+v", f)
		}
	}
}

func testHello() wire.Frame {
	return wire.Frame{Hello: &wire.Hello{
		SchemaVersion:   protocol.SchemaVersion,
		Hostname:        "ws-host",
		Platform:        "linux",
		AgentVersion:    "test",
		Capabilities:    []string{wire.CapSequenceFloorV1},
		EnrollmentEpoch: 1,
		Permissions: permission.PermissionReport{
			Supported:  []string{"probe.icmp"},
			Granted:    []string{"probe.icmp"},
			Effective:  []string{"probe.icmp"},
			Source:     "environment",
			PolicyHash: "h1",
		},
	}}
}

// handshake walks the schema-8 connect pushes on an already-dialed connection:
// Hello up, DesiredState down, then the SequenceFloor, then the applied reply.
// It returns the pushed floor so tests can assert on it. A redundant
// DesiredState may land between the initial push and the floor — a config
// change made before the session existed fans out on the hub's own goroutine
// and can race the connect pushes — so those are skipped, never mistaken for
// the floor.
func handshake(t *testing.T, conn *websocket.Conn, epoch uint64) wire.SequenceFloor {
	t.Helper()
	sendFrame(t, conn, testHello())
	f := readFrame(t, conn)
	if f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}
	var floor wire.SequenceFloor
	for {
		f = readFrame(t, conn)
		if f.SequenceFloor != nil {
			floor = *f.SequenceFloor
			break
		}
		if f.DesiredState == nil {
			t.Fatalf("waiting for the SequenceFloor, got %+v", f)
		}
	}
	if floor.EnrollmentEpoch != epoch {
		t.Fatalf("floor epoch = %d, want %d", floor.EnrollmentEpoch, epoch)
	}
	if floor.SessionID == "" {
		t.Fatalf("floor carries no session id: %+v", floor)
	}
	sendFrame(t, conn, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: floor.EnrollmentEpoch,
		SequenceFloor:   floor.SequenceFloor,
	}})
	return floor
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
// pushed unconditionally, the schema-8 sequence floor follows it, and the hub
// tracks the session.
func TestConnectHelloOnline(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	e.setTargets(t, "1.1.1.1") // config_version 0 -> 1

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	floor := handshake(t, conn, 1)
	if floor.SequenceFloor != 0 {
		t.Errorf("floor = %d for a fresh agent, want 0", floor.SequenceFloor)
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
	handshake(t, conn, 1)

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
	handshake(t, conn, 1)

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

	// A replayed sequence still acks the watermark (idempotent dedup). The
	// fingerprint excludes per-sample timestamps, so the re-served copy's fresh
	// clock stamp does not read as different content.
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
	handshake(t, conn, 1)

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
	handshake(t, conn1, 1)

	conn2 := e.dial(t, "tok_a", wire.SubprotocolJSON)
	handshake(t, conn2, 1)

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

	first, _ := e.hostLive.Request("agent_a", []string{"host.process.basic.read", "host.connection.summary.read"})
	if e.hub.PushSnapshotRequest("agent_a", first) {
		t.Fatal("push to a disconnected agent must return false")
	}

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}
	// The request registered before the connect is still pending, so the hub
	// re-pushed it right after DesiredState (the reconnect-blip path), before
	// the sequence floor.
	f := readFrame(t, conn)
	if f.SnapshotRequest == nil {
		t.Fatalf("second push = %+v, want re-pushed SnapshotRequest", f)
	}
	// The floor follows, and the barrier opens.
	f = readFrame(t, conn)
	if f.SequenceFloor == nil {
		t.Fatalf("third push = %+v, want SequenceFloor", f)
	}
	sendFrame(t, conn, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: f.SequenceFloor.EnrollmentEpoch,
		SequenceFloor:   f.SequenceFloor.SequenceFloor,
	}})

	// A fresh request while connected pushes directly. It asks for a scope the
	// still-pending request above does not cover — a subset of it would (rightly)
	// be coalesced into that one instead of producing a second push.
	req, push := e.hostLive.Request("agent_a", []string{"host.process.owner.read"})
	if !push {
		t.Fatal("a request for an uncovered scope must be pushed")
	}
	if !e.hub.PushSnapshotRequest("agent_a", req) {
		t.Fatal("push to a connected agent returned false")
	}
	f = readFrame(t, conn)
	if f.SnapshotRequest == nil || f.SnapshotRequest.RequestID != req.RequestID {
		t.Fatalf("pushed frame = %+v, want SnapshotRequest %s", f, req.RequestID)
	}
	if len(f.SnapshotRequest.Scopes) != 1 || f.SnapshotRequest.Scopes[0] != "host.process.owner.read" {
		t.Errorf("request scopes = %+v, want [host.process.owner.read]", f.SnapshotRequest.Scopes)
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
	handshake(t, conn, 1)
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
	if f := readFrame(t, conn); f.SequenceFloor == nil {
		t.Fatalf("second push = %+v, want SequenceFloor", f)
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
	// Hello up, DesiredState down, then the schema-8 floor barrier.
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
	f, err = c.ReadFrame(ctx)
	if err != nil || f.SequenceFloor == nil {
		t.Fatalf("second push = %+v err=%v, want SequenceFloor", f, err)
	}
	if f.SequenceFloor.EnrollmentEpoch != 1 {
		t.Fatalf("floor epoch = %d, want 1", f.SequenceFloor.EnrollmentEpoch)
	}
	if err := c.WriteFrame(ctx, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: f.SequenceFloor.EnrollmentEpoch,
		SequenceFloor:   f.SequenceFloor.SequenceFloor,
	}}); err != nil {
		t.Fatalf("write floor applied: %v", err)
	}

	// Packet up, Ack down.
	if err := c.WriteFrame(ctx, testPacket(1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	// Skip any DesiredState on the way to the Ack. The setTargets above
	// published TopicConfigChanged before this session existed, and the hub
	// fans those out on its own goroutine — on a loaded machine that goroutine
	// can be scheduled after the session registers and deliver a (redundant)
	// push between the handshake and this Ack. That is legal protocol traffic,
	// not a defect: the server may push DesiredState at any time and the agent
	// ignores any version it has already applied. Asserting on "the very next
	// frame" made this test lose that race on a two-core CI runner.
	f, err = readFrameUntilAck(ctx, c)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if f.Ack.HighestSequence != 1 {
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
	// Drain the floor too: CloseAll's writer drains queued frames before the
	// close, and the test must read them or they mask the close error.
	if _, err := c2.ReadFrame(ctx); err != nil {
		t.Fatalf("read floor 2: %v", err)
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

// TestDialLocalRefusedAfterCloseAll pins the shutdown gate: once CloseAll has
// swept the hub, a dial must fail instead of registering a session the sweep
// already passed. On the desktop a listen-address restart shuts the old server
// down while the bundled agent is reconnecting on its backoff, so without this
// the agent would latch onto the outgoing server (whose DB is about to close)
// and never reach its replacement.
func TestDialLocalRefusedAfterCloseAll(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	e.hub.CloseAll("shutting down")

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("DialLocal after CloseAll = %v, want ErrClosed", err)
	}
	if c != nil {
		t.Fatal("DialLocal returned a connection after CloseAll")
	}
	if e.hub.IsConnected("agent_a") {
		t.Fatal("hub registered a session after CloseAll")
	}
}

// TestCloseAllCutsPreHelloHandshake pins the handshake half of the shutdown
// gate: a dial that was admitted but has not sent its Hello yet must neither
// survive CloseAll (its serve would write registry state after the DB closes)
// nor stall it for the whole helloTimeout — CloseAll closes the connection out
// from under the parked Hello read and waits for the serve to return.
func TestCloseAllCutsPreHelloHandshake(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	// No Hello is sent: the serve goroutine parks in its Hello read.

	done := make(chan struct{})
	go func() { e.hub.CloseAll("shutting down"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// helloTimeout is 10s: finishing well under it proves the cut, not a wait.
		t.Fatal("CloseAll stalled behind a handshake that never sent its Hello")
	}

	rctx, rcancel := context.WithTimeout(ctx, 2*time.Second)
	defer rcancel()
	if _, err := c.ReadFrame(rctx); err == nil {
		t.Fatal("pre-Hello connection still alive after CloseAll")
	}
	if e.hub.IsConnected("agent_a") {
		t.Fatal("pre-Hello handshake registered a session after CloseAll")
	}
}

// waitDisconnectKind polls the agent's recorded last_disconnect_kind until it
// matches want (session teardown runs asynchronously to the client close).
func (e *testEnv) waitDisconnectKind(t *testing.T, agentID, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a, err := e.reg.Get(context.Background(), agentID); err == nil && a.LastDisconnectKind == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	a, _ := e.reg.Get(context.Background(), agentID)
	t.Fatalf("last_disconnect_kind = %q, want %q", a.LastDisconnectKind, want)
}

// TestFirstConnectedAndCleanDisconnect covers the AGENT-002 provenance: the first
// Hello stamps first_connected_at, and a peer-initiated normal close is recorded
// as a clean disconnect.
func TestFirstConnectedAndCleanDisconnect(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	_ = readFrame(t, conn) // DesiredState

	if a, _ := e.reg.Get(context.Background(), "agent_a"); a.FirstConnectedAt == nil {
		t.Fatal("first_connected_at not stamped on Hello")
	}

	_ = conn.Close(websocket.StatusNormalClosure, "bye")
	e.waitDisconnectKind(t, "agent_a", "clean")
}

// TestUnexpectedDisconnectKind severs the TCP without a close handshake; the read
// error carries no close code, so the disconnect is classified unexpected.
func TestUnexpectedDisconnectKind(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	_ = readFrame(t, conn)
	_ = conn.CloseNow() // abrupt close, no close frame
	e.waitDisconnectKind(t, "agent_a", "error")
}

// TestSupersededDoesNotOverwriteProvenance reconnects the same agent, then cleanly
// closes the replacement. The kicked (superseded) session must NOT write disconnect
// provenance — it no longer owns the agent's slot — so the final recorded kind is
// the replacement's "clean", never "superseded". This guards the race where a slow
// superseded teardown could otherwise clobber the live session's disconnect kind.
func TestSupersededDoesNotOverwriteProvenance(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn1 := e.dial(t, "tok_a", wire.SubprotocolJSON)
	handshake(t, conn1, 1)

	conn2 := e.dial(t, "tok_a", wire.SubprotocolJSON)
	handshake(t, conn2, 1)

	// Let the kicked session's close handshake complete so its teardown runs.
	expectClose(t, conn1, wire.CloseSuperseded)

	// The live replacement then closes cleanly; its teardown owns provenance.
	_ = conn2.Close(websocket.StatusNormalClosure, "bye")
	e.waitDisconnectKind(t, "agent_a", "clean")
}

// TestBadSchemaRecordsVersionIncompatible rejects a Hello with an unsupported
// schema; the disconnect kind maps to version-incompatible and first_connected_at
// stays NULL (the agent never completed a valid Hello).
func TestBadSchemaRecordsVersionIncompatible(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	hello := testHello()
	hello.Hello.SchemaVersion = 9999 // > protocol.SchemaVersion
	sendFrame(t, conn, hello)
	expectClose(t, conn, wire.CloseUnsupportedSchema)

	e.waitDisconnectKind(t, "agent_a", "unsupported_schema")
	if a, _ := e.reg.Get(context.Background(), "agent_a"); a.FirstConnectedAt != nil {
		t.Fatal("first_connected_at set despite an unsupported-schema Hello")
	}
}

// TestHelloFloorGateRejects: a Hello without the sequence_floor_v1 capability
// is refused before registration — a peer that cannot speak the barrier must
// not get a session whose packets could be renumbered in place. (A zero epoch
// is NOT refused: it is the pre-schema-8 bootstrap case — see
// TestZeroEpochHelloAccepted.)
func TestHelloFloorGateRejects(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	hello := testHello()
	hello.Hello.Capabilities = nil
	sendFrame(t, conn, hello)
	expectClose(t, conn, wire.CloseProtocolError)
}

// TestPacketBeforeFloorAppliedCloses pins the barrier fail-closed: a packet
// sent before the SequenceFloorApplied reply is a protocol error, even though
// the floor was pushed and the session is otherwise healthy.
func TestPacketBeforeFloorAppliedCloses(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}
	if f := readFrame(t, conn); f.SequenceFloor == nil {
		t.Fatalf("second push = %+v, want SequenceFloor", f)
	}
	// The barrier is still closed: no applied reply was sent.
	sendFrame(t, conn, testPacket(1))
	expectClose(t, conn, wire.CloseProtocolError)
}

// TestFloorAppliedMismatchCloses: the applied reply must restate exactly this
// session's pushed floor — epoch included. A wrong floor value or a wrong
// epoch is a protocol error.
func TestFloorAppliedMismatchCloses(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	// Wrong floor value.
	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn, testHello())
	_ = readFrame(t, conn) // DesiredState
	floor := readFrame(t, conn)
	if floor.SequenceFloor == nil {
		t.Fatalf("push = %+v, want SequenceFloor", floor)
	}
	sendFrame(t, conn, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: floor.SequenceFloor.EnrollmentEpoch,
		SequenceFloor:   floor.SequenceFloor.SequenceFloor + 12345,
	}})
	expectClose(t, conn, wire.CloseProtocolError)

	// Wrong epoch.
	conn2 := e.dial(t, "tok_a", wire.SubprotocolJSON)
	sendFrame(t, conn2, testHello())
	_ = readFrame(t, conn2) // DesiredState
	floor2 := readFrame(t, conn2)
	if floor2.SequenceFloor == nil {
		t.Fatalf("push = %+v, want SequenceFloor", floor2)
	}
	sendFrame(t, conn2, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: floor2.SequenceFloor.EnrollmentEpoch + 1,
		SequenceFloor:   floor2.SequenceFloor.SequenceFloor,
	}})
	expectClose(t, conn2, wire.CloseProtocolError)
}

// TestStaleHelloEpochChallenges: a Hello presenting a stale credential
// generation gets an epoch_mismatch rotation challenge instead of a floor,
// bound to the HELLO epoch — and the rotation then SUCCEEDS end to end: the
// new generation comes from the row, so the stale agent jumps forward instead
// of being denied, and its reconnect under the new credential converges.
func TestStaleHelloEpochChallenges(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	// Enroll a real agent: the rotation must verify an ed25519 possession
	// proof, so the row needs a real key.
	tok, err := e.reg.CreateEnrollmentToken(ctx, site.DefaultSiteID, "stale", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const nonce = "nonce-stale"
	resp, err := e.reg.Enroll(ctx, enroll.EnrollRequest{
		SchemaVersion:   protocol.SchemaVersion,
		PublicKey:       pub,
		Nonce:           nonce,
		Signature:       ed25519.Sign(priv, []byte(nonce)),
		EnrollmentToken: tok,
		Hostname:        "stale-host",
		Platform:        "windows",
		AgentVersion:    "test",
		Permissions:     permission.PermissionReport{},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	agentID := resp.AgentID

	staleHello := func() wire.Frame {
		h := testHello()
		h.Hello.EnrollmentEpoch = 5 // the row is at generation 1
		return h
	}

	// The stale session: DesiredState, then the challenge bound to the Hello's
	// epoch. No floor was pushed, so the barrier stays closed and a packet is
	// still refused.
	conn := e.dial(t, resp.AgentToken, wire.SubprotocolJSON)
	sendFrame(t, conn, staleHello())
	if f := readFrame(t, conn); f.DesiredState == nil {
		t.Fatalf("first push = %+v, want DesiredState", f)
	}
	f := readFrame(t, conn)
	if f.EpochRotationChallenge == nil {
		t.Fatalf("second push = %+v, want EpochRotationChallenge", f)
	}
	if f.EpochRotationChallenge.Reason != "epoch_mismatch" || f.EpochRotationChallenge.Challenge == "" {
		t.Errorf("challenge = %+v, want reason epoch_mismatch with a non-empty challenge", f.EpochRotationChallenge)
	}
	sendFrame(t, conn, testPacket(1))
	expectClose(t, conn, wire.CloseProtocolError)

	// A second stale session drives the rotation through: the agent signs the
	// challenge with the HELLO epoch it believes in (5), and the row derives
	// the new generation (1+1=2).
	conn2 := e.dial(t, resp.AgentToken, wire.SubprotocolJSON)
	sendFrame(t, conn2, staleHello())
	_ = readFrame(t, conn2) // DesiredState
	f = readFrame(t, conn2)
	if f.EpochRotationChallenge == nil {
		t.Fatalf("push = %+v, want EpochRotationChallenge", f)
	}
	challenge := f.EpochRotationChallenge.Challenge
	sendFrame(t, conn2, wire.Frame{EpochRotationRequest: &wire.EpochRotationRequest{
		Challenge: challenge,
		OldEpoch:  5,
		Signature: ed25519.Sign(priv, []byte(challenge)),
	}})
	f = readFrame(t, conn2)
	if f.EpochRotationResult == nil || f.EpochRotationResult.Status != wire.RotationOK ||
		f.EpochRotationResult.NewEpoch != 2 || f.EpochRotationResult.AgentToken == "" {
		t.Fatalf("result = %+v, want RotationOK epoch 2 with a token — a stale agent must jump to row+1, never be denied", f.EpochRotationResult)
	}
	rotatedToken := f.EpochRotationResult.AgentToken
	expectClose(t, conn2, wire.CloseGoingAway)

	// Reconnect under the new credential: the auth completes phase 2 and the
	// session serves the floor at the converged generation.
	conn3 := e.dial(t, rotatedToken, wire.SubprotocolJSON)
	hello3 := testHello()
	hello3.Hello.EnrollmentEpoch = 2
	sendFrame(t, conn3, hello3)
	if f := readFrame(t, conn3); f.DesiredState == nil {
		t.Fatalf("push = %+v, want DesiredState", f)
	}
	f = readFrame(t, conn3)
	if f.SequenceFloor == nil || f.SequenceFloor.EnrollmentEpoch != 2 {
		t.Fatalf("push = %+v, want SequenceFloor at the converged epoch 2", f)
	}
	if f.SequenceFloor.SequenceFloor != 0 {
		t.Errorf("post-rotation floor = %d, want 0 (the switch zeroes the watermark)", f.SequenceFloor.SequenceFloor)
	}
	sendFrame(t, conn3, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: f.SequenceFloor.EnrollmentEpoch,
		SequenceFloor:   f.SequenceFloor.SequenceFloor,
	}})
	auth, err := e.reg.AuthenticateAgent(ctx, rotatedToken)
	if err != nil || auth.AgentID != agentID || auth.Epoch != 2 {
		t.Fatalf("rotated token auth = %+v, %v; want %q at epoch 2", auth, err, agentID)
	}
}

// TestSequenceConflictChallengesRotation: a replayed sequence carrying
// different content is refused with a sequence_conflict rotation challenge
// (no ack), and the session stays alive — the agent drives the rotation from
// here, and unrelated fresh sequences keep flowing.
func TestSequenceConflictChallengesRotation(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")

	conn := e.dial(t, "tok_a", wire.SubprotocolJSON)
	handshake(t, conn, 1)

	sendFrame(t, conn, testPacket(1))
	if f := readFrame(t, conn); f.Ack == nil || f.Ack.HighestSequence != 1 {
		t.Fatalf("ack = %+v, want watermark 1", f.Ack)
	}

	// Same sequence, different content: a conflict, not a duplicate.
	alt := testPacket(1)
	alt.Packet.Metrics[0].Value = 99.0
	sendFrame(t, conn, alt)
	f := readFrame(t, conn)
	if f.EpochRotationChallenge == nil {
		t.Fatalf("conflict reply = %+v, want EpochRotationChallenge (no ack)", f)
	}
	if f.EpochRotationChallenge.Reason != "sequence_conflict" {
		t.Errorf("challenge reason = %q, want sequence_conflict", f.EpochRotationChallenge.Reason)
	}

	// The session is still live: a fresh sequence flows normally.
	sendFrame(t, conn, testPacket(2))
	if f := readFrame(t, conn); f.Ack == nil || f.Ack.HighestSequence != 2 {
		t.Fatalf("post-conflict ack = %+v, want watermark 2", f.Ack)
	}
}

// TestRotationOverHub drives the complete controlled rotation over an
// in-process pipe session: the agent asks to be challenged, signs the
// challenge with its enrolled key, receives the new credential and the close
// 1001; a reconnect with the OLD token gets the committed result re-issued
// idempotently (the pending window); and the NEW token authenticates at the
// advanced generation — closing the old-token window for good.
func TestRotationOverHub(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	// Enroll a real agent: the rotation must verify an ed25519 possession
	// proof, so the seeded row needs a real key.
	tok, err := e.reg.CreateEnrollmentToken(ctx, site.DefaultSiteID, "rotation", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const nonce = "nonce-rotation"
	resp, err := e.reg.Enroll(ctx, enroll.EnrollRequest{
		SchemaVersion:   protocol.SchemaVersion,
		PublicKey:       pub,
		Nonce:           nonce,
		Signature:       ed25519.Sign(priv, []byte(nonce)),
		EnrollmentToken: tok,
		Hostname:        "rot-host",
		Platform:        "windows",
		AgentVersion:    "test",
		Permissions:     permission.PermissionReport{},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	agentID := resp.AgentID
	if resp.EnrollmentEpoch != 1 {
		t.Fatalf("enrollment epoch = %d, want 1", resp.EnrollmentEpoch)
	}
	oldToken := resp.AgentToken

	// The floor barrier first: epoch 1, floor 0, applied.
	c, err := e.hub.DialLocal(ctx, oldToken)
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	if err := c.WriteFrame(ctx, testHello()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
	}
	f, err := c.ReadFrame(ctx)
	if err != nil || f.SequenceFloor == nil || f.SequenceFloor.EnrollmentEpoch != 1 {
		t.Fatalf("second push = %+v err=%v, want SequenceFloor for epoch 1", f, err)
	}
	if err := c.WriteFrame(ctx, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: f.SequenceFloor.EnrollmentEpoch,
		SequenceFloor:   f.SequenceFloor.SequenceFloor,
	}}); err != nil {
		t.Fatalf("write applied: %v", err)
	}

	// The agent asks to be rotated (its in-flight claim is at/below the floor).
	if err := c.WriteFrame(ctx, wire.Frame{EpochRotationChallengeRequest: &wire.EpochRotationChallengeRequest{Reason: "claim_below_floor"}}); err != nil {
		t.Fatalf("write challenge request: %v", err)
	}
	f, err = c.ReadFrame(ctx)
	if err != nil || f.EpochRotationChallenge == nil {
		t.Fatalf("challenge = %+v err=%v", f, err)
	}
	if f.EpochRotationChallenge.Reason != "claim_below_floor" {
		t.Errorf("challenge reason = %q, want claim_below_floor", f.EpochRotationChallenge.Reason)
	}

	// The possession proof, then the verdict.
	challenge := f.EpochRotationChallenge.Challenge
	if err := c.WriteFrame(ctx, wire.Frame{EpochRotationRequest: &wire.EpochRotationRequest{
		Challenge: challenge,
		OldEpoch:  1,
		Signature: ed25519.Sign(priv, []byte(challenge)),
	}}); err != nil {
		t.Fatalf("write rotation request: %v", err)
	}
	f, err = c.ReadFrame(ctx)
	if err != nil || f.EpochRotationResult == nil {
		t.Fatalf("rotation result = %+v err=%v", f, err)
	}
	res := f.EpochRotationResult
	if res.Status != wire.RotationOK || res.NewEpoch != 2 || res.AgentToken == "" {
		t.Fatalf("result = %+v, want RotationOK epoch 2 with a token", res)
	}
	// The session ends with 1001 after the result: the agent persists and
	// reconnects under the new identity.
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	if _, err := c.ReadFrame(rctx); wire.CloseStatus(err) != wire.CloseGoingAway {
		t.Fatalf("post-rotation close = %v, want CloseGoingAway (1001)", err)
	}

	// The old token is inside its pending window: a reconnect with it re-issues
	// the committed result idempotently instead of a floor.
	cOld, err := e.hub.DialLocal(ctx, oldToken)
	if err != nil {
		t.Fatalf("DialLocal(old token): %v", err)
	}
	if err := cOld.WriteFrame(ctx, testHello()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if f, err := cOld.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("old-token first push = %+v err=%v, want DesiredState", f, err)
	}
	f, err = cOld.ReadFrame(ctx)
	if err != nil || f.EpochRotationResult == nil {
		t.Fatalf("old-token second push = %+v err=%v, want the re-issued EpochRotationResult", f, err)
	}
	if got := f.EpochRotationResult; got.Status != wire.RotationOK || got.NewEpoch != 2 || got.AgentToken != res.AgentToken {
		t.Fatalf("re-issued result = %+v, want the committed result %+v", got, res)
	}
	if _, err := cOld.ReadFrame(rctx); wire.CloseStatus(err) != wire.CloseGoingAway {
		t.Fatalf("old-token close = %v, want CloseGoingAway (1001)", err)
	}

	// The new credential authenticates: its first use COMPLETES phase 2 (the
	// credential switch), and the old token dies with it.
	auth, err := e.reg.AuthenticateAgent(ctx, res.AgentToken)
	if err != nil || auth.AgentID != agentID || auth.Epoch != 2 {
		t.Fatalf("new token auth = %+v, %v; want %q at epoch 2", auth, err, agentID)
	}
	if _, err := e.reg.AuthenticateAgent(ctx, oldToken); err == nil {
		t.Fatal("old token still authenticates after phase 2 completed")
	}
	var rowEpoch, pendingEpoch uint64
	var high int64
	if err := e.db.QueryRowContext(ctx,
		`SELECT enrollment_epoch, pending_next_epoch, high_sequence FROM agents WHERE id=?`, agentID).
		Scan(&rowEpoch, &pendingEpoch, &high); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if rowEpoch != 2 || pendingEpoch != 0 || high != 0 {
		t.Errorf("row after phase 2 = epoch %d pending %d high %d, want 2/0/0", rowEpoch, pendingEpoch, high)
	}
}

// TestZeroEpochHelloAccepted: a schema-8 Hello with a zero enrollment epoch is
// the pre-schema-8 credential bootstrap — it must NOT be rejected. The server
// skips the floor barrier entirely (the agent side skips it too) and the first
// packet is admitted and acked normally.
func TestZeroEpochHelloAccepted(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	hello := testHello()
	hello.Hello.EnrollmentEpoch = 0
	if err := c.WriteFrame(ctx, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
	}
	// No floor frame may precede the ack: the next frame down must be the
	// packet's ack (a floor would arrive before it and is asserted against).
	if err := c.WriteFrame(ctx, testPacket(1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	f, err := readFrameUntilAck(ctx, c)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if f.Ack.HighestSequence != 1 {
		t.Fatalf("ack = %+v, want HighestSequence 1 (a zero-epoch packet admits without a barrier)", f.Ack)
	}
}
