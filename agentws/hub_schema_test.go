package agentws

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/site"
)

// This file covers sessions admitted under the pre-boundary wire schema and
// the schema-8 epoch gate that decides between bootstrap, open, rotate and
// refuse-ahead. Every case is driven over the in-process pipe (DialLocal) so
// the session machinery is exercised end to end.

// testHello7 returns a Hello exactly as a pre-boundary agent ships it: schema
// 7, and neither the capabilities nor the enrollment epoch fields (the peer
// cannot encode them).
func testHello7() wire.Frame {
	h := testHello()
	h.Hello = &wire.Hello{
		SchemaVersion: 7,
		Hostname:      "v7-host",
		Platform:      "linux",
		AgentVersion:  "v0.4.4",
		Permissions: permission.PermissionReport{
			Supported:  []string{"probe.icmp"},
			Granted:    []string{"probe.icmp"},
			Effective:  []string{"probe.icmp"},
			Source:     "environment",
			PolicyHash: "h1",
		},
	}
	return h
}

func testPacket7(seq uint64) wire.Frame {
	p := testPacket(seq)
	p.Packet.SchemaVersion = 7
	return p
}

// enrollRotateAgent enrolls one real agent for the rotation-flow tests: the
// rotation must verify an ed25519 possession proof, so the row needs a real
// key.
func enrollRotateAgent(t *testing.T, e *testEnv) (ed25519.PrivateKey, string, string) {
	t.Helper()
	ctx := context.Background()
	tok, err := e.reg.CreateEnrollmentToken(ctx, site.DefaultSiteID, "rotate", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const nonce = "rotate-nonce"
	resp, err := e.reg.Enroll(ctx, enroll.EnrollRequest{
		SchemaVersion:   protocol.SchemaVersion,
		PublicKey:       pub,
		Nonce:           nonce,
		Signature:       ed25519.Sign(priv, []byte(nonce)),
		EnrollmentToken: tok,
		Hostname:        "rotate-host",
		Platform:        "linux",
		AgentVersion:    "test",
		Permissions:     permission.PermissionReport{},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return priv, resp.AgentToken, resp.AgentID
}

// TestSchema7SessionServesLegacyPeer (H1): a pre-boundary session registers,
// gets its DesiredState, never gets a SequenceFloor, and has its schema 7
// packets ingested and acked — the receiver-half mainline for a released
// peer.
func TestSchema7SessionServesLegacyPeer(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	if err := c.WriteFrame(ctx, testHello7()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
	}
	// No floor may precede the ack: readFrameUntilAck fails on a SequenceFloor.
	if err := c.WriteFrame(ctx, testPacket7(1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	f, err := readFrameUntilAck(ctx, c)
	if err != nil {
		t.Fatalf("read ack: %v (a SequenceFloor must never be pushed to a 7 session)", err)
	}
	if f.Ack.HighestSequence != 1 {
		t.Fatalf("ack = %+v, want HighestSequence 1", f.Ack)
	}
}

// TestUnknownSchemaHelloCloses4001Silently (H2): a Hello for a schema the
// registry does not serve is closed with 4001 and no explanation frame — the
// frozen WS-side shape the peer's retry keys on.
func TestUnknownSchemaHelloCloses4001Silently(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	hello := testHello()
	hello.Hello.SchemaVersion = 9 // not served: the N+1 case
	if err := c.WriteFrame(ctx, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	// Any frame before the close would fail this read.
	if _, err := c.ReadFrame(ctx); wire.CloseStatus(err) != wire.CloseUnsupportedSchema {
		t.Fatalf("close = %v, want 4001 with no frame before it", err)
	}
}

// TestSchema7SessionRejectsOutOfSchemaFrames (H4): a pre-boundary session must
// not receive the control frames it never negotiated. Each of the three
// schema 8 control frames is refused with a protocol error (4003) instead of
// being mis-processed — the current code would otherwise mint a challenge or
// run a rotation on a session that cannot complete one.
func TestSchema7SessionRejectsOutOfSchemaFrames(t *testing.T) {
	frames := map[string]wire.Frame{
		"SequenceFloorApplied":          {SequenceFloorApplied: &wire.SequenceFloorApplied{}},
		"EpochRotationChallengeRequest": {EpochRotationChallengeRequest: &wire.EpochRotationChallengeRequest{Reason: "claim_below_floor"}},
		"EpochRotationRequest":          {EpochRotationRequest: &wire.EpochRotationRequest{}},
	}
	for name, frame := range frames {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			e.seedAgent(t, "agent_a", "tok_a")
			ctx := context.Background()
			c, err := e.hub.DialLocal(ctx, "tok_a")
			if err != nil {
				t.Fatalf("DialLocal: %v", err)
			}
			if err := c.WriteFrame(ctx, testHello7()); err != nil {
				t.Fatalf("write hello: %v", err)
			}
			if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
				t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
			}
			if err := c.WriteFrame(ctx, frame); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
			if _, err := c.ReadFrame(ctx); wire.CloseStatus(err) != wire.CloseProtocolError {
				t.Fatalf("%s on a 7 session = %v, want 4003", name, err)
			}
		})
	}
}

// TestSchema7ConflictClosesWithUpgradeReason (H5): a pre-boundary session that
// hits a fingerprint conflict gets no ack, no challenge frame, and a terminal
// 4001 whose reason tells the peer the way out is an upgrade. The disconnect
// kind records sequence_conflict for the alert pipeline. Four things must all
// be present, which is what pins the "no silent infinite retry" backstop.
func TestSchema7ConflictClosesWithUpgradeReason(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	if err := c.WriteFrame(ctx, testHello7()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
	}
	// Admit sequence 1 once...
	if err := c.WriteFrame(ctx, testPacket7(1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	if f, err := readFrameUntilAck(ctx, c); err != nil || f.Ack.HighestSequence != 1 {
		t.Fatalf("first ack = %+v err=%v, want watermark 1", f, err)
	}
	// ...then re-serve the same sequence with different content: a conflict.
	alt := testPacket7(1)
	alt.Packet.Metrics[0].Value = 99.0
	if err := c.WriteFrame(ctx, alt); err != nil {
		t.Fatalf("write conflicting packet: %v", err)
	}
	// No ack (the batch stays in the peer's WAL), no challenge (this session
	// cannot rotate), and a terminal 4001 with the upgrade reason.
	if _, err := c.ReadFrame(ctx); wire.CloseStatus(err) != wire.CloseUnsupportedSchema {
		t.Fatalf("conflict close = %v, want 4001", err)
	}
	e.waitDisconnectKind(t, "agent_a", "sequence_conflict")
}

// TestHelloEpochAheadRefused (H6): a schema 8 session whose Hello reports a
// credential generation AHEAD of the authority's is refused with a retryable
// 4003 naming the condition — never a challenge (which would let the data
// plane vouch for an impossible generation) and never an adopted epoch. No
// floor is pushed and no challenge is minted: the close is the first thing on
// the wire.
func TestHelloEpochAheadRefused(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a") // the row is at generation 1
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	hello := testHello()
	hello.Hello.EnrollmentEpoch = 2 // authority+1: ahead
	if err := c.WriteFrame(ctx, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	_, err = c.ReadFrame(ctx)
	ce, ok := err.(*wire.CloseError)
	if !ok || ce.Code != wire.CloseProtocolError || ce.Reason != "epoch_ahead_of_authority" {
		t.Fatalf("close = %v, want 4003 epoch_ahead_of_authority (no floor, no challenge)", err)
	}
}

// TestEpochAheadDoesNotTouchLastSeen (H6a): the refusal above runs before any
// Hello side effect, so it must not advance last_seen_at (which would push the
// connectivity alert past the whole reconnect backoff) and must record the
// epoch_ahead kind for the alert reason.
func TestEpochAheadDoesNotTouchLastSeen(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	hello := testHello()
	hello.Hello.EnrollmentEpoch = 2
	if err := c.WriteFrame(ctx, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if _, err := c.ReadFrame(ctx); wire.CloseStatus(err) != wire.CloseProtocolError {
		t.Fatalf("close = %v, want 4003", err)
	}
	e.waitDisconnectKind(t, "agent_a", "epoch_ahead")
	a, _ := e.reg.Get(ctx, "agent_a")
	if a.LastSeenAt != nil {
		t.Errorf("last_seen_at advanced on an epoch-ahead refusal: %v", a.LastSeenAt)
	}
}

// TestStagedRotationReissuesBeforeEpochRefusal (H6c): while a rotation is
// staged, the recovery path takes priority over the ahead-of-authority gate —
// whatever the Hello reports, the SAME result is re-issued idempotently and
// the session hands off. The early gate is exempted precisely so a peer that
// missed a result is never refused before it can be re-issued.
func TestStagedRotationReissuesBeforeEpochRefusal(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	priv, oldToken, agentID := enrollRotateAgent(t, e)
	// Stage phase 1: the old token now carries a pending rotation.
	ch := e.reg.IssueRotationChallenge(agentID, 1, "test")
	newEpoch, newToken, err := e.reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil || newEpoch != 2 {
		t.Fatalf("phase 1 = epoch %d, %v; want 2", newEpoch, err)
	}

	c, err := e.hub.DialLocal(ctx, oldToken)
	if err != nil {
		t.Fatalf("DialLocal(old token): %v", err)
	}
	// The Hello reports an epoch AHEAD of the authority — normally refused, but
	// a staged rotation exempts the early gate so the recovery re-issues first.
	hello := testHello()
	hello.Hello.EnrollmentEpoch = 9
	if err := c.WriteFrame(ctx, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
	}
	f, err := c.ReadFrame(ctx)
	if err != nil || f.EpochRotationResult == nil {
		t.Fatalf("second push = %+v err=%v, want the re-issued EpochRotationResult", f, err)
	}
	if f.EpochRotationResult.NewEpoch != 2 || f.EpochRotationResult.AgentToken != newToken {
		t.Fatalf("re-issued result = %+v, want the SAME staged result epoch 2 token %q", f.EpochRotationResult, newToken)
	}
	if _, err := c.ReadFrame(ctx); wire.CloseStatus(err) != wire.CloseGoingAway {
		t.Fatalf("post-reissue close = %v, want 1001", err)
	}
}

// TestSchema7SessionIgnoresStagedRotation (H7): a pre-boundary session with a
// staged rotation serves normally — it cannot carry the result frame, so it
// does not, and the old token (still a live credential) keeps working until
// the peer probes a schema that can.
func TestSchema7SessionIgnoresStagedRotation(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	priv, oldToken, agentID := enrollRotateAgent(t, e)
	ch := e.reg.IssueRotationChallenge(agentID, 1, "test")
	if _, _, err := e.reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	}); err != nil {
		t.Fatalf("phase 1: %v", err)
	}

	c, err := e.hub.DialLocal(ctx, oldToken)
	if err != nil {
		t.Fatalf("DialLocal(old token): %v", err)
	}
	if err := c.WriteFrame(ctx, testHello7()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
	}
	// The result frame must NOT be pushed to a 7 session: readFrameUntilAck
	// would fail on an EpochRotationResult, and the packet must be acked.
	if err := c.WriteFrame(ctx, testPacket7(1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	if f, err := readFrameUntilAck(ctx, c); err != nil || f.Ack.HighestSequence != 1 {
		t.Fatalf("ack = %+v err=%v, want watermark 1 (session serves normally)", f, err)
	}
}

// TestSchema7DownlinkGuardFailsLoud (H8): if a server bug enqueues a control
// frame a pre-boundary session never negotiated, the downlink guard refuses it
// and tears the session down loudly with 1011 — the frame must never reach the
// peer.
func TestSchema7DownlinkGuardFailsLoud(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	if err := c.WriteFrame(ctx, testHello7()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
	}

	// Force a floor frame into the writer's queue, bypassing the serve branches
	// that would never build one.
	e.hub.mu.Lock()
	s := e.hub.conns["agent_a"]
	e.hub.mu.Unlock()
	if s == nil {
		t.Fatal("session not registered")
	}
	if !s.enqueue(wire.Frame{SequenceFloor: &wire.SequenceFloor{EnrollmentEpoch: 1}}) {
		t.Fatal("enqueue floor frame")
	}
	if _, err := c.ReadFrame(ctx); wire.CloseStatus(err) != wire.CloseInternalError {
		t.Fatalf("close = %v, want 1011 (the downlink guard failed loud)", err)
	}
}

// TestPacketSchemaMustMatchSession (H10): a packet whose declared schema
// disagrees with the session's is refused with a protocol error before
// ingest — the equality check that turns mixed-schema confusion into a clear
// close instead of an ingest failure.
func TestPacketSchemaMustMatchSession(t *testing.T) {
	e := newTestEnv(t)
	e.seedAgent(t, "agent_a", "tok_a")
	ctx := context.Background()

	c, err := e.hub.DialLocal(ctx, "tok_a")
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	if err := c.WriteFrame(ctx, testHello()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	// Consume the connect pushes (DesiredState, then the floor) and open the
	// barrier so the session is fully established.
	if f, err := c.ReadFrame(ctx); err != nil || f.DesiredState == nil {
		t.Fatalf("first push = %+v err=%v, want DesiredState", f, err)
	}
	floor, err := c.ReadFrame(ctx)
	if err != nil || floor.SequenceFloor == nil {
		t.Fatalf("second push = %+v err=%v, want SequenceFloor", floor, err)
	}
	if err := c.WriteFrame(ctx, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: floor.SequenceFloor.EnrollmentEpoch,
		SequenceFloor:   floor.SequenceFloor.SequenceFloor,
	}}); err != nil {
		t.Fatalf("write floor applied: %v", err)
	}
	// A schema 8 session receiving a schema 7 packet.
	if err := c.WriteFrame(ctx, testPacket7(1)); err != nil {
		t.Fatalf("write mismatched packet: %v", err)
	}
	if _, err := c.ReadFrame(ctx); wire.CloseStatus(err) != wire.CloseProtocolError {
		t.Fatalf("mismatched packet close = %v, want 4003", err)
	}
}
