package agentws

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/nettact/protocol/config"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/wireadapt"
)

// countingConn is a wire.Conn that records what the session sent and whether it
// closed, so a test can assert on the peer's receipt directly instead of on a
// timing-dependent goroutine race.
type countingConn struct {
	mu     sync.Mutex
	writes []wire.Frame
	closed bool
}

func (c *countingConn) ReadFrame(context.Context) (wire.Frame, error) {
	return wire.Frame{}, errors.New("not used in this test")
}
func (c *countingConn) WriteFrame(_ context.Context, f wire.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, f)
	return nil
}
func (c *countingConn) Ping(context.Context) error { return nil }
func (c *countingConn) Close(wire.CloseCode, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *countingConn) wrote() []wire.Frame {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]wire.Frame(nil), c.writes...)
}
func (c *countingConn) wasClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func newTestSession(adapter *wireadapt.Adapter) (*session, *countingConn) {
	conn := &countingConn{}
	return &session{
		conn:     conn,
		agentID:  "agent_test",
		adapter:  adapter,
		sendCh:   make(chan wire.Frame),
		done:     make(chan struct{}),
		closed:   make(chan struct{}),
	}, conn
}

// TestWriteGuardedRefusesAForbiddenFrameBeforeThePeer: a frame the session's
// schema never negotiated must be refused before it reaches the peer, and the
// refusal must tear the session down loudly. This is the total-guard property
// both the live path and the drain path rely on; testing the shared method is
// what makes it deterministic — the alternative (racing the writer into its
// drain branch) is a genuine timing window and the existing session test for
// it is correspondingly timing-dependent.
func TestWriteGuardedRefusesAForbiddenFrameBeforeThePeer(t *testing.T) {
	// Schema 7 has no sequence-floor state machine, so a floor frame is exactly
	// the kind of frame a bug could enqueue against a pre-boundary session.
	a7, ok := wireadapt.Lookup(7)
	if !ok {
		t.Fatal("schema 7 adapter missing from the registry")
	}
	s, conn := newTestSession(a7)

	err := s.writeGuarded(wire.Frame{SequenceFloor: &wire.SequenceFloor{EnrollmentEpoch: 1}})
	if !errors.Is(err, errDownlinkGuard) {
		t.Fatalf("writeGuarded = %v, want errDownlinkGuard", err)
	}
	if n := len(conn.wrote()); n != 0 {
		t.Errorf("the forbidden frame reached the peer (%d write(s)); the guard must refuse before sending", n)
	}
	if !conn.wasClosed() {
		t.Error("a guard refusal must tear the session down loudly, but the connection was not closed")
	}
}

// TestWriteGuardedPassesAForbiddenFreeFrame: the guard must be selective — a
// frame the schema does permit (a schema 7 DesiredState, say) goes straight
// through. A guard that refuses everything would be a different, quieter bug.
func TestWriteGuardedPassesAnAllowedFrame(t *testing.T) {
	a7, ok := wireadapt.Lookup(7)
	if !ok {
		t.Fatal("schema 7 adapter missing from the registry")
	}
	s, conn := newTestSession(a7)

	allowed := wire.Frame{DesiredState: &config.DesiredState{}}
	if err := s.writeGuarded(allowed); err != nil {
		t.Fatalf("writeGuarded(allowed) = %v, want nil", err)
	}
	if got := conn.wrote(); len(got) != 1 || got[0] != allowed {
		t.Errorf("wrote %#v, want exactly the allowed frame", got)
	}
}
