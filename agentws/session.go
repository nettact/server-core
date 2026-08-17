package agentws

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/ingest"
	"github.com/nettact/server-core/registry"
)

const (
	// sendQueueCap is the outbound frame buffer per session. Pushes are rare
	// (acks + occasional config/snapshot frames), so a small buffer absorbs
	// bursts without letting a dead peer pin much memory.
	sendQueueCap = 32
	// enqueueTimeout is how long a push may block on a full queue before the
	// session is declared a slow consumer and killed. The agent reconnects and
	// gets fresh state on connect, which beats buffering unboundedly.
	enqueueTimeout = 5 * time.Second
	// writeTimeout bounds a single frame write so one wedged TCP connection
	// can't hang the writer goroutine forever.
	writeTimeout = 10 * time.Second
	// pingInterval / pingTimeout drive the keepalive that doubles as the
	// online heartbeat: every successful ping bumps last_seen_at.
	pingInterval = 15 * time.Second
	pingTimeout  = 5 * time.Second
)

// session is one agent's live connection (a WebSocket, or the desktop's
// in-process pipe). Reads happen on the goroutine that entered serve; all
// writes are funneled through sendCh into the single writer goroutine, so
// frames (in particular acks) leave in exactly the order they were enqueued.
type session struct {
	conn    wire.Conn
	agentID string
	siteID  string

	// Schema-8 session state. epoch/floorSent/floorPushed are set
	// by serve before readLoop starts; floorApplied is read and written only by
	// readLoop; rotated is set by the rotation paths before their close so the
	// teardown classifies the disconnect for what it was.
	epoch uint64
	// helloEpoch is the credential generation the agent stated in its Hello —
	// the epoch its signatures and OldEpoch values will name. It differs from
	// epoch when the credential is pre-schema-8 (Hello states 0) or stale
	// (a rotation the agent missed). Challenges are bound to helloEpoch, not
	// to the row's epoch, so the agent's answers always validate.
	helloEpoch      uint64
	floorSent       bool
	floorPushed     uint64
	floorApplied    bool
	sessionID       string
	pendingRotation *wire.EpochRotationResult
	rotated         bool

	sendCh chan wire.Frame
	done   chan struct{} // closed exactly once on shutdown
	once   sync.Once

	// closed is closed by serve() only after the session has fully torn down
	// (reader returned, unregistered, last_seen stamped). Disconnect/CloseAll
	// wait on it so a caller — notably agent deletion — knows no ingest is still
	// in flight before it purges the agent's series.
	closed chan struct{}

	// closeMu guards the close code captured by the first shutdown. serve()'s
	// teardown reads it to classify why the session ended (server-initiated
	// supersede/revoke/shutdown/error vs a peer-initiated close it must instead
	// read off the read error). closeReason rides along for the connection
	// close the writer performs after draining its queue.
	closeMu     sync.Mutex
	closeCode   wire.CloseCode
	closeReason string
	closeSet    bool
}

// shutdown records the close code and signals the session to end. The writer
// goroutine observes the signal, drains the frames already enqueued (so a
// final frame — the epoch-rotation result — precedes the close on the wire),
// and performs the connection close with the recorded code and reason. Safe to
// call from any goroutine, any number of times; only the first code/reason
// wins — and only that first code is captured for disconnect classification.
func (s *session) shutdown(code wire.CloseCode, reason string) {
	s.once.Do(func() {
		s.closeMu.Lock()
		s.closeCode, s.closeReason, s.closeSet = code, reason, true
		s.closeMu.Unlock()
		close(s.done)
	})
}

// closeInfo returns the code the session was first shut down with, and whether
// a server-side shutdown set it. When set=false the session ended because the
// read loop saw the peer close (or the link break) first, and the caller must
// classify from the read error instead.
func (s *session) closeInfo() (wire.CloseCode, bool) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeCode, s.closeSet
}

// closeInfoReason is closeInfo plus the reason, for the connection close the
// writer performs after draining its queue.
func (s *session) closeInfoReason() (wire.CloseCode, string, bool) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeCode, s.closeReason, s.closeSet
}

// enqueue hands a frame to the writer goroutine. It blocks briefly on a full
// queue; if the queue stays full past enqueueTimeout the peer is not draining
// (slow consumer) and the session is killed rather than buffered forever.
// Returns false when the frame was not accepted (session dead or killed).
func (s *session) enqueue(f wire.Frame) bool {
	t := time.NewTimer(enqueueTimeout)
	defer t.Stop()
	select {
	case s.sendCh <- f:
		return true
	case <-s.done:
		return false
	case <-t.C:
		s.shutdown(wire.ClosePolicyViolation, "write queue overflow")
		return false
	}
}

// writeLoop is the session's single writer: it serializes and sends every
// outbound frame in enqueue order, then performs the connection close with the
// code shutdown recorded. Encoding (protobuf vs JSON) lives in the transport
// adapter. On shutdown it drains the frames already queued first: a final
// frame enqueued just before the shutdown (the epoch-rotation result) must
// precede the close on the wire, the same ordering the pipe transport's reader
// already implements on the receiving side.
func (s *session) writeLoop() {
	for {
		select {
		case f := <-s.sendCh:
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			err := s.conn.WriteFrame(ctx, f)
			cancel()
			if err != nil {
				// A write error means the peer is gone (a clean agent close races the
				// writer) or, far more rarely, a server-built frame failed to marshal.
				// Either way the session cannot continue; the reader's teardown handles
				// the rest. Kept quiet because peer-gone is the normal disconnect path.
				// Record the classification and close here directly — this IS the
				// goroutine shutdown would ask to drain and close.
				s.shutdown(wire.CloseInternalError, "write failed")
				_ = s.conn.Close(wire.CloseInternalError, "write failed")
				return
			}
		case <-s.done:
			// Drain-before-close: everything already enqueued goes out, then the
			// close frame with the recorded code. A frame that cannot be written
			// (the peer is gone) ends the drain; the close attempt follows with
			// the recorded code, which still carries the classification.
		drain:
			for {
				select {
				case f := <-s.sendCh:
					ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
					err := s.conn.WriteFrame(ctx, f)
					cancel()
					if err != nil {
						break drain
					}
				default:
					code, reason, _ := s.closeInfoReason()
					_ = s.conn.Close(code, reason)
					return
				}
			}
			code, reason, _ := s.closeInfoReason()
			_ = s.conn.Close(code, reason)
			return
		}
	}
}

// pingLoop keeps the connection verified-alive: a successful ping proves the
// agent end-to-end, so each one bumps last_seen_at even when the agent has
// nothing to report. Over the in-memory pipe Ping always succeeds while the
// link is open, so last_seen stays fresh for the desktop's bundled agent too.
// A failed ping kills the session promptly instead of waiting for TCP to notice.
func (s *session) pingLoop(reg *registry.Service) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
			err := s.conn.Ping(ctx)
			cancel()
			if err != nil {
				s.shutdown(wire.CloseInternalError, "ping failed")
				return
			}
			tctx, tcancel := context.WithTimeout(context.Background(), pingTimeout)
			_ = reg.TouchLastSeenThrottled(tctx, s.agentID)
			tcancel()
		case <-s.done:
			return
		}
	}
}

// readLoop consumes agent->server frames until the connection dies. Because
// there is a single reader and a single ordered write queue, acks go back in
// the same order the packets arrived (the link guarantees message order), which
// is what the agent's WAL-pruning watermark logic relies on. It returns the
// terminal ReadFrame error so serve() can classify a peer-initiated close; when
// readLoop itself decides to shut the session down (bad frame, ingest failure,
// unexpected frame) it returns nil and the captured local close code carries the
// classification instead.
func (h *Hub) readLoop(ctx context.Context, s *session) error {
	for {
		frame, err := s.conn.ReadFrame(ctx)
		if err != nil {
			// A codec error (only the WebSocket transport can produce one) means the
			// agent sent bytes we cannot decode: close with the protocol-error code
			// so it learns the frame was rejected, not that the server went away.
			// Any other error is a normal disconnect handled by the deferred teardown.
			if errors.Is(err, errBadFrame) {
				s.shutdown(wire.CloseProtocolError, "bad frame")
				return nil
			}
			return err // closed, kicked, or broken — the deferred teardown handles it
		}
		switch {
		case frame.Packet != nil:
			// Fail closed: until the agent echoes the pushed floor back, no packet
			// may be claimed — a packet admitted before the barrier would be
			// renumberable in place, which is exactly what the epoch exists to
			// forbid.
			if !s.floorApplied {
				s.shutdown(wire.CloseProtocolError, "packet before floor applied")
				return nil
			}
			ack, err := h.deps.Ingest.Ingest(ctx, s.agentID, s.siteID, s.epoch, *frame.Packet)
			if err != nil {
				if errors.Is(err, ingest.ErrSequenceConflict) {
					// The batch collides with the durable receipt ledger under its
					// (epoch, sequence): it was either never admitted at this
					// watermark or admitted with different content. Renumbering in
					// place is forbidden, so the agent must rotate its epoch. No
					// ack, and the session STAYS — the agent drives the rotation
					// from here (challenge request or a direct request against the
					// challenge just issued).
					log.Printf("agentws: sequence conflict from %s (epoch %d, seq %d): offering an epoch rotation",
						s.agentID, s.epoch, frame.Packet.Sequence)
					ch := h.deps.Registry.IssueRotationChallenge(s.agentID, s.helloEpoch, "sequence_conflict")
					if !s.enqueue(wire.Frame{EpochRotationChallenge: &ch}) {
						return nil
					}
					continue
				}
				// No ack means the agent keeps the batch in its WAL; closing makes
				// it reconnect and retry rather than stream into a failing server.
				log.Printf("agentws: ingest from %s: %v", s.agentID, err)
				s.shutdown(wire.CloseInternalError, "ingest failed")
				return nil
			}
			// Liveness rides inside Ingest's transaction (TouchAgentTx); nothing
			// to stamp here — the ack goes straight back.
			wack := wire.Ack(ack)
			if !s.enqueue(wire.Frame{Ack: &wack}) {
				return nil
			}
		case frame.SequenceFloorApplied != nil:
			// The barrier's echo: it must restate exactly the floor this session
			// pushed, epoch included. Anything else is either a protocol error or
			// an echo of some other session's floor.
			applied := frame.SequenceFloorApplied
			if !s.floorSent || applied.EnrollmentEpoch != s.epoch || applied.SequenceFloor != s.floorPushed {
				s.shutdown(wire.CloseProtocolError, "sequence floor mismatch")
				return nil
			}
			s.floorApplied = true
		case frame.EpochRotationChallengeRequest != nil:
			// The agent asks to be rotated (its in-flight claim sits at or below
			// the floor, or some other local reason): mint a challenge and let the
			// normal challenge→request→result exchange follow.
			ch := h.deps.Registry.IssueRotationChallenge(s.agentID, s.helloEpoch, frame.EpochRotationChallengeRequest.Reason)
			if !s.enqueue(wire.Frame{EpochRotationChallenge: &ch}) {
				return nil
			}
		case frame.EpochRotationRequest != nil:
			newEpoch, newToken, err := h.deps.Registry.RotateEpoch(ctx, s.agentID, *frame.EpochRotationRequest)
			if err != nil {
				// Never log token plaintexts; the error carries epoch/reason only.
				status, reason := wire.RotationDenied, err.Error()
				switch {
				case errors.Is(err, registry.ErrRotationChallenge),
					errors.Is(err, registry.ErrRotationEpoch),
					errors.Is(err, registry.ErrAuth),
					errors.Is(err, registry.ErrSignature):
					status = wire.RotationDenied
				default:
					// Transient (a DB error mid-rotation): the agent may retry with
					// a fresh challenge.
					status = wire.RotationRetry
				}
				log.Printf("agentws: epoch rotation for %s: %v", s.agentID, err)
				if !s.enqueue(wire.Frame{EpochRotationResult: &wire.EpochRotationResult{Status: status, Reason: reason}}) {
					return nil
				}
				continue // keep the session: the old credential stays in force
			}
			// Success: deliver the new credential exactly once (a lost delivery
			// is recovered through the registry's old-token pending window), then
			// end the session — the agent persists the credential and reconnects
			// under the new identity.
			if !s.enqueue(wire.Frame{EpochRotationResult: &wire.EpochRotationResult{
				Status:     wire.RotationOK,
				NewEpoch:   newEpoch,
				AgentToken: newToken,
			}}) {
				return nil
			}
			s.rotated = true
			s.shutdown(wire.CloseGoingAway, "epoch rotated; reconnect")
			return nil
		case frame.HostSnapshot != nil:
			// Stored in memory only, latest-wins and idempotent; never acked.
			if h.deps.HostLive != nil {
				h.deps.HostLive.Store(s.agentID, *frame.HostSnapshot)
			}
		case frame.MonitorStatus != nil:
			// The agent's full-state view of its probe monitors for a config
			// version: reconcile monitor_status + operational_issues. Never acked;
			// the monotonic guard inside drops stale/out-of-order frames.
			if h.deps.OpIssue != nil {
				if err := h.deps.OpIssue.ApplyMonitorStatus(ctx, s.agentID, s.siteID, *frame.MonitorStatus); err != nil {
					log.Printf("agentws: monitor status from %s: %v", s.agentID, err)
				}
			}
		default:
			// A second Hello, or a server->agent frame kind (Ack / DesiredState /
			// SnapshotRequest) coming FROM the agent: both are protocol violations.
			s.shutdown(wire.CloseProtocolError, "unexpected frame")
			return nil
		}
	}
}
