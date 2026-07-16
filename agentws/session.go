package agentws

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/nettact/protocol/wire"
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

	sendCh chan wire.Frame
	done   chan struct{} // closed exactly once on shutdown
	once   sync.Once

	// closed is closed by serve() only after the session has fully torn down
	// (reader returned, unregistered, last_seen stamped). Disconnect/CloseAll
	// wait on it so a caller — notably agent deletion — knows no ingest is still
	// in flight before it purges the agent's series.
	closed chan struct{}
}

// shutdown closes the connection with the given code and stops the writer
// and ping goroutines. Safe to call from any goroutine, any number of times;
// only the first code/reason wins.
func (s *session) shutdown(code wire.CloseCode, reason string) {
	s.once.Do(func() {
		close(s.done)
		_ = s.conn.Close(code, reason)
	})
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
// outbound frame in enqueue order. Encoding (protobuf vs JSON) lives in the
// transport adapter.
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
				s.shutdown(wire.CloseInternalError, "write failed")
				return
			}
		case <-s.done:
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
			_ = reg.TouchLastSeen(tctx, s.agentID)
			tcancel()
		case <-s.done:
			return
		}
	}
}

// readLoop consumes agent->server frames until the connection dies. Because
// there is a single reader and a single ordered write queue, acks go back in
// the same order the packets arrived (the link guarantees message order), which
// is what the agent's WAL-pruning watermark logic relies on.
func (h *Hub) readLoop(ctx context.Context, s *session) {
	for {
		frame, err := s.conn.ReadFrame(ctx)
		if err != nil {
			// A codec error (only the WebSocket transport can produce one) means the
			// agent sent bytes we cannot decode: close with the protocol-error code
			// so it learns the frame was rejected, not that the server went away.
			// Any other error is a normal disconnect handled by the deferred teardown.
			if errors.Is(err, errBadFrame) {
				s.shutdown(wire.CloseProtocolError, "bad frame")
			}
			return // closed, kicked, or broken — the deferred teardown handles it
		}
		switch {
		case frame.Packet != nil:
			ack, err := h.deps.Ingest.Ingest(ctx, s.agentID, s.siteID, *frame.Packet)
			if err != nil {
				// No ack means the agent keeps the batch in its WAL; closing makes
				// it reconnect and retry rather than stream into a failing server.
				log.Printf("agentws: ingest from %s: %v", s.agentID, err)
				s.shutdown(wire.CloseInternalError, "ingest failed")
				return
			}
			_ = h.deps.Registry.TouchLastSeen(ctx, s.agentID)
			_ = h.deps.Registry.SetReportedConfigVersion(ctx, s.agentID, frame.Packet.ReportedConfigVersion)
			wack := wire.Ack(ack)
			if !s.enqueue(wire.Frame{Ack: &wack}) {
				return
			}
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
		case frame.IncidentSnapshot != nil:
			// One-shot incident-scene result. Never acked; matched idempotently by
			// (request id + incident id + authenticated agent id) — a duplicate, late
			// or wrong-agent result is a no-op inside the orchestration.
			if h.deps.IncidentOps != nil {
				if err := h.deps.IncidentOps.IngestSnapshot(ctx, s.agentID, *frame.IncidentSnapshot); err != nil {
					log.Printf("agentws: incident snapshot from %s: %v", s.agentID, err)
				}
			}
		case frame.TraceResult != nil:
			// One-shot traceroute result. Never acked; matched by (report id +
			// authenticated agent id + nonterminal state) so a duplicate/late/wrong-
			// agent result cannot mutate or attach elsewhere.
			if h.deps.IncidentOps != nil {
				if err := h.deps.IncidentOps.IngestTrace(ctx, s.agentID, *frame.TraceResult); err != nil {
					log.Printf("agentws: trace result from %s: %v", s.agentID, err)
				}
			}
		default:
			// A second Hello, or a server->agent frame kind (Ack / DesiredState /
			// SnapshotRequest) coming FROM the agent: both are protocol violations.
			s.shutdown(wire.CloseProtocolError, "unexpected frame")
			return
		}
	}
}
