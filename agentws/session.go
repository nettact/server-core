package agentws

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/coder/websocket"

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

// session is one agent's live WebSocket connection. Reads happen on the
// goroutine that entered HandleUpgrade; all writes are funneled through sendCh
// into the single writer goroutine, so frames (in particular acks) leave in
// exactly the order they were enqueued.
type session struct {
	conn        *websocket.Conn
	agentID     string
	siteID      string
	contentType string // fixed per connection by the negotiated subprotocol

	sendCh chan wire.Frame
	done   chan struct{} // closed exactly once on shutdown
	once   sync.Once
}

// shutdown closes the connection with the given status and stops the writer
// and ping goroutines. Safe to call from any goroutine, any number of times;
// only the first status/reason wins.
func (s *session) shutdown(code websocket.StatusCode, reason string) {
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
		s.shutdown(websocket.StatusPolicyViolation, "write queue overflow")
		return false
	}
}

// writeLoop is the session's single writer: it serializes and sends every
// outbound frame. Binary messages carry protobuf, text carries JSON, matching
// what the negotiated subprotocol promises the agent.
func (s *session) writeLoop() {
	msgType := websocket.MessageText
	if s.contentType == wire.ContentTypeProtobuf {
		msgType = websocket.MessageBinary
	}
	for {
		select {
		case f := <-s.sendCh:
			data, err := wire.MarshalFrame(f, s.contentType)
			if err != nil {
				// Server-built frames always carry exactly one payload, so this
				// is a programming error — surface it instead of hiding it.
				log.Printf("agentws: marshal frame for %s: %v", s.agentID, err)
				s.shutdown(websocket.StatusInternalError, "encode frame")
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			err = s.conn.Write(ctx, msgType, data)
			cancel()
			if err != nil {
				// The connection is broken; the reader will notice and tear down.
				s.shutdown(websocket.StatusAbnormalClosure, "write failed")
				return
			}
		case <-s.done:
			return
		}
	}
}

// pingLoop keeps the connection verified-alive: a successful ping proves the
// agent end-to-end (coder/websocket answers incoming pings automatically while
// a Read is in flight, and Ping is safe concurrently with the writer — writes
// are serialized internally), so each one bumps last_seen_at even when the
// agent has nothing to report. A failed ping kills the session promptly
// instead of waiting for TCP to notice.
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
				s.shutdown(websocket.StatusAbnormalClosure, "ping failed")
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
// the same order the packets arrived (WS guarantees message order), which is
// what the agent's WAL-pruning watermark logic relies on.
func (h *Hub) readLoop(ctx context.Context, s *session) {
	for {
		_, data, err := s.conn.Read(ctx)
		if err != nil {
			return // closed, kicked, or broken — the deferred teardown handles it
		}
		frame, err := wire.UnmarshalFrame(data, s.contentType)
		if err != nil {
			s.shutdown(StatusProtocolError, "bad frame")
			return
		}
		switch {
		case frame.Packet != nil:
			ack, err := h.deps.Ingest.Ingest(ctx, s.agentID, s.siteID, *frame.Packet)
			if err != nil {
				// No ack means the agent keeps the batch in its WAL; closing makes
				// it reconnect and retry rather than stream into a failing server.
				log.Printf("agentws: ingest from %s: %v", s.agentID, err)
				s.shutdown(websocket.StatusInternalError, "ingest failed")
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
		default:
			// A second Hello, or a server->agent frame kind (Ack / DesiredState /
			// SnapshotRequest) coming FROM the agent: both are protocol violations.
			s.shutdown(StatusProtocolError, "unexpected frame")
			return
		}
	}
}
