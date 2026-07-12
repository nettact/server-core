// Package agentws is the server side of the persistent agent WebSocket channel
// that replaced the HTTP POST telemetry endpoint. Each agent holds one
// long-lived connection: it authenticates with its bearer token, sends a Hello,
// then streams telemetry Packets (acked in order) and HostSnapshots up, while
// the server pushes DesiredState and SnapshotRequests down the same pipe.
// Liveness is connection-driven: an open, ping-answering socket means the agent
// is online *now*, so config changes and snapshot requests reach it instantly
// instead of riding the next telemetry ack.
package agentws

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/hostlive"
	"github.com/nettact/server-core/ingest"
	"github.com/nettact/server-core/registry"
)

// Application close codes (4000-4999 range reserved for applications by RFC
// 6455). The agent switches on these to decide whether reconnecting is useful.
const (
	// StatusSuperseded closes an old session when the same agent connects again;
	// the replaced side must NOT reconnect (it would kick the new one in a loop).
	StatusSuperseded websocket.StatusCode = 4000
	// StatusUnsupportedSchema rejects a Hello whose schema version this server
	// does not understand; reconnecting won't help until one side is upgraded.
	StatusUnsupportedSchema websocket.StatusCode = 4001
	// StatusUnsupportedSubprotocol rejects a client that offered neither
	// nettact.v1 subprotocol, so the Frame encoding was never agreed on.
	StatusUnsupportedSubprotocol websocket.StatusCode = 4002
	// StatusProtocolError rejects a frame the protocol does not allow at that
	// point (non-Hello first frame, duplicate Hello, server->agent frame kinds
	// sent by the agent, or undecodable bytes).
	StatusProtocolError websocket.StatusCode = 4003
	// StatusRevoked evicts the session of an agent being deleted: its credential
	// is about to stop authenticating, so the agent must not reconnect (it would
	// re-enroll instead). Sent BEFORE the registry row is removed so no in-flight
	// packet can recreate purged series.
	StatusRevoked websocket.StatusCode = 4004
)

// maxFrameBytes bounds a single inbound frame. It matches the old POST body
// limit; the coder/websocket default (32 KiB) is far too small — a 500-row
// metrics packet alone exceeds it.
const maxFrameBytes = 8 << 20

// helloTimeout is how long a freshly upgraded connection may sit silent before
// it must have sent its Hello.
const helloTimeout = 10 * time.Second

// Deps are the services the hub drives on behalf of connected agents.
type Deps struct {
	Registry *registry.Service
	Ingest   *ingest.Service
	Config   *config.Service
	HostLive *hostlive.Store // in-memory live snapshots (never persisted)
	Bus      *eventbus.Bus   // source of TopicConfigChanged pushes
}

// Hub tracks the one live session per agent and fans server-initiated pushes
// (config changes, snapshot requests) out to them.
type Hub struct {
	deps Deps

	mu    sync.Mutex
	conns map[string]*session // agentID -> its single live session
}

// New constructs the hub and subscribes it to config changes so edited targets
// reach connected agents without waiting for anything agent-initiated.
func New(d Deps) *Hub {
	h := &Hub{deps: d, conns: make(map[string]*session)}
	if d.Bus != nil {
		d.Bus.Subscribe(eventbus.TopicConfigChanged, func(m eventbus.Message) {
			ev, ok := m.Payload.(eventbus.ConfigChanged)
			if !ok {
				return
			}
			// The bus is synchronous and the publisher is a console HTTP request;
			// building DesiredState runs one DB query per connected agent, so do
			// the fan-out on our own goroutine instead of blocking that request.
			// Two rapid edits may therefore deliver their pushes out of version
			// order — the agent guards against that by ignoring DesiredState older
			// than what it already applied, so no serialization is needed here.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				h.PushDesiredStateSite(ctx, ev.SiteID)
			}()
		})
	}
	return h
}

// HandleUpgrade is the GET /agent/ws handler: it authenticates the bearer
// token, upgrades to WebSocket, requires a valid Hello as the first frame, and
// then serves the session until either side goes away.
func (h *Hub) HandleUpgrade(w http.ResponseWriter, r *http.Request) {
	// Authenticate BEFORE upgrading so a bad token gets a plain 401 the agent
	// can distinguish from transport trouble (and we never hold sockets for
	// unauthenticated callers).
	agentID, siteID, err := h.deps.Registry.AuthenticateAgent(r.Context(), bearer(r))
	if err != nil {
		http.Error(w, "invalid agent token", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{wire.SubprotocolProtobuf, wire.SubprotocolJSON},
		// Telemetry frames are small and frequent; per-message deflate costs
		// more CPU than the bytes are worth on a LAN/home link.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return // Accept already replied with an HTTP error
	}
	// An empty negotiated subprotocol means the client offered neither
	// nettact.v1 variant, so we never agreed on a Frame encoding.
	if conn.Subprotocol() == "" {
		_ = conn.Close(StatusUnsupportedSubprotocol, "unsupported subprotocol")
		return
	}
	conn.SetReadLimit(maxFrameBytes)
	contentType := wire.SubprotocolContentType(conn.Subprotocol())

	// The first frame MUST be a Hello, promptly.
	helloCtx, cancel := context.WithTimeout(r.Context(), helloTimeout)
	_, data, err := conn.Read(helloCtx)
	cancel()
	if err != nil {
		_ = conn.Close(StatusProtocolError, "expected hello")
		return
	}
	frame, err := wire.UnmarshalFrame(data, contentType)
	if err != nil || frame.Hello == nil {
		_ = conn.Close(StatusProtocolError, "first frame must be hello")
		return
	}
	hello := frame.Hello
	if err := protocol.ValidateSchema(hello.SchemaVersion); err != nil {
		_ = conn.Close(StatusUnsupportedSchema, "unsupported schema")
		return
	}

	// The Hello replaces the per-request X-Agent-* headers of the old POST
	// transport: refresh the agent-owned fields it carries, then mark the agent
	// online immediately — a connected socket IS liveness, no packet needed.
	ctx := r.Context()
	_ = h.deps.Registry.UpdateCapabilities(ctx, agentID, hello.Capabilities)
	_ = h.deps.Registry.UpdateReportedInfo(ctx, agentID, hello.Hostname, hello.Platform, hello.AgentVersion)
	_ = h.deps.Registry.SetReportedConfigVersion(ctx, agentID, hello.ReportedConfigVersion)
	_ = h.deps.Registry.TouchLastSeen(ctx, agentID)

	s := &session{
		conn:        conn,
		agentID:     agentID,
		siteID:      siteID,
		contentType: contentType,
		sendCh:      make(chan wire.Frame, sendQueueCap),
		done:        make(chan struct{}),
	}

	// Register, kicking any previous session for this agent: exactly one live
	// connection per agent keeps ack ordering and push routing unambiguous. The
	// kick runs on its own goroutine because Close performs the WebSocket close
	// handshake (it can block seconds on an unresponsive peer) and must not
	// stall this handler or anyone else waiting on the hub mutex.
	h.mu.Lock()
	old := h.conns[agentID]
	h.conns[agentID] = s
	h.mu.Unlock()
	if old != nil {
		go old.shutdown(StatusSuperseded, "superseded")
	}

	defer func() {
		s.shutdown(websocket.StatusNormalClosure, "")
		// Unregister by identity: if a newer session already took this agent's
		// slot (we were kicked), we must not evict the replacement.
		h.mu.Lock()
		if h.conns[agentID] == s {
			delete(h.conns, agentID)
		}
		h.mu.Unlock()
		// Stamp last_seen_at one final time; status stays 'online' and the
		// sweeper flips it after the grace period, so a quick reconnect never
		// shows a bogus offline blip. The request ctx may already be dead here.
		tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = h.deps.Registry.TouchLastSeen(tctx, agentID)
		tcancel()
	}()

	go s.writeLoop()
	go s.pingLoop(h.deps.Registry)

	// Push the current DesiredState unconditionally. Applying it is idempotent
	// on the agent, and always pushing removes every "is it stale?" branch the
	// old ack-piggyback transport needed.
	if ds, err := h.deps.Config.DesiredStateFor(ctx, agentID); err == nil {
		if !s.enqueue(wire.Frame{DesiredState: &ds}) {
			return
		}
	} else {
		log.Printf("agentws: desired state for %s: %v", agentID, err)
	}
	// Re-push a snapshot request that is still awaiting its answer, covering a
	// request that arrived while the agent was mid-reconnect.
	if h.deps.HostLive != nil {
		if req := h.deps.HostLive.Pending(agentID); req != nil {
			if !s.enqueue(wire.Frame{SnapshotRequest: req}) {
				return
			}
		}
	}

	h.readLoop(ctx, s)
}

// PushDesiredStateSite rebuilds and pushes DesiredState to every connected
// agent of a site (per-agent, since group scoping resolves per agent).
func (h *Hub) PushDesiredStateSite(ctx context.Context, siteID string) {
	h.mu.Lock()
	sessions := make([]*session, 0, len(h.conns))
	for _, s := range h.conns {
		if s.siteID == siteID {
			sessions = append(sessions, s)
		}
	}
	h.mu.Unlock()
	for _, s := range sessions {
		ds, err := h.deps.Config.DesiredStateFor(ctx, s.agentID)
		if err != nil {
			log.Printf("agentws: desired state for %s: %v", s.agentID, err)
			continue
		}
		s.enqueue(wire.Frame{DesiredState: &ds})
	}
}

// PushSnapshotRequest sends a live-snapshot request to the agent's session,
// reporting false when the agent is not connected (the caller then tells the
// console the agent is offline instead of leaving a request dangling).
func (h *Hub) PushSnapshotRequest(agentID string, req pcfg.SnapshotRequest) bool {
	h.mu.Lock()
	s := h.conns[agentID]
	h.mu.Unlock()
	if s == nil {
		return false
	}
	return s.enqueue(wire.Frame{SnapshotRequest: &req})
}

// Disconnect synchronously evicts an agent's live session (no-op when it has
// none), performing the close handshake before returning. The agent-delete
// path calls this BEFORE purging: the session authenticated at upgrade time,
// so without an explicit evict it would keep ingesting under the captured
// identity and could recreate series the purge just removed.
func (h *Hub) Disconnect(agentID string, code websocket.StatusCode, reason string) {
	h.mu.Lock()
	s := h.conns[agentID]
	h.mu.Unlock()
	if s != nil {
		s.shutdown(code, reason)
	}
}

// IsConnected reports whether an agent currently holds a live session.
func (h *Hub) IsConnected(agentID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[agentID] != nil
}

// ConnectedIDs returns the agent IDs with a live session, for the offline
// sweeper's exclusion list.
func (h *Hub) ConnectedIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.conns))
	for id := range h.conns {
		ids = append(ids, id)
	}
	return ids
}

// CloseAll closes every session with StatusGoingAway for graceful shutdown.
// http.Server.Shutdown does NOT wait for (or close) hijacked WebSocket
// connections, so without this they would stall the shutdown deadline. Each
// close performs the close handshake (blocking up to its internal timeout on a
// dead peer), so they run in parallel and CloseAll waits for all of them.
func (h *Hub) CloseAll(reason string) {
	h.mu.Lock()
	sessions := make([]*session, 0, len(h.conns))
	for _, s := range h.conns {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func(s *session) {
			defer wg.Done()
			s.shutdown(websocket.StatusGoingAway, reason)
		}(s)
	}
	wg.Wait()
}

// bearer extracts the Authorization bearer token (same shape as the api
// package's helper; duplicated because it is three lines and the packages
// must not depend on each other).
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}
