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
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/hostlive"
	"github.com/nettact/server-core/ingest"
	"github.com/nettact/server-core/opissue"
	"github.com/nettact/server-core/registry"
)

// maxFrameBytes bounds a single inbound frame. It matches the old POST body
// limit; the coder/websocket default (32 KiB) is far too small — a 500-row
// metrics packet alone exceeds it.
const maxFrameBytes = 8 << 20

// helloTimeout is how long a freshly upgraded connection may sit silent before
// it must have sent its Hello.
const helloTimeout = 10 * time.Second

// ErrClosed is returned by DialLocal after CloseAll: the hub is shutting down
// and accepts no further sessions.
var ErrClosed = errors.New("agentws: hub closed")

// Deps are the services the hub drives on behalf of connected agents.
type Deps struct {
	Registry *registry.Service
	Ingest   *ingest.Service
	Config   *config.Service
	HostLive *hostlive.Store  // in-memory live snapshots (never persisted)
	OpIssue  *opissue.Service // operational-issue engine (monitor status + host re-eval)
	Bus      *eventbus.Bus    // source of TopicConfigChanged pushes
	// IncidentOps routes inbound incident-snapshot / trace-result frames and drives
	// the on-connect re-push of still-outstanding, in-deadline snapshot/trace work.
	// Optional (nil in a build without the orchestration wired).
	IncidentOps IncidentOps
}

// IncidentOps is the incident snapshot/trace orchestration surface the hub needs:
// ingest of agent results and the reconnect re-push. Satisfied by
// *incidentops.Service; kept as an interface so agentws does not hard-depend on
// its construction.
type IncidentOps interface {
	IngestSnapshot(ctx context.Context, agentID string, snap telemetry.IncidentSnapshot) error
	IngestTrace(ctx context.Context, agentID string, res telemetry.TraceResult) error
	OnAgentConnected(ctx context.Context, agentID string)
}

// Hub tracks the one live session per agent and fans server-initiated pushes
// (config changes, snapshot requests) out to them.
type Hub struct {
	deps Deps

	mu          sync.Mutex
	conns       map[string]*session    // agentID -> its single live session
	closed      bool                   // set by CloseAll; refuses further sessions
	handshaking map[wire.Conn]struct{} // admitted conns not yet registered; CloseAll cuts them loose
	serving     sync.WaitGroup         // one per admitted serve; CloseAll waits for all of them
}

// New constructs the hub and subscribes it to config changes so edited targets
// reach connected agents without waiting for anything agent-initiated.
func New(d Deps) *Hub {
	h := &Hub{deps: d, conns: make(map[string]*session), handshaking: make(map[wire.Conn]struct{})}
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
// token, upgrades to WebSocket, checks the negotiated subprotocol, then hands
// the connection to serve (which owns the Hello handshake and session loop).
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
		_ = conn.Close(websocket.StatusCode(wire.CloseUnsupportedSubprotocol), "unsupported subprotocol")
		return
	}
	conn.SetReadLimit(maxFrameBytes)

	sc := &wsConn{c: conn, contentType: wire.SubprotocolContentType(conn.Subprotocol())}
	h.serve(r.Context(), agentID, siteID, sc)
}

// serve runs one authenticated session over an established frame link: it
// requires a valid Hello as the first frame, refreshes registry state, registers
// the session (kicking any prior one for the same agent), pushes current
// DesiredState, and loops until the link dies. It blocks for the session's life.
// Transport-agnostic: HandleUpgrade wraps a WebSocket, DialLocal wraps a pipe.
func (h *Hub) serve(ctx context.Context, agentID, siteID string, c wire.Conn) {
	// Admission: a hub CloseAll has swept accepts no further connections, and one
	// it HAS admitted must be awaited — the Hello side effects below write through
	// the registry, so CloseAll must not return (its caller closes the DB) while a
	// handshake is mid-write. The conn is tracked until registration so CloseAll
	// can cut a parked Hello read loose instead of stalling shutdown for up to
	// helloTimeout.
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = c.Close(wire.CloseGoingAway, "server shutting down")
		return
	}
	h.serving.Add(1)
	h.handshaking[c] = struct{}{}
	h.mu.Unlock()
	defer h.serving.Done()
	defer func() {
		// Idempotent with the delete at registration; covers every earlier return.
		h.mu.Lock()
		delete(h.handshaking, c)
		h.mu.Unlock()
	}()

	// The first frame MUST be a Hello, promptly.
	helloCtx, cancel := context.WithTimeout(ctx, helloTimeout)
	frame, err := c.ReadFrame(helloCtx)
	cancel()
	if err != nil || frame.Hello == nil {
		if h.isClosed() {
			// CloseAll cut this handshake off mid-read; that is a shutdown, not a
			// peer protocol error, and must be recorded as one.
			_ = h.deps.Registry.RecordDisconnect(ctx, agentID, "server_shutdown")
			_ = c.Close(wire.CloseGoingAway, "server shutting down")
			return
		}
		_ = h.deps.Registry.RecordDisconnect(ctx, agentID, "error")
		_ = c.Close(wire.CloseProtocolError, "first frame must be hello")
		return
	}
	hello := frame.Hello
	if err := protocol.ValidateSchema(hello.SchemaVersion); err != nil {
		// Record the reason at a point where the agent identity is already known
		// (auth happened before the upgrade), so a firing connectivity alert can
		// map it to "version incompatible" rather than a generic loss.
		_ = h.deps.Registry.RecordDisconnect(ctx, agentID, "unsupported_schema")
		_ = c.Close(wire.CloseUnsupportedSchema, "unsupported schema")
		return
	}

	// The Hello replaces the per-request X-Agent-* headers of the old POST
	// transport: refresh the agent-owned fields it carries, then mark the agent
	// online immediately — a connected link IS liveness, no packet needed.
	_ = h.deps.Registry.UpdatePermissions(ctx, agentID, hello.Permissions)
	_ = h.deps.Registry.UpdateReportedInfo(ctx, agentID, hello.Hostname, hello.Platform, hello.AgentVersion)
	_ = h.deps.Registry.SetReportedConfigVersion(ctx, agentID, hello.ReportedConfigVersion)
	_ = h.deps.Registry.TouchLastSeen(ctx, agentID)
	// Stamp the first-ever connection (no-op after the first): until this is set
	// the agent is "never connected", which the status list and alert engine
	// treat differently from an agent that connected and later went offline.
	_ = h.deps.Registry.MarkFirstConnected(ctx, agentID)
	// The agent's effective policy just refreshed, so recompute which of its host
	// monitors are permission-blocked (probe monitors arrive via MonitorStatus),
	// and seed predicted rows for its applicable probe monitors so a freshly
	// connected agent's pairs have an assignment clock before its first frame.
	if h.deps.OpIssue != nil {
		if err := h.deps.OpIssue.ReevaluateHostMonitors(ctx, agentID); err != nil {
			log.Printf("agentws: reevaluate host monitors for %s: %v", agentID, err)
		}
		if err := h.deps.OpIssue.PredictProbeMonitorsForAgent(ctx, agentID); err != nil {
			log.Printf("agentws: predict probe monitors for %s: %v", agentID, err)
		}
	}

	s := &session{
		conn:    c,
		agentID: agentID,
		siteID:  siteID,
		sendCh:  make(chan wire.Frame, sendQueueCap),
		done:    make(chan struct{}),
		closed:  make(chan struct{}),
	}
	// Registered first so it runs LAST (after the teardown defer below): closing
	// `closed` signals Disconnect/CloseAll that the reader has returned and the
	// final ingest, if any, has completed.
	defer close(s.closed)

	// Register, kicking any previous session for this agent: exactly one live
	// connection per agent keeps ack ordering and push routing unambiguous. The
	// kick runs on its own goroutine because Close performs the WebSocket close
	// handshake (it can block seconds on an unresponsive peer) and must not
	// stall this handler or anyone else waiting on the hub mutex.
	//
	// A hub that CloseAll already swept must never gain a session: absent from
	// the sweep's snapshot, it would outlive the shutdown and keep writing
	// through services the caller is about to stop (on the desktop, a
	// reconnecting bundled agent would latch onto the outgoing server instead of
	// its replacement). This closes the window between admission and
	// registration: the Hello above just marked the agent online, so the refusal
	// also records the cutoff — the DB is still open, because CloseAll is
	// waiting on h.serving. Registration also ends the handshake phase: from
	// here the conn is owned by the registered session and CloseAll closes it
	// through s.shutdown, not the handshake sweep.
	h.mu.Lock()
	delete(h.handshaking, c)
	if h.closed {
		h.mu.Unlock()
		tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = h.deps.Registry.RecordDisconnect(tctx, agentID, "server_shutdown")
		tcancel()
		_ = c.Close(wire.CloseGoingAway, "server shutting down")
		return
	}
	old := h.conns[agentID]
	h.conns[agentID] = s
	h.mu.Unlock()
	if old != nil {
		go old.shutdown(wire.CloseSuperseded, "superseded")
	}

	var readErr error
	defer func() {
		// Classify BEFORE the default shutdown below: a peer-initiated close leaves
		// closeSet=false and carries its code in readErr, while a server-initiated
		// shutdown (supersede/revoke/CloseAll/ping/write/ingest error) already set
		// the local code. The default shutdown here would otherwise stamp
		// CloseNormalClosure and mask an unexpected drop as a clean one.
		kind := classifyDisconnect(readErr, s)
		s.shutdown(wire.CloseNormalClosure, "")
		// Unregister by identity: if a newer session already took this agent's
		// slot (we were kicked), we must not evict the replacement.
		h.mu.Lock()
		wasCurrent := h.conns[agentID] == s
		if wasCurrent {
			delete(h.conns, agentID)
		}
		h.mu.Unlock()
		// Only the session that still owns the agent's slot writes liveness and
		// provenance. If a newer session already superseded us, IT owns them (its
		// Hello re-stamped last_seen and it will record its own disconnect kind on
		// teardown); a late teardown here must not overwrite the newer session's
		// disconnect kind with "superseded" or re-stamp last_seen. When we are the
		// current session, record how it ended and stamp last_seen_at one final
		// time so a quick reconnect never shows a bogus offline blip.
		if wasCurrent {
			tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = h.deps.Registry.RecordDisconnect(tctx, agentID, kind)
			_ = h.deps.Registry.TouchLastSeen(tctx, agentID)
			tcancel()
		}
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
	// Re-push still-outstanding, in-deadline incident-snapshot and traceroute work.
	// The session is already registered above, so the orchestration's Pusher resolves
	// to this live session. Runs before the read loop so a reconnect promptly resumes
	// collection/execution.
	if h.deps.IncidentOps != nil {
		h.deps.IncidentOps.OnAgentConnected(ctx, agentID)
	}

	readErr = h.readLoop(ctx, s)
}

// classifyDisconnect maps how a session ended to a last_disconnect_kind. A
// server-initiated shutdown captured the local close code (supersede kick, agent
// revoke, graceful CloseAll, or a ping/write/ingest failure); a peer-initiated
// close leaves the local code unset and carries its RFC 6455 code in the read
// error. Both WebSocket and the in-process pipe surface peer codes through
// wire.CloseStatus, so the desktop's bundled agent classifies identically.
func classifyDisconnect(readErr error, s *session) string {
	if code, set := s.closeInfo(); set {
		switch code {
		case wire.CloseSuperseded:
			return "superseded"
		case wire.CloseRevoked:
			return "revoked"
		case wire.CloseGoingAway:
			return "server_shutdown"
		case wire.CloseNormalClosure:
			return "clean"
		default:
			return "error"
		}
	}
	switch wire.CloseStatus(readErr) {
	case wire.CloseNormalClosure, wire.CloseGoingAway:
		return "clean"
	default:
		return "error"
	}
}

// DialLocal authenticates the token and, on success, attaches an in-process
// agent link: it creates a frame pipe, serves the server end on its own
// goroutine (same lifecycle as a WebSocket session — registered in the hub,
// kicked on supersede, closed by CloseAll), and returns the agent end. The
// desktop's bundled agent connects through this instead of a loopback
// WebSocket, so telemetry never leaves the process.
//
// It returns ErrClosed once CloseAll has run: the server is shutting down and
// its DB is about to close, so failing fast lets the bundled agent's reconnect
// loop reach the replacement server instead of latching onto this one.
func (h *Hub) DialLocal(ctx context.Context, token string) (wire.Conn, error) {
	h.mu.Lock()
	closed := h.closed
	h.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	agentID, siteID, err := h.deps.Registry.AuthenticateAgent(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("authenticate agent: %w", err)
	}
	agentEnd, serverEnd := wire.Pipe()
	// context.Background(): the session's lifetime is governed by the link itself
	// plus CloseAll on shutdown, exactly like a hijacked WebSocket that outlives
	// the request context in practice.
	go h.serve(context.Background(), agentID, siteID, serverEnd)
	return agentEnd, nil
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

// PushIncidentSnapshotRequest pushes an incident-scene snapshot request to the
// agent's live session, reporting false when the agent is offline (the entry then
// stays collecting until its deadline or a reconnect re-push). Satisfies
// incidentops.Pusher.
func (h *Hub) PushIncidentSnapshotRequest(agentID string, req pcfg.IncidentSnapshotRequest) bool {
	h.mu.Lock()
	s := h.conns[agentID]
	h.mu.Unlock()
	if s == nil {
		return false
	}
	return s.enqueue(wire.Frame{IncidentSnapshotRequest: &req})
}

// PushTraceRequest pushes a traceroute request to the agent's live session,
// reporting false when the agent is offline (the report then stays queued for a
// reconnect re-dispatch). Satisfies incidentops.Pusher.
func (h *Hub) PushTraceRequest(agentID string, req pcfg.TraceRequest) bool {
	h.mu.Lock()
	s := h.conns[agentID]
	h.mu.Unlock()
	if s == nil {
		return false
	}
	return s.enqueue(wire.Frame{TraceRequest: &req})
}

// Disconnect synchronously evicts an agent's live session (no-op when it has
// none), waiting for the session to fully tear down before returning. The
// agent-delete path calls this BEFORE purging: the session authenticated at
// upgrade time, so without an explicit evict it would keep ingesting under the
// captured identity and could recreate series the purge just removed. Waiting on
// s.closed guarantees any in-flight ingest has finished before the caller purges.
func (h *Hub) Disconnect(agentID string, code wire.CloseCode, reason string) {
	h.mu.Lock()
	s := h.conns[agentID]
	h.mu.Unlock()
	if s != nil {
		s.shutdown(code, reason)
		<-s.closed
	}
}

// IsConnected reports whether an agent currently holds a live session.
func (h *Hub) IsConnected(agentID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[agentID] != nil
}

// isClosed reports whether CloseAll has latched the hub shut.
func (h *Hub) isClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
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

// CloseAll closes every session with CloseGoingAway for graceful shutdown.
// http.Server.Shutdown does NOT wait for (or close) hijacked WebSocket
// connections, so without this they would stall the shutdown deadline. Each
// close performs the close handshake (blocking up to its internal timeout on a
// dead peer), so they run in parallel and CloseAll waits for every session to
// fully tear down — including any in-flight ingest — before returning, so the
// caller's later db.Close cannot race a live writer.
//
// It also latches the hub closed in the same critical section that snapshots the
// sessions, so a connection racing the sweep is refused rather than surviving it
// (see serve and DialLocal). Connections still mid-handshake — admitted but not
// yet registered — are cut loose (unblocking a parked Hello read immediately
// instead of at helloTimeout) and then awaited via h.serving, so no Hello side
// effect can write through a DB the caller closes after CloseAll returns. The
// latch is permanent: a Hub is never reused.
func (h *Hub) CloseAll(reason string) {
	h.mu.Lock()
	h.closed = true
	sessions := make([]*session, 0, len(h.conns))
	for _, s := range h.conns {
		sessions = append(sessions, s)
	}
	handshakes := make([]wire.Conn, 0, len(h.handshaking))
	for c := range h.handshaking {
		handshakes = append(handshakes, c)
	}
	h.mu.Unlock()
	// Fire-and-forget: Close can block on a dead peer's close handshake, and the
	// h.serving wait below already guarantees the serve goroutines (the only DB
	// writers among them) have returned before CloseAll does.
	for _, c := range handshakes {
		go func(c wire.Conn) { _ = c.Close(wire.CloseGoingAway, reason) }(c)
	}
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func(s *session) {
			defer wg.Done()
			s.shutdown(wire.CloseGoingAway, reason)
			<-s.closed
		}(s)
	}
	wg.Wait()
	h.serving.Wait()
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
