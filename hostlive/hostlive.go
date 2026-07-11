// Package hostlive holds the ephemeral, pull-on-demand host snapshots (live
// process and network-connection lists) that agents return in response to a
// console user opening the live page. Nothing here is persisted: the store keeps
// only the latest snapshot per agent in memory, plus a short-lived pending
// request that is attached to the agent's next DesiredState downlink. This is
// how a request reaches the outbound-only agent, and why process/connection data
// is never written to the database or alerted on.
package hostlive

import (
	"sync"
	"time"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

const (
	// pendingTTL bounds how long an unanswered request stays live (agent offline).
	pendingTTL = 60 * time.Second
	// dispatchThrottle keeps the server from re-asking on every telemetry upload
	// while a request is in flight; it re-dispatches only after this interval.
	dispatchThrottle = 12 * time.Second
	// snapshotTTL is how long a delivered snapshot is served before it is stale.
	snapshotTTL = 60 * time.Second
)

type pending struct {
	req          pcfg.SnapshotRequest
	requestedAt  time.Time
	dispatchedAt time.Time
}

type stored struct {
	snap telemetry.HostSnapshot
	at   time.Time
}

// Store is the in-memory registry of pending requests and latest snapshots.
type Store struct {
	mu      sync.Mutex
	pending map[string]*pending // agentID -> pending request
	latest  map[string]stored   // agentID -> most recent snapshot
	nowFn   func() time.Time
}

func New() *Store {
	return &Store{
		pending: map[string]*pending{},
		latest:  map[string]stored{},
		nowFn:   time.Now,
	}
}

// Request registers (or replaces) a pending live-snapshot request for an agent
// and returns the new request id. wantProcs/wantConns come from the console; the
// agent still re-checks its own opt-in flags before collecting anything.
func (s *Store) Request(agentID string, wantProcs, wantConns bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := "snap_" + uuid.NewString()
	s.pending[agentID] = &pending{
		req:         pcfg.SnapshotRequest{RequestID: id, WantProcesses: wantProcs, WantConnections: wantConns},
		requestedAt: s.nowFn(),
	}
	return id
}

// PendingFor returns the request to attach to an agent's DesiredState, or nil.
// It expires stale requests and throttles re-dispatch so a request in flight is
// not re-sent on every telemetry upload.
func (s *Store) PendingFor(agentID string) *pcfg.SnapshotRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[agentID]
	if !ok {
		return nil
	}
	now := s.nowFn()
	if now.Sub(p.requestedAt) > pendingTTL {
		delete(s.pending, agentID)
		return nil
	}
	if !p.dispatchedAt.IsZero() && now.Sub(p.dispatchedAt) < dispatchThrottle {
		return nil
	}
	p.dispatchedAt = now
	req := p.req
	return &req
}

// Store records a snapshot returned by an agent and clears the matching pending
// request. It is idempotent (latest-wins), so it is safe to call outside the
// ingest dedup path.
func (s *Store) Store(agentID string, snap telemetry.HostSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest[agentID] = stored{snap: snap, at: s.nowFn()}
	if p, ok := s.pending[agentID]; ok && (snap.RequestID == "" || p.req.RequestID == snap.RequestID) {
		delete(s.pending, agentID)
	}
}

// Latest returns the most recent snapshot for an agent if it is still fresh, and
// whether a request is currently pending (so the console can show a spinner).
// It also enforces pendingTTL here: an offline agent never calls PendingFor, so
// without this the console would poll a "pending" request forever and the entry
// would leak.
func (s *Store) Latest(agentID string) (telemetry.HostSnapshot, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.pending[agentID]; ok && s.nowFn().Sub(p.requestedAt) > pendingTTL {
		delete(s.pending, agentID)
	}
	_, isPending := s.pending[agentID]
	st, ok := s.latest[agentID]
	if !ok || s.nowFn().Sub(st.at) > snapshotTTL {
		return telemetry.HostSnapshot{}, false, isPending
	}
	return st.snap, true, isPending
}
