// Package hostlive holds the ephemeral, pull-on-demand host snapshots (live
// process and network-connection lists) that agents return in response to a
// console user opening the live page. Nothing here is persisted: the store keeps
// only the latest snapshot per agent in memory, plus a short-lived pending
// request. Dispatch is a direct WebSocket push — once when the console asks,
// and again if the agent reconnects while the request is still live (covering a
// blip between ask and delivery) — so no re-dispatch throttle is needed. This
// is also why process/connection data is never written to the database or
// alerted on.
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
	// snapshotTTL is how long a delivered snapshot is served before it is stale.
	snapshotTTL = 60 * time.Second
	// coalesceWindow is how recently a snapshot must have been delivered for a NEW
	// request to be answered from it instead of asking the agent again.
	//
	// It exists because the agent refuses back-to-back collections:
	// agent/internal/conn rate-limits them to one per SnapshotMinInterval (3s) and
	// answers a request inside that window with every scope marked failed
	// ("rate_limited"), which the console can only render as "collection failed".
	// Two people — or one person with the page open twice — would each make the
	// other's page look broken. This window must stay comfortably ABOVE the
	// agent's interval, or the coalescing lets exactly the request through that
	// the agent is about to refuse.
	coalesceWindow = 5 * time.Second
)

type pending struct {
	req         pcfg.SnapshotRequest
	requestedAt time.Time
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

// Request answers a console's ask for a live snapshot. It returns the request the
// console should poll for, and whether the caller must push it to the agent.
//
// A push is skipped when an answer for these scopes is already on its way or has
// just arrived:
//
//   - an unanswered request that covers the asked-for scopes — the second caller
//     joins it and polls the same request id, so both see the one snapshot;
//   - a snapshot delivered within coalesceWindow that covers them — returned as
//     its own request id, which the caller's next poll matches immediately.
//
// Either way nothing reaches the agent, which is the point: the agent refuses a
// second collection inside its rate-limit window and answers with every scope
// failed, so a second console open used to turn into "collection failed" on the
// page that asked second (and, a moment later, on any page that polled).
//
// A snapshot containing a failed scope is never reused — failure is the one
// answer worth asking again for, and it is also how a rate_limited response from
// before this coalescing (or from another server sharing the agent) drains out
// instead of being replayed for the next 5 seconds. Denied and unsupported are
// stable answers: asking again returns them unchanged.
func (s *Store) Request(agentID string, scopes []string) (pcfg.SnapshotRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFn()

	if p, ok := s.pending[agentID]; ok {
		switch {
		case now.Sub(p.requestedAt) > pendingTTL:
			delete(s.pending, agentID)
		case covers(p.req.Scopes, scopes):
			return p.req, false
		}
	}
	if st, ok := s.latest[agentID]; ok && now.Sub(st.at) <= coalesceWindow && reusable(st.snap, scopes) {
		return pcfg.SnapshotRequest{RequestID: st.snap.RequestID, Scopes: scopes}, false
	}

	req := pcfg.SnapshotRequest{
		RequestID: "snap_" + uuid.NewString(),
		Scopes:    scopes,
	}
	s.pending[agentID] = &pending{req: req, requestedAt: now}
	return req, true
}

// covers reports whether have ⊇ want.
func covers(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, s := range want {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// reusable reports whether a delivered snapshot can answer a fresh ask for the
// given scopes: it must carry a result for every one of them, and none of those
// results may be a failure (see Request).
func reusable(snap telemetry.HostSnapshot, want []string) bool {
	if snap.RequestID == "" {
		return false
	}
	answered := make(map[string]string, len(snap.Scopes))
	for _, sr := range snap.Scopes {
		answered[sr.Scope] = sr.Status
	}
	for _, sc := range want {
		st, ok := answered[sc]
		if !ok || st == telemetry.ScopeFailed {
			return false
		}
	}
	return true
}

// Pending returns the agent's live pending request, or nil. Its only remaining
// caller is the WebSocket hub's on-connect re-push (the initial dispatch pushes
// the request directly), so a non-nil result means "still waiting for the
// snapshot" and is safe to re-send: the agent answers idempotently.
func (s *Store) Pending(agentID string) *pcfg.SnapshotRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[agentID]
	if !ok {
		return nil
	}
	if s.nowFn().Sub(p.requestedAt) > pendingTTL {
		delete(s.pending, agentID)
		return nil
	}
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
// It also enforces pendingTTL here: an offline agent never answers, so without
// this the console would poll a "pending" request forever and the entry would
// leak.
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
