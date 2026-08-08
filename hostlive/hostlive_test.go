package hostlive

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// fakeNow installs a controllable clock and returns the advance function.
func fakeNow(s *Store) func(d time.Duration) {
	now := time.Now()
	s.nowFn = func() time.Time { return now }
	return func(d time.Duration) { now = now.Add(d) }
}

// TestPendingLifecycle covers the pending-request path used by the WebSocket
// hub's on-connect re-push: a live request is returned as long as it is
// unanswered and fresh, expires after pendingTTL, and is cleared by the
// matching snapshot.
func TestPendingLifecycle(t *testing.T) {
	s := New()
	advance := fakeNow(s)

	if s.Pending("agent_a") != nil {
		t.Fatal("Pending with no request should be nil")
	}

	req, _ := s.Request("agent_a", []string{"host.process.basic.read"})
	if req.RequestID == "" || len(req.Scopes) != 1 || req.Scopes[0] != "host.process.basic.read" {
		t.Fatalf("Request returned %+v, want a single process-basic scope with an id", req)
	}

	// Unanswered and fresh: returned every time (re-push is idempotent).
	for i := 0; i < 2; i++ {
		p := s.Pending("agent_a")
		if p == nil || p.RequestID != req.RequestID {
			t.Fatalf("Pending #%d = %+v, want request %s", i, p, req.RequestID)
		}
	}

	// The matching snapshot clears it.
	s.Store("agent_a", telemetry.HostSnapshot{RequestID: req.RequestID})
	if s.Pending("agent_a") != nil {
		t.Error("Pending after the matching snapshot should be nil")
	}

	// An unanswered request expires after pendingTTL.
	s.Request("agent_a", []string{"host.process.basic.read", "host.connection.summary.read"})
	advance(pendingTTL + time.Second)
	if s.Pending("agent_a") != nil {
		t.Error("Pending past pendingTTL should be nil")
	}
}

// TestLatestFreshnessAndPending covers the console-polling view: a fresh
// snapshot is served with the pending flag, and both expire on their TTLs.
func TestLatestFreshnessAndPending(t *testing.T) {
	s := New()
	advance := fakeNow(s)

	req, _ := s.Request("agent_a", []string{"host.process.basic.read", "host.connection.summary.read"})
	if _, ok, pending := s.Latest("agent_a"); ok || !pending {
		t.Fatalf("before snapshot: ok=%v pending=%v, want false/true", ok, pending)
	}

	total := 7
	s.Store("agent_a", telemetry.HostSnapshot{RequestID: req.RequestID, ProcessTotal: &total})
	snap, ok, pending := s.Latest("agent_a")
	if !ok || pending || snap.ProcessTotal == nil || *snap.ProcessTotal != 7 {
		t.Fatalf("after snapshot: ok=%v pending=%v total=%v, want true/false/7", ok, pending, snap.ProcessTotal)
	}

	// The stored snapshot goes stale after snapshotTTL.
	advance(snapshotTTL + time.Second)
	if _, ok, _ := s.Latest("agent_a"); ok {
		t.Error("snapshot past snapshotTTL should not be served")
	}

	// An unanswered pending request stops being reported after pendingTTL, so
	// the console spinner cannot run forever for an agent that went away.
	s.Request("agent_b", []string{"host.process.basic.read"})
	advance(pendingTTL + time.Second)
	if _, _, pending := s.Latest("agent_b"); pending {
		t.Error("pending past pendingTTL should be cleared by Latest")
	}
}

// TestRequestCoalescing is the two-open case: a page opened a second time (or in
// a second browser) must not turn into a rate-limited "collection failed" for
// everyone. Whether the first answer is still in flight or just landed, the
// second ask rides on it and nothing extra reaches the agent.
func TestRequestCoalescing(t *testing.T) {
	scopes := []string{"host.process.basic.read", "host.connection.summary.read"}
	s := New()
	advance := fakeNow(s)

	first, push := s.Request("agent_a", scopes)
	if !push {
		t.Fatal("the first request must be pushed")
	}

	// Still unanswered: the second opener joins it and polls the same id.
	if req, push := s.Request("agent_a", scopes); push || req.RequestID != first.RequestID {
		t.Fatalf("in-flight join = (%s, push=%v), want (%s, push=false)", req.RequestID, push, first.RequestID)
	}
	// A subset joins too; anything the pending request does not cover does not.
	if _, push := s.Request("agent_a", []string{"host.process.basic.read"}); push {
		t.Error("a subset of the pending scopes must not be pushed")
	}
	if _, push := s.Request("agent_a", []string{"host.process.io.read"}); !push {
		t.Error("a scope the pending request does not cover must be pushed")
	}

	// Answered. Inside the window the delivered snapshot answers a new ask.
	s.Store("agent_a", telemetry.HostSnapshot{
		RequestID: first.RequestID,
		Scopes: []telemetry.SnapshotScopeResult{
			{Scope: scopes[0], Status: telemetry.ScopeCollected},
			{Scope: scopes[1], Status: telemetry.ScopeDenied},
		},
	})
	advance(coalesceWindow - time.Second)
	if req, push := s.Request("agent_a", scopes); push || req.RequestID != first.RequestID {
		t.Fatalf("fresh-snapshot reuse = (%s, push=%v), want (%s, push=false)", req.RequestID, push, first.RequestID)
	}

	// Past the window the agent is asked again.
	advance(2 * time.Second)
	if req, push := s.Request("agent_a", scopes); !push || req.RequestID == first.RequestID {
		t.Fatalf("past the window = (%s, push=%v), want a new id with push=true", req.RequestID, push)
	}
}

// A snapshot with a failed scope is the one answer worth asking again for — and
// the way a rate_limited response drains out instead of being replayed to every
// caller for the length of the window.
func TestRequestDoesNotReuseFailedSnapshot(t *testing.T) {
	scopes := []string{"host.process.basic.read"}
	s := New()
	fakeNow(s)

	first, _ := s.Request("agent_a", scopes)
	s.Store("agent_a", telemetry.HostSnapshot{
		RequestID: first.RequestID,
		Scopes: []telemetry.SnapshotScopeResult{
			{Scope: scopes[0], Status: telemetry.ScopeFailed, Reason: "rate_limited"},
		},
	})
	if req, push := s.Request("agent_a", scopes); !push || req.RequestID == first.RequestID {
		t.Fatalf("reuse of a failed snapshot = (%s, push=%v), want a new id with push=true", req.RequestID, push)
	}

	// A snapshot that never named the scope cannot answer for it either.
	second, _ := s.Request("agent_b", scopes)
	s.Store("agent_b", telemetry.HostSnapshot{RequestID: second.RequestID})
	if _, push := s.Request("agent_b", scopes); !push {
		t.Error("a snapshot with no result for the scope must not be reused")
	}
}
