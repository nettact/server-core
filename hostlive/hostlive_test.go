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

	req := s.Request("agent_a", true, false)
	if req.RequestID == "" || !req.WantProcesses || req.WantConnections {
		t.Fatalf("Request returned %+v, want processes-only with an id", req)
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
	s.Request("agent_a", true, true)
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

	req := s.Request("agent_a", true, true)
	if _, ok, pending := s.Latest("agent_a"); ok || !pending {
		t.Fatalf("before snapshot: ok=%v pending=%v, want false/true", ok, pending)
	}

	s.Store("agent_a", telemetry.HostSnapshot{RequestID: req.RequestID, ProcessTotal: 7})
	snap, ok, pending := s.Latest("agent_a")
	if !ok || pending || snap.ProcessTotal != 7 {
		t.Fatalf("after snapshot: ok=%v pending=%v total=%d, want true/false/7", ok, pending, snap.ProcessTotal)
	}

	// The stored snapshot goes stale after snapshotTTL.
	advance(snapshotTTL + time.Second)
	if _, ok, _ := s.Latest("agent_a"); ok {
		t.Error("snapshot past snapshotTTL should not be served")
	}

	// An unanswered pending request stops being reported after pendingTTL, so
	// the console spinner cannot run forever for an agent that went away.
	s.Request("agent_b", true, true)
	advance(pendingTTL + time.Second)
	if _, _, pending := s.Latest("agent_b"); pending {
		t.Error("pending past pendingTTL should be cleared by Latest")
	}
}
