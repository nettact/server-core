// Package sse is a minimal Server-Sent Events fan-out used to push live updates
// to connected consoles. It is intentionally tiny: a broker holds one buffered
// event channel per subscriber; a site notification is a non-blocking send, and a
// subscriber that cannot keep up (its buffer overflows) is dropped by closing its
// channel — the HTTP handler then ends that response and the browser's EventSource
// reconnects.
//
// Events are typed (STATUS-001): the broker now carries a small Event value so it
// can multiplex more than one stream on one connection. Two kinds ride it:
//
//   - "issues" (Data nil) — a signal only; the SSE handler re-queries the
//     authoritative operational-issue state and writes a full, idempotent
//     snapshot, exactly as before.
//   - "target.status.changed" (Data set) — the precise affected-id payload, written
//     to the client verbatim so it can coalesce a batch refresh.
package sse

import "sync"

// subChanCap bounds a subscriber's pending events before it is treated as a slow
// consumer and dropped.
const subChanCap = 64

// Well-known SSE event names carried by Event.Name.
const (
	EventIssues              = "issues"
	EventTargetStatusChanged = "target.status.changed"
	// EventAgentStatusChanged (Data set: {"site_id":...}) signals that a site's
	// agent-status list changed (liveness flip, connectivity alert, or a rule
	// alert/issue affecting an agent). Written verbatim; the console coalesces and
	// refetches the whole agent-status list.
	EventAgentStatusChanged = "agent.status.changed"
)

// Event is one server-sent event to fan out to a site's subscribers. Name is the
// SSE event name; Data is the pre-marshaled JSON payload written verbatim, or nil
// when the handler should re-query authoritative state (the issues snapshot).
type Event struct {
	Name string
	Data []byte
}

type sub struct {
	siteID string
	ch     chan Event
}

// Broker fans typed site events out to per-connection subscribers.
type Broker struct {
	mu   sync.Mutex
	subs map[int]*sub
	next int
}

// NewBroker returns an empty broker.
func NewBroker() *Broker {
	return &Broker{subs: make(map[int]*sub)}
}

// Subscribe registers a subscriber for a site and returns its id plus a
// receive-only channel that delivers every Event notified for the site and is
// closed when the subscriber is dropped (overflow) or Unsubscribed.
func (b *Broker) Subscribe(siteID string) (int, <-chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	s := &sub{siteID: siteID, ch: make(chan Event, subChanCap)}
	b.subs[id] = s
	return id, s.ch
}

// Unsubscribe drops a subscriber (idempotent). Safe to call from the handler's
// defer even after an overflow already closed the channel.
func (b *Broker) Unsubscribe(id int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeLocked(id)
}

// Notify delivers ev to every subscriber of siteID. A subscriber whose buffer is
// full is dropped (its channel closed) rather than blocking the publisher.
func (b *Broker) Notify(siteID string, ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, s := range b.subs {
		if s.siteID != siteID {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			b.closeLocked(id) // slow consumer: drop it
		}
	}
}

// closeLocked removes and closes a subscriber; the caller holds b.mu.
func (b *Broker) closeLocked(id int) {
	if s, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(s.ch)
	}
}

// Close drops every subscriber, closing their channels so active SSE handlers
// return. Call it during shutdown before the database is closed, so no handler
// keeps querying through a closed DB.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id := range b.subs {
		b.closeLocked(id)
	}
}
