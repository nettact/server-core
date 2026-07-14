// Package sse is a minimal Server-Sent Events fan-out used to push live
// operational-issue updates to connected consoles. It is intentionally tiny: a
// broker holds one buffered signal channel per subscriber; a site notification is
// a non-blocking send, and a subscriber that cannot keep up (its buffer overflows)
// is dropped by closing its channel — the HTTP handler then ends that response and
// the browser's EventSource reconnects. The broker carries no payload: it only
// signals "site X changed", and the SSE handler re-queries the authoritative state
// and writes a full, idempotent snapshot.
package sse

import "sync"

// subChanCap bounds a subscriber's pending signals before it is treated as a slow
// consumer and dropped.
const subChanCap = 64

type sub struct {
	siteID string
	ch     chan struct{}
}

// Broker fans site-change signals out to per-connection subscribers.
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
// receive-only channel that fires (a) on every Notify for the site and (b) is
// closed when the subscriber is dropped (overflow) or Unsubscribed.
func (b *Broker) Subscribe(siteID string) (int, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	s := &sub{siteID: siteID, ch: make(chan struct{}, subChanCap)}
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

// Notify signals every subscriber of siteID. A subscriber whose buffer is full is
// dropped (its channel closed) rather than blocking the publisher.
func (b *Broker) Notify(siteID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, s := range b.subs {
		if s.siteID != siteID {
			continue
		}
		select {
		case s.ch <- struct{}{}:
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
