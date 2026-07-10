// Package eventbus is a tiny in-process pub/sub used to decouple server-core
// modules (architecture §6/§15.4). It is the seam that later becomes NATS
// JetStream (§8 stage 2) without touching module code. P0 delivery is
// synchronous, which is enough for Lite scale.
package eventbus

import "sync"

// Well-known topics.
const (
	TopicTelemetryIngested = "telemetry.ingested"
	TopicThresholdBreached = "metric.threshold.breached"
	TopicAlertRaised       = "alert.raised"
	TopicAlertResolved     = "alert.resolved"
	TopicIncidentOpened    = "incident.opened"
	TopicIncidentUpdated   = "incident.updated"
)

// Message is one published event.
type Message struct {
	Topic   string
	Payload any
}

// Handler receives a published Message.
type Handler func(Message)

// Bus is a synchronous fan-out pub/sub.
type Bus struct {
	mu   sync.RWMutex
	subs map[string][]Handler
}

// New returns an empty Bus.
func New() *Bus {
	return &Bus{subs: make(map[string][]Handler)}
}

// Subscribe registers h for topic. Not safe to call concurrently with Publish
// on the same topic during startup wiring; wire all subscriptions before serving.
func (b *Bus) Subscribe(topic string, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs[topic] = append(b.subs[topic], h)
}

// Publish delivers payload to every subscriber of topic, synchronously.
func (b *Bus) Publish(topic string, payload any) {
	b.mu.RLock()
	handlers := append([]Handler(nil), b.subs[topic]...)
	b.mu.RUnlock()
	for _, h := range handlers {
		h(Message{Topic: topic, Payload: payload})
	}
}
