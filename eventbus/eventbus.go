// Package eventbus is a tiny in-process pub/sub used to decouple server-core
// modules (architecture §6/§15.4). It is the seam that later becomes NATS
// JetStream (§8 stage 2) without touching module code. P0 delivery is
// synchronous, which is enough for Lite scale.
package eventbus

import "sync"

// Well-known topics.
const (
	// Fault-signal lifecycle, published post-commit by the built-in detectors.
	TopicFaultConfirmed           = "fault.confirmed"
	TopicFaultResolved            = "fault.resolved"
	TopicIncidentOpened           = "incident.opened"
	TopicIncidentUpdated          = "incident.updated"
	TopicIncidentResolved         = "incident.resolved"
	TopicConfigChanged            = "config.changed"
	TopicIssueChanged             = "issue.changed"
	TopicTargetStatusChanged      = "target.status.changed"
	TopicAgentLivenessChanged     = "agent.liveness.changed"
	TopicAgentConnectivityChanged = "agent.connectivity.changed"
)

// IncidentEvent is the payload for the incident lifecycle topics
// (TopicIncidentOpened / TopicIncidentUpdated / TopicIncidentResolved),
// published post-commit by the fault engine so later notification, snapshot and
// diagnostic handlers can react without sharing the write transaction.
// Escalated is set on TopicIncidentUpdated when a membership change raised the
// incident's severity (the only membership growth that notifies, per policy).
type IncidentEvent struct {
	IncidentID string
	SiteID     string
	GroupID    string
	Severity   string
	Escalated  bool
}

// TargetStatusChanged is the payload for TopicTargetStatusChanged, published
// post-commit after any change that can alter a target's authoritative current
// status (telemetry + rule evaluation, execution-dimension reports, config/rule/
// scope mutations). It carries only the affected site and target ids; an empty
// TargetIDs means the whole site changed and the client should fully refresh.
type TargetStatusChanged struct {
	SiteID    string
	TargetIDs []string
}

// AgentLivenessChanged is the payload for TopicAgentLivenessChanged, published
// post-commit when an agent flips online↔offline. Liveness affects every target
// in the agent's scope, so a bridge fans it out to a site-wide status refresh.
type AgentLivenessChanged struct {
	SiteID  string
	AgentID string
	Status  string // online | offline
}

// AgentConnectivityChanged is the payload for TopicAgentConnectivityChanged,
// published by the agent-connectivity engine after it opens or resolves a
// liveness fault, so a bridge can fan a fresh agent-status snapshot out to
// connected consoles. It carries only the affected site; the console refetches
// the whole site's agent-status list.
type AgentConnectivityChanged struct {
	SiteID string
}

// ConfigChanged is the payload for TopicConfigChanged, published after a site's
// monitoring targets change (and config_version is bumped) so the WebSocket hub
// can push fresh DesiredState to the site's connected agents immediately.
type ConfigChanged struct {
	SiteID string
}

// IssueChanged is the payload for TopicIssueChanged, published after a site's
// operational_issues / monitor_status rows change (agent report, host
// re-evaluation, scope reconcile, mark-read) so the SSE broker can push a fresh
// snapshot to connected consoles.
type IssueChanged struct {
	SiteID string
}

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
