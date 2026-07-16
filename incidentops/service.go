// Package incidentops is the server-side orchestration for an incident's
// immutable state snapshot (INCIDENT-002) and its automatic detecting-Agent
// traceroute reports (DIAG-001). It owns the snapshot/trace persistence, the
// per-Agent collecting/dispatch lifecycle over the agent WebSocket, result
// ingest with idempotent matching, single-flight trace sharing scoped to
// overlapping alert lifecycles, startup recovery, callable worker ticks, and the
// hourly evidence-retention pass.
//
// Dependency direction is one-way: the fault engine (package rules) calls
// WriteIncidentBase inside its incident-open transaction; the agent hub (package
// agentws) routes inbound IncidentSnapshot/TraceResult frames here and pushes
// outbound requests through the injected Pusher (satisfied by *agentws.Hub) so
// this package never imports agentws. Post-commit triggers (OnIncidentOpened /
// OnEvidence / OnAlertResolved) are wired by server-lite onto the event bus — no
// goroutine is spawned here and no DB-writing bus handler runs inside the open
// fault transition transaction.
package incidentops

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// Pusher pushes a server->agent request down an agent's live WebSocket session,
// reporting false when the agent is not connected. It is satisfied by
// *agentws.Hub; defining it here keeps the dependency one-way (incidentops never
// imports agentws).
type Pusher interface {
	PushIncidentSnapshotRequest(agentID string, req pcfg.IncidentSnapshotRequest) bool
	PushTraceRequest(agentID string, req pcfg.TraceRequest) bool
}

// Service orchestrates incident snapshots and traceroute reports.
type Service struct {
	db       *store.DB
	metrics  *metrics.Store
	settings *settings.Service
	bus      *eventbus.Bus
	pusher   Pusher
}

// New constructs the orchestration service. metrics/settings/bus may be nil in
// tests (recent-sample summaries, tuned bounds and event publication degrade to
// defaults/no-ops). The Pusher is injected later via SetPusher because the agent
// hub needs a reference to this service too (construction is a cycle otherwise).
func New(db *store.DB, m *metrics.Store, set *settings.Service, bus *eventbus.Bus) *Service {
	return &Service{db: db, metrics: m, settings: set, bus: bus}
}

// SetPusher injects the agent-WebSocket pusher. Called once during wiring, before
// serving, so no lock is needed.
func (s *Service) SetPusher(p Pusher) { s.pusher = p }

// ---- tuned settings (nil-safe: fall back to registered defaults) ----

func (s *Service) intSetting(ctx context.Context, key string) int {
	n, _ := s.settings.Int(ctx, key)
	return n
}

func (s *Service) snapshotDeadline(ctx context.Context) time.Duration {
	return time.Duration(s.intSetting(ctx, settings.KeyIncidentSnapshotDeadlineMs)) * time.Millisecond
}

func (s *Service) snapshotMaxBytes(ctx context.Context) int {
	return s.intSetting(ctx, settings.KeyIncidentSnapshotMaxBytes)
}

func (s *Service) diagEnabled(ctx context.Context) bool {
	if s.settings == nil {
		return settings.IntKeys[settings.KeyDiagEnabled].Default != 0
	}
	return s.settings.Bool(ctx, settings.KeyDiagEnabled)
}

func (s *Service) diagTotalTimeout(ctx context.Context) time.Duration {
	return time.Duration(s.intSetting(ctx, settings.KeyDiagTotalTimeoutMs)) * time.Millisecond
}

func (s *Service) diagMaxHops(ctx context.Context) int {
	return s.intSetting(ctx, settings.KeyDiagMaxHops)
}
func (s *Service) diagAttempts(ctx context.Context) int {
	return s.intSetting(ctx, settings.KeyDiagAttemptsPerHop)
}
func (s *Service) diagAgentConcurrency(ctx context.Context) int {
	return s.intSetting(ctx, settings.KeyDiagAgentConcurrency)
}
func (s *Service) diagGlobalConcurrency(ctx context.Context) int {
	return s.intSetting(ctx, settings.KeyDiagGlobalConcurrency)
}
func (s *Service) diagResolveHops(ctx context.Context) bool {
	if s.settings == nil {
		return settings.IntKeys[settings.KeyDiagResolveHops].Default != 0
	}
	return s.settings.Bool(ctx, settings.KeyDiagResolveHops)
}
func (s *Service) retentionDays(ctx context.Context) int {
	return s.intSetting(ctx, settings.KeyEvidenceRetentionDays)
}

// ---- shared helpers ----

// agentName returns the frozen display name for an agent (display_name or
// hostname), read on the read pool. Empty when the agent is unknown.
func (s *Service) agentName(ctx context.Context, agentID string) string {
	var name string
	_ = s.db.Read().QueryRowContext(ctx,
		`SELECT COALESCE(NULLIF(display_name,''), hostname, '') FROM agents WHERE id=?`, agentID).Scan(&name)
	return name
}

// agentEffective returns an agent's effective permission set from its last
// reported policy, for the traceroute permission gate. Empty on unknown agent.
func (s *Service) agentEffective(ctx context.Context, agentID string) permission.Set {
	var raw string
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT COALESCE(perm_effective,'[]') FROM agents WHERE id=?`, agentID).Scan(&raw); err != nil {
		return permission.Set{}
	}
	return permission.FromStrings(decodeStrings(raw))
}

// canonicalDest returns the single-flight destination key and the display host
// for a raw target host/IP. An IP literal keys as "ip:<canonical-ip>"; anything
// else keys as "host:<lowercased-host>" (the hostname stands in until the agent
// resolves an address, matching the spec's per-Agent canonical-destination rule).
func canonicalDest(host string) (destKey, destHost, destIP string) {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		c := ip.String()
		return "ip:" + c, c, c
	}
	lower := strings.ToLower(host)
	return "host:" + lower, lower, ""
}

// terminal snapshot / entry statuses.
const (
	statusCollecting = "collecting"
	statusComplete   = "complete"
	statusPartial    = "partial"
	statusFailed     = "failed"
)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullTime returns a NULL-aware time pointer for a sql.NullTime.
func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}
