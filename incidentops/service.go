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
// OnEvidence / OnAlertResolved) are wired by the server onto the event bus — no
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

// diagEnabled gates the claim path. The bounds themselves are pushed to the
// Agent inside DesiredState (see config.DiagPolicy) — the server states the
// policy but keeps none of the execution — so the only thing it reads here is
// whether path diagnostics exist at all.
func (s *Service) diagEnabled(ctx context.Context) bool {
	if s.settings == nil {
		return settings.IntKeys[settings.KeyDiagEnabled].Default != 0
	}
	return s.settings.Bool(ctx, settings.KeyDiagEnabled)
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

// agentPermissions returns an agent's three reported permission views from its
// last reported policy — supported (platform/runtime capability), granted
// (policy) and effective (their intersection; the only view that authorizes
// execution) — for the traceroute permission gate and its fallback/denial
// classification. All empty on unknown agent.
func (s *Service) agentPermissions(ctx context.Context, agentID string) (supported, granted, effective permission.Set) {
	var supRaw, grantRaw, effRaw string
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT COALESCE(perm_supported,'[]'), COALESCE(perm_granted,'[]'), COALESCE(perm_effective,'[]')
		 FROM agents WHERE id=?`, agentID).Scan(&supRaw, &grantRaw, &effRaw); err != nil {
		return permission.Set{}, permission.Set{}, permission.Set{}
	}
	return permission.FromStrings(decodeStrings(supRaw)),
		permission.FromStrings(decodeStrings(grantRaw)),
		permission.FromStrings(decodeStrings(effRaw))
}

// canonicalDest returns the destination key and display host for a raw target
// host/IP. An IP literal keys as "ip:<canonical-ip>"; anything else keys as
// "host:<lowercased-host>".
//
// It must spell keys exactly as the Agent's own canonicalization does: the key is
// how a stored report and a confirmed fault find each other, and two independent
// normalizations are two chances to disagree about whether "Example.com" and
// "example.com" are one destination.
func canonicalDest(host string) (destKey, destHost string) {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		c := ip.String()
		return "ip:" + c, c
	}
	lower := strings.ToLower(host)
	return "host:" + lower, lower
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
