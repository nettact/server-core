// Package incidentops is the server-side custody of an incident's evidence: the
// immutable server-authored snapshot base (INCIDENT-002), the scenes agents
// collect on their own fault edges (INCIDENT-005), and the traceroutes they run
// on their own initiative (DIAG-001). It owns the persistence of all three,
// idempotent ingest inside the telemetry write transaction, the two-way claim
// between evidence and the fault it explains, startup recovery, callable worker
// ticks, and the hourly evidence-retention pass.
//
// Dependency direction is one-way and there is no longer any server→agent leg:
// the fault engine (package fault) calls WriteIncidentBase inside its
// incident-open transaction, telemetry ingest calls IngestScenesTx /
// IngestTracesTx inside its own, and the post-commit claim triggers
// (OnSignalConfirmed / OnSignalResolved) are wired by the server onto the event
// bus. Nothing here pushes down the agent WebSocket, so this package neither
// imports agentws nor needs anything injected from it — an evidence collection
// that has to be commanded is a collection that never happens for the offline
// agent it is most needed from. No goroutine is spawned here and no DB-writing
// bus handler runs inside the open fault transition transaction.
package incidentops

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"time"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// Service orchestrates incident snapshots, agent scenes and traceroute reports.
type Service struct {
	db       *store.DB
	metrics  *metrics.Store
	settings *settings.Service
	bus      *eventbus.Bus
}

// New constructs the evidence service. metrics/settings/bus may be nil in tests
// (recent-sample summaries, tuned bounds and event publication degrade to
// defaults/no-ops).
func New(db *store.DB, m *metrics.Store, set *settings.Service, bus *eventbus.Bus) *Service {
	return &Service{db: db, metrics: m, settings: set, bus: bus}
}

// ---- tuned settings (nil-safe: fall back to registered defaults) ----

func (s *Service) intSetting(ctx context.Context, key string) int {
	n, _ := s.settings.Int(ctx, key)
	return n
}

// snapshotMaxBytes is the hard cap on one stored evidence body — the server's
// frozen incident base, and each agent scene payload. One knob covers both
// because they are the two halves of the same page and an operator raising it
// means "let me keep more of the scene", not "let me keep more of one of its
// columns".
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
