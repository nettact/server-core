// Package settings is a tiny key/value store for global, UI-editable server
// settings backed by the app_settings table. It intentionally stays generic so
// new global knobs can be added without schema changes.
package settings

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/nettact/server-core/store"
)

// KeyConsoleBaseURL is the console's externally-reachable origin (scheme+host,
// e.g. "http://localhost:12450"). Used to build deep links in notifications.
const KeyConsoleBaseURL = "console_base_url"

// KeyListenAddr is the UI-configured HTTP listen address ("host:port", host
// limited to 127.0.0.1 or 0.0.0.0). It overrides the -addr flag and the built-in
// default; the server resolves it at startup (standalone: next start; desktop:
// immediate embedded restart).
const KeyListenAddr = "listen_addr"

// KeyDashboardLayout stores the instance-wide dashboard widget layout. The
// authenticated console reads the same value from every browser connected to
// this server instance.
const KeyDashboardLayout = "dashboard_layout"

// KeyOnboardingState stores the console's first-run onboarding progress
// (structured JSON: status/step/selected regions/banner state). It is served
// through dedicated /api/v1/onboarding endpoints and is never exposed through
// the generic settings API.
const KeyOnboardingState = "onboarding_state"

// Incident-snapshot (INCIDENT-002) and diagnostic-traceroute (DIAG-001) tuning
// knobs, plus evidence retention. Each is a UI-editable, server-validated int
// setting stored in app_settings; the bounds and defaults live in one table
// (IntKeys) so the API validator and the typed accessors never drift.
const (
	KeyIncidentSnapshotDeadlineMs = "incident_snapshot_deadline_ms"
	KeyIncidentSnapshotMaxBytes   = "incident_snapshot_max_bytes"
	KeyDiagEnabled                = "diag_enabled"
	KeyDiagTotalTimeoutMs         = "diag_total_timeout_ms"
	KeyDiagMaxHops                = "diag_max_hops"
	KeyDiagAttemptsPerHop         = "diag_attempts_per_hop"
	KeyDiagAgentConcurrency       = "diag_agent_concurrency"
	KeyDiagGlobalConcurrency      = "diag_global_concurrency"
	KeyDiagResolveHops            = "diag_resolve_hops"
	KeyEvidenceRetentionDays      = "evidence_retention_days"
)

// Agent connectivity-alert (AGENT-002) knobs. The int knobs live in IntKeys
// (auto-exposed and bounds-checked by the settings API); the two free-form
// string keys are validated explicitly in the API handler and added to its
// allow-list. agent_status_stale_seconds also drives the status list's
// resource-staleness marking (AGENT-001).
const (
	KeyAgentAlertEnabled        = "agent_alert_enabled"         // 0/1
	KeyAgentAlertGraceSeconds   = "agent_alert_grace_seconds"   // offline grace before an alert fires
	KeyAgentAlertRecoverSeconds = "agent_alert_recover_seconds" // sustained-online confirmation before resolve
	KeyAgentStatusStaleSeconds  = "agent_status_stale_seconds"  // resource sample freshness cutoff
	KeyAgentAlertSeverity       = "agent_alert_severity"        // '' (=warn) | info | warn | error | critical
	KeyAgentAlertChannelIDs     = "agent_alert_channel_ids"     // JSON array; '' / [] = all enabled channels
)

// IntBounds is one integer setting's default and inclusive [Min,Max] range.
type IntBounds struct {
	Default int
	Min     int
	Max     int
}

// IntKeys is the single source of truth for the incident/diagnostic integer
// settings: their defaults and validated bounds. The generic settings API reads
// it to (a) allow-list the keys, (b) reject out-of-range values, and the typed
// accessors below read it to fall back to the default on unset/invalid values.
// Booleans (diag_enabled, diag_resolve_hops) are modeled as 0/1 ints.
var IntKeys = map[string]IntBounds{
	KeyIncidentSnapshotDeadlineMs: {Default: 10000, Min: 1000, Max: 60000},
	KeyIncidentSnapshotMaxBytes:   {Default: 262144, Min: 65536, Max: 1048576},
	KeyDiagEnabled:                {Default: 1, Min: 0, Max: 1},
	KeyDiagTotalTimeoutMs:         {Default: 90000, Min: 5000, Max: 120000},
	KeyDiagMaxHops:                {Default: 30, Min: 1, Max: 64},
	KeyDiagAttemptsPerHop:         {Default: 3, Min: 1, Max: 5},
	KeyDiagAgentConcurrency:       {Default: 4, Min: 1, Max: 16},
	KeyDiagGlobalConcurrency:      {Default: 16, Min: 1, Max: 64},
	KeyDiagResolveHops:            {Default: 0, Min: 0, Max: 1},
	KeyEvidenceRetentionDays:      {Default: 30, Min: 1, Max: 365},
	// Agent connectivity alerts. Grace min (15s) stays above the sweeper's 10s
	// presence grace so an offline alert is always strictly slower than the UI
	// flipping the agent offline; stale default (120s) is ~4x the 30s host-metric
	// collection interval.
	KeyAgentAlertEnabled:        {Default: 1, Min: 0, Max: 1},
	KeyAgentAlertGraceSeconds:   {Default: 60, Min: 15, Max: 3600},
	KeyAgentAlertRecoverSeconds: {Default: 30, Min: 5, Max: 600},
	KeyAgentStatusStaleSeconds:  {Default: 120, Min: 30, Max: 3600},
}

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

// Int returns the stored value for an integer key, falling back to the key's
// registered default when unset, unparseable, or out of bounds. Unknown keys
// return (0, false). Nil-safe so tests without a settings service degrade to
// defaults.
func (s *Service) Int(ctx context.Context, key string) (int, bool) {
	b, ok := IntKeys[key]
	if !ok {
		return 0, false
	}
	if s == nil {
		return b.Default, true
	}
	v, err := s.Get(ctx, key)
	if err != nil || v == "" {
		return b.Default, true
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < b.Min || n > b.Max {
		return b.Default, true
	}
	return n, true
}

// Bool reads a 0/1 integer key as a boolean (default applied on unset/invalid).
func (s *Service) Bool(ctx context.Context, key string) bool {
	n, _ := s.Int(ctx, key)
	return n != 0
}

// Get returns the value for key, or "" if unset.
func (s *Service) Get(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.Read().QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// All returns every stored setting as a map.
func (s *Service) All(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Read().QueryContext(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// Set upserts a key. An empty value clears it (row removed) so "unset" and
// "empty string" read back the same.
func (s *Service) Set(ctx context.Context, key, value string) error {
	if value == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM app_settings WHERE key=?`, key)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ConsoleBaseURL returns the configured console origin with any trailing slash
// removed, or "" when unset. Nil-safe so callers without a settings service
// (e.g. tests) degrade to "no deep link".
func (s *Service) ConsoleBaseURL(ctx context.Context) string {
	if s == nil {
		return ""
	}
	v, err := s.Get(ctx, KeyConsoleBaseURL)
	if err != nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(v), "/")
}
