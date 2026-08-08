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
//
// The diag_* keys are the SERVER's statement of policy, not its schedule: the
// Agent decides when to traceroute and executes it, and these travel down inside
// DesiredState as config.DiagPolicy. That is why there is no concurrency knob
// here any more — how many traces may run at once is a property of the machine
// running them, and it is configured on the Agent alongside its probe budget.
const (
	KeyIncidentSnapshotDeadlineMs = "incident_snapshot_deadline_ms"
	KeyIncidentSnapshotMaxBytes   = "incident_snapshot_max_bytes"
	KeyDiagEnabled                = "diag_enabled"
	KeyDiagTotalTimeoutMs         = "diag_total_timeout_ms"
	KeyDiagMaxHops                = "diag_max_hops"
	KeyDiagAttemptsPerHop         = "diag_attempts_per_hop"
	// KeyDiagConsecutiveFailures is how many consecutive failing rounds an Agent
	// must see before it traces. It defaults to the same 3 as the balanced
	// availability profile so a trace fires as the fault becomes real, rather than
	// on the first blip (noise) or long after confirmation (evidence collected past
	// the interesting moment).
	KeyDiagConsecutiveFailures = "diag_consecutive_failures"
	// KeyDiagCooldownSec is the minimum spacing between two traces of one
	// destination on one Agent. A target that stays down produces a failing round
	// every interval, and the path to it does not change nearly that often.
	KeyDiagCooldownSec       = "diag_cooldown_sec"
	KeyDiagPerHopTimeoutMs   = "diag_per_hop_timeout_ms"
	KeyEvidenceRetentionDays = "evidence_retention_days"
	// KeyFluctuationRetentionDays ages out recorded sub-threshold streaks. It bounds
	// only the UNLINKED ones: a fluctuation claimed as an incident's precursor is
	// that incident's evidence and lives as long as it does.
	KeyFluctuationRetentionDays = "fluctuation_retention_days"
)

// Agent connectivity detector (AGENT-002) knobs — detection only. Since
// ALERT-002 these decide whether an offline Agent is RECORDED as a fault and how
// long it takes to confirm; who hears about it is a notification policy, and its
// severity is fixed at critical. There is deliberately no channel or severity key
// here: routing lives in exactly one place.
//
// agent_status_stale_seconds is not part of the detector at all — it is the
// Agent list's resource-sample freshness cutoff (AGENT-001) — and is grouped
// here only because both are read off the same settings service.
const (
	KeyAgentConnectivityEnabled        = "agent_connectivity_enabled"         // 0/1; off = the fault is not even recorded
	KeyAgentConnectivityGraceSeconds   = "agent_connectivity_grace_seconds"   // offline grace before the fault is confirmed
	KeyAgentConnectivityRecoverSeconds = "agent_connectivity_recover_seconds" // sustained-online confirmation before resolve
	KeyAgentStatusStaleSeconds         = "agent_status_stale_seconds"         // resource sample freshness cutoff
)

// Alert-storm suppression (ALERT-001). When one Agent's vantage point goes dark,
// every monitor group under it breaches at once and each incident would announce
// itself separately. These two knobs decide when that burst is collapsed into a
// single "N faults at once" message.
//
// The threshold counts INCIDENTS, not monitor groups, because an incident is
// exactly one message: five targets failing inside one unmerged group is five
// messages, and that is the harassment being prevented. The rendered message
// still states both numbers, so the reader is never misled about the scope.
//
// A threshold of 0 turns correlation off entirely and restores the per-incident
// behaviour.
const (
	KeyIncidentStormThreshold     = "incident_storm_threshold"
	KeyIncidentStormWindowSeconds = "incident_storm_window_seconds"
)

// LAN device inventory retention. Discovery is upsert-only — the agent never
// reports a departure and ingest ignores OpRemove — so without an age cutoff the
// devices table only ever grows. The worst offender is MAC randomization: phones
// and laptops mint a fresh locally-administered address on every Wi-Fi join, and
// each one would otherwise become a permanent row.
//
// The two keys are not symmetric. KeyDeviceRetentionDays is the master switch
// (0 = never delete anything); KeyDeviceRandomMACRetentionDays only NARROWS the
// window for randomized addresses (0 = no narrowing, they age out on the master
// window).
//
// IntBounds cannot express that relationship — each key is range-checked on its
// own — so the narrowing rule is enforced outside this table, in two places: the
// settings API rejects a PUT whose resolved pair inverts it, and inventory clamps
// the randomized window to the master one when reading. Without both, a 7-day
// master beside a 30-day randomized window passes every per-key check and leaves
// throwaway addresses outliving the real devices they exist to age out ahead of.
const (
	KeyDeviceRetentionDays          = "device_retention_days"
	KeyDeviceRandomMACRetentionDays = "device_random_mac_retention_days"
)

// Game presentation retention. The two windows are independent because the rows
// they bound are nothing alike: a bucket is one row per second of play, and a run
// is one row per session carrying the summary an operator compares over months.
// Ageing them together would mean either keeping seconds nobody will chart or
// discarding the history that makes "is this machine getting worse" answerable.
//
// 0 disables that window, in which case those rows are kept indefinitely.
const (
	KeyGameBucketRetentionDays = "game_bucket_retention_days"
	KeyGameRunRetentionDays    = "game_run_retention_days"
)

// Update-notice state, shared by every surface that can announce a new release.
//
// The switch is a SERVER setting rather than per-client state on purpose: the
// desktop tray balloon and the web-console banner announce the same release, so
// turning notices off in the console has to silence the tray too. The desktop
// keeps only its own once-per-version bookkeeping locally.
//
// KeyUpdateDismissedVersion holds the version whose console banner was closed
// (the tray has no equivalent — a balloon is dismissed by ignoring it).
const (
	KeyUpdateNoticeDisabled   = "update_notice_disabled"
	KeyUpdateDismissedVersion = "update_dismissed_version"
)

// MaxDismissedVersionLen bounds the stored dismissed version. It holds a release
// tag the server itself reported, so this is a sanity cap, not a format rule.
const MaxDismissedVersionLen = 64

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
// Booleans (diag_enabled) are modeled as 0/1 ints.
var IntKeys = map[string]IntBounds{
	KeyIncidentSnapshotDeadlineMs: {Default: 10000, Min: 1000, Max: 60000},
	KeyIncidentSnapshotMaxBytes:   {Default: 262144, Min: 65536, Max: 1048576},
	KeyDiagEnabled:                {Default: 1, Min: 0, Max: 1},
	KeyDiagTotalTimeoutMs:         {Default: 300000, Min: 5000, Max: 600000},
	KeyDiagMaxHops:                {Default: 30, Min: 1, Max: 64},
	KeyDiagAttemptsPerHop:         {Default: 3, Min: 1, Max: 5},
	KeyDiagConsecutiveFailures:    {Default: 3, Min: 1, Max: 20},
	KeyDiagCooldownSec:            {Default: 900, Min: 60, Max: 86400},
	// 0 means "derive it from the total budget and the hop ceiling", which is the
	// sane relationship; the range starts at the Agent's own per-attempt floor.
	KeyDiagPerHopTimeoutMs:      {Default: 0, Min: 0, Max: 10000},
	KeyEvidenceRetentionDays:    {Default: 30, Min: 1, Max: 365},
	KeyFluctuationRetentionDays: {Default: 30, Min: 1, Max: 365},
	// Agent connectivity detection. Grace min (15s) stays above the sweeper's 10s
	// presence grace so a confirmed fault is always strictly slower than the UI
	// flipping the agent offline; stale default (120s) is ~4x the 30s host-metric
	// collection interval.
	KeyAgentConnectivityEnabled:        {Default: 1, Min: 0, Max: 1},
	KeyAgentConnectivityGraceSeconds:   {Default: 60, Min: 15, Max: 3600},
	KeyAgentConnectivityRecoverSeconds: {Default: 30, Min: 5, Max: 600},
	KeyAgentStatusStaleSeconds:         {Default: 120, Min: 30, Max: 3600},
	// Alert-storm correlation. Three is the smallest count that reads as "several
	// things at once" rather than coincidence, and the 300s window matches the
	// default warn notification delay (notifypolicy.DefaultWarnDelaySec) so the
	// whole delay window can be collapsed into one message rather than only its
	// tail. 0 threshold = correlation off.
	KeyIncidentStormThreshold:     {Default: 3, Min: 0, Max: 50},
	KeyIncidentStormWindowSeconds: {Default: 300, Min: 30, Max: 3600},
	// Device retention. A present device is re-seen every regular collection
	// cycle, so a week of silence is already a strong departure signal; a day is
	// plenty for a throwaway address that is only ever seen during one Wi-Fi
	// association. 0 has a distinct meaning per key — see the key comments.
	KeyDeviceRetentionDays:          {Default: 7, Min: 0, Max: 365},
	KeyDeviceRandomMACRetentionDays: {Default: 1, Min: 0, Max: 365},
	// Game data. A week of seconds covers "what happened in that session" while a
	// quarter of runs covers "has this machine got worse", which is the comparison
	// the run summaries exist for.
	KeyGameBucketRetentionDays: {Default: 7, Min: 0, Max: 365},
	KeyGameRunRetentionDays:    {Default: 90, Min: 0, Max: 3650},
	// Update notices default to on: a monitoring tool that quietly runs an old
	// build is the failure mode worth avoiding.
	KeyUpdateNoticeDisabled: {Default: 0, Min: 0, Max: 1},
}

type Service struct {
	db *store.DB

	// onDiagChange, when set, runs after a successful Set of any diag_* key.
	// The diag keys are the one settings family that travels to agents inside
	// DesiredState rather than being read lazily by a server-side worker, so a
	// mutation must trigger a push — otherwise a connected agent keeps tracing
	// under the old policy (including one the operator just switched off) until
	// it happens to reconnect. The hook lives here, on the single mutation
	// choke point, rather than in the HTTP handler: every future writer of
	// these keys gets the push for free.
	onDiagChange func()
}

func New(db *store.DB) *Service { return &Service{db: db} }

// diagPolicyKeys are the keys DesiredStateFor folds into the pushed DiagPolicy.
var diagPolicyKeys = map[string]bool{
	KeyDiagEnabled:             true,
	KeyDiagTotalTimeoutMs:      true,
	KeyDiagMaxHops:             true,
	KeyDiagAttemptsPerHop:      true,
	KeyDiagConsecutiveFailures: true,
	KeyDiagCooldownSec:         true,
	KeyDiagPerHopTimeoutMs:     true,
}

// keyDiagPolicySerial is bookkeeping, not an operator setting (hence not in
// IntKeys and never rendered by the console): a monotonic counter bumped with
// every diag_* change, stamped onto the pushed DiagPolicy so the agent can
// order policy updates that arrive out of build order. Persisted because the
// ordering must survive a server restart — an in-memory counter would restart
// at zero and make every pre-restart policy look newer than every later one.
const keyDiagPolicySerial = "diag_policy_serial"

// DiagPolicySerial returns the current policy generation, zero on an install
// whose diagnostic settings were never touched (every zero-serial push carries
// the identical defaults, so ordering among them is moot). Nil-safe like the
// other readers.
func (s *Service) DiagPolicySerial(ctx context.Context) uint64 {
	if s == nil {
		return 0
	}
	v, err := s.Get(ctx, keyDiagPolicySerial)
	if err != nil || v == "" {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// OnDiagPolicyChange registers fn to run after any diag_* key changes. The
// assembly points it at a TopicConfigChanged publish so connected agents get a
// fresh DesiredState immediately. Not safe to call concurrently with Set; wire
// it during assembly, before the HTTP surface is up.
func (s *Service) OnDiagPolicyChange(fn func()) { s.onDiagChange = fn }

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
		if _, err := s.db.ExecContext(ctx, `DELETE FROM app_settings WHERE key=?`, key); err != nil {
			return err
		}
	} else {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO app_settings(key, value) VALUES(?, ?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	// Clearing counts as a change too: reverting to the default is as much a
	// policy edit as setting a number. The serial bump commits before the hook
	// fires so the push the hook triggers reads the new generation.
	if diagPolicyKeys[key] {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO app_settings(key, value) VALUES(?, '1')
			ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)`,
			keyDiagPolicySerial); err != nil {
			return err
		}
		if s.onDiagChange != nil {
			s.onDiagChange()
		}
	}
	return nil
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
