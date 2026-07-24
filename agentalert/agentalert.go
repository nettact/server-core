// Package agentalert is the connectivity-alert engine (AGENT-002): it raises a
// single manageable alert when an agent stays offline past a configurable grace
// period and resolves it after the agent reconnects for a confirmation period.
//
// It is a SEPARATE stream from the metric-threshold rule/incident engine — it
// never touches the alerts/incidents tables and never enters incident merging.
// Liveness is measured from the live connected-session set the worker passes in
// each tick (monotonic durations, so a wall-clock jump can't manufacture offline
// time), not from agents.status, so there is no ordering race with the offline
// sweeper. Grace is measured from the first tick an agent is observed absent, so
// after a server restart no alert can open before roughly startup + grace — well
// after every agent's reconnect backoff — which prevents a mass false-offline
// wave. Notifications for opens and recoveries are buffered briefly and merged so
// one LAN outage produces one notification rather than a burst.
package agentalert

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// notifyBatchDelay is how long the engine buffers pending open/recovery notices
// before flushing them merged. A switch/LAN outage is detected across a 0-20s
// spread (15s ping interval + write failures), so a short buffer collapses it to
// one notification while adding bounded latency.
const notifyBatchDelay = 15 * time.Second

const defaultSeverity = "warn"

// Notifier is the notification surface the engine dispatches through (satisfied
// by *notification.Service). An interface so tests can capture payloads.
type Notifier interface {
	Notify(ctx context.Context, channelIDs []string, p notification.Payload)
}

// Engine owns the offline/recovery state machine. Its persistent state is the
// agent_alerts table; its in-memory state is the per-agent absent/connected
// clocks and the pending-notification buffer, all guarded by mu.
type Engine struct {
	db    *store.DB
	set   *settings.Service
	notif Notifier      // nil-safe: no notifications dispatched
	bus   *eventbus.Bus // nil-safe: no SSE bridge events published
	now   func() time.Time

	mu             sync.Mutex
	absentSince    map[string]time.Time // agentID -> first tick observed absent (cleared when connected)
	connectedSince map[string]time.Time // agentID -> first tick observed connected (cleared when absent)
	pending        []pendingNotice
	pendingSince   time.Time
}

// New constructs the engine. set/notif/bus may be nil (tests / degraded modes).
func New(db *store.DB, set *settings.Service, notif Notifier, bus *eventbus.Bus) *Engine {
	return &Engine{
		db:             db,
		set:            set,
		notif:          notif,
		bus:            bus,
		now:            time.Now,
		absentSince:    map[string]time.Time{},
		connectedSince: map[string]time.Time{},
	}
}

// Alert is the JSON DTO returned by the console list endpoint.
type Alert struct {
	ID               string     `json:"id"`
	SiteID           string     `json:"site_id"`
	AgentID          string     `json:"agent_id"`
	Status           string     `json:"status"` // firing | resolved
	Reason           string     `json:"reason"` // unexpected | clean_shutdown | version_incompatible
	Severity         string     `json:"severity"`
	AgentDisplayName string     `json:"agent_display_name"`
	AgentHostname    string     `json:"agent_hostname"`
	OfflineSince     time.Time  `json:"offline_since"`
	OpenedAt         time.Time  `json:"opened_at"`
	ResolvedAt       *time.Time `json:"resolved_at"`
	ResolveReason    string     `json:"resolve_reason,omitempty"`
}

// agentRow is the per-agent state Tick needs.
type agentRow struct {
	id          string
	siteID      string
	displayName string
	hostname    string
	lastSeenAt  sql.NullTime
	firstConnAt sql.NullTime
	muted       bool
	disconnKind string
}

// firingRow identifies an already-open alert and carries the severity + channel
// selection frozen when it opened, so a recovery notification routes exactly like
// the offline notification did even if the settings changed meanwhile.
type firingRow struct {
	id         string
	siteID     string
	severity   string
	channelIDs []string
}

// pendingNotice is one buffered open/recovery to merge into a notification.
type pendingNotice struct {
	event      string // agent.offline | agent.recovered
	siteID     string
	severity   string
	channelIDs []string
	agent      notification.AgentDetail
}

// Tick advances the state machine once. connectedIDs is the live connected set
// (hub.ConnectedIDs()), exactly as the offline sweeper receives it. It opens,
// resolves, publishes bus events, and flushes due notifications.
func (e *Engine) Tick(ctx context.Context, connectedIDs []string) error {
	now := e.now()
	enabled := e.set == nil || e.set.Bool(ctx, settings.KeyAgentAlertEnabled)
	graceSec, _ := e.set.Int(ctx, settings.KeyAgentAlertGraceSeconds)
	recoverSec, _ := e.set.Int(ctx, settings.KeyAgentAlertRecoverSeconds)
	grace := time.Duration(graceSec) * time.Second
	recover := time.Duration(recoverSec) * time.Second

	connected := make(map[string]bool, len(connectedIDs))
	for _, id := range connectedIDs {
		connected[id] = true
	}

	agents, err := e.loadAgents(ctx)
	if err != nil {
		return err
	}
	firing, err := e.loadFiring(ctx)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	changedSites := map[string]bool{}

	// Globally disabled: close every firing alert (no notification) so the switch
	// does not leave zombies firing forever, and stop. Any notices buffered before
	// the switch are dropped — disabled means no delivery.
	if !enabled {
		for agentID, row := range firing {
			if e.resolve(ctx, row.id, "disabled", now) {
				changedSites[row.siteID] = true
			}
			delete(e.absentSince, agentID)
			delete(e.connectedSince, agentID)
		}
		e.pending = nil
		e.pendingSince = time.Time{}
		e.publishChanges(changedSites)
		return nil
	}

	sev := e.severity(ctx)
	channels := e.channelIDs(ctx)

	seen := make(map[string]bool, len(agents))
	for _, a := range agents {
		seen[a.id] = true
		isConnected := connected[a.id]

		// Maintain the monotonic absent/connected clocks.
		if isConnected {
			delete(e.absentSince, a.id)
			if _, ok := e.connectedSince[a.id]; !ok {
				e.connectedSince[a.id] = now
			}
		} else {
			delete(e.connectedSince, a.id)
			if _, ok := e.absentSince[a.id]; !ok {
				e.absentSince[a.id] = now
			}
		}

		row, hasFiring := firing[a.id]

		// Muted: close any firing alert as 'muted' with no notification, and skip
		// the state machine entirely (the user-deactivated semantic). Drop any
		// notice still buffered for this agent so a mute inside the batch window
		// cannot flush a late offline/recovery notification.
		if a.muted {
			if hasFiring && e.resolve(ctx, row.id, "muted", now) {
				changedSites[a.siteID] = true
			}
			e.dropPending(a.id)
			continue
		}

		// Never connected: nothing was lost, so no offline alert.
		if !a.firstConnAt.Valid {
			continue
		}

		if isConnected {
			// Recovery requires a sustained connection, not a single late packet.
			// Route the recovery notice through the severity + channels frozen on the
			// firing alert, so it reaches the same recipients as the offline notice
			// even if the settings changed while the agent was down.
			if hasFiring && now.Sub(e.connectedSince[a.id]) >= recover {
				if e.resolve(ctx, row.id, "recovered", now) {
					changedSites[a.siteID] = true
					e.queue("agent.recovered", a, row.severity, row.channelIDs, now)
				}
			}
			continue
		}

		// Absent past grace with no firing alert: open exactly one.
		if !hasFiring && now.Sub(e.absentSince[a.id]) >= grace {
			if _, ok := e.open(ctx, a, sev, channels, now); ok {
				changedSites[a.siteID] = true
				e.queue("agent.offline", a, sev, channels, now)
			}
		}
	}

	// Prune clocks for agents that no longer exist (deleted).
	for id := range e.absentSince {
		if !seen[id] {
			delete(e.absentSince, id)
		}
	}
	for id := range e.connectedSince {
		if !seen[id] {
			delete(e.connectedSince, id)
		}
	}

	e.publishChanges(changedSites)
	e.flush(ctx, now)
	return nil
}

// OnMuteChanged is the API mute hook. Muting closes any firing alert as 'muted'
// with no notification; unmuting does nothing here (the next tick reopens if the
// agent is still offline past grace). Serialized with Tick through mu.
func (e *Engine) OnMuteChanged(ctx context.Context, agentID string, muted bool) {
	if !muted {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var id, siteID string
	err := e.db.QueryRowContext(ctx,
		`SELECT id, site_id FROM agent_alerts WHERE agent_id=? AND status='firing'`, agentID).Scan(&id, &siteID)
	if err != nil {
		return // no firing alert (sql.ErrNoRows) or transient error: nothing to do
	}
	if e.resolve(ctx, id, "muted", e.now()) {
		e.publishChanges(map[string]bool{siteID: true})
	}
	// Drop any notice still buffered for this agent: muting must never notify, even
	// if the offline alert opened moments ago and is still inside the batch window.
	e.dropPending(agentID)
}

// dropPending removes every buffered notice for an agent, used by the mute paths
// (tick + API) so a mute inside the 15s batch window cannot flush a late
// offline/recovery notification. Caller holds e.mu.
func (e *Engine) dropPending(agentID string) {
	if len(e.pending) == 0 {
		return
	}
	kept := e.pending[:0]
	for _, n := range e.pending {
		if n.agent.AgentID != agentID {
			kept = append(kept, n)
		}
	}
	e.pending = kept
}

// open inserts a firing alert for an offline agent, freezing its display fields,
// severity, channel selection, and offline_since. Returns (id, true) on insert;
// (,"" false) if the partial unique index rejected a concurrent duplicate.
func (e *Engine) open(ctx context.Context, a agentRow, severity string, channels []string, now time.Time) (string, bool) {
	id := "aa_" + uuid.NewString()
	offlineSince := now
	if a.lastSeenAt.Valid {
		offlineSince = a.lastSeenAt.Time
	}
	chJSON, _ := json.Marshal(channels)
	_, err := e.db.ExecContext(ctx, `
		INSERT INTO agent_alerts(id, site_id, agent_id, status, reason, severity,
		                         agent_display_name, agent_hostname, channel_ids, offline_since, opened_at)
		VALUES(?,?,?, 'firing', ?, ?, ?, ?, ?, ?, ?)`,
		id, a.siteID, a.id, reasonFor(a.disconnKind), severity,
		a.displayName, a.hostname, string(chJSON), offlineSince, now)
	if err != nil {
		return "", false
	}
	return id, true
}

// resolve closes a firing alert with the given reason, acting only when a firing
// row is still present (conditional UPDATE), so the API mute path and the tick
// can never double-resolve or double-notify. Returns whether a row changed.
func (e *Engine) resolve(ctx context.Context, id, reason string, now time.Time) bool {
	res, err := e.db.ExecContext(ctx,
		`UPDATE agent_alerts SET status='resolved', resolve_reason=?, resolved_at=? WHERE id=? AND status='firing'`,
		reason, now, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (e *Engine) queue(event string, a agentRow, severity string, channels []string, now time.Time) {
	if len(e.pending) == 0 {
		e.pendingSince = now
	}
	name := a.displayName
	if name == "" {
		name = a.hostname
	}
	if name == "" {
		name = a.id
	}
	det := notification.AgentDetail{AgentID: a.id, Name: name}
	if a.lastSeenAt.Valid {
		det.LastSeenAt = a.lastSeenAt.Time
	}
	if event == "agent.offline" {
		det.Reason = reasonFor(a.disconnKind)
	}
	e.pending = append(e.pending, pendingNotice{
		event: event, siteID: a.siteID, severity: severity, channelIDs: channels, agent: det,
	})
}

// flush dispatches merged notifications once the oldest pending notice has aged
// past notifyBatchDelay, grouping by (event, site, severity, channels).
func (e *Engine) flush(ctx context.Context, now time.Time) {
	if len(e.pending) == 0 || now.Sub(e.pendingSince) < notifyBatchDelay {
		return
	}
	type group struct {
		event    string
		siteID   string
		severity string
		channels []string
		agents   []notification.AgentDetail
	}
	groups := map[string]*group{}
	for _, n := range e.pending {
		key := n.event + "|" + n.siteID + "|" + n.severity + "|" + strings.Join(n.channelIDs, ",")
		g := groups[key]
		if g == nil {
			g = &group{event: n.event, siteID: n.siteID, severity: n.severity, channels: n.channelIDs}
			groups[key] = g
		}
		g.agents = append(g.agents, n.agent)
	}
	url := e.consoleURL(ctx)
	for _, g := range groups {
		scope := "single"
		if len(g.agents) > 1 {
			scope = "site"
		}
		payload := notification.Payload{
			Event:      g.event,
			SiteID:     g.siteID,
			Severity:   g.severity,
			Scope:      scope,
			AgentCount: len(g.agents),
			Agents:     g.agents,
			URL:        url,
			At:         now,
		}
		if e.notif != nil {
			channels := g.channels
			go e.notif.Notify(context.WithoutCancel(ctx), channels, payload)
		}
	}
	e.pending = nil
	e.pendingSince = time.Time{}
}

func (e *Engine) publishChanges(sites map[string]bool) {
	if e.bus == nil {
		return
	}
	for siteID := range sites {
		e.bus.Publish(eventbus.TopicAgentAlertChanged, eventbus.AgentAlertChanged{SiteID: siteID})
	}
}

// ListAlerts returns connectivity alerts for the console. When agentID is set it
// scopes to that agent; otherwise to the site. status is firing | resolved | all
// (default firing). limit caps the rows (newest opened first).
func (e *Engine) ListAlerts(ctx context.Context, siteID, status, agentID string, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var where []string
	var args []any
	if agentID != "" {
		where = append(where, "agent_id=?")
		args = append(args, agentID)
	} else {
		where = append(where, "site_id=?")
		args = append(args, siteID)
	}
	switch status {
	case "resolved":
		where = append(where, "status='resolved'")
	case "all":
		// no status filter
	default:
		where = append(where, "status='firing'")
	}
	q := `SELECT id, site_id, agent_id, status, reason, severity,
	             COALESCE(agent_display_name,''), COALESCE(agent_hostname,''),
	             offline_since, opened_at, resolved_at, COALESCE(resolve_reason,'')
	      FROM agent_alerts WHERE ` + strings.Join(where, " AND ") + ` ORDER BY opened_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := e.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var resolvedAt sql.NullTime
		if err := rows.Scan(&a.ID, &a.SiteID, &a.AgentID, &a.Status, &a.Reason, &a.Severity,
			&a.AgentDisplayName, &a.AgentHostname, &a.OfflineSince, &a.OpenedAt, &resolvedAt, &a.ResolveReason); err != nil {
			return nil, err
		}
		if resolvedAt.Valid {
			t := resolvedAt.Time
			a.ResolvedAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (e *Engine) loadAgents(ctx context.Context) ([]agentRow, error) {
	rows, err := e.db.Read().QueryContext(ctx, `
		SELECT id, site_id, COALESCE(display_name,''), COALESCE(hostname,''),
		       last_seen_at, first_connected_at, connectivity_alerts_muted, COALESCE(last_disconnect_kind,'')
		FROM agents WHERE revoked=0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []agentRow
	for rows.Next() {
		var a agentRow
		var muted int
		if err := rows.Scan(&a.id, &a.siteID, &a.displayName, &a.hostname,
			&a.lastSeenAt, &a.firstConnAt, &muted, &a.disconnKind); err != nil {
			return nil, err
		}
		a.muted = muted != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

func (e *Engine) loadFiring(ctx context.Context) (map[string]firingRow, error) {
	rows, err := e.db.Read().QueryContext(ctx,
		`SELECT id, site_id, agent_id, severity, COALESCE(channel_ids,'[]') FROM agent_alerts WHERE status='firing'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]firingRow{}
	for rows.Next() {
		var id, siteID, agentID, severity, chJSON string
		if err := rows.Scan(&id, &siteID, &agentID, &severity, &chJSON); err != nil {
			return nil, err
		}
		var channels []string
		_ = json.Unmarshal([]byte(chJSON), &channels)
		out[agentID] = firingRow{id: id, siteID: siteID, severity: severity, channelIDs: channels}
	}
	return out, rows.Err()
}

func (e *Engine) severity(ctx context.Context) string {
	if e.set == nil {
		return defaultSeverity
	}
	v, _ := e.set.Get(ctx, settings.KeyAgentAlertSeverity)
	v = strings.TrimSpace(v)
	switch v {
	case "info", "warn", "error", "critical":
		return v
	default:
		return defaultSeverity
	}
}

// channelIDs returns the frozen channel selection (empty = all enabled channels,
// resolved by notification.Notify's fallback).
func (e *Engine) channelIDs(ctx context.Context) []string {
	if e.set == nil {
		return nil
	}
	v, _ := e.set.Get(ctx, settings.KeyAgentAlertChannelIDs)
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	var ids []string
	if json.Unmarshal([]byte(v), &ids) != nil {
		return nil
	}
	return ids
}

func (e *Engine) consoleURL(ctx context.Context) string {
	base := e.set.ConsoleBaseURL(ctx)
	if base == "" {
		return ""
	}
	return base + "/agents"
}

// reasonFor maps an agent's last disconnect kind to a connectivity-alert reason.
func reasonFor(disconnectKind string) string {
	switch disconnectKind {
	case "clean":
		return "clean_shutdown"
	case "unsupported_schema":
		return "version_incompatible"
	default:
		return "unexpected"
	}
}
