// Package agentalert is the Agent-liveness detector (AGENT-002): it confirms a
// fault when an agent stays offline past a configurable grace period and resolves
// it after the agent reconnects for a confirmation period.
//
// It owns the liveness STATE MACHINE only. The fault it produces goes through the
// same pipeline as every probe fault — a fault signal, its own incident, and a
// notification planned by the notification policy — so the fault centre is
// complete, the tray count matches it, and there is exactly one place that
// decides whether anything is sent.
//
// Liveness is measured from the live connected-session set the worker passes in
// each tick (monotonic durations, so a wall-clock jump cannot manufacture offline
// time), not from agents.status, so there is no ordering race with the offline
// sweeper. Grace is measured from the first tick an agent is observed absent, so
// after a server restart no fault can open before roughly startup + grace — well
// after every agent's reconnect backoff — which prevents a mass false-offline
// wave.
package agentalert

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// FaultRecorder is the fault-engine surface this detector writes through
// (satisfied by *fault.Service). An interface so tests can observe the calls
// without a database.
type FaultRecorder interface {
	OpenAgentSignal(ctx context.Context, in fault.AgentSignalInput, now time.Time) (string, error)
	ResolveAgentSignal(ctx context.Context, agentID, reason string, now time.Time) error
	FiringAgentSignals(ctx context.Context) (map[string]string, error)
}

// Engine owns the offline/recovery state machine. Its persistent state is the
// fault_signals table (through the recorder); its in-memory state is the
// per-agent absent/connected clocks, guarded by mu.
type Engine struct {
	db     *store.DB
	set    *settings.Service
	faults FaultRecorder // nil-safe: the state machine then records nothing
	bus    *eventbus.Bus // nil-safe: no SSE bridge events published
	now    func() time.Time

	mu             sync.Mutex
	absentSince    map[string]time.Time // agentID -> first tick observed absent (cleared when connected)
	connectedSince map[string]time.Time // agentID -> first tick observed connected (cleared when absent)
}

// New constructs the engine. set/faults/bus may be nil (tests / degraded modes).
func New(db *store.DB, set *settings.Service, faults FaultRecorder, bus *eventbus.Bus) *Engine {
	return &Engine{
		db:             db,
		set:            set,
		faults:         faults,
		bus:            bus,
		now:            time.Now,
		absentSince:    map[string]time.Time{},
		connectedSince: map[string]time.Time{},
	}
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

// Tick advances the state machine once. connectedIDs is the live connected set
// (hub.ConnectedIDs()), exactly as the offline sweeper receives it.
func (e *Engine) Tick(ctx context.Context, connectedIDs []string) error {
	if e.faults == nil {
		return nil
	}
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
	firing, err := e.faults.FiringAgentSignals(ctx)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	changedSites := map[string]bool{}

	// Globally disabled: end every firing fault (reason 'disabled', so it is not
	// announced as a recovery) so the switch does not leave zombies firing forever,
	// and stop.
	if !enabled {
		for _, a := range agents {
			if _, ok := firing[a.id]; !ok {
				continue
			}
			if err := e.faults.ResolveAgentSignal(ctx, a.id, fault.ReasonDisabled, now); err != nil {
				return err
			}
			changedSites[a.siteID] = true
			delete(e.absentSince, a.id)
			delete(e.connectedSince, a.id)
		}
		e.publishChanges(changedSites)
		return nil
	}

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

		_, hasFiring := firing[a.id]

		// Muted: end any firing fault as 'muted' (silently — the operator turned the
		// detector off, the agent did not come back) and skip the state machine.
		if a.muted {
			if hasFiring {
				if err := e.faults.ResolveAgentSignal(ctx, a.id, fault.ReasonMuted, now); err != nil {
					return err
				}
				changedSites[a.siteID] = true
			}
			continue
		}

		// Never connected: nothing was lost, so no offline fault.
		if !a.firstConnAt.Valid {
			continue
		}

		if isConnected {
			// Recovery requires a sustained connection, not a single late packet.
			if hasFiring && now.Sub(e.connectedSince[a.id]) >= recover {
				if err := e.faults.ResolveAgentSignal(ctx, a.id, fault.ReasonRecovered, now); err != nil {
					return err
				}
				changedSites[a.siteID] = true
			}
			continue
		}

		// Absent past grace with no firing fault: confirm exactly one.
		if !hasFiring && now.Sub(e.absentSince[a.id]) >= grace {
			id, err := e.faults.OpenAgentSignal(ctx, fault.AgentSignalInput{
				AgentID:      a.id,
				SiteID:       a.siteID,
				Name:         a.label(),
				Reason:       reasonFor(a.disconnKind),
				OfflineSince: a.offlineSince(now),
			}, now)
			if err != nil {
				return err
			}
			if id != "" {
				changedSites[a.siteID] = true
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
	return nil
}

// OnMuteChanged is the API mute hook. Muting ends any firing fault as 'muted'
// with no notification; unmuting does nothing here (the next tick reopens if the
// agent is still offline past grace). Serialized with Tick through mu.
func (e *Engine) OnMuteChanged(ctx context.Context, agentID string, muted bool) {
	if !muted || e.faults == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var siteID string
	if err := e.db.QueryRowContext(ctx, `SELECT site_id FROM agents WHERE id=?`, agentID).Scan(&siteID); err != nil {
		return
	}
	if err := e.faults.ResolveAgentSignal(ctx, agentID, fault.ReasonMuted, e.now()); err != nil {
		return
	}
	e.publishChanges(map[string]bool{siteID: true})
}

func (e *Engine) publishChanges(sites map[string]bool) {
	if e.bus == nil {
		return
	}
	for siteID := range sites {
		e.bus.Publish(eventbus.TopicAgentAlertChanged, eventbus.AgentAlertChanged{SiteID: siteID})
	}
}

// label is the agent's frozen display label: display name, else hostname, else
// id — resolved here so the recorded fault keeps the name that was true when it
// happened.
func (a agentRow) label() string {
	if a.displayName != "" {
		return a.displayName
	}
	if a.hostname != "" {
		return a.hostname
	}
	return a.id
}

// offlineSince is when the agent was last seen, used as the fault's observed_at
// so its duration counts from the actual loss rather than from grace expiry.
func (a agentRow) offlineSince(now time.Time) time.Time {
	if a.lastSeenAt.Valid {
		return a.lastSeenAt.Time
	}
	return now
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

// reasonFor maps an agent's last disconnect kind to a connectivity fault reason.
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
