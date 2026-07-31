package fault

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
)

// Agent connectivity is a built-in detector like any other, not a parallel
// alerting stream. An offline Agent produces a fault signal, an incident and a
// notification plan through exactly the same path a failing probe does, so the
// fault centre is complete, the tray count matches it, and there is only one
// notification pipeline to reason about.
//
// Its incident never merges with a monitor group's (open_key "agent:<id>"): an
// Agent going offline is not a member of any group's fault, and folding it in
// would let one Agent's outage silently absorb unrelated target faults.

// AgentSignalInput is the frozen identity of an Agent-connectivity fault.
type AgentSignalInput struct {
	AgentID string
	SiteID  string
	// Name is the Agent's display name (falling back to hostname, then id),
	// frozen so a later rename cannot rewrite history.
	Name string
	// Reason is the offline cause: unexpected | clean_shutdown |
	// version_incompatible.
	Reason string
	// OfflineSince is when the Agent was last seen; it becomes the fault's
	// observed_at, so the recorded duration counts from the actual loss rather
	// than from the moment the grace period expired.
	OfflineSince time.Time
}

// OpenAgentSignal confirms an Agent-connectivity fault in its own transaction,
// opening its dedicated incident and planning the notification. Returns the
// signal id, or "" when one is already firing for the Agent (the partial unique
// index makes a duplicate impossible, so this is simply idempotent).
func (s *Service) OpenAgentSignal(ctx context.Context, in AgentSignalInput, now time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var existing string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM fault_signals WHERE agent_id=? AND target_id='' AND detector_key=? AND state='firing'`,
		in.AgentID, DetectorAgentConnectivity).Scan(&existing)
	if err == nil {
		return "", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	signalID := "sig_" + uuid.NewString()
	observed := in.OfflineSince
	if observed.IsZero() {
		observed = now
	}
	sig := Signal{
		ID: signalID, SiteID: in.SiteID, AgentID: in.AgentID, AgentName: in.Name,
		DetectorKey: DetectorAgentConnectivity, Severity: SeverityCritical, Layer: "local",
		ReasonDetail: in.Reason, ObservedAt: observed.UTC(), ConfirmedAt: now,
	}
	incidentID, opened, _, err := findOrCreateIncident(ctx, tx,
		"agent:"+in.AgentID, in.SiteID, "", "", SignalTitle(sig), sig.Severity, sig.Layer, now)
	if err != nil {
		return "", err
	}
	sig.IncidentID = incidentID
	if err := insertSignal(ctx, tx, sig, 0); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE incidents SET severity=?, summary=? WHERE id=?`, sig.Severity, SignalTitle(sig), incidentID); err != nil {
		return "", err
	}
	out := &txOut{}
	addTimeline(ctx, tx, incidentID, "fault.confirmed", SignalTitle(sig), signalID, now)
	out.confirmed = append(out.confirmed, SignalEvent{
		SignalID: signalID, IncidentID: incidentID, SiteID: in.SiteID,
		AgentID: in.AgentID, Severity: sig.Severity,
	})
	if opened {
		// Same immutable base snapshot a target fault gets. Without it the
		// post-commit orchestrator only writes its empty-base fallback row, and an
		// offline-Agent incident loses the frozen identity its detail view shows.
		if s.snap != nil {
			if err := s.snap.WriteIncidentBase(ctx, tx, incidentID, now); err != nil {
				log.Printf("fault: incident base snapshot for %s: %v", incidentID, err)
			}
		}
		addTimeline(ctx, tx, incidentID, "incident.opened", "", incidentID, now)
		out.incidentOpened = append(out.incidentOpened, incidentEvent(incidentID, in.SiteID, "", sig.Severity, false))
		if s.planner != nil {
			if err := s.planner.PlanOpenTx(ctx, tx, IncidentScope{
				IncidentID: incidentID, SiteID: in.SiteID, Severity: sig.Severity,
				AgentConnectivity: true,
			}, now); err != nil {
				return "", err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	s.publish(out)
	return signalID, nil
}

// ResolveAgentSignal ends an Agent's firing connectivity fault with the given
// reason, in its own transaction. Only ReasonRecovered produces a recovery
// notification; ReasonMuted and ReasonDisabled end the fault silently, since the
// operator turned the detector off rather than the Agent coming back.
// Idempotent: resolving an absent signal is a no-op.
func (s *Service) ResolveAgentSignal(ctx context.Context, agentID, reason string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	var signalID string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM fault_signals WHERE agent_id=? AND target_id='' AND detector_key=? AND state='firing'`,
		agentID, DetectorAgentConnectivity).Scan(&signalID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	out := &txOut{}
	if err := s.resolveSignal(ctx, tx, signalID, reason, now, now, out); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	s.publish(out)
	return nil
}

// FiringAgentSignals returns the agent ids that currently have a firing
// connectivity fault, so the liveness state machine can tell open from closed
// without owning a table of its own.
func (s *Service) FiringAgentSignals(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT agent_id, id FROM fault_signals WHERE detector_key=? AND state='firing'`, DetectorAgentConnectivity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var agentID, id string
		if err := rows.Scan(&agentID, &id); err != nil {
			return nil, err
		}
		out[agentID] = id
	}
	return out, rows.Err()
}
