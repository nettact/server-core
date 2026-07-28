package notifypolicy

import (
	"context"
	"database/sql"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/notification"
)

// Delivery is one planned or completed notification, surfaced on the incident
// detail so an operator can see exactly what was sent, to where, and when — or
// why nothing was.
type Delivery struct {
	ID          string     `json:"id"`
	IncidentID  string     `json:"incident_id"`
	EventKind   string     `json:"event_kind"`
	ChannelID   string     `json:"channel_id"`
	ChannelName string     `json:"channel_name,omitempty"`
	PolicyID    string     `json:"policy_id,omitempty"`
	Status      string     `json:"status"`
	DueAt       time.Time  `json:"due_at"`
	SentAt      *time.Time `json:"sent_at,omitempty"`
}

const (
	eventOpened   = "incident.opened"
	eventResolved = "incident.resolved"

	statusPending  = "pending"
	statusSent     = "sent"
	statusCanceled = "canceled"
)

// PlanOpenTx schedules the open notification for a newly-opened incident, inside
// the fault engine's transaction, so the plan and the fault it describes commit
// together. Nothing is planned when no policy matches, the incident's severity is
// below the policy floor, or the policy has no channels — all legal states in
// which the fault is still fully recorded.
//
// The routing is FROZEN onto the delivery rows here. An incident that merges more
// members later keeps the channel set its first member resolved, so the recipient
// list cannot silently change halfway through an incident's life, and a policy
// edited or deleted mid-incident cannot orphan a pending notification.
func (s *Service) PlanOpenTx(ctx context.Context, tx *sql.Tx, sc fault.IncidentScope, now time.Time) error {
	eff, err := s.Resolve(ctx, sc.SiteID, sc.GroupID)
	if err != nil {
		return err
	}
	if eff.Policy == nil || !eff.Policy.Covers(sc.Severity) || len(eff.Policy.ChannelIDs) == 0 {
		return nil
	}
	due := now.Add(eff.Policy.Delay(sc.Severity))
	return insertDeliveries(ctx, tx, sc.IncidentID, sc.SiteID, eventOpened, *eff.Policy, due, now)
}

// EscalateTx reacts to a merged incident's severity rising. A pending open
// notification is pulled earlier to the higher severity's delay (never later),
// and one the previous severity was below the floor for is planned now.
//
// It deliberately does NOT re-notify a channel that was already sent to: an
// incident growing worse while someone is already looking at it is not worth a
// second message, and the incident's own severity is live in the console.
func (s *Service) EscalateTx(ctx context.Context, tx *sql.Tx, sc fault.IncidentScope, now time.Time) error {
	eff, err := s.Resolve(ctx, sc.SiteID, sc.GroupID)
	if err != nil {
		return err
	}
	if eff.Policy == nil || !eff.Policy.Covers(sc.Severity) || len(eff.Policy.ChannelIDs) == 0 {
		return nil
	}
	due := now.Add(eff.Policy.Delay(sc.Severity))
	if _, err := tx.ExecContext(ctx, `
		UPDATE notification_deliveries SET due_at=MIN(due_at, ?)
		WHERE incident_id=? AND event_kind=? AND status=?`,
		due, sc.IncidentID, eventOpened, statusPending); err != nil {
		return err
	}
	// INSERT OR IGNORE covers both cases: channels already planned keep the row the
	// UPDATE above just tightened, channels the lower severity skipped get one now.
	return insertDeliveries(ctx, tx, sc.IncidentID, sc.SiteID, eventOpened, *eff.Policy, due, now)
}

// ResolveTx closes out an incident's notifications, inside the fault engine's
// transaction:
//
//   - anything still pending is canceled — a fault that recovered inside its
//     notification delay is recorded in full but never announced, which is the
//     whole point of the delay;
//   - a recovery notice is planned ONLY for channels that actually received the
//     open notice, so no channel ever gets a lone "recovered" for a fault it
//     never heard about;
//   - a non-recovery ending (target deleted, disabled, reconfigured, agent
//     removed) plans nothing at all: the fault did not come back, it stopped
//     being observable, and saying "recovered" would be false.
func (s *Service) ResolveTx(ctx context.Context, tx *sql.Tx, incidentID, reason string, now time.Time) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE notification_deliveries SET status=? WHERE incident_id=? AND status=?`,
		statusCanceled, incidentID, statusPending); err != nil {
		return err
	}
	if !fault.IsRecovery(reason) {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT channel_id, policy_id FROM notification_deliveries
		WHERE incident_id=? AND event_kind=? AND status=? AND recovery_enabled=1`,
		incidentID, eventOpened, statusSent)
	if err != nil {
		return err
	}
	type pair struct{ channelID, policyID string }
	var sent []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.channelID, &p.policyID); err != nil {
			rows.Close()
			return err
		}
		sent = append(sent, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(sent) == 0 {
		return nil
	}
	var siteID string
	if err := tx.QueryRowContext(ctx, `SELECT site_id FROM incidents WHERE id=?`, incidentID).Scan(&siteID); err != nil {
		return err
	}
	for _, p := range sent {
		if err := insertDelivery(ctx, tx, incidentID, siteID, eventResolved, p.channelID, p.policyID, true, now, now); err != nil {
			return err
		}
	}
	return nil
}

func insertDeliveries(ctx context.Context, tx *sql.Tx, incidentID, siteID, event string, p Policy, due, now time.Time) error {
	for _, ch := range p.ChannelIDs {
		if ch == "" {
			continue
		}
		if err := insertDelivery(ctx, tx, incidentID, siteID, event, ch, p.ID, p.NotifyRecovery, due, now); err != nil {
			return err
		}
	}
	return nil
}

// insertDelivery writes one planned delivery. INSERT OR IGNORE against the
// (incident, event, channel) UNIQUE constraint is the idempotency guarantee: a
// replayed event, a reconnect or a restart can re-plan freely and still deliver
// at most once.
func insertDelivery(ctx context.Context, tx *sql.Tx, incidentID, siteID, event, channelID, policyID string, recovery bool, due, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO notification_deliveries(id, incident_id, site_id, event_kind, channel_id,
		    policy_id, recovery_enabled, status, due_at, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"nd_"+uuid.NewString(), incidentID, siteID, event, channelID, policyID,
		boolInt(recovery), statusPending, due, now)
	return err
}

// ---- worker ----

// deliverBatch bounds how many notifications one tick sends, so a burst cannot
// monopolize the worker.
const deliverBatch = 100

// dispatchTimeout bounds one claimed group's delivery. It exists so a shutdown
// that races a claim still finishes the send instead of dropping it, without
// letting an unresponsive channel hold shutdown open indefinitely.
const dispatchTimeout = 30 * time.Second

// dueDelivery is one row the worker picked up this tick.
type dueDelivery struct{ id, incidentID, siteID, event, channelID string }

// Tick sends every delivery whose delay has expired. Called on a short interval
// by the server's worker loop.
//
// Restart recovery needs no separate path: due_at is an absolute time, so a
// server that was down when a delay expired simply finds the row overdue on its
// first tick and sends it, and a clock change can neither duplicate a send nor
// produce a negative wait.
func (s *Service) Tick(ctx context.Context) error {
	now := time.Now().UTC()
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, incident_id, site_id, event_kind, channel_id
		FROM notification_deliveries
		WHERE status=? AND due_at<=? ORDER BY due_at LIMIT ?`, statusPending, now, deliverBatch)
	if err != nil {
		return err
	}

	var pending []dueDelivery
	for rows.Next() {
		var d dueDelivery
		if err := rows.Scan(&d.id, &d.incidentID, &d.siteID, &d.event, &d.channelID); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}

	// Group by (incident, event) so one incident reaching several channels is
	// rendered once and dispatched to all of them.
	type key struct{ incidentID, event string }
	order := []key{}
	byKey := map[key][]dueDelivery{}
	for _, d := range pending {
		k := key{d.incidentID, d.event}
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], d)
	}

	for _, k := range order {
		group := byKey[k]
		// An incident that resolved while its open notice was still waiting must not
		// announce a fault that is already over. The recovery notice is planned by
		// ResolveTx, not resurrected here.
		if k.event == eventOpened {
			var state string
			if err := s.db.Read().QueryRowContext(ctx,
				`SELECT state FROM incidents WHERE id=?`, k.incidentID).Scan(&state); err != nil || state != "open" {
				s.markStatus(ctx, group, statusCanceled, now)
				continue
			}
		}
		// Everything that can fail without having sent anything happens BEFORE the
		// claim. Building the payload after claiming would mark a row sent that was
		// never even attempted — and worse, ResolveTx treats a sent open row as
		// "this channel heard about the fault", so it would later be given a recovery
		// notice for something it never received.
		payload, ok := s.buildPayload(ctx, k.incidentID, k.event)
		if !ok {
			continue // left pending; the next tick retries
		}
		// Claim, then send. A crash between the two loses one notification, whereas
		// claiming after sending would let a restart re-send one that already
		// arrived. Duplicate alarms erode trust in every future alarm, so at-most-once
		// is the right side to fail on. Retry/backoff is NOTIFY-001.
		claimed := s.claim(ctx, group, now)
		if len(claimed) == 0 {
			continue
		}
		if s.notif != nil {
			// Detached from the caller's context: a graceful shutdown cancels the tick
			// loop while a claim is already committed, and letting that cancellation
			// abort the HTTP request would drop the notification for good — the row is
			// marked sent, so no later tick or restart retries it. The deadline keeps
			// shutdown bounded (the channel transports have their own shorter timeouts).
			sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dispatchTimeout)
			s.notif.Notify(sendCtx, claimed, payload)
			cancel()
		}
	}
	return nil
}

// claim marks a group of deliveries sent and returns the channel ids that were
// actually claimed (a row another tick already took is skipped).
func (s *Service) claim(ctx context.Context, group []dueDelivery, now time.Time) []string {
	out := make([]string, 0, len(group))
	for _, d := range group {
		res, err := s.db.ExecContext(ctx,
			`UPDATE notification_deliveries SET status=?, sent_at=? WHERE id=? AND status=?`,
			statusSent, now, d.id, statusPending)
		if err != nil {
			log.Printf("notifypolicy: claim %s: %v", d.id, err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			out = append(out, d.channelID)
		}
	}
	return out
}

// markStatus moves a group of deliveries to a terminal status without sending.
func (s *Service) markStatus(ctx context.Context, group []dueDelivery, status string, now time.Time) {
	for _, d := range group {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE notification_deliveries SET status=? WHERE id=? AND status=?`,
			status, d.id, statusPending); err != nil {
			log.Printf("notifypolicy: mark %s %s: %v", d.id, status, err)
		}
	}
}

// buildPayload assembles the notification for an incident event from the
// incident and its fault signals. An Agent-connectivity incident (open_key
// "agent:…") is rendered through the agent wording; everything else through the
// per-target fault wording.
func (s *Service) buildPayload(ctx context.Context, incidentID, event string) (notification.Payload, bool) {
	var siteID, severity, suspected, groupName, openKey, state string
	if err := s.db.Read().QueryRowContext(ctx, `
		SELECT site_id, severity, COALESCE(suspected_layer,''), COALESCE(group_name,''),
		       COALESCE(open_key,''), state
		FROM incidents WHERE id=?`, incidentID).
		Scan(&siteID, &severity, &suspected, &groupName, &openKey, &state); err != nil {
		return notification.Payload{}, false
	}
	p := notification.Payload{
		Event:          event,
		IncidentID:     incidentID,
		SiteID:         siteID,
		State:          state,
		Severity:       severity,
		SuspectedLayer: suspected,
		GroupName:      groupName,
		GroupMerged:    strings.HasPrefix(openKey, "grp:"),
		URL:            s.incidentURL(ctx, incidentID),
		At:             time.Now().UTC(),
	}
	if strings.HasPrefix(openKey, "agent:") {
		p.Event = "agent.offline"
		if event == eventResolved {
			p.Event = "agent.recovered"
		}
		p.Agents = s.agentDetails(ctx, incidentID)
		p.AgentCount = len(p.Agents)
		p.Scope = "single"
		return p, true
	}

	agents := map[string]bool{}
	switch event {
	case eventResolved:
		// The members have all resolved by now, so there is nothing "firing" to list.
		// Name what came back, scoped to the members that genuinely recovered.
		p.RecoveredTargets = s.recoveredTargets(ctx, incidentID)
		for _, d := range s.details(ctx, incidentID, "") {
			agents[d.AgentHost] = true
		}
	default:
		p.Details = s.details(ctx, incidentID, "firing")
		for _, d := range p.Details {
			agents[d.AgentHost] = true
		}
	}
	p.AgentCount = len(agents)
	p.Scope = "single"
	if len(agents) > 1 {
		p.Scope = "site"
	}
	return p, true
}

// details reads an incident's member facts in the renderer's shape. state ""
// includes every member.
func (s *Service) details(ctx context.Context, incidentID, state string) []notification.FaultDetail {
	q := `SELECT ` + fault.SignalDetailColumns() + ` FROM fault_signals WHERE incident_id=?`
	args := []any{incidentID}
	if state != "" {
		q += ` AND state=?`
		args = append(args, state)
	}
	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	out, err := fault.ScanDetails(rows)
	if err != nil {
		return nil
	}
	return out
}

// recoveredTargets lists the distinct targets of an incident's members that
// ended with a genuine recovery.
func (s *Service) recoveredTargets(ctx context.Context, incidentID string) []notification.RecoveredTarget {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT DISTINCT target_name, target_addr, probe_kind
		FROM fault_signals WHERE incident_id=? AND resolve_reason=?
		ORDER BY probe_kind, target_name, target_addr`, incidentID, fault.ReasonRecovered)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []notification.RecoveredTarget
	for rows.Next() {
		var rt notification.RecoveredTarget
		if err := rows.Scan(&rt.Name, &rt.Addr, &rt.ProbeKind); err != nil {
			continue
		}
		out = append(out, rt)
	}
	return out
}

// agentDetails reads the agent facts of an Agent-connectivity incident.
func (s *Service) agentDetails(ctx context.Context, incidentID string) []notification.AgentDetail {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT agent_id, COALESCE(agent_name,''), observed_at, COALESCE(reason_detail,'')
		FROM fault_signals WHERE incident_id=?`, incidentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []notification.AgentDetail
	for rows.Next() {
		var d notification.AgentDetail
		if err := rows.Scan(&d.AgentID, &d.Name, &d.LastSeenAt, &d.Reason); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out
}

func (s *Service) incidentURL(ctx context.Context, incidentID string) string {
	if s.set == nil {
		return ""
	}
	base := s.set.ConsoleBaseURL(ctx)
	if base == "" {
		return ""
	}
	return base + "/incidents?incident=" + url.QueryEscape(incidentID)
}

// ListForIncident returns an incident's notification records, so the console can
// show whether a fault was announced, is still waiting out its delay, or was
// deliberately not sent.
func (s *Service) ListForIncident(ctx context.Context, incidentID string) ([]Delivery, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT d.id, d.incident_id, d.event_kind, d.channel_id, COALESCE(c.name,''),
		       d.policy_id, d.status, d.due_at, d.sent_at
		FROM notification_deliveries d
		LEFT JOIN notification_channels c ON c.id = d.channel_id
		WHERE d.incident_id=? ORDER BY d.due_at, d.event_kind`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		var sentAt sql.NullTime
		if err := rows.Scan(&d.ID, &d.IncidentID, &d.EventKind, &d.ChannelID, &d.ChannelName,
			&d.PolicyID, &d.Status, &d.DueAt, &sentAt); err != nil {
			return nil, err
		}
		if sentAt.Valid {
			t := sentAt.Time.UTC()
			d.SentAt = &t
		}
		d.DueAt = d.DueAt.UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}
