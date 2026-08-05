package notifypolicy

import (
	"context"
	"database/sql"
	"encoding/json"
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
	ID         string `json:"id"`
	IncidentID string `json:"incident_id,omitempty"`
	// StormID is set instead of IncidentID on the rows that announced a correlated
	// burst, so the console can say "told once, as part of a storm" rather than
	// leaving a member fault looking unannounced.
	StormID     string     `json:"storm_id,omitempty"`
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
	// Storm events announce a correlated burst instead of its members (ALERT-001).
	eventStormOpened   = "storm.opened"
	eventStormResolved = "storm.resolved"

	statusPending  = "pending"
	statusSent     = "sent"
	statusCanceled = "canceled"
)

// subject is what a delivery announces. Exactly one id is set: a delivery either
// speaks for one incident, or for the storm that swallowed a burst of them. The
// database enforces the same exclusivity, so a row can never claim both.
type subject struct {
	incidentID string
	stormID    string
}

func (s subject) isStorm() bool { return s.stormID != "" }

// id is the subject's identity for grouping and logging.
func (s subject) id() string {
	if s.isStorm() {
		return s.stormID
	}
	return s.incidentID
}

// cols returns the (incident_id, storm_id) column values, with the unused side
// NULL so the table's exclusivity CHECK and its two UNIQUE indexes behave.
func (s subject) cols() (any, any) {
	if s.isStorm() {
		return nil, s.stormID
	}
	return s.incidentID, nil
}

// queryFor is the one place the engine's scope becomes a policy lookup, so the
// open and escalate paths can never walk different chains for the same incident.
func queryFor(sc fault.IncidentScope) Query {
	return Query{SiteID: sc.SiteID, GroupID: sc.GroupID, AgentConnectivity: sc.AgentConnectivity}
}

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
// Storm correlation runs LAST, after the per-incident notice has been planned.
// Doing it that way keeps the overwhelmingly common no-storm path byte-for-byte
// what it was, and gives correlation the concrete routing it needs to move: the
// storm inherits the exact channels and due times the members had planned,
// rather than re-deriving them from a policy that may since have changed.
func (s *Service) PlanOpenTx(ctx context.Context, tx *sql.Tx, sc fault.IncidentScope, now time.Time) error {
	eff, err := s.Resolve(ctx, queryFor(sc))
	if err != nil {
		return err
	}
	if eff.Policy != nil && eff.Policy.Covers(sc.Severity) && len(eff.Policy.ChannelIDs) > 0 {
		due := now.Add(eff.Policy.Delay(sc.Severity))
		if err := insertDeliveries(ctx, tx, subject{incidentID: sc.IncidentID}, sc.SiteID,
			eventOpened, *eff.Policy, due, now); err != nil {
			return err
		}
	}
	return s.correlateStormTx(ctx, tx, sc, now)
}

// EscalateTx reacts to a merged incident's severity rising. A pending open
// notification is pulled earlier to the higher severity's delay (never later),
// and one the previous severity was below the floor for is planned now.
//
// It deliberately does NOT re-notify a channel that was already sent to: an
// incident growing worse while someone is already looking at it is not worth a
// second message, and the incident's own severity is live in the console.
func (s *Service) EscalateTx(ctx context.Context, tx *sql.Tx, sc fault.IncidentScope, now time.Time) error {
	eff, err := s.Resolve(ctx, queryFor(sc))
	if err != nil {
		return err
	}
	if eff.Policy != nil && eff.Policy.Covers(sc.Severity) && len(eff.Policy.ChannelIDs) > 0 {
		due := now.Add(eff.Policy.Delay(sc.Severity))
		if _, err := tx.ExecContext(ctx, `
			UPDATE notification_deliveries SET due_at=MIN(due_at, ?)
			WHERE incident_id=? AND event_kind=? AND status=?`,
			due, sc.IncidentID, eventOpened, statusPending); err != nil {
			return err
		}
		// INSERT OR IGNORE covers both cases: channels already planned keep the row the
		// UPDATE above just tightened, channels the lower severity skipped get one now.
		if err := insertDeliveries(ctx, tx, subject{incidentID: sc.IncidentID}, sc.SiteID,
			eventOpened, *eff.Policy, due, now); err != nil {
			return err
		}
	}
	// Correlation runs even when the policy routed NOTHING. An incident whose own
	// group has no policy, sits below the floor, or has no channels still raised
	// its severity, and its storm — announced through channels other members
	// contributed — has to hear about that or it will send a stale summary.
	// An escalating storm member also must not start announcing itself again:
	// correlation moves whatever was just (re)planned onto the storm.
	return s.correlateStormTx(ctx, tx, sc, now)
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
//     being observable, and saying "recovered" would be false;
//
// The "only channels that were told" rule is also what makes storms fall out for
// free: a channel whose open notice was swallowed by a storm has no sent row, so
// it gets no lone recovery here and is covered by the storm's one summary
// instead — while a channel that opted out of merging still gets its pair.
func (s *Service) ResolveTx(ctx context.Context, tx *sql.Tx, incidentID, reason string, now time.Time) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE notification_deliveries SET status=? WHERE incident_id=? AND status=?`,
		statusCanceled, incidentID, statusPending); err != nil {
		return err
	}
	// Advance the storm this incident belonged to (if any) before deciding the
	// per-incident recovery: the storm's own summary is planned there.
	if err := s.settleStormTx(ctx, tx, incidentID, now); err != nil {
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
		if err := insertDelivery(ctx, tx, subject{incidentID: incidentID}, siteID, eventResolved,
			p.channelID, p.policyID, true, now, now); err != nil {
			return err
		}
	}
	return nil
}

func insertDeliveries(ctx context.Context, tx *sql.Tx, sb subject, siteID, event string, p Policy, due, now time.Time) error {
	for _, ch := range p.ChannelIDs {
		if ch == "" {
			continue
		}
		if err := insertDelivery(ctx, tx, sb, siteID, event, ch, p.ID, p.NotifyRecovery, due, now); err != nil {
			return err
		}
	}
	return nil
}

// insertDelivery writes one planned delivery. INSERT OR IGNORE against the
// (subject, event, channel) UNIQUE constraint is the idempotency guarantee: a
// replayed event, a reconnect or a restart can re-plan freely and still deliver
// at most once.
func insertDelivery(ctx context.Context, tx *sql.Tx, sb subject, siteID, event, channelID, policyID string, recovery bool, due, now time.Time) error {
	incidentID, stormID := sb.cols()
	_, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO notification_deliveries(id, incident_id, storm_id, site_id, event_kind, channel_id,
		    policy_id, recovery_enabled, status, due_at, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		"nd_"+uuid.NewString(), incidentID, stormID, siteID, event, channelID, policyID,
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
type dueDelivery struct {
	id, siteID, event, channelID string
	subject                      subject
}

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
		SELECT id, COALESCE(incident_id,''), COALESCE(storm_id,''), site_id, event_kind, channel_id
		FROM notification_deliveries
		WHERE status=? AND due_at<=? ORDER BY due_at LIMIT ?`, statusPending, now, deliverBatch)
	if err != nil {
		return err
	}

	var pending []dueDelivery
	for rows.Next() {
		var d dueDelivery
		if err := rows.Scan(&d.id, &d.subject.incidentID, &d.subject.stormID,
			&d.siteID, &d.event, &d.channelID); err != nil {
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

	// Group by (subject, event) so one incident — or one storm standing in for a
	// burst of them — reaching several channels is rendered once and dispatched to
	// all of them.
	type key struct {
		subject subject
		event   string
	}
	order := []key{}
	byKey := map[key][]dueDelivery{}
	for _, d := range pending {
		k := key{d.subject, d.event}
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], d)
	}

	for _, k := range order {
		group := byKey[k]
		// A subject that ended while its open notice was still waiting must not
		// announce something that is already over. The recovery notice is planned by
		// ResolveTx / closeStormTx, not resurrected here.
		if k.event == eventOpened || k.event == eventStormOpened {
			if !s.subjectStillOpen(ctx, k.subject) {
				s.markStatus(ctx, group, statusCanceled, now)
				continue
			}
		}
		// Everything that can fail without having sent anything happens BEFORE the
		// claim. Building the payload after claiming would mark a row sent that was
		// never even attempted — and worse, ResolveTx treats a sent open row as
		// "this channel heard about the fault", so it would later be given a recovery
		// notice for something it never received.
		payload, ok := s.buildPayload(ctx, k.subject, k.event)
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

// subjectStillOpen reports whether the thing an open notice describes is in fact
// still ongoing.
func (s *Service) subjectStillOpen(ctx context.Context, sb subject) bool {
	q := `SELECT state FROM incidents WHERE id=?`
	if sb.isStorm() {
		q = `SELECT state FROM alert_storms WHERE id=?`
	}
	var state string
	err := s.db.Read().QueryRowContext(ctx, q, sb.id()).Scan(&state)
	return err == nil && state == "open"
}

// buildPayload assembles the notification for one subject's event.
func (s *Service) buildPayload(ctx context.Context, sb subject, event string) (notification.Payload, bool) {
	if sb.isStorm() {
		return s.buildStormPayload(ctx, sb.stormID, event)
	}
	return s.buildIncidentPayload(ctx, sb.incidentID, event)
}

// buildStormPayload assembles the notification for a correlated burst: the
// storm's own facts plus one line per monitor group it hit.
//
// The member incidents are read at SEND time rather than frozen when the storm
// formed, so a storm that grew while its notice waited out the delay describes
// what is actually broken now — which is the whole reason the notice is delayed.
func (s *Service) buildStormPayload(ctx context.Context, stormID, event string) (notification.Payload, bool) {
	var siteID, agentName, severity, suspected, state string
	var openedAt time.Time
	var resolvedAt sql.NullTime
	if err := s.db.Read().QueryRowContext(ctx, `
		SELECT site_id, COALESCE(agent_name,''), severity, COALESCE(suspected_layer,''),
		       state, opened_at, resolved_at
		FROM alert_storms WHERE id=?`, stormID).
		Scan(&siteID, &agentName, &severity, &suspected, &state, &openedAt, &resolvedAt); err != nil {
		return notification.Payload{}, false
	}
	p := notification.Payload{
		Event:          event,
		StormID:        stormID,
		SiteID:         siteID,
		State:          state,
		Severity:       severity,
		SuspectedLayer: suspected,
		// One Agent's vantage point by construction — a storm is never correlated
		// across agents — so the scope wording stays honest about that.
		Scope:      "single",
		AgentCount: 1,
		URL:        s.stormURL(ctx, stormID),
		At:         time.Now().UTC(),
	}
	detail := &notification.StormDetail{AgentName: agentName}
	if event == eventStormResolved {
		end := time.Now().UTC()
		if resolvedAt.Valid {
			end = resolvedAt.Time
		}
		if d := int(end.Sub(openedAt).Seconds()); d > 0 {
			detail.DurationS = d
		}
	}
	// Which members the notice may speak for:
	//
	//   open     — every member; the total is how many separate messages this one
	//              notice is replacing.
	//   resolved — ONLY members that genuinely recovered. A member whose target was
	//              deleted or reconfigured never came back, and counting it would
	//              make "N faults have all recovered" a false statement about
	//              something an operator may be relying on.
	member := stormMembersAll
	if event == eventStormResolved {
		member = stormMembersRecovered
	}
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incidents i WHERE i.storm_id=?`+member, stormID).Scan(&detail.FaultCount); err != nil {
		return notification.Payload{}, false
	}
	groups, err := s.stormGroups(ctx, stormID, member)
	if err != nil {
		return notification.Payload{}, false
	}
	detail.Groups = groups
	detail.GroupCount = len(groups)
	p.Storm = detail
	// A storm whose members all ended some other way has nothing true to say.
	// closeStormTx only plans a summary when at least one member recovered, so
	// this is a belt-and-braces guard against announcing an empty recovery.
	if event == eventStormResolved && detail.FaultCount == 0 {
		return notification.Payload{}, false
	}
	return p, true
}

// Member predicates for a storm's notice, correlated to an incidents row aliased
// i. Kept as constants so the count and the group list can never disagree about
// who the notice is speaking for.
const (
	// stormMembersAll is every member of the burst. An open storm speaks for all
	// of them — including any that recovered while the notice waited out its delay
	// — so its two numbers ("N faults across M groups") always describe the same
	// set rather than two subtly different ones.
	stormMembersAll = ``
	// stormMembersRecovered is what actually came back.
	//
	// It deliberately does NOT also exclude members that were announced
	// individually before the storm formed. "Was this already announced" is a
	// per-CHANNEL fact, and the summary is one message to many channels: a member
	// can have a sent individual notice to a channel that opted out of merging
	// while the merging channels only ever heard the storm. Excluding on that
	// basis silences the summary for everyone.
	stormMembersRecovered = ` AND i.resolve_reason='recovered'`
)

// stormGroups collapses the selected member incidents into one line per monitor
// group, keeping each group's worst severity.
func (s *Service) stormGroups(ctx context.Context, stormID, member string) ([]notification.StormGroup, error) {
	q := `SELECT COALESCE(i.group_id,''), COALESCE(i.group_name,''), i.severity, COALESCE(i.suspected_layer,'')
	      FROM incidents i WHERE i.storm_id=?` + member
	args := []any{stormID}
	q += ` ORDER BY i.opened_at`
	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byGroup := map[string]int{} // group key -> index into out
	var out []notification.StormGroup
	for rows.Next() {
		var groupID, groupName, sev, layer string
		if err := rows.Scan(&groupID, &groupName, &sev, &layer); err != nil {
			return nil, err
		}
		key := groupID + "\x00" + groupName
		if i, seen := byGroup[key]; seen {
			if severityRank[sev] > severityRank[out[i].Severity] {
				out[i].Severity = sev
			}
			continue
		}
		byGroup[key] = len(out)
		out = append(out, notification.StormGroup{Name: groupName, Severity: sev, Layer: layer})
	}
	return out, rows.Err()
}

// buildIncidentPayload assembles the notification for an incident event from the
// incident and its fault signals. An Agent-connectivity incident (open_key
// "agent:…") is rendered through the agent wording; everything else through the
// per-target fault wording.
func (s *Service) buildIncidentPayload(ctx context.Context, incidentID, event string) (notification.Payload, bool) {
	var siteID, severity, suspected, groupName, openKey, state, attribution, attrEv string
	if err := s.db.Read().QueryRowContext(ctx, `
		SELECT site_id, severity, COALESCE(suspected_layer,''), COALESCE(group_name,''),
		       COALESCE(open_key,''), state, COALESCE(attribution,''), COALESCE(attribution_evidence,'[]')
		FROM incidents WHERE id=?`, incidentID).
		Scan(&siteID, &severity, &suspected, &groupName, &openKey, &state, &attribution, &attrEv); err != nil {
		return notification.Payload{}, false
	}
	p := notification.Payload{
		Event:          event,
		IncidentID:     incidentID,
		SiteID:         siteID,
		State:          state,
		Severity:       severity,
		SuspectedLayer: suspected,
		Attribution:    attribution,
		GroupName:      groupName,
		GroupMerged:    strings.HasPrefix(openKey, "grp:"),
		URL:            s.incidentURL(ctx, incidentID),
		At:             time.Now().UTC(),
	}
	if p.Attribution != "" && attrEv != "" && attrEv != "[]" {
		var clues []notification.AttributionClue
		if json.Unmarshal([]byte(attrEv), &clues) == nil {
			p.AttributionEvidence = clues
		}
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
	return s.consoleLink(ctx, "incident", incidentID)
}

// stormURL deep-links into the fault centre filtered to the storm's members, so
// clicking a summary lands on exactly the faults it summarized.
func (s *Service) stormURL(ctx context.Context, stormID string) string {
	return s.consoleLink(ctx, "storm", stormID)
}

func (s *Service) consoleLink(ctx context.Context, param, id string) string {
	if s.set == nil {
		return ""
	}
	base := s.set.ConsoleBaseURL(ctx)
	if base == "" {
		return ""
	}
	return base + "/incidents?" + param + "=" + url.QueryEscape(id)
}

// ListForIncident returns an incident's notification records, so the console can
// show whether a fault was announced, is still waiting out its delay, or was
// deliberately not sent.
//
// It also returns the records of the STORM this incident belongs to, if any.
// Without them the detail panel of a correlated fault would show only canceled
// rows and read as "nobody was told" — when in fact everyone was told, once, as
// part of a summary. The storm rows carry storm_id so the console can label them
// differently from the incident's own.
func (s *Service) ListForIncident(ctx context.Context, incidentID string) ([]Delivery, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT d.id, COALESCE(d.incident_id,''), COALESCE(d.storm_id,''), d.event_kind,
		       d.channel_id, COALESCE(c.name,''), d.policy_id, d.status, d.due_at, d.sent_at
		FROM notification_deliveries d
		LEFT JOIN notification_channels c ON c.id = d.channel_id
		WHERE d.incident_id=?
		   OR d.storm_id = (SELECT storm_id FROM incidents WHERE id=? AND storm_id IS NOT NULL)
		ORDER BY d.due_at, d.event_kind`, incidentID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		var sentAt sql.NullTime
		if err := rows.Scan(&d.ID, &d.IncidentID, &d.StormID, &d.EventKind, &d.ChannelID, &d.ChannelName,
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
