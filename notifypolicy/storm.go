package notifypolicy

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/settings"
)

// Alert-storm correlation (ALERT-001).
//
// When an upstream link dies, every monitor group under one Agent breaches
// within seconds of the others. Each breach is a genuine, separately recorded
// incident — and each one would announce itself, so the operator gets N messages
// about ONE root cause and then N more on recovery. People respond to that by
// muting notifications, which costs them every future alarm too.
//
// A storm changes NOTHING about detection or the incident record. It is a
// correlation layer that decides only how many messages leave the building: one
// "N faults at once, likely at the <layer> layer" instead of N, and one summary
// recovery instead of N.
//
// Correlation is per (site, agent) because the agent is the vantage point the
// faults were observed from: "everything this agent can see broke at once" is
// the only claim the evidence actually supports. Cross-agent re-aggregation is
// deliberately not attempted.
//
// The whole lifecycle runs inside the fault engine's write transaction, so the
// storm and the incidents it owns commit together. That is what makes a restart
// mid-storm safe: the storm is re-read from alert_storms, and the recovery is
// still exactly one message.

// stormMemberChannel is one channel a joining incident contributes to its
// storm, carrying the routing that was frozen when the incident planned its own
// (now superseded) notice.
type stormMemberChannel struct {
	channelID string
	policyID  string
	recovery  bool
	due       time.Time
}

// correlateStormTx decides whether a freshly-opened incident belongs to a storm,
// and if so moves its announcement onto that storm. Called at the tail of
// PlanOpenTx, after the per-incident notice has been planned: the common case is
// no storm at all, so the normal path stays untouched and correlation only ever
// has to cancel and replace.
func (s *Service) correlateStormTx(ctx context.Context, tx *sql.Tx, sc fault.IncidentScope, now time.Time) error {
	// An incident that ALREADY belongs to a storm stays with that storm, whatever
	// agent this particular signal was observed from. A merge-enabled group's
	// incident collects signals from every agent in scope, so an escalation can
	// arrive carrying a different AgentID than the one whose storm owns the
	// incident — and routing its notices to that other agent's storm would split
	// one fault's announcements across two summaries.
	//
	// This runs before the threshold check on purpose: turning correlation off
	// must not strand a storm that is already running with members mid-flight.
	owner, err := stormOf(ctx, tx, sc.IncidentID)
	if err != nil {
		return err
	}
	if owner != "" {
		return s.joinStormTx(ctx, tx, owner, []string{sc.IncidentID}, now)
	}

	threshold, _ := s.set.Int(ctx, settings.KeyIncidentStormThreshold)
	// Threshold 0 is "off": every incident announces itself, exactly as before
	// this feature existed. An incident with no observing agent (there is no such
	// path today) cannot be correlated to a vantage point, so it is left alone.
	if threshold <= 0 || sc.AgentID == "" {
		return nil
	}

	var stormID string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM alert_storms WHERE site_id=? AND agent_id=? AND state='open'`,
		sc.SiteID, sc.AgentID).Scan(&stormID)
	switch {
	case err == nil:
		// A storm is already running for this vantage point. Everything new that
		// breaks under it is part of the same event until it clears.
		return s.joinStormTx(ctx, tx, stormID, []string{sc.IncidentID}, now)
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}

	windowSec, _ := s.set.Int(ctx, settings.KeyIncidentStormWindowSeconds)
	since := now.Add(-time.Duration(windowSec) * time.Second)
	members, err := unstormedOpenIncidents(ctx, tx, sc.SiteID, sc.AgentID, since)
	if err != nil {
		return err
	}
	// The count is of INCIDENTS, not of monitor groups: one incident is one
	// message, so five targets failing inside a single unmerged group is five
	// messages and deserves collapsing just as much as five groups do. The
	// rendered notice states both numbers, so nobody is misled about the spread.
	if len(members) < threshold {
		return nil
	}
	return s.openStormTx(ctx, tx, sc, members, now)
}

// stormOf returns the storm an incident belongs to, or "" when it belongs to
// none (including when the incident no longer exists).
func stormOf(ctx context.Context, tx *sql.Tx, incidentID string) (string, error) {
	var stormID string
	err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(storm_id,'') FROM incidents WHERE id=?`, incidentID).Scan(&stormID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return stormID, err
}

// unstormedOpenIncidents lists the site's open, not-yet-correlated incidents
// observed by one agent inside the correlation window, oldest first.
//
// The agent is derived from the incident's fault signals rather than stored on
// the incident: an incident's identity is its group, not the Agent that happened
// to see it first, and denormalizing a second answer to "whose incident is this"
// would eventually disagree with the signals.
func unstormedOpenIncidents(ctx context.Context, tx *sql.Tx, siteID, agentID string, since time.Time) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT i.id FROM incidents i
		WHERE i.site_id=? AND i.state='open' AND i.storm_id IS NULL AND i.opened_at>=?
		  AND EXISTS(SELECT 1 FROM fault_signals s WHERE s.incident_id=i.id AND s.agent_id=?)
		ORDER BY i.opened_at`, siteID, since, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// openStormTx creates the storm and folds every qualifying incident into it.
func (s *Service) openStormTx(ctx context.Context, tx *sql.Tx, sc fault.IncidentScope, members []string, now time.Time) error {
	stormID := "stm_" + uuid.NewString()
	name, err := frozenAgentName(ctx, tx, sc.SiteID, sc.AgentID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO alert_storms(id, site_id, agent_id, agent_name, state, severity, suspected_layer, opened_at)
		VALUES(?,?,?,?, 'open', ?, '', ?)`,
		stormID, sc.SiteID, sc.AgentID, name, fault.SeverityWarn, now); err != nil {
		return err
	}
	return s.joinStormTx(ctx, tx, stormID, members, now)
}

// mergingChannel is the predicate for "this delivery's channel wants storm
// summaries", correlated to a notification_deliveries row aliased d. A delivery
// whose channel row is gone defaults to merging, so it is canceled along with
// the rest instead of surviving as an orphan that still fires.
//
// One constant, used by both the SELECT that collects a member's channels and
// the UPDATE that cancels them: if those two predicates ever disagreed, a
// channel would either be silently dropped or notified twice.
const mergingChannel = `COALESCE((SELECT c.storm_merge FROM notification_channels c WHERE c.id=d.channel_id), 1)=1`

// joinStormTx attaches incidents to a storm and moves their announcements onto
// it: each member's own pending open notice is canceled, and the channels that
// notice would have reached are added to the storm's single notice.
//
// Two kinds of channel are left alone, and both keep their per-incident notice:
//
//   - a channel with merging turned off, which asked for one message per
//     incident (a ticketing webhook, a log sink) and would be made lossy by a
//     summary;
//   - a channel whose open notice was ALREADY SENT, which has heard about this
//     fault; repeating it inside a summary is the duplication a storm exists to
//     remove. Its later recovery notice is paired to that sent open notice by
//     the ordinary ResolveTx path.
//
// The incident joins the storm either way — membership is about how the console
// groups it and which faults the summary counts, not only about who was told.
func (s *Service) joinStormTx(ctx context.Context, tx *sql.Tx, stormID string, incidentIDs []string, now time.Time) error {
	var contributed []stormMemberChannel
	var siteID string
	for _, id := range incidentIDs {
		res, err := tx.ExecContext(ctx,
			`UPDATE incidents SET storm_id=? WHERE id=? AND storm_id IS NULL`, stormID, id)
		if err != nil {
			return err
		}
		// The timeline entry marks the moment of joining, so it is written once —
		// but the sweep below runs on EVERY call, including for an incident that was
		// already a member. An escalating member re-plans its open notice for
		// channels a lower severity had skipped, and those newly-planned rows have to
		// be moved onto the storm too. Skipping them would let one member announce
		// itself alone in the middle of a storm, reporting "1 fault" where the truth
		// is "4 at once".
		if n, _ := res.RowsAffected(); n > 0 {
			fault.AddTimelineTx(ctx, tx, id, "storm.joined", "", stormID, now)
		} else {
			// The update matched nothing: either this incident is already a member of
			// THIS storm (sweep it, as above) or it belongs to a different one. In the
			// latter case its notices are that storm's to move, and taking them here
			// would split one fault's announcements across two summaries.
			owner, err := stormOf(ctx, tx, id)
			if err != nil {
				return err
			}
			if owner != stormID {
				continue
			}
		}
		if err := tx.QueryRowContext(ctx, `SELECT site_id FROM incidents WHERE id=?`, id).Scan(&siteID); err != nil {
			return err
		}
		chans, err := pendingOpenChannels(ctx, tx, id)
		if err != nil {
			return err
		}
		if len(chans) == 0 {
			continue
		}
		contributed = append(contributed, chans...)
		if _, err := tx.ExecContext(ctx, `
			UPDATE notification_deliveries SET status=?
			WHERE id IN (SELECT d.id FROM notification_deliveries d
			             WHERE d.incident_id=? AND d.event_kind=? AND d.status=? AND `+mergingChannel+`)`,
			statusCanceled, id, eventOpened, statusPending); err != nil {
			return err
		}
	}

	if siteID != "" {
		for _, c := range contributed {
			if err := s.planStormOpen(ctx, tx, stormID, siteID, c, now); err != nil {
				return err
			}
		}
	}
	return recomputeStormTx(ctx, tx, stormID)
}

// planStormOpen adds one channel to the storm's open notice. due_at is pulled
// EARLIER but never later, so a member joining late cannot delay a storm that
// was already about to speak, and each channel still waits out the delay its own
// policy asked for.
//
// Escalation deliberately does not re-notify a channel that already received the
// storm notice, matching EscalateTx: an event growing worse while someone is
// already looking at it is not worth a second message, and the console shows the
// live severity.
//
// recovery_enabled is merged with MAX, not left at whatever the first
// contributing member happened to carry. One channel can be routed by several
// group policies with different notify_recovery settings, and the storm row is
// unique per (storm, event, channel) — so without the merge the outcome would
// depend on which fault confirmed first, and a policy that asked for a recovery
// notice could silently lose it. Any route asking for recovery wins.
func (s *Service) planStormOpen(ctx context.Context, tx *sql.Tx, stormID, siteID string, c stormMemberChannel, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE notification_deliveries
		SET due_at=MIN(due_at, ?), recovery_enabled=MAX(recovery_enabled, ?)
		WHERE storm_id=? AND event_kind=? AND channel_id=? AND status=?`,
		c.due, boolInt(c.recovery), stormID, eventStormOpened, c.channelID, statusPending); err != nil {
		return err
	}
	return insertDelivery(ctx, tx, subject{stormID: stormID}, siteID, eventStormOpened,
		c.channelID, c.policyID, c.recovery, c.due, now)
}

// pendingOpenChannels reads the routing an incident had planned but not yet
// sent, restricted to channels that accept storm summaries.
func pendingOpenChannels(ctx context.Context, tx *sql.Tx, incidentID string) ([]stormMemberChannel, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT d.channel_id, d.policy_id, d.recovery_enabled, d.due_at
		FROM notification_deliveries d
		WHERE d.incident_id=? AND d.event_kind=? AND d.status=? AND `+mergingChannel,
		incidentID, eventOpened, statusPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []stormMemberChannel
	for rows.Next() {
		var c stormMemberChannel
		var recovery int
		if err := rows.Scan(&c.channelID, &c.policyID, &recovery, &c.due); err != nil {
			return nil, err
		}
		c.recovery = recovery != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// RecomputeTx refreshes the storm of an incident that changed while staying open
// — a partial recovery, where the worst member came back and others are still
// firing. Without it a storm keeps the severity and layer of a fault that has
// already recovered, and a summary still waiting out its delay goes out
// describing a crisis that is over.
func (s *Service) RecomputeTx(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) error {
	stormID, err := stormOf(ctx, tx, incidentID)
	if err != nil || stormID == "" {
		return err
	}
	return recomputeStormTx(ctx, tx, stormID)
}

// settleStormTx advances a member incident's storm after that incident ended.
// A no-op for an incident that never belonged to one.
//
// It deliberately does NOT suppress the caller's per-incident recovery
// planning. That planning is already gated on "this channel actually received
// the open notice", and a merged channel's open notice was canceled — so it has
// nothing to pair with and is covered by the storm's summary, while a channel
// that opted out of merging (or was notified before the storm formed) gets the
// paired recovery it is owed. One rule, no special case.
func (s *Service) settleStormTx(ctx context.Context, tx *sql.Tx, incidentID string, now time.Time) error {
	var stormID string
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(storm_id,'') FROM incidents WHERE id=?`, incidentID).Scan(&stormID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if stormID == "" {
		return nil
	}
	var openMembers int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incidents WHERE storm_id=? AND state='open'`, stormID).Scan(&openMembers); err != nil {
		return err
	}
	if openMembers > 0 {
		// Partial recovery: the event is not over. Recompute what is still broken
		// and say nothing, matching the per-incident rule for a partial recovery.
		return recomputeStormTx(ctx, tx, stormID)
	}
	return s.closeStormTx(ctx, tx, stormID, now)
}

// closeStormTx ends a storm whose members have all finished and, when at least
// one of them genuinely recovered, plans the single summary recovery notice.
//
// A storm whose members ALL ended through a configuration change (target
// deleted, disabled, reconfigured, agent removed) closes silently: nothing came
// back, the faults merely stopped being observable, and announcing a recovery
// would be false. That is the same distinction the per-incident path draws, and
// it is also what stops a storm from becoming a zombie when its members are
// deleted mid-event.
func (s *Service) closeStormTx(ctx context.Context, tx *sql.Tx, stormID string, now time.Time) error {
	res, err := tx.ExecContext(ctx,
		`UPDATE alert_storms SET state='resolved', resolved_at=? WHERE id=? AND state='open'`, now, stormID)
	if err != nil {
		return err
	}
	// Already closed (a concurrent or replayed settle): the summary went out with
	// the close that won, and planning it again would duplicate.
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	var recovered int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM incidents WHERE storm_id=? AND resolve_reason=?`,
		stormID, fault.ReasonRecovered).Scan(&recovered); err != nil {
		return err
	}
	if recovered == 0 {
		return nil
	}
	// Only channels that actually received the storm's open notice, and only
	// where the governing policy asked for recovery notices.
	rows, err := tx.QueryContext(ctx, `
		SELECT channel_id, policy_id, site_id FROM notification_deliveries
		WHERE storm_id=? AND event_kind=? AND status=? AND recovery_enabled=1`,
		stormID, eventStormOpened, statusSent)
	if err != nil {
		return err
	}
	type sentRow struct{ channelID, policyID, siteID string }
	var sent []sentRow
	for rows.Next() {
		var r sentRow
		if err := rows.Scan(&r.channelID, &r.policyID, &r.siteID); err != nil {
			rows.Close()
			return err
		}
		sent = append(sent, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range sent {
		if err := insertDelivery(ctx, tx, subject{stormID: stormID}, r.siteID, eventStormResolved,
			r.channelID, r.policyID, true, now, now); err != nil {
			return err
		}
	}
	return nil
}

// recomputeStormTx refreshes a storm's severity and suspected layer from the
// members that are still open, so the notice that eventually goes out describes
// what is broken now rather than what was broken when the first member fell over.
func recomputeStormTx(ctx context.Context, tx *sql.Tx, stormID string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT severity, COALESCE(suspected_layer,'') FROM incidents WHERE storm_id=? AND state='open'`, stormID)
	if err != nil {
		return err
	}
	var severities, layers []string
	for rows.Next() {
		var sev, layer string
		if err := rows.Scan(&sev, &layer); err != nil {
			rows.Close()
			return err
		}
		severities = append(severities, sev)
		if layer != "" {
			layers = append(layers, layer)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(severities) == 0 {
		return nil // nothing open left; closeStormTx owns the terminal state
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE alert_storms SET severity=?, suspected_layer=? WHERE id=?`,
		fault.WorstSeverity(severities), fault.MostFundamentalLayer(layers), stormID)
	return err
}

// frozenAgentName resolves the display name to freeze onto a storm, preferring
// the name a fault signal already froze (so the storm says what its members say)
// and falling back to the live agent row.
func frozenAgentName(ctx context.Context, tx *sql.Tx, siteID, agentID string) (string, error) {
	var name string
	err := tx.QueryRowContext(ctx, `
		SELECT agent_name FROM fault_signals
		WHERE site_id=? AND agent_id=? AND agent_name<>''
		ORDER BY confirmed_at DESC LIMIT 1`, siteID, agentID).Scan(&name)
	if err == nil {
		return name, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(NULLIF(display_name,''), hostname, id) FROM agents WHERE id=?`, agentID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return agentID, nil
	}
	return name, err
}

// RecoverStorms closes any storm left open with no open members. Under normal
// operation this can never happen — a storm closes in the same transaction as
// its last member — so this is purely a boot-time backstop against a state no
// code path is supposed to be able to produce. It closes SILENTLY: announcing a
// recovery for an event whose ending was never observed would be a guess.
func (s *Service) RecoverStorms(ctx context.Context) error {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id FROM alert_storms st WHERE st.state='open'
		  AND NOT EXISTS(SELECT 1 FROM incidents i WHERE i.storm_id=st.id AND i.state='open')`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE alert_storms SET state='resolved', resolved_at=? WHERE id=? AND state='open'`, now, id); err != nil {
			return err
		}
	}
	return nil
}
