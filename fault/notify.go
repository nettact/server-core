package fault

import (
	"context"
	"database/sql"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
)

// txOut accumulates the lifecycle events produced inside the fault write
// transaction, published only after commit.
//
// There are no notifications here. The engine's job ends at recording the fact
// and planning a delivery row; the delivery worker decides what actually goes
// out and when. That separation is what lets a fault be recorded in full with no
// channel configured, and what keeps a channel outage from touching the fault.
type txOut struct {
	confirmed        []SignalEvent
	resolved         []SignalEvent
	incidentOpened   []eventbus.IncidentEvent
	incidentUpdated  []eventbus.IncidentEvent
	incidentResolved []eventbus.IncidentEvent
	// changedTargets are extra target ids whose status shifted through a path that
	// does not report them another way (the termination paths).
	changedTargets []string
}

func incidentEvent(incidentID, siteID, groupID, severity string, escalated bool) eventbus.IncidentEvent {
	return eventbus.IncidentEvent{
		IncidentID: incidentID, SiteID: siteID, GroupID: groupID,
		Severity: severity, Escalated: escalated,
	}
}

// PublishOutcome fans an Outcome's accumulated lifecycle events out on the bus
// after a successful commit. No-op for a nil Outcome.
func (s *Service) PublishOutcome(ctx context.Context, out *Outcome) {
	if out == nil {
		return
	}
	s.publish(out.out)
}

func (s *Service) publish(out *txOut) {
	if s.bus == nil || out == nil {
		return
	}
	for _, e := range out.confirmed {
		s.bus.Publish(eventbus.TopicFaultConfirmed, e)
	}
	for _, e := range out.resolved {
		s.bus.Publish(eventbus.TopicFaultResolved, e)
	}
	for _, e := range out.incidentOpened {
		s.bus.Publish(eventbus.TopicIncidentOpened, e)
	}
	for _, e := range out.incidentUpdated {
		s.bus.Publish(eventbus.TopicIncidentUpdated, e)
	}
	for _, e := range out.incidentResolved {
		s.bus.Publish(eventbus.TopicIncidentResolved, e)
	}
}

// publishTargetStatus emits one precise TopicTargetStatusChanged for the site +
// affected targets after a committing lifecycle change. Empty sets publish
// nothing.
func (s *Service) publishTargetStatus(siteID string, targetIDs []string) {
	if s.bus == nil {
		return
	}
	ids := dedupeStrings(targetIDs)
	if len(ids) == 0 {
		return
	}
	s.bus.Publish(eventbus.TopicTargetStatusChanged, eventbus.TargetStatusChanged{SiteID: siteID, TargetIDs: ids})
}

func dedupeStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// signalDetailCols selects a fault signal's frozen facts in the shape the
// notification renderer consumes, so one query shape serves the summary, the
// timeline and the delivered message.
const signalDetailCols = `probe_kind, metric_kind, comparator, threshold, value, reason_code, reason_detail,
	target_name, target_addr, COALESCE(layer,''), severity, agent_name`

// renderIncidentSummary builds an incident's one-line summary from its firing
// members, inside the write tx.
func renderIncidentSummary(ctx context.Context, tx *sql.Tx, incidentID string) (string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT `+signalDetailCols+` FROM fault_signals WHERE incident_id=? AND state='firing'`, incidentID)
	if err != nil {
		return "", err
	}
	details, err := ScanDetails(rows)
	if err != nil {
		return "", err
	}
	return notification.RenderSummary(notification.Payload{Details: details}, "zh"), nil
}

// ScanDetails reads rows selected with signalDetailCols into renderer details.
// Exported so the notification-policy layer can reuse the exact same projection
// when it composes a delivery, rather than re-deriving the field order.
func ScanDetails(rows *sql.Rows) ([]notification.FaultDetail, error) {
	defer rows.Close()
	var out []notification.FaultDetail
	for rows.Next() {
		var d notification.FaultDetail
		if err := rows.Scan(&d.ProbeKind, &d.MetricKind, &d.Comparator, &d.Threshold, &d.Value,
			&d.ReasonCode, &d.ReasonDetail, &d.TargetName, &d.Target, &d.Layer, &d.Severity, &d.AgentHost); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SignalDetailColumns exposes the projection used by ScanDetails so other
// packages can build the matching SELECT.
func SignalDetailColumns() string { return signalDetailCols }
