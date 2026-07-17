package rules

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"time"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
)

// severityRank / layerPriority order incident severity and suspected root-cause
// layer (shared by the engine's recompute and escalation logic).
var severityRank = map[string]int{"info": 0, "warn": 1, "error": 2, "critical": 3}
var layerPriority = []string{"local", "lan", "wan", "internet", "dns", "service", "wireless"}

// txOut accumulates the events and notifications produced inside the fault-flow
// write transaction, dispatched only after commit.
type txOut struct {
	raised           []alert.Raised
	resolved         []alert.Raised
	evidence         []eventbus.EvidenceAdded
	incidentOpened   []eventbus.IncidentEvent
	incidentUpdated  []eventbus.IncidentEvent
	incidentResolved []eventbus.IncidentEvent
	notices          []notice
}

// notice is a post-commit notification to render and dispatch for an incident.
type notice struct {
	incidentID string
	siteID     string
	event      string // incident.opened | incident.updated | incident.resolved | incident.terminated
	state      string // open | resolved | terminated
}

// publishAndNotify fans the accumulated post-commit events out on the bus and
// dispatches notifications off the write path.
func (s *Service) publishAndNotify(ctx context.Context, out *txOut) {
	if s.bus != nil {
		for _, r := range out.raised {
			s.bus.Publish(eventbus.TopicAlertRaised, r)
		}
		for _, r := range out.resolved {
			s.bus.Publish(eventbus.TopicAlertResolved, r)
		}
		for _, e := range out.evidence {
			s.bus.Publish(eventbus.TopicEvidenceAdded, e)
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
	if s.notif == nil {
		return
	}
	for _, n := range out.notices {
		payload := s.buildIncidentPayload(ctx, n.incidentID, n.siteID, n.event, n.state)
		channels := s.incidentChannels(ctx, n.incidentID)
		// Dispatch off the eval path: channel delivery does blocking network I/O.
		go s.notif.Notify(context.WithoutCancel(ctx), channels, payload)
	}
}

// buildIncidentPayload assembles a notification payload from an incident's
// current state and firing-member evidence.
func (s *Service) buildIncidentPayload(ctx context.Context, incidentID, siteID, event, state string) notification.Payload {
	var severity, suspected string
	_ = s.db.Read().QueryRowContext(ctx,
		`SELECT severity, COALESCE(suspected_layer,'') FROM incidents WHERE id=?`, incidentID).Scan(&severity, &suspected)
	details := s.incidentDetails(ctx, incidentID)
	agents := map[string]bool{}
	for _, d := range details {
		agents[d.AgentHost] = true
	}
	scope := "single"
	if len(agents) > 1 {
		scope = "site"
	}
	return notification.Payload{
		Event:          event,
		IncidentID:     incidentID,
		SiteID:         siteID,
		State:          state,
		Severity:       severity,
		Scope:          scope,
		AgentCount:     len(agents),
		SuspectedLayer: suspected,
		Details:        details,
		URL:            s.incidentURL(ctx, incidentID),
		At:             time.Now().UTC(),
	}
}

// incidentDetails returns the AlertDetail facts for an incident's firing-member
// evidence, read on the read pool.
func (s *Service) incidentDetails(ctx context.Context, incidentID string) []notification.AlertDetail {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT e.probe_kind, e.metric_kind, e.comparator, e.threshold, e.value, e.target_name, e.target_addr,
		       COALESCE(a.layer,''), a.severity, COALESCE(NULLIF(ag.display_name,''), ag.hostname,'')
		FROM alert_evidence e
		JOIN alerts a ON a.id = e.alert_id
		LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE a.incident_id=? AND a.state='firing'`, incidentID)
	if err != nil {
		return nil
	}
	return scanDetails(rows)
}

// renderIncidentSummary builds the one-line incident summary from its firing
// evidence, inside the write tx.
func renderIncidentSummary(ctx context.Context, tx *sql.Tx, incidentID string) string {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.probe_kind, e.metric_kind, e.comparator, e.threshold, e.value, e.target_name, e.target_addr,
		       COALESCE(a.layer,''), a.severity, COALESCE(NULLIF(ag.display_name,''), ag.hostname,'')
		FROM alert_evidence e
		JOIN alerts a ON a.id = e.alert_id
		LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE a.incident_id=? AND a.state='firing'`, incidentID)
	if err != nil {
		return ""
	}
	details := scanDetails(rows)
	return notification.RenderSummary(notification.Payload{Details: details}, "zh")
}

// faultLine renders the specific-fault timeline line for one alert from its
// frozen evidence, inside the write tx.
func (s *Service) faultLine(ctx context.Context, tx *sql.Tx, alertID string) string {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.probe_kind, e.metric_kind, e.comparator, e.threshold, e.value, e.target_name, e.target_addr,
		       COALESCE(a.layer,''), a.severity, COALESCE(NULLIF(ag.display_name,''), ag.hostname,'')
		FROM alert_evidence e
		JOIN alerts a ON a.id = e.alert_id
		LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE e.alert_id=?`, alertID)
	if err != nil {
		return ""
	}
	details := scanDetails(rows)
	if len(details) == 0 {
		return ""
	}
	return notification.RenderSummary(notification.Payload{Details: details}, "zh")
}

func scanDetails(rows *sql.Rows) []notification.AlertDetail {
	defer rows.Close()
	var out []notification.AlertDetail
	for rows.Next() {
		var d notification.AlertDetail
		if err := rows.Scan(&d.ProbeKind, &d.MetricKind, &d.Comparator, &d.Threshold, &d.Value,
			&d.TargetName, &d.Target, &d.Layer, &d.Severity, &d.AgentHost); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out
}

// incidentChannels returns the union of the notification channel ids frozen onto
// an incident's member alerts at fire time. Reading the alerts' own frozen
// channel_ids (not the live group_rules join filtered to firing members) means a
// final resolution/termination notice — dispatched post-commit, after the last
// member has resolved, possibly with its rule deleted — still routes to the
// configured channels instead of collapsing to an empty list. Empty only when the
// incident's rules genuinely configured no channels, in which case
// notification.Notify's all-enabled-channels fallback applies consistently for
// both the open and the resolve notice.
func (s *Service) incidentChannels(ctx context.Context, incidentID string) []string {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT DISTINCT COALESCE(channel_ids,'[]') FROM alerts WHERE incident_id=?`, incidentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var chans string
		if err := rows.Scan(&chans); err != nil {
			continue
		}
		if chans == "" {
			continue
		}
		var ids []string
		if json.Unmarshal([]byte(chans), &ids) != nil {
			continue
		}
		for _, id := range ids {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// incidentURL builds a console deep link to an incident, or "" when no console
// base URL is configured.
func (s *Service) incidentURL(ctx context.Context, incidentID string) string {
	base := s.settings.ConsoleBaseURL(ctx)
	if base == "" {
		return ""
	}
	return base + "/incidents?incident=" + url.QueryEscape(incidentID)
}

// evidenceLine renders one evidence-added timeline event from only the condition
// inserted by that event. An already-firing OR rule can accumulate multiple
// condition rows over time; re-rendering every row would keep the first target as
// the headline and mislabel a later target as "N issues in total".
func (s *Service) evidenceLine(ctx context.Context, tx *sql.Tx, alertID, conditionID string) string {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.probe_kind, e.metric_kind, e.comparator, e.threshold, e.value, e.target_name, e.target_addr,
		       COALESCE(a.layer,''), a.severity, COALESCE(NULLIF(ag.display_name,''), ag.hostname,'')
		FROM alert_evidence e
		JOIN alerts a ON a.id = e.alert_id
		LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE e.alert_id=? AND e.condition_id=?`, alertID, conditionID)
	if err != nil {
		return ""
	}
	details := scanDetails(rows)
	if len(details) == 0 {
		return ""
	}
	return notification.DescribeDetail(details[0], "zh")
}
