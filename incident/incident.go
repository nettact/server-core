// Package incident correlates firing alerts into incidents, runs the §4 layered
// diagnosis (which layer is the likely root cause, single-device vs site-wide),
// maintains a timeline, and triggers notifications. P0 keeps one open incident
// per site — the site-level fault view of §16.
package incident

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

type Incident struct {
	ID             string     `json:"id"`
	SiteID         string     `json:"site_id"`
	Title          string     `json:"title"`
	SuspectedLayer string     `json:"suspected_layer"`
	State          string     `json:"state"`
	Severity       string     `json:"severity"`
	Summary        string     `json:"summary"`
	OpenedAt       time.Time  `json:"opened_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
}

type TimelineEntry struct {
	TS      time.Time `json:"ts"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
}

type Service struct {
	db       *store.DB
	bus      *eventbus.Bus
	notif    *notification.Service
	settings *settings.Service // for the console base URL used in deep links (nil-safe)
	mu       sync.Mutex        // serialize correlation so we never open duplicate incidents
}

func New(db *store.DB, bus *eventbus.Bus, notif *notification.Service, set *settings.Service) *Service {
	return &Service{db: db, bus: bus, notif: notif, settings: set}
}

// Wire subscribes to alert lifecycle events.
func (s *Service) Wire() {
	s.bus.Subscribe(eventbus.TopicAlertRaised, func(m eventbus.Message) {
		if a, ok := m.Payload.(alert.Raised); ok {
			s.onRaised(a)
		}
	})
	s.bus.Subscribe(eventbus.TopicAlertResolved, func(m eventbus.Message) {
		if a, ok := m.Payload.(alert.Raised); ok {
			s.onResolved(a)
		}
	})
}

func (s *Service) onRaised(a alert.Raised) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()

	incID, opened, err := s.ensureOpenIncident(ctx, a.SiteID)
	if err != nil {
		log.Printf("incident ensure: %v", err)
		return
	}
	event := "incident.opened"
	if !opened {
		event = "incident.updated"
	}
	p := s.buildPayload(ctx, incID, a.SiteID, event, "open")
	summary := notification.RenderSummary(p, "zh")
	_, _ = s.db.ExecContext(ctx, `UPDATE incidents SET suspected_layer=?, severity=?, summary=? WHERE id=?`, p.SuspectedLayer, p.Severity, summary, incID)
	s.addTimeline(ctx, incID, "alert.raised", s.raisedLine(ctx, a))

	if opened {
		s.addTimeline(ctx, incID, "incident.opened", summary)
		s.bus.Publish(eventbus.TopicIncidentOpened, incID)
	} else {
		s.bus.Publish(eventbus.TopicIncidentUpdated, incID)
	}
	// Dispatch off the correlation lock: notification delivery does blocking
	// network I/O (webhook/SMTP), and holding s.mu across it would stall all
	// other incident processing when a channel endpoint is slow or unreachable.
	go s.notify(ctx, a.SiteID, p)
}

// raisedLine renders the timeline entry for a newly-firing alert. It looks up
// the alert's full facts so the line states the specific fault ("网站 X 返回状态码
// 503（来自 host）") rather than a bare rule name and number; on lookup failure it
// falls back to the rule name + target.
func (s *Service) raisedLine(ctx context.Context, a alert.Raised) string {
	if d, ok := s.alertDetail(ctx, a.ID); ok {
		return notification.DescribeDetail(d, "zh")
	}
	return fmt.Sprintf("%s — %s", a.RuleName, a.Target)
}

func (s *Service) onResolved(a alert.Raised) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()

	incID, err := s.openIncidentID(ctx, a.SiteID)
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	if err != nil {
		log.Printf("incident lookup: %v", err)
		return
	}
	s.addTimeline(ctx, incID, "alert.resolved", fmt.Sprintf("%s — %s 恢复", a.RuleName, a.Target))

	var firing int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE site_id=? AND state='firing'`, a.SiteID).Scan(&firing)
	if firing == 0 {
		now := time.Now().UTC()
		_, _ = s.db.ExecContext(ctx, `UPDATE incidents SET state='resolved', resolved_at=? WHERE id=?`, now, incID)
		s.addTimeline(ctx, incID, "incident.resolved", "所有告警已恢复")
		s.bus.Publish(eventbus.TopicIncidentUpdated, incID)
		resolved := s.buildPayload(ctx, incID, a.SiteID, "incident.resolved", "resolved")
		go s.notify(ctx, a.SiteID, resolved)
		return
	}
	p := s.buildPayload(ctx, incID, a.SiteID, "incident.updated", "open")
	summary := notification.RenderSummary(p, "zh")
	_, _ = s.db.ExecContext(ctx, `UPDATE incidents SET suspected_layer=?, severity=?, summary=? WHERE id=?`, p.SuspectedLayer, p.Severity, summary, incID)
	s.bus.Publish(eventbus.TopicIncidentUpdated, incID)
	go s.notify(ctx, a.SiteID, p)
}

func (s *Service) openIncidentID(ctx context.Context, siteID string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM incidents WHERE site_id=? AND state='open' ORDER BY opened_at DESC LIMIT 1`, siteID).Scan(&id)
	return id, err
}

func (s *Service) ensureOpenIncident(ctx context.Context, siteID string) (id string, opened bool, err error) {
	id, err = s.openIncidentID(ctx, siteID)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	id = "inc_" + uuid.NewString()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO incidents(id, site_id, title, state, opened_at) VALUES(?,?,?, 'open', ?)`,
		id, siteID, "网络故障", time.Now().UTC())
	return id, true, err
}

var layerPriority = []string{"local", "lan", "wan", "internet", "dns", "service", "wireless"}
var severityRank = map[string]int{"info": 0, "warn": 1, "error": 2, "critical": 3}

// diagnose applies the §4 layered logic to the site's firing alerts, returning
// the scope (single host vs site-wide), the number of distinct alerting agents,
// the suspected root-cause layer, and the worst severity.
func (s *Service) diagnose(ctx context.Context, siteID string) (scope string, agentCount int, suspected, severity string) {
	// INNER JOIN (every alert is created from a rule) so the agent count and
	// suspected layer are computed over exactly the alerts collectDetails renders
	// — otherwise a rule-less row could be counted here but dropped from details.
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(r.layer,''), COALESCE(r.severity,'warn'), a.agent_id
		FROM alerts a JOIN alert_rules r ON r.id=a.rule_id
		WHERE a.site_id=? AND a.state='firing'`, siteID)
	if err != nil {
		return "single", 0, "", "warn"
	}
	defer rows.Close()

	layers := map[string]bool{}
	agents := map[string]bool{}
	worst := "warn"
	for rows.Next() {
		var l, sev, ag string
		if err := rows.Scan(&l, &sev, &ag); err != nil {
			continue
		}
		if l != "" {
			layers[l] = true
		}
		agents[ag] = true
		if severityRank[sev] > severityRank[worst] {
			worst = sev
		}
	}

	suspected = ""
	for _, l := range layerPriority {
		if layers[l] {
			suspected = l
			break
		}
	}
	scope = "single"
	if len(agents) > 1 {
		scope = "site"
	}
	return scope, len(agents), suspected, worst
}

// detailCols / detailFrom are shared by collectDetails (all firing alerts on a
// site) and alertDetail (one alert by id): alerts joined with their rule (metric
// + threshold), the bound probe task (kind + friendly name), and the detecting
// agent (display name / hostname).
const detailCols = `r.metric_kind, r.comparator, r.threshold, COALESCE(r.layer,''), COALESCE(r.severity,'warn'),
	COALESCE(p.kind,''), COALESCE(p.name,''), a.target, a.value,
	COALESCE(NULLIF(ag.display_name,''), ag.hostname, '')`

const detailFrom = `FROM alerts a
	JOIN alert_rules r ON r.id = a.rule_id
	LEFT JOIN probe_tasks p ON p.id = r.probe_task_id
	LEFT JOIN agents ag ON ag.id = a.agent_id`

func scanDetail(row scanner) (notification.AlertDetail, error) {
	var d notification.AlertDetail
	err := row.Scan(&d.MetricKind, &d.Comparator, &d.Threshold, &d.Layer, &d.Severity,
		&d.ProbeKind, &d.TargetName, &d.Target, &d.Value, &d.AgentHost)
	return d, err
}

// collectDetails returns the structured facts for every firing alert on a site,
// used to render per-target lines in notifications.
func (s *Service) collectDetails(ctx context.Context, siteID string) []notification.AlertDetail {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+detailCols+` `+detailFrom+` WHERE a.site_id=? AND a.state='firing'`, siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []notification.AlertDetail
	for rows.Next() {
		d, err := scanDetail(rows)
		if err != nil {
			continue
		}
		out = append(out, d)
	}
	return out
}

// alertDetail returns the facts for a single alert by id (used for the timeline
// line of a just-fired alert).
func (s *Service) alertDetail(ctx context.Context, alertID string) (notification.AlertDetail, bool) {
	row := s.db.QueryRowContext(ctx, `SELECT `+detailCols+` `+detailFrom+` WHERE a.id=?`, alertID)
	d, err := scanDetail(row)
	if err != nil {
		return notification.AlertDetail{}, false
	}
	return d, true
}

// buildPayload assembles the structured notification payload from the current
// site diagnosis plus the list of firing-alert facts.
func (s *Service) buildPayload(ctx context.Context, incID, siteID, event, state string) notification.Payload {
	scope, count, suspected, severity := s.diagnose(ctx, siteID)
	return notification.Payload{
		Event:          event,
		IncidentID:     incID,
		SiteID:         siteID,
		State:          state,
		Severity:       severity,
		Scope:          scope,
		AgentCount:     count,
		SuspectedLayer: suspected,
		Details:        s.collectDetails(ctx, siteID),
		URL:            s.incidentURL(ctx, incID),
		At:             time.Now().UTC(),
	}
}

// incidentURL builds a deep link to this incident in the console, or "" when no
// console base URL is configured. The frontend reads ?incident=<id> to auto-open
// the incident's timeline.
func (s *Service) incidentURL(ctx context.Context, incID string) string {
	base := s.settings.ConsoleBaseURL(ctx)
	if base == "" {
		return ""
	}
	return base + "/incidents?incident=" + url.QueryEscape(incID)
}

func (s *Service) addTimeline(ctx context.Context, incID, kind, message string) {
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO incident_timeline(id, incident_id, ts, kind, message) VALUES(?,?,?,?,?)`,
		"tl_"+uuid.NewString(), incID, time.Now().UTC(), kind, message)
}

// notify routes the payload to the union of channels selected on the rules of
// this site's firing alerts. When none specify channels, Notify falls back to
// all enabled.
func (s *Service) notify(ctx context.Context, siteID string, p notification.Payload) {
	channelIDs := s.firingChannels(ctx, siteID)
	s.notif.Notify(ctx, channelIDs, p)
}

// firingChannels returns the distinct channel IDs configured on the rules of a
// site's currently-firing alerts.
func (s *Service) firingChannels(ctx context.Context, siteID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT COALESCE(r.channel_ids,'')
		FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
		WHERE a.site_id=? AND a.state='firing'`, siteID)
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

// --- UI reads ---

func (s *Service) List(ctx context.Context, siteID string) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, site_id, COALESCE(title,''), COALESCE(suspected_layer,''), state,
		       COALESCE(severity,''), COALESCE(summary,''), opened_at, resolved_at
		FROM incidents WHERE site_id=? ORDER BY opened_at DESC LIMIT 200`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, id string) (Incident, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, site_id, COALESCE(title,''), COALESCE(suspected_layer,''), state,
		       COALESCE(severity,''), COALESCE(summary,''), opened_at, resolved_at
		FROM incidents WHERE id=?`, id)
	return scanIncident(row)
}

func (s *Service) Timeline(ctx context.Context, incID string) ([]TimelineEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, kind, COALESCE(message,'') FROM incident_timeline WHERE incident_id=? ORDER BY ts`, incID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelineEntry
	for rows.Next() {
		var e TimelineEntry
		if err := rows.Scan(&e.TS, &e.Kind, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanIncident(row scanner) (Incident, error) {
	var inc Incident
	var resolved sql.NullTime
	err := row.Scan(&inc.ID, &inc.SiteID, &inc.Title, &inc.SuspectedLayer, &inc.State,
		&inc.Severity, &inc.Summary, &inc.OpenedAt, &resolved)
	if err != nil {
		return Incident{}, err
	}
	if resolved.Valid {
		t := resolved.Time
		inc.ResolvedAt = &t
	}
	return inc, nil
}
