// Package incident correlates firing alerts into incidents, runs the §4 layered
// diagnosis (which layer is the likely root cause, single-device vs site-wide),
// maintains a timeline, and triggers notifications. P0 keeps one open incident
// per site — the site-level fault view of §16.
package incident

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
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
	db    *store.DB
	bus   *eventbus.Bus
	notif *notification.Service
	mu    sync.Mutex // serialize correlation so we never open duplicate incidents
}

func New(db *store.DB, bus *eventbus.Bus, notif *notification.Service) *Service {
	return &Service{db: db, bus: bus, notif: notif}
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
	layer, severity, summary := s.diagnose(ctx, a.SiteID)
	_, _ = s.db.ExecContext(ctx, `UPDATE incidents SET suspected_layer=?, severity=?, summary=? WHERE id=?`, layer, severity, summary, incID)
	s.addTimeline(ctx, incID, "alert.raised", fmt.Sprintf("%s — %s (%s层) = %.1f", a.RuleName, a.Target, layerLabel(a.Layer), a.Value))

	event := "incident.updated"
	if opened {
		s.addTimeline(ctx, incID, "incident.opened", summary)
		event = "incident.opened"
		s.bus.Publish(eventbus.TopicIncidentOpened, incID)
	} else {
		s.bus.Publish(eventbus.TopicIncidentUpdated, incID)
	}
	s.notify(ctx, incID, event)
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
		s.notify(ctx, incID, "incident.resolved")
		return
	}
	layer, severity, summary := s.diagnose(ctx, a.SiteID)
	_, _ = s.db.ExecContext(ctx, `UPDATE incidents SET suspected_layer=?, severity=?, summary=? WHERE id=?`, layer, severity, summary, incID)
	s.bus.Publish(eventbus.TopicIncidentUpdated, incID)
	s.notify(ctx, incID, "incident.updated")
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

// diagnose applies the §4 layered logic to the site's firing alerts.
func (s *Service) diagnose(ctx context.Context, siteID string) (layer, severity, summary string) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(r.layer,''), COALESCE(r.severity,'warn'), a.agent_id
		FROM alerts a LEFT JOIN alert_rules r ON r.id=a.rule_id
		WHERE a.site_id=? AND a.state='firing'`, siteID)
	if err != nil {
		return "", "warn", "检测到网络告警"
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

	suspected := ""
	for _, l := range layerPriority {
		if layers[l] {
			suspected = l
			break
		}
	}
	scope := "单机"
	if len(agents) > 1 {
		scope = "站点级"
	}
	summary = fmt.Sprintf("%s故障：%d 个 agent 出现告警，疑似 %s层", scope, len(agents), layerLabel(suspected))
	return suspected, worst, summary
}

func layerLabel(l string) string {
	switch l {
	case "local":
		return "本机"
	case "lan":
		return "局域网"
	case "wan":
		return "WAN"
	case "internet":
		return "互联网"
	case "dns":
		return "DNS"
	case "service":
		return "服务"
	case "wireless":
		return "无线"
	}
	return "网络"
}

func (s *Service) addTimeline(ctx context.Context, incID, kind, message string) {
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO incident_timeline(id, incident_id, ts, kind, message) VALUES(?,?,?,?,?)`,
		"tl_"+uuid.NewString(), incID, time.Now().UTC(), kind, message)
}

func (s *Service) notify(ctx context.Context, incID, event string) {
	inc, err := s.Get(ctx, incID)
	if err != nil {
		return
	}
	s.notif.Notify(ctx, notification.Payload{
		Event: event, IncidentID: inc.ID, SiteID: inc.SiteID, SuspectedLayer: inc.SuspectedLayer,
		Severity: inc.Severity, State: inc.State, Summary: inc.Summary, At: time.Now().UTC(),
	})
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
