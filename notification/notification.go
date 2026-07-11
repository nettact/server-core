// Package notification delivers incident events to configured channels
// (webhook + SMTP + native OS desktop notification). Delivery is best-effort
// and must never block or fail the incident pipeline.
package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/store"
)

// Payload is the incident event delivered to channels.
type Payload struct {
	Event          string    `json:"event"` // incident.opened | incident.updated | incident.resolved
	IncidentID     string    `json:"incident_id"`
	SiteID         string    `json:"site_id"`
	SuspectedLayer string    `json:"suspected_layer"`
	Severity       string    `json:"severity"`
	State          string    `json:"state"`
	Summary        string    `json:"summary"`
	At             time.Time `json:"at"`
}

// Channel is a notification destination.
type Channel struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"` // human label to tell multiple channels apart
	Type    string            `json:"type"` // "webhook" | "email" | "system"
	Config  map[string]string `json:"config"`
	Enabled bool              `json:"enabled"`
}

type Service struct {
	db     *store.DB
	client *http.Client
}

func New(db *store.DB) *Service {
	return &Service{db: db, client: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Service) List(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(name,''), type, config, enabled FROM notification_channels ORDER BY type, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		var cfg string
		var enabled int
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &cfg, &enabled); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(cfg), &c.Config)
		c.Enabled = enabled == 1
		out = append(out, redact(c))
	}
	return out, rows.Err()
}

// Create adds a channel. config is stored as JSON.
func (s *Service) Create(ctx context.Context, name, typ string, config map[string]string) (string, error) {
	id := "chan_" + uuid.NewString()
	b, _ := json.Marshal(config)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO notification_channels(id, name, type, config, enabled) VALUES(?,?,?,?,1)`, id, name, typ, string(b))
	return id, err
}

// Update edits a channel's name/enabled and, when config is non-nil, its config.
func (s *Service) Update(ctx context.Context, id, name string, enabled bool, config map[string]string) error {
	en := 0
	if enabled {
		en = 1
	}
	if config != nil {
		b, _ := json.Marshal(config)
		_, err := s.db.ExecContext(ctx,
			`UPDATE notification_channels SET name=?, enabled=?, config=? WHERE id=?`, name, en, string(b), id)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE notification_channels SET name=?, enabled=? WHERE id=?`, name, en, id)
	return err
}

func (s *Service) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM notification_channels WHERE id=?`, id)
	return err
}

// Notify delivers p to the given enabled channels (best-effort, logged on
// failure). When channelIDs is empty it falls back to ALL enabled channels, so
// callers with no routing configured keep the original global fan-out behavior.
func (s *Service) Notify(ctx context.Context, channelIDs []string, p Payload) {
	q := `SELECT type, config FROM notification_channels WHERE enabled=1`
	var args []any
	if len(channelIDs) > 0 {
		placeholders := make([]byte, 0, len(channelIDs)*2)
		for i, id := range channelIDs {
			if i > 0 {
				placeholders = append(placeholders, ',')
			}
			placeholders = append(placeholders, '?')
			args = append(args, id)
		}
		q += " AND id IN (" + string(placeholders) + ")"
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		log.Printf("notify: list channels: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var typ, cfg string
		if err := rows.Scan(&typ, &cfg); err != nil {
			continue
		}
		var config map[string]string
		_ = json.Unmarshal([]byte(cfg), &config)
		switch typ {
		case "webhook":
			s.sendWebhook(ctx, config["url"], p)
		case "email":
			s.sendEmail(config, p)
		case "system":
			s.sendNative(ctx, p)
		}
	}
}

func (s *Service) sendWebhook(ctx context.Context, url string, p Payload) {
	if url == "" {
		return
	}
	body, _ := json.Marshal(p)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("notify webhook %s: %v", url, err)
		return
	}
	resp.Body.Close()
}

func (s *Service) sendEmail(cfg map[string]string, p Payload) {
	host, from, to := cfg["host"], cfg["from"], cfg["to"]
	if host == "" || from == "" || to == "" {
		return
	}
	port := cfg["port"]
	if port == "" {
		port = "587"
	}
	subject := fmt.Sprintf("[NetTact] %s: %s", p.Event, p.Summary)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\nSite: %s\r\nLayer: %s\r\nSeverity: %s\r\nAt: %s\r\n",
		from, to, subject, p.Summary, p.SiteID, p.SuspectedLayer, p.Severity, p.At.Format(time.RFC3339))
	var auth smtp.Auth
	if cfg["username"] != "" {
		auth = smtp.PlainAuth("", cfg["username"], cfg["password"], host)
	}
	if err := smtp.SendMail(host+":"+port, auth, from, []string{to}, []byte(msg)); err != nil {
		log.Printf("notify email: %v", err)
	}
}

// sendNative pops a desktop notification on the host running this process
// (Windows / macOS). It is a no-op on unsupported platforms. Delivery is
// best-effort and bounded by a short timeout so it never blocks the pipeline.
func (s *Service) sendNative(ctx context.Context, p Payload) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	title := fmt.Sprintf("[NetTact] %s", p.Event)
	body := p.Summary
	if p.SuspectedLayer != "" || p.Severity != "" {
		body = fmt.Sprintf("%s (%s / %s)", p.Summary, p.SuspectedLayer, p.Severity)
	}
	if err := nativeNotify(ctx, title, body); err != nil {
		log.Printf("notify system: %v", err)
	}
}

// redact hides secrets when listing channels for the UI.
func redact(c Channel) Channel {
	if c.Config == nil {
		return c
	}
	out := make(map[string]string, len(c.Config))
	for k, v := range c.Config {
		if k == "password" && v != "" {
			out[k] = "••••••"
		} else {
			out[k] = v
		}
	}
	c.Config = out
	return c
}
