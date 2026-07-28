// Package notification delivers incident events to configured channels
// (webhook + SMTP + native OS desktop notification). Delivery is best-effort
// and must never block or fail the incident pipeline.
package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/store"
)

// Payload is the incident event delivered to channels. It carries STRUCTURED
// facts (scope + the list of firing alerts) rather than a pre-rendered string,
// so each channel can render title/summary/details in its own language at
// delivery time.
type Payload struct {
	Event          string `json:"event"` // incident.opened | incident.updated | incident.resolved | incident.terminated | agent.offline | agent.recovered
	IncidentID     string `json:"incident_id"`
	SiteID         string `json:"site_id"`
	State          string `json:"state"`                // open | resolved | terminated
	Severity       string `json:"severity"`             // worst firing severity
	Scope          string `json:"scope"`                // "single" | "site"
	AgentCount     int    `json:"agent_count"`          // distinct agents alerting
	SuspectedLayer string `json:"suspected_layer"`      // root-cause layer code
	GroupName      string `json:"group_name,omitempty"` // incident's frozen alert-group name
	// GroupMerged is true when the incident merges the whole group's alerts
	// (monitor_groups.merge_enabled), so a terminal notice may speak for the group
	// ("all alerts recovered"). False ⇒ a per-alert incident: sibling alerts in the
	// same group may still be firing, and the wording must stay per-alert.
	GroupMerged      bool              `json:"group_merged,omitempty"`
	Details          []FaultDetail     `json:"details,omitempty"`           // per-target firing facts (incident events)
	RecoveredTargets []RecoveredTarget `json:"recovered_targets,omitempty"` // targets that came back (resolved/terminated events)
	Agents           []AgentDetail     `json:"agents,omitempty"`            // per-agent facts (agent.offline / agent.recovered events)
	URL              string            `json:"url,omitempty"`               // deep link to the incident/agents view in the console
	At               time.Time         `json:"at"`
}

// RecoveredTarget is one monitored target that was part of a now-resolved incident,
// listed in the recovery notice so it names the group AND what came back.
type RecoveredTarget struct {
	Name      string `json:"name"`       // operator-set friendly name, optional
	Addr      string `json:"addr"`       // address ("1.1.1.1", "https://…", "host:port")
	ProbeKind string `json:"probe_kind"` // "icmp" | "dns" | "http" | "tcp" | "gateway" | ""
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

// Get returns a single channel by id with its config UNREDACTED — callers like
// the update handler need the real stored values to validate against. Returns
// sql.ErrNoRows when the channel does not exist.
func (s *Service) Get(ctx context.Context, id string) (Channel, error) {
	var c Channel
	var cfg string
	var enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(name,''), type, config, enabled FROM notification_channels WHERE id=?`, id).
		Scan(&c.ID, &c.Name, &c.Type, &cfg, &enabled)
	if err != nil {
		return Channel{}, err
	}
	_ = json.Unmarshal([]byte(cfg), &c.Config)
	c.Enabled = enabled == 1
	return c, nil
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
// failure).
//
// An empty channel list sends NOTHING. Under the notification-policy model an
// empty list is a deliberate, meaningful configuration — "record every fault,
// send nothing" — so the old fall-back-to-all-channels behaviour would invert the
// operator's intent and page everyone precisely when they asked for silence.
func (s *Service) Notify(ctx context.Context, channelIDs []string, p Payload) {
	if len(channelIDs) == 0 {
		return
	}
	placeholders := make([]byte, 0, len(channelIDs)*2)
	args := make([]any, 0, len(channelIDs))
	for i, id := range channelIDs {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args = append(args, id)
	}
	q := `SELECT type, config FROM notification_channels WHERE enabled=1 AND id IN (` + string(placeholders) + `)`
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
			s.sendWebhook(ctx, config, p)
		case "email":
			s.sendEmail(config, p)
		case "system":
			s.sendNative(ctx, config["lang"], p)
		}
	}
}

// webhookBody is the JSON posted to webhook channels: the raw structured
// Payload (machine consumers localize themselves) plus title/text pre-rendered
// in the channel's configured language for convenience.
type webhookBody struct {
	Payload
	Title string   `json:"title"`
	Text  string   `json:"text"`
	Lines []string `json:"lines"`
}

func (s *Service) sendWebhook(ctx context.Context, cfg map[string]string, p Payload) {
	status, _, err := s.deliverWebhook(ctx, cfg, p)
	switch {
	case err != nil:
		log.Printf("notify webhook %s: %v", cfg["url"], err)
	case status >= 300:
		log.Printf("notify webhook %s: status %d", cfg["url"], status)
	}
}

// deliverWebhook builds and sends one webhook request from cfg and returns the
// response status plus a short snippet of the response body (first 512 bytes).
// It honors the channel's method / headers / URL / body template (see
// template.go); an empty body template falls back to the default structured
// webhookBody. The snippet lets a test send surface soft failures like
// DingTalk's HTTP-200 errcode replies. Callers guarantee cfg["url"] is non-empty
// (API-layer validation).
func (s *Service) deliverWebhook(ctx context.Context, cfg map[string]string, p Payload) (int, string, error) {
	rawURL := cfg["url"]
	if rawURL == "" {
		return 0, "", fmt.Errorf("webhook url is empty")
	}
	lang := cfg["lang"]
	vars := buildVars(p, lang)

	method := strings.ToUpper(strings.TrimSpace(cfg["method"]))
	if method == "" {
		method = http.MethodPost
	}
	target := substitute(rawURL, vars, escapeURLValue)

	var body []byte
	if strings.TrimSpace(cfg["body"]) != "" {
		body = []byte(substitute(cfg["body"], vars, escapeJSONValue))
	} else {
		body, _ = json.Marshal(webhookBody{
			Payload: p,
			Title:   RenderTitle(p, lang),
			Text:    RenderScope(p, lang),
			Lines:   RenderLines(p, lang),
		})
	}

	// GET/HEAD carry no request body.
	sendBody := method != http.MethodGet && method != http.MethodHead
	var reqBody io.Reader
	if sendBody {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
	if err != nil {
		return 0, "", err
	}
	// Custom headers first, so an explicit Content-Type wins over the default.
	explicitCT := false
	if raw := strings.TrimSpace(cfg["headers"]); raw != "" {
		var hdrs map[string]string
		if json.Unmarshal([]byte(raw), &hdrs) == nil {
			for k, v := range hdrs {
				req.Header.Set(k, substitute(v, vars, escapeHeaderValue))
				if strings.EqualFold(k, "Content-Type") {
					explicitCT = true
				}
			}
		}
	}
	if sendBody && !explicitCT {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, string(snippet), nil
}

// TestWebhook delivers p to the webhook described by cfg WITHOUT persisting a
// channel, returning the HTTP status, a response snippet and any transport
// error. It backs the "send test" button so an operator can validate a custom
// method / headers / body template against sample data before saving.
func (s *Service) TestWebhook(ctx context.Context, cfg map[string]string, p Payload) (int, string, error) {
	return s.deliverWebhook(ctx, cfg, p)
}

// SampleWebhookPayload builds a representative payload for test sends: one
// HTTP-503 fault on a single host, deep-linked into consoleBase when configured.
// The event is "test" so the rendered title/text and the {{event}} variable mark
// it clearly as a test, letting receivers distinguish it from a real incident.
func SampleWebhookPayload(consoleBase string) Payload {
	link := ""
	if consoleBase != "" {
		link = consoleBase + "/incidents?incident=inc_sample"
	}
	return Payload{
		Event:          "test",
		IncidentID:     "inc_sample",
		SiteID:         "site_sample",
		State:          "open",
		Severity:       "critical",
		Scope:          "single",
		AgentCount:     1,
		SuspectedLayer: "service",
		Details: []FaultDetail{{
			ProbeKind:  "http",
			MetricKind: "probe.http.status",
			Comparator: "eq",
			Threshold:  200,
			Value:      503,
			TargetName: "Example Site",
			Target:     "https://example.com",
			Layer:      "service",
			Severity:   "critical",
			AgentHost:  "living-room",
		}},
		URL: link,
		At:  time.Now().UTC(),
	}
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
	lang := cfg["lang"]
	title := RenderTitle(p, lang)
	// Subject may contain non-ASCII (e.g. "网络告警"); RFC 2047-encode it so the
	// header stays 7-bit-clean and clients render it correctly.
	subject := mime.QEncoding.Encode("utf-8", "[NetTact] "+title)

	var b strings.Builder
	b.WriteString(RenderScope(p, lang))
	b.WriteString("\r\n")
	for _, line := range RenderLines(p, lang) {
		b.WriteString("\r\n- ")
		b.WriteString(line)
	}
	if link := LinkLine(p.URL, lang); link != "" {
		b.WriteString("\r\n\r\n")
		b.WriteString(link)
	}
	b.WriteString("\r\n\r\n")
	b.WriteString(emailFooter(p, lang))

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		from, to, subject, b.String())
	var auth smtp.Auth
	if cfg["username"] != "" {
		auth = smtp.PlainAuth("", cfg["username"], cfg["password"], host)
	}
	if err := smtp.SendMail(host+":"+port, auth, from, []string{to}, []byte(msg)); err != nil {
		log.Printf("notify email: %v", err)
	}
}

// emailFooter renders the localized "Site / Severity / Time" trailer.
func emailFooter(p Payload, lang string) string {
	at := p.At.Format(time.RFC3339)
	if normLang(lang) == "en" {
		return fmt.Sprintf("Site: %s\r\nSeverity: %s\r\nTime: %s", p.SiteID, p.Severity, at)
	}
	return fmt.Sprintf("站点：%s\r\n级别：%s\r\n时间：%s", p.SiteID, p.Severity, at)
}

// sendNative pops a desktop notification on the host running this process
// (Windows / macOS). It is a no-op on unsupported platforms. Delivery is
// best-effort and bounded by a short timeout so it never blocks the pipeline.
func (s *Service) sendNative(ctx context.Context, lang string, p Payload) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	title := RenderTitle(p, lang)
	body := RenderScope(p, lang)
	if lines := RenderLines(p, lang); len(lines) > 0 {
		body = body + "\n" + lines[0] // keep the toast short — lead with the top fault
	}
	// p.URL is attached as the toast's click action (protocol activation) rather
	// than printed into the body, so clicking the toast opens the incident page.
	if err := nativeNotify(ctx, title, body, p.URL); err != nil {
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
