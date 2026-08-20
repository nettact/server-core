// Package notification delivers incident events to configured channels
// (webhook + SMTP + native OS desktop notification + the push platforms behind
// the Provider registry). Delivery is best-effort and must never block or fail
// the incident pipeline.
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
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

// Payload is the incident event delivered to channels. It carries STRUCTURED
// facts (scope + the list of firing alerts) rather than a pre-rendered string,
// so each channel can render title/summary/details in its own language at
// delivery time.
type Payload struct {
	Event          string `json:"event"` // incident.opened | incident.resolved | agent.offline | agent.recovered | storm.opened | storm.resolved
	IncidentID     string `json:"incident_id"`
	StormID        string `json:"storm_id,omitempty"`
	SiteID         string `json:"site_id"`
	State          string `json:"state"`           // open | resolved | terminated
	Severity       string `json:"severity"`        // worst firing severity
	Scope          string `json:"scope"`           // "single" | "site"
	AgentCount     int    `json:"agent_count"`     // distinct agents alerting
	SuspectedLayer string `json:"suspected_layer"` // root-cause layer code
	// Attribution is the one-line user-language position ('' when evidence is
	// insufficient, e.g. merged multi-agent incidents); AttributionEvidence is
	// the typed clues behind it. Both travel structurally so the webhook carries
	// the raw data and every renderer picks its own wording/language.
	Attribution         string            `json:"attribution,omitempty"`
	AttributionEvidence []AttributionClue `json:"attribution_evidence,omitempty"`
	GroupName           string            `json:"group_name,omitempty"` // incident's frozen alert-group name
	// GroupMerged is true when the incident merges the whole group's alerts
	// (monitor_groups.merge_enabled), so a terminal notice may speak for the group
	// ("all alerts recovered"). False ⇒ a per-alert incident: sibling alerts in the
	// same group may still be firing, and the wording must stay per-alert.
	GroupMerged      bool              `json:"group_merged,omitempty"`
	Details          []FaultDetail     `json:"details,omitempty"`           // per-target firing facts (incident events)
	RecoveredTargets []RecoveredTarget `json:"recovered_targets,omitempty"` // targets that came back (resolved/terminated events)
	Agents           []AgentDetail     `json:"agents,omitempty"`            // per-agent facts (agent.offline / agent.recovered events)
	Storm            *StormDetail      `json:"storm,omitempty"`             // correlated burst facts (storm.* events)
	URL              string            `json:"url,omitempty"`               // deep link to the incident/agents view in the console
	At               time.Time         `json:"at"`
}

// StormDetail is a correlated burst's facts (ALERT-001): many faults confirmed
// at once from one Agent's vantage point, announced as a single message instead
// of one per fault.
//
// Both counts are carried because they answer different questions and only
// stating one would mislead: FaultCount is how many messages this notice
// replaced, GroupCount is how far the damage spread. A single unmerged group
// with five broken targets is five faults in one group, and a reader must be
// able to tell that from five groups each losing one.
type StormDetail struct {
	AgentName  string       `json:"agent_name"`           // frozen display name of the observing Agent
	FaultCount int          `json:"fault_count"`          // member incidents
	GroupCount int          `json:"group_count"`          // distinct monitor groups they span
	Groups     []StormGroup `json:"groups,omitempty"`     // per-group lines, worst first
	DurationS  int          `json:"duration_s,omitempty"` // how long the storm lasted (resolved events)
}

// StormGroup is one monitor group caught in a storm.
type StormGroup struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Layer    string `json:"layer"`
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
	ID   string `json:"id"`
	Name string `json:"name"` // human label to tell multiple channels apart
	// Type is one of the nine destinations: "webhook" (generic HTTP, templatable)
	// | "email" (SMTP) | "system" (native OS notification on the host process) |
	// "dingtalk" | "wecom" | "feishu" | "telegram" | "serverchan" | "wxpusher".
	// The last six are push platforms served by the Provider registry; each has
	// its own credential keys (see SecretKeys) rather than a URL.
	Type    string            `json:"type"`
	Config  map[string]string `json:"config"`
	Enabled bool              `json:"enabled"`
	// StormMerge decides whether this destination receives one summary when many
	// faults break out at once under a single Agent, or one message per fault
	// (ALERT-001). On by default: for a phone or a chat room, N messages about one
	// outage is the harm. Turn it off for a machine consumer — a ticketing webhook
	// or a log sink — that needs one record per incident and would be made lossy
	// by a summary.
	StormMerge bool `json:"storm_merge"`
}

type Service struct {
	db     *store.DB
	client *http.Client

	// nativeDeepLinks says the host process has a per-user nettact:// protocol
	// handler registered — the Desktop app on Windows. Only then may a native OS
	// notification carry a nettact:// URI: clicking one on a host without a
	// handler does nothing at all, which is worse than landing on a login page.
	//
	// It exists because a console URL and a native notification disagree about
	// what "the console" means. Payload.URL is built from console_base_url, which
	// may be a LAN IP, a hostname, or a reverse proxy — a different browser origin
	// from the 127.0.0.1 the Desktop authenticates against, and cookies are
	// per-origin. So a local toast click landed on the login page even though the
	// user was signed in. The deep link routes the click back through the Desktop,
	// which mints a fresh one-time login against whatever loopback address it is
	// actually serving right now. Email and webhook recipients are not on this
	// machine and keep the console URL regardless.
	nativeDeepLinks bool
}

func New(db *store.DB, nativeDeepLinks bool) *Service {
	return &Service{
		db:              db,
		client:          &http.Client{Timeout: 10 * time.Second},
		nativeDeepLinks: nativeDeepLinks,
	}
}

// nativeClickURL picks the click action for a native OS notification: a
// credential-free deep link when the host can receive one, else the console URL
// every other channel uses.
//
// The URI carries only an action and a resource ID — never a session, token, or
// any other secret — because it is visible to anything that can read the toast
// XML and is handed to the shell to route.
//
// A payload sets StormID or IncidentID, never both (notifypolicy builds storm
// and incident payloads separately), so the order below is only about being
// deterministic. A payload with neither — nothing addressable to open — falls
// back to the console URL rather than inventing a target.
func (s *Service) nativeClickURL(p Payload) string {
	if s.nativeDeepLinks {
		switch {
		case p.StormID != "":
			return "nettact://storm/" + url.PathEscape(p.StormID)
		case p.IncidentID != "":
			return "nettact://incident/" + url.PathEscape(p.IncidentID)
		}
	}
	return p.URL
}

const channelCols = `id, COALESCE(name,''), type, config, enabled, storm_merge`

func (s *Service) List(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+channelCols+` FROM notification_channels ORDER BY type, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		var cfg string
		var enabled, stormMerge int
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &cfg, &enabled, &stormMerge); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(cfg), &c.Config)
		c.Enabled = enabled == 1
		c.StormMerge = stormMerge == 1
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
	var enabled, stormMerge int
	err := s.db.QueryRowContext(ctx,
		`SELECT `+channelCols+` FROM notification_channels WHERE id=?`, id).
		Scan(&c.ID, &c.Name, &c.Type, &cfg, &enabled, &stormMerge)
	if err != nil {
		return Channel{}, err
	}
	_ = json.Unmarshal([]byte(cfg), &c.Config)
	c.Enabled = enabled == 1
	c.StormMerge = stormMerge == 1
	return c, nil
}

// Create adds a channel. Config is stored as JSON and the grouping choice is
// explicit so creation has the same delivery semantics as later edits.
func (s *Service) Create(ctx context.Context, name, typ string, config map[string]string, stormMerge bool) (string, error) {
	id := "chan_" + uuid.NewString()
	b, _ := json.Marshal(config)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO notification_channels(id, name, type, config, enabled, storm_merge) VALUES(?,?,?,?,1,?)`,
		id, name, typ, string(b), boolInt(stormMerge))
	return id, err
}

// Update edits a channel's name/enabled/storm-merge and, when config is non-nil,
// its config.
func (s *Service) Update(ctx context.Context, id, name string, enabled, stormMerge bool, config map[string]string) error {
	if config != nil {
		b, _ := json.Marshal(config)
		_, err := s.db.ExecContext(ctx,
			`UPDATE notification_channels SET name=?, enabled=?, storm_merge=?, config=? WHERE id=?`,
			name, boolInt(enabled), boolInt(stormMerge), string(b), id)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE notification_channels SET name=?, enabled=?, storm_merge=? WHERE id=?`,
		name, boolInt(enabled), boolInt(stormMerge), id)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
		default:
			// Push platforms (DingTalk / WeCom / Feishu / Telegram / ServerChan /
			// WxPusher) all deliver through one code path, so adding a platform is a
			// registry entry rather than another case here. An unregistered type is
			// silently skipped: a row can only carry one if the type allow-list was
			// bypassed, and a notification path is the wrong place to raise about it.
			if prov, ok := ProviderFor(typ); ok {
				s.sendProvider(ctx, typ, prov, config, p)
			}
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
			// Attribution clue lines lead so the recipient sees the reasoning
			// ("网关探测正常 ✓ …") without parsing the JSON; a storm or an
			// unattributed incident contributes no lines. A RESOLVED incident's
			// payload still carries the frozen outage evidence, and leading a
			// recovery notice with "gateway unreachable ✗" would contradict the
			// recovery it announces — clues only lead open/test fault events.
			Lines: append(clueLines(p, lang), RenderLines(p, lang)...),
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

// SamplePayload builds a representative payload for test sends: one HTTP-503
// fault on a single host, deep-linked into consoleBase when configured. The
// event is "test" so the rendered title/text and the {{event}} variable mark it
// clearly as a test, letting receivers distinguish it from a real incident.
//
// It feeds EVERY testable channel type, not just webhooks: the same payload is
// what a push provider renders through pushText, so a test send exercises the
// real rendering path rather than a special-cased "hello" string.
func SamplePayload(consoleBase string) Payload {
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
		Attribution:    "service",
		AttributionEvidence: []AttributionClue{{
			Kind:    ClueOnlyTargetFailing,
			Targets: []string{"Example Site"},
		}, {
			Kind:       ClueReason,
			ReasonCode: telemetry.ProbeReasonHTTPStatus,
		}},
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
	at := p.At.Local().Format(time.RFC3339)
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
	// The click URL is attached as the toast's click action (protocol activation
	// on Windows, a UN click handler on the desktop's macOS) rather than printed
	// into the body, so clicking the toast opens the incident page. See
	// nativeClickURL for why this is not simply p.URL.
	//
	// Native, not nativeNotify: a host that replaced the OS-notification path
	// with SetNativeNotify (the desktop app on macOS) must see incident toasts on
	// that path too, or they would land back on osascript's Script Editor.
	if err := Native(ctx, title, body, s.nativeClickURL(p)); err != nil {
		log.Printf("notify system: %v", err)
	}
}

// redact hides secrets when listing channels for the UI. Which keys count as
// secret is decided per channel type by SecretKeys — the same authority the API
// layer uses to merge masked values back on update — so a newly registered push
// provider is masked here without this function knowing it exists.
//
// Only non-empty values are masked: showing bullets for an unset optional
// credential (a DingTalk channel with no signing secret) would tell the operator
// a secret is configured when none is.
func redact(c Channel) Channel {
	if c.Config == nil {
		return c
	}
	out := make(map[string]string, len(c.Config))
	for k, v := range c.Config {
		out[k] = v
	}
	for _, k := range SecretKeys(c.Type) {
		if out[k] != "" {
			out[k] = MaskedSecret
		}
	}
	c.Config = out
	return c
}
