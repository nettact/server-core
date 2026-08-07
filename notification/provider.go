package notification

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Provider is one push platform's wire contract — DingTalk, WeCom, Feishu,
// Telegram, ServerChan, WxPusher. Each is a FIRST-CLASS channel type, not a
// preset of the generic webhook channel, and that is a deliberate choice worth
// stating because the preset route is the obvious one:
//
//   - All six report application failures as HTTP 200 with an in-band error code
//     ({"errcode":310000,…}). A webhook preset would call that a success and the
//     operator would watch a "working" channel deliver nothing. CheckResponse
//     exists so each platform can classify its own replies.
//   - DingTalk and Feishu sign the request at SEND time (HMAC over a timestamp).
//     A template language cannot compute an HMAC, and a `{{sign}}` variable would
//     have to bake platform crypto into the template engine anyway.
//   - Their credentials are discrete secrets (access_token, sendkey, bot_token …)
//     that must be masked when the console lists channels and merged back when an
//     edit round-trips. A webhook config has one opaque url field with no notion
//     of which part is a secret.
//
// The generic webhook channel deliberately stays OUTSIDE this interface: it
// supports GET/HEAD, custom methods, custom headers and a body template, none of
// which a fixed POST-JSON provider has any use for. Folding it in would mean
// implementing four methods that describe nothing.
type Provider interface {
	// ValidateConfig checks a channel config before it is stored or test-sent and
	// returns a user-facing English message, or "" when the config is valid. Same
	// shape and same style as validateWebhookConfig in the API layer, so the
	// handler treats every channel type identically.
	ValidateConfig(cfg map[string]string) string

	// Build renders p in cfg["lang"] and returns the POST target URL and the JSON
	// request body.
	//
	// now is the send instant. It is a parameter rather than a time.Now() call
	// inside each provider because DingTalk and Feishu embed it in their HMAC
	// signature: injecting it is what lets a test recompute the expected signature
	// and compare, instead of asserting "some base64 string is present".
	Build(cfg map[string]string, p Payload, now time.Time) (url string, body []byte, err error)

	// CheckResponse classifies a platform reply and returns nil only for a genuine
	// success. It MUST treat HTTP 200 with a non-zero in-band error code as a
	// failure — that is the normal failure mode on all six platforms (bad token,
	// bad signature, rate limit) and the whole reason this interface exists.
	CheckResponse(status int, body []byte) error

	// SecretKeys lists the config keys holding credentials. They are masked by
	// redact when the console lists channels, and merged back from storage by
	// MergeMaskedSecrets when an update or a test send echoes the mask instead of
	// re-typing the secret. The set is part of the channel's public contract (the
	// console renders those fields as password inputs), so it is fixed per type.
	SecretKeys() []string
}

// providers is the static channel-type registry. It is a plain map literal, and
// intentionally not an init()-time Register() call from each file: with a literal
// the full set of supported channel types is greppable in one place, and adding a
// type that nothing references is a compile error rather than a silent no-op.
var providers = map[string]Provider{
	"dingtalk":   dingTalkProvider{},
	"wecom":      weComProvider{},
	"feishu":     feishuProvider{},
	"telegram":   telegramProvider{},
	"serverchan": serverChanProvider{},
	"wxpusher":   wxPusherProvider{},
}

// ProviderFor looks up a push provider by channel type. The bool result is the
// single "is this a push channel type?" test used by the create/update/test
// handlers — no second allow-list of type strings exists anywhere.
func ProviderFor(typ string) (Provider, bool) {
	p, ok := providers[typ]
	return p, ok
}

// MaskedSecret is the placeholder the console sees in place of a stored
// credential, and the sentinel it posts back to mean "keep the stored value".
//
// The collision case — an operator whose real token IS six bullet characters —
// is accepted as absurd rather than defended against. Guarding it would need a
// per-field "unchanged" flag through the whole console/API/store path to protect
// a secret no platform would issue.
const MaskedSecret = "••••••"

// SecretKeys returns the credential config keys for ANY channel type: a
// registered provider's own set, ["password"] for email, and nil for webhook and
// system. It is the single authority behind both redact and the API's
// masked-value merge, so a new provider's secrets get masked and merged without
// touching either.
//
// A webhook's url is deliberately absent even though it frequently embeds a
// token: it is the channel's identity in the console list, and the audit layer
// already strips it to scheme://host. Feishu's webhook_url, by contrast, IS in
// the secret set — the surface inconsistency is intentional, because for a Feishu
// channel the URL is the only credential there is.
func SecretKeys(typ string) []string {
	if p, ok := providers[typ]; ok {
		return p.SecretKeys()
	}
	if typ == "email" {
		return []string{"password"}
	}
	return nil
}

// MergeMaskedSecrets replaces, in place, every posted secret value that is the
// mask with the stored value for that key.
//
// It exists because the console never receives real credentials: List redacts
// them, so an edit form shows bullets, and saving the form without retyping the
// token would otherwise overwrite the token WITH the bullets. Keys the caller
// posted with a real new value are left alone (that is a genuine rotation), and
// a mask with nothing stored behind it is left alone too, so per-type validation
// still gets to reject it rather than silently dropping the field.
func MergeMaskedSecrets(typ string, posted, stored map[string]string) {
	if posted == nil || stored == nil {
		return
	}
	for _, k := range SecretKeys(typ) {
		if posted[k] != MaskedSecret {
			continue
		}
		if v, ok := stored[k]; ok {
			posted[k] = v
		}
	}
}

// pushText is the shared plain-text body every push provider sends, rendered in
// lang. The line order mirrors the default webhook body (see webhookBody):
// diagnosis line, attribution clues, per-target fault lines, console link — so a
// DingTalk message and a webhook payload tell the same story in the same order,
// and only one ordering decision exists in the package.
//
// Providers render the headline separately with RenderTitle: some platforms carry
// a dedicated title field (ServerChan, WxPusher) and some prepend it to the text
// with their own prefix (DingTalk's keyword marker), so baking it in here would
// force half of them to strip it back out.
func pushText(p Payload, lang string) string {
	lines := make([]string, 0, 8)
	if scope := RenderScope(p, lang); scope != "" {
		lines = append(lines, scope)
	}
	lines = append(lines, clueLines(p, lang)...)
	lines = append(lines, RenderLines(p, lang)...)
	if link := LinkLine(p.URL, lang); link != "" {
		lines = append(lines, link)
	}
	return strings.Join(lines, "\n")
}

// ellipsis marks a truncated message. It is counted against the limit by both
// truncators: a platform that rejects an over-long body would reject "limit + 1
// character" just as hard as "limit + 1000".
const ellipsis = "…"

// truncateRunes caps s at n CHARACTERS, appending an ellipsis when it cuts.
// Telegram counts its 4096-character message limit in UTF-16 code units, which
// equals the rune count for everything short of astral-plane emoji — close
// enough that a rune count is the honest approximation and a byte count would be
// wildly wrong for Chinese text (3 bytes per character).
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	keep := n - utf8.RuneCountInString(ellipsis)
	if keep <= 0 {
		return ellipsis
	}
	i := 0
	for idx := range s {
		if i == keep {
			return s[:idx] + ellipsis
		}
		i++
	}
	return s
}

// truncateBytes caps s at n BYTES, appending an ellipsis when it cuts. WeCom
// states its limit in bytes, so a rune count would let a 2048-character Chinese
// message sail past a 2048-byte ceiling. The cut lands on a rune boundary: a
// half-written UTF-8 sequence is not text, and the platforms reject the whole
// message over it.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < len(ellipsis) {
		return ""
	}
	cut := n - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}

// deliverProvider sends one provider message and returns the HTTP status, a
// short snippet of the response body (first 512 bytes), and the classification
// error from CheckResponse.
//
// It returns the same (status, snippet, err) triple as deliverWebhook so the
// test-send endpoint reports both channel families through one response shape,
// and so the snippet carries the platform's own errmsg back to the operator —
// "errcode 310000: sign not match" is the one thing that makes a soft failure
// fixable.
//
// The transport is fixed POST + application/json for all six; a provider that
// needed anything else would not belong behind this interface.
func (s *Service) deliverProvider(ctx context.Context, prov Provider, cfg map[string]string, p Payload) (int, string, error) {
	target, body, err := prov.Build(cfg, p, time.Now())
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		// url.Parse failures echo the string they failed on, and for every
		// provider here that string embeds a credential. The URL is assembled
		// from validated config plus hard-coded bases, so this path is all but
		// unreachable — a generic message loses nothing worth a token.
		return 0, "", errors.New("building the provider request failed: invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		// client.Do wraps every failure in *url.Error, whose text leads with
		// the full request URL — a DingTalk access_token, a Telegram bot token
		// in the path, a ServerChan sendkey. The error flows into server logs
		// (sendProvider) and the test-send response, so unwrap to the transport
		// cause ("dial tcp …: connection refused") and drop the URL. The host
		// alone is not a secret, but the cause never needs the path or query to
		// be actionable.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	snippet := string(raw)
	return resp.StatusCode, snippet, prov.CheckResponse(resp.StatusCode, raw)
}

// sendProvider is the Notify path's wrapper: best-effort delivery, failures
// logged and swallowed. Mirrors sendWebhook — a notification must never block or
// fail the incident pipeline, and one broken chat room must not stop the other
// channels from being told.
//
// The log line names the channel TYPE and never the config, because every
// provider's identifying value is a credential (a DingTalk URL is its
// access_token) and a log file is not a place to put one.
func (s *Service) sendProvider(ctx context.Context, typ string, prov Provider, cfg map[string]string, p Payload) {
	status, snippet, err := s.deliverProvider(ctx, prov, cfg, p)
	switch {
	case err != nil:
		log.Printf("notify %s: %v (status %d, body %q)", typ, err, status, snippet)
	case status >= 300:
		log.Printf("notify %s: status %d (body %q)", typ, status, snippet)
	}
}

// TestProvider delivers p through prov WITHOUT persisting a channel, returning
// the HTTP status, a response snippet and any transport or classification error.
// It backs the "send test" button, and mirrors TestWebhook so the handler treats
// both channel families the same way.
func (s *Service) TestProvider(ctx context.Context, prov Provider, cfg map[string]string, p Payload) (int, string, error) {
	return s.deliverProvider(ctx, prov, cfg, p)
}
