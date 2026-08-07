package notification

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// telegramMaxRunes is Telegram's documented message ceiling for sendMessage,
// counted in CHARACTERS and not bytes. It is a hard cap, not a soft one: over
// it the API does not trim, it rejects the whole request with
// {"ok":false,"error_code":400,"description":"Bad Request: message is too
// long"} — so a message that would have said something useful says nothing at
// all. Hence truncateRunes rather than truncateBytes; a byte cut at 4096 would
// throw away three quarters of a Chinese message that Telegram would have
// accepted whole.
const telegramMaxRunes = 4096

// telegramDefaultAPIBase is the public Bot API host, used when the channel does
// not override it.
const telegramDefaultAPIBase = "https://api.telegram.org"

// telegramProvider pushes to a Telegram chat through the Bot API's sendMessage
// method. Three of its choices are worth stating, because each has an obvious
// alternative that is wrong here:
//
//   - The bot token lives in the URL PATH (/bot<token>/sendMessage), not in a
//     header or the body. That is Telegram's design, not ours, and it is why
//     bot_token is in SecretKeys and why nothing in this package logs a
//     provider's built URL — the target string IS the credential.
//   - chat_id is marshalled as a JSON STRING and never parsed as a number.
//     Telegram accepts both a numeric id (negative for groups/supergroups, e.g.
//     -100123) and an "@channelusername" in the same field, and it accepts the
//     numeric form quoted. Parsing would therefore buy nothing and cost the
//     channel-name case, plus it would invite an int64 overflow bug on ids the
//     operator pasted from somewhere.
//   - api_base is overridable because api.telegram.org is unreachable from a
//     good share of the networks NetTact runs on. Operators there front the Bot
//     API with a reverse proxy on their own domain; without this key the whole
//     channel type would be unusable for them, and the alternative — telling
//     them to route the server's egress — is a much bigger hammer.
//
// No parse_mode is set, so the text is plain: Telegram then treats <, & and *
// as literal characters. With MarkdownV2 or HTML enabled, a target named
// "shop&cart" or an error string containing a "<" would make the API reject the
// message for a malformed entity, and escaping user data for a markup dialect
// the message does not need is work with only a downside.
type telegramProvider struct{}

// telegramMessage is the sendMessage request body. Field order is the wire
// order the tests assert on.
type telegramMessage struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

func (telegramProvider) ValidateConfig(cfg map[string]string) string {
	token := cfg["bot_token"]
	if strings.TrimSpace(token) == "" {
		return "telegram bot token is required"
	}
	// Checked on the RAW value, not a trimmed copy: Build pastes the token into
	// the URL path verbatim, so even leading/trailing whitespace — which a
	// trim-then-check would wave through while Build kept the original — builds
	// a broken request that comes back as an opaque 404. Reject it where it can
	// still be explained.
	if strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return "telegram bot token must not contain whitespace"
	}
	chatID := cfg["chat_id"]
	if strings.TrimSpace(chatID) == "" {
		return "telegram chat id is required"
	}
	// Same raw-value rule: chat_id goes into the JSON body verbatim, and no
	// legitimate id or @channelname contains whitespace.
	if strings.IndexFunc(chatID, unicode.IsSpace) >= 0 {
		return "telegram chat id must not contain whitespace"
	}
	// Raw prefix check: Build only trims trailing slashes, so a pasted leading
	// space would survive into the URL. Such a value fails this prefix test and
	// the message tells the operator what to fix.
	if base := cfg["api_base"]; strings.TrimSpace(base) != "" &&
		!strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return "telegram api base must start with http:// or https://"
	}
	return ""
}

// Build renders the headline and body into one plain-text message. now is
// unused — Telegram authenticates with the bearer-style token in the path and
// signs nothing — but the parameter stays because it is the Provider contract
// that DingTalk and Feishu need.
func (telegramProvider) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	base := strings.TrimRight(cfg["api_base"], "/")
	if base == "" {
		base = telegramDefaultAPIBase
	}
	lang := cfg["lang"]
	text := truncateRunes(RenderTitle(p, lang)+"\n"+pushText(p, lang), telegramMaxRunes)
	body, err := json.Marshal(telegramMessage{ChatID: cfg["chat_id"], Text: text})
	if err != nil {
		return "", nil, err
	}
	return base + "/bot" + cfg["bot_token"] + "/sendMessage", body, nil
}

// CheckResponse classifies a Bot API reply by its in-band ok flag, which is the
// authoritative one: Telegram answers a rejected sendMessage with the error
// code in BOTH the HTTP status and the envelope, but a reverse proxy in front
// of it (see api_base) is free to rewrite the status and frequently does.
//
// Decoding is deliberately lenient. deliverProvider hands this the first 512
// bytes of the response, so a long description arrives as truncated — and
// therefore invalid — JSON, and an api_base pointing at something that is not
// the Bot API replies with an HTML error page. Neither is a reason to invent a
// failure or to hide one, so an undecodable body falls back to the HTTP status
// alone; the caller shows the operator the snippet regardless.
func (telegramProvider) CheckResponse(status int, body []byte) error {
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		ErrorCode   int    `json:"error_code"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		if status >= 300 {
			return fmt.Errorf("http %d", status)
		}
		return nil
	}
	if r.OK {
		return nil
	}
	return fmt.Errorf("telegram error_code %d: %s", r.ErrorCode, r.Description)
}

// SecretKeys: bot_token alone. chat_id is a destination, not a credential — it
// stays readable so the console channel list can show which chat a channel
// targets.
func (telegramProvider) SecretKeys() []string { return []string{"bot_token"} }
