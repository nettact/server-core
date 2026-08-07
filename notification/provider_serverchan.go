package notification

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// serverChanKeyPattern recognizes a Server酱³ send key by its own shape:
// "sctp" + the account's numeric id + "t" + the random tail (sctp12345t…). The
// captured id IS the subdomain of that account's shard, which is what makes the
// endpoint derivable from the key alone. Turbo keys ("SCT…") carry no id and go
// to one shared host.
//
// Compiled once at package level rather than inside Build: Build runs per
// delivery, and MustCompile on every notification would be pure waste plus a
// panic risk moved from process start to send time.
var serverChanKeyPattern = regexp.MustCompile(`^sctp(\d+)t`)

const (
	// serverChanTitleRunes is ServerChan's documented 32-character title limit.
	// Counted in RUNES, not bytes: the limit is stated in characters and a Chinese
	// headline is 3 bytes per character, so a byte cap would cut a legitimate
	// 11-character title.
	serverChanTitleRunes = 32

	// serverChanDespBytes caps the body. ServerChan publishes no exact desp limit,
	// so this is a deliberately conservative self-imposed ceiling rather than a
	// documented one — big enough that no real notification ever reaches it (a
	// storm message is a few hundred bytes), small enough that a pathological
	// payload cannot post a megabyte at a chat relay.
	serverChanDespBytes = 30000
)

// serverChanProvider pushes to Server酱 (ServerChan), a personal WeChat push
// relay: it has no bot, no room and no webhook URL to create — one send key
// addresses one person's WeChat, and posting title+desp to it delivers a service
// notification to that person's phone. The key is therefore both the address and
// the credential (hence SecretKeys).
//
// TWO GENERATIONS COEXIST, and the only thing that tells them apart is the shape
// of the key the operator pastes in:
//
//   - Turbo keys look like "SCT12345abcdef" and post to the single shared host
//     https://sctapi.ftqq.com/<key>.send.
//   - Server酱³ keys look like "sctp12345tabcdef", where 12345 is the account id
//     and also the subdomain of the shard serving it:
//     https://12345.push.ft07.com/send/<key>.send.
//
// So the endpoint is derived from the key instead of being a second config field
// or a "version" dropdown. That is on purpose: the operator copies one string off
// the ServerChan dashboard and has no idea which generation issued it, and a
// mis-set dropdown would fail with an unrelated-looking 404. The key format is
// self-describing, so we read it rather than ask.
//
// MARKDOWN NEWLINE QUIRK: desp is rendered as markdown, where a single "\n" is
// NOT a line break — it collapses into the previous line, and the carefully
// ordered fault lines from pushText would arrive as one run-on paragraph. Every
// newline is therefore doubled into a blank line, which markdown does honor as a
// paragraph break. Doubling beats emitting markdown list syntax ("- " prefixes)
// because pushText is shared with platforms that render plain text and would show
// the bullets literally.
type serverChanProvider struct{}

func (serverChanProvider) ValidateConfig(cfg map[string]string) string {
	key := cfg["sendkey"]
	if strings.TrimSpace(key) == "" {
		return "serverchan sendkey is required"
	}
	// The key is spliced into the request path, so stray whitespace from a paste
	// is not a cosmetic issue: it would build a broken URL that fails as a 404.
	if strings.IndexFunc(key, unicode.IsSpace) >= 0 {
		return "serverchan sendkey must not contain whitespace"
	}
	return ""
}

// serverChanURL derives the send endpoint from the key generation. See the type
// comment for why this is inferred rather than configured.
func serverChanURL(key string) string {
	if m := serverChanKeyPattern.FindStringSubmatch(key); m != nil {
		return "https://" + m[1] + ".push.ft07.com/send/" + key + ".send"
	}
	return "https://sctapi.ftqq.com/" + key + ".send"
}

// Build renders the title/desp pair. now is unused — ServerChan authenticates by
// the key in the path and signs nothing, so there is no send instant to embed —
// but the parameter stays because it is the Provider contract shared with the
// HMAC-signing providers.
func (serverChanProvider) Build(cfg map[string]string, p Payload, _ time.Time) (string, []byte, error) {
	key := cfg["sendkey"]
	if key == "" {
		return "", nil, errors.New("serverchan: sendkey is empty")
	}
	lang := cfg["lang"]
	body, err := json.Marshal(struct {
		Title string `json:"title"`
		Desp  string `json:"desp"`
	}{
		Title: truncateRunes(RenderTitle(p, lang), serverChanTitleRunes),
		Desp:  truncateBytes(strings.ReplaceAll(pushText(p, lang), "\n", "\n\n"), serverChanDespBytes),
	})
	if err != nil {
		return "", nil, err
	}
	return serverChanURL(key), body, nil
}

// CheckResponse classifies a ServerChan reply. Both generations answer
// {"code":0,"message":"","data":{…}} on success and reuse HTTP 200 for
// application failures (40001 = bad sendkey), which is exactly the case the
// Provider interface exists for.
//
// Decoding is deliberately LENIENT: an undecodable or empty body is reported as
// success rather than as an error. deliverProvider hands this the first 512 bytes
// only, so a long success reply arrives as truncated (invalid) JSON — treating
// that as a failure would flag working channels as broken. The raw snippet is
// surfaced to the operator either way, so nothing is hidden by the leniency.
func (serverChanProvider) CheckResponse(status int, body []byte) error {
	if status >= 300 {
		return fmt.Errorf("http %d", status)
	}
	var r struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil
	}
	if r.Code == 0 {
		return nil
	}
	if r.Message != "" {
		return fmt.Errorf("serverchan code %d: %s", r.Code, r.Message)
	}
	return fmt.Errorf("serverchan code %d", r.Code)
}

// SecretKeys: sendkey is both the address and the credential.
func (serverChanProvider) SecretKeys() []string { return []string{"sendkey"} }
