package notification

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// feishuProvider pushes to a Feishu / Lark (飞书) group custom bot
// (自定义机器人) via the webhook URL the operator copies out of the bot's setup
// dialog.
//
// Three things about this platform drive the shape of the code below, and none
// of them are guessable from the other providers:
//
//   - The webhook URL IS the credential. Feishu does not split "endpoint" from
//     "token": the hook id in the path is the entire authorization, so anyone
//     holding the URL can post to the group. That is why webhook_url is in
//     SecretKeys here while the generic webhook channel's url is not — for a
//     Feishu channel there is nothing else to mask.
//
//   - The optional signing key (签名校验) is used BACKWARDS relative to
//     DingTalk, and getting this wrong yields a 19021 "sign match fail" that
//     looks like a typo'd secret. DingTalk signs the string
//     "<timestamp>\n<secret>" USING the secret as the HMAC key. Feishu instead
//     builds the HMAC KEY from "<timestamp>\n<secret>" and signs an EMPTY
//     message — i.e. the digest is mac.Sum(nil) with no Write at all. Feishu
//     also counts its timestamp in SECONDS where DingTalk uses milliseconds, and
//     transmits it as a JSON string rather than a number. Both quirks are
//     deliberate on their side and non-negotiable on ours.
//
//   - Replies come in two shapes. Current bots answer {"code":0,"msg":"success"}
//     and older ones {"StatusCode":0,"StatusMessage":"success"}; a group that
//     was created years ago can still be on the legacy shape today. Both are
//     decoded into one struct (see feishuReply) rather than sniffed, because the
//     absent field of either shape decodes to 0, which is exactly the "no error"
//     value.
type feishuProvider struct{}

// feishuMaxTextBytes caps the message text. Feishu does not publish a hard limit
// for text messages, so this is a conservative self-imposed ceiling rather than
// a documented one: large enough that a real incident notification is never cut,
// small enough that a pathological payload cannot turn into a multi-megabyte
// POST. Bytes, not runes, because any real server-side limit will be counted in
// bytes and Chinese text costs three per character.
const feishuMaxTextBytes = 20000

// feishuBody is the custom-bot request. timestamp and sign are omitempty: an
// unsigned bot rejects a request that carries them at all, so "no secret
// configured" must mean the keys are absent from the JSON, not present and
// empty.
type feishuBody struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Sign      string     `json:"sign,omitempty"`
	MsgType   string     `json:"msg_type"`
	Content   feishuText `json:"content"`
}

type feishuText struct {
	Text string `json:"text"`
}

// feishuReply carries both reply shapes at once — see the type comment on
// feishuProvider. Absent fields decode to 0, which is each shape's success
// value, so a response in either format is classified correctly without asking
// which format it is.
type feishuReply struct {
	Code       int    `json:"code"`
	Msg        string `json:"msg"`
	StatusCode int    `json:"StatusCode"`
}

// ValidateConfig mirrors validateWebhookConfig's prefix check and message tone:
// the URL is checked for a scheme prefix rather than fully parsed, since the
// only failure worth catching here is an operator pasting the bot's id or a
// "lark.com/..." fragment instead of the whole hook URL. secret is optional —
// signing is a per-bot opt-in on Feishu's side.
func (feishuProvider) ValidateConfig(cfg map[string]string) string {
	u := strings.TrimSpace(cfg["webhook_url"])
	if u == "" {
		return "feishu webhook url is required"
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "feishu webhook url must start with http:// or https://"
	}
	return ""
}

// Build posts the URL exactly as the operator pasted it — the hook id lives in
// the path and there is no query parameter to add — with a plain text message.
// The headline is prepended to the body text because a Feishu text message has
// no title field of its own.
func (feishuProvider) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	target := strings.TrimSpace(cfg["webhook_url"])
	if target == "" {
		return "", nil, fmt.Errorf("feishu webhook url is empty")
	}
	lang := cfg["lang"]
	content := truncateBytes(RenderTitle(p, lang)+"\n"+pushText(p, lang), feishuMaxTextBytes)

	body := feishuBody{MsgType: "text", Content: feishuText{Text: content}}
	if secret := strings.TrimSpace(cfg["secret"]); secret != "" {
		ts := strconv.FormatInt(now.Unix(), 10)
		body.Timestamp = ts
		body.Sign = feishuSign(ts, secret)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", nil, err
	}
	return target, raw, nil
}

// feishuSign computes the 签名校验 digest: HMAC-SHA256 whose KEY is
// "<timestamp>\n<secret>" over an EMPTY message, base64 std-encoded. The empty
// message is not an oversight — Sum(nil) without a preceding Write is the whole
// algorithm, and it is the inverse of DingTalk's arrangement (see the type
// comment). Kept as a named function so the test can state the same recipe
// independently and compare.
func feishuSign(ts, secret string) string {
	mac := hmac.New(sha256.New, []byte(ts+"\n"+secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// CheckResponse classifies the reply. A non-2xx status is reported by status
// alone; otherwise the in-band code decides, because Feishu answers a rejected
// signature or a disabled bot with HTTP 200.
//
// Decoding is deliberately lenient: an unparseable or empty body degrades to
// success rather than to an error. deliverProvider already hands the operator
// the first 512 bytes of the response, so an odd reply is visible either way,
// and that truncation means a long valid JSON body can arrive here as a
// syntactically broken fragment — turning "I could not parse this" into "your
// channel is broken" would manufacture failures out of a display limit.
func (feishuProvider) CheckResponse(status int, body []byte) error {
	if status >= 300 {
		return fmt.Errorf("http %d", status)
	}
	var r feishuReply
	if json.Unmarshal(body, &r) != nil {
		return nil
	}
	// Either shape's success value is 0 and the other shape's field is absent
	// (also 0), so a non-zero in EITHER field is a real error code.
	code := r.Code
	if code == 0 {
		code = r.StatusCode
	}
	if code == 0 {
		return nil
	}
	if r.Msg != "" {
		return fmt.Errorf("feishu code %d: %s", code, r.Msg)
	}
	return fmt.Errorf("feishu code %d", code)
}

// SecretKeys: webhook_url is a secret here — unlike the generic webhook
// channel's url, it embeds the bot's hook id and is the whole credential — and
// secret is the optional signing key.
func (feishuProvider) SecretKeys() []string { return []string{"webhook_url", "secret"} }
