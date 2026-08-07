package notification

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// dingTalkProvider pushes to a DingTalk (钉钉) group custom robot.
//
// The platform contract this implements:
//
//   - One endpoint, POST https://oapi.dingtalk.com/robot/send, with the robot's
//     access_token in the QUERY STRING. The token both identifies the robot and
//     authorizes the send — there is no separate credential — which is why it is
//     in SecretKeys and why the URL must never reach a log or the audit trail.
//   - A robot must have at least one of three security modes enabled, and the
//     mode is chosen in the DingTalk client, not here: (1) keyword — every
//     message body must contain one of the robot's configured keywords;
//     (2) IP allowlist — the sending host's egress IP must be listed, which
//     needs nothing from us; (3) 加签 (signing) — the request carries a
//     timestamp plus an HMAC of it, and the robot's "secret" (SECxxxx…) is the
//     key. Only (1) and (3) are visible in this file; a config with no secret is
//     therefore NOT an unauthenticated config, it is a keyword- or
//     allowlist-secured robot, which is why secret is optional.
//
// The signing direction is the subtle part and the one worth writing down,
// because it is inverted relative to Feishu and both produce a well-formed
// base64 string when swapped — a mistake that surfaces only as a remote
// errcode 310000 "sign not match", never as a local failure. DingTalk:
//
//	sign = base64(HMAC_SHA256(key = secret, message = timestamp + "\n" + secret))
//
// so the secret appears on BOTH sides — it is the HMAC key and it is also the
// tail of the signed message. Feishu's is the mirror image (the timestamp +
// "\n" + secret string is the KEY, over an empty message). Do not "simplify"
// either one into the other.
//
// The fixed "[NetTact] " content prefix exists for security mode (1). A
// keyword-mode robot matches a literal substring of the message text, and this
// channel renders its message in the operator's configured language — a robot
// keyed on "网络故障" would silently drop every message from an en channel, and
// one keyed on "Network fault" would drop every zh one. The prefix gives the
// operator a single keyword to configure that is stable across zh/en and across
// every event type (fault, recovery, storm, agent offline, test), so a robot set
// up once keeps working when the language or the incident kind changes. It is
// deliberately a constant and not derived from anything.
type dingTalkProvider struct{}

// dingTalkEndpoint is the robot send URL. Only the query differs per send.
const dingTalkEndpoint = "https://oapi.dingtalk.com/robot/send"

// dingTalkKeywordPrefix leads every message content; see the type comment for
// why it is fixed rather than localized.
const dingTalkKeywordPrefix = "[NetTact] "

// dingTalkMaxContentBytes caps the text content. It is a CONSERVATIVE
// self-imposed limit, not a number DingTalk publishes — the documented text
// message has no stated byte ceiling, and the observed behavior is a rejection
// somewhere in the tens of kilobytes. 20000 bytes is far past anything the
// renderers produce (maxDetailLines caps the fault list at 5 lines + a tail), so
// in practice this only fires on pathological target names; it exists so a
// runaway payload gets a delivered-but-clipped message instead of a remote
// reject that loses the whole notification. Bytes rather than runes because the
// unknown ceiling is far more likely to be a byte one, and zh text costs 3
// bytes per character.
const dingTalkMaxContentBytes = 20000

// dingTalkTextBody is the {"msgtype":"text"} message. Text (as opposed to
// markdown or actionCard) is the deliberate choice: it renders identically in
// the DingTalk mobile push preview, the desktop client and the message list,
// and an alert is read in the preview line more often than it is opened.
type dingTalkTextBody struct {
	MsgType string           `json:"msgtype"`
	Text    dingTalkTextPart `json:"text"`
}

type dingTalkTextPart struct {
	Content string `json:"content"`
}

// dingTalkReply is the in-band result envelope. Every DingTalk failure that is
// not a network failure arrives as HTTP 200 with a non-zero errcode (310000 bad
// signature / not in allowlist / no keyword, 300001 invalid token, 130101 rate
// limited), which is exactly the case Provider.CheckResponse exists for.
type dingTalkReply struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// ValidateConfig requires an access_token and rejects whitespace in it. The
// whitespace rule is not cosmetic: url.Values.Encode would faithfully
// percent-encode a stray space or a newline pasted along with the token from
// the DingTalk UI, and the robot would answer 300001 "token is not exist" —
// a remote error for a local, obvious mistake. The secret is not checked beyond
// being optional; only DingTalk can say whether it matches.
func (dingTalkProvider) ValidateConfig(cfg map[string]string) string {
	token := cfg["access_token"]
	if strings.TrimSpace(token) == "" {
		return "dingtalk access_token is required"
	}
	if strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return "dingtalk access_token must not contain whitespace"
	}
	return ""
}

// Build renders the message and returns the signed send URL and the JSON body.
// cfg is assumed to have passed ValidateConfig (the API layer runs it before
// storing or test-sending); a bad token here just produces the robot's own
// errcode, which is a better error message than anything this layer could
// invent.
func (dingTalkProvider) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	q := url.Values{"access_token": {cfg["access_token"]}}
	if secret := cfg["secret"]; secret != "" {
		// now is injected rather than read here so a test can recompute this
		// exact signature; see Provider.Build. Milliseconds, and DingTalk
		// rejects a timestamp more than an hour from its own clock.
		ts := strconv.FormatInt(now.UnixMilli(), 10)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "\n" + secret))
		q.Set("timestamp", ts)
		// Encode() escapes the base64 (+ / =) for us — never hand-concatenate.
		q.Set("sign", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}

	lang := cfg["lang"]
	content := truncateBytes(dingTalkKeywordPrefix+RenderTitle(p, lang)+"\n"+pushText(p, lang), dingTalkMaxContentBytes)
	body, err := json.Marshal(dingTalkTextBody{MsgType: "text", Text: dingTalkTextPart{Content: content}})
	if err != nil {
		return "", nil, err
	}
	return dingTalkEndpoint + "?" + q.Encode(), body, nil
}

// CheckResponse classifies a robot reply: a transport-level status is an error,
// and so is an HTTP 200 carrying a non-zero errcode.
//
// Decoding is deliberately lenient — an unparseable or empty body is reported
// as success rather than as a decode failure. Two reasons: deliverProvider
// passes only the first 512 bytes of the response, so a long body can arrive
// truncated mid-JSON through no fault of the robot; and that same snippet is
// handed straight back to the operator by the test-send endpoint, so a genuinely
// broken reply is visible to a human anyway. Inventing a "malformed response"
// error here would only turn a working delivery into a scary red result.
func (dingTalkProvider) CheckResponse(status int, body []byte) error {
	if status >= 300 {
		return fmt.Errorf("http %d", status)
	}
	var reply dingTalkReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return nil
	}
	if reply.ErrCode != 0 {
		return fmt.Errorf("dingtalk errcode %d: %s", reply.ErrCode, reply.ErrMsg)
	}
	return nil
}

// SecretKeys: access_token identifies AND authorizes the robot; secret is the
// optional signing key for the "加签" security mode.
func (dingTalkProvider) SecretKeys() []string { return []string{"access_token", "secret"} }
