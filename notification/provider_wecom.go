package notification

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// weComProvider pushes to a WeCom (企业微信) group robot webhook.
//
// The platform contract is unusually thin, and every field below follows from
// it. A group robot has exactly one endpoint,
// https://qyapi.weixin.qq.com/cgi-bin/webhook/send, and the whole credential is
// the key query parameter: there is no app id, no secret, no access-token
// exchange and no request signature, so possession of the key IS authorization
// to post into that chat. That is why key is the sole config field and the sole
// entry in SecretKeys, and why Build ignores now — nothing in the request is
// time-bound, unlike DingTalk's and Feishu's HMAC.
//
// The message is sent as msgtype "text" rather than "markdown" because the body
// pushText produces is plain lines with no markup to render, and WeCom's
// markdown flavor would eat the punctuation in URLs and metric expressions.
//
// WeCom documents a hard 2048-BYTE cap on a text message's content and rejects
// the whole message when it is exceeded, so Build truncates rather than letting
// a site-wide storm silently deliver nothing. Bytes, not characters: a 2048-rune
// Chinese message is ~6 KB on the wire, which is why the shared byte truncator
// exists at all (see truncateBytes).
//
// Failures come back as HTTP 200 with an in-band {"errcode":93000,…}, which is
// what CheckResponse is for.
type weComProvider struct{}

// weComContentBytes is WeCom's documented maximum size of a text message's
// content field, counted in UTF-8 bytes. Over it, the API rejects the message
// outright, so we cut it down instead.
const weComContentBytes = 2048

// weComSendURL is the group-robot endpoint; the key query parameter carries the
// entire credential.
const weComSendURL = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key="

// weComTextBody is the msgtype "text" request envelope.
type weComTextBody struct {
	MsgType string      `json:"msgtype"`
	Text    weComTextIn `json:"text"`
}

type weComTextIn struct {
	Content string `json:"content"`
}

// weComReply is the shared shape of every WeCom API response. errcode 0 is the
// only success.
type weComReply struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

func (weComProvider) ValidateConfig(cfg map[string]string) string {
	key := cfg["key"]
	if strings.TrimSpace(key) == "" {
		return "wecom key is required"
	}
	// Whitespace anywhere in the key is always a paste artifact — the robot key
	// is a UUID-shaped token — and rejecting it here beats a mystery errcode
	// 93000 at send time.
	if strings.ContainsAny(key, " \t\r\n") {
		return "wecom key must not contain whitespace"
	}
	return ""
}

// Build renders the notification into a text message. now is unused: the WeCom
// request carries no timestamp and no signature. It stays in the signature
// because Provider is one interface for six platforms, half of which sign.
func (weComProvider) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	lang := cfg["lang"]
	// No prefix marker here: unlike DingTalk's keyword security mode, a WeCom
	// robot's key is the only gate, so the headline is just the first line.
	content := RenderTitle(p, lang) + "\n" + pushText(p, lang)
	body, err := json.Marshal(weComTextBody{
		MsgType: "text",
		Text:    weComTextIn{Content: truncateBytes(content, weComContentBytes)},
	})
	if err != nil {
		return "", nil, err
	}
	return weComSendURL + url.QueryEscape(cfg["key"]), body, nil
}

// CheckResponse classifies a WeCom reply. A malformed or empty body is
// deliberately NOT an error: the caller already hands the operator the raw
// response snippet, and deliverProvider passes only the first 512 bytes here, so
// a long reply arrives truncated mid-JSON. Inventing a failure out of "I could
// not parse this" would flag working channels as broken.
func (weComProvider) CheckResponse(status int, body []byte) error {
	if status >= 300 {
		return fmt.Errorf("http %d", status)
	}
	var r weComReply
	if err := json.Unmarshal(body, &r); err != nil {
		return nil
	}
	if r.ErrCode != 0 {
		return fmt.Errorf("wecom errcode %d: %s", r.ErrCode, r.ErrMsg)
	}
	return nil
}

// SecretKeys: key is the robot's only credential — anyone holding it can post
// to the group.
func (weComProvider) SecretKeys() []string { return []string{"key"} }
