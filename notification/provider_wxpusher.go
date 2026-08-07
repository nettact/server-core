package notification

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// wxPusherProvider pushes to WxPusher (wxpusher.zjiecode.com), a WeChat relay:
// the operator registers an "application" on the WxPusher console, recipients
// follow that application's WeChat service account, and anything POSTed with the
// application's appToken arrives as a WeChat message. There is no bot, no group
// webhook and no per-recipient credential — appToken is the ONLY secret, and the
// audience is addressed by two independent lists:
//
//   - uids — per-user ids ("UID_xxx") WxPusher hands out when someone subscribes;
//     the precise route, one message to exactly those people.
//   - topicIds — numeric ids of topics; everyone subscribed to the topic gets it,
//     so the audience changes without editing the channel.
//
// Either list alone is a complete address, and both may be given at once (the
// platform de-duplicates a user who is in both). At least one must be non-empty,
// because a message with neither has no recipients and WxPusher still answers
// 200 — an operator would watch a "healthy" channel deliver to nobody.
//
// Both lists live in a channel config that is a flat map[string]string, so they
// are stored as ONE delimited string each rather than as JSON arrays: the
// console edits them in a plain textarea, and operators paste ids one per line,
// comma-separated, or both. wxPusherSplitList is the single place that rule
// exists — Validate and Build call it, so what the console accepted is exactly
// what gets sent, and there is no second parser to drift.
//
// The classification trap this type exists for: WxPusher's success code is
// **1000**, not 0. Every other platform in this registry uses zero-means-ok, so
// a reflexive `code != 0` check here would report every successful send as a
// failure and every failure ({"code":1001,"msg":"appToken 校验失败"}) as a
// success. See CheckResponse.
type wxPusherProvider struct{}

// wxPusherEndpoint is fixed: WxPusher is a hosted service with a single send
// endpoint, so unlike DingTalk/Feishu there is no per-channel URL to configure —
// which is also why appToken is a discrete config key rather than something
// smuggled inside a webhook URL.
const wxPusherEndpoint = "https://wxpusher.zjiecode.com/api/send/message"

// wxPusherContentTypeText is WxPusher's contentType enum: 1 = plain text,
// 2 = HTML, 3 = Markdown. NetTact sends 1 because pushText builds a
// newline-separated plain-text body; under 2 those newlines would collapse (HTML
// ignores them) and under 3 the addresses and comparators in fault lines would
// be re-interpreted as markup.
const wxPusherContentTypeText = 1

// wxPusherSummaryRunes caps the summary, which is what WeChat shows in the
// notification banner and the chat list. WxPusher truncates anything longer
// itself; doing it here means the cut lands with an ellipsis instead of
// mid-sentence.
const wxPusherSummaryRunes = 20

// wxPusherContentRunes is WxPusher's documented content ceiling. Counted in
// runes, not bytes: the limit is a character limit and NetTact's default
// language is Chinese, where a byte count would cut a conforming message at a
// third of its allowance.
const wxPusherContentRunes = 40000

// wxPusherSplitList parses one config value into its ids. It accepts commas,
// spaces, tabs and newlines interchangeably — the console renders these fields
// as a free-form textarea, and an operator pasting a list from a spreadsheet,
// from the WxPusher console, or typing one per line must all work without a
// documented syntax. Empty fragments (a trailing comma, a blank line) vanish
// rather than becoming empty ids.
func wxPusherSplitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == '\v' || r == '\f'
	})
}

func (wxPusherProvider) ValidateConfig(cfg map[string]string) string {
	if strings.TrimSpace(cfg["app_token"]) == "" {
		return "wxpusher app token is required"
	}
	uids := wxPusherSplitList(cfg["uids"])
	topics := wxPusherSplitList(cfg["topic_ids"])
	if len(uids) == 0 && len(topics) == 0 {
		return "wxpusher needs at least one uid or topic id"
	}
	for _, t := range topics {
		if _, err := strconv.Atoi(t); err != nil {
			return "wxpusher topic id must be a number: " + t
		}
	}
	return ""
}

// wxPusherRequest is WxPusher's send body. The two recipient lists are
// omitempty so an absent audience is an absent key: WxPusher treats a present
// "uids":[] differently from no uids at all in some client versions, and a null
// (which a nil slice would marshal to without omitempty) is not a list.
type wxPusherRequest struct {
	AppToken    string   `json:"appToken"`
	Content     string   `json:"content"`
	Summary     string   `json:"summary"`
	ContentType int      `json:"contentType"`
	UIDs        []string `json:"uids,omitempty"`
	TopicIDs    []int    `json:"topicIds,omitempty"`
	URL         string   `json:"url,omitempty"`
}

// Build renders the message. now is unused — WxPusher authenticates with a
// static appToken and signs nothing — but stays in the signature because it is
// the Provider contract shared with DingTalk and Feishu, which do sign over it.
func (wxPusherProvider) Build(cfg map[string]string, p Payload, now time.Time) (string, []byte, error) {
	lang := cfg["lang"]
	title := RenderTitle(p, lang)

	// The title is prepended to the content as well as sent as summary: summary is
	// only the banner line, and a reader opening the message would otherwise see
	// the fault lines with no headline above them.
	content := truncateRunes(title+"\n"+pushText(p, lang), wxPusherContentRunes)

	topics := wxPusherSplitList(cfg["topic_ids"])
	var topicIDs []int
	for _, t := range topics {
		n, err := strconv.Atoi(t)
		if err != nil {
			return "", nil, fmt.Errorf("wxpusher: invalid topic id %q", t)
		}
		topicIDs = append(topicIDs, n)
	}

	body, err := json.Marshal(wxPusherRequest{
		AppToken:    cfg["app_token"],
		Content:     content,
		Summary:     truncateRunes(title, wxPusherSummaryRunes),
		ContentType: wxPusherContentTypeText,
		UIDs:        wxPusherSplitList(cfg["uids"]),
		TopicIDs:    topicIDs,
		URL:         p.URL,
	})
	if err != nil {
		return "", nil, err
	}
	return wxPusherEndpoint, body, nil
}

// wxPusherOK is WxPusher's success code. It is 1000, NOT 0 — see the type
// comment. 1001 is a bad appToken, 1002 an unknown uid; both arrive as HTTP 200.
const wxPusherOK = 1000

func (wxPusherProvider) CheckResponse(status int, body []byte) error {
	if status >= 300 {
		return fmt.Errorf("http %d", status)
	}
	var r struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	// Decoding is best-effort on purpose: deliverProvider hands us at most the
	// first 512 bytes of the response, so a long reply arrives as truncated —
	// invalid — JSON, and treating that as a delivery failure would be a lie about
	// a request the platform accepted. The raw snippet reaches the operator
	// through the test-send response either way, so nothing is hidden.
	if json.Unmarshal(body, &r) != nil {
		return nil
	}
	if r.Code != wxPusherOK {
		return fmt.Errorf("wxpusher code %d: %s", r.Code, r.Msg)
	}
	return nil
}

// SecretKeys: app_token alone. uids and topic_ids are recipients, not
// credentials, and stay readable so the console can summarize the channel's
// audience.
func (wxPusherProvider) SecretKeys() []string { return []string{"app_token"} }
