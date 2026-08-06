package notification

import "context"

// Native pops a single OS desktop notification, bypassing the channel/policy
// pipeline entirely. It exists for hosts that need the same OS notification
// surface for their own messages — the desktop app's tray notices ("the agent
// stopped", "a new version is available") are not incidents and have no
// Payload, but they must land in the same place, look the same, and be
// attributed to the same app as the incident toasts this package already sends.
//
// It is exported rather than left to each host to reimplement because the
// platform-native path is not a one-liner: on Windows it is a WinRT
// (Windows.UI.Notifications) call on a dedicated COM apartment thread under a
// registered AppUserModelID. The obvious alternative — a Shell_NotifyIcon
// balloon from the tray icon the host already owns — is not equivalent: the
// Windows shell converts those to toasts only for a process it can attribute,
// and for an unpackaged binary it silently drops them instead, which is
// indistinguishable to the user from the app doing nothing at all.
//
// url, when non-empty, becomes the notification's click action where the
// platform can route one (Windows protocol activation); where it cannot
// (macOS), it is appended to the body text. Callers that need to know which
// they are getting — because the wording promises a click, or because they must
// perform the action themselves — must decide from the platform, not from the
// return value: a nil error means the notification was handed to the OS, not
// that it was displayed or clicked.
//
// title, body and url may be untrusted; both platform implementations escape
// them for their respective document/script syntax. Delivery is best-effort and
// bounded by ctx.
func Native(ctx context.Context, title, body, url string) error {
	return nativeNotify(ctx, title, body, url)
}
