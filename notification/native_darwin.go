//go:build darwin

package notification

import (
	"context"
	"os/exec"
	"strings"
)

// NativeSupported reports whether this build can pop OS desktop notifications.
func NativeSupported() bool { return true }

// nativeNotify shows a macOS notification via osascript. title/body are escaped
// for embedding inside an AppleScript double-quoted string literal to avoid
// injection from arbitrary incident text. A plain `display notification` has no
// click action, so url (when set) is appended to the body text rather than made
// clickable.
func nativeNotify(ctx context.Context, title, body, url string) error {
	if url != "" {
		body = body + " " + url
	}
	script := "display notification \"" + escapeAppleScript(body) +
		"\" with title \"" + escapeAppleScript(title) + "\""
	return exec.CommandContext(ctx, "osascript", "-e", script).Run()
}

func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	// AppleScript string literals cannot span raw newlines; collapse them.
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
