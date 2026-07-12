//go:build !windows && !darwin

package notification

import "context"

// NativeSupported reports whether this build can pop OS desktop notifications.
func NativeSupported() bool { return false }

// nativeNotify is a no-op on platforms without a supported desktop-notification
// mechanism (e.g. Linux servers). The "system" channel simply does nothing.
func nativeNotify(_ context.Context, _, _, _ string) error { return nil }
