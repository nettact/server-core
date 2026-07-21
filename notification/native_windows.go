//go:build windows

package notification

import (
	"context"
	"encoding/base64"
	"os/exec"
	"syscall"
	"unicode/utf16"
)

// createNoWindow (CREATE_NO_WINDOW) stops Windows from allocating a console
// for powershell.exe — without it a console window flashes on every toast
// when the parent is a GUI process (the desktop app).
const createNoWindow = 0x08000000

// NativeSupported reports whether this build can pop OS desktop notifications.
func NativeSupported() bool { return true }

// appUserModelID is NetTact's own AppUserModelID. The toast is shown under it
// (not PowerShell's) so the notification is attributed to "NetTact" instead of
// "Windows PowerShell". It is a plain dotted string with no metacharacters, so
// it is safe inside the single-quoted PowerShell literals below.
const appUserModelID = "NetTact.ServerLite"

// nativeNotify shows a Windows toast via PowerShell + WinRT, attributed to
// NetTact. It first registers NetTact's AppUserModelID under
// HKCU\Software\Classes\AppUserModelId (idempotent, current-user only, no admin)
// with DisplayName "NetTact" — the documented way for an unpackaged app to give
// its toasts a proper source label — then shows the toast under that AppID.
//
// Incident text is untrusted (target names etc. flow into the summary), so it
// must never touch PowerShell or XML syntax: title/body/url are base64-encoded
// (UTF-8) and decoded at runtime, then inserted into the toast XML as DOM text
// nodes / attributes via CreateTextNode / SetAttribute (escaping handled on
// serialization). Base64 output is [A-Za-z0-9+/=] only, so it cannot break out
// of the surrounding single-quoted literals or trigger PowerShell expansion. The
// whole script is then passed via -EncodedCommand (base64 UTF-16LE) to avoid
// shell quoting entirely.
//
// When url is non-empty it is set as the toast's launch string with
// activationType="protocol", so clicking the toast opens the incident page in
// the default browser. Protocol activation is the one activation type that works
// for an unpackaged app without a registered COM activator.
func nativeNotify(ctx context.Context, title, body, url string) error {
	titleB64 := base64.StdEncoding.EncodeToString([]byte(title))
	bodyB64 := base64.StdEncoding.EncodeToString([]byte(body))
	urlB64 := base64.StdEncoding.EncodeToString([]byte(url))
	script := `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
$appId = '` + appUserModelID + `'
$regPath = "HKCU:\Software\Classes\AppUserModelId\$appId"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name DisplayName -Value 'NetTact'
$title = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + titleB64 + `'))
$body = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + bodyB64 + `'))
$url = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + urlB64 + `'))
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml('<toast><visual><binding template="ToastGeneric"><text></text><text></text></binding></visual></toast>')
if ($url) {
  $doc.DocumentElement.SetAttribute('launch', $url)
  $doc.DocumentElement.SetAttribute('activationType', 'protocol')
}
$texts = $doc.GetElementsByTagName('text')
[void]$texts.Item(0).AppendChild($doc.CreateTextNode($title))
[void]$texts.Item(1).AppendChild($doc.CreateTextNode($body))
$toast = New-Object Windows.UI.Notifications.ToastNotification $doc
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)`

	enc := base64.StdEncoding.EncodeToString(utf16LE(script))
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", enc)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow, HideWindow: true}
	return cmd.Run()
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}
