//go:build windows

package notification

import (
	"context"
	"encoding/xml"
	"os"
	"strings"
	"testing"
	"time"
)

// TestBuildToastXML checks the toast document is well-formed and that untrusted
// incident text (target names flow into title/body, the deep link into launch)
// is XML-escaped so it cannot break out of the document structure.
func TestBuildToastXML(t *testing.T) {
	doc := buildToastXML(
		`Alert <critical> & "urgent"`,
		"host</text><script>evil</script>",
		`https://x/i?a=1&b=<2>`,
	)

	// Must parse as XML — proof nothing escaped the element/attribute grammar.
	if err := xml.Unmarshal([]byte(doc), new(struct {
		XMLName xml.Name `xml:"toast"`
	})); err != nil {
		t.Fatalf("toast XML is not well-formed: %v\n%s", err, doc)
	}

	// The raw injection payloads must not appear verbatim.
	for _, bad := range []string{"<critical>", "<script>", "a=1&b=<2>"} {
		if strings.Contains(doc, bad) {
			t.Errorf("unescaped payload %q leaked into toast XML:\n%s", bad, doc)
		}
	}
	if !strings.Contains(doc, `activationType="protocol"`) {
		t.Errorf("expected protocol activation for a non-empty url:\n%s", doc)
	}
}

// TestBuildToastXMLNoURL omits the launch attributes when there is no deep link.
func TestBuildToastXMLNoURL(t *testing.T) {
	doc := buildToastXML("Recovered", "all clear", "")
	if strings.Contains(doc, "launch=") || strings.Contains(doc, "activationType=") {
		t.Errorf("did not expect launch attributes without a url:\n%s", doc)
	}
	if err := xml.Unmarshal([]byte(doc), new(struct {
		XMLName xml.Name `xml:"toast"`
	})); err != nil {
		t.Fatalf("toast XML is not well-formed: %v\n%s", err, doc)
	}
}

// TestNativeNotifySmoke fires a real toast through the full WinRT call chain. It
// must not panic, block, or error on a supported host. This is the regression
// guard for the COM syscall path that replaced the powershell.exe shell-out.
//
// It has real side effects (shows a toast, writes HKCU) and needs an interactive
// desktop session, so it is opt-in: a headless CI runner or Windows Server host
// without notification support would otherwise fail an ordinary `go test ./...`.
// Set NETTACT_TOAST_TEST=1 to run it.
func TestNativeNotifySmoke(t *testing.T) {
	if os.Getenv("NETTACT_TOAST_TEST") == "" {
		t.Skip("set NETTACT_TOAST_TEST=1 to run the real-toast integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := nativeNotify(ctx, "NetTact test", "notification self-test", ""); err != nil {
		t.Fatalf("nativeNotify: %v", err)
	}
}
