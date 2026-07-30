package notification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testConsoleURL   = "http://192.168.1.10:12450/incidents?incident=inc_1"
	testIncidentID   = "inc_2f1c9a4e-6b7d-4a11-9c33-0d5e8f7a2b64"
	testStormID      = "stm_7d4e1b02-33af-4c58-8e91-6a2b0c4d5e73"
	testStormConsole = "http://192.168.1.10:12450/incidents?storm=" + testStormID
)

// TestNativeClickURLSelection pins the whole point of the deep-link work: a
// native toast on a Desktop host must click through to the Desktop, which can
// authenticate the browser against its live loopback address, while every other
// situation keeps the console_base_url link. Getting this wrong is silent — the
// notification still appears, it just lands on a login page (capability wrongly
// off) or does nothing at all (capability wrongly on, no handler registered).
func TestNativeClickURLSelection(t *testing.T) {
	tests := []struct {
		name       string
		deepLinks  bool
		payload    Payload
		want       string
		wantScheme bool // want a nettact:// URI rather than the console URL
	}{
		{
			name:       "desktop incident uses deep link",
			deepLinks:  true,
			payload:    Payload{Event: "incident.opened", IncidentID: testIncidentID, URL: testConsoleURL},
			want:       "nettact://incident/" + testIncidentID,
			wantScheme: true,
		},
		{
			name:       "desktop agent offline is an incident too",
			deepLinks:  true,
			payload:    Payload{Event: "agent.offline", IncidentID: testIncidentID, URL: testConsoleURL},
			want:       "nettact://incident/" + testIncidentID,
			wantScheme: true,
		},
		{
			name:       "desktop storm uses storm deep link",
			deepLinks:  true,
			payload:    Payload{Event: "storm.opened", StormID: testStormID, URL: testStormConsole},
			want:       "nettact://storm/" + testStormID,
			wantScheme: true,
		},
		{
			// Nothing addressable to open: fall back rather than invent a target.
			name:      "desktop payload with no ids falls back to console url",
			deepLinks: true,
			payload:   Payload{Event: "incident.opened", URL: testConsoleURL},
			want:      testConsoleURL,
		},
		{
			// console_base_url unset upstream — still no deep link to invent.
			name:      "desktop payload with no ids and no url stays empty",
			deepLinks: true,
			payload:   Payload{Event: "incident.opened"},
			want:      "",
		},
		{
			name:      "standalone incident keeps console url",
			deepLinks: false,
			payload:   Payload{Event: "incident.opened", IncidentID: testIncidentID, URL: testConsoleURL},
			want:      testConsoleURL,
		},
		{
			name:      "standalone storm keeps console url",
			deepLinks: false,
			payload:   Payload{Event: "storm.opened", StormID: testStormID, URL: testStormConsole},
			want:      testStormConsole,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{nativeDeepLinks: tc.deepLinks}
			got := s.nativeClickURL(tc.payload)
			if got != tc.want {
				t.Fatalf("nativeClickURL = %q, want %q", got, tc.want)
			}
			if !tc.wantScheme && strings.Contains(got, "nettact://") {
				t.Fatalf("unexpected nettact:// scheme in %q", got)
			}
		})
	}
}

// TestNativeClickURLCarriesNoSecret guards the security constraint that the URI
// may contain only an action and a resource ID. It is handed to the shell and
// visible in the toast XML, so a token or session id in it would be readable by
// anything on the machine.
func TestNativeClickURLCarriesNoSecret(t *testing.T) {
	s := &Service{nativeDeepLinks: true}
	got := s.nativeClickURL(Payload{
		Event:      "incident.opened",
		IncidentID: testIncidentID,
		SiteID:     "site_default",
		URL:        testConsoleURL,
	})
	if got != "nettact://incident/"+testIncidentID {
		t.Fatalf("deep link carries more than the action and id: %q", got)
	}
	for _, banned := range []string{"token", "session", "password", "?", "&"} {
		if strings.Contains(got, banned) {
			t.Fatalf("deep link %q contains %q", got, banned)
		}
	}
}

// TestWebhookKeepsConsoleURLOnDesktop pins that the deep link never escapes the
// native channel. A webhook receiver is another machine; nettact:// would be
// unopenable there, and 127.0.0.1 would point at the receiver's own host.
func TestWebhookKeepsConsoleURLOnDesktop(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := webhookTestService()
	s.nativeDeepLinks = true // desktop host, deep links available
	p := webhookSamplePayload()
	p.URL = testConsoleURL

	if _, _, err := s.deliverWebhook(context.Background(), map[string]string{"url": srv.URL}, p); err != nil {
		t.Fatalf("deliver webhook: %v", err)
	}
	if strings.Contains(string(gotBody), "nettact://") {
		t.Fatalf("webhook body leaked a nettact:// deep link: %s", gotBody)
	}
	var body webhookBody
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("unmarshal webhook body: %v", err)
	}
	if body.URL != testConsoleURL {
		t.Fatalf("webhook url = %q, want console url %q", body.URL, testConsoleURL)
	}
}
