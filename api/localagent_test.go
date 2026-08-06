package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store/storetest"
)

// fakeLocalAgent is an in-memory LocalAgentAPI standing in for the desktop's
// implementation. It keeps the enrollment tokens it was handed in a field the
// API layer can never reach, which is what lets a test assert both halves of the
// write-only rule: the token got through to the implementation, and it never
// appears in a response.
type fakeLocalAgent struct {
	servers []LocalAgentServer
	tokens  map[string]string
	failure error // forced non-sentinel failure, for the 500 path
}

func newFakeLocalAgent() *fakeLocalAgent {
	return &fakeLocalAgent{tokens: map[string]string{}}
}

// fakeRecommendedPermissions is this fake's answer to an unspecified permission
// list — the seam's "implementation's recommended default".
func fakeRecommendedPermissions() []string { return permission.Bundles()[0].Set.Strings() }

// resolveGrant is the rule every implementation of the seam owes the contract:
// nil defers to the recommendation, and anything else — empty included — is
// taken literally.
func resolveGrant(p *[]string) []string {
	if p == nil {
		return fakeRecommendedPermissions()
	}
	return *p
}

func (f *fakeLocalAgent) index(name string) int {
	for i, s := range f.servers {
		if s.Name == name {
			return i
		}
	}
	return -1
}

func (f *fakeLocalAgent) List(ctx context.Context) ([]LocalAgentServer, error) {
	if f.failure != nil {
		return nil, f.failure
	}
	return append([]LocalAgentServer(nil), f.servers...), nil
}

func (f *fakeLocalAgent) Add(ctx context.Context, spec LocalAgentServerSpec) (LocalAgentServer, error) {
	if f.failure != nil {
		return LocalAgentServer{}, f.failure
	}
	if f.index(spec.Name) >= 0 {
		// Wrapped on purpose: the handler must match with errors.Is, not ==.
		return LocalAgentServer{}, fmt.Errorf("add %q: %w", spec.Name, ErrLocalAgentDuplicate)
	}
	srv := LocalAgentServer{
		Name:        spec.Name,
		URL:         spec.URL,
		TLSInsecure: spec.TLSInsecure,
		Permissions: resolveGrant(spec.Permissions),
		Status:      LocalAgentServerStatus{State: "connecting"},
	}
	f.servers = append(f.servers, srv)
	f.tokens[spec.Name] = spec.EnrollToken
	return srv, nil
}

func (f *fakeLocalAgent) Remove(ctx context.Context, name string) error {
	i := f.index(name)
	if i < 0 {
		return fmt.Errorf("remove %q: %w", name, ErrLocalAgentNotFound)
	}
	f.servers = append(f.servers[:i], f.servers[i+1:]...)
	delete(f.tokens, name)
	return nil
}

func (f *fakeLocalAgent) SetPermissions(ctx context.Context, name string, permissions *[]string) error {
	i := f.index(name)
	if i < 0 {
		return fmt.Errorf("set permissions %q: %w", name, ErrLocalAgentNotFound)
	}
	f.servers[i].Permissions = resolveGrant(permissions)
	return nil
}

// localAgentTestDeps builds a Deps with a logged-in admin session, returning the
// session id so requests go through the real router (route table included)
// rather than calling handlers directly.
func localAgentTestDeps(t *testing.T, la LocalAgentAPI) (Deps, string) {
	t.Helper()
	db := storetest.Open(t)
	id := identity.New(db)
	admin, _, err := id.EnsureAdmin(context.Background(), "admin", "local-agent-test-pw")
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	sid, _, err := id.CreateSession(context.Background(), admin.ID)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	d := Deps{Identity: id, Audit: audit.New(db), Settings: settings.New(db)}
	if la != nil {
		d.LocalAgent = la
	}
	return d, sid
}

func localAgentRequest(t *testing.T, d Deps, sid, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	w := httptest.NewRecorder()
	Router(d).ServeHTTP(w, req)
	return w
}

// decodeLocalAgentServers reads the {"servers": […]} envelope.
func decodeLocalAgentServers(t *testing.T, w *httptest.ResponseRecorder) []LocalAgentServer {
	t.Helper()
	var resp struct {
		Servers []LocalAgentServer `json:"servers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode servers: %v (body=%s)", err, w.Body.String())
	}
	return resp.Servers
}

func TestLocalAgentRoutesAbsentWithoutSeam(t *testing.T) {
	d, sid := localAgentTestDeps(t, nil)

	cases := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/local-agent/servers", ""},
		{http.MethodPost, "/api/v1/local-agent/servers", `{"url":"https://server.example.com","enroll_token":"tok"}`},
		{http.MethodDelete, "/api/v1/local-agent/servers/work", ""},
		{http.MethodPut, "/api/v1/local-agent/servers/work/permissions", `{"permissions":["probe.icmp"]}`},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			w := localAgentRequest(t, d, sid, c.method, c.path, c.body)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	// The capability bit must be absent too, so the console never renders the
	// panel on a server whose routes are 404.
	w := localAgentRequest(t, d, sid, http.MethodGet, "/api/v1/server-info", "")
	if strings.Contains(w.Body.String(), "local_agent") {
		t.Fatalf("server-info advertises local_agent without a seam: %s", w.Body.String())
	}
}

func TestLocalAgentRoutesRequireSession(t *testing.T) {
	d, _ := localAgentTestDeps(t, newFakeLocalAgent())

	w := httptest.NewRecorder()
	Router(d).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/local-agent/servers", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestServerInfoLocalAgentCapability(t *testing.T) {
	d, sid := localAgentTestDeps(t, newFakeLocalAgent())

	w := localAgentRequest(t, d, sid, http.MethodGet, "/api/v1/server-info", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		LocalAgent bool `json:"local_agent"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.LocalAgent {
		t.Fatalf("local_agent not advertised: %s", w.Body.String())
	}
}

func TestListLocalAgentServersEmptyIsArray(t *testing.T) {
	d, sid := localAgentTestDeps(t, newFakeLocalAgent())

	w := localAgentRequest(t, d, sid, http.MethodGet, "/api/v1/local-agent/servers", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"servers":[]}` {
		t.Fatalf("body=%q; want an empty array, never null", got)
	}
}

func TestAddLocalAgentServerRejectsInvalidPayloads(t *testing.T) {
	d, sid := localAgentTestDeps(t, newFakeLocalAgent())

	cases := map[string]string{
		"malformed":          `{"url":`,
		"unknown field":      `{"url":"https://server.example.com","enroll_token":"tok","nope":true}`,
		"multiple values":    `{"url":"https://server.example.com","enroll_token":"tok"} {}`,
		"missing url":        `{"enroll_token":"tok"}`,
		"blank url":          `{"url":"   ","enroll_token":"tok"}`,
		"bad scheme":         `{"url":"ftp://server.example.com","enroll_token":"tok"}`,
		"opaque scheme":      `{"url":"server.example.com:12450","enroll_token":"tok"}`,
		"no host":            `{"url":"http://","enroll_token":"tok"}`,
		// url.Parse reads this as a host of ":12450", which is non-empty and names
		// nothing. Supplying a name skips the derivation that would otherwise have
		// caught it, so without a Hostname() check it persists an undialable entry.
		"port only":          `{"url":"http://:12450","enroll_token":"tok","name":"work"}`,
		"port only derived":  `{"url":"http://:12450","enroll_token":"tok"}`,
		"path":               `{"url":"https://server.example.com/agents","enroll_token":"tok"}`,
		"query":              `{"url":"https://server.example.com?site=default","enroll_token":"tok"}`,
		"fragment":           `{"url":"https://server.example.com/#/agents","enroll_token":"tok"}`,
		"credentials":        `{"url":"https://admin:hunter2@server.example.com","enroll_token":"tok"}`,
		"long url":           `{"url":"https://` + strings.Repeat("a", maxLocalAgentURLLength) + `.example.com","enroll_token":"tok"}`,
		"name charset":       `{"name":"Work Server","url":"https://server.example.com","enroll_token":"tok"}`,
		"name leading dash":  `{"name":"-work","url":"https://server.example.com","enroll_token":"tok"}`,
		"name too long":      `{"name":"` + strings.Repeat("w", 65) + `","url":"https://server.example.com","enroll_token":"tok"}`,
		"reserved name":      `{"name":"local","url":"https://server.example.com","enroll_token":"tok"}`,
		"derived reserved":   `{"url":"https://local","enroll_token":"tok"}`,
		"missing token":      `{"url":"https://server.example.com"}`,
		"blank token":        `{"url":"https://server.example.com","enroll_token":"   "}`,
		"unknown permission": `{"url":"https://server.example.com","enroll_token":"tok","permissions":["probe.icmp","not.a.permission"]}`,
		"unmet dependency":   `{"url":"https://server.example.com","enroll_token":"tok","permissions":["probe.http.extended"]}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", payload)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	oversized := `{"url":"https://server.example.com","enroll_token":"` + strings.Repeat("t", maxLocalAgentBodySize) + `"}`
	w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", oversized)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAddLocalAgentServerNormalizesAndKeepsTokenWriteOnly(t *testing.T) {
	fake := newFakeLocalAgent()
	d, sid := localAgentTestDeps(t, fake)

	// Trailing slash stripped, name derived from the host (port dropped), token
	// trimmed of the whitespace a paste carries.
	body := `{"url":"https://server.example.com:8443/","enroll_token":"  s3cret-token  ","tls_insecure":true}`
	w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var got LocalAgentServer
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != "server-example-com" {
		t.Fatalf("derived name=%q", got.Name)
	}
	if got.URL != "https://server.example.com:8443" {
		t.Fatalf("normalized url=%q", got.URL)
	}
	if !got.TLSInsecure {
		t.Fatalf("tls_insecure lost: %+v", got)
	}
	if len(got.Permissions) == 0 {
		t.Fatal("empty permissions must resolve to the implementation default")
	}
	if got.Status.State != "connecting" {
		t.Fatalf("status=%+v", got.Status)
	}

	// The token reached the implementation…
	if fake.tokens["server-example-com"] != "s3cret-token" {
		t.Fatalf("token handed to Add=%q", fake.tokens["server-example-com"])
	}
	// …and appears nowhere in the response.
	if strings.Contains(w.Body.String(), "s3cret-token") || strings.Contains(w.Body.String(), "enroll_token") {
		t.Fatalf("enrollment token echoed back: %s", w.Body.String())
	}

	// Nor in the list read.
	list := localAgentRequest(t, d, sid, http.MethodGet, "/api/v1/local-agent/servers", "")
	if strings.Contains(list.Body.String(), "s3cret-token") || strings.Contains(list.Body.String(), "enroll_token") {
		t.Fatalf("enrollment token exposed by list: %s", list.Body.String())
	}
	if servers := decodeLocalAgentServers(t, list); len(servers) != 1 || servers[0].Name != "server-example-com" {
		t.Fatalf("servers=%+v", servers)
	}
}

func TestAddLocalAgentServerCanonicalizesPermissions(t *testing.T) {
	fake := newFakeLocalAgent()
	d, sid := localAgentTestDeps(t, fake)

	body := `{"name":"work","url":"https://server.example.com","enroll_token":"tok","permissions":["probe.http","probe.icmp","probe.icmp"]}`
	w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got LocalAgentServer
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Canonical order (see permission.canonicalOrder), duplicates collapsed.
	if len(got.Permissions) != 2 || got.Permissions[0] != "probe.icmp" || got.Permissions[1] != "probe.http" {
		t.Fatalf("permissions=%v", got.Permissions)
	}
}

func TestAddLocalAgentServerDuplicateIsConflict(t *testing.T) {
	d, sid := localAgentTestDeps(t, newFakeLocalAgent())

	body := `{"url":"https://server.example.com","enroll_token":"tok"}`
	if w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", body); w.Code != http.StatusOK {
		t.Fatalf("first add status=%d body=%s", w.Code, w.Body.String())
	}
	w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", body)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestNormalizeLocalAgentURLFoldsDNSCase covers the normalization that makes an
// implementation's duplicate check work at all: it compares normalized URLs for
// equality, and url.URL round-trips host case verbatim, so two spellings of one
// server would otherwise stand up two runners against it.
func TestNormalizeLocalAgentURLFoldsDNSCase(t *testing.T) {
	cases := map[string]string{
		"https://WORK.example":             "https://work.example",
		"https://Work.Example:8443":        "https://work.example:8443",
		"HTTPS://Work.Example":             "https://work.example",
		"https://work.example":             "https://work.example",
		"http://192.168.1.5:12450":         "http://192.168.1.5:12450",
		// IPv6 literals are left exactly as written: the zone id is a
		// percent-encoded interface name whose case is significant, and the hex
		// digits have no meaning to fold.
		"http://[FE80::1%25Ethernet]:8080": "http://[FE80::1%25Ethernet]:8080",
		"http://[2001:DB8::1]:12450":       "http://[2001:DB8::1]:12450",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got, err := normalizeLocalAgentURL(in)
			if err != nil {
				t.Fatalf("normalize(%q): %v", in, err)
			}
			if got != want {
				t.Fatalf("normalize(%q)=%q want %q", in, got, want)
			}
			// Whatever comes out has to parse back to the same thing, or the value
			// stored is not the value the agent will dial.
			if again, err := normalizeLocalAgentURL(got); err != nil || again != got {
				t.Fatalf("re-normalize(%q)=%q err=%v; normalization is not idempotent", got, again, err)
			}
		})
	}

	// The case fold is what makes these one entry rather than two.
	upper, err := normalizeLocalAgentURL("https://WORK.example:12450")
	if err != nil {
		t.Fatalf("normalize upper: %v", err)
	}
	lower, err := normalizeLocalAgentURL("https://work.example:12450")
	if err != nil {
		t.Fatalf("normalize lower: %v", err)
	}
	if upper != lower {
		t.Fatalf("%q != %q; a duplicate-URL guard comparing these would miss", upper, lower)
	}
}

func TestRemoveLocalAgentServer(t *testing.T) {
	fake := newFakeLocalAgent()
	d, sid := localAgentTestDeps(t, fake)

	body := `{"name":"work","url":"https://server.example.com","enroll_token":"tok"}`
	if w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", body); w.Code != http.StatusOK {
		t.Fatalf("add status=%d body=%s", w.Code, w.Body.String())
	}

	// Unknown entry → 404 through the sentinel (wrapped by the implementation).
	if w := localAgentRequest(t, d, sid, http.MethodDelete, "/api/v1/local-agent/servers/nope", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing name status=%d body=%s", w.Code, w.Body.String())
	}
	// A name that could never be an entry is rejected before the seam sees it.
	if w := localAgentRequest(t, d, sid, http.MethodDelete, "/api/v1/local-agent/servers/Work", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("bad name status=%d body=%s", w.Code, w.Body.String())
	}
	if w := localAgentRequest(t, d, sid, http.MethodDelete, "/api/v1/local-agent/servers/local", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("reserved name status=%d body=%s", w.Code, w.Body.String())
	}

	w := localAgentRequest(t, d, sid, http.MethodDelete, "/api/v1/local-agent/servers/work", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(fake.servers) != 0 {
		t.Fatalf("servers after remove=%+v", fake.servers)
	}
	if _, held := fake.tokens["work"]; held {
		t.Fatal("credential outlived the entry")
	}
}

func TestSetLocalAgentServerPermissions(t *testing.T) {
	fake := newFakeLocalAgent()
	d, sid := localAgentTestDeps(t, fake)

	add := `{"name":"work","url":"https://server.example.com","enroll_token":"tok","permissions":["probe.icmp"]}`
	if w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", add); w.Code != http.StatusOK {
		t.Fatalf("add status=%d body=%s", w.Code, w.Body.String())
	}

	const path = "/api/v1/local-agent/servers/work/permissions"
	bad := map[string]string{
		"malformed":          `{"permissions":`,
		"unknown field":      `{"permissions":["probe.icmp"],"nope":true}`,
		"multiple values":    `{"permissions":["probe.icmp"]} {}`,
		"unknown permission": `{"permissions":["not.a.permission"]}`,
		"unmet dependency":   `{"permissions":["probe.http.extended"]}`,
	}
	for name, payload := range bad {
		t.Run(name, func(t *testing.T) {
			w := localAgentRequest(t, d, sid, http.MethodPut, path, payload)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	// Unknown entry → 404, same sentinel translation as Remove.
	miss := localAgentRequest(t, d, sid, http.MethodPut, "/api/v1/local-agent/servers/nope/permissions", `{"permissions":["probe.icmp"]}`)
	if miss.Code != http.StatusNotFound {
		t.Fatalf("missing name status=%d body=%s", miss.Code, miss.Body.String())
	}

	w := localAgentRequest(t, d, sid, http.MethodPut, path, `{"permissions":["host.cpu.read","probe.dns","probe.icmp"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
		t.Fatalf("body=%q", w.Body.String())
	}
	servers := decodeLocalAgentServers(t, localAgentRequest(t, d, sid, http.MethodGet, "/api/v1/local-agent/servers", ""))
	if len(servers) != 1 {
		t.Fatalf("servers=%+v", servers)
	}
	want := []string{"probe.icmp", "probe.dns", "host.cpu.read"} // canonical order
	if strings.Join(servers[0].Permissions, ",") != strings.Join(want, ",") {
		t.Fatalf("permissions=%v want %v", servers[0].Permissions, want)
	}

	// An explicitly empty list is a decision, not an omission: the console's
	// picker lets an operator clear every box and calls the result "collects
	// nothing", so folding it into the recommended default would grant back
	// exactly what they had just taken away.
	if w := localAgentRequest(t, d, sid, http.MethodPut, path, `{"permissions":[]}`); w.Code != http.StatusOK {
		t.Fatalf("empty permissions status=%d body=%s", w.Code, w.Body.String())
	}
	if got := fake.servers[0].Permissions; len(got) != 0 {
		t.Fatalf("permissions after an explicit empty set=%v; want the grant actually cleared", got)
	}
	// …and it survives the read as [] rather than as null or as a default.
	servers = decodeLocalAgentServers(t, localAgentRequest(t, d, sid, http.MethodGet, "/api/v1/local-agent/servers", ""))
	if len(servers) != 1 || len(servers[0].Permissions) != 0 {
		t.Fatalf("servers after clearing=%+v", servers)
	}

	// Omitting the field entirely is the other answer, and still means "your
	// recommended default".
	if w := localAgentRequest(t, d, sid, http.MethodPut, path, `{}`); w.Code != http.StatusOK {
		t.Fatalf("omitted permissions status=%d body=%s", w.Code, w.Body.String())
	}
	if got := strings.Join(fake.servers[0].Permissions, ","); got != strings.Join(fakeRecommendedPermissions(), ",") {
		t.Fatalf("permissions after an omitted list=%v; want the recommended default", fake.servers[0].Permissions)
	}
}

// TestAddLocalAgentServerDistinguishesEmptyFromOmittedPermissions pins the other
// half of the same contract on the create path. Both spellings reach the seam
// through one field, so only the pointer's nil-ness tells them apart.
func TestAddLocalAgentServerDistinguishesEmptyFromOmittedPermissions(t *testing.T) {
	fake := newFakeLocalAgent()
	d, sid := localAgentTestDeps(t, fake)

	omitted := `{"name":"defaulted","url":"https://a.example","enroll_token":"tok"}`
	if w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", omitted); w.Code != http.StatusOK {
		t.Fatalf("omitted status=%d body=%s", w.Code, w.Body.String())
	}
	empty := `{"name":"withheld","url":"https://b.example","enroll_token":"tok","permissions":[]}`
	if w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", empty); w.Code != http.StatusOK {
		t.Fatalf("empty status=%d body=%s", w.Code, w.Body.String())
	}

	if got := strings.Join(fake.servers[0].Permissions, ","); got != strings.Join(fakeRecommendedPermissions(), ",") {
		t.Fatalf("omitted permissions resolved to %v; want the recommended default", fake.servers[0].Permissions)
	}
	if got := fake.servers[1].Permissions; len(got) != 0 {
		t.Fatalf("an explicit empty grant was upgraded to %v", got)
	}

	// A list of blanks canonicalizes to the empty grant rather than to the
	// default: presence of the field is what makes a list specified, never what
	// happens to be inside it.
	blank := `{"name":"blanks","url":"https://c.example","enroll_token":"tok","permissions":["","   "]}`
	if w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", blank); w.Code != http.StatusOK {
		t.Fatalf("blank status=%d body=%s", w.Code, w.Body.String())
	}
	if got := fake.servers[2].Permissions; len(got) != 0 {
		t.Fatalf("a list of blanks resolved to %v; want the empty grant", got)
	}
}

func TestLocalAgentImplementationFailureIsServerError(t *testing.T) {
	fake := newFakeLocalAgent()
	fake.failure = fmt.Errorf("config store unavailable")
	d, sid := localAgentTestDeps(t, fake)

	if w := localAgentRequest(t, d, sid, http.MethodGet, "/api/v1/local-agent/servers", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	add := `{"url":"https://server.example.com","enroll_token":"tok"}`
	if w := localAgentRequest(t, d, sid, http.MethodPost, "/api/v1/local-agent/servers", add); w.Code != http.StatusInternalServerError {
		t.Fatalf("add status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestLocalAgentServerJSONShape pins the exact field names and presence rules of
// the read DTO. A console client is hand-written against these (web-console's
// src/api.ts is hand-synced with the Go types), so a rename here is a silent
// break there — this test is what makes it loud.
func TestLocalAgentServerJSONShape(t *testing.T) {
	raw, err := json.Marshal(LocalAgentServer{
		Name:        "work",
		URL:         "https://server.example.com",
		TLSInsecure: true,
		Permissions: []string{"probe.icmp"},
		Enrolled:    true,
		Status: LocalAgentServerStatus{
			State:     "connected",
			AgentID:   "agent_123",
			Since:     time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC),
			LastError: "",
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"name":"work","url":"https://server.example.com","tls_insecure":true,` +
		`"permissions":["probe.icmp"],"enrolled":true,` +
		`"status":{"state":"connected","agent_id":"agent_123","since":"2026-08-06T12:00:00Z"}}`
	if string(raw) != want {
		t.Fatalf("shape=%s\nwant  =%s", raw, want)
	}

	// A state with no timestamp behind it drops the key entirely. omitempty does
	// not do this for a struct field — LocalAgentServerStatus.MarshalJSON does —
	// and it matters because "added, nothing has happened yet" is the ordinary
	// state of a fresh entry, not an edge case, and the year-1 date a value type
	// would emit renders as a date rather than as "unknown".
	raw, err = json.Marshal(LocalAgentServerStatus{State: "connecting"})
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	if string(raw) != `{"state":"connecting"}` {
		t.Fatalf("zero status shape=%s", raw)
	}
	// The same holds nested, which is the shape the console actually reads.
	raw, err = json.Marshal(LocalAgentServer{Name: "work", URL: "https://server.example.com", Permissions: []string{}})
	if err != nil {
		t.Fatalf("marshal server: %v", err)
	}
	if strings.Contains(string(raw), "0001-01-01") {
		t.Fatalf("the zero timestamp reached the console: %s", raw)
	}

	// A real timestamp still round-trips through the same marshaller.
	var back LocalAgentServerStatus
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	raw, err = json.Marshal(LocalAgentServerStatus{State: "connected", Since: at})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !back.Since.Equal(at) || back.State != "connected" {
		t.Fatalf("round trip=%+v", back)
	}
}

// TestLocalAgentServerNeverEmitsNullPermissions guards the console's iteration:
// an implementation returning a nil slice must still reach it as [].
func TestLocalAgentServerNeverEmitsNullPermissions(t *testing.T) {
	fake := newFakeLocalAgent()
	fake.servers = []LocalAgentServer{{Name: "work", URL: "https://server.example.com"}}
	d, sid := localAgentTestDeps(t, fake)

	w := localAgentRequest(t, d, sid, http.MethodGet, "/api/v1/local-agent/servers", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"permissions":null`) {
		t.Fatalf("null permissions reached the console: %s", w.Body.String())
	}
}
