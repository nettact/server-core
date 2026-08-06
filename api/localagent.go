package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/protocol/permission"
)

// Local-agent external-server API (AGENT-007 phase 3).
//
// The desktop app runs an agent and a server in one process, joined by an
// in-memory pipe rather than a loopback socket. That embedded agent may ALSO
// push to servers outside this machine — the home desktop additionally reporting
// to a workplace server — and the product rule for that list is that it is
// managed entirely from the console: a desktop user is never asked to hand-edit
// an agent YAML file. The console the desktop serves is the same web-console a
// self-hosted server serves, so the management surface has to live on the
// server's HTTP API even though only one of the two hosts can implement it.
//
// Hence the seam below. server-core owns the contract — paths, payload shapes,
// validation, status codes — precisely BECAUSE it cannot implement it: the
// console must not have to speak a different dialect to the desktop, and the
// desktop must not be free to invent one. What server-core does not own is the
// list itself; it has no store, no config file and no agent to reconfigure.

const (
	// maxLocalAgentBodySize bounds the create/permissions payloads. Both are a
	// short URL, a token and a permission list; 8 KiB is roughly an order of
	// magnitude of headroom over the largest realistic body (every compiled
	// permission spelled out is well under 1 KiB).
	maxLocalAgentBodySize = 8 << 10

	// maxLocalAgentURLLength bounds the base URL before it is parsed, so a
	// pathological input is rejected by length rather than by url.Parse's own
	// limits (which are effectively none).
	maxLocalAgentURLLength = 512

	// localAgentReservedName is the name the desktop's own in-process server owns.
	// The embedded agent is born attached to it and it is not part of this list, so
	// accepting the name here would let an external entry shadow the one connection
	// the user cannot configure — and, in a UI listing both, make them
	// indistinguishable.
	localAgentReservedName = "local"
)

// localAgentNamePattern is the accepted name charset: lowercase alphanumerics,
// '-' and '_', starting with an alphanumeric, at most 64 characters.
//
// It is deliberately narrower than "any non-empty string". The name is the key
// in every other method of LocalAgentAPI and it travels in a URL path segment,
// so it must survive that round-trip with no escaping question; and an
// implementation is free to use it as a filename or a config-map key, which is
// where a permissive charset turns into a traversal or collision bug. Case is
// excluded for the same reason two names differing only in case would be a
// support ticket, not a feature.
var localAgentNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Sentinel errors a LocalAgentAPI implementation returns so the HTTP layer can
// answer with a meaningful status instead of flattening everything to 500.
// Wrapping is fine — the handlers compare with errors.Is.
var (
	// ErrLocalAgentNotFound: the named entry is not in the list. → 404.
	ErrLocalAgentNotFound = errors.New("local agent server not found")
	// ErrLocalAgentDuplicate: the name Add was given (or derived) is taken. → 409.
	ErrLocalAgentDuplicate = errors.New("local agent server already exists")
)

// LocalAgentAPI is the desktop-only seam for the embedded agent's
// external-server list: the servers this machine's agent connects to in addition
// to the in-process one it is born attached to.
//
// Non-nil only in desktop mode, for the same reason and by the same precedent as
// Deps.ApplyListenAddr: a self-hosted server has no embedded agent to
// reconfigure, so it leaves the field nil and the four routes answer 404 (see
// requireLocalAgent for why 404 and not 501).
//
// Name is the identity in every method; there is no opaque id. These are a
// handful of user-named connections in a local config, not rows in a table, and
// a synthetic id would only add a lookup the user cannot see — while the name is
// the thing they typed and the thing the console shows. The cost is that a
// rename would be a remove plus an add, which is the right shape anyway: the
// name is also how the credential is filed.
//
// Error contract:
//
//   - ErrLocalAgentNotFound from Remove/SetPermissions → 404.
//   - ErrLocalAgentDuplicate from Add → 409.
//   - anything else → 500.
//
// Notably NOT errors: a server that is unreachable, or that rejects the
// enrollment token. Add persists the entry and reports the outcome through
// LocalAgentServerStatus instead, because enrollment is retried in the
// background and a laptop that happens to be off the network when the user
// pastes a token must not silently discard what they typed. "Did this work?" is
// a status question with an answer that changes over time, not the return value
// of one HTTP call.
type LocalAgentAPI interface {
	// List returns every configured external server with its current connection
	// status. It never returns enrollment tokens — LocalAgentServer has nowhere to
	// put one.
	List(ctx context.Context) ([]LocalAgentServer, error)

	// Add registers a server and begins enrolling against it. The spec arrives
	// fully normalized and validated (concrete name, canonical URL, trimmed token,
	// permission ids in canonical order) — see normalizeLocalAgentSpec — so an
	// implementation may store it as given. A nil Permissions means "your
	// recommended default"; a non-nil empty one means "grant nothing". See
	// SetPermissions for why those have to be two different answers.
	Add(ctx context.Context, spec LocalAgentServerSpec) (LocalAgentServer, error)

	// Remove stops the connection and drops the entry with its credentials. It is
	// local-only: the remote server keeps its agent record (this machine has no
	// authority there), so re-adding it later means a fresh enrollment token from
	// that server's console.
	Remove(ctx context.Context, name string) error

	// SetPermissions replaces the granted set this machine reports to one server —
	// the "this server may collect host metrics, that one only basic probes"
	// decision AGENT-007 exists for.
	//
	// The pointer is load-bearing. nil is "unspecified: use your recommended
	// default"; a non-nil empty slice is "grant nothing". A plain []string cannot
	// hold both, and this seam used to fold them together on the argument that a
	// zero-permission connection can do nothing but occupy a slot, so an empty
	// list was far likelier to mean "you choose" than "grant nothing" — and that
	// removing the entry was how a user said the latter.
	//
	// Both halves of that were wrong. The console's permission picker lets an
	// operator clear every box and labels the result "collects nothing", so the
	// deliberate empty grant is not a theoretical caller mistake, it is one click
	// away on the one screen whose entire purpose is withholding — and folding it
	// into the default GRANTED what the user had just taken away. Nor is removing
	// the entry the same act: removal drops the credential and needs a fresh
	// enrollment token from that server's console to undo, while a zero grant
	// leaves the connection up and reversible, still proving the machine is
	// online and widenable again later without touching the other server at all.
	//
	// nil keeps meaning the default because a caller with genuinely nothing to say
	// is a real case (a client that omits the field), and server-core has no
	// opinion on what a desktop should grant a stranger — the agent build that
	// owns the permission model does.
	SetPermissions(ctx context.Context, name string, permissions *[]string) error
}

// LocalAgentServerSpec is the create payload for one external server.
type LocalAgentServerSpec struct {
	// Name identifies the entry. Empty means "derive one from the URL host": the
	// common case is one server per host and asking a user to invent a label for
	// it is friction with no payoff. Derivation happens in the HTTP layer (see
	// deriveLocalAgentName), so an implementation reached through this API always
	// receives a concrete name that already passed validation — a derived name is
	// held to exactly the same charset and reserved-word rules as a typed one.
	Name string `json:"name,omitempty"`

	// URL is the server's base address ("https://nettact.example.com"), scheme and
	// authority only. See normalizeLocalAgentURL for what is normalized and what is
	// rejected.
	URL string `json:"url"`

	// EnrollToken is the one-time enrollment token minted by the OTHER server's
	// console. It is WRITE-ONLY across this surface — LocalAgentServer has no field
	// for it and no read echoes it back. Unlike a proxy password (see proxies.go)
	// there is nothing to round-trip: the token is spent at enrollment and worthless
	// afterwards, so a placeholder-and-keep dance would exist only to put a live
	// credential in a browser for the minutes before it expires.
	EnrollToken string `json:"enroll_token"`

	// TLSInsecure skips certificate verification for this server. It exists for
	// LAN deployments behind a self-signed certificate — the same opt-in the
	// standalone agent has — and is per server, never global.
	TLSInsecure bool `json:"tls_insecure,omitempty"`

	// Permissions is the granted set reported to this server. Absent (nil) means
	// the implementation's recommended default, an explicitly empty list means
	// grant nothing, and a non-empty list must be dependency closed
	// (permission.Validate's rule, enforced here so a set the agent would refuse
	// at startup is refused at the point the user chose it).
	//
	// A pointer rather than a plain slice because the first two are different
	// answers and encoding/json cannot tell an absent field from an empty array
	// any other way — see LocalAgentAPI.SetPermissions for why the difference
	// matters enough to pay for it.
	Permissions *[]string `json:"permissions,omitempty"`
}

// LocalAgentServer is one configured external server as the console sees it:
// the stored configuration plus the live connection state. Deliberately not a
// mirror of the spec — there is no enroll_token field, and there is a status the
// spec cannot carry.
type LocalAgentServer struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	TLSInsecure bool   `json:"tls_insecure"`
	// Permissions is the effective stored grant, so a console that omitted the
	// field on the way in sees which default it got rather than an empty box.
	// There is no "unspecified" on the way out: an empty list here is the real
	// answer that this server is granted nothing.
	Permissions []string `json:"permissions"`
	// Enrolled reports whether this machine holds a credential for the server.
	// Distinct from Status.State: an enrolled agent can be disconnected (offline,
	// backing off), and an un-enrolled one can be mid-handshake. The console needs
	// the difference to decide whether the remedy is "wait" or "paste a new token".
	Enrolled bool                   `json:"enrolled"`
	Status   LocalAgentServerStatus `json:"status"`
}

// LocalAgentServerStatus is the live connection state of one external server.
//
// State vocabulary:
//
//   - "connected"     — session established, telemetry flowing.
//   - "connecting"    — dialing, or backing off between attempts. The ordinary
//     transient state; not a fault.
//   - "enroll_failed" — the enrollment token was rejected or had expired. Needs a
//     new token from the remote console: user action, not a retry.
//   - "superseded"    — another connection took this agent's slot on that server
//     (close code 4000). The agent stops fighting for it rather than flapping.
//   - "revoked"       — the server no longer recognizes the credential (the agent
//     was deleted there). Also terminal, also needs a new token.
//   - "stopped"       — not running: the entry exists but nothing is dialing.
//
// Readers MUST tolerate a state they do not know and fall back to a generic
// label. The console is versioned separately from the binary that serves it (a
// release server downloads its stamped console at runtime), so "newer host, older
// console" is ordinary rather than a fault.
type LocalAgentServerStatus struct {
	State string `json:"state"`
	// AgentID is the identity this machine holds on that server, once enrolled.
	// It is what lets a user match this entry to the agent row in the other
	// console.
	AgentID string `json:"agent_id,omitempty"`
	// LastError is the human-readable reason behind a failing state, verbatim from
	// whatever failed. Advisory only — never parsed, never a status code.
	LastError string `json:"last_error,omitempty"`
	// Since is when the current state was entered, and is ABSENT rather than zero
	// when there is nothing meaningful to report. An implementation that has no
	// timestamp for a state leaves it zero rather than substituting now(), which
	// would render as a duration that resets on every poll; MarshalJSON below is
	// what turns that zero into an absent key.
	Since time.Time `json:"since,omitempty"`
}

// MarshalJSON drops a zero Since instead of writing the year-1 timestamp
// encoding/json would.
//
// omitempty does not apply to a struct field, so the tag above is a promise the
// default marshaller cannot keep: an unset value goes out as
// "0001-01-01T00:00:00Z", which reads as "unknown" to nobody — it is a date, and
// a console that renders whatever timestamp it is handed renders the year 1.
// That is not an edge case here: it is the ordinary state of an entry between
// being added and the agent's first transition on it.
//
// The obvious alternative is a *time.Time field, which omits by itself. It was
// not taken because it moves the guarantee out of this package and into every
// implementation of LocalAgentAPI — which lives elsewhere by construction, the
// desktop being the only one — and a pointer to a zero time marshals as the
// year-1 date exactly like the value did. Doing it here makes "absent means
// unknown" a property of the wire format rather than of everyone who writes to
// it, and leaves implementations assigning a plain time.Time that reads
// correctly whether or not they thought about this.
func (s LocalAgentServerStatus) MarshalJSON() ([]byte, error) {
	// alias sheds this method, so json.Marshal below does not recurse into it.
	// The outer Since is a shallower field of the same JSON name and therefore
	// wins the conflict against the embedded one, which is how the value field
	// gets replaced by an omittable pointer without restating the whole struct.
	type alias LocalAgentServerStatus
	out := struct {
		alias
		Since *time.Time `json:"since,omitempty"`
	}{alias: alias(s)}
	if !s.Since.IsZero() {
		out.Since = &s.Since
	}
	return json.Marshal(out)
}

// requireLocalAgent resolves the desktop seam, or answers 404 and reports false.
//
// 404 rather than 501: on a self-hosted server this endpoint genuinely does not
// exist — there is no embedded agent, and no version of that server that could
// grow one at runtime. 501 would advertise a route that is merely unimplemented
// here, inviting a console to retry or to show "not supported yet". The console
// instead learns the capability up front from server-info's local_agent bit and
// never probes these routes on a server that lacks them.
func (d Deps) requireLocalAgent(w http.ResponseWriter) (LocalAgentAPI, bool) {
	if d.LocalAgent == nil {
		writeError(w, http.StatusNotFound, "not found")
		return nil, false
	}
	return d.LocalAgent, true
}

// handleListLocalAgentServers serves GET /local-agent/servers. The response is
// wrapped in an object ({"servers": […]}) rather than returned as a bare array,
// like the other composite console reads (/permissions, /issues).
func (d Deps) handleListLocalAgentServers(w http.ResponseWriter, r *http.Request) {
	la, ok := d.requireLocalAgent(w)
	if !ok {
		return
	}
	servers, err := la.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// An implementation with nothing configured returns nil; the console renders a
	// list, so it must see [] and never null.
	if servers == nil {
		servers = []LocalAgentServer{}
	}
	for i := range servers {
		servers[i] = normalizeLocalAgentServer(servers[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": servers})
}

// normalizeLocalAgentServer applies the same null-free guarantee to the fields
// inside one entry: the console iterates permissions, and a nil slice would
// reach it as null rather than as the empty list it can render.
func normalizeLocalAgentServer(s LocalAgentServer) LocalAgentServer {
	if s.Permissions == nil {
		s.Permissions = []string{}
	}
	return s
}

// handleAddLocalAgentServer serves POST /local-agent/servers. Every rejection
// below is a 400 naming the offending field: this body is typed by a human
// pasting an address and a token, so the error is the whole user interface for
// getting it right.
func (d Deps) handleAddLocalAgentServer(w http.ResponseWriter, r *http.Request) {
	la, ok := d.requireLocalAgent(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLocalAgentBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var spec LocalAgentServerSpec
	if err := decoder.Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid local agent server")
		return
	}
	if err := ensureJSONEnd(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid local agent server")
		return
	}
	if err := normalizeLocalAgentSpec(&spec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	server, err := la.Add(r.Context(), spec)
	if err != nil {
		writeLocalAgentError(w, err)
		return
	}
	// Name and URL only: the audit trail records that this machine was pointed at
	// an outside server, which is the security-relevant fact, and never the token
	// that would let a reader of the log re-enroll something else there.
	d.Audit.Log(r.Context(), "admin", "local_agent.server.add", spec.Name, spec.URL)
	writeJSON(w, http.StatusOK, normalizeLocalAgentServer(server))
}

// handleRemoveLocalAgentServer serves DELETE /local-agent/servers/{name}.
func (d Deps) handleRemoveLocalAgentServer(w http.ResponseWriter, r *http.Request) {
	la, ok := d.requireLocalAgent(w)
	if !ok {
		return
	}
	name, ok := localAgentNameParam(w, r)
	if !ok {
		return
	}
	if err := la.Remove(r.Context(), name); err != nil {
		writeLocalAgentError(w, err)
		return
	}
	d.Audit.Log(r.Context(), "admin", "local_agent.server.remove", name, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSetLocalAgentServerPermissions serves
// PUT /local-agent/servers/{name}/permissions.
//
// It answers {"ok":true} rather than the updated server: the caller already
// knows what it set, and everything else about the entry (state, agent id, last
// error) is moving underneath — a single-object response would be a snapshot
// that is stale by the time it is rendered. The console re-reads the list, which
// is the surface that is actually live.
func (d Deps) handleSetLocalAgentServerPermissions(w http.ResponseWriter, r *http.Request) {
	la, ok := d.requireLocalAgent(w)
	if !ok {
		return
	}
	name, ok := localAgentNameParam(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLocalAgentBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var body struct {
		// A pointer for the same reason the spec field is one: {"permissions":[]}
		// is "grant nothing" and an omitted key is "use your recommended default",
		// and folding those together silently re-grants what a user just cleared.
		Permissions *[]string `json:"permissions"`
	}
	if err := decoder.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid permissions")
		return
	}
	if err := ensureJSONEnd(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid permissions")
		return
	}
	permissions, err := canonicalLocalAgentPermissions(body.Permissions)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := la.SetPermissions(r.Context(), name, permissions); err != nil {
		writeLocalAgentError(w, err)
		return
	}
	d.Audit.Log(r.Context(), "admin", "local_agent.server.permissions", name, auditPermissions(permissions))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// auditPermissions renders a grant for the audit log without collapsing the
// three-way distinction the field carries. "Deferred to the default", "granted
// nothing" and "granted exactly these" are three different administrative acts,
// and the log is the only place anyone can still tell them apart afterwards — an
// empty string for the first two would make the most security-relevant of them
// (revoking everything) indistinguishable from a no-op.
func auditPermissions(p *[]string) string {
	switch {
	case p == nil:
		return "(default)"
	case len(*p) == 0:
		return "(none)"
	default:
		return strings.Join(*p, ",")
	}
}

// localAgentNameParam reads and validates the {name} path segment, answering 400
// when it could not name an entry.
//
// Validating a lookup key looks redundant — a name outside the charset simply
// won't be in the list — but the value is about to be handed to an
// implementation that may well use it as a filename or a map key on the desktop
// side. Rejecting it at the boundary means that implementation never has to be
// the one that gets path traversal right, and it also turns a typo into a
// specific message instead of a bare "not found".
func localAgentNameParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	if err := validateLocalAgentName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return name, true
}

// writeLocalAgentError maps the seam's error contract onto status codes.
func writeLocalAgentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrLocalAgentNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrLocalAgentDuplicate):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

// normalizeLocalAgentSpec validates the create payload and rewrites it into the
// canonical form implementations may store verbatim. It mutates spec in place so
// there is exactly one representation downstream — the normalized URL is also
// what the derived name is computed from, and what the response echoes back, so
// the value the user sees is the value that was stored.
func normalizeLocalAgentSpec(spec *LocalAgentServerSpec) error {
	normalizedURL, err := normalizeLocalAgentURL(spec.URL)
	if err != nil {
		return err
	}
	spec.URL = normalizedURL

	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = deriveLocalAgentName(normalizedURL)
	}
	if err := validateLocalAgentName(name); err != nil {
		return err
	}
	spec.Name = name

	// Tokens are copied out of another console and arrive with whatever whitespace
	// the clipboard picked up; trimming here is the difference between "it worked"
	// and an enrollment rejected for a trailing newline.
	spec.EnrollToken = strings.TrimSpace(spec.EnrollToken)
	if spec.EnrollToken == "" {
		return errors.New("enrollment token is required")
	}

	permissions, err := canonicalLocalAgentPermissions(spec.Permissions)
	if err != nil {
		return err
	}
	spec.Permissions = permissions
	return nil
}

// normalizeLocalAgentURL checks a server base URL and returns its canonical form
// (scheme + authority, no trailing slash).
//
// Trailing slashes are STRIPPED rather than tolerated because the agent's two
// entry points disagree about them: enrollment builds its URL by concatenation
// (serverURL + "/api/v1/enroll" in agent/internal/enroll), while the WebSocket
// link uses url.JoinPath (agent/internal/conn/wslink.go), which collapses the
// duplicate. A stored "https://host/" therefore produces a working ws URL and an
// enrollment POST to "//api/v1/enroll" that 404s — a failure that looks like a
// broken server rather than a stray keystroke.
//
// A deeper path is REJECTED rather than stripped. The agent would in fact honor
// a reverse-proxy sub-path mount (both entry points append to it), but the
// overwhelmingly likelier paste into this field is a console deep link —
// web-console uses history routing, so "https://host/agents" carries no '#' to
// give it away — and stripping the path would quietly accept a URL that names
// something else and pretend it meant the base. Left alone it is worse still:
// the remote server's SPA handler answers that enrollment POST with HTML and a
// 200, so the user's mistake resurfaces much later as an unintelligible decode
// error. Naming the problem now is the only version of this that teaches anyone
// anything. (If sub-path mounts ever need supporting from the console, this is
// the single check to relax — the agent side already works.)
//
// Query strings, fragments and embedded credentials are rejected outright: none
// of them belong to a base address, the agent has no use for any of them, and
// userinfo in particular would end up in every log line that records the URL.
//
// A DNS host is lower-cased, because url.URL round-trips host case verbatim and
// two spellings of one server must not survive as two strings. The desktop's
// duplicate guard compares normalized URLs for equality, so "https://WORK.example"
// alongside "https://work.example" would slip past it and stand up two runners
// against one server — enrolling this machine there twice and then superseding
// each other's sessions in a close-code-4000 loop, which is the exact failure
// that guard exists to prevent. IP literals are left alone: an IPv6 literal
// carries a zone id whose case is significant (a percent-encoded interface name),
// and an IPv4 literal has no letters to fold.
func normalizeLocalAgentURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("server URL is required")
	}
	if len(raw) > maxLocalAgentURLLength {
		return "", errors.New("server URL is too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("server URL is invalid")
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return "", errors.New("server URL must start with http:// or https://")
	}
	// Hostname(), not Host: url.Parse reads "http://:12450" as a host of ":12450",
	// which is non-empty and names nothing. Left to the derivation path that would
	// be caught (an empty derived name fails validation), but a spec that supplies
	// its own name skips derivation entirely and would persist an entry the agent
	// can never dial.
	if u.Hostname() == "" {
		return "", errors.New("server URL must include a host")
	}
	if u.User != nil {
		return "", errors.New("server URL must not contain credentials")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("server URL must not contain a query string")
	}
	if u.Fragment != "" {
		return "", errors.New("server URL must not contain a fragment")
	}
	if strings.Trim(u.Path, "/") != "" {
		return "", errors.New("server URL must be the server's base address, without a path")
	}
	u.Path = ""
	u.RawPath = ""
	u.Host = lowerDNSHost(u.Host)
	return u.String(), nil
}

// lowerDNSHost lower-cases the host of an authority when it is a DNS name,
// leaving IP literals untouched.
//
// It works on the raw authority rather than on Hostname()+Port() because
// Hostname() decodes an IPv6 zone id ("%25eth0" → "%eth0"), so reassembling from
// it would emit a URL that no longer parses back to the same host. Skipping
// anything bracketed keeps that whole class of value out of reach; a ':' or '%'
// outside brackets is equally not a DNS name we should be rewriting.
func lowerDNSHost(host string) string {
	if strings.HasPrefix(host, "[") {
		return host // IPv6 literal, possibly with a case-significant zone id
	}
	name, port, found := strings.Cut(host, ":")
	if strings.ContainsAny(name, "%[]") {
		return host
	}
	if !found {
		return strings.ToLower(name)
	}
	return strings.ToLower(name) + ":" + port
}

// deriveLocalAgentName builds a name from the URL host for a spec that omitted
// one: lowercased, port dropped, and every character outside the name charset
// folded to '-' (so "192.168.1.5" becomes "192-168-1-5" and an IPv6 literal
// survives too). Returns "" when nothing usable is left, which validation then
// reports as a missing name — the honest outcome, since the alternative is
// inventing a label the user never chose and cannot predict.
//
// The port is dropped rather than folded in: a name is a label for "that server",
// and two entries differing only by port on the same host are rare enough that
// the duplicate conflict (409) telling the user to name them is better than
// every ordinary name carrying a "-12450" tail.
func deriveLocalAgentName(normalizedURL string) string {
	u, err := url.Parse(normalizedURL)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, c := range strings.ToLower(u.Hostname()) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteRune('-')
		}
	}
	// The charset allows '-'/'_' anywhere but the first position, so trim the
	// leading run rather than rejecting a host that merely starts with one.
	name := strings.TrimLeft(b.String(), "-_")
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// validateLocalAgentName enforces the name rules for both a submitted name and a
// derived one.
func validateLocalAgentName(name string) error {
	if name == "" {
		return errors.New("server name is required")
	}
	if !localAgentNamePattern.MatchString(name) {
		return errors.New("server name must be 1-64 characters of a-z, 0-9, '-' or '_', starting with a letter or digit")
	}
	if name == localAgentReservedName {
		return errors.New(`server name "local" is reserved for this machine's own server`)
	}
	return nil
}

// canonicalLocalAgentPermissions validates a submitted permission list and
// returns it in canonical order. nil in is "unspecified" and stays nil out
// (every consumer reads that as the implementation's recommended default); a
// present list stays present, including when it is empty — that is the operator
// saying "grant nothing", which is a decision and not an omission.
//
// Blank entries are dropped rather than rejected (permission.FromStrings does
// it), so ["", " "] canonicalizes to the empty grant. That follows from the same
// rule: what makes a list "unspecified" is the field being absent, never what
// happens to be inside it.
//
// The set is NOT dependency-closed for the caller. permission.Validate treats an
// unsatisfied dependency as an error by design — the agent refuses to start on a
// policy like that — so silently adding the parent here would hand back a grant
// broader than the one the operator ticked, on a screen whose entire purpose is
// deciding what an outside server may collect. The console already sends closed
// sets: /permissions ships each entry's full `implies` closure precisely so a
// union of ticked boxes is closed by construction.
//
// The error text is permission.Validate's own (one line per violation, joined),
// because it names the exact ids at fault — the same text the agent would refuse
// to boot with, which is what makes the two ends debuggable together.
func canonicalLocalAgentPermissions(in *[]string) (*[]string, error) {
	if in == nil {
		return nil, nil
	}
	set := permission.FromStrings(*in)
	if err := permission.Validate(set); err != nil {
		return nil, err
	}
	// Strings() already returns a non-nil empty slice for an empty set, which
	// matters: the whole point of getting here with a pointer is that the value it
	// points at is an empty list rather than a null.
	out := set.Strings()
	return &out, nil
}
