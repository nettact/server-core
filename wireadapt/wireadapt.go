// Package wireadapt is the per-wire-schema adapter registry for this module's
// own WebSocket hub and enrollment endpoint. It holds exactly one Adapter for
// each wire schema this build will serve, and everything that decides how a
// session of that schema behaves lives in that Adapter — what a valid Hello
// looks like, which frames a session may receive or send, and how an
// enrollment request is accepted and its response encoded.
//
// The registry is the receiver half of the N/N-1 compatibility discipline
// described in the protocol package's ValidateSchema documentation: that
// function stays the exact "native schema of this build" check, and a host
// that must accept several schema versions side by side does so through an
// explicit per-version adapter registry like this one — never by relaxing the
// schema check into a range. Membership here is an explicit enumeration, so
// "which schemas this build serves" is a single source of truth (Schemas) that
// both the rejection language and the tests read, instead of a comparison a
// future edit could silently widen.
//
// Ownership boundary: this registry exists for the HTTP/console shell of this
// module — the WebSocket hub (agentws), the enrollment endpoint (registry) and
// the enrollment response encoder (api). A host that embeds only the domain
// core (the store contract, the ingest pipeline, fault detection) adapts wire
// schemas at its own edge and does not consume this package; the domain core
// itself knows nothing about which schemas exist.
package wireadapt

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/wire"
)

// ErrUndeclaredControlFrame reports a schema 8 control frame being sent or
// received on a session that never negotiated the capability the frame belongs
// to. The session treats a received one as a protocol error (close 4003) and a
// server-built one as a server bug (fail loud); either way the sentinel keeps
// the classification out of string matching.
var ErrUndeclaredControlFrame = errors.New("control frame for an undeclared capability")

// UnsupportedSchemaError reports a wire schema version that is not a member of
// this registry. The message names the mismatch and the schemas this build
// serves — the same shape as protocol.ValidateSchema's refusal, pluralized to
// the registry's membership. It is the one refusal shape both the enrollment
// endpoint and the hub build their "this build speaks …" language from.
type UnsupportedSchemaError struct {
	Version int
}

func (e *UnsupportedSchemaError) Error() string {
	return fmt.Sprintf("unsupported schema_version %d (this build speaks %s; upgrade the other side)",
		e.Version, schemaList())
}

// schemaList renders the registry's membership in the rejection language:
// "7 and 8". Schemas itself returns ints so membership stays a testable
// comparison; the string form is only ever for the refusal message.
func schemaList() string {
	schemas := Schemas()
	s := make([]string, len(schemas))
	for i, v := range schemas {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, " and ")
}

// UnsupportedSchema builds the refusal error for a version this registry does
// not serve.
func UnsupportedSchema(version int) error {
	return &UnsupportedSchemaError{Version: version}
}

// Adapter is one wire schema's complete behavior surface. Fields are functions
// rather than methods so "the enrollment adapter is in the registry" is a
// directly assertable fact and a removed piece shows up as a visible nil.
type Adapter struct {
	// Schema is the wire schema version this adapter serves.
	Schema int
	// RunsFloorBarrier reports whether a session of this schema participates in
	// the sequence-floor barrier at all. Schema 7 peers predate the barrier, so
	// the server must not push a floor or hold their packets behind one.
	RunsFloorBarrier bool
	// RunsEpochGate reports whether a session of this schema runs the
	// credential-generation gate on Hello. A schema 7 peer cannot even encode
	// an enrollment epoch, so the whole gate is closed for it — not "open, and
	// only open when the epoch happens to be zero" — otherwise every 7 session
	// would be judged stale and refused.
	RunsEpochGate bool
	// ValidateHello checks a decoded Hello before any session side effect. For
	// schema 8 it enforces the capability that gates the floor barrier; for
	// schema 7 it tolerates and ignores fields the peer cannot encode (an
	// absent capability is a fact about the peer, not a reason to strand it).
	ValidateHello func(wire.Hello) error
	// AcceptUplink admits a decoded agent->server frame to a session of this
	// schema. The two schemas decode through the same codec (schema 8 is a
	// strict superset of 7), so the adapter gates on behavior, not bytes: a 7
	// session must not receive a control frame it never negotiated.
	AcceptUplink func(wire.Frame) error
	// GuardDownlink is the mechanical backing for "never send a control frame
	// to a peer that did not declare the capability". The session code already
	// branches so such frames are never built for a 7 session; the guard is the
	// fail-loud backstop if a server bug lets one through anyway.
	GuardDownlink func(wire.Frame) error
	// AcceptEnrollRequest admits an enrollment request of this schema. The
	// request shape is identical across both schemas, so acceptance is a
	// fail-closed membership check: a missing or unknown schema version is
	// refused, never silently treated as the native one.
	AcceptEnrollRequest func(enroll.EnrollRequest) (enroll.EnrollRequest, error)
	// EncodeEnrollResponse renders a canonical enroll.EnrollResponse in this
	// schema's shape. Schema 8 marshals the canonical struct; schema 7 has its
	// own struct without the enrollment_epoch key, because the canonical field
	// lacks omitempty and a 7 peer that never learned the generation must not
	// be handed a value it cannot act on.
	EncodeEnrollResponse func(enroll.EnrollResponse) ([]byte, error)
}

// registry is the explicit membership list: exactly the schemas this build
// serves, each with a complete adapter. It is the sole source Schemas reads,
// and Lookup's "is this a member" answer comes from this map — never from a
// range comparison.
var registry = map[int]*Adapter{
	adapter7.Schema: adapter7,
	adapter8.Schema: adapter8,
}

// Lookup returns the adapter for v. The bool reports membership; it is false
// for any version the registry does not explicitly serve.
func Lookup(v int) (*Adapter, bool) {
	a, ok := registry[v]
	return a, ok
}

// Schemas returns the wire schema versions this registry serves, sorted. It is
// the single source of the "this build speaks …" rejection language.
func Schemas() []int {
	return []int{adapter7.Schema, adapter8.Schema}
}
