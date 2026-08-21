package wireadapt

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// TestRegistryMembershipExact pins the registry's shape (A1): it holds exactly
// the two schemas this build serves, and every adapter is complete — the
// Schema metadata plus the five behavioral pieces, enrollment included. A
// missing entry or a removed piece shows up here as a hard failure, which is
// what makes "the enrollment adapter is in the registry" a directly assertable
// fact rather than a claim.
func TestRegistryMembershipExact(t *testing.T) {
	if got, want := Schemas(), []int{7, 8}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Schemas() = %v, want %v", got, want)
	}
	for _, v := range []int{7, 8} {
		a, ok := Lookup(v)
		if !ok {
			t.Fatalf("Lookup(%d) = _, false; want an adapter", v)
		}
		if a.Schema != v {
			t.Errorf("adapter.Schema = %d, want %d", a.Schema, v)
		}
		if a.ValidateHello == nil {
			t.Errorf("adapter %d missing ValidateHello", v)
		}
		if a.AcceptUplink == nil {
			t.Errorf("adapter %d missing AcceptUplink", v)
		}
		if a.GuardDownlink == nil {
			t.Errorf("adapter %d missing GuardDownlink", v)
		}
		if a.AcceptEnrollRequest == nil {
			t.Errorf("adapter %d missing AcceptEnrollRequest", v)
		}
		if a.EncodeEnrollResponse == nil {
			t.Errorf("adapter %d missing EncodeEnrollResponse", v)
		}
	}
}

// TestLookupIsExactMembership (A2): membership is an explicit enumeration, not
// a range. Versions just outside the served set, and the zero value (which a
// request with a missing schema version decodes to), all miss.
func TestLookupIsExactMembership(t *testing.T) {
	for _, v := range []int{0, 6, 9} {
		if a, ok := Lookup(v); ok {
			t.Errorf("Lookup(%d) = %+v, true; want a miss", v, a)
		}
	}
}

// TestValidateHelloSchema8 (A3): the capability that gates the floor barrier
// is enforced on a schema 8 Hello; a peer that cannot echo a floor must not
// get a session whose packets could be renumbered in place.
func TestValidateHelloSchema8(t *testing.T) {
	a, _ := Lookup(8)
	if err := a.ValidateHello(wire.Hello{SchemaVersion: 8}); err == nil {
		t.Fatal("ValidateHello without the floor capability succeeded, want an error")
	}
	h := wire.Hello{SchemaVersion: 8, Capabilities: []string{wire.CapSequenceFloorV1}}
	if err := a.ValidateHello(h); err != nil {
		t.Fatalf("ValidateHello with the floor capability: %v", err)
	}
}

// TestValidateHelloSchema7Tolerates (A4): a schema 7 Hello is accepted bare,
// and also with newer fields riding along. A 7 peer cannot encode a capability
// declaration; refusing it over one would strand a working install over a
// cosmetic mismatch.
func TestValidateHelloSchema7Tolerates(t *testing.T) {
	a, _ := Lookup(7)
	if err := a.ValidateHello(wire.Hello{SchemaVersion: 7}); err != nil {
		t.Fatalf("bare schema 7 Hello: %v", err)
	}
	if err := a.ValidateHello(wire.Hello{
		SchemaVersion:   7,
		Capabilities:    []string{wire.CapSequenceFloorV1},
		EnrollmentEpoch: 1,
	}); err != nil {
		t.Fatalf("schema 7 Hello with newer fields riding along: %v", err)
	}
}

// TestAcceptUplinkSchema7RejectsUndeclaredControlFrames (A5): a schema 7
// session must not receive the control frames it never negotiated. Every
// pre-boundary frame is admitted; the three schema 8 control frames are
// refused with the undeclared-capability sentinel. The schema 8 adapter admits
// everything.
func TestAcceptUplinkSchema7RejectsUndeclaredControlFrames(t *testing.T) {
	a7, _ := Lookup(7)
	rejected := []wire.Frame{
		{SequenceFloorApplied: &wire.SequenceFloorApplied{}},
		{EpochRotationRequest: &wire.EpochRotationRequest{}},
		{EpochRotationChallengeRequest: &wire.EpochRotationChallengeRequest{}},
	}
	for _, f := range rejected {
		if err := a7.AcceptUplink(f); !errors.Is(err, ErrUndeclaredControlFrame) {
			t.Errorf("AcceptUplink(%+v) = %v, want ErrUndeclaredControlFrame", f, err)
		}
	}
	admitted := []wire.Frame{
		{Hello: &wire.Hello{SchemaVersion: 7}},
		{Packet: &telemetry.Packet{}},
		{HostSnapshot: &telemetry.HostSnapshot{}},
		{MonitorStatus: &wire.MonitorStatus{}},
	}
	for _, f := range admitted {
		if err := a7.AcceptUplink(f); err != nil {
			t.Errorf("AcceptUplink(%+v) = %v, want nil", f, err)
		}
	}
	a8, _ := Lookup(8)
	for _, f := range rejected {
		if err := a8.AcceptUplink(f); err != nil {
			t.Errorf("schema 8 AcceptUplink(%+v) = %v, want nil", f, err)
		}
	}
}

// TestGuardDownlinkSchema7RejectsUndeclaredControlFrames (A6): the server must
// never send the schema 8 control frames to a 7 peer. The pre-boundary frames
// (Ack, DesiredState, SnapshotRequest) are permitted; the schema 8 adapter
// permits everything.
func TestGuardDownlinkSchema7RejectsUndeclaredControlFrames(t *testing.T) {
	a7, _ := Lookup(7)
	rejected := []wire.Frame{
		{SequenceFloor: &wire.SequenceFloor{}},
		{EpochRotationChallenge: &wire.EpochRotationChallenge{}},
		{EpochRotationResult: &wire.EpochRotationResult{}},
	}
	for _, f := range rejected {
		if err := a7.GuardDownlink(f); !errors.Is(err, ErrUndeclaredControlFrame) {
			t.Errorf("GuardDownlink(%+v) = %v, want ErrUndeclaredControlFrame", f, err)
		}
	}
	admitted := []wire.Frame{
		{Ack: &wire.Ack{}},
		{DesiredState: &pcfg.DesiredState{}},
		{SnapshotRequest: &pcfg.SnapshotRequest{}},
	}
	for _, f := range admitted {
		if err := a7.GuardDownlink(f); err != nil {
			t.Errorf("GuardDownlink(%+v) = %v, want nil", f, err)
		}
	}
	a8, _ := Lookup(8)
	for _, f := range rejected {
		if err := a8.GuardDownlink(f); err != nil {
			t.Errorf("schema 8 GuardDownlink(%+v) = %v, want nil", f, err)
		}
	}
}

// TestEpochVerdictTable (A7): the four-value verdict is a pure function. The
// reported epoch is compared against the authority, never adopted: a zero
// report bootstraps, equality opens the barrier, a stale report rotates, and
// an ahead-of-authority report is refused.
func TestEpochVerdictTable(t *testing.T) {
	cases := []struct {
		reported, authority uint64
		want                Verdict
	}{
		{0, 1, VerdictBootstrap},
		{0, 0, VerdictBootstrap},
		{1, 1, VerdictOpen},
		{8, 8, VerdictOpen},
		{1, 3, VerdictRotate},
		{0, 5, VerdictBootstrap}, // zero is bootstrap even when the authority is higher
		{5, 1, VerdictRefuseAhead},
		{3, 2, VerdictRefuseAhead},
	}
	for _, c := range cases {
		if got := EpochVerdict(c.reported, c.authority); got != c.want {
			t.Errorf("EpochVerdict(%d, %d) = %v, want %v", c.reported, c.authority, got, c.want)
		}
	}
}

// TestValidateSchemaStaysExact (V1): the protocol package's schema check keeps
// exact-match semantics. This is a cross-repository regression: if a future
// protocol change relaxes ValidateSchema into a range, this test goes red on
// the receiver side. It also pins the refusal wording the downgrade retry keys
// on.
func TestValidateSchemaStaysExact(t *testing.T) {
	if err := protocol.ValidateSchema(protocol.SchemaVersion); err != nil {
		t.Fatalf("ValidateSchema(%d) = %v, want nil", protocol.SchemaVersion, err)
	}
	for _, v := range []int{7, 9} {
		err := protocol.ValidateSchema(v)
		if err == nil {
			t.Fatalf("ValidateSchema(%d) = nil, want an error", v)
		}
		if !strings.Contains(err.Error(), "unsupported schema_version") {
			t.Errorf("ValidateSchema(%d) error %q missing the refusal marker", v, err)
		}
	}
}
