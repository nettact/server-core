package wireadapt

import (
	"encoding/json"
	"errors"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/wire"
)

// adapter8 is the current native schema. It runs the full state machine the
// version introduced: the capability-gated sequence-floor barrier, the
// credential-generation gate, and both directions of control-frame traffic.
var adapter8 = &Adapter{
	Schema:               protocol.SchemaVersion,
	RunsFloorBarrier:     true,
	RunsEpochGate:        true,
	ValidateHello:        validateHello8,
	AcceptUplink:         acceptUplink8,
	GuardDownlink:        guardDownlink8,
	AcceptEnrollRequest:  acceptEnrollRequest8,
	EncodeEnrollResponse: encodeEnrollResponse8,
}

// validateHello8 requires the capability that gates the floor barrier: a peer
// that cannot echo a floor must not get a session whose packets could be
// renumbered in place. Everything else is tolerated — a receiver must ignore
// capability names it does not know, and a future capability is not a reason
// to refuse a peer that still speaks today's barrier.
func validateHello8(hello wire.Hello) error {
	if !wire.HasCapability(hello.Capabilities, wire.CapSequenceFloorV1) {
		return errors.New("missing sequence_floor_v1 capability")
	}
	return nil
}

// acceptUplink8 admits every frame a schema 8 session may receive: the control
// frames are part of the negotiated capability set, and the ordinary frames
// predate the version.
func acceptUplink8(_ wire.Frame) error { return nil }

// guardDownlink8 permits every outbound frame for a schema 8 peer.
func guardDownlink8(_ wire.Frame) error { return nil }

// acceptEnrollRequest8 admits an enrollment declaring this schema. The request
// is same-shaped across the two schemas; the check is the fail-closed
// membership guard, so a missing (0) or foreign version never sneaks through
// as the native one.
func acceptEnrollRequest8(req enroll.EnrollRequest) (enroll.EnrollRequest, error) {
	if req.SchemaVersion != protocol.SchemaVersion {
		return enroll.EnrollRequest{}, UnsupportedSchema(req.SchemaVersion)
	}
	return req, nil
}

// encodeEnrollResponse8 marshals the canonical response, which carries the
// enrollment epoch the schema-8 agent persists with its credential.
func encodeEnrollResponse8(resp enroll.EnrollResponse) ([]byte, error) {
	return json.Marshal(resp)
}
