package wireadapt

import (
	"encoding/json"
	"time"

	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/wire"
)

// adapter7 serves peers released before the current schema boundary. Their
// binary cannot encode a capability list or an enrollment epoch and does not
// know the floor barrier or the controlled rotation, so a 7 session runs none
// of the newer state machines — its frames are exactly the pre-boundary set,
// and the server must not push anything the peer never negotiated.
//
// This is a support-window compatibility surface, not a permanent second
// protocol: a session of this schema exists so an already-deployed peer keeps
// reporting while its owner upgrades. Its removal is a release-process
// decision, not a runtime one.
var adapter7 = &Adapter{
	Schema:               7,
	RunsFloorBarrier:     false,
	RunsEpochGate:        false,
	ValidateHello:        validateHello7,
	AcceptUplink:         acceptUplink7,
	GuardDownlink:        guardDownlink7,
	AcceptEnrollRequest:  acceptEnrollRequest7,
	EncodeEnrollResponse: encodeEnrollResponse7,
}

// validateHello7 tolerates a bare schema 7 Hello and ignores any newer fields
// that happen to ride along. A schema 7 peer simply cannot encode a capability
// declaration; refusing it over an absent capability would strand a working
// install over a cosmetic mismatch. A missing capability is a fact about the
// peer, and the right answer is to serve it with the subset both sides share.
func validateHello7(_ wire.Hello) error { return nil }

// acceptUplink7 refuses the schema 8 control frames on a session that never
// negotiated them: SequenceFloorApplied, EpochRotationRequest and
// EpochRotationChallengeRequest all belong to state machines a 7 peer has no
// part in, and processing them would let a confused peer drive a rotation the
// session cannot complete. Every pre-boundary frame (Packet, HostSnapshot,
// MonitorStatus, Hello) is admitted.
func acceptUplink7(f wire.Frame) error {
	switch {
	case f.SequenceFloorApplied != nil,
		f.EpochRotationRequest != nil,
		f.EpochRotationChallengeRequest != nil:
		return ErrUndeclaredControlFrame
	}
	return nil
}

// guardDownlink7 refuses to send the schema 8 control frames to a 7 peer:
// SequenceFloor, EpochRotationChallenge and EpochRotationResult. The other
// outbound frames (Ack, DesiredState, SnapshotRequest) predate the boundary
// and are permitted. The session logic already avoids building these for a 7
// session; the guard is the mechanical backstop.
func guardDownlink7(f wire.Frame) error {
	switch {
	case f.SequenceFloor != nil,
		f.EpochRotationChallenge != nil,
		f.EpochRotationResult != nil:
		return ErrUndeclaredControlFrame
	}
	return nil
}

// acceptEnrollRequest7 admits an enrollment declaring schema 7. The request
// shape is identical to schema 8 — the newer version only adds a field to the
// RESPONSE — so acceptance is the same fail-closed membership check.
func acceptEnrollRequest7(req enroll.EnrollRequest) (enroll.EnrollRequest, error) {
	if req.SchemaVersion != 7 {
		return enroll.EnrollRequest{}, UnsupportedSchema(req.SchemaVersion)
	}
	return req, nil
}

// enrollResponseV7 is the schema 7 enrollment response shape. It is its own
// struct, not the canonical one minus a field: the canonical EnrollResponse's
// EnrollmentEpoch carries no omitempty, so marshaling the canonical struct
// would always emit the key, and a 7 peer that never learned a generation must
// not be handed one. The credential this response describes still HAS a
// generation server-side (every credential does); the response simply cannot
// carry it, and the peer presents a zero epoch it cannot know about until it
// upgrades and the server guides it forward.
type enrollResponseV7 struct {
	AgentID       string    `json:"agent_id"`
	SiteID        string    `json:"site_id"`
	AgentToken    string    `json:"agent_token"`
	ServerTime    time.Time `json:"server_time"`
	ConfigVersion int       `json:"config_version"`
}

func encodeEnrollResponse7(resp enroll.EnrollResponse) ([]byte, error) {
	return json.Marshal(enrollResponseV7{
		AgentID:       resp.AgentID,
		SiteID:        resp.SiteID,
		AgentToken:    resp.AgentToken,
		ServerTime:    resp.ServerTime,
		ConfigVersion: resp.ConfigVersion,
	})
}
