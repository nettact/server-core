package wireadapt

// This file holds the credential-generation verdict used by the WebSocket hub
// when a Hello states an enrollment epoch. The verdict is a pure function so
// the whole gate is table-testable: it decides between four outcomes and has
// no other inputs.
//
// The reported epoch is only ever compared, never adopted. The authoritative
// generation is the one the credential row carries — the session's epoch is
// assigned exactly once, from that row, and every artifact that flows out of
// the session (the floor frame's epoch, the ingest principal's epoch, the
// rotation's new generation) is derived from it, not from what a peer claims.
// A verdict here can at most send the peer through the rotation path; it can
// never write a generation the server did not derive.

// Verdict is one of the four outcomes of the epoch gate.
type Verdict int

const (
	// VerdictBootstrap: the peer reports a zero epoch, which means a credential
	// issued before the peer could know generations. No floor is pushed and the
	// barrier opens immediately — gating it would stall every install upgraded
	// from before the boundary.
	VerdictBootstrap Verdict = iota
	// VerdictOpen: the peer is on the current generation; the session runs the
	// barrier normally.
	VerdictOpen
	// VerdictRotate: the peer is on a stale generation. The server challenges
	// it to rotate and the session holds for the rotation flow.
	VerdictRotate
	// VerdictRefuseAhead: the peer reports a generation NEWER than the
	// authority. A stale peer is rotated forward, but an ahead-of-authority
	// report cannot be converged by rotating, so the session is refused with a
	// retryable protocol error instead.
	//
	// The three refusal candidates were each rejected on behavior: a 4001
	// (unsupported schema) would send the agent's downgrade retry looking for a
	// different wire schema and silently bypass the epoch gate; a 4004 (revoked)
	// would make the agent delete a credential that is still valid; silently
	// adopting the report would let a peer choose its own generation. Only a
	// retryable 4003 leaves the credential intact and the pairing re-probable —
	// the agent backs off and reconnects, and a genuinely recovered authority
	// then serves the peer normally.
	VerdictRefuseAhead
)

// EpochVerdict decides the session's handling of a Hello's reported enrollment
// epoch against the authority's generation. The reported value is compared
// against, never assigned from.
func EpochVerdict(reported, authority uint64) Verdict {
	switch {
	case reported == 0:
		return VerdictBootstrap
	case reported == authority:
		return VerdictOpen
	case reported < authority:
		return VerdictRotate
	default:
		return VerdictRefuseAhead
	}
}
