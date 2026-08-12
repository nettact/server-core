// Schema 8 (CLOUD-013C): credential generations and the controlled epoch
// rotation. Everything about the (agent, enrollment_epoch, sequence) identity
// — the challenge/request/result exchange, the old-token pending window, and
// the bearer authentication that reports which generation a token belongs to
// — lives in this file.
package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/store"
)

const (
	// challengeTTL is how long an issued rotation challenge stays live. The
	// challenge is the one-time binding the agent signs to prove possession of
	// the enrolled ed25519 key, so a short window keeps a leaked challenge from
	// being replayed after the legitimate agent has moved on.
	challengeTTL = time.Minute
	// rotationPendingWindow is how long a committed rotation's OLD token keeps
	// authenticating after the commit. The agent persists the new credential
	// from the EpochRotationResult, but the result can be lost in transit (the
	// session dies after the commit); within this window a reconnect presenting
	// the old token gets the result re-issued idempotently instead of the
	// sequence floor.
	rotationPendingWindow = 2 * time.Minute
)

var (
	// ErrRotationChallenge means the presented challenge is unknown, expired,
	// already consumed, or bound to a different (agent, epoch). Terminal for
	// this challenge: the hub answers RotationDenied.
	ErrRotationChallenge = errors.New("rotation challenge unknown, expired or mismatched")
	// ErrRotationEpoch means the agents row's epoch moved past the request's
	// OldEpoch (a concurrent rotation or reinstall won) or the row is gone.
	// Terminal for this request: the hub answers RotationDenied.
	ErrRotationEpoch = errors.New("rotation request targets a stale epoch")
)

// AuthResult is what a bearer-token authentication resolves to.
type AuthResult struct {
	AgentID string
	SiteID  string
	// Epoch is the credential generation the CURRENT token belongs to. It is
	// what the hub compares against Hello.EnrollmentEpoch and stamps onto the
	// session for the sequence-floor barrier.
	Epoch uint64
	// PendingRotation is set when the presented token is the OLD token of a
	// rotation that has already committed server-side: the rotation result
	// must be re-issued idempotently instead of the floor.
	PendingRotation *wire.EpochRotationResult
}

// rotationChallenge is the server-side binding of one issued challenge: which
// agent, which epoch it rotates out of, and when it expires. The challenge
// string the agent signs is base64 of 32 random bytes and is treated as
// opaque; the binding itself never leaves the process.
type rotationChallenge struct {
	agentID string
	epoch   uint64
	expires time.Time
}

// pendingRotationResult is the re-issuable outcome of a committed rotation,
// keyed by agent. It exists because only the token's HASH is durable (see
// AuthenticateAgent): re-issuing the result to the old-token holder needs the
// new token's plaintext, which exists nowhere but here. Lost on restart by
// design — the prev-token auth then fails with ErrAuth, and the agent's own
// retry loop keeps the in-memory credential alive until its restart
// persistence retry lands (it retries on every reconnect). The agents row's
// pending_prev_* columns still record the window for audit/observability.
type pendingRotationResult struct {
	newEpoch uint64
	newToken string
	until    time.Time
}

// AuthenticateAgent maps a bearer token to its agent identity, the credential
// generation the token belongs to, and — when the token is the OLD token of an
// already-committed rotation still inside its pending window — the result that
// must be re-issued. Returns ErrAuth for anything that does not match.
//
// The first successful authentication with the CURRENT token clears the
// in-memory pending entry, closing the old-token window early: once the new
// credential is demonstrably in the agent's hands, a party still presenting
// the old one is no longer the legitimate rotation survivor.
func (s *Service) AuthenticateAgent(ctx context.Context, token string) (AuthResult, error) {
	if token == "" {
		return AuthResult{}, ErrAuth
	}
	hash := sha256hex(token)
	var agentID, siteID string
	var epoch uint64
	var pendingHash string
	var pendingUntil int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, site_id, enrollment_epoch, pending_prev_token_hash, pending_prev_token_until
		FROM agents WHERE token_hash=? AND revoked=0`, hash).
		Scan(&agentID, &siteID, &epoch, &pendingHash, &pendingUntil)
	if errors.Is(err, sql.ErrNoRows) {
		// Not the current token. It may be the OLD token of a rotation whose
		// commit this process saw; only the pending columns can say, and only
		// the in-memory map can supply the token plaintext to re-issue.
		return s.authPending(ctx, hash)
	}
	if err != nil {
		return AuthResult{}, err
	}
	// First use of the current credential: the old token's window is over.
	s.clearPendingRotation(agentID)
	return AuthResult{AgentID: agentID, SiteID: siteID, Epoch: epoch}, nil
}

// authPending resolves a token that does not match the row's CURRENT hash
// against the rotation pending window: the presented token must be the OLD
// token of a committed rotation (pending_prev_token_hash) inside its window
// (pending_prev_token_until), AND this process must still hold the pending
// result in memory. Any gap fails closed with ErrAuth — including the
// post-restart state, where the column window survives but the re-issuable
// plaintext does not (see pendingRotationResult).
func (s *Service) authPending(ctx context.Context, hash string) (AuthResult, error) {
	var agentID, siteID string
	var epoch uint64
	var until int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, site_id, enrollment_epoch, pending_prev_token_until
		FROM agents WHERE pending_prev_token_hash=? AND revoked=0`, hash).
		Scan(&agentID, &siteID, &epoch, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthResult{}, ErrAuth
	}
	if err != nil {
		return AuthResult{}, err
	}
	if until <= 0 || time.Now().UTC().Unix() > until {
		return AuthResult{}, ErrAuth // window never opened, or closed
	}
	res := s.pendingRotationLookup(agentID)
	if res == nil {
		return AuthResult{}, ErrAuth // committed elsewhere (restart lost the map)
	}
	return AuthResult{
		AgentID: agentID,
		SiteID:  siteID,
		Epoch:   epoch,
		PendingRotation: &wire.EpochRotationResult{
			Status:     wire.RotationOK,
			NewEpoch:   res.newEpoch,
			AgentToken: res.newToken,
		},
	}, nil
}

// IssueRotationChallenge mints a one-time rotation challenge bound to
// (agentID, epoch) and remembers the binding (plus its expiry) in memory. The
// challenge string is base64 of 32 crypto/rand bytes — the agent treats it as
// opaque bytes to sign; its only server-side meaning is as a key into the
// binding map. reason tells the agent WHY it is being rotated (open enum; see
// wire.EpochRotationChallenge).
func (s *Service) IssueRotationChallenge(agentID string, epoch uint64, reason string) wire.EpochRotationChallenge {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	challenge := base64.RawURLEncoding.EncodeToString(b)
	expires := time.Now().UTC().Add(challengeTTL)
	s.rotMu.Lock()
	s.challenges[challenge] = &rotationChallenge{agentID: agentID, epoch: epoch, expires: expires}
	s.rotMu.Unlock()
	return wire.EpochRotationChallenge{Challenge: challenge, Reason: reason, ExpiresAt: expires}
}

// consumeChallenge validates that ch is live for (agentID, epoch) and unexpired,
// and consumes it: a challenge is single-use, so even a request that later
// fails its signature can never retry with the same one.
func (s *Service) consumeChallenge(ch, agentID string, epoch uint64) error {
	s.rotMu.Lock()
	defer s.rotMu.Unlock()
	c, ok := s.challenges[ch]
	if !ok || c.agentID != agentID || c.epoch != epoch {
		return ErrRotationChallenge
	}
	delete(s.challenges, ch)
	if time.Now().UTC().After(c.expires) {
		return ErrRotationChallenge
	}
	return nil
}

// RotateEpoch performs the controlled credential/epoch rotation: validate the
// challenge, verify the ed25519 possession proof against the enrolled public
// key, and — in ONE write transaction — advance enrollment_epoch, swap the
// token, open the old token's pending window, and zero the sequence watermark.
// Returns the new epoch and the new token (shown exactly once, like
// enrollment).
//
// Fail-closed on every mismatch: an unknown/expired/reused challenge, a row
// whose epoch already moved (concurrent rotation or reinstall — the guarded
// UPDATE's WHERE makes double rotation impossible: exactly one caller advances
// the epoch, the loser sees RowsAffected 0), or a bad signature all refuse the
// rotation outright. Token plaintexts are never logged; callers log epoch and
// reason only.
//
// After the commit the result is recorded in the in-memory pending map (the
// re-issue source for the old-token window) and the ResetSeqWatermark seam is
// invoked — the same seam reenrollment uses — so the ingest service's cached
// watermark follows the zeroed column and no straggler advance from a session
// that authenticated before the rotation can resurrect the old high.
func (s *Service) RotateEpoch(ctx context.Context, agentID string, req wire.EpochRotationRequest) (newEpoch uint64, newToken string, err error) {
	if err := s.consumeChallenge(req.Challenge, agentID, req.OldEpoch); err != nil {
		return 0, "", err
	}
	newToken = randToken()
	newHash := sha256hex(newToken)
	windowUntil := time.Now().UTC().Add(rotationPendingWindow)
	err = s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var pub []byte
		var epoch uint64
		var oldHash string
		if err := wtx.QueryRowContext(ctx,
			`SELECT public_key, enrollment_epoch, token_hash FROM agents WHERE id=? AND revoked=0`,
			agentID).Scan(&pub, &epoch, &oldHash); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrRotationEpoch
			}
			return nil, err
		}
		if epoch != req.OldEpoch {
			return nil, ErrRotationEpoch
		}
		// The possession proof: the challenge string signed with the key the
		// agent enrolled. Any mismatch fails closed.
		if !ed25519.Verify(ed25519.PublicKey(pub), []byte(req.Challenge), req.Signature) {
			return nil, ErrSignature
		}
		// The guarded epoch advance: the WHERE pins the rotation to the exact
		// generation this request proved possession for, so a concurrent
		// rotation (or reinstall) that committed first makes this one a no-op
		// loser instead of double-advancing the generation. high_sequence is
		// zeroed with the generation switch — the fresh epoch's watermark starts
		// at the same point a reinstall's does, and the hub pushes that floor
		// (AcceptedFloor) on the agent's reconnect.
		res, err := wtx.ExecContext(ctx, `
			UPDATE agents SET
				enrollment_epoch = enrollment_epoch + 1,
				token_hash = ?,
				pending_prev_token_hash = ?,
				pending_prev_token_until = ?,
				high_sequence = 0
			WHERE id = ? AND enrollment_epoch = ?`,
			newHash, oldHash, windowUntil.Unix(), agentID, req.OldEpoch)
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, ErrRotationEpoch
		}
		if err := wtx.QueryRowContext(ctx,
			`SELECT enrollment_epoch FROM agents WHERE id=?`, agentID).Scan(&newEpoch); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return 0, "", err
	}

	// The commit is durable. Record the pending result so a reconnect with the
	// OLD token re-issues it idempotently within the window.
	s.rotMu.Lock()
	s.pending[agentID] = &pendingRotationResult{newEpoch: newEpoch, newToken: newToken, until: windowUntil}
	s.rotMu.Unlock()
	// The column was zeroed inside the transaction above; the ingest service's
	// in-memory watermark must follow (the reenrollment seam).
	if s.ResetSeqWatermark != nil {
		s.ResetSeqWatermark(ctx, agentID)
	}
	return newEpoch, newToken, nil
}

// pendingRotationLookup returns the agent's re-issuable rotation result,
// evicting it lazily once its window has expired.
func (s *Service) pendingRotationLookup(agentID string) *pendingRotationResult {
	s.rotMu.Lock()
	defer s.rotMu.Unlock()
	res, ok := s.pending[agentID]
	if !ok {
		return nil
	}
	if time.Now().UTC().After(res.until) {
		delete(s.pending, agentID)
		return nil
	}
	return res
}

// clearPendingRotation drops the agent's pending rotation result. Called on the
// first successful authentication with the CURRENT token (the old-token window
// is over the moment the new credential is demonstrably in use) and after a
// reinstall (the previous generation's token died with the credential swap).
func (s *Service) clearPendingRotation(agentID string) {
	s.rotMu.Lock()
	delete(s.pending, agentID)
	s.rotMu.Unlock()
}
