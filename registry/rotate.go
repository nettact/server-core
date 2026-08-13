// Schema 8 (CLOUD-013C): credential generations and the controlled epoch
// rotation. Everything about the (agent, enrollment_epoch, sequence) identity
// — the challenge/request/result exchange, the two-phase credential switch,
// and the bearer authentication that reports which generation a token belongs
// to — lives in this file.
//
// The rotation is two-phase on purpose. A single-transaction token swap has a
// lockout window: the moment the swap commits, the old token dies, and a
// result lost in transit (the session can die right after the commit, before
// the frame is delivered) strands the agent with a credential the server no
// longer accepts — recovered only by a reinstall. Two phases remove the
// window entirely:
//
//   - Phase 1 (RotateEpoch) only STAGES the next generation
//     (pending_next_epoch/until). The old token stays fully live, so a lost
//     result is re-issued idempotently on the agent's reconnect until the
//     window closes.
//   - Phase 2 (AuthenticateAgent, seeing the deterministic NEXT token) swaps
//     token_hash, advances enrollment_epoch, zeroes the sequence watermark and
//     clears the pending columns in one write transaction — the agent has
//     proven it holds the new credential, so nothing can be stranded.
//
// The next token is DETERMINISTIC (rotationToken): HMAC-SHA256 of a persisted
// secret over agentID||epoch. A random token would exist in plaintext only
// until the result frame was delivered and would be lost on a server restart,
// locking the install out mid-rotation; a deterministic one can be re-derived
// forever, so phase 2 remains completable and the result re-issuable no
// matter how many times the process restarts inside the window. The secret
// (app_settings.rotation_key) is created lazily inside the phase-1
// transaction, so no plaintext bearer ever rests in the database.
package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
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
	// rotationPendingWindow is how long a phase-1 rotation stays staged: within
	// it the old token keeps authenticating (re-issuing the result) and the
	// deterministic next token completes the switch (phase 2). It is the
	// recovery window for a result lost in transit.
	rotationPendingWindow = 2 * time.Minute
	// rotationKeySetting is the app_settings key holding the rotation HMAC
	// secret. It is infrastructure, not an operator setting: written by the
	// registry itself, never listed or edited by the settings service.
	rotationKeySetting = "rotation_key"
)

var (
	// ErrRotationChallenge means the presented challenge is unknown, expired,
	// already consumed, or bound to a different (agent, epoch). Terminal for
	// this challenge: the hub answers RotationDenied.
	ErrRotationChallenge = errors.New("rotation challenge unknown, expired or mismatched")
	// ErrRotationEpoch means the agents row could not be rotated: it is gone,
	// or a concurrent rotation/reinstall moved it out from under the request.
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
	// PendingRotation is set when the presented token is the CURRENT (old)
	// token while a phase-1 rotation is staged within its window: the rotation
	// result must be re-issued idempotently instead of the floor.
	PendingRotation *wire.EpochRotationResult
}

// rotationChallenge is the server-side binding of one issued challenge: the
// challenge string (base64 of 32 random bytes, treated by the agent as opaque
// bytes to sign), the HELLO epoch it is bound to — the generation the agent
// will state as OldEpoch when it signs — and its expiry. One slot per agent:
// issuing a new challenge replaces any outstanding one, and issuance plus
// consumption both sweep expired entries, so the map never exceeds one entry
// per agent that has ever rotated (bounded by the agent table itself).
type rotationChallenge struct {
	challenge string
	epoch     uint64
	expires   time.Time
}

// AuthenticateAgent maps a bearer token to its agent identity, the credential
// generation it belongs to, and the rotation state that token implies:
//
//   - The CURRENT token while a phase-1 rotation is staged within its window
//     carries PendingRotation (the idempotent re-issue).
//   - The deterministic NEXT token of a staged rotation completes PHASE 2: one
//     write transaction swaps token_hash, advances enrollment_epoch, zeroes
//     high_sequence and clears the pending columns; post-commit the
//     ResetSeqWatermark seam (cache) and the DisconnectSession seam (fence any
//     residual old-epoch session) run, in that order. The result is a normal
//     AuthResult for the new generation.
//
// An expired staged rotation is treated as absent in both branches: the
// current token then authenticates plainly, and the next token is rejected.
func (s *Service) AuthenticateAgent(ctx context.Context, token string) (AuthResult, error) {
	if token == "" {
		return AuthResult{}, ErrAuth
	}
	hash := sha256hex(token)
	now := time.Now().UTC().Unix()
	var agentID, siteID string
	var epoch, nextEpoch uint64
	var nextUntil int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, site_id, enrollment_epoch, pending_next_epoch, pending_next_until
		FROM agents WHERE token_hash=? AND revoked=0`, hash).
		Scan(&agentID, &siteID, &epoch, &nextEpoch, &nextUntil)
	if errors.Is(err, sql.ErrNoRows) {
		// Not the current token. It may be the deterministic NEXT token of a
		// staged rotation: phase 2.
		return s.authPhase2(ctx, hash)
	}
	if err != nil {
		return AuthResult{}, err
	}
	// The current token, with a rotation staged inside its window: re-issue the
	// result idempotently (a lost delivery is recovered on this reconnect).
	if nextEpoch != 0 && nextUntil > 0 && now <= nextUntil {
		key, err := s.readRotationKey(ctx)
		if err != nil {
			return AuthResult{}, err
		}
		return AuthResult{
			AgentID: agentID, SiteID: siteID, Epoch: epoch,
			PendingRotation: &wire.EpochRotationResult{
				Status:     wire.RotationOK,
				NewEpoch:   nextEpoch,
				AgentToken: rotationToken(key, agentID, nextEpoch),
			},
		}, nil
	}
	return AuthResult{AgentID: agentID, SiteID: siteID, Epoch: epoch}, nil
}

// authPhase2 resolves a token that does not match the row's current hash
// against the staged rotations: the token must be the deterministic NEXT
// credential of an agent with a staged rotation. Completion is NOT
// window-gated — the token is the secret the agent was issued, and the agent
// may reconnect after the re-issue window lapsed (an offline upgrade, a long
// outage); the window only limits how long the OLD token can fetch the
// re-issued result, not when the new credential may first be used. The
// candidate scan runs on the read pool (a failed auth must not take the write
// lock); the authoritative re-check and the swap run in one write transaction.
// No matching candidate fails closed with ErrAuth — never with an empty
// result.
func (s *Service) authPhase2(ctx context.Context, hash string) (AuthResult, error) {
	key, err := s.readRotationKey(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthResult{}, ErrAuth // no rotation has ever committed
		}
		return AuthResult{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, site_id, enrollment_epoch, pending_next_epoch
		FROM agents WHERE revoked=0 AND pending_next_epoch>0`)
	if err != nil {
		return AuthResult{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, siteID string
		var curEpoch, nextEpoch uint64
		if err := rows.Scan(&id, &siteID, &curEpoch, &nextEpoch); err != nil {
			return AuthResult{}, err
		}
		if sha256hex(rotationToken(key, id, nextEpoch)) != hash {
			continue
		}
		rows.Close()
		return s.completeRotation(ctx, id, siteID, curEpoch, nextEpoch, hash)
	}
	if err := rows.Err(); err != nil {
		return AuthResult{}, err
	}
	return AuthResult{}, ErrAuth
}

// completeRotation is phase 2: the authoritative, guarded credential switch.
// The guard (enrollment_epoch and pending_next_epoch must be exactly the
// generation the candidate scan saw) makes a double completion impossible —
// a concurrent phase 1/2 that moved the row makes this a no-op loser, and the
// agent's reconnect retries against the row as it now stands.
func (s *Service) completeRotation(ctx context.Context, agentID, siteID string, curEpoch, nextEpoch uint64, hash string) (AuthResult, error) {
	err := s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		var dbCur, dbNext uint64
		if err := wtx.QueryRowContext(ctx, `
			SELECT enrollment_epoch, pending_next_epoch
			FROM agents WHERE id=? AND revoked=0`, agentID).Scan(&dbCur, &dbNext); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrAuth
			}
			return nil, err
		}
		// Deliberately NO window check here: the window limits how long the
		// OLD token can fetch the re-issued result, not when the issued
		// credential may first be used. The deterministic token IS the secret
		// the agent was handed; a late reconnect (outage, offline upgrade)
		// must still complete the switch or the agent is locked out forever.
		if dbCur != curEpoch || dbNext != nextEpoch {
			return nil, ErrAuth // the row moved on
		}
		res, err := wtx.ExecContext(ctx, `
			UPDATE agents SET
				token_hash=?, enrollment_epoch=?, high_sequence=0,
				pending_next_epoch=0, pending_next_until=0
			WHERE id=? AND enrollment_epoch=? AND pending_next_epoch=?`,
			hash, nextEpoch, agentID, dbCur, dbNext)
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, ErrAuth
		}
		// The old epoch's receipts are dead with the switch: the ledger keys on
		// (agent, epoch, sequence) and a new epoch can never replay an old slot,
		// so dropping them bounds the table to one epoch's worth of rows per
		// agent instead of letting it accumulate forever across rotations.
		if _, err := wtx.ExecContext(ctx,
			`DELETE FROM packet_receipts WHERE agent_id=? AND enrollment_epoch<?`,
			agentID, nextEpoch); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return AuthResult{}, err
	}
	// Post-commit, in order: the ingest watermark cache follows the zeroed
	// column (the same seam reenrollment uses), then any residual old-epoch
	// session is fenced — its epoch no longer matches the row, so its packets
	// are already refused by the epoch-pinned admission; the fence just ends
	// the session instead of letting it fail one packet at a time.
	if s.ResetSeqWatermark != nil {
		s.ResetSeqWatermark(ctx, agentID)
	}
	if s.DisconnectSession != nil {
		s.DisconnectSession(ctx, agentID)
	}
	return AuthResult{AgentID: agentID, SiteID: siteID, Epoch: nextEpoch}, nil
}

// IssueRotationChallenge mints a one-time rotation challenge bound to
// (agentID, epoch) — epoch is the HELLO generation the agent believes it is
// on, i.e. the value it will state as OldEpoch and sign with its enrolled
// key. The binding (plus its expiry) is remembered in memory only, one slot
// per agent: a new challenge replaces any outstanding one. reason tells the
// agent WHY it is being rotated (open enum; see wire.EpochRotationChallenge).
func (s *Service) IssueRotationChallenge(agentID string, epoch uint64, reason string) wire.EpochRotationChallenge {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	challenge := base64.RawURLEncoding.EncodeToString(b)
	expires := time.Now().UTC().Add(challengeTTL)
	s.rotMu.Lock()
	s.sweepChallengesLocked(time.Now().UTC())
	s.challenges[agentID] = &rotationChallenge{challenge: challenge, epoch: epoch, expires: expires}
	s.rotMu.Unlock()
	return wire.EpochRotationChallenge{Challenge: challenge, Reason: reason, ExpiresAt: expires}
}

// consumeChallenge validates that ch is live for (agentID, epoch) and unexpired,
// and consumes it: a challenge is single-use, so even a request that later
// fails its signature can never retry with the same one.
func (s *Service) consumeChallenge(ch, agentID string, epoch uint64) error {
	s.rotMu.Lock()
	defer s.rotMu.Unlock()
	s.sweepChallengesLocked(time.Now().UTC())
	c, ok := s.challenges[agentID]
	if !ok || c.challenge != ch || c.epoch != epoch {
		return ErrRotationChallenge
	}
	delete(s.challenges, agentID)
	if time.Now().UTC().After(c.expires) {
		return ErrRotationChallenge
	}
	return nil
}

// sweepChallengesLocked evicts expired challenge bindings. Called (under
// rotMu) on every issuance and consumption, which keeps the map at most one
// entry per agent that has recently rotated — the sweep is O(agents with a
// challenge), and the map's bound is the agent table itself, so no separate
// reaper is needed.
func (s *Service) sweepChallengesLocked(now time.Time) {
	for id, c := range s.challenges {
		if now.After(c.expires) {
			delete(s.challenges, id)
		}
	}
}

// RotateEpoch performs phase 1 of the controlled credential/epoch rotation:
// validate the challenge, verify the ed25519 possession proof against the
// enrolled public key, and — in ONE write transaction — STAGE the next
// generation. The live credential (token_hash, enrollment_epoch,
// high_sequence) is deliberately untouched: the old token stays fully valid
// until the agent proves it holds the deterministic next token (phase 2 in
// AuthenticateAgent), so a result lost in transit can never lock the install
// out. Returns the staged epoch and its deterministic token (shown exactly
// once per result, like enrollment).
//
// The new generation comes from the ROW (enrollment_epoch + 1), never from
// req.OldEpoch: a stale agent (Hello epoch behind the row) signs with the
// challenge bound to its HELLO epoch and jumps forward to row+1, a current
// one advances normally. If a rotation is already staged within its window,
// this call RE-ISSUES it idempotently — the double-rotation guard.
//
// Fail-closed on every mismatch: an unknown/expired/reused challenge or a bad
// signature refuses outright. Token plaintexts are never logged; callers log
// epoch and reason only.
func (s *Service) RotateEpoch(ctx context.Context, agentID string, req wire.EpochRotationRequest) (newEpoch uint64, newToken string, err error) {
	if err := s.consumeChallenge(req.Challenge, agentID, req.OldEpoch); err != nil {
		return 0, "", err
	}
	err = s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		// The rotation key is created lazily here, inside the same transaction
		// that first needs it (INSERT OR IGNORE, then read back), so its
		// creation and use can never interleave across processes.
		key, err := s.rotationKey(ctx, wtx)
		if err != nil {
			return nil, err
		}
		var pub []byte
		var epoch, pendingEpoch uint64
		var pendingUntil int64
		if err := wtx.QueryRowContext(ctx, `
			SELECT public_key, enrollment_epoch, pending_next_epoch, pending_next_until
			FROM agents WHERE id=? AND revoked=0`, agentID).
			Scan(&pub, &epoch, &pendingEpoch, &pendingUntil); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrRotationEpoch
			}
			return nil, err
		}
		// The possession proof: the challenge string signed with the key the
		// agent enrolled. Any mismatch fails closed.
		if !ed25519.Verify(ed25519.PublicKey(pub), []byte(req.Challenge), req.Signature) {
			return nil, ErrSignature
		}
		now := time.Now().UTC().Unix()
		if pendingEpoch != 0 && pendingUntil > now {
			// Already committed within its window: re-issue idempotently. This is
			// what makes concurrent double rotations harmless — both callers get
			// the same staged generation, and the row moves exactly once (phase 2).
			newEpoch = pendingEpoch
			newToken = rotationToken(key, agentID, pendingEpoch)
			return nil, nil
		}
		newEpoch = epoch + 1
		newToken = rotationToken(key, agentID, newEpoch)
		// Stage the switch. The epoch guard keeps a concurrent phase 2 (which
		// advances enrollment_epoch) from being overwritten by this straggler:
		// zero rows means the row moved on and this request must be re-issued
		// against the new generation instead.
		res, err := wtx.ExecContext(ctx, `
			UPDATE agents SET pending_next_epoch=?, pending_next_until=?
			WHERE id=? AND enrollment_epoch=?`,
			newEpoch, now+int64(rotationPendingWindow/time.Second), agentID, epoch)
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
		return nil, nil
	})
	if err != nil {
		return 0, "", err
	}
	return newEpoch, newToken, nil
}

// rotationKey reads (creating if absent) the rotation HMAC secret from
// app_settings, THROUGH the caller's write transaction: the write handle is a
// single connection, so reading via s.db while wtx holds it would deadlock.
// The INSERT OR IGNORE and the read-back are atomic under the single writer,
// so two first-time callers cannot disagree about the value.
func (s *Service) rotationKey(ctx context.Context, wtx store.WriteTx) ([]byte, error) {
	candidate := make([]byte, 32)
	if _, err := rand.Read(candidate); err != nil {
		return nil, err
	}
	if _, err := wtx.ExecContext(ctx,
		`INSERT OR IGNORE INTO app_settings(key, value) VALUES(?, ?)`,
		rotationKeySetting, base64.RawURLEncoding.EncodeToString(candidate)); err != nil {
		return nil, err
	}
	var enc string
	if err := wtx.QueryRowContext(ctx,
		`SELECT value FROM app_settings WHERE key=?`, rotationKeySetting).Scan(&enc); err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(enc)
}

// readRotationKey reads the rotation HMAC secret. Returns sql.ErrNoRows when
// no rotation has ever been staged (the key row does not exist yet).
func (s *Service) readRotationKey(ctx context.Context) ([]byte, error) {
	var enc string
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM app_settings WHERE key=?`, rotationKeySetting).Scan(&enc); err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(enc)
}

// rotationToken derives the deterministic bearer for one agent generation:
// base64url(HMAC-SHA256(rotationKey, agentID || big-endian uint64(epoch))).
// Determinism is what makes the rotation survive restarts and re-issuable
// forever: the plaintext never rests anywhere, but anyone holding the server
// secret (the server) can reproduce it on demand — phase 2 completion and the
// pending-window re-issue therefore need no in-memory state at all.
func rotationToken(key []byte, agentID string, epoch uint64) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(agentID))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], epoch)
	_, _ = mac.Write(b[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
