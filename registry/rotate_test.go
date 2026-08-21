package registry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/store/storetest"
)

// enrollTestAgent enrolls one agent with a real ed25519 key and returns the
// keypair, the token, and the agent id.
func enrollTestAgent(t *testing.T, reg *Service, siteID string) (ed25519.PrivateKey, string, string) {
	t.Helper()
	ctx := context.Background()
	token, err := reg.CreateEnrollmentToken(ctx, siteID, "rotate-test", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	resp, err := reg.Enroll(ctx, enrollReq(priv, pub, token, "rotate-host", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if resp.EnrollmentEpoch != 1 {
		t.Fatalf("fresh enrollment epoch = %d, want 1", resp.EnrollmentEpoch)
	}
	return priv, resp.AgentToken, resp.AgentID
}

// TestAuthenticateAgentReportsEpoch pins the AuthResult contract: a current
// token authenticates to its agent with the generation it belongs to, and
// garbage does not authenticate at all.
func TestAuthenticateAgentReportsEpoch(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	_, token, agentID := enrollTestAgent(t, reg, "site_default")

	res, err := reg.AuthenticateAgent(ctx, token)
	if err != nil {
		t.Fatalf("AuthenticateAgent: %v", err)
	}
	if res.AgentID != agentID || res.SiteID != "site_default" {
		t.Errorf("auth = agent %q site %q, want %q/site_default", res.AgentID, res.SiteID, agentID)
	}
	if res.Epoch != 1 {
		t.Errorf("auth epoch = %d, want 1", res.Epoch)
	}
	if res.PendingRotation != nil {
		t.Errorf("auth of a current token carries a pending rotation: %+v", res.PendingRotation)
	}
	if _, err := reg.AuthenticateAgent(ctx, "bogus"); !errors.Is(err, ErrAuth) {
		t.Errorf("bogus token = %v, want ErrAuth", err)
	}
	if _, err := reg.AuthenticateAgent(ctx, ""); !errors.Is(err, ErrAuth) {
		t.Errorf("empty token = %v, want ErrAuth", err)
	}
}

// TestRotateEpochTwoPhase pins the phase split. Phase 1 (RotateEpoch) STAGES
// the next generation without touching the live credential: the old token
// keeps authenticating — carrying the idempotent re-issue — and the watermark
// column is untouched. Authenticating with the deterministic next token then
// completes phase 2: the swap commits with the epoch advanced, the watermark
// zeroed and the pending columns cleared, the ResetSeqWatermark and
// DisconnectSession seams fire in order, and the next token becomes the
// current credential.
func TestRotateEpochTwoPhase(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)
	var seamLog []string
	reg.ResetSeqWatermark = func(context.Context, string) { seamLog = append(seamLog, "reset") }
	reg.DisconnectSession = func(context.Context, string) { seamLog = append(seamLog, "disconnect") }

	priv, oldToken, agentID := enrollTestAgent(t, reg, "site_default")
	mustExec(t, db, `UPDATE agents SET high_sequence=77 WHERE id=?`, agentID)

	ch := reg.IssueRotationChallenge(agentID, 1, "sequence_conflict")
	if ch.Challenge == "" || ch.Reason != "sequence_conflict" {
		t.Fatalf("challenge = %+v, want a non-empty challenge with the reason echoed", ch)
	}
	if !ch.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("challenge expiry %v is not in the future", ch.ExpiresAt)
	}

	newEpoch, newToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge,
		OldEpoch:  1,
		Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil {
		t.Fatalf("RotateEpoch: %v", err)
	}
	if newEpoch != 2 {
		t.Errorf("newEpoch = %d, want 2", newEpoch)
	}
	if newToken == "" || newToken == oldToken {
		t.Errorf("newToken = %q, want a fresh deterministic token distinct from the old one", newToken)
	}
	if len(seamLog) != 0 {
		t.Errorf("phase 1 fired seams %v, want none — the old credential is still live", seamLog)
	}

	// Phase 1 staged the switch only: the live credential and the watermark
	// column are untouched; the pending columns hold the staged generation and
	// its window.
	var epoch uint64
	var storedHash string
	var pendingEpoch uint64
	var pendingUntil, high int64
	if err := db.QueryRowContext(ctx,
		`SELECT enrollment_epoch, token_hash, pending_next_epoch, pending_next_until, high_sequence
		 FROM agents WHERE id=?`, agentID).
		Scan(&epoch, &storedHash, &pendingEpoch, &pendingUntil, &high); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if epoch != 1 {
		t.Errorf("enrollment_epoch = %d after phase 1, want 1 (staged, not switched)", epoch)
	}
	if storedHash != sha256hex(oldToken) {
		t.Errorf("token_hash changed in phase 1")
	}
	if pendingEpoch != 2 {
		t.Errorf("pending_next_epoch = %d, want 2", pendingEpoch)
	}
	if until := time.Unix(pendingUntil, 0); until.Before(time.Now().UTC()) || until.After(time.Now().UTC().Add(rotationPendingWindow+time.Minute)) {
		t.Errorf("pending_next_until = %v, want now+%v", until, rotationPendingWindow)
	}
	if high != 77 {
		t.Errorf("high_sequence = %d after phase 1, want 77 (untouched)", high)
	}

	// The old token is the live credential, now carrying the re-issue.
	res, err := reg.AuthenticateAgent(ctx, oldToken)
	if err != nil {
		t.Fatalf("old token after phase 1: %v", err)
	}
	if res.AgentID != agentID || res.Epoch != 1 {
		t.Errorf("old-token auth = agent %q epoch %d, want %q/1", res.AgentID, res.Epoch, agentID)
	}
	if res.PendingRotation == nil || res.PendingRotation.Status != wire.RotationOK ||
		res.PendingRotation.NewEpoch != 2 || res.PendingRotation.AgentToken != newToken {
		t.Fatalf("PendingRotation = %+v, want RotationOK epoch 2 with the deterministic token", res.PendingRotation)
	}

	// Phase 2: the deterministic next token completes the switch.
	res, err = reg.AuthenticateAgent(ctx, newToken)
	if err != nil {
		t.Fatalf("next token: %v", err)
	}
	if res.AgentID != agentID || res.Epoch != 2 {
		t.Errorf("phase-2 auth = agent %q epoch %d, want %q/2", res.AgentID, res.Epoch, agentID)
	}
	if res.PendingRotation != nil {
		t.Errorf("phase-2 auth carries a pending rotation: %+v", res.PendingRotation)
	}
	if len(seamLog) != 2 || seamLog[0] != "reset" || seamLog[1] != "disconnect" {
		t.Errorf("phase-2 seams = %v, want [reset disconnect]", seamLog)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT enrollment_epoch, token_hash, pending_next_epoch, pending_next_until, high_sequence
		 FROM agents WHERE id=?`, agentID).
		Scan(&epoch, &storedHash, &pendingEpoch, &pendingUntil, &high); err != nil {
		t.Fatalf("read agent after phase 2: %v", err)
	}
	if epoch != 2 || storedHash != sha256hex(newToken) || pendingEpoch != 0 || pendingUntil != 0 || high != 0 {
		t.Errorf("row after phase 2 = epoch %d hash-ok %v pending %d/%d high %d, want 2/next/0/0/0",
			epoch, storedHash == sha256hex(newToken), pendingEpoch, pendingUntil, high)
	}

	// The old token is dead once the new credential is in use.
	if _, err := reg.AuthenticateAgent(ctx, oldToken); !errors.Is(err, ErrAuth) {
		t.Errorf("old token still authenticates after phase 2: %v", err)
	}
}

// TestRotationSurvivesServerRestart: the staged rotation and its deterministic
// token are durable across a process restart. Phase 1 runs, the store closes
// and reopens, a fresh Service over the same DB re-issues the same result to
// the old token, and the next token completes phase 2.
func TestRotationSurvivesServerRestart(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, oldToken, agentID := enrollTestAgent(t, reg, "site_default")
	ch := reg.IssueRotationChallenge(agentID, 1, "test")
	newEpoch, newToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil || newEpoch != 2 {
		t.Fatalf("phase 1 = epoch %d, %v; want 2", newEpoch, err)
	}

	// "Restart": a fresh Service over the same database file. storetest owns
	// the handle; reusing the same open DB with a new Service is the faithful
	// equivalent (nothing but the DB row and the persisted key are read).
	reg2 := New(db, 0, nil)
	res, err := reg2.AuthenticateAgent(ctx, oldToken)
	if err != nil {
		t.Fatalf("old token after restart: %v", err)
	}
	if res.PendingRotation == nil || res.PendingRotation.NewEpoch != 2 || res.PendingRotation.AgentToken != newToken {
		t.Fatalf("re-issued result = %+v, want the SAME deterministic token %q at epoch 2", res.PendingRotation, newToken)
	}
	res, err = reg2.AuthenticateAgent(ctx, newToken)
	if err != nil || res.Epoch != 2 {
		t.Fatalf("phase 2 after restart = epoch %d, %v; want 2", res.Epoch, err)
	}
}

// TestDoubleRotationDoesNotDoubleAdvance: a second rotation inside the staged
// window re-issues the SAME pending generation and token — concurrent or
// repeated rotations are idempotent, and the row moves exactly once (phase 2).
func TestDoubleRotationDoesNotDoubleAdvance(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, _, agentID := enrollTestAgent(t, reg, "site_default")
	c1 := reg.IssueRotationChallenge(agentID, 1, "test")
	e1, tok1, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: c1.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(c1.Challenge)),
	})
	if err != nil || e1 != 2 {
		t.Fatalf("first rotation = epoch %d, %v; want 2", e1, err)
	}

	c2 := reg.IssueRotationChallenge(agentID, 1, "test")
	e2, tok2, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: c2.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(c2.Challenge)),
	})
	if err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	if e2 != 2 || tok2 != tok1 {
		t.Fatalf("second rotation = epoch %d token %q, want the SAME staged epoch 2 token %q", e2, tok2, tok1)
	}
	var pendingEpoch uint64
	if err := db.QueryRowContext(ctx,
		`SELECT pending_next_epoch FROM agents WHERE id=?`, agentID).Scan(&pendingEpoch); err != nil {
		t.Fatalf("read pending: %v", err)
	}
	if pendingEpoch != 2 {
		t.Errorf("pending_next_epoch = %d, want 2 (no double advance)", pendingEpoch)
	}
}

// TestRotateEpochDeniesBadProofs pins the fail-closed paths: an unknown, an
// expired, a superseded and an already-consumed challenge, plus a bad
// signature, all refuse the rotation and leave the row untouched.
func TestRotateEpochDeniesBadProofs(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, _, agentID := enrollTestAgent(t, reg, "site_default")
	sign := func(ch string) []byte { return ed25519.Sign(priv, []byte(ch)) }

	// Unknown challenge.
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: "never-issued", OldEpoch: 1, Signature: sign("never-issued"),
	}); !errors.Is(err, ErrRotationChallenge) {
		t.Errorf("unknown challenge = %v, want ErrRotationChallenge", err)
	}

	// Expired challenge: age the binding in place (the 1-minute TTL is not
	// worth waiting out in a test).
	expired := reg.IssueRotationChallenge(agentID, 1, "test")
	reg.rotMu.Lock()
	reg.challenges[agentID].expires = time.Now().UTC().Add(-time.Second)
	reg.rotMu.Unlock()
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: expired.Challenge, OldEpoch: 1, Signature: sign(expired.Challenge),
	}); !errors.Is(err, ErrRotationChallenge) {
		t.Errorf("expired challenge = %v, want ErrRotationChallenge", err)
	}

	// Superseded challenge: a new issuance invalidates the previous one.
	first := reg.IssueRotationChallenge(agentID, 1, "test")
	_ = reg.IssueRotationChallenge(agentID, 1, "test")
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: first.Challenge, OldEpoch: 1, Signature: sign(first.Challenge),
	}); !errors.Is(err, ErrRotationChallenge) {
		t.Errorf("superseded challenge = %v, want ErrRotationChallenge", err)
	}

	// Bad signature: the challenge is valid, the proof is not.
	badSig := reg.IssueRotationChallenge(agentID, 1, "test")
	_, otherKey, _ := ed25519.GenerateKey(nil)
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: badSig.Challenge, OldEpoch: 1, Signature: ed25519.Sign(otherKey, []byte(badSig.Challenge)),
	}); !errors.Is(err, ErrSignature) {
		t.Errorf("bad signature = %v, want ErrSignature", err)
	}

	// Consumed challenge: use it once successfully, then again.
	reused := reg.IssueRotationChallenge(agentID, 1, "test")
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: reused.Challenge, OldEpoch: 1, Signature: sign(reused.Challenge),
	}); err != nil {
		t.Fatalf("first use of the challenge: %v", err)
	}
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: reused.Challenge, OldEpoch: 1, Signature: sign(reused.Challenge),
	}); !errors.Is(err, ErrRotationChallenge) {
		t.Errorf("reused challenge = %v, want ErrRotationChallenge", err)
	}

	// Every refusal left the row alone: epoch 1, no staged rotation.
	var epoch, pendingEpoch uint64
	if err := db.QueryRowContext(ctx,
		`SELECT enrollment_epoch, pending_next_epoch FROM agents WHERE id=?`, agentID).
		Scan(&epoch, &pendingEpoch); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if epoch != 1 || pendingEpoch != 2 {
		t.Errorf("row = epoch %d pending %d, want 1/2 (only the one successful phase 1 staged anything)",
			epoch, pendingEpoch)
	}
}

// TestStaleEpochRotation: a stale agent (Hello epoch behind the row) must be
// able to rotate. The challenge is bound to the HELLO epoch it signs with; the
// new generation comes from the ROW, so the stale agent jumps forward to
// row+1 — never "denied because old".
func TestStaleEpochRotation(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, oldToken, agentID := enrollTestAgent(t, reg, "site_default")
	// The row moves ahead to generation 3 (two prior credential replacements
	// the agent missed), while the agent still believes it is on 2.
	mustExec(t, db, `UPDATE agents SET enrollment_epoch=3 WHERE id=?`, agentID)

	ch := reg.IssueRotationChallenge(agentID, 2, "epoch_mismatch")
	newEpoch, newToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge, OldEpoch: 2, Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil {
		t.Fatalf("stale rotation: %v", err)
	}
	if newEpoch != 4 {
		t.Fatalf("staged epoch = %d, want row+1 = 4", newEpoch)
	}

	// The row's current credential (generation 3) is untouched and still the
	// live one, carrying the re-issue for the staged generation 4.
	res, err := reg.AuthenticateAgent(ctx, oldToken)
	if err != nil {
		t.Fatalf("current token after stale rotation: %v", err)
	}
	if res.Epoch != 3 {
		t.Errorf("auth epoch = %d, want 3 (the live generation)", res.Epoch)
	}
	if res.PendingRotation == nil || res.PendingRotation.NewEpoch != 4 || res.PendingRotation.AgentToken != newToken {
		t.Fatalf("PendingRotation = %+v, want epoch 4 with token %q", res.PendingRotation, newToken)
	}
}

// TestChallengeReplacementAndEviction pins the challenge store's bound: one
// slot per agent (issuance replaces), and expired entries are swept lazily by
// issuance and consumption, so the map never outlives the agents that rotated.
func TestChallengeReplacementAndEviction(t *testing.T) {
	db := storetest.Open(t)
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	_, _, agentID := enrollTestAgent(t, reg, "site_default")

	// Replacement: one slot per agent.
	first := reg.IssueRotationChallenge(agentID, 1, "first")
	reg.rotMu.Lock()
	if len(reg.challenges) != 1 || reg.challenges[agentID].challenge != first.Challenge {
		t.Fatalf("challenge store = %+v, want exactly the first challenge for the agent", reg.challenges)
	}
	reg.rotMu.Unlock()
	second := reg.IssueRotationChallenge(agentID, 1, "second")
	reg.rotMu.Lock()
	if len(reg.challenges) != 1 || reg.challenges[agentID].challenge != second.Challenge {
		t.Fatalf("challenge store after replacement = %+v, want exactly the second challenge", reg.challenges)
	}
	reg.rotMu.Unlock()
	if first.Challenge == second.Challenge {
		t.Fatal("a fresh issuance must carry a fresh challenge string")
	}

	// Expiry: an expired binding fails consumption and is swept by the next
	// issuance.
	expired := reg.IssueRotationChallenge(agentID, 1, "expired")
	reg.rotMu.Lock()
	reg.challenges[agentID].expires = time.Now().UTC().Add(-time.Second)
	reg.rotMu.Unlock()
	if err := reg.consumeChallenge(expired.Challenge, agentID, 1); !errors.Is(err, ErrRotationChallenge) {
		t.Fatalf("expired challenge consumed = %v, want ErrRotationChallenge", err)
	}
	reg.rotMu.Lock()
	if len(reg.challenges) != 0 {
		t.Errorf("consume left the expired binding behind: %+v", reg.challenges)
	}
	reg.rotMu.Unlock()

	// The sweep also runs on issuance: plant an expired entry for a second
	// agent, then issue for the first and watch the store shrink.
	mustExec(t, db, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_b','site_default',x'00','h','online')`)
	planted := reg.IssueRotationChallenge("agent_b", 1, "planted")
	reg.rotMu.Lock()
	reg.challenges["agent_b"].expires = time.Now().UTC().Add(-time.Second)
	reg.rotMu.Unlock()
	_ = reg.IssueRotationChallenge(agentID, 1, "sweeping")
	reg.rotMu.Lock()
	_, plantedAlive := reg.challenges["agent_b"]
	reg.rotMu.Unlock()
	if plantedAlive {
		t.Errorf("issuance did not sweep the expired binding %q", planted.Challenge)
	}

	// The map holds at most one live entry per agent that has rotated; nothing
	// else ever lands in it.
	reg.rotMu.Lock()
	n := len(reg.challenges)
	reg.rotMu.Unlock()
	if n != 1 {
		t.Errorf("challenge store holds %d entries after the sweep, want 1", n)
	}
}

// TestReinstallClosesRotationPendingWindow: a reinstall replaces the credential
// wholesale and invalidates any staged rotation of the dead lineage — the
// staged next token dies with it (the pending columns are zeroed), and the
// reinstall's credential is the live one at its own generation.
func TestReinstallClosesRotationPendingWindow(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, oldToken, agentID := enrollTestAgent(t, reg, "site_default")
	ch := reg.IssueRotationChallenge(agentID, 1, "test")
	newEpoch, rotatedToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil || newEpoch != 2 {
		t.Fatalf("rotation = epoch %d, %v; want 2", newEpoch, err)
	}
	// The staged window is live: the old token re-issues the result.
	if res, err := reg.AuthenticateAgent(ctx, oldToken); err != nil || res.PendingRotation == nil {
		t.Fatalf("old token before reinstall = %+v, %v; want a pending rotation", res, err)
	}

	// Reinstall: a fresh key, a fresh credential, epoch 2 (bumped from 1 by
	// the reinstall itself — the staged rotation never committed).
	reToken, err := reg.CreateReinstallToken(ctx, agentID, time.Hour)
	if err != nil {
		t.Fatalf("CreateReinstallToken: %v", err)
	}
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	resp, err := reg.Enroll(ctx, enrollReq(priv2, pub2, reToken, "rotate-host-2", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("reinstall Enroll: %v", err)
	}
	if resp.EnrollmentEpoch != 2 {
		t.Fatalf("reinstall epoch = %d, want 2", resp.EnrollmentEpoch)
	}

	// Both previous-lineage tokens are dead: the staged next token (the
	// pending columns were zeroed, so phase 2 cannot fire) and the old token
	// (the credential swap superseded it).
	for name, tok := range map[string]string{"pre-rotation": oldToken, "staged": rotatedToken} {
		if _, err := reg.AuthenticateAgent(ctx, tok); !errors.Is(err, ErrAuth) {
			t.Errorf("%s token still authenticates after reinstall: %v", name, err)
		}
	}
	var pendingEpoch uint64
	if err := db.QueryRowContext(ctx,
		`SELECT pending_next_epoch FROM agents WHERE id=?`, agentID).Scan(&pendingEpoch); err != nil {
		t.Fatalf("read pending: %v", err)
	}
	if pendingEpoch != 0 {
		t.Errorf("pending_next_epoch = %d after reinstall, want 0", pendingEpoch)
	}
	// The reinstall's credential is the live one, at its own generation.
	res, err := reg.AuthenticateAgent(ctx, resp.AgentToken)
	if err != nil || res.Epoch != 2 {
		t.Errorf("reinstall token auth = epoch %d, %v; want 2", res.Epoch, err)
	}
}

// TestPhase2CompletesAfterWindowExpiry: the window limits how long the OLD
// token can fetch the re-issued result, NOT when the new credential may first
// be used. An agent that persisted the rotated token and reconnects late (an
// outage, an offline upgrade) must still complete the switch — otherwise the
// only credential it holds would be permanently rejected and recovery would
// mean reinstalling.
func TestPhase2CompletesAfterWindowExpiry(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, token, agentID := enrollTestAgent(t, reg, "site_default")
	ch := reg.IssueRotationChallenge(agentID, 1, "sequence_conflict")
	newEpoch, newToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge,
		OldEpoch:  1,
		Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil {
		t.Fatalf("RotateEpoch: %v", err)
	}
	if newEpoch != 2 {
		t.Fatalf("staged epoch = %d, want 2", newEpoch)
	}
	// The re-issue window has closed: force the column into the past. The old
	// token must no longer fetch the result...
	mustExec(t, db, `UPDATE agents SET pending_next_until=? WHERE id=?`, 1, agentID)
	res, err := reg.AuthenticateAgent(ctx, token)
	if err != nil {
		t.Fatalf("old token after window: %v", err)
	}
	if res.PendingRotation != nil {
		t.Fatalf("expired window still re-issues: %+v", res.PendingRotation)
	}
	// ...but the issued credential itself completes phase 2 regardless.
	res, err = reg.AuthenticateAgent(ctx, newToken)
	if err != nil {
		t.Fatalf("staged token after window: %v", err)
	}
	if res.AgentID != agentID || res.Epoch != 2 || res.PendingRotation != nil {
		t.Fatalf("phase 2 auth = %+v, want %q at epoch 2 with no pending", res, agentID)
	}
	var nextEpoch int64
	if err := db.QueryRowContext(ctx, `SELECT pending_next_epoch FROM agents WHERE id=?`, agentID).Scan(&nextEpoch); err != nil {
		t.Fatalf("read pending column: %v", err)
	}
	if nextEpoch != 0 {
		t.Errorf("pending_next_epoch after phase 2 = %d, want 0", nextEpoch)
	}
	// The old token is now revoked by the swap.
	if _, err := reg.AuthenticateAgent(ctx, token); !errors.Is(err, ErrAuth) {
		t.Errorf("old token after phase 2 = %v, want ErrAuth", err)
	}
}

// TestRotationPurgesOldEpochReceipts pins the P2 review fix: completing a
// rotation drops the previous epoch's receipt rows, so packet_receipts stays
// bounded to one epoch per agent instead of accumulating forever across
// credential generations.
func TestRotationPurgesOldEpochReceipts(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, token, agentID := enrollTestAgent(t, reg, "site_default")
	ch := reg.IssueRotationChallenge(agentID, 1, "sequence_conflict")
	newEpoch, newToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge,
		OldEpoch:  1,
		Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil {
		t.Fatalf("RotateEpoch: %v", err)
	}
	// A receipt the OLD epoch left behind, still sitting in the ledger.
	mustExec(t, db, `INSERT INTO packet_receipts(agent_id, enrollment_epoch, sequence, fingerprint, received_at) VALUES(?,1,1,'fp',?)`, agentID, time.Now().UTC().Unix())

	// Phase 2 completes the switch and must drop the old epoch's rows.
	if _, err := reg.AuthenticateAgent(ctx, newToken); err != nil {
		t.Fatalf("phase-2 auth: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM packet_receipts WHERE agent_id=? AND enrollment_epoch<?`, agentID, newEpoch).Scan(&n); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d old-epoch receipts survived the rotation, want 0", n)
	}
	// The old token is now dead, proving the receipt was the old epoch's only
	// trail and the ledger no longer references it.
	if _, err := reg.AuthenticateAgent(ctx, token); !errors.Is(err, ErrAuth) {
		t.Errorf("old token after rotation = %v, want ErrAuth", err)
	}
}

// The three independent anti-stranding regressions. The two-phase rotation
// already structurally satisfies them (completeRotation is the only place the
// old credential is revoked, and it is reached only by the NEW token's first
// authentication), but the existing flow test (TestRotateEpochTwoPhase) rolls
// all three into one sequence, so a refactor that breaks one strand cannot be
// pointed at. Each test below stands alone, and the third exists precisely to
// catch a "revoke-on-commit" family that the first two would both pass: an
// implementation that swapped token_hash at phase-1 commit fails R2 and R3,
// while one that revoked the old credential after the first delivery or at
// window expiry passes R1 and R2 — only R3's "delivered many times + window
// expired + old token still live, revoked only by the new token's first use"
// sequence stops it.

// TestRotationResultReissueIsIdempotent (R1): a result lost in transit is
// re-served as the SAME result — same new epoch, same token, byte for byte —
// however many times the old token reconnects, and identically after a
// process restart. Re-issuing a NEW round on every reconnect would strand a
// peer that just missed the first delivery.
func TestRotationResultReissueIsIdempotent(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, oldToken, agentID := enrollTestAgent(t, reg, "site_default")
	ch := reg.IssueRotationChallenge(agentID, 1, "test")
	newEpoch, newToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil || newEpoch != 2 {
		t.Fatalf("phase 1 = epoch %d, %v; want 2", newEpoch, err)
	}

	var prev *wire.EpochRotationResult
	for i := 0; i < 3; i++ {
		res, err := reg.AuthenticateAgent(ctx, oldToken)
		if err != nil {
			t.Fatalf("auth %d: %v", i, err)
		}
		if res.PendingRotation == nil {
			t.Fatalf("auth %d: no pending rotation", i)
		}
		if prev != nil && (res.PendingRotation.NewEpoch != prev.NewEpoch || res.PendingRotation.AgentToken != prev.AgentToken) {
			t.Fatalf("re-issue %d changed: %+v vs %+v", i, res.PendingRotation, prev)
		}
		prev = res.PendingRotation
	}

	// "Restart": a fresh Service over the same database re-issues the identical
	// result.
	reg2 := New(db, 0, nil)
	res, err := reg2.AuthenticateAgent(ctx, oldToken)
	if err != nil {
		t.Fatalf("auth after restart: %v", err)
	}
	if res.PendingRotation == nil || res.PendingRotation.NewEpoch != prev.NewEpoch ||
		res.PendingRotation.AgentToken != prev.AgentToken || res.PendingRotation.AgentToken != newToken {
		t.Fatalf("post-restart result = %+v, want the SAME result %+v (token %q)", res.PendingRotation, prev, newToken)
	}
}

// TestOldTokenServesWhileRotationStaged (R2): staging a rotation must not
// touch the old credential's present usability — it still authenticates to the
// same identity at the OLD generation, and the token_hash column is unchanged.
func TestOldTokenServesWhileRotationStaged(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, oldToken, agentID := enrollTestAgent(t, reg, "site_default")
	ch := reg.IssueRotationChallenge(agentID, 1, "test")
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	}); err != nil {
		t.Fatalf("phase 1: %v", err)
	}

	res, err := reg.AuthenticateAgent(ctx, oldToken)
	if err != nil {
		t.Fatalf("old token while staged: %v", err)
	}
	if res.AgentID != agentID || res.Epoch != 1 {
		t.Fatalf("auth = %+v, want %q at epoch 1", res, agentID)
	}
	var hash string
	if err := db.QueryRowContext(ctx, `SELECT token_hash FROM agents WHERE id=?`, agentID).Scan(&hash); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if hash != sha256hex(oldToken) {
		t.Fatalf("token_hash changed during staging")
	}
}

// TestOldCredentialOutlivesUnusedNewCredential (R3): the ONLY trigger that
// revokes the old credential is the new credential's first use. Staging the
// rotation, delivering the result, and letting the staging window lapse each
// leave the old credential live — so a peer that received the result but never
// used it is never locked out. This is the test that a "revoke on commit"
// implementation (phase 1 swaps token_hash) AND a "revoke after first
// delivery / at window expiry" implementation both fail, while R1 and R2 alone
// would pass the latter.
func TestOldCredentialOutlivesUnusedNewCredential(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, oldToken, agentID := enrollTestAgent(t, reg, "site_default")
	ch := reg.IssueRotationChallenge(agentID, 1, "test")
	newEpoch, newToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: ch.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(ch.Challenge)),
	})
	if err != nil || newEpoch != 2 {
		t.Fatalf("phase 1 = epoch %d, %v; want 2", newEpoch, err)
	}

	// The result is delivered (fetched) several times: delivery is not the
	// revocation trigger.
	for i := 0; i < 3; i++ {
		res, err := reg.AuthenticateAgent(ctx, oldToken)
		if err != nil || res.PendingRotation == nil {
			t.Fatalf("delivery %d = %+v, %v; want a pending rotation", i, res, err)
		}
	}

	// The staging window lapses: by the window's own semantics the staging is
	// now absent, and the old token is the ONLY live credential.
	mustExec(t, db, `UPDATE agents SET pending_next_until=? WHERE id=?`, 1, agentID)

	// The old credential still authenticates — revocation happens only on the
	// NEW credential's first use, never on staging, never on delivery, never on
	// window expiry.
	res, err := reg.AuthenticateAgent(ctx, oldToken)
	if err != nil {
		t.Fatalf("old token after window expiry, before first new-token use: %v", err)
	}
	if res.AgentID != agentID || res.Epoch != 1 {
		t.Fatalf("auth = %+v, want %q at epoch 1", res, agentID)
	}
	if res.PendingRotation != nil {
		t.Fatalf("expired window still re-issues: %+v", res.PendingRotation)
	}

	// The first use of the new credential completes phase 2...
	if _, err := reg.AuthenticateAgent(ctx, newToken); err != nil {
		t.Fatalf("first use of new token: %v", err)
	}
	// ...and only now is the old credential revoked.
	if _, err := reg.AuthenticateAgent(ctx, oldToken); !errors.Is(err, ErrAuth) {
		t.Fatalf("old token after first new-token use = %v, want ErrAuth", err)
	}
}
