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

// TestRotateEpochHappyPath runs the full controlled rotation: challenge, signed
// request, commit. The row advances exactly one generation with the new token,
// the old token enters the pending window (its auth re-issues the result), the
// watermark column is zeroed and the ResetSeqWatermark seam is invoked; the
// first authentication with the CURRENT token then closes the old-token window.
func TestRotateEpochHappyPath(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)
	var resetCalls int
	reg.ResetSeqWatermark = func(context.Context, string) { resetCalls++ }

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
		t.Errorf("newToken = %q, want a fresh token distinct from the old one", newToken)
	}
	if resetCalls != 1 {
		t.Errorf("ResetSeqWatermark called %d times, want 1", resetCalls)
	}

	// The row advanced exactly one generation, swapped the token, opened the
	// old token's pending window, and zeroed the sequence watermark.
	var storedEpoch uint64
	var storedHash, pendingHash string
	var pendingUntil, high int64
	if err := db.QueryRowContext(ctx,
		`SELECT enrollment_epoch, token_hash, pending_prev_token_hash, pending_prev_token_until, high_sequence
		 FROM agents WHERE id=?`, agentID).
		Scan(&storedEpoch, &storedHash, &pendingHash, &pendingUntil, &high); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if storedEpoch != 2 {
		t.Errorf("enrollment_epoch = %d, want 2", storedEpoch)
	}
	if storedHash != sha256hex(newToken) {
		t.Errorf("token_hash is not the new token's hash")
	}
	if pendingHash != sha256hex(oldToken) {
		t.Errorf("pending_prev_token_hash is not the old token's hash")
	}
	if until := time.Unix(pendingUntil, 0); until.Before(time.Now().UTC()) || until.After(time.Now().UTC().Add(rotationPendingWindow+time.Minute)) {
		t.Errorf("pending_prev_token_until = %v, want now+%v", until, rotationPendingWindow)
	}
	if high != 0 {
		t.Errorf("high_sequence = %d after rotation, want 0", high)
	}

	// The old token is inside its pending window: authenticating it re-issues
	// the committed result idempotently.
	res, err := reg.AuthenticateAgent(ctx, oldToken)
	if err != nil {
		t.Fatalf("old token in the pending window: %v", err)
	}
	if res.AgentID != agentID || res.Epoch != 2 {
		t.Errorf("pending auth = agent %q epoch %d, want %q/2", res.AgentID, res.Epoch, agentID)
	}
	if res.PendingRotation == nil || res.PendingRotation.Status != wire.RotationOK ||
		res.PendingRotation.NewEpoch != 2 || res.PendingRotation.AgentToken != newToken {
		t.Fatalf("PendingRotation = %+v, want RotationOK epoch 2 with the new token", res.PendingRotation)
	}

	// First use of the CURRENT credential closes the old-token window.
	res, err = reg.AuthenticateAgent(ctx, newToken)
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	if res.Epoch != 2 || res.PendingRotation != nil {
		t.Errorf("current-token auth = epoch %d pending %+v, want epoch 2 with no pending", res.Epoch, res.PendingRotation)
	}
	if _, err := reg.AuthenticateAgent(ctx, oldToken); !errors.Is(err, ErrAuth) {
		t.Errorf("old token still authenticates after the new credential was first used: %v", err)
	}
}

// TestRotateEpochDeniesBadProofs pins the fail-closed paths: an unknown, an
// expired and an already-consumed challenge, a wrong old epoch, and a bad
// signature all refuse the rotation and leave the row untouched.
func TestRotateEpochDeniesBadProofs(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, oldToken, agentID := enrollTestAgent(t, reg, "site_default")

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
	reg.challenges[expired.Challenge].expires = time.Now().UTC().Add(-time.Second)
	reg.rotMu.Unlock()
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: expired.Challenge, OldEpoch: 1, Signature: sign(expired.Challenge),
	}); !errors.Is(err, ErrRotationChallenge) {
		t.Errorf("expired challenge = %v, want ErrRotationChallenge", err)
	}

	// Challenge bound to a different epoch than the request claims: the row is
	// still at 1, the challenge claims 2.
	offEpoch := reg.IssueRotationChallenge(agentID, 2, "test")
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: offEpoch.Challenge, OldEpoch: 2, Signature: sign(offEpoch.Challenge),
	}); !errors.Is(err, ErrRotationEpoch) {
		t.Errorf("off-epoch challenge = %v, want ErrRotationEpoch", err)
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

	// After the one successful rotation above the row is at epoch 2; every
	// denial before it left the row alone.
	var epoch uint64
	var tokenHash string
	if err := db.QueryRowContext(ctx, `SELECT enrollment_epoch, token_hash FROM agents WHERE id=?`, agentID).
		Scan(&epoch, &tokenHash); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if epoch != 2 {
		t.Errorf("enrollment_epoch = %d, want 2 (only the successful rotation advanced it)", epoch)
	}
	// The old token may no longer be current, but the hash column must still be
	// the last successfully rotated credential's.
	if tokenHash == sha256hex(oldToken) {
		t.Errorf("token_hash is still the pre-rotation token's hash")
	}
}

// TestDoubleRotationDoesNotDoubleAdvance: two live challenges for the same
// (agent, epoch) must not create two generations. The second request passes
// challenge consumption but loses the guarded epoch-pinned UPDATE.
func TestDoubleRotationDoesNotDoubleAdvance(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	reg := New(db, 0, nil)

	priv, _, agentID := enrollTestAgent(t, reg, "site_default")
	c1 := reg.IssueRotationChallenge(agentID, 1, "test")
	c2 := reg.IssueRotationChallenge(agentID, 1, "test")

	newEpoch, newToken, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: c1.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(c1.Challenge)),
	})
	if err != nil || newEpoch != 2 {
		t.Fatalf("first rotation = epoch %d, %v; want 2", newEpoch, err)
	}
	if _, _, err := reg.RotateEpoch(ctx, agentID, wire.EpochRotationRequest{
		Challenge: c2.Challenge, OldEpoch: 1, Signature: ed25519.Sign(priv, []byte(c2.Challenge)),
	}); !errors.Is(err, ErrRotationEpoch) {
		t.Fatalf("second rotation = %v, want ErrRotationEpoch", err)
	}

	var epoch uint64
	var tokenHash string
	if err := db.QueryRowContext(ctx, `SELECT enrollment_epoch, token_hash FROM agents WHERE id=?`, agentID).
		Scan(&epoch, &tokenHash); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if epoch != 2 {
		t.Errorf("enrollment_epoch = %d, want 2 (no double advance)", epoch)
	}
	if tokenHash != sha256hex(newToken) {
		t.Errorf("token_hash = %q, want the first rotation's token", tokenHash)
	}
}

// TestReinstallClosesRotationPendingWindow: a reinstall replaces the credential
// wholesale and ends any rotation window outright — the rotation's new token
// dies with the old lineage, and the pending entry cannot be re-issued to a
// stale holder.
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
	// The pending window is live: the old token re-issues the result.
	if res, err := reg.AuthenticateAgent(ctx, oldToken); err != nil || res.PendingRotation == nil {
		t.Fatalf("old token before reinstall = %+v, %v; want a pending rotation", res, err)
	}

	// Reinstall: a fresh key, a fresh credential, epoch 3.
	reToken, err := reg.CreateReinstallToken(ctx, agentID, time.Hour)
	if err != nil {
		t.Fatalf("CreateReinstallToken: %v", err)
	}
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	resp, err := reg.Enroll(ctx, enrollReq(priv2, pub2, reToken, "rotate-host-2", permission.PermissionReport{}))
	if err != nil {
		t.Fatalf("reinstall Enroll: %v", err)
	}
	if resp.EnrollmentEpoch != 3 {
		t.Fatalf("reinstall epoch = %d, want 3", resp.EnrollmentEpoch)
	}

	// Both previous-generation tokens are dead: the rotation's new token (the
	// credential swap superseded it before it was ever used) and the old token
	// (the pending entry was cleared with the window).
	for name, tok := range map[string]string{"pre-rotation": oldToken, "rotated": rotatedToken} {
		if _, err := reg.AuthenticateAgent(ctx, tok); !errors.Is(err, ErrAuth) {
			t.Errorf("%s token still authenticates after reinstall: %v", name, err)
		}
	}
	// The reinstall's credential is the live one, at its own generation.
	res, err := reg.AuthenticateAgent(ctx, resp.AgentToken)
	if err != nil || res.Epoch != 3 {
		t.Errorf("reinstall token auth = epoch %d, %v; want 3", res.Epoch, err)
	}
}
