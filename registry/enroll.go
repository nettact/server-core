package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/enroll"
)

var (
	// ErrQuota means the configured max_agents limit has been reached.
	ErrQuota = errors.New("agent quota reached")
	// ErrEnrollToken means the enrollment token is missing, used, or expired.
	ErrEnrollToken = errors.New("invalid or expired enrollment token")
	// ErrSignature means the ed25519 possession proof failed.
	ErrSignature = errors.New("invalid enrollment signature")
	// ErrAuth means a bearer token did not match a live agent.
	ErrAuth = errors.New("unauthorized")
	// ErrReinstallAgent means a reinstall token's bound agent no longer exists
	// (deleted between minting and redemption). Distinct from ErrEnrollToken so
	// the API can explain what actually went wrong.
	ErrReinstallAgent = errors.New("reinstall token targets a missing agent")
)

// --- enrollment tokens ---

// EnrollmentToken is metadata about an issued token (never the plaintext).
type EnrollmentToken struct {
	TokenHash string     `json:"token_hash"`
	SiteID    string     `json:"site_id"`
	AgentID   *string    `json:"agent_id"` // non-nil = reinstall token bound to that agent
	Note      string     `json:"note"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	Revoked   bool       `json:"revoked"`
}

// CreateEnrollmentToken issues a one-time token bound to a site; only the hash
// is stored. The plaintext is returned once.
//
// The note is not merely a label on the token list: whoever mints a token
// already knows which machine it is for ("living-room router"), and Enroll
// carries that note onto the agent it creates as its initial display_name.
// Without that, the operator names the device twice — once when minting, once
// again in the agent list after it appears under a bare hostname — and the note
// they typed decays into a row about a credential nobody looks at again.
func (s *Service) CreateEnrollmentToken(ctx context.Context, siteID, note string, ttl time.Duration) (string, error) {
	token := randToken()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO enrollment_tokens(token_hash, site_id, note, expires_at) VALUES(?,?,?,?)`,
		sha256hex(token), siteID, note, time.Now().UTC().Add(ttl)); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT token_hash, site_id, COALESCE(note,''), expires_at, used_at, agent_id, revoked
		 FROM enrollment_tokens ORDER BY expires_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		var used sql.NullTime
		var agentID sql.NullString
		var revoked int
		if err := rows.Scan(&t.TokenHash, &t.SiteID, &t.Note, &t.ExpiresAt, &used, &agentID, &revoked); err != nil {
			return nil, err
		}
		if used.Valid {
			u := used.Time
			t.UsedAt = &u
		}
		if agentID.Valid {
			t.AgentID = &agentID.String
		}
		t.Revoked = revoked != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateReinstallToken mints a one-time token bound to an existing agent: on
// redemption the agent rejoins under the SAME agent_id instead of enrolling a
// new row (AGENT-006), inheriting its metrics/incident/status history. Only the
// hash is stored; the plaintext is returned once. Returns sql.ErrNoRows if no
// live agent has that id. The note is set by the server so the token list
// self-describes.
//
// Minting supersedes the agent's other unused reinstall tokens: a console that
// opens and closes the reinstall dialog several times must not leave a pile of
// valid 24h credentials for the same identity (an earlier one could rebind the
// agent after a fresh one was handed out). Lookup, supersession, and insertion
// run in ONE transaction so two concurrent mints cannot both slip past the
// revoke-before-insert ordering and leave two valid tokens.
func (s *Service) CreateReinstallToken(ctx context.Context, agentID string, ttl time.Duration) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var siteID string
	if err := tx.QueryRowContext(ctx,
		`SELECT site_id FROM agents WHERE id=? AND revoked=0`, agentID).Scan(&siteID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE enrollment_tokens SET revoked=1 WHERE agent_id=? AND used_at IS NULL AND revoked=0`,
		agentID); err != nil {
		return "", err
	}
	token := randToken()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO enrollment_tokens(token_hash, site_id, note, expires_at, agent_id)
		 VALUES(?,?,?,?,?)`,
		sha256hex(token), siteID, "reinstall:"+agentID, time.Now().UTC().Add(ttl), agentID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// RevokeEnrollmentToken voids an unused enrollment token. Revoking a used or
// already-revoked token is a no-op and reports sql.ErrNoRows (a used token was
// consumed; the row only carries history). Expired-but-unused tokens may still
// be revoked harmlessly.
func (s *Service) RevokeEnrollmentToken(ctx context.Context, tokenHash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE enrollment_tokens SET revoked=1 WHERE token_hash=? AND used_at IS NULL AND revoked=0`,
		tokenHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- enroll ---

// Enroll verifies the possession proof and one-time token, enforces the agent
// quota, creates the agent, and returns a bearer token (shown once). A fresh
// enrollment inherits the token's note as its display name (see
// CreateEnrollmentToken); a reinstall token keeps the existing agent's name.
func (s *Service) Enroll(ctx context.Context, req enroll.EnrollRequest) (enroll.EnrollResponse, error) {
	if err := protocol.ValidateSchema(req.SchemaVersion); err != nil {
		return enroll.EnrollResponse{}, err
	}
	if len(req.PublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(req.PublicKey), []byte(req.Nonce), req.Signature) {
		return enroll.EnrollResponse{}, ErrSignature
	}

	// A reinstall token redeems against a live session that must be fenced BEFORE
	// this transaction takes the single write handle: the hub's session teardown
	// writes through that same handle, so disconnecting while holding it would
	// deadlock. The hint read is best-effort — the authoritative token validation
	// still happens inside the transaction — and only matches currently-valid
	// reinstall tokens, so a revoked/used/expired token cannot be used to bounce
	// someone's session.
	if s.DisconnectSession != nil {
		if agentID := s.reinstallTarget(ctx, req.EnrollmentToken); agentID != "" {
			s.DisconnectSession(ctx, agentID)
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return enroll.EnrollResponse{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var siteID string
	var expiresAt time.Time
	var usedAt sql.NullTime
	var tokenAgentID sql.NullString
	var revoked int
	var tokenNote string
	err = tx.QueryRowContext(ctx,
		`SELECT site_id, expires_at, used_at, agent_id, revoked, COALESCE(note,'') FROM enrollment_tokens WHERE token_hash=?`,
		sha256hex(req.EnrollmentToken)).Scan(&siteID, &expiresAt, &usedAt, &tokenAgentID, &revoked, &tokenNote)
	if errors.Is(err, sql.ErrNoRows) {
		return enroll.EnrollResponse{}, ErrEnrollToken
	}
	if err != nil {
		return enroll.EnrollResponse{}, err
	}
	if revoked != 0 || usedAt.Valid || time.Now().UTC().After(expiresAt) {
		return enroll.EnrollResponse{}, ErrEnrollToken
	}

	now := time.Now().UTC()
	var agentID, agentToken string
	var siteSerial int
	var enrollmentEpoch uint64 = 1 // fresh enrollments are generation 1
	reclaimed := false
	if tokenAgentID.Valid && tokenAgentID.String != "" {
		// A reinstall token (AGENT-006) rejoins the bound agent's row under the
		// SAME agent_id instead of minting a new one: metrics, incidents and status
		// history are inherited, and no "old offline + new online" pair is produced.
		// The quota is irrelevant because no row is added. The bound agent must
		// still be live (not hard-deleted) — reenrollAgent reports ErrReinstallAgent.
		// (The old session was already fenced pre-transaction; see above.)
		siteID, siteSerial, agentToken, enrollmentEpoch, err = s.reenrollAgent(ctx, tx, tokenAgentID.String, req)
		if err != nil {
			return enroll.EnrollResponse{}, err
		}
		agentID = tokenAgentID.String
		reclaimed = true
	} else {
		if s.maxAgents > 0 {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE revoked=0`).Scan(&n); err != nil {
				return enroll.EnrollResponse{}, err
			}
			if n >= s.maxAgents {
				return enroll.EnrollResponse{}, ErrQuota
			}
		}

		agentID = "agent_" + uuid.NewString()
		agentToken = randToken()

		// The token's note is this device's name from the moment it appears. It is
		// what the operator typed when minting the token to describe the machine
		// they were about to install on, so applying it here is the difference
		// between an agent list of hostnames the operator has to decode and one
		// that reads the way they described their own network. It stays editable
		// afterwards (UpdateAgent) — this only decides the FIRST name, and an empty
		// note leaves display_name NULL so the UI falls back to the hostname.
		//
		// Only a fresh enrollment does this. A reinstall token takes the branch
		// above, which must not touch the name: its note is the server-generated
		// "reinstall:<agent_id>" (see CreateReinstallToken), and the agent it
		// rejoins already carries whatever the operator named it.
		var displayName sql.NullString
		if note := strings.TrimSpace(tokenNote); note != "" {
			displayName = sql.NullString{String: note, Valid: true}
		}

		// The enrollment report's unsupported reasons are stored like the sets beside
		// them: a first-time agent whose sensor is broken is precisely when an operator
		// is looking at the page, so the "why" must be there from the first report and
		// not only after the first reconnect refreshes it.
		//
		// enrollment_epoch defaults to 1; the pending-rotation staging columns are
		// named explicitly so a fresh row reads the same shape a reader of any
		// other row expects (0 = no pending rotation).
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO agents(id, site_id, public_key, token_hash, display_name, hostname, platform, agent_version,
			                   perm_supported, perm_granted, perm_effective, perm_unsupported_reasons,
			                   policy_source, policy_hash,
			                   status, last_seen_at, created_at,
			                   enrollment_epoch, pending_next_epoch, pending_next_until)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'online', ?, ?, 1, 0, 0)`,
			agentID, siteID, []byte(req.PublicKey), sha256hex(agentToken), displayName,
			req.Hostname, req.Platform, req.AgentVersion,
			marshalStrings(req.Permissions.Supported), marshalStrings(req.Permissions.Granted),
			marshalStrings(req.Permissions.Effective),
			marshalReasons(req.Permissions.UnsupportedReasons, req.Permissions.Supported),
			req.Permissions.Source, req.Permissions.PolicyHash,
			now, now); err != nil {
			return enroll.EnrollResponse{}, err
		}
		// The site config serial is the desired-config axis; report it (informational —
		// the agent starts at appliedConfigVersion = -1 and applies the first pushed
		// DesiredState regardless).
		if err := tx.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id=?`, siteID).Scan(&siteSerial); err != nil {
			return enroll.EnrollResponse{}, err
		}
		// A brand-new agent is online from the moment it enrolls. A REINSTALL is
		// deliberately not marked here — that transition belongs to the new session's
		// Hello, so the offline→online event fires (and a reinstall that never
		// connects stays visibly offline).
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO agent_status_history(id, agent_id, status, changed_at) VALUES(?,?,'online',?)`,
			"ash_"+uuid.NewString(), agentID, now); err != nil {
			return enroll.EnrollResponse{}, err
		}
	}

	// Shared tail: consume the one-time token and commit. A reinstall consumes its
	// token row just like a first enrollment, so a stolen reinstall token is
	// single-use.
	if _, err := tx.ExecContext(ctx,
		`UPDATE enrollment_tokens SET used_at=? WHERE token_hash=?`, now, sha256hex(req.EnrollmentToken)); err != nil {
		return enroll.EnrollResponse{}, err
	}
	if err := tx.Commit(); err != nil {
		return enroll.EnrollResponse{}, err
	}
	committed = true

	// A reenrollment reused an identity whose WAL was wiped; reset the ingest
	// service's in-memory sequence watermark (and bump its epoch, discarding any
	// straggler advance from a session that authenticated before the rotation)
	// so the first ack reflects the zeroed agents.high_sequence instead of the
	// old installation's high.
	if reclaimed && s.ResetSeqWatermark != nil {
		s.ResetSeqWatermark(ctx, agentID)
	}

	return enroll.EnrollResponse{
		AgentID: agentID, SiteID: siteID, AgentToken: agentToken,
		ServerTime: now, ConfigVersion: siteSerial,
		EnrollmentEpoch: enrollmentEpoch,
	}, nil
}

// reinstallTarget reports the agent a currently-valid reinstall token is bound to,
// or "". It is a read-only hint taken OUTSIDE the enroll transaction so the
// caller can fence a live session before taking the single write handle (the
// hub's teardown writes through that handle — disconnecting while holding it
// deadlocks). Only tokens that could still redeem are matched, so a
// revoked/used/expired token cannot be used to bounce someone's session; the
// authoritative check still runs inside the transaction.
func (s *Service) reinstallTarget(ctx context.Context, token string) string {
	if token == "" {
		return ""
	}
	var agentID sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT agent_id FROM enrollment_tokens
		 WHERE token_hash=? AND agent_id IS NOT NULL AND revoked=0 AND used_at IS NULL AND expires_at > ?`,
		sha256hex(token), time.Now().UTC()).Scan(&agentID); err != nil || !agentID.Valid {
		return ""
	}
	return agentID.String
}

// reenrollAgent re-binds an existing agents row to a freshly installed machine.
// Only the machine-owned identity and reported fields are rewritten — public_key,
// token_hash, hostname/platform/agent_version, the permission mirror (reset per
// AGENT-006: the next install command's --permissions decides), and the
// config-watermark bookkeeping. Operator state is preserved: site_id, created_at,
// first_connected_at, display_name, connectivity_alerts_muted, revoked.
//
// The agent is set offline here even when the previous session left it online: a
// reinstall reuses the identity after its old session was evicted, and the online
// transition belongs to the new session's Hello (TouchLastSeen). Explicitly
// offline means a reinstall that never connects stays visibly offline, and the
// reconnect publishes the normal offline→online liveness event.
//
// The old installation's packet-sequence watermark (agents.high_sequence) is
// the ingest dedup boundary; the reinstalled machine's fresh WAL starts again
// at sequence 1, so without resetting it every batch the new install sends
// would be misread as a replay and silently dropped.
//
// Schema 8: a reinstall replaces an install, so it advances the enrollment
// epoch like the controlled wire rotation does — the (agent, epoch, sequence)
// receipt identity must never reuse a generation, or the fresh WAL could
// collide with durable receipts the previous installation left behind. Any
// rotation staged for the dead lineage is invalidated outright: the staged
// next token derives from the previous generation's HMAC input and must not
// complete a switch the reinstall already superseded.
//
// Runs inside Enroll's transaction (the caller commits), so a failure rolls the
// token consumption back together with the row update. Returns ErrReinstallAgent
// if the bound agent row is gone, and the agent's new enrollment epoch.
func (s *Service) reenrollAgent(ctx context.Context, tx *sql.Tx, agentID string,
	req enroll.EnrollRequest) (siteID string, siteSerial int, agentToken string, enrollmentEpoch uint64, err error) {

	// The authoritative site comes from the existing row, never from the token's
	// site_id, so a reinstall can't move an agent across sites.
	if err := tx.QueryRowContext(ctx,
		`SELECT site_id FROM agents WHERE id=? AND revoked=0`, agentID).Scan(&siteID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, "", 0, ErrReinstallAgent
		}
		return "", 0, "", 0, err
	}

	agentToken = randToken()
	// Every field the MACHINE owns is reset, not merged: this row now describes a
	// different installation, and a value it never reported must not be attributed
	// to it. The upload cadence matters particularly, because a frame that omits
	// it deliberately keeps the last known one — so without the reset an older
	// replacement would inherit its predecessor's cadence indefinitely, and the
	// host detectors would judge its readings' lateness against a window nobody
	// reported.
	if _, err := tx.ExecContext(ctx, `
		UPDATE agents SET
			public_key=?, token_hash=?, hostname=?, platform=?, agent_version=?,
			perm_supported=?, perm_granted=?, perm_effective=?, perm_unsupported_reasons=?,
			policy_source=?, policy_hash=?,
			status='offline', high_sequence=0, last_status_config_version=-1,
			upload_interval_seconds=0,
			last_disconnect_kind='',
			enrollment_epoch=enrollment_epoch+1,
			pending_next_epoch=0, pending_next_until=0
		WHERE id=?`,
		[]byte(req.PublicKey), sha256hex(agentToken),
		req.Hostname, req.Platform, req.AgentVersion,
		marshalStrings(req.Permissions.Supported), marshalStrings(req.Permissions.Granted),
		marshalStrings(req.Permissions.Effective),
		marshalReasons(req.Permissions.UnsupportedReasons, req.Permissions.Supported),
		req.Permissions.Source, req.Permissions.PolicyHash,
		agentID); err != nil {
		return "", 0, "", 0, err
	}
	// The reinstalled lineage's receipts are dead: every (agent, epoch,
	// sequence) slot from before this generation is unreachable, so dropping
	// them bounds the ledger to one epoch per agent.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM packet_receipts WHERE agent_id=?`, agentID); err != nil {
		return "", 0, "", 0, err
	}
	// The new generation this reinstall just minted, for the EnrollResponse (the
	// agent persists it with the new credential and presents it in every Hello).
	if err := tx.QueryRowContext(ctx,
		`SELECT enrollment_epoch FROM agents WHERE id=?`, agentID).Scan(&enrollmentEpoch); err != nil {
		return "", 0, "", 0, err
	}
	// The old session was fenced (DisconnectSession) before this transaction and
	// the new one has not connected yet, so no ingest can race this reset.
	// high_sequence went to 0 in the UPDATE above; agent_wifi.last_sequence is a
	// second sequence guard that applyInterfaceSnapshot would otherwise use to
	// reject the fresh WAL's low-sequence snapshots, leaving the interfaces/Wi-Fi
	// state stale until the new machine out-paces the old one.
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_wifi WHERE agent_id=?`, agentID); err != nil {
		return "", 0, "", 0, err
	}
	// Throttle hygiene: the entry describes the previous installation. Clearing
	// it early (pre-commit) is safe — a cleared throttle only means the next
	// touch writes, never that a write is skipped.
	s.forgetTouch(agentID)
	if err := tx.QueryRowContext(ctx,
		`SELECT config_serial FROM sites WHERE id=?`, siteID).Scan(&siteSerial); err != nil {
		return "", 0, "", 0, err
	}
	return siteID, siteSerial, agentToken, enrollmentEpoch, nil
}

// --- agent bearer auth ---

// AuthenticateAgent maps a bearer token to its agent identity (see
// registry/rotate.go for the schema-8 AuthResult, epoch and rotation-pending
// semantics).

// --- config version (agents table) ---

// ConfigStatus is an agent's site plus the site-level desired config serial
// (the single desired-config axis). What the agent has APPLIED is not tracked
// here — the MonitorStatus frame's config-version echo is that signal
// (agents.last_status_config_version, maintained by opissue).
type ConfigStatus struct {
	SiteID        string
	ConfigVersion int
}

func (s *Service) ConfigStatus(ctx context.Context, agentID string) (ConfigStatus, error) {
	var c ConfigStatus
	err := s.db.QueryRowContext(ctx,
		`SELECT a.site_id, COALESCE(st.config_serial,0)
		 FROM agents a JOIN sites st ON st.id = a.site_id WHERE a.id=?`, agentID).
		Scan(&c.SiteID, &c.ConfigVersion)
	return c, err
}

// AgentCount / MaxAgents feed the "X / max" quota display.
func (s *Service) AgentCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE revoked=0`).Scan(&n)
	return n, err
}

func (s *Service) MaxAgents() int { return s.maxAgents }

// --- helpers ---

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
