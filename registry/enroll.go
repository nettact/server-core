package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
)

// --- enrollment tokens ---

// EnrollmentToken is metadata about an issued token (never the plaintext).
type EnrollmentToken struct {
	SiteID    string     `json:"site_id"`
	Note      string     `json:"note"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
}

// CreateEnrollmentToken issues a one-time token bound to a site; only the hash
// is stored. The plaintext is returned once.
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
		`SELECT site_id, COALESCE(note,''), expires_at, used_at FROM enrollment_tokens ORDER BY expires_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		var used sql.NullTime
		if err := rows.Scan(&t.SiteID, &t.Note, &t.ExpiresAt, &used); err != nil {
			return nil, err
		}
		if used.Valid {
			u := used.Time
			t.UsedAt = &u
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- enroll ---

// Enroll verifies the possession proof and one-time token, enforces the agent
// quota, creates the agent, and returns a bearer token (shown once).
func (s *Service) Enroll(ctx context.Context, req enroll.EnrollRequest) (enroll.EnrollResponse, error) {
	if err := protocol.ValidateSchema(req.SchemaVersion); err != nil {
		return enroll.EnrollResponse{}, err
	}
	if len(req.PublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(req.PublicKey), []byte(req.Nonce), req.Signature) {
		return enroll.EnrollResponse{}, ErrSignature
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
	err = tx.QueryRowContext(ctx,
		`SELECT site_id, expires_at, used_at FROM enrollment_tokens WHERE token_hash=?`,
		sha256hex(req.EnrollmentToken)).Scan(&siteID, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return enroll.EnrollResponse{}, ErrEnrollToken
	}
	if err != nil {
		return enroll.EnrollResponse{}, err
	}
	if usedAt.Valid || time.Now().UTC().After(expiresAt) {
		return enroll.EnrollResponse{}, ErrEnrollToken
	}

	if s.maxAgents > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE revoked=0`).Scan(&n); err != nil {
			return enroll.EnrollResponse{}, err
		}
		if n >= s.maxAgents {
			return enroll.EnrollResponse{}, ErrQuota
		}
	}

	agentID := "agent_" + uuid.NewString()
	agentToken := randToken()
	capsJSON, _ := json.Marshal(req.Capabilities)
	now := time.Now().UTC()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agents(id, site_id, public_key, token_hash, hostname, platform, agent_version,
		                   capabilities, status, config_version, reported_config_version, last_seen_at, created_at)
		VALUES(?,?,?,?,?,?,?,?, 'online', 0, 0, ?, ?)`,
		agentID, siteID, []byte(req.PublicKey), sha256hex(agentToken),
		req.Hostname, req.Platform, req.AgentVersion, string(capsJSON), now, now); err != nil {
		return enroll.EnrollResponse{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE enrollment_tokens SET used_at=? WHERE token_hash=?`, now, sha256hex(req.EnrollmentToken)); err != nil {
		return enroll.EnrollResponse{}, err
	}
	if err := tx.Commit(); err != nil {
		return enroll.EnrollResponse{}, err
	}
	committed = true

	return enroll.EnrollResponse{
		AgentID: agentID, SiteID: siteID, AgentToken: agentToken,
		ServerTime: now, ConfigVersion: 0,
	}, nil
}

// --- agent bearer auth ---

// AuthenticateAgent maps a bearer token to its agent id + site, or ErrAuth.
func (s *Service) AuthenticateAgent(ctx context.Context, token string) (agentID, siteID string, err error) {
	if token == "" {
		return "", "", ErrAuth
	}
	err = s.db.QueryRowContext(ctx,
		`SELECT id, site_id FROM agents WHERE token_hash=? AND revoked=0`, sha256hex(token)).
		Scan(&agentID, &siteID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrAuth
	}
	return agentID, siteID, err
}

// --- config version (agents table) ---

// ConfigStatus is an agent's desired vs reported config version.
type ConfigStatus struct {
	SiteID          string
	ConfigVersion   int
	ReportedVersion int
}

func (s *Service) ConfigStatus(ctx context.Context, agentID string) (ConfigStatus, error) {
	var c ConfigStatus
	err := s.db.QueryRowContext(ctx,
		`SELECT site_id, config_version, reported_config_version FROM agents WHERE id=?`, agentID).
		Scan(&c.SiteID, &c.ConfigVersion, &c.ReportedVersion)
	return c, err
}

func (s *Service) SetReportedConfigVersion(ctx context.Context, agentID string, v int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET reported_config_version=? WHERE id=?`, v, agentID)
	return err
}

// BumpConfigVersionForSite marks every agent in a site as needing new config.
func (s *Service) BumpConfigVersionForSite(ctx context.Context, siteID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET config_version=config_version+1 WHERE site_id=?`, siteID)
	return err
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
