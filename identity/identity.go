// Package identity handles the single admin user: bootstrap, password auth
// (bcrypt) and server-side sessions (HttpOnly cookie). P0 Lite is single-user
// with no tenant concept (architecture §11, user requirement).
package identity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/nettact/server-core/store"
)

// ErrAuth is returned for any authentication failure (kept generic on purpose).
var ErrAuth = errors.New("invalid credentials")

const sessionTTL = 7 * 24 * time.Hour

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

// EnsureAdmin creates the single admin user on first run. On later runs it is a
// no-op (the bootstrap flags only seed the very first user).
func (s *Service) EnsureAdmin(ctx context.Context, username, password string) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if username == "" || password == "" {
		return errors.New("first run requires --admin-user and --admin-pass")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users(id, username, password_hash, created_at) VALUES(?,?,?,?)`,
		"user_"+uuid.NewString(), username, string(hash), time.Now().UTC())
	return err
}

// Authenticate verifies a username/password.
func (s *Service) Authenticate(ctx context.Context, username, password string) (User, error) {
	var u User
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrAuth
	}
	if err != nil {
		return User{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return User{}, ErrAuth
	}
	return u, nil
}

// CreateSession issues a new session and returns its id and expiry.
func (s *Service) CreateSession(ctx context.Context, userID string) (string, time.Time, error) {
	id := randToken()
	now := time.Now().UTC()
	exp := now.Add(sessionTTL)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(id, user_id, created_at, expires_at) VALUES(?,?,?,?)`,
		id, userID, now, exp); err != nil {
		return "", time.Time{}, err
	}
	return id, exp, nil
}

// ValidateSession returns the user for a session id, or ErrAuth if missing/expired.
func (s *Service) ValidateSession(ctx context.Context, sessionID string) (User, error) {
	if sessionID == "" {
		return User{}, ErrAuth
	}
	var u User
	var exp time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?`,
		sessionID).Scan(&u.ID, &u.Username, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrAuth
	}
	if err != nil {
		return User{}, err
	}
	if time.Now().UTC().After(exp) {
		_ = s.DeleteSession(ctx, sessionID)
		return User{}, ErrAuth
	}
	return u, nil
}

// DeleteSession invalidates a session (logout).
func (s *Service) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, sessionID)
	return err
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
