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
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/nettact/server-core/store"
)

// ErrAuth is returned for any authentication failure (kept generic on purpose).
var ErrAuth = errors.New("invalid credentials")

// ErrPasswordPolicy wraps every ValidatePassword failure so callers can map a
// weak-password rejection to a 400 (errors.Is) while still surfacing the specific
// rule that failed via the error's message.
var ErrPasswordPolicy = errors.New("password does not meet policy")

const sessionTTL = 7 * 24 * time.Hour

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

// EnsureAdmin creates the single admin user on first run and returns it. On
// later runs it does not re-create anything (the bootstrap credentials only seed
// the very first user) but still queries and returns the existing admin, because
// callers such as the desktop host need the admin's ID on every launch to mint
// sessions.
//
// The second return value is the auto-generated initial password, and is
// non-empty only when the very first user was created without a supplied
// password: on an empty users table with password=="", the username defaults to
// "admin" (or the supplied username) and a strong random password is generated,
// created, and returned so the caller can print it once. When a password is
// supplied (or on any later run) the returned password is "".
func (s *Service) EnsureAdmin(ctx context.Context, username, password string) (User, string, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return User{}, "", err
	}
	if count > 0 {
		// The single-user model means the one existing row is the admin.
		var u User
		if err := s.db.QueryRowContext(ctx,
			`SELECT id, username FROM users ORDER BY created_at LIMIT 1`).Scan(&u.ID, &u.Username); err != nil {
			return User{}, "", err
		}
		return u, "", nil
	}
	if username == "" {
		username = "admin"
	}
	generated := ""
	if password == "" {
		pw, err := generatePassword(16)
		if err != nil {
			return User{}, "", err
		}
		password = pw
		generated = pw
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, "", err
	}
	id := "user_" + uuid.NewString()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO users(id, username, password_hash, created_at) VALUES(?,?,?,?)`,
		id, username, string(hash), time.Now().UTC()); err != nil {
		return User{}, "", err
	}
	return User{ID: id, Username: username}, generated, nil
}

// ValidatePassword enforces the password policy: at least 8 characters and no
// more than 72 bytes. The upper bound is bcrypt's hard limit — it silently
// truncates input past 72 bytes, so a longer password would not authenticate as
// the user typed it.
func ValidatePassword(pw string) error {
	if utf8.RuneCountInString(pw) < 8 {
		return fmt.Errorf("%w: must be at least 8 characters", ErrPasswordPolicy)
	}
	if len(pw) > 72 {
		return fmt.Errorf("%w: must be at most 72 bytes", ErrPasswordPolicy)
	}
	return nil
}

// UpdatePassword atomically rotates a user's password and revokes every session
// except keepSessionID. The whole flow runs inside a single SQLite write
// transaction so the hash swap and the session cull commit together — a caller
// can never observe a changed password with stale sessions still live, and two
// concurrent changes can't both "succeed" (last-write-wins).
//
// A wrong (or missing) old password returns ErrAuth; a policy violation returns
// the ValidatePassword error verbatim. The UPDATE is a compare-and-swap on the
// exact hash we read under the transaction: if a racing change already rotated
// the row, RowsAffected is 0 and we return ErrAuth rather than clobber the
// winner. bcrypt runs inside the transaction (~100ms holding the single write
// connection); that is acceptable for the single-admin console.
func (s *Service) UpdatePassword(ctx context.Context, userID, oldPassword, newPassword, keepSessionID string) error {
	return s.setPassword(ctx, userID, newPassword, keepSessionID, func(hash string) error {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPassword)) != nil {
			return ErrAuth
		}
		return nil
	})
}

// SetPassword rotates a user's password WITHOUT proving knowledge of the current
// one, keeping everything else about UpdatePassword (single transaction,
// compare-and-swap, other sessions revoked).
//
// This exists for the desktop all-in-one, and only makes sense there. A desktop
// install generates a random admin password at first start and never shows it:
// the app mints the console session in-process from a loopback-only one-time
// token, so nobody — including the owner — can produce the current password to
// type into a "change password" form. Requiring one would make the account
// permanently unchangeable, which in turn makes logging in from a phone or a
// second computer impossible.
//
// It grants no authority that the caller does not already hold. Reaching this
// path requires a live admin session, and on a desktop install the only way to
// obtain one is to be at the machine (the login URL is minted by the tray and
// redeemable from loopback only) or to already know the password. The server API
// must therefore keep this behind that desktop check — a self-hosted server, where
// a session can be obtained from anywhere with the password, must keep requiring
// the old one so a stolen session cannot lock the owner out.
func (s *Service) SetPassword(ctx context.Context, userID, newPassword, keepSessionID string) error {
	return s.setPassword(ctx, userID, newPassword, keepSessionID, nil)
}

// setPassword is the shared transaction. verify, when non-nil, is the
// old-password check, run against the hash read inside the transaction.
func (s *Service) setPassword(ctx context.Context, userID, newPassword, keepSessionID string, verify func(hash string) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var hash string
	err = tx.QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE id=?`, userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuth
	}
	if err != nil {
		return err
	}
	if verify != nil {
		if err := verify(hash); err != nil {
			return err
		}
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash=? WHERE id=? AND password_hash=?`,
		string(newHash), userID, hash)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		// The row changed out from under us since the SELECT above.
		return ErrAuth
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id=? AND id<>?`, userID, keepSessionID); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetAdminPassword replaces the single admin's password out of band (the CLI
// passwd subcommand, for lost-password recovery). In one write transaction it
// selects the one existing user (the single-user model picks the earliest-created
// row), validates and rewrites the hash, then deletes all of that user's sessions
// so every logged-in client is forced to re-authenticate — hash swap and session
// cull commit together. It returns the affected username. An empty users table is
// an error.
func (s *Service) ResetAdminPassword(ctx context.Context, newPassword string) (string, error) {
	if err := ValidatePassword(newPassword); err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var id, username string
	err = tx.QueryRowContext(ctx,
		`SELECT id, username FROM users ORDER BY created_at LIMIT 1`).Scan(&id, &username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("no admin user exists to reset")
	}
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash=? WHERE id=?`, string(hash), id); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return username, nil
}

// generatePassword returns a random alphanumeric password of n characters drawn
// from crypto/rand, used to seed the first admin when no password is supplied on
// first run. The small modulo bias over a 62-symbol alphabet is irrelevant for a
// 16-character bootstrap secret.
func generatePassword(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// LoginSession verifies a username/password and, only if the password is still
// current, mints a session — closing the race where a password change lands
// between the credential check and the INSERT and would otherwise mint a
// full-TTL session for a password the user just rotated away.
//
// bcrypt (~100ms) runs OUTSIDE the write transaction against the read pool so it
// never holds the single write connection. The verified hash is then re-checked
// under the write transaction: if the stored hash changed since the bcrypt
// check (a concurrent UpdatePassword/ResetAdminPassword committed), the stale
// login is rejected with ErrAuth. Returns the user, new session id, and expiry.
func (s *Service) LoginSession(ctx context.Context, username, password string) (User, string, time.Time, error) {
	var u User
	var verifiedHash string
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT id, username, password_hash FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &verifiedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", time.Time{}, ErrAuth
	}
	if err != nil {
		return User{}, "", time.Time{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(verifiedHash), []byte(password)) != nil {
		return User{}, "", time.Time{}, ErrAuth
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, "", time.Time{}, err
	}
	defer tx.Rollback()

	var currentHash string
	err = tx.QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE id=?`, u.ID).Scan(&currentHash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", time.Time{}, ErrAuth
	}
	if err != nil {
		return User{}, "", time.Time{}, err
	}
	if currentHash != verifiedHash {
		// The password rotated between the bcrypt check and here.
		return User{}, "", time.Time{}, ErrAuth
	}

	id := randToken()
	now := time.Now().UTC()
	exp := now.Add(sessionTTL)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sessions(id, user_id, created_at, expires_at) VALUES(?,?,?,?)`,
		id, u.ID, now, exp); err != nil {
		return User{}, "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, "", time.Time{}, err
	}
	return u, id, exp, nil
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
// It reads through the read-only pool: requireSession wraps every console API
// route, so validation must never queue behind the single write connection (a
// long rollup/retention transaction would otherwise stall every endpoint).
func (s *Service) ValidateSession(ctx context.Context, sessionID string) (User, error) {
	if sessionID == "" {
		return User{}, ErrAuth
	}
	var u User
	var exp time.Time
	err := s.db.Read().QueryRowContext(ctx,
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

// PruneSessions deletes all expired session rows and returns how many were
// removed. ValidateSession only deletes an expired row when it happens to be
// presented again, so a long-lived host that mints a session per launch and per
// activation would otherwise accumulate dead rows for months. Meant to run on a
// periodic retention tick.
func (s *Service) PruneSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
