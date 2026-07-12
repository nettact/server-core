// Package settings is a tiny key/value store for global, UI-editable server
// settings backed by the app_settings table. It intentionally stays generic so
// new global knobs can be added without schema changes.
package settings

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/nettact/server-core/store"
)

// KeyConsoleBaseURL is the console's externally-reachable origin (scheme+host,
// e.g. "http://localhost:8080"). Used to build deep links in notifications.
const KeyConsoleBaseURL = "console_base_url"

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

// Get returns the value for key, or "" if unset.
func (s *Service) Get(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// All returns every stored setting as a map.
func (s *Service) All(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// Set upserts a key. An empty value clears it (row removed) so "unset" and
// "empty string" read back the same.
func (s *Service) Set(ctx context.Context, key, value string) error {
	if value == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM app_settings WHERE key=?`, key)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ConsoleBaseURL returns the configured console origin with any trailing slash
// removed, or "" when unset. Nil-safe so callers without a settings service
// (e.g. tests) degrade to "no deep link".
func (s *Service) ConsoleBaseURL(ctx context.Context) string {
	if s == nil {
		return ""
	}
	v, err := s.Get(ctx, KeyConsoleBaseURL)
	if err != nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(v), "/")
}
