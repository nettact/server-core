// Package site manages Sites — a home or office location that groups multiple
// agents (architecture §2.2). Grouping agents by Site is what lets the rule
// engine tell "one device down" from "whole-site down" (§4 / §16). P0 is
// single-user; every Site belongs to the one admin.
package site

import (
	"context"
	"time"

	"github.com/nettact/server-core/store"
)

// DefaultSiteID is the seeded site agents fall back to when they enroll without
// a specific site (dev auto-registration in M1).
const DefaultSiteID = "site_default"

type Site struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

// EnsureDefault creates the default site if it does not already exist.
func (s *Service) EnsureDefault(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sites(id, name, created_at) VALUES(?, 'Default Site', ?)
		 ON CONFLICT(id) DO NOTHING`,
		DefaultSiteID, time.Now().UTC())
	return err
}

// Exists reports whether a site with the given id exists.
func (s *Service) Exists(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sites WHERE id=?`, id).Scan(&n)
	return n > 0, err
}

func (s *Service) List(ctx context.Context) ([]Site, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM sites ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Site
	for rows.Next() {
		var st Site
		if err := rows.Scan(&st.ID, &st.Name, &st.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}
