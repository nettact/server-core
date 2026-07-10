// Package audit records security-relevant actions (login, enroll, config
// changes). P0 is a skeleton: append-only rows, best-effort (an audit write
// failure never blocks the underlying request).
package audit

import (
	"context"
	"time"

	"github.com/nettact/server-core/store"
)

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service { return &Service{db: db} }

// Log appends an audit entry. Errors are swallowed intentionally.
func (s *Service) Log(ctx context.Context, actor, action, target, detail string) {
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO audit_log(ts, actor, action, target, detail) VALUES(?,?,?,?,?)`,
		time.Now().UTC(), actor, action, target, detail)
}

type Entry struct {
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
}

func (s *Service) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, COALESCE(actor,''), action, COALESCE(target,''), COALESCE(detail,'')
		 FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.TS, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
