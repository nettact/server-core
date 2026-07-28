package config

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// ErrDefaultGroup is returned when a caller tries to delete a site's undeletable
// default monitor group.
var ErrDefaultGroup = errors.New("default monitor group cannot be deleted")

// ErrDuplicateTargetID reports a submitted target set that names one id twice.
// It is a malformed REQUEST, not a server fault, so the API layer matches it with
// errors.Is and answers 400 — a 500 would invite clients to retry a payload that
// can never succeed.
var ErrDuplicateTargetID = errors.New("duplicate target id in the submitted set")

// txExec is the subset of *sql.Tx used by the shared helpers, so they can run
// inside any caller's write transaction.
type txExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func scanIDs(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
