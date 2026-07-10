// Package store opens the SQLite database (pure-Go modernc driver, CGO-free)
// and applies embedded migrations. It is shared by every server-core module.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps *sql.DB so modules can depend on a single type.
type DB struct {
	*sql.DB
}

// Open opens (creating if needed) the SQLite database at path, applies pending
// migrations, and returns a ready DB. PRAGMAs are set via the DSN so every
// pooled connection gets them.
func Open(path string) (*DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_pragma=auto_vacuum(INCREMENTAL)"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite has a single writer; cap the pool to avoid SQLITE_BUSY churn.
	// WAL still allows this connection to read and write; Lite scale is fine.
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	db := &DB{sqldb}
	if err := db.migrate(); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}
