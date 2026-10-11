package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migration is one numbered schema step. Most steps are embedded .sql files
// (migrations/NNNN_name.sql); a step whose work a plain script cannot express —
// SQLite has no ADD COLUMN IF NOT EXISTS, no ALTER of a column's constraints,
// and a table rebuild has to run with foreign-key enforcement suspended, which
// a pragma inside a transaction cannot do — is a Go function registered in
// goMigrations instead. Both kinds share one numbering, run in version order,
// each in its own transaction, and are recorded in schema_migrations exactly
// like each other: a Go step is not a side channel, it is a migration whose
// body happens to be code.
type migration struct {
	version int
	// name is what the ledger records next to the version: the file name for a
	// .sql step, the registered name for a Go step. It is what lets a later
	// build tell "version 2 of THIS history" from "a version 2 of some other
	// history" — see checkLedgerLineage.
	name string
	sql  string                                      // .sql steps
	run  func(ctx context.Context, tx *sql.Tx) error // Go steps; runs with foreign_keys=OFF
}

// goMigrations are the Go-coded steps, merged into the .sql files' numbering.
// A version may be claimed by a file or by a Go step, never both (loadMigrations
// refuses the build).
var goMigrations = []migration{
	{version: repairBaselineVersion, name: repairBaselineName, run: repairBaselineDrift},
}

// ErrPreBaselineDatabase reports a database whose migration ledger belongs to
// a schema history older than the release baseline (0001_init.sql). Its
// version numbers collide with the current chain — its version 2 is not this
// build's version 2 — so the runner cannot tell which of this build's steps
// have run, and treating it as current would silently skip them. The file is
// left untouched. A host can detect this with errors.Is and tell the operator
// what to do; the wrapped message already says it.
var ErrPreBaselineDatabase = errors.New("store: database predates the release baseline schema and cannot be upgraded in place")

// migrate applies every migration not yet recorded in schema_migrations, each
// in its own transaction, in version order.
//
// Before anything is applied the ledger's lineage is verified
// (checkLedgerLineage): a database written by a different schema history is
// refused loudly instead of being half-migrated. The verification is the only
// thing that runs before the steps, and it changes nothing on a database it
// refuses.
func (db *DB) migrate() error {
	return db.migrateTo(int(^uint(0) >> 1))
}

// migrateTo is migrate stopped after the step numbered limit. Production
// always runs the whole chain; tests use the limit to reproduce the exact
// shape an intermediate step runs against (the baseline repair, for one, only
// ever sees the database as it stands before the later steps).
func (db *DB) migrateTo(limit int) error {
	ctx := context.Background()
	migs, err := loadMigrations()
	if err != nil {
		return err
	}
	// A brand-new ledger carries the name column from the start; an existing
	// one gains it in checkLedgerLineage, after its lineage has been verified.
	if _, err := db.Exec(
		`CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL, name TEXT NOT NULL DEFAULT '')`,
	); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}
	if err := db.checkLedgerLineage(ctx, migs); err != nil {
		return err
	}

	for _, m := range migs {
		if m.version > limit {
			break
		}
		var applied int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version=?`, m.version).Scan(&applied); err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		if m.run != nil {
			if err := db.applyGoMigration(ctx, m); err != nil {
				return err
			}
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		if err := recordMigration(ctx, tx, m); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// applyGoMigration runs one Go step inside SQLite's documented table-rebuild
// envelope (https://www.sqlite.org/lang_altertable.html#otheralter): foreign-key
// enforcement OFF on the connection, then BEGIN, the work, the ledger row,
// COMMIT, then enforcement back ON.
//
// Enforcement has to be off because a rebuild drops and recreates tables that
// other tables reference. With it on, dropping a parent runs an implicit DELETE
// that fires every ON DELETE CASCADE beneath it — the rebuild would wipe the
// children it is trying to keep — and renaming one rewrites its children's
// REFERENCES clauses to the new name. PRAGMA foreign_keys is a no-op inside a
// transaction, so the pragma has to be issued on the connection before BEGIN,
// which is why the step pins one connection for its whole duration instead of
// going through the pool. Turning enforcement off moves the responsibility, it
// does not remove it: a Go step must verify the integrity it could have broken
// before returning (repairBaselineDrift's verifyRebuilt), so the commit only
// happens on a consistent schema.
func (db *DB) applyGoMigration(ctx context.Context, m migration) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return fmt.Errorf("apply migration %s: disable foreign keys: %w", m.name, err)
	}
	defer func() {
		// The connection goes back to the pool afterwards, and every other
		// caller relies on enforcement being on. If it cannot be restored, the
		// connection must not be reused: report it so Open fails and closes it.
		if _, rerr := conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`); rerr != nil && err == nil {
			err = fmt.Errorf("apply migration %s: re-enable foreign keys: %w", m.name, rerr)
		}
	}()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := m.run(ctx, tx); err != nil {
		tx.Rollback()
		return fmt.Errorf("apply migration %s: %w", m.name, err)
	}
	if err := recordMigration(ctx, tx, m); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func recordMigration(ctx context.Context, tx *sql.Tx, m migration) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at, name) VALUES(?, ?, ?)`,
		m.version, time.Now().UTC(), m.name)
	return err
}

// loadMigrations returns the embedded .sql files and the Go steps, merged and
// sorted by version. A version claimed twice is a build defect and fails every
// Open, which no test run can miss.
func loadMigrations() ([]migration, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	byVersion := map[int]string{}
	var migs []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("bad migration filename %q: %w", e.Name(), err)
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		if prev, dup := byVersion[v]; dup {
			return nil, fmt.Errorf("migration version %d claimed by both %s and %s", v, prev, e.Name())
		}
		byVersion[v] = e.Name()
		migs = append(migs, migration{version: v, name: e.Name(), sql: string(body)})
	}
	for _, g := range goMigrations {
		if prev, dup := byVersion[g.version]; dup {
			return nil, fmt.Errorf("migration version %d claimed by both %s and %s", g.version, prev, g.name)
		}
		byVersion[g.version] = g.name
		migs = append(migs, g)
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	return migs, nil
}

// legacyLedgerVersions maps the versions a ledger written before the name
// column existed can legitimately hold to the step each one was. Every release
// that wrote an unnamed ledger shipped exactly these two files, so these are
// the only versions such a ledger can hold for this history.
var legacyLedgerVersions = map[int]string{
	1: "0001_init.sql",
	2: "0002_schema8_epoch.sql",
}

// preBaselineTables exist only in databases built by the schema history that
// preceded the release baseline: the rule-engine alerting model it carried was
// replaced before the baseline was cut, so no database of this history has ever
// had one of them. Their presence identifies the old history even when its
// ledger got no further than version 1.
var preBaselineTables = []string{"alert_rules", "alerts", "agent_alerts", "group_rules", "group_rule_conditions", "rule_condition_state"}

// checkLedgerLineage verifies that the ledger was written by this schema
// history before the runner trusts its version numbers.
//
// The runner used to record bare version numbers, and the number alone cannot
// say WHICH step ran. That is a real hazard, not a hypothetical one: the
// release baseline replaced an earlier migration chain that had already
// shipped, and that chain's numbers overlap this one's (its version 2 was a
// different file, and it recorded versions up to 23). A database from it looks,
// by numbers, like a database that has already run this chain's early steps —
// so they would be skipped and the server would start against a schema it does
// not have. The ledger therefore now records each step's name, and a ledger
// that predates the name column is classified exactly once, when it gains it:
//
//   - every recorded version must be one an unnamed ledger of this history can
//     hold (legacyLedgerVersions), version 2 must have left its mark (the
//     packet_receipts table it creates — no step of this history before the one
//     doing the classification has ever dropped it), and none of the old
//     history's own tables may exist. Anything else is the old history (or
//     something unknown) and is refused with ErrPreBaselineDatabase, before a
//     single byte is written.
//   - a ledger that passes gets the column, and its rows get their names.
//
// Why refuse rather than repair: the old history is not just older DDL. Its
// later steps converted data between two different alerting models and renamed
// settings, and the compatibility code for its leftovers was removed when the
// baseline was cut; a structural repair (repairBaselineDrift) can rebuild its
// tables but cannot reproduce those conversions, and guessing at them would
// fabricate history. A loud refusal that leaves the file intact is recoverable;
// a silent half-upgrade is not.
//
// Once named, a ledger is checked row by row: a recorded name that disagrees
// with this build's step of the same version is the same collision one level
// up and is refused the same way. An empty name is accepted — it is what a
// build older than the name column writes if it is run against the database
// again (the column defaults to ”), and such a build only ever records
// legacyLedgerVersions. Versions this build does not know are left alone, as
// they always were: they are steps of a newer build, and refusing them would
// turn every rollback into an outage.
func (db *DB) checkLedgerLineage(ctx context.Context, migs []migration) error {
	hasName, err := columnExists(ctx, db.DB, "schema_migrations", "name")
	if err != nil {
		return err
	}
	if !hasName {
		return db.classifyLegacyLedger(ctx)
	}

	names := map[int]string{}
	for _, m := range migs {
		names[m.version] = m.name
	}
	rows, err := db.QueryContext(ctx, `SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v int
		var name string
		if err := rows.Scan(&v, &name); err != nil {
			return err
		}
		want, known := names[v]
		if !known || name == "" || name == want {
			continue
		}
		return fmt.Errorf("%w: %s records version %d as %q, but this build's version %d is %q; "+
			"the file has not been modified — keep it as a backup and move it aside to start with a fresh database",
			ErrPreBaselineDatabase, db.describePath(), v, name, v, want)
	}
	return rows.Err()
}

// classifyLegacyLedger is checkLedgerLineage's one-time pass over a ledger
// written before the name column existed.
func (db *DB) classifyLegacyLedger(ctx context.Context) error {
	var versions []int
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		versions = append(versions, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	refuse := func(why string) error {
		return fmt.Errorf("%w: %s (%s; recorded versions %v). The file has not been modified — "+
			"keep it as a backup and move it aside to start with a fresh database",
			ErrPreBaselineDatabase, db.describePath(), why, versions)
	}
	recorded := map[int]bool{}
	for _, v := range versions {
		if _, ok := legacyLedgerVersions[v]; !ok {
			return refuse(fmt.Sprintf("version %d belongs to an older migration history", v))
		}
		recorded[v] = true
	}
	if recorded[2] {
		if !recorded[1] {
			return refuse("version 2 is recorded without version 1")
		}
		ok, err := tableExists(ctx, db.DB, "packet_receipts")
		if err != nil {
			return err
		}
		if !ok {
			return refuse("the recorded version 2 is not this history's version 2")
		}
	}
	for _, t := range preBaselineTables {
		ok, err := tableExists(ctx, db.DB, t)
		if err != nil {
			return err
		}
		if ok {
			return refuse(fmt.Sprintf("table %s belongs to an older migration history", t))
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE schema_migrations ADD COLUMN name TEXT NOT NULL DEFAULT ''`); err != nil {
		tx.Rollback()
		return fmt.Errorf("add schema_migrations.name: %w", err)
	}
	for v, name := range legacyLedgerVersions {
		if _, err := tx.ExecContext(ctx, `UPDATE schema_migrations SET name=? WHERE version=?`, name, v); err != nil {
			tx.Rollback()
			return fmt.Errorf("name schema_migrations rows: %w", err)
		}
	}
	return tx.Commit()
}

func (db *DB) describePath() string {
	if db.path == "" {
		return "the database"
	}
	return "the database at " + db.path
}

// queryer is the read surface shared by *sql.DB, *sql.Conn and *sql.Tx.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func tableExists(ctx context.Context, q queryer, name string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	return n > 0, err
}

func columnExists(ctx context.Context, q queryer, table, column string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, table, column).Scan(&n)
	return n > 0, err
}
