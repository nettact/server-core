package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// repairBaselineVersion / repairBaselineName identify the Go step that
// reconciles a database with the schema 0001_init.sql + 0002_schema8_epoch.sql
// define today.
const (
	repairBaselineVersion = 3
	repairBaselineName    = "0003_repair_baseline_drift"
)

// baselineFiles are the steps whose combined result is the shape
// repairBaselineDrift restores. They are frozen: a shipped migration file is
// never edited again, so the reference this step derives from them is the same
// on every build that carries the step. Later steps (0004 onward) are
// deliberately NOT part of it — they run after this one, against the shape it
// leaves behind, exactly as on a fresh install.
var baselineFiles = []string{"migrations/0001_init.sql", "migrations/0002_schema8_epoch.sql"}

// repairBaselineDrift brings a database whose version 1 was applied by an
// earlier text of 0001_init.sql to the schema the current text creates.
//
// Why this step exists: 0001_init.sql was revised in place across several
// releases after it had already shipped, while the runner records only that
// version 1 ran. A database created by an earlier release therefore never
// received the later objects — and never will, because version 1 is recorded.
// The visible failure is a server that starts against a schema it does not
// have: queries naming a table that is not there (the scene-report tables),
// inserts tripping a NOT NULL column the current code no longer writes (the
// old incident_snapshots shape), and ingest failing every packet that touches
// either, so the agent's backlog never drains. Seven distinct texts of 0001
// shipped; the drift between each of them and today's is pinned by the
// fixtures under testdata/released_0001.
//
// Why a structural reconciliation instead of a hand-written script per
// release: the earlier texts differ from today's in different subsets of the
// same objects, and SQLite can neither ADD COLUMN IF NOT EXISTS nor alter a
// column's constraints, so a script written for one release fails on another.
// The step instead derives the reference schema by applying baselineFiles to a
// private in-memory database, compares it object by object with the live one,
// and changes only what differs. On a database already in today's shape every
// comparison is equal and the step changes nothing, which is what makes it
// safe to run on every installation, fresh or old.
//
// What it does, per object of the reference:
//
//   - a missing table is created with the reference DDL, verbatim;
//   - a table whose definition differs (columns, types, constraints, defaults,
//     foreign keys — anything but comments and whitespace) is rebuilt with
//     SQLite's documented procedure: the old table is renamed aside, the
//     reference table created under the real name, every row copied across,
//     the old table dropped. Rows keep their rowid and an AUTOINCREMENT table
//     keeps its high-water mark (series ids are never reused — the data plane
//     relies on it). A column the reference no longer has is not carried over:
//     the old texts' extra columns are lifecycle fields of mechanisms that were
//     removed (server-commanded traceroutes and scene collection), and several
//     of them are NOT NULL without a default, so keeping them would make every
//     current insert fail. A reference column the old table lacks takes its
//     declared default, or a value derived from the old row where the
//     reference declares no default (repairFills);
//   - a missing or differing index is (re)created; an index on a reference
//     table that the reference does not declare is dropped (indexes hold no
//     data).
//
// What it deliberately leaves alone: tables the reference does not define at
// all. Earlier releases kept chart samples, a packet-dedup ledger and
// per-agent scene entries in SQLite; nothing reads them any more, but they are
// user data this step cannot account for, and dropping gigabytes of it inside
// a startup migration is not a decision a schema repair should make. They are
// inert: nothing writes them, and none constrains a current table (the one
// that references a current table, incident_snapshot_entries, does so ON
// DELETE CASCADE).
//
// The runner executes this with foreign-key enforcement off (see
// applyGoMigration); before returning, the step verifies what enforcement
// would have guarded (verifyRebuilt), so a violation fails the step and rolls
// the whole repair back rather than committing a broken schema.
func repairBaselineDrift(ctx context.Context, tx *sql.Tx) error {
	ref, err := referenceSchema(ctx)
	if err != nil {
		return fmt.Errorf("build reference schema: %w", err)
	}
	live, err := readSchema(ctx, tx)
	if err != nil {
		return err
	}
	liveByName := map[string]schemaObject{}
	for _, o := range live {
		liveByName[o.name] = o
	}
	refTables := map[string]bool{}
	for _, o := range ref {
		if o.typ == "table" {
			refTables[o.name] = true
		}
	}

	// Pass 1: create every missing table before rebuilding anything, so a
	// rebuilt table's foreign keys never point at a table that does not exist
	// yet (the final foreign_key_check would report it as an error).
	var rebuild []schemaObject
	for _, o := range ref {
		if o.typ != "table" {
			continue
		}
		cur, ok := liveByName[o.name]
		switch {
		case !ok:
			if _, err := tx.ExecContext(ctx, o.sql); err != nil {
				return fmt.Errorf("create table %s: %w", o.name, err)
			}
		case cur.typ != "table":
			return fmt.Errorf("%s is a %s, the schema expects a table", o.name, cur.typ)
		case normalizeDDL(cur.sql) != normalizeDDL(o.sql):
			rebuild = append(rebuild, o)
		}
	}

	// Indexes on the tables about to be rebuilt go first: they would otherwise
	// follow the old table to its temporary name and collide with the
	// reference indexes recreated below.
	if len(rebuild) > 0 {
		rebuilding := map[string]bool{}
		for _, o := range rebuild {
			rebuilding[o.name] = true
		}
		for _, o := range live {
			if o.typ == "index" && rebuilding[o.tbl] {
				if err := dropIndex(ctx, tx, o.name); err != nil {
					return err
				}
				delete(liveByName, o.name)
			}
		}
	}
	for _, o := range rebuild {
		if err := rebuildTable(ctx, tx, o); err != nil {
			return fmt.Errorf("rebuild table %s: %w", o.name, err)
		}
	}

	// Indexes: make each reference table's set exactly the reference set.
	refIndex := map[string]bool{}
	for _, o := range ref {
		if o.typ != "index" {
			continue
		}
		refIndex[o.name] = true
		cur, ok := liveByName[o.name]
		if ok && cur.typ == "index" && cur.tbl == o.tbl && normalizeDDL(cur.sql) == normalizeDDL(o.sql) {
			continue
		}
		if ok {
			if cur.typ != "index" {
				return fmt.Errorf("%s is a %s, the schema expects an index", o.name, cur.typ)
			}
			if err := dropIndex(ctx, tx, o.name); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, o.sql); err != nil {
			return fmt.Errorf("create index %s: %w", o.name, err)
		}
	}
	for _, o := range live {
		if o.typ == "index" && refTables[o.tbl] && !refIndex[o.name] {
			if _, still := liveByName[o.name]; !still {
				continue
			}
			if err := dropIndex(ctx, tx, o.name); err != nil {
				return err
			}
		}
	}

	if len(rebuild) > 0 {
		return verifyRebuilt(ctx, tx, rebuild)
	}
	return nil
}

// verifyRebuilt is the integrity check that has to stand in for foreign-key
// enforcement while it is off. Two things could have gone wrong, and each
// check catches one:
//
//   - a child table's REFERENCES clause followed the old table to its
//     temporary name (the rename was not in legacy mode) — the clause would
//     then name a table that no longer exists. No stored definition may
//     mention the temporary prefix.
//   - copied rows violate a foreign key of, or into, a rebuilt table.
//     PRAGMA foreign_key_check runs over the whole database, but only a
//     violation that involves a rebuilt table fails the step: anything else
//     predates the repair and is not this step's to judge (and failing on it
//     would turn a latent oddity into a server that cannot start).
func verifyRebuilt(ctx context.Context, tx *sql.Tx, rebuilt []schemaObject) error {
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE sql LIKE '%\_repair\_old\_%' ESCAPE '\'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%d schema objects still reference a table renamed aside during the rebuild", n)
	}
	touched := map[string]bool{}
	for _, o := range rebuilt {
		touched[o.name] = true
	}
	rows, err := tx.QueryContext(ctx, `SELECT "table", rowid, parent FROM pragma_foreign_key_check`)
	if err != nil {
		return fmt.Errorf("foreign_key_check: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, parent string
		var rowid sql.NullInt64
		if err := rows.Scan(&table, &rowid, &parent); err != nil {
			return err
		}
		if touched[table] || touched[parent] {
			return fmt.Errorf("foreign key violation after rebuild: %s row %d references a missing %s row", table, rowid.Int64, parent)
		}
	}
	return rows.Err()
}

// repairFills supplies the value of a reference column that an old table
// lacks and that the reference declares without a default, keyed by table and
// column. A fill applies only when the old table has every column in needs, so
// it never fires against a shape it was not written for. A NOT NULL column
// with no default, no old counterpart and no fill fails the step loudly rather
// than inventing a value.
var repairFills = map[string]map[string]repairFill{
	// Earlier texts recorded a server-commanded traceroute's lifecycle
	// (requested → started → completed, with a deadline). Today a report is a
	// finished execution the agent pushed, stamped with the server's receive
	// time — the claim window is measured on it. The closest an old row has is
	// when it finished, else when it started, else when it was requested.
	"trace_reports": {
		"received_at": {needs: []string{"requested_at"}, expr: "COALESCE(completed_at, started_at, requested_at)"},
		// queued/running are states of the removed command lifecycle: nothing
		// will ever finish such a row now, and today's vocabulary has no word
		// for "still in flight". canceled is the honest terminal state.
		"status": {needs: []string{"cohort_open"}, expr: "CASE WHEN status IN ('queued','running') THEN 'canceled' ELSE status END"},
	},
}

type repairFill struct {
	needs []string
	expr  string
}

// schemaObject is one row of sqlite_master that carries DDL.
type schemaObject struct {
	typ, name, tbl, sql string
}

// referenceSchema applies baselineFiles to a private in-memory database and
// returns its objects in creation order (creation order matters only for
// readability of the result: SQLite resolves foreign keys lazily).
func referenceSchema(ctx context.Context) ([]schemaObject, error) {
	mem, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer mem.Close()
	// Every pooled connection to :memory: is its own database; pin one.
	mem.SetMaxOpenConns(1)
	for _, f := range baselineFiles {
		body, err := migrationsFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if _, err := mem.ExecContext(ctx, string(body)); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	return readSchema(ctx, mem)
}

// readSchema returns every table and index that carries DDL, excluding
// SQLite's own objects and the migration ledger (which the runner owns).
// Autoindexes have no DDL — they come and go with their table's constraints.
func readSchema(ctx context.Context, q queryer) ([]schemaObject, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT type, name, tbl_name, sql FROM sqlite_master
		WHERE sql IS NOT NULL AND type IN ('table','index','view','trigger')
		  AND name NOT LIKE 'sqlite\_%' ESCAPE '\' AND tbl_name <> 'schema_migrations'
		ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []schemaObject
	for rows.Next() {
		var o schemaObject
		if err := rows.Scan(&o.typ, &o.name, &o.tbl, &o.sql); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func dropIndex(ctx context.Context, tx *sql.Tx, name string) error {
	if _, err := tx.ExecContext(ctx, `DROP INDEX `+quoteIdent(name)); err != nil {
		return fmt.Errorf("drop index %s: %w", name, err)
	}
	return nil
}

// rebuildTable replaces a live table with the reference definition, keeping
// its rows.
//
// The order differs from the documentation's create-new/copy/drop-old/rename
// sequence on purpose: renaming the NEW table onto the old name stores the
// definition as CREATE TABLE "name"(…), so a repaired database would differ
// textually from a fresh one forever. Renaming the OLD table aside instead lets
// the reference DDL be executed verbatim under the real name. That rename must
// not touch the REFERENCES clauses of child tables — they have to keep naming
// the real table, which is about to exist again — and with foreign-key
// enforcement off, legacy_alter_table=ON is exactly the mode in which SQLite
// renames a table without rewriting its children's references.
func rebuildTable(ctx context.Context, tx *sql.Tx, ref schemaObject) (err error) {
	name := ref.name
	aside := "_repair_old_" + name

	oldCols, err := tableColumns(ctx, tx, name)
	if err != nil {
		return err
	}
	oldRowid, err := hasRowid(ctx, tx, name)
	if err != nil {
		return err
	}
	seq, hasSeq, err := autoincrementSeq(ctx, tx, name)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `PRAGMA legacy_alter_table=ON`); err != nil {
		return err
	}
	defer func() {
		if _, rerr := tx.ExecContext(ctx, `PRAGMA legacy_alter_table=OFF`); rerr != nil && err == nil {
			err = rerr
		}
	}()
	if _, err := tx.ExecContext(ctx, `ALTER TABLE `+quoteIdent(name)+` RENAME TO `+quoteIdent(aside)); err != nil {
		return fmt.Errorf("rename aside: %w", err)
	}
	if _, err := tx.ExecContext(ctx, ref.sql); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	newCols, err := tableColumns(ctx, tx, name)
	if err != nil {
		return err
	}
	newRowid, err := hasRowid(ctx, tx, name)
	if err != nil {
		return err
	}

	have := map[string]bool{}
	for _, c := range oldCols {
		have[c.name] = true
	}
	var dst, src []string
	for _, c := range newCols {
		if f, ok := repairFills[name][c.name]; ok && hasAll(have, f.needs) {
			dst, src = append(dst, quoteIdent(c.name)), append(src, f.expr)
			continue
		}
		if have[c.name] {
			dst, src = append(dst, quoteIdent(c.name)), append(src, quoteIdent(c.name))
			continue
		}
		if c.notNull && !c.hasDefault && !(c.pk > 0 && isRowidAlias(newCols, c)) {
			return fmt.Errorf("column %s is NOT NULL without a default and has no source in the old table", c.name)
		}
	}
	// Keep rowids stable for a rowid table without an INTEGER PRIMARY KEY (an
	// alias is copied as an ordinary column above).
	if oldRowid && newRowid && !hasRowidAlias(newCols) {
		dst, src = append([]string{"rowid"}, dst...), append([]string{"rowid"}, src...)
	}
	if len(dst) > 0 {
		q := `INSERT INTO ` + quoteIdent(name) + `(` + strings.Join(dst, ", ") + `) SELECT ` +
			strings.Join(src, ", ") + ` FROM ` + quoteIdent(aside)
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("copy rows: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE `+quoteIdent(aside)); err != nil {
		return fmt.Errorf("drop old: %w", err)
	}
	if hasSeq {
		res, err := tx.ExecContext(ctx, `UPDATE sqlite_sequence SET seq=MAX(seq, ?) WHERE name=?`, seq, name)
		if err != nil {
			return fmt.Errorf("restore autoincrement: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO sqlite_sequence(name, seq) VALUES(?, ?)`, name, seq); err != nil {
				return fmt.Errorf("restore autoincrement: %w", err)
			}
		}
	}
	return nil
}

type columnInfo struct {
	name       string
	typ        string
	notNull    bool
	hasDefault bool
	pk         int
}

func tableColumns(ctx context.Context, q queryer, table string) ([]columnInfo, error) {
	rows, err := q.QueryContext(ctx, `SELECT name, type, "notnull", dflt_value IS NOT NULL, pk FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []columnInfo
	for rows.Next() {
		var c columnInfo
		if err := rows.Scan(&c.name, &c.typ, &c.notNull, &c.hasDefault, &c.pk); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// hasRowidAlias reports whether the table's primary key is a single INTEGER
// column, which in a rowid table IS the rowid.
func hasRowidAlias(cols []columnInfo) bool {
	n := 0
	var pk columnInfo
	for _, c := range cols {
		if c.pk > 0 {
			n++
			pk = c
		}
	}
	return n == 1 && strings.EqualFold(pk.typ, "INTEGER")
}

func isRowidAlias(cols []columnInfo, c columnInfo) bool {
	return hasRowidAlias(cols) && c.pk > 0
}

func hasRowid(ctx context.Context, q queryer, table string) (bool, error) {
	var wr int
	if err := q.QueryRowContext(ctx, `SELECT wr FROM pragma_table_list WHERE schema='main' AND name=?`, table).Scan(&wr); err != nil {
		return false, fmt.Errorf("table_list %s: %w", table, err)
	}
	return wr == 0, nil
}

// autoincrementSeq reads a table's AUTOINCREMENT high-water mark, if it has
// one.
func autoincrementSeq(ctx context.Context, q queryer, table string) (int64, bool, error) {
	ok, err := tableExists(ctx, q, "sqlite_sequence")
	if err != nil || !ok {
		return 0, false, err
	}
	var seq int64
	err = q.QueryRowContext(ctx, `SELECT seq FROM sqlite_sequence WHERE name=?`, table).Scan(&seq)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return seq, err == nil, err
}

func hasAll(have map[string]bool, cols []string) bool {
	for _, c := range cols {
		if !have[c] {
			return false
		}
	}
	return true
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// normalizeDDL reduces a stored CREATE statement to what determines the
// object: comments are removed, whitespace runs collapse to one space, and
// whitespace next to punctuation disappears. Quoted text (string literals,
// quoted identifiers) is kept verbatim, so a DEFAULT '--' is never mistaken
// for a comment. Two statements that normalize equal define the same object;
// the converse is not required — a false "differs" only costs a rebuild that
// changes nothing.
func normalizeDDL(s string) string {
	var b []byte
	pending := false // whitespace or a comment was skipped since the last byte
	put := func(c byte) {
		if pending && len(b) > 0 {
			if last := b[len(b)-1]; last != '(' && last != ',' && c != '(' && c != ')' && c != ',' {
				b = append(b, ' ')
			}
		}
		pending = false
		b = append(b, c)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			pending = true
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			i += 2
			for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
				i++
			}
			i++
			pending = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			pending = true
		case c == '\'' || c == '"' || c == '`' || c == '[':
			end := c
			if c == '[' {
				end = ']'
			}
			put(c)
			for i++; i < len(s); i++ {
				b = append(b, s[i])
				if s[i] != end {
					continue
				}
				if end != ']' && i+1 < len(s) && s[i+1] == end { // a doubled quote is an escaped one
					i++
					b = append(b, s[i])
					continue
				}
				break
			}
		default:
			put(c)
		}
	}
	return string(b)
}
