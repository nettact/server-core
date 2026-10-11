package routehist

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nettact/server-core/store"
)

// Retention tiers. The split follows what each tier is for: full per-attempt
// detail answers "what exactly did that sweep see" and is only worth its
// volume while recent (or while a change cites it as evidence); IP-level
// variant counts explain ECMP behaviour within an era and stay useful for a
// year; eras and changes are the long history itself — a handful of rows per
// monitor per year — and are kept forever.
const (
	DetailRetention  = 7 * 24 * time.Hour
	VariantRetention = 365 * 24 * time.Hour
)

// RetentionTx prunes route history inside the caller's write transaction:
//
//   - run detail older than DetailRetention, except runs a route change cites
//     (before/after evidence) and each monitor's last consistent run (the
//     "before" evidence of a change that has not been confirmed yet);
//   - variant counts of eras that ended more than VariantRetention ago;
//   - paths nothing references any more (eras, variants, detail, live
//     detector state, pending candidates);
//   - dictionary rows (addresses, AS names) no remaining path or era names.
//
// Eras and changes are never pruned here; they go only with their monitor or
// agent (foreign-key cascade). Idempotent.
func RetentionTx(ctx context.Context, scope store.Scope, wtx store.WriteTx, now time.Time) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if wtx.Scope() != scope {
		return errors.New("routehist: write transaction scope does not match the call's scope")
	}
	detailCut := now.Add(-DetailRetention).Unix()
	if _, err := wtx.ExecContext(ctx, `
		DELETE FROM route_runs_detail
		WHERE run_ts < ?
		  AND id NOT IN (SELECT before_run_id FROM route_changes WHERE before_run_id IS NOT NULL)
		  AND id NOT IN (SELECT after_run_id FROM route_changes WHERE after_run_id IS NOT NULL)
		  AND id NOT IN (SELECT last_run_id FROM route_monitor_state WHERE last_run_id IS NOT NULL)`,
		detailCut); err != nil {
		return err
	}
	if _, err := wtx.ExecContext(ctx, `
		DELETE FROM route_epoch_variants
		WHERE epoch_id IN (SELECT id FROM route_epochs WHERE end_ts < ?)`,
		now.Add(-VariantRetention).Unix()); err != nil {
		return err
	}

	// Paths still named by a pending candidate live only inside its JSON, so
	// they are collected here and spared explicitly.
	pendingPaths, err := pendingPathIDs(ctx, wtx)
	if err != nil {
		return err
	}
	rows, err := wtx.QueryContext(ctx, `
		SELECT id FROM route_paths
		WHERE id NOT IN (SELECT path_id FROM route_epochs)
		  AND id NOT IN (SELECT path_id FROM route_epoch_variants)
		  AND id NOT IN (SELECT path_id FROM route_runs_detail)
		  AND id NOT IN (SELECT last_path_id FROM route_monitor_state WHERE last_path_id IS NOT NULL)`)
	if err != nil {
		return err
	}
	var dropPaths []any
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !pendingPaths[id] {
			dropPaths = append(dropPaths, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := deleteIDs(ctx, wtx, "route_paths", dropPaths); err != nil {
		return err
	}

	// Addresses: every address a detail row names is in its own path, so the
	// remaining paths are the complete reference set.
	keep := map[int64]bool{}
	rows, err = wtx.QueryContext(ctx, `SELECT ip_path FROM route_paths`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			rows.Close()
			return err
		}
		ip, err := decodeIPPath(blob)
		if err != nil {
			continue // a corrupt path keeps nothing alive; it is unreadable anyway
		}
		for _, hop := range ip {
			for _, id := range hop {
				keep[id] = true
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var drop []any
	rows, err = wtx.QueryContext(ctx, `SELECT id FROM route_ips`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !keep[id] {
			drop = append(drop, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := deleteIDs(ctx, wtx, "route_ips", drop); err != nil {
		return err
	}
	_, err = wtx.ExecContext(ctx, `
		DELETE FROM asn_info
		WHERE asn NOT IN (SELECT asn FROM route_ips)
		  AND asn NOT IN (SELECT local_asn FROM route_epochs WHERE local_asn IS NOT NULL)`)
	return err
}

func pendingPathIDs(ctx context.Context, q store.Executor) (map[int64]bool, error) {
	out := map[int64]bool{}
	rows, err := q.QueryContext(ctx, `SELECT pending FROM route_monitor_state WHERE pending<>''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p pendingState
		if json.Unmarshal([]byte(raw), &p) != nil {
			continue
		}
		out[p.PathID] = true
		for _, r := range p.Runs {
			out[r.PathID] = true
		}
	}
	return out, rows.Err()
}

// deleteIDs deletes rows by id in bounded batches (SQLite caps bound
// parameters per statement). table is one of this package's own constants.
func deleteIDs(ctx context.Context, wtx store.WriteTx, table string, ids []any) error {
	for len(ids) > 0 {
		n := min(len(ids), 500)
		if _, err := wtx.ExecContext(ctx, `DELETE FROM `+table+` WHERE id IN (`+placeholders(n)+`)`, ids[:n]...); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}
