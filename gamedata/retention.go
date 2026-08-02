package gamedata

import (
	"context"
	"time"

	"github.com/nettact/server-core/settings"
)

// Retention deletes aged-out game data and reports the rows removed.
//
// The two windows are deliberately far apart. Buckets are one row per second of
// play — the fastest-growing table in the store — and their value is short-lived:
// nobody charts the frame-by-frame shape of a session from three months ago. Runs
// are one row each and carry the summary an operator does compare over time, so
// they outlive their detail. A run whose buckets have gone still reports that
// summary in full, because ingest folds every second into the run's own totals as
// it lands rather than deriving them from the rows this sweep deletes.
//
// Machine seconds age on the BUCKET window and are counted with them. They are
// per-second detail of exactly the same kind, they grow slightly faster (they
// also cover the frameless seconds), and outliving the buckets would leave a run
// whose machine curves are drawn across a frame chart with nothing in it — which
// reads as a game that stopped rendering rather than as data that aged out.
//
// Gaps need no sweep of their own: they are per-run rather than per-second, so a
// whole evening produces a handful, and game_run_gaps cascades from game_runs.
// They are deleted with the run whose blanks they explain, which is the only
// moment they stop meaning anything.
//
// The first return counts every per-second row removed — buckets and machine
// seconds together — because they age on one window and a caller that reported
// them apart would be describing an implementation detail rather than the sweep.
func (s *Service) Retention(ctx context.Context) (seconds, runs int64, err error) {
	now := time.Now().UTC()

	if days, _ := s.settings.Int(ctx, settings.KeyGameBucketRetentionDays); days > 0 {
		cutoff := now.AddDate(0, 0, -days).Unix()
		res, err := s.db.ExecContext(ctx, `DELETE FROM game_buckets WHERE ts < ?`, cutoff)
		if err != nil {
			return 0, 0, err
		}
		seconds, _ = res.RowsAffected()

		res, err = s.db.ExecContext(ctx, `DELETE FROM game_host_seconds WHERE ts < ?`, cutoff)
		if err != nil {
			return seconds, 0, err
		}
		n, _ := res.RowsAffected()
		seconds += n
	}

	// Runs age on last_seen_at, not started_at: a session that ran across the cutoff
	// is still recent data, and dropping it because it began a day earlier would
	// take its buckets with it.
	if days, _ := s.settings.Int(ctx, settings.KeyGameRunRetentionDays); days > 0 {
		cutoff := now.AddDate(0, 0, -days).Unix()
		res, err := s.db.ExecContext(ctx,
			`DELETE FROM game_buckets WHERE run_id IN (SELECT id FROM game_runs WHERE last_seen_at < ?)`,
			cutoff)
		if err != nil {
			return seconds, 0, err
		}
		// Counted with the age sweep's rows rather than dropped on the floor. With the
		// bucket window disabled or set longer than the run window this delete is the
		// only one that removes any, and reporting zero would have the log claim
		// retention found nothing to do while it was deleting.
		n, _ := res.RowsAffected()
		seconds += n

		// Explicitly, not by the cascade, for the reason DeleteRun gives: the
		// delete must not depend on a connection-level pragma being set.
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM game_run_gaps WHERE run_id IN (SELECT id FROM game_runs WHERE last_seen_at < ?)`,
			cutoff); err != nil {
			return seconds, 0, err
		}

		res, err = s.db.ExecContext(ctx, `DELETE FROM game_runs WHERE last_seen_at < ?`, cutoff)
		if err != nil {
			return seconds, 0, err
		}
		runs, _ = res.RowsAffected()
	}
	return seconds, runs, nil
}
