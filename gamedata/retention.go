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
func (s *Service) Retention(ctx context.Context) (buckets, runs int64, err error) {
	now := time.Now().UTC()

	if days, _ := s.settings.Int(ctx, settings.KeyGameBucketRetentionDays); days > 0 {
		res, err := s.db.ExecContext(ctx, `DELETE FROM game_buckets WHERE ts < ?`,
			now.AddDate(0, 0, -days).Unix())
		if err != nil {
			return 0, 0, err
		}
		buckets, _ = res.RowsAffected()
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
			return buckets, 0, err
		}
		// Counted with the age sweep's rows rather than dropped on the floor. With the
		// bucket window disabled or set longer than the run window this delete is the
		// only one that removes any, and reporting zero would have the log claim
		// retention found nothing to do while it was deleting.
		n, _ := res.RowsAffected()
		buckets += n

		res, err = s.db.ExecContext(ctx, `DELETE FROM game_runs WHERE last_seen_at < ?`, cutoff)
		if err != nil {
			return buckets, 0, err
		}
		runs, _ = res.RowsAffected()
	}
	return buckets, runs, nil
}
