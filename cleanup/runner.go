package cleanup

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nettact/server-core/metrics"
)

// maxTS is an upper bound past any real unix-seconds timestamp, used to clear a
// live/system series' entire history via PurgeRange (which keeps the dictionary
// row) instead of PurgeSeriesIDs (which removes it).
const maxTS int64 = 1 << 62

// Recover requeues any job left 'running' by a process stop. Its still-pending
// items are re-executed idempotently on the next Tick. Called at startup; Tick
// also self-heals the same way, so a failed startup Recover does not wedge the
// subsystem.
func (s *Service) Recover(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE cleanup_jobs SET state='queued' WHERE state='running'`)
	return err
}

// Tick claims the oldest queued job and runs it to completion, item by item. It
// is the single-job-at-a-time executor driven on a timer by the server; when no
// job is queued it returns immediately. Each item's deletes run as autocommit
// statements (like the metrics purge path), releasing the single writer between
// items so ingest is never starved, and a per-item failure is recorded and the
// run continues (partial failure is retryable). Cancellation (shutdown) leaves
// the job 'running' with pending items; the next Tick's self-heal requeues it.
func (s *Service) Tick(ctx context.Context) error {
	// Self-heal: a job left 'running' can only be a crash/shutdown orphan here —
	// Tick processes jobs synchronously on one goroutine, so no job is actively
	// running while another Tick starts. Requeue it so a failed startup Recover (or
	// a shutdown mid-item) never wedges the subsystem (Tick only claims 'queued').
	if _, err := s.db.ExecContext(ctx, `UPDATE cleanup_jobs SET state='queued' WHERE state='running'`); err != nil {
		return err
	}

	jobID, err := s.claim(ctx)
	if err != nil || jobID == "" {
		return err
	}

	run, err := s.loadPending(ctx, jobID)
	if err != nil {
		if ctx.Err() != nil {
			return nil // interrupted before any work; self-heal requeues it
		}
		return s.failJob(ctx, jobID, err)
	}
	// Existence maps classify each item as live/system (keep the dictionary row,
	// since an agent may be concurrently ingesting it) vs orphan (safe to remove).
	monitors, agents, err := s.nameSets(ctx, run.site)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return s.failJob(ctx, jobID, err)
	}

	for _, it := range run.items {
		if ctx.Err() != nil {
			// Shutdown: leave the job running; the next Tick's self-heal requeues it.
			return nil
		}
		if err := s.runItem(ctx, run, jobID, it, monitors, agents); err != nil {
			// A context error means shutdown interrupted this item mid-flight: leave
			// the job 'running' so the self-heal requeues it, rather than failing it
			// permanently. Any other error is a real DB failure that aborts the job.
			if ctx.Err() != nil {
				return nil
			}
			return s.failJob(ctx, jobID, err)
		}
	}
	return s.finishJob(ctx, jobID)
}

// claim atomically moves the oldest queued job to running and returns its id, or
// "" when nothing is queued.
func (s *Service) claim(ctx context.Context) (string, error) {
	var jobID string
	err := s.db.Read().QueryRowContext(ctx, `SELECT id FROM cleanup_jobs WHERE state='queued' ORDER BY created_at LIMIT 1`).Scan(&jobID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE cleanup_jobs SET state='running', started_at=? WHERE id=? AND state='queued'`, time.Now().UTC(), jobID)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", nil // lost a race (shouldn't happen: single writer)
	}
	return jobID, nil
}

type pendingItem struct {
	idx    int
	key    ItemKey
	detail string // carries persisted planned counts across a crash (see runItem)
}

// jobRun is a claimed job's scope + its still-pending items.
type jobRun struct {
	site  string
	from  int64
	to    int64
	items []pendingItem
}

func (s *Service) loadPending(ctx context.Context, jobID string) (jobRun, error) {
	var run jobRun
	if err := s.db.Read().QueryRowContext(ctx, `SELECT site_id, from_ts, to_ts FROM cleanup_jobs WHERE id=?`, jobID).Scan(&run.site, &run.from, &run.to); err != nil {
		return run, err
	}
	rows, err := s.db.Read().QueryContext(ctx, `SELECT idx, agent_id, monitor_id, kind, target, detail FROM cleanup_job_items WHERE job_id=? AND state='pending' ORDER BY idx`, jobID)
	if err != nil {
		return run, err
	}
	defer rows.Close()
	for rows.Next() {
		var p pendingItem
		if err := rows.Scan(&p.idx, &p.key.AgentID, &p.key.MonitorID, &p.key.Kind, &p.key.Target, &p.detail); err != nil {
			return run, err
		}
		run.items = append(run.items, p)
	}
	return run, rows.Err()
}

// plannedCounts is the per-item deletion tally, measured before the delete and
// persisted on the item so a crash between the delete and the completion write
// does not make a re-run report zero. Stored as JSON in the item's detail column
// while the item is still pending.
type plannedCounts struct {
	S int64 `json:"s"` // samples
	R int64 `json:"r"` // rollup rows
	E int64 `json:"e"` // series rows removed
}

func parsePlanned(detail string) (plannedCounts, bool) {
	if !strings.HasPrefix(detail, "{") {
		return plannedCounts{}, false
	}
	var p plannedCounts
	if err := json.Unmarshal([]byte(detail), &p); err != nil {
		return plannedCounts{}, false
	}
	return p, true
}

// runItem executes one item's delete and records the outcome. A real per-item data
// error is recorded on the item (state=failed) and returns nil so the run
// continues. A context error (shutdown) is returned as-is WITHOUT marking the item
// failed, so it stays pending; a DB write failure aborts the job.
//
// Crash-safe counts: the deletion size is measured and persisted on the item
// BEFORE the (autocommit) delete runs, so if the process stops between the delete
// and the completion write, the requeued re-run reads the persisted counts instead
// of recomputing zero from the already-deleted data.
func (s *Service) runItem(ctx context.Context, run jobRun, jobID string, it pendingItem, monitors, agents map[string]string) error {
	ids, err := s.metrics.ResolveSeriesIDs(ctx, run.site, it.key.AgentID, it.key.MonitorID, it.key.Kind, it.key.Target)
	if err != nil {
		return s.failOrCancel(ctx, jobID, it.idx, err)
	}

	full := run.from == 0 && run.to == 0
	_, agentPresent := agents[it.key.AgentID]
	_, monitorPresent := monitors[it.key.MonitorID]
	// Keep the dictionary row for a live monitor or a present agent's system series:
	// it may be concurrently ingesting (EnsureSeries releases the metrics lock before
	// InsertSamples), so removing the row could strand samples under a deleted id.
	keepRow := agentPresent && (it.key.MonitorID == "" || monitorPresent)

	// Measure + persist planned counts once (reused verbatim on a crash re-run).
	planned, hasPlan := parsePlanned(it.detail)
	if !hasPlan {
		rc, err := s.metrics.CountRange(ctx, ids, run.from, run.to)
		if err != nil {
			return s.failOrCancel(ctx, jobID, it.idx, err)
		}
		planned = plannedCounts{S: rc.Samples, R: rc.Rollups()}
		if full && !keepRow {
			planned.E = int64(len(ids)) // orphan full delete removes the rows
		}
		if err := s.persistPlanned(ctx, jobID, it.idx, planned); err != nil {
			if ctx.Err() != nil {
				return err
			}
			return err // DB write failure aborts the job
		}
	}

	// Delete (idempotent): a re-run resolves to fewer/zero ids and removes nothing.
	var actual metrics.PurgeCounts
	switch {
	case !full:
		actual, err = s.metrics.PurgeRange(ctx, ids, run.from, run.to)
	case keepRow:
		actual, err = s.metrics.PurgeRange(ctx, ids, 0, maxTS) // clear all data, keep the row
	default:
		actual, err = s.metrics.PurgeSeriesIDs(ctx, ids)
	}
	if err != nil {
		return s.failOrCancel(ctx, jobID, it.idx, err)
	}

	// Counter precision vs crash-safety: on the normal path (the plan was measured
	// in THIS run, moments before the delete) the delete's own result is strictly
	// more accurate — rows may have arrived or been retention-pruned in between —
	// so report it. On a crash re-run (hasPlan: the plan was persisted by an
	// earlier attempt) the rows are already gone and the delete returns zero, so
	// the persisted plan is the only truthful record.
	if !hasPlan {
		planned = plannedCounts{S: actual.Samples, R: actual.Rollups, E: actual.Series}
	}

	detail := fmt.Sprintf("%d samples, %d rollup rows, %d series", planned.S, planned.R, planned.E)
	return s.markDone(ctx, jobID, it.idx, planned, detail)
}

// failOrCancel records a per-item failure and continues (returns nil), unless the
// error is a shutdown cancellation, in which case it is returned so the job stays
// running for the self-heal to requeue.
func (s *Service) failOrCancel(ctx context.Context, jobID string, idx int, cause error) error {
	if ctx.Err() != nil {
		return cause
	}
	return s.markFailed(ctx, jobID, idx, cause.Error())
}

// persistPlanned writes the pre-delete counts onto the still-pending item.
func (s *Service) persistPlanned(ctx context.Context, jobID string, idx int, p plannedCounts) error {
	b, _ := json.Marshal(p)
	_, err := s.db.ExecContext(ctx, `UPDATE cleanup_job_items SET detail=? WHERE job_id=? AND idx=?`, string(b), jobID, idx)
	return err
}

// markDone flips an item to done and folds its planned counts into the job in one
// transaction, so the item state and the job counters can't diverge on a crash.
func (s *Service) markDone(ctx context.Context, jobID string, idx int, p plannedCounts, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cleanup_job_items SET state='done', detail=? WHERE job_id=? AND idx=?`, detail, jobID, idx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE cleanup_jobs SET done_items=done_items+1, del_samples=del_samples+?, del_rollups=del_rollups+?, del_series=del_series+? WHERE id=?`,
		p.S, p.R, p.E, jobID); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// markFailed flips an item to failed and bumps the job's failed counter.
func (s *Service) markFailed(ctx context.Context, jobID string, idx int, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cleanup_job_items SET state='failed', detail=? WHERE job_id=? AND idx=?`, detail, jobID, idx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cleanup_jobs SET failed_items=failed_items+1 WHERE id=?`, jobID); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Service) finishJob(ctx context.Context, jobID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE cleanup_jobs SET state='done', finished_at=? WHERE id=?`, time.Now().UTC(), jobID)
	return err
}

func (s *Service) failJob(ctx context.Context, jobID string, cause error) error {
	// Best-effort: record the job-level error. Return the original cause so the
	// worker logs it.
	_, _ = s.db.ExecContext(context.Background(), `UPDATE cleanup_jobs SET state='failed', error=?, finished_at=? WHERE id=?`, cause.Error(), time.Now().UTC(), jobID)
	return cause
}
