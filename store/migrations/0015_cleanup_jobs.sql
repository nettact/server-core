-- Durable history-data cleanup jobs (DATA-001).
--
-- A cleanup job deletes selected time-series history (raw samples + rollups)
-- asynchronously: the API creates a queued job, a server-lite worker tick claims
-- and runs it batch-by-batch, and the console polls its progress. Persisting the
-- job (rather than holding it in memory) makes it survive a restart: Recover
-- requeues any job left 'running' when the process stopped, and each item is
-- re-executed idempotently (it stores the logical series key, re-resolved to
-- series ids at run time, so an already-deleted item resolves to nothing and
-- completes as a no-op — never a false success on out-of-range data).
--
-- Cascade note: this only touches metrics tables. Incidents, alerts, snapshots
-- and the audit log are stored separately (frozen evidence copies) and are NOT
-- deleted by a cleanup job.

CREATE TABLE cleanup_jobs(
  id            TEXT PRIMARY KEY,                    -- 'cj_' + uuid
  site_id       TEXT NOT NULL,
  client_token  TEXT NOT NULL DEFAULT '',            -- idempotency key (dedupes double-submit)
  mode          TEXT NOT NULL,                       -- 'selection' | 'orphans'
  from_ts       INTEGER NOT NULL DEFAULT 0,          -- inclusive lower bound (unix s); 0/0 = full delete
  to_ts         INTEGER NOT NULL DEFAULT 0,          -- exclusive upper bound (unix s)
  allow_live    INTEGER NOT NULL DEFAULT 0,          -- 1 = permitted to delete a range of a live target
  state         TEXT NOT NULL DEFAULT 'queued'       -- queued|running|done|failed|interrupted
                CHECK(state IN('queued','running','done','failed','interrupted')),
  total_items   INTEGER NOT NULL DEFAULT 0,
  done_items    INTEGER NOT NULL DEFAULT 0,
  failed_items  INTEGER NOT NULL DEFAULT 0,
  del_samples   INTEGER NOT NULL DEFAULT 0,          -- aggregate rows deleted, for the result summary
  del_rollups   INTEGER NOT NULL DEFAULT 0,
  del_series    INTEGER NOT NULL DEFAULT 0,
  error         TEXT NOT NULL DEFAULT '',            -- job-level failure (DB error aborting the loop)
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at    TIMESTAMP,
  finished_at   TIMESTAMP
);
-- One job per client_token: a resubmitted create returns the existing job.
CREATE UNIQUE INDEX idx_cleanup_jobs_token ON cleanup_jobs(client_token) WHERE client_token != '';
-- The worker claims by state; the console lists recent jobs per site.
CREATE INDEX idx_cleanup_jobs_state ON cleanup_jobs(state);
CREATE INDEX idx_cleanup_jobs_site ON cleanup_jobs(site_id, created_at);

CREATE TABLE cleanup_job_items(
  job_id     TEXT NOT NULL REFERENCES cleanup_jobs(id) ON DELETE CASCADE,
  idx        INTEGER NOT NULL,                       -- stable order within the job
  agent_id   TEXT NOT NULL,
  monitor_id TEXT NOT NULL DEFAULT '',               -- '' = system series
  kind       TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  label      TEXT NOT NULL,                          -- frozen human-readable label for the UI
  state      TEXT NOT NULL DEFAULT 'pending'         -- pending|done|failed
             CHECK(state IN('pending','done','failed')),
  detail     TEXT NOT NULL DEFAULT '',               -- error text (failed) or deleted-count note (done)
  PRIMARY KEY(job_id, idx)
);
