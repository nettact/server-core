package gamedata

import (
	"context"
	"time"
)

// The staleness bounds past which a run with no ending is treated as abandoned.
//
// A run's ending is written by the agent: the sensor stopping parks the current
// session, which stamps ended_at and hands the run to the next drain. Every
// ORDERLY way a session can finish therefore ends its own run. What no agent can
// do is end a run whose process died at the instant the run was orphaned — a
// force-kill, a crash, a power cut, a BSOD — because the code that would have
// written the ending died with it, and after a restart the recorder's parked map
// is empty, so nothing on that machine remembers the run to close it. The row is
// left with ended_at NULL forever, the console reads NULL as "running", and an
// abandoned session shows as in progress indefinitely. The server is the only
// party left that can close it.
//
// # The connected bound
//
// For a run whose agent is connected, the bound has to clear the longest gap a
// HEALTHY session can leave between two reports of itself, and that gap is
// dominated by the agent's WAL batch-upload cadence — which is configurable
// (NETTACT_AGENT_UPLOAD_INTERVAL), not the 5s default. Draining game data into the
// WAL at most every 60s does not help: the WAL is on the agent's disk, and the
// server learns nothing until the batch is uploaded. So a fixed constant chosen
// against the default would close every live run on a deployment configured to
// upload every 15 minutes, over and over, for most of each upload cycle.
//
// The bound is therefore derived from what the agent itself reported:
//
//	max(runAbandonedFloor, runAbandonedUploadFactor × reported upload interval)
//
// capped at runAbandonedMax. The factor follows the precedent in
// protocol/config.StaleAfter, which adds 2×upload of link slack to every
// freshness window on the grounds that a sample can miss one batch boundary and
// then need a retry; 4× doubles that allowance, because unlike a probe sample a
// run report is not resent on its own — it rides the next batch that happens to
// carry the run. The 60s drain bound needs no term of its own: above the point
// where the factor takes over (upload > 2.5 min) 4×upload already exceeds
// 60s + 2×upload, and below it the floor does.
//
// runAbandonedFloor governs the ordinary deployment (5s uploads → the factor
// yields 20s, which would reap a live run the moment one batch was late). Ten
// minutes is roughly two orders of magnitude above the default cadence, which is
// what keeps ordinary jitter, a burst of WAL backlog and a moderately wrong agent
// clock from tripping it: last_seen_at is stamped by the AGENT's clock, which this
// codebase already accepts can run ahead of (and therefore also behind) the
// server's. A clock behind by more than the bound would have its live runs reaped
// and immediately un-reaped by the next batch — see "Why guessing wrong is safe"
// on CloseAbandonedRuns — so the failure mode is a flap rather than lost data, and
// that is why the floor can be chosen for responsiveness rather than defensively.
//
// runAbandonedMax exists because the reported interval is agent-supplied and
// validated only for positivity. Without a cap, one agent reporting a nonsense
// interval would disable the sweep for its own runs indefinitely, which is the
// reported bug back again. Six hours is far past any honest upload cadence and
// still bounds how long a wrong "in progress" can survive.
//
// # The offline bound
//
// Once the owning agent is not connected, no report for its runs can physically
// arrive, which is sharper evidence than any timestamp — and it is measured on the
// SERVER's clock by the offline sweeper, so an agent's own clock cannot affect it.
//
// The grace is measured from when the agent was last HEARD FROM (agents.
// last_seen_at), not from the run's staleness. Those are different quantities and
// using the run's would defeat the grace outright: a run whose last report is
// already older than the grace when its agent drops — after a server restart, or
// an upload backlog, i.e. exactly when a live agent looks stale — would be closed
// on the very first tick with no grace at all. agents.last_seen_at is the right
// clock for it because agentws pings every 15s and each successful ping bumps it,
// so a connected agent's stamp is never more than a ping old whatever its upload
// cadence is, and it is the same column the offline sweeper thresholds on: waiting
// two minutes past it is waiting ~two minutes past the disconnect, which absorbs a
// reconnect blip, an agent restart and a server restart without ending a run that
// is still being played.
//
// # Cost
//
// Both tests read tables this package is already in: agents on the ingest path
// (agentPermissions), and monitor_status for the one column that carries the
// reported upload interval. Neither adds a dependency on agentstatus,
// agentconnectivity or the fault engine.
const (
	runAbandonedFloor        = 10 * time.Minute
	runAbandonedUploadFactor = 4
	runAbandonedMax          = 6 * time.Hour
	runAbandonedAfterOffline = 2 * time.Minute
)

// CloseAbandonedRuns ends runs that can no longer receive data and reports how
// many it closed, so the worker log can say what it did the way Retention's
// counts do.
//
// The ending is stamped at the run's own last_seen_at, never at the time of the
// sweep. The session really did stop when its last second arrived; stamping "now"
// would invent however many minutes or hours passed between the crash and the
// sweep noticing, and duration is computed from ended_at (see runAggregate.
// duration), so that invention would be reported as play time that never
// happened.
//
// # Why guessing wrong is safe
//
// Reaping is a guess, and it has to be safe to guess wrong. It is, because of how
// upsertRun resolves a conflict: every mutable field, ended_at included, is taken
// from the report with the newer last_seen_at. A run this sweep closed at L is
// stored as last_seen_at=L, ended_at=L; a later batch from a session that was
// alive all along carries last_seen_at=L' > L and ended_at NULL, wins the
// comparison, and writes that NULL — reopening the run. So a premature close is
// undone by the very next report, and the only cost of guessing wrong is that the
// console briefly showed a run as finished. TestAbandonedRunReopensOnLateBatch
// pins that sequence end to end.
//
// One consequence worth naming: because the comparison is >=, a replayed batch
// carrying the SAME last_seen_at and no ending also clears the reap. That run is
// then closed again on the next sweep, so the state converges either way; it just
// costs an extra flap on a redelivery.
//
// Self-healing is what makes the guess permissible, NOT what makes it acceptable
// to guess badly: every reversal is a run the console showed as finished while it
// was being played. Both bounds above are therefore sized so a healthy session
// never reaches them, and self-healing covers only what no bound can predict — a
// wrong agent clock, an outage-sized backlog.
func (s *Service) CloseAbandonedRuns(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, reapSQL,
		now.Unix(),
		int64(runAbandonedMax.Seconds()),
		int64(runAbandonedFloor.Seconds()),
		runAbandonedUploadFactor,
		now.Add(-runAbandonedAfterOffline))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// reapSQL is a named constant so TestReapSweepsOnlyOpenRuns can put THIS query
// through EXPLAIN QUERY PLAN rather than a copy of it that could drift.
//
// ended_at IS NULL is a top-level term, which is what lets SQLite use the partial
// index (idx_game_runs_open) at all, and it reduces the minute tick to a walk of
// the sessions currently in progress — normally none — instead of a scan of every
// run in the ninety-day window. Both arms hang off that term, so their correlated
// subqueries run per OPEN run rather than per run.
//
// The upload interval is read from monitor_status because that is where it lands:
// the agent reports it on MonitorStatus, which is a per-target frame, so an
// agent-global setting is stored once per (agent, monitor) pair. MAX over the
// agent's rows recovers the one value they all carry, and the (agent_id,
// monitor_id) primary key makes it a key-prefix lookup. An agent with no probe
// targets at all has no row and no reported interval — COALESCE to 0 then leaves
// the floor in charge, which is the correct answer for an agent that has told us
// nothing.
//
// The liveness arm is written as "an agent that is not live owns this run" rather
// than "the agent is offline", so a revoked agent — socket gone, never to be
// admitted again — falls under the same clause without a second one. Its own
// last_seen_at carries the grace: NULL there means the server has never heard from
// this agent at all, which satisfies any grace there could be.
const reapSQL = `
	UPDATE game_runs SET ended_at = last_seen_at
	 WHERE ended_at IS NULL
	   AND (last_seen_at < ? - min(?, max(?, ? * COALESCE(
	              (SELECT MAX(ms.upload_interval_seconds) FROM monitor_status ms
	                WHERE ms.agent_id = game_runs.agent_id
	                  AND ms.upload_interval_seconds > 0), 0)))
	        OR EXISTS (SELECT 1 FROM agents a
	                    WHERE a.id = game_runs.agent_id
	                      AND (a.status <> 'online' OR a.revoked <> 0)
	                      AND (a.last_seen_at IS NULL OR a.last_seen_at < ?)))`
