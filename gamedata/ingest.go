package gamedata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/permission"
)

// Result reports what one packet's game payload did, for the ingest log. A packet
// whose data was refused wholesale (Denied) is a different event from one whose
// individual buckets were rejected, and the two must not read alike when someone
// is working out why a run has no frames.
type Result struct {
	Runs     int  // runs upserted
	Buckets  int  // buckets stored (a replayed second stores nothing)
	Rejected int  // buckets refused: unknown run or unrecognized histogram layout
	Denied   bool // the agent does not hold game.performance.read
}

// Apply stores a packet's runs and buckets inside the caller's ingest
// transaction, so game data and the telemetry it arrived with reach one committed
// state together.
//
// Runs are upserted: the agent re-sends a run whenever its mutable fields change
// (title, last seen, ending), which is what completes a run that outlived a
// disconnect. Buckets are INSERT OR IGNORE on (run_id, ts) like every other
// replay-safe write here — an at-least-once uploader must be able to retry a batch
// without duplicating or rewriting a second that is already recorded.
func Apply(ctx context.Context, tx *sql.Tx, agentID, siteID string, runs []gamesense.Run, buckets []gamesense.Bucket) (Result, error) {
	var res Result
	if len(runs) == 0 && len(buckets) == 0 {
		return res, nil
	}

	// Permission gate. Game data is not a metric, so the metric-kind mapping does
	// not cover it and the permission is checked directly. The agent enforces its
	// own policy, but a policy that was narrowed while a batch sat in the agent's
	// WAL would otherwise still land here — storing frame data the operator has
	// since revoked. The effective set is the intersection the agent reported, so a
	// build or platform that cannot capture frames also fails this test.
	ok, err := hasGamePermission(ctx, tx, agentID)
	if err != nil {
		return res, err
	}
	if !ok {
		res.Denied = true
		log.Printf("gamedata: dropped %d run(s) and %d bucket(s) from agent %s without %s",
			len(runs), len(buckets), agentID, permission.GamePerformanceRead)
		return res, nil
	}

	for _, run := range runs {
		if run.ID == "" {
			continue
		}
		if err := upsertRun(ctx, tx, agentID, siteID, run); err != nil {
			return res, err
		}
		res.Runs++
	}

	// Buckets are only stored under a run this agent already owns. Creating a run
	// from a bucket would invent a session with no start, no source and no
	// capability list — a phantom whose frames could never be interpreted, since
	// nothing would say what the capture could see.
	known, err := ownedRuns(ctx, tx, agentID, buckets)
	if err != nil {
		return res, err
	}
	deltas := map[string]*runDelta{}
	for _, b := range buckets {
		if !known[b.RunID] || !knownLayout(b.Hist) {
			res.Rejected++
			continue
		}
		stored, err := insertBucket(ctx, tx, b)
		if err != nil {
			return res, err
		}
		// Only a second the insert actually took is folded into the run's totals. A
		// replayed batch re-reports every second it carries, and a second counted
		// twice can never be caught: the totals outlive the rows they came from, so
		// nothing downstream could ever recompute them and notice.
		if stored {
			res.Buckets++
			fold(deltas, b)
		}
	}
	if err := writeAggregates(ctx, tx, deltas); err != nil {
		return res, err
	}
	if res.Rejected > 0 {
		log.Printf("gamedata: rejected %d bucket(s) from agent %s (unknown run or histogram layout)", res.Rejected, agentID)
	}
	return res, nil
}

// hasGamePermission reports whether the agent's reported effective set includes
// the frame-data permission. An agent row that has vanished mid-batch simply
// fails the test rather than erroring: there is nothing left to attribute the data
// to.
func hasGamePermission(ctx context.Context, tx *sql.Tx, agentID string) (bool, error) {
	var effective string
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(perm_effective,'[]') FROM agents WHERE id=?`, agentID).Scan(&effective)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return permission.FromStrings(decodeStrings(effective)).Has(permission.GamePerformanceRead), nil
}

// knownLayout reports whether this histogram is one this build can interpret.
// Storing counts under an unrecognized layout name would let a later reader apply
// the wrong bin edges to them and report frame times that were never measured —
// the layout name is the whole compatibility contract, so a mismatch is refused
// rather than kept "just in case".
func knownLayout(h gamesense.Histogram) bool {
	return h.Layout == gamesense.HistLayoutLog24V1 && len(h.Counts) == gamesense.HistBins
}

// upsertRun writes a run, letting the newer report win on the mutable fields.
//
// Newer is decided by last_seen_at rather than by arrival order, because an
// at-least-once uploader can redeliver an early copy of a run after a later one
// has already landed; taking arrival order would then reinstate a stale window
// title and rewind the run's extent. ended_at is COALESCEd instead: once a run is
// known to be over, no replay may reopen it.
//
// Identity columns (agent, site, start, source, caps) are never updated. They
// describe the session and how it was measured, and a run whose measurement basis
// changed under it is a different run.
func upsertRun(ctx context.Context, tx *sql.Tx, agentID, siteID string, run gamesense.Run) error {
	var ended sql.NullInt64
	if run.EndedAt != nil {
		ended = sql.NullInt64{Int64: run.EndedAt.Unix(), Valid: true}
	}
	// The agent_id guard on the update is what stops one agent's run id from
	// overwriting another's. Ids are agent-generated, so collision is the caller's
	// mistake to make; the write silently does nothing rather than reattributing a
	// session to the wrong machine.
	//
	// Every mutable field, the ending included, follows the same rule: the report
	// that has seen the most of the run wins. An ending is provisional — a person
	// who alt-tabs away and comes back within the hour is in the same session, and
	// the agent reopens it — so a rule that made an end permanent would leave the
	// second half of that session stranded in a run marked finished. Ordering on
	// last_seen_at is what keeps that from also letting a replayed old packet
	// reopen a run that genuinely finished: a stale report has, by definition,
	// seen less.
	// The profile stamp is mutable under the same guard as proc and title: a
	// profile created while a session is already running re-classifies it on the
	// agent's next report, and an empty id is a session that matches none — stored
	// as NULL, never as the empty string, so "other process" is one value rather
	// than two that readers would have to test for separately.
	_, err := tx.ExecContext(ctx, `
		INSERT INTO game_runs(id, agent_id, site_id, proc, title, profile_id, started_at, last_seen_at, ended_at, source, caps)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			proc = CASE WHEN excluded.last_seen_at >= game_runs.last_seen_at THEN excluded.proc ELSE game_runs.proc END,
			title = CASE WHEN excluded.last_seen_at >= game_runs.last_seen_at THEN excluded.title ELSE game_runs.title END,
			profile_id = CASE WHEN excluded.last_seen_at >= game_runs.last_seen_at
			                  THEN excluded.profile_id ELSE game_runs.profile_id END,
			last_seen_at = max(game_runs.last_seen_at, excluded.last_seen_at),
			ended_at = CASE WHEN excluded.last_seen_at >= game_runs.last_seen_at
			                THEN excluded.ended_at ELSE game_runs.ended_at END
		WHERE game_runs.agent_id = excluded.agent_id`,
		run.ID, agentID, siteID, run.Proc, run.Title, nullStr(run.ProfileID),
		run.StartedAt.Unix(), run.LastSeenAt.Unix(), ended, run.Source,
		string(mustJSON(run.Caps)))
	return err
}

// ownedRuns returns which of the referenced run ids exist and belong to this
// agent. Read after the upserts so a run arriving in the same packet as its first
// buckets is already there.
func ownedRuns(ctx context.Context, tx *sql.Tx, agentID string, buckets []gamesense.Bucket) (map[string]bool, error) {
	want := map[string]bool{}
	args := []any{agentID}
	for _, b := range buckets {
		if b.RunID == "" {
			continue
		}
		if _, seen := want[b.RunID]; !seen {
			want[b.RunID] = false
			args = append(args, b.RunID)
		}
	}
	if len(want) == 0 {
		return want, nil
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM game_runs WHERE agent_id=? AND id IN (`+placeholders(len(want))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if _, referenced := want[id]; referenced {
			want[id] = true
		}
	}
	return want, rows.Err()
}

func insertBucket(ctx context.Context, tx *sql.Tx, b gamesense.Bucket) (bool, error) {
	var (
		dispAvg, dispP95              sql.NullFloat64
		mode, api                     sql.NullString
		sync, tearing, presentChanged sql.NullInt64
	)
	if b.DispFT != nil {
		dispAvg = nullFloat(b.DispFT.Avg, true)
		dispP95 = nullFloat(b.DispFT.P95, true)
	}
	if b.Present != nil {
		mode = nullStr(b.Present.Mode)
		api = nullStr(b.Present.API)
		sync = nullInt(b.Present.Sync)
		tearing = nullBool(b.Present.Tearing)
		// Written unconditionally for a present block, including false: it is the
		// column that says the block was observed at all.
		presentChanged = nullBool(&b.Present.Changed)
	}
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO game_buckets(
			run_id, ts, presented, displayed, dropped, app_frames, generated_frames,
			ft_avg, ft_p50, ft_p95, ft_p99, ft_max, ft_sd,
			hist_layout, hist, disp_ft_avg, disp_ft_p95,
			present_mode, sync_interval, tearing, api, present_changed, quality)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		b.RunID, b.TS.Unix(), b.Frames.Presented,
		nullInt(b.Frames.Displayed), nullInt(b.Frames.Dropped),
		nullInt(b.Frames.App), nullInt(b.Frames.Generated),
		b.FT.Avg, b.FT.P50, b.FT.P95, b.FT.P99, b.FT.Max, b.FT.SD,
		b.Hist.Layout, encodeHist(b.Hist.Counts), dispAvg, dispP95,
		mode, sync, tearing, api, presentChanged, encodeStrings(b.Quality))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// runDelta is one packet's contribution to a run's stored totals.
type runDelta struct {
	hist               []uint32
	presented          int64
	displayed, dropped int64
	sawDisplayed       bool
	sawDropped         bool
}

// fold adds one newly stored second to its run's delta.
func fold(deltas map[string]*runDelta, b gamesense.Bucket) {
	d := deltas[b.RunID]
	if d == nil {
		d = &runDelta{hist: make([]uint32, gamesense.HistBins)}
		deltas[b.RunID] = d
	}
	d.presented += int64(b.Frames.Presented)
	// A count this second could not see is a blind spot in the source, not a zero:
	// it contributes nothing AND leaves the run's total absent unless some second
	// could see it. A source that never can must keep NULL, because a zero there
	// reads as a run that dropped no frames.
	if b.Frames.Displayed != nil {
		d.displayed += int64(*b.Frames.Displayed)
		d.sawDisplayed = true
	}
	if b.Frames.Dropped != nil {
		d.dropped += int64(*b.Frames.Dropped)
		d.sawDropped = true
	}
	gamesense.HistAdd(d.hist, b.Hist.Counts)
}

// writeAggregates merges each run's delta into the totals stored on its row.
//
// One read-modify-write per run per packet rather than per second, because a
// batch commonly carries a minute of them and the histogram merge cannot be
// expressed in SQL. It runs in the caller's transaction, so a second's row and
// its contribution to the run reach one committed state together — the two can
// never disagree about what has been counted.
func writeAggregates(ctx context.Context, tx *sql.Tx, deltas map[string]*runDelta) error {
	for id, d := range deltas {
		var (
			presented          int64
			displayed, dropped sql.NullInt64
			layout             sql.NullString
			blob               []byte
		)
		if err := tx.QueryRowContext(ctx,
			`SELECT presented, displayed, dropped, hist_layout, hist FROM game_runs WHERE id=?`, id).
			Scan(&presented, &displayed, &dropped, &layout, &blob); err != nil {
			return err
		}
		a := newRunAggregate(presented, displayed, dropped, layout, blob)

		merged := make([]uint32, gamesense.HistBins)
		gamesense.HistAdd(merged, a.hist)
		gamesense.HistAdd(merged, d.hist)

		// An absent total takes the delta as-is: NULL is "nothing has ever counted
		// this", so the first second that can count it establishes the total rather
		// than adding to a zero that was never measured.
		if d.sawDisplayed {
			a.displayed = sql.NullInt64{Int64: a.displayed.Int64 + d.displayed, Valid: true}
		}
		if d.sawDropped {
			a.dropped = sql.NullInt64{Int64: a.dropped.Int64 + d.dropped, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE game_runs SET presented=?, displayed=?, dropped=?, hist_layout=?, hist=? WHERE id=?`,
			a.presented+d.presented, a.displayed, a.dropped,
			gamesense.HistLayoutLog24V1, encodeHist(merged), id); err != nil {
			return err
		}
	}
	return nil
}

// mustJSON encodes a capability list, falling back to an empty array. A list that
// cannot be marshalled is not a reason to lose the run.
func mustJSON(ss []string) []byte {
	if len(ss) == 0 {
		return []byte("[]")
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return []byte("[]")
	}
	return b
}
