-- The stretches of a run that produced no frames, and which silence each was.
--
-- A new numbered file for the reason 0002 and 0004 give: 0001 is already
-- recorded in schema_migrations of a live development database, so an edit there
-- would silently never run.
--
-- Why this table exists. A game that is minimized, alt-tabbed, sitting on a
-- loading screen or building a shader cache presents nothing, and a second with
-- no frames produces no bucket — "nothing was rendering" and "rendering happened
-- at zero" are different facts and only one of them can be plotted. The result
-- was a blank stretch across every chart that a reader could only interpret as
-- lost data. This records what the blank was.
--
-- Two reasons rather than one, because the remedies are opposite. 'background'
-- is time nobody was playing: nothing is wrong and the figures around it must
-- not be read as a stall. 'no_frames' is the player sitting in front of the
-- game waiting for it, which is an experience worth measuring. Recording only
-- "no frames" would be the same as recording nothing — the blank is already
-- visible, and what a reader cannot see is which kind it was. The vocabulary is
-- open: the sensor owns it, and a reader meeting a code it does not know must
-- render the band unlabelled rather than drop it.
CREATE TABLE game_run_gaps(
  -- Minted by the agent, which is the only party that can attribute a silence to
  -- a run: run ids are its to make, and it is what knows a session parked after
  -- thirty frameless seconds is still the same session ten minutes later.
  id TEXT PRIMARY KEY,
  -- CASCADE, unlike game_runs.profile_id's deliberate lack of a foreign key. A
  -- gap is part of the run's own record rather than a stamp of separate
  -- configuration, so deleting the run deletes it — and retention then needs no
  -- sweep of its own here.
  run_id TEXT NOT NULL REFERENCES game_runs(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,            -- 'background' | 'no_frames'; open vocabulary
  -- Unix seconds. started_at is the moment the first frameless second BEGAN and
  -- ended_at the moment the last one closed, so an interval sits on the same
  -- axis a bucket's ts does and a single frameless second spans exactly one.
  --
  -- ended_at is NOT NULL even while the stretch is still growing: the agent
  -- re-sends the interval with a later end as it accumulates, and an "open"
  -- state would add a case no reader would draw differently from "ends here for
  -- now" while costing every reader a branch.
  --
  -- It may fall AFTER the run's own ended_at, and must not be clamped. A run
  -- ends at its last frame; a player who minimized the game and never came back
  -- leaves fifty minutes of silence after it, and "did they stop playing or just
  -- alt-tab" is exactly the question this table answers.
  started_at INTEGER NOT NULL,
  ended_at INTEGER NOT NULL
);
-- The read pattern: one run's gaps in time order, for the bands drawn under its
-- charts.
CREATE INDEX idx_game_run_gaps_run ON game_run_gaps(run_id, started_at);
