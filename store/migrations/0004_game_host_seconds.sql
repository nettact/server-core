-- Machine-level per-second telemetry, keyed by the agent and the second rather
-- than by a run — and the four columns it takes out of game_buckets.
--
-- ---------------------------------------------------------------------------
-- Why a new numbered file and not an edit to 0001
--
-- The same reason 0002 gives at length: store/migrate.go applies each numbered
-- file once and records it in schema_migrations, 0001 is already recorded in a
-- live development database holding real collected game data, and an edit there
-- would silently never run — no error, no columns, and the endpoints broken
-- until someone deleted the file and lost the data. 0001 stays the baseline for
-- fresh installs; post-baseline changes append from here.
--
-- This is not a compatibility shim. It carries no dual-read path and retains no
-- deprecated column; it is schema history, which is what the migrator exists to
-- apply.
-- ---------------------------------------------------------------------------
--
-- Why the readings moved. gpu_util_pct is the ADAPTER's load and
-- busiest_core_pct is the PROCESSOR's; both describe every process on the
-- machine. Storing them per-run-per-second meant they existed only for the
-- seconds a diag-tier game happened to win, so a machine-level question — "was
-- something else taking the card" — could only be asked of the seconds one
-- particular game was drawing in. Worse, the seconds with no frames at all (a
-- minimized game, a loading screen) produced no bucket, so the stretch a reader
-- most wants explained was the stretch with no data.
--
-- Here they are collected for every second the sensor is watching anything,
-- frames or not, and a run reads whichever of them its window covers. Two runs
-- overlapping a second share one row instead of each holding a private copy of
-- one machine's load, and deleting a run does not take the machine's history
-- with it.
--
-- The columns leave game_buckets in this same file, because leaving them in both
-- places is the one outcome nothing here wants: two sources for one fact,
-- disagreeing the moment a run is base-tier.
--
-- NULL means NOT MEASURED here as everywhere else in this schema.

CREATE TABLE game_host_seconds(
  agent_id TEXT NOT NULL REFERENCES agents(id),
  -- Denormalized from agents exactly as game_runs.site_id is, so the read and
  -- retention queries are self-contained and a site-ownership check costs no join.
  site_id TEXT NOT NULL,
  ts INTEGER NOT NULL,             -- unix seconds, the second this reading closed
  -- The busy share of every logical core, and of the busiest one. Written and
  -- left NULL together: one counter read is differenced into both, so a machine
  -- that answered has both figures and one that did not has neither, and
  -- cpu_total_pct is the pair's discriminator.
  --
  -- Both are stored because either alone misleads. A single-threaded game pins
  -- one core at 100% while a sixteen-thread machine reports 6% busy: the total
  -- alone says the machine is idle while the game is starved, and the busiest
  -- alone says it is saturated while fifteen cores sit free. The GAP between
  -- them is the finding, and a gap is only visible when both are recorded.
  --
  -- Two zeros is a genuinely idle machine and a real measurement. Only NULL
  -- means the counters could not be read.
  cpu_total_pct REAL,
  cpu_busiest_pct REAL,
  -- The processor's clock, MHz, and its nominal maximum. Written and left NULL
  -- together: one power-management call returns both.
  --
  -- cpu_mhz is the HIGHEST clock any logical core is at, not a mean. Processors
  -- boost a few cores well past the all-core clock and the game's own thread is
  -- often one of them, so an average reports a processor coasting at its base
  -- clock while the thread that matters is at its ceiling — the same argument
  -- cpu_busiest_pct makes about utilization, and read alongside it.
  --
  -- The maximum is stored per second rather than once per machine for the reason
  -- mem_total is: 3.2 GHz is a processor coasting on one machine and one pinned
  -- at its ceiling on another, and nothing else in the row says which.
  --
  -- Separate from the pair above because they come from different calls that
  -- fail independently: one differences performance counters, the other reads
  -- power management. Needs no graphics permission — the processor is not the
  -- graphics device.
  cpu_mhz REAL,
  cpu_max_mhz REAL,
  -- Physical memory in use, and installed. The capacity is stored per second
  -- rather than once per machine because it is what makes the level readable: 12
  -- GB in use is comfortable on a 32 GB box and terminal on a 16 GB one, and a
  -- reader looking at a stored second months later has nothing else to tell them
  -- apart. Written and left NULL together; one call returns both, and mem_used
  -- is the pair's discriminator.
  mem_used INTEGER,
  mem_total INTEGER,
  -- Whole-adapter telemetry. These three are EACH independent, unlike the pairs
  -- above: which figures a driver publishes varies by vendor and by metric, so a
  -- card reporting utilization and no memory is an ordinary card rather than a
  -- failed read. Read-back rebuilds the block when ANY of them is non-NULL.
  --
  -- This is the only block here gated by game.gpu.read — it describes the card
  -- every process on the machine shares. The CPU and memory readings above need
  -- no graphics permission at all and are never stripped: the busiest core is a
  -- fact about the processor, and so is the rest of it.
  gpu_util_pct REAL,               -- whole-GPU utilization 0-100
  gpu_mem_used INTEGER,            -- whole-GPU dedicated memory used, bytes
  gpu_mem_size INTEGER,            -- dedicated memory capacity, bytes
  -- The card's two clocks, MHz. Two of them because they throttle for different
  -- reasons and independently: the core drops on power and thermal limits while
  -- memory holds its clock through most of that. A frame rate that fell while
  -- the core clock fell with it is a card that ran out of headroom; one that
  -- fell while both clocks held is not, and that is the fork these decide.
  gpu_core_mhz REAL,
  gpu_mem_mhz REAL,
  -- JSON array of flags; NULL when none apply. A row with every reading NULL and
  -- no flag is never written: an all-NULL row asserts "this second was covered
  -- and nothing was readable", which has to be earned by an explanation, or a
  -- reader is left treating the row as evidence of something with nothing behind
  -- it.
  quality TEXT,
  -- (agent_id, ts) is the identity, so a replayed upload overwrites nothing —
  -- and it is also the read pattern: a run detail asks for one agent's window
  -- and gets a primary-key range scan rather than a filter over every machine.
  PRIMARY KEY(agent_id, ts)
) WITHOUT ROWID;
-- Retention sweeps by age across every agent at once, and this table grows at
-- one row per second of play — faster than game_buckets, since it also covers
-- the frameless seconds. The age sweep gets its own index rather than scanning.
CREATE INDEX idx_game_host_seconds_ts ON game_host_seconds(ts);

-- The columns these replace. Dropped rather than left in place: the project
-- keeps no deprecated fields, and a column no writer fills and no reader reads
-- is a trap for whoever opens the database next.
--
-- 0001's DDL is NOT edited to match. A fresh install still creates these four
-- and then drops them here; deleting the declarations there would make this file
-- fail on exactly the installs it was written for.
ALTER TABLE game_buckets DROP COLUMN gpu_util_pct;
ALTER TABLE game_buckets DROP COLUMN gpu_mem_used;
ALTER TABLE game_buckets DROP COLUMN gpu_mem_size;
ALTER TABLE game_buckets DROP COLUMN busiest_core_pct;
