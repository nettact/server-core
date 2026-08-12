# Store contract migration ledger (CLOUD-014A)

Internal working document for the Scope/Executor/WriteTx store-contract
migration. Tracks which call sites speak the new contract, which still speak
raw `*sql.Tx` / `*store.DB`, and who owns closing each gap. Updated per slice;
deleted when CLOUD-015 lands.

## What this milestone shipped

- `store/contract.go` — `Scope` (+ `Validate`, `IsSystem`, `SystemScope`,
  `Standalone`), `Dialect` (+ `Rebind`), `Executor`, `WriteTx`.
- `store/tx.go` — the SQLite adapter (`sqliteTx`) and the entry points
  `DB.WriteTx`, `DB.ReadTx`, plus the migration seam `DB.SQLiteTx(WriteTx)`.
- `store/contract_test.go` — scope matrix, post-after-commit visibility,
  post-discarded-on-error paths, bridge behavior.
- **One vertical slice migrated: ingest** (see below). Everything else is
  explicitly unchanged and enumerated here.

## Migrated in this slice (ingest)

| Site | Before | After |
| --- | --- | --- |
| `ingest.Ingest` transaction | `s.db.BeginTx` + manual commit/rollback/`committed` flag | `s.db.WriteTx(ctx, store.Standalone(), fn)`; the post-commit block (touchPost → AppendRawSamples → UpdateLatest → PublishOutcome) is the returned post closure, preserving the old ordering; append failure still acks |
| `ingest.probeMeta` / `ingest.hostMeta` / `ingest.reportedUploadSeconds` | `rowQuerier` (QueryContext-only) | `store.Executor` (read pool and WriteTx both satisfy it) |
| `ingest.applyInventory`, `ingest.applyInterfaceSnapshot` | `*sql.Tx` | `store.WriteTx` |
| events `INSERT OR IGNORE`, admission `UPDATE agents SET high_sequence` | `*sql.Tx` | `store.WriteTx` |
| `fault.EvaluateAgentTx` / `EvaluateHostTx`, `gamedata.Apply`, `incidentops.IngestTracesTx` / `IngestScenesTx`, `metrics.RewindForBatch` | `*sql.Tx` | **unchanged** — called through `DB.SQLiteTx` inside `Ingest`; they migrate in CLOUD-015 |
| `ingest.TouchAgentTx` (wired to `registry.TouchLastSeenTx` from `server.Start`) | `*sql.Tx` | **unchanged by design** — migrating it ripples into registry, out of scope for this slice |

## Remaining call sites (尚未迁移清单)

Owner column: **014B** = migrate the package onto the contract in a later
slice; **015** = the PostgreSQL-adapter milestone (dialect-flag SQL, RLS,
`SQLiteTx` seam removal). "Owns a tx" = the function opens/commits/rollbacks a
transaction itself; "consumes `*sql.Tx`" = the function receives one from an
owner.

### baseline

| Function | Kind | Owner |
| --- | --- | --- |
| `foldBatch`, `Prune` | owns a tx (`db.BeginTx`) | 014B |
| `foldOne`, `foldBucket` | consume `*sql.Tx` | 014B |
| `Bands` (and the rest of the read surface) | read pool (`db.Read()`) | 014B |

### cleanup

| Function | Kind | Owner |
| --- | --- | --- |
| `runner.markDone`, `runner.markFailed`, `CreateJob` | own a tx | 014B |
| service read paths | read pool | 014B |

### config

| Function | Kind | Owner |
| --- | --- | --- |
| `CreateGroup`, `UpdateGroup`, `DeleteGroup`, `SetSiteTargets`, `UpdateDetectionSettings`, `inGameTx` (+ its 4 closures), `UpdateHostDetection`, `UpdateProxy`, `DeleteProxy` | own a tx | 014B |
| `TerminateForTargetsTx`, `TerminateForGroupTx`, `ClearDetectorStateTx` (delegates to fault) | consume `*sql.Tx` | 014B |
| detection/gameprofiles/hostdetection read paths | read pool | 014B |

### fault

| Function | Kind | Owner |
| --- | --- | --- |
| `OpenAgentSignal`, `ResolveAgentSignal`, `RecomputeOpenAttributions`, `terminate` (+ its `extra func(*sql.Tx) error` hook) | own a tx | 014B |
| ~50 functions across `engine.go` (`EvaluateAgentTx`, detector/signal/incident helpers), `host.go` (`EvaluateHostTx` + helpers), `degradation.go`, `fluctuation.go`, `attribution.go`, `terminate.go`, `notify.go` | consume `*sql.Tx` | 014B |
| signal/fluctuation read paths | read pool | 014B |

### gamedata

| Function | Kind | Owner |
| --- | --- | --- |
| `DeleteRun` | owns a tx | 014B |
| `Apply`, `agentPermissions`, `upsertRun`, `ownedRuns`, `insertBucket`, `ownedGapRuns`, `upsertGap`, `insertHostSecond`, `writeAggregates` | consume `*sql.Tx` | 014B |
| `read.go` queries | read pool (one opens a read tx) | 014B |

### identity

| Function | Kind | Owner |
| --- | --- | --- |
| `setPassword`, `ResetAdminPassword`, `LoginSession` | own a tx | 014B |

### incidentops

| Function | Kind | Owner |
| --- | --- | --- |
| `claimScenes`, `fileReconciledScene`, `claimTraces` | own a tx | 014B |
| `IngestScenesTx` / `IngestTracesTx` + scene/trace/snapshot helpers | consume `*sql.Tx` | 015 (called via `SQLiteTx` from ingest today) |

### ingest

| Function | Kind | Owner |
| --- | --- | --- |
| `TouchAgentTx` field (→ `registry.TouchLastSeenTx`) | consumes `*sql.Tx` | 015 — deliberately kept this slice (ripples into registry) |

### metrics

| Function | Kind | Owner |
| --- | --- | --- |
| `rollupTier` (two tx sites) | owns a tx | 014B |
| `RewindForBatch`, `rewindRollups` | consume `*sql.Tx` | 015 (called via `SQLiteTx` from ingest today) |

### notifypolicy

| Function | Kind | Owner |
| --- | --- | --- |
| `AttachChannelToBuiltins` | owns a tx | 014B |
| `PlanOpenTx`, `EscalateTx`, `ResolveTx`, `RecomputeTx`, `insertDeliver*`, storm helpers | consume `*sql.Tx` | 014B (called from fault's tx) |

### opissue

| Function | Kind | Owner |
| --- | --- | --- |
| `ApplyMonitorStatus`, `ReevaluateHostMonitors`, `ReconcileScope`, `PredictProbeMonitors`, `PredictProbeMonitorsForAgent` | own a tx | 014B |
| `hostRequired`, `scopedAgents`, `upsertIssue`, `resolve*`, `upsert*Status`, `deleteAbsentProbeStatus`, `probeMonitorSerials` | consume `*sql.Tx` | 014B |

### registry

| Function | Kind | Owner |
| --- | --- | --- |
| `CreateReinstallToken`, `Enroll`, `UpdateGroup`, `DeleteGroup`, `DeleteAgent` | own a tx | 014B |
| `reenrollAgent`, `TouchLastSeenTx` | consume `*sql.Tx` | 014B (TouchLastSeenTx blocks the ingest TouchAgentTx migration — do both together) |

### statuspage

| Function | Kind | Owner |
| --- | --- | --- |
| `inTx` (shared owner), `PublicIncidentHistory`, `resolveWithSelection` | own a tx | 014B |
| `loadPublicIncidentSubjects`, `clearHome`, `ensureSlugFree`, `replaceMembers` (+ closures) | consume `*sql.Tx` | 014B |

### targetstatus

| Function | Kind | Owner |
| --- | --- | --- |
| `SiteStatuses` | owns a **read** tx (`db.Read().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})`) — the pre-contract read-tx precedent; fold into `DB.ReadTx` | 014B |
| `loadTargets`, `loadApplicablePairs`, `loadMonitorStatus`, `loadLatestSamples`, `loadDetectorState`, `loadFiringSignals` | consume `*sql.Tx` | 014B |

### Not tx-shaped but dialect-bound (015)

Everything above still speaks SQLite SQL. The dialect surface is narrow and
enumerable — `?` placeholders (covered by `Dialect.Rebind`), `INSERT OR
IGNORE`, `ON CONFLICT … DO UPDATE`, no RETURNING, JSON marshalled in Go, times
as strings/ints. Any statement needing more than Rebind (upsert syntax,
RETURNING, JSON operators) gets one explicit implementation per dialect behind
a repository interface — no ORM, no inline dialect branching. The `SQLiteTx`
seam is removed when the last `*sql.Tx` consumer above migrates; `db.BeginTx`
owners become `DB.WriteTx` callers as their slices land.

## Constraints observed

- `store.Open(path)` behavior stays byte-identical; it remains the
  compatibility opener for `server`/`desktop`.
- `store/migrations/0001_init.sql` is shipped; never edited.
- Per-row tenant enforcement (RLS) does not exist here; the scope field is
  carried for assertion and future adapters, and repositories must not use it
  as a filter.
- The commit-error arm of `DB.WriteTx` is hard to exercise against SQLite (no
  deferred constraints; statement errors surface inside fn). `contract_test.go`
  simulates it by rolling back the underlying tx so `Commit` fails with
  `sql.ErrTxDone`, and documents what that does and does not cover.
