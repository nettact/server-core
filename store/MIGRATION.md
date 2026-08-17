# Store contract migration ledger (CLOUD-014A → CLOUD-015)

Internal working document for the Scope/Executor/WriteTx store-contract
migration. Tracks which call sites speak the new contract, which still speak
raw `*sql.Tx` / `*store.DB`, and who owns closing each gap.

## What shipped

- **CLOUD-014A** — `store/contract.go` (`Scope`, `Dialect`, `Executor`,
  `WriteTx`), the SQLite adapter (`store/tx.go`), `DB.WriteTx`/`DB.ReadTx`,
  the `SQLiteTx` migration seam, and the ingest vertical slice.
- **CLOUD-015** — the ingest transaction core extracted as
  `ingest.Prepare`/`ApplyPacketTx`/`Commit` (ingest/apply.go) so a Cloud
  state consumer runs the same domain logic inside a PostgreSQL tenant
  transaction; the **`SQLiteTx` seam is DELETED** (the scope-bypass it
  enabled no longer exists); `store.AdaptTx` added as the safe,
  owner-side direction (`*sql.Tx` → `WriteTx`) for the tx owners still on
  this ledger and for tests; `store.WriteTx` extended with `PrepareContext`
  (the rewind's prepared UPDATE).

## Migrated in CLOUD-015 (the ingest transaction slice)

| Site | Before | After |
| --- | --- | --- |
| `ingest.Ingest` | single function: prepare + `WriteTx` + post closure | three phases: `Prepare` (pre-tx) → `ApplyPacketTx` (tx core, no commit/rollback/conn/network) → `Commit` (post-commit executor); `Ingest` = wiring of the three, external behavior byte-identical (characterization suite) |
| `ingest.Evaluator` (`fault.EvaluateAgentTx`/`EvaluateHostTx`) | `*sql.Tx` via `SQLiteTx` | `store.WriteTx` |
| `ingest.AgentEvidence` (`incidentops.IngestTracesTx`/`IngestScenesTx`) | `*sql.Tx` via `SQLiteTx` | `store.WriteTx` |
| `ingest.TouchAgentTx` (→ `registry.TouchLastSeenTx`) | `*sql.Tx` via `SQLiteTx` | `store.WriteTx`; `server.Start` wiring assignment unchanged |
| `gamedata.Apply` | `*sql.Tx` | `store.WriteTx` |
| `metrics.RewindForBatch` / `rewindRollups` | `*sql.Tx` | `store.WriteTx` (the rewind's prepared UPDATE rides the new `WriteTx.PrepareContext`) |
| fault engine/host/degradation/fluctuation/attribution/notify helpers (~45 functions), `Planner` + `SnapshotWriter` interfaces | `*sql.Tx` | `store.Executor` (reachable from both the ingest WriteTx and the remaining `*sql.Tx` owners; `*sql.Tx` satisfies Executor by the compile-time pin) |
| notifypolicy `PlanOpenTx`/`EscalateTx`/`ResolveTx`/`RecomputeTx` + storm/deliver helpers | `*sql.Tx` | `store.Executor` (called from fault's Planner interface, both paths) |
| incidentops scene/trace/snapshot helpers, `WriteIncidentBase` | `*sql.Tx` | `store.Executor` |
| gamedata helpers (`agentPermissions`, `upsertRun`, `ownedRuns`, `insertBucket`, `ownedGapRuns`, `upsertGap`, `insertHostSecond`, `writeAggregates`) | `*sql.Tx` | `store.Executor` |
| `fault.RecomputeAttributionTx`, `fault.AddTimelineTx` | `*sql.Tx` | `store.Executor` (called from incidentops and notifypolicy with both tx kinds) |
| `fault.TerminateForTargetsTx` / `TerminateForGroupTx` / `ClearDetectorStateTx` | `*sql.Tx` | **kept `*sql.Tx` by design** — the config-change path, not the ingest slice; they implement `config.FaultTerminator` and migrate with config's tx owners (below). Their internal helpers (`terminateTx`, `terminationPub`, …) are Executor-typed so both directions compile. |
| `store.DB.SQLiteTx` bridge + its tests | present | **deleted**; its commit-error test moved to `store/tx_internal_test.go` (package-internal, reaches the adapter directly) |
| `store.WriteTx` | ExecContext/QueryContext/QueryRowContext/Dialect/Scope | + `PrepareContext` (additive; trivial for the SQLite adapter) |
| `store.AdaptTx(tx *sql.Tx, s Scope) WriteTx` | — | **added**: the safe seam for owners still on BeginTx and for tests; deliberately one-directional |

## Remaining call sites (014B)

Owner column: **014B** = migrate the package onto the contract (tx owners
move to `DB.WriteTx`; their remaining `*sql.Tx` consumers follow). "Owns a
tx" = the function opens/commits/rollbacks a transaction itself; "consumes
`*sql.Tx`" = the function receives one from an owner.

### Write owners first — and why the target is `DB.WriteTx`, not `AdaptTx`

Root `adr/0004` **SC-8** names `AdaptTx` an honest residue: the scope is
**self-reported by the owner** and the contract layer cannot check it. It also
rules out the tempting backstop — if a request belonging to tenant A is wrapped
in a `Scope` for tenant B, SC-6 sets `app.tenant_id` to B and RLS *correctly*
authorizes B's rows; the database holds no Principal and cannot see the
mismatch. RLS defends against "the SQL forgot `WHERE tenant_id`", **not**
against "the scope argument was wrong". SC-8's conclusion is that closing this
ledger is the *only* real mitigation.

Two consequences for how the remaining rows get cleared:

1. **Wrapping an owner's `*sql.Tx` in `AdaptTx` does not clear its row.** That
   keeps the self-reported scope and merely changes its spelling. A row is done
   when the owner calls `DB.WriteTx`, which validates the scope *before* the
   connection is touched.
2. **Write owners are the priority; read-pool rows are not on the SC-8 path.**
   `AdaptTx` is a write-side seam, so read paths carry no equivalent trust gap.
   They still move to `DB.ReadTx` for scope-carrying uniformity, but clearing
   them buys no SC-8 mitigation and should not be confused with it.

**Progress (W2-02):** `gamedata` and `identity` are clear (0 `BeginTx`
outside tests). Remaining non-test `BeginTx` sites by package: baseline 2,
cleanup 3, config 9, fault 4, incidentops 3, metrics 2, notifypolicy 1,
opissue 5, registry 5, statuspage 3, targetstatus 1.

### baseline

| Function | Kind | Owner |
| --- | --- | --- |
| `foldBatch`, `Prune` | own a tx (`db.BeginTx`) | 014B |
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
| `OpenAgentSignal`, `ResolveAgentSignal`, `RecomputeOpenAttributions`, `terminate` (+ its `extra func(*sql.Tx) error` hook) | own a tx | 014B — wrap the tx with `store.AdaptTx` or move to `DB.WriteTx` |
| `TerminateForTargetsTx`, `TerminateForGroupTx`, `ClearDetectorStateTx` | consume `*sql.Tx` | 014B (with config — they implement `config.FaultTerminator`) |
| signal/fluctuation read paths | read pool | 014B |

### gamedata

| Function | Kind | Owner |
| --- | --- | --- |
| `DeleteRun` | owns a tx | **done (W2-02)** — `DB.WriteTx` + `store.Standalone()`. Returning `ErrNotFound` from `fn` rolls back exactly as the pre-contract fall-through-to-deferred-`Rollback` did, and `WriteTx` propagates `fn`'s error unwrapped so callers' `errors.Is(err, ErrNotFound)` is unchanged |
| `read.go` queries | read pool | 014B — read paths only; no `AdaptTx` seam on this side (see "Write owners first") |

### identity

| Function | Kind | Owner |
| --- | --- | --- |
| `setPassword`, `ResetAdminPassword`, `LoginSession` | own a tx | **done (W2-02)** — all three on `DB.WriteTx` + `store.Standalone()`; zero `BeginTx` left in the package. `LoginSession`'s session id/expiry are minted *before* the transaction so the values returned to the caller are the committed ones; `ResetAdminPassword` closes over `username` for the same reason |

### incidentops

| Function | Kind | Owner |
| --- | --- | --- |
| `claimScenes`, `fileReconciledScene`, `claimTraces` | own a tx | 014B |

### metrics

| Function | Kind | Owner |
| --- | --- | --- |
| `rollupTier` (two tx sites) | owns a tx | 014B |

### notifypolicy

| Function | Kind | Owner |
| --- | --- | --- |
| `AttachChannelToBuiltins` | owns a tx | 014B |

### opissue

| Function | Kind | Owner |
| --- | --- | --- |
| `ApplyMonitorStatus`, `ReevaluateHostMonitors`, `ReconcileScope`, `PredictProbeMonitors`, `PredictProbeMonitorsForAgent` | own a tx | 014B |
| `hostRequired`, `scopedAgents`, `upsertIssue`, `resolve*`, `upsert*Status`, `deleteAbsentProbeStatus`, `probeMonitorSerials` | consume `*sql.Tx` | 014B |

### registry

| Function | Kind | Owner |
| --- | --- | --- |
| `CreateReinstallToken`, `Enroll`, `UpdateGroup`, `DeleteGroup`, `DeleteAgent` | own a tx | 014B |
| `reenrollAgent` | consume `*sql.Tx` | 014B |

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

### Not tx-shaped but dialect-bound (PostgreSQL adapter milestone)

Everything above still speaks SQLite SQL. The dialect surface is narrow and
enumerable — `?` placeholders (covered by `Dialect.Rebind`), `INSERT OR
IGNORE`, `ON CONFLICT … DO UPDATE`, no RETURNING, JSON marshalled in Go, times
as strings/ints. Any statement needing more than Rebind (upsert syntax,
RETURNING, JSON operators) gets one explicit implementation per dialect behind
a repository interface — no ORM, no inline dialect branching. The removed
`SQLiteTx` seam was the last way to reach a raw handle out of a WriteTx;
`AdaptTx` is the only remaining bridge and points the other way.

## Constraints observed

- `store.Open(path)` behavior stays byte-identical; it remains the
  compatibility opener for `server`/`desktop`.
- `store/migrations/0001_init.sql` is shipped; never edited.
- Per-row tenant enforcement (RLS) does not exist here; the scope field is
  carried for assertion and future adapters, and repositories must not use it
  as a filter. `ingest.ApplyPacketTx` fails closed when the call's scope does
  not validate or does not match the transaction's own scope.
- The commit-error arm of `DB.WriteTx` is hard to exercise against SQLite (no
  deferred constraints; statement errors surface inside fn).
  `store/tx_internal_test.go` simulates it by rolling back the underlying tx
  so `Commit` fails with `sql.ErrTxDone`, and documents what that does and
  does not cover.
