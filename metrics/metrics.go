// Package metrics is the time-series layer: the SQLite series dictionary, the
// in-memory latest-value cache, the query planner, and the rollup/purge
// bookkeeping — while the sample data itself lives in the tsstore data plane
// (embedded Prometheus TSDB instances; see package tsstore for why SQLite
// stopped holding it: per-series B-tree tail pages made every 30s packet
// commit rewrite ~2.6KB per stored float). What stays relational stays here:
// series identity, rollup_state watermarks, and everything reads need to
// resolve WHICH series to fetch before touching the data plane.
//
// Series are keyed by (agent, monitor, kind, target, config_serial): monitor_id is
// the user-created monitor (probe_tasks.id) stamped by the agent, and config_serial
// is the target's material generation, so a material edit starts a fresh series and
// old-generation samples never surface as current. System metrics (host.*,
// iface.up, agent.*) carry monitor_id ” and generation 0.
//
// Hot reads (the /latest snapshot and rule evaluation, which runs on every
// ingest) are served from an in-memory latest-value cache updated at ingest —
// no storage reads on those paths after the per-agent warm-up.
package metrics

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/tsstore"
)

// seriesIdent is the in-memory identity of one series row. config_serial is part
// of the identity: a material target edit starts a new generation (new series id)
// even when kind/target/params coincide textually, so old-generation samples
// never surface as current.
type seriesIdent struct {
	id           int64
	monitorID    string
	kind         string
	target       string
	layer        string
	unit         string
	configSerial int
	purgeCutoff  int64 // series.purge_cutoff; reads clamp below it
}

type latestVal struct {
	ts    int64 // unix seconds
	value float64
}

type Store struct {
	db *store.DB
	ts tsstore.SeriesStore

	mu      sync.Mutex
	cache   map[string]int64                  // seriesKey -> series id
	byAgent map[string]map[int64]*seriesIdent // agent -> its series identities
	latest  map[int64]latestVal               // series id -> newest sample
	warmed  map[string]bool                   // agent -> identities+latest loaded from DB
	purged  map[int64]purgeWindow             // series id -> last purged range; see UpdateLatest
	// retention is the window set the data plane drops blocks by, kept here so
	// reads can tell which tier still holds a given moment. It is the same value
	// the host derived tsstore.Config from; SetRetention exists so a host that
	// configures non-default windows keeps the two in agreement.
	retention RetentionConfig

	// rollupMu serializes every bucket-affecting operation: the rollup pass,
	// PurgeRange, PurgeSeriesIDs and full-history clears. The k-encoded repair
	// protocol (read window max ms → SQLite watermark rewind → append → CAS)
	// is a multi-step exchange across two stores; interleaving two of them on
	// one (tier, sid) can allocate the same k twice or cascade a rewind that a
	// concurrent pass immediately re-advances past.
	rollupMu sync.Mutex

	// pendingAppend marks series whose ingest transaction has COMMITTED (the
	// rollup_state rewind is durable) but whose raw samples have not yet
	// reached the data plane — AppendRaw runs after the SQLite commit. The
	// rollup pass skips marked series: recomputing in that gap would consume
	// the rewind, advance the watermark past the still-in-flight samples, and
	// silently exclude them from every tier forever. Entries are cleared once
	// AppendRaw returns; a crash clears them trivially (process state) while
	// the durable rewind makes the next pass recompute — the unchanged-guard
	// then absorbs it. Guarded by pendingMu (not mu: ingest holds it across a
	// data-plane write and must not block cache reads).
	//
	// pendingTickets is the same set keyed by an issue order, for the OTHER
	// waiter: a purge. Prometheus clamps a tombstone to the samples a series
	// actually holds when Delete runs (Head.Delete → clampInterval against the
	// series' current min/max), so a sample appended afterwards INSIDE the
	// requested range is not masked by it — it survives a delete that reported
	// success. A purge therefore has to let already-committed batches land
	// first. Waiting on the ticket numbers outstanding at entry (rather than on
	// the set being empty) makes that wait finite: batches arriving during the
	// wait get higher tickets and are none of this purge's business.
	pendingMu      sync.Mutex
	pendingCond    *sync.Cond // on pendingMu; broadcast when a ticket retires
	pendingAppend  map[int64]int
	pendingTickets map[uint64]struct{}
	nextTicket     uint64
}

// purgeWindow is a deleted [from, to) sample range. An UpdateLatest fold whose
// ts lands inside it may belong to a batch that committed BEFORE the purge ran
// (the rows are gone), so such folds re-verify against the data plane instead
// of resurrecting deleted samples in the latest cache. until bounds the guard
// in wall-clock time; it is stamped when PurgeRange RELEASES s.mu (not when
// the window is recorded), so a fold that spent an arbitrarily long purge
// blocked on the mutex still finds a live guard. Only folds already in flight
// at purge time can race, and those land within milliseconds of the unlock, so
// entries expire quickly instead of forcing storage reads forever (a
// full-history purge has to==maxTS). Expired entries are swept by the next
// fold or purge.
type purgeWindow struct{ from, to, until int64 }

// purgeGuardSeconds is how long a purge window keeps guarding folds. Generous
// versus the actual commit→fold gap (milliseconds) yet short enough that the
// hot ingest path returns to pure cache hits almost immediately.
const purgeGuardSeconds = 30

func New(db *store.DB, ts tsstore.SeriesStore) *Store {
	s := &Store{
		db:             db,
		ts:             ts,
		cache:          make(map[string]int64),
		byAgent:        make(map[string]map[int64]*seriesIdent),
		latest:         make(map[int64]latestVal),
		warmed:         make(map[string]bool),
		purged:         make(map[int64]purgeWindow),
		pendingAppend:  make(map[int64]int),
		pendingTickets: make(map[uint64]struct{}),
		retention:      DefaultRetention(),
	}
	s.pendingCond = sync.NewCond(&s.pendingMu)
	return s
}

// SetRetention tells reads which windows the pruner is actually deleting by.
// Hosts that leave retention at the defaults need not call it — New starts from
// the same DefaultRetention the pruner falls back to. A host that CONFIGURES
// retention must, or the reader would keep selecting a tier the pruner empties
// on a schedule the reader does not know about. Call it at startup, before
// serving.
func (s *Store) SetRetention(cfg RetentionConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retention = cfg
}

// retentionCfg reads the configured windows under the lock.
func (s *Store) retentionCfg() RetentionConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retention
}

func seriesKey(agentID, monitorID, kind, target string, configSerial int) string {
	return agentID + "\x1f" + monitorID + "\x1f" + kind + "\x1f" + target + "\x1f" + strconv.Itoa(configSerial)
}

// registerLocked adds a series identity to the in-memory registry. Caller holds s.mu.
func (s *Store) registerLocked(agentID string, ident *seriesIdent) {
	s.cache[seriesKey(agentID, ident.monitorID, ident.kind, ident.target, ident.configSerial)] = ident.id
	ag := s.byAgent[agentID]
	if ag == nil {
		ag = make(map[int64]*seriesIdent)
		s.byAgent[agentID] = ag
	}
	ag[ident.id] = ident
}

// warmAgentLocked loads an agent's series identities and each one's newest
// sample from the DB, once per process lifetime. In-memory latest values that
// are already newer (samples ingested since startup) are kept. Caller holds s.mu.
func (s *Store) warmAgentLocked(ctx context.Context, agentID string) error {
	if s.warmed[agentID] {
		return nil
	}
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, COALESCE(monitor_id,''), kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,''), config_serial, purge_cutoff
		FROM series WHERE agent_id=?`, agentID)
	if err != nil {
		return err
	}
	var idents []*seriesIdent
	for rows.Next() {
		var si seriesIdent
		if err := rows.Scan(&si.id, &si.monitorID, &si.kind, &si.target, &si.layer, &si.unit, &si.configSerial, &si.purgeCutoff); err != nil {
			rows.Close()
			return err
		}
		idents = append(idents, &si)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, si := range idents {
		s.registerLocked(agentID, si)
	}
	// One bulk read resolves every series' newest sample; in-memory values that
	// are already newer (ingested since startup) are kept. The lower bound is
	// the raw tier's LOGICAL window — anything older would not be served as
	// "current" anyway — raised to the series' own purge cutoff where one is set.
	// RawSeconds==0 means keep forever, so the bound must be 0 (unbounded), not
	// now: subtracting zero would put the floor at the present instant and skip
	// every pre-restart sample, leaving latest and target status on no_data
	// until the next packet arrives.
	var bound int64
	if s.retention.RawSeconds > 0 {
		bound = time.Now().Unix() - s.retention.RawSeconds
	}
	var missing []int64
	for _, si := range idents {
		if _, ok := s.latest[si.id]; ok {
			continue
		}
		if si.purgeCutoff > bound {
			one, err := s.ts.RawLatest(ctx, []int64{si.id}, si.purgeCutoff)
			if err != nil {
				return err
			}
			if smp, ok := one[si.id]; ok {
				s.latest[si.id] = latestVal{ts: smp.TS, value: smp.Value}
			}
			continue
		}
		missing = append(missing, si.id)
	}
	if len(missing) > 0 {
		latest, err := s.ts.RawLatest(ctx, missing, bound)
		if err != nil {
			return err
		}
		for id, smp := range latest {
			s.latest[id] = latestVal{ts: smp.TS, value: smp.Value}
		}
	}
	s.warmed[agentID] = true
	return nil
}

// EnsureSeries resolves (creating if needed) the series id for every metric,
// returning a key→id map. Each series is keyed by the metric's ConfigSerial (the
// target generation ingest has already verified equals the target's current
// serial), so a material edit lands in a fresh series. System metrics carry
// serial 0. It runs on the write DB directly (autocommit) and MUST be called
// before opening the ingest transaction.
func (s *Store) EnsureSeries(ctx context.Context, agentID, siteID string, ms []telemetry.Metric) (map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string]int64, len(ms))
	for i := range ms {
		m := &ms[i]
		key := seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial)
		if _, ok := out[key]; ok {
			continue
		}
		if id, ok := s.cache[key]; ok {
			out[key] = id
			continue
		}
		if _, err := s.db.ExecContext(ctx, `
			INSERT OR IGNORE INTO series(agent_id, site_id, monitor_id, kind, target, layer, unit, config_serial)
			VALUES(?,?,?,?,?,?,?,?)`, agentID, siteID, m.MonitorID, string(m.Kind), m.Target, string(m.Layer), m.Unit, m.ConfigSerial); err != nil {
			return nil, err
		}
		var id int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT id FROM series WHERE agent_id=? AND monitor_id=? AND kind=? AND target=? AND config_serial=?`,
			agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial).Scan(&id); err != nil {
			return nil, err
		}
		s.registerLocked(agentID, &seriesIdent{
			id: id, monitorID: m.MonitorID, kind: string(m.Kind), target: m.Target,
			layer: string(m.Layer), unit: m.Unit, configSerial: m.ConfigSerial,
		})
		out[key] = id
	}
	return out, nil
}

// RewindForBatch runs inside the ingest transaction where InsertSamples used
// to: samples now reach the data plane AFTER this transaction commits (see
// ingest's ordering), so the 1m watermark rewind — the durable intent that
// makes a backfilled range get re-aggregated — is computed from the WHOLE
// batch rather than from "rows that actually landed". The loosening is
// deliberate and cheap: a replayed old packet may issue a rewind whose
// recompute finds nothing changed, and the rollup upsert's unchanged-guard
// then writes nothing. ids comes from EnsureSeries.
func (s *Store) RewindForBatch(ctx context.Context, tx store.WriteTx, agentID string, ids map[string]int64, ms []telemetry.Metric) error {
	oldest := make(map[int64]int64, len(ids))
	for i := range ms {
		m := &ms[i]
		id, ok := ids[seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial)]
		if !ok {
			continue
		}
		ts := m.TS.Unix()
		if cur, ok := oldest[id]; !ok || ts < cur {
			oldest[id] = ts
		}
	}
	return rewindRollups(ctx, tx, oldest)
}

// AppendRawSamples writes a committed batch's samples to the data plane —
// ingest calls it AFTER its SQLite transaction commits (see the ordering
// rationale there). The conversion mirrors RewindForBatch's key lookup so the
// two can never disagree about which series a metric lands in.
func (s *Store) AppendRawSamples(ctx context.Context, agentID string, ids map[string]int64, ms []telemetry.Metric) (tsstore.AppendResult, error) {
	raws := make([]tsstore.RawSample, 0, len(ms))
	for i := range ms {
		m := &ms[i]
		id, ok := ids[seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial)]
		if !ok {
			continue
		}
		raws = append(raws, tsstore.RawSample{SID: id, TS: m.TS.Unix(), Value: m.Value})
	}
	return s.ts.AppendRaw(ctx, raws)
}

// BeginPendingAppend marks the batch's series as having a committed rewind
// whose raw samples are still in flight to the data plane; the rollup pass
// skips them until the returned done() runs (after AppendRaw). See the
// pendingAppend field comment for why the gap matters.
func (s *Store) BeginPendingAppend(ids map[string]int64) (done func()) {
	s.pendingMu.Lock()
	ticket := s.nextTicket
	s.nextTicket++
	s.pendingTickets[ticket] = struct{}{}
	for _, id := range ids {
		s.pendingAppend[id]++
	}
	s.pendingMu.Unlock()
	return func() {
		s.pendingMu.Lock()
		delete(s.pendingTickets, ticket)
		for _, id := range ids {
			if s.pendingAppend[id] <= 1 {
				delete(s.pendingAppend, id)
			} else {
				s.pendingAppend[id]--
			}
		}
		s.pendingCond.Broadcast()
		s.pendingMu.Unlock()
	}
}

// waitForPendingAppends blocks until every append that had already been issued
// when it was called has reached the data plane. A purge calls it before
// computing tombstones: a batch whose SQLite transaction committed before the
// purge began must be visible to Delete, or the tombstone gets clamped short of
// it and the sample survives the purge (see pendingTickets).
//
// Only tickets issued before this call are waited on, so a steady ingest stream
// cannot starve the purge.
func (s *Store) waitForPendingAppends() {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	cutoff := s.nextTicket
	for {
		outstanding := false
		for t := range s.pendingTickets {
			if t < cutoff {
				outstanding = true
				break
			}
		}
		if !outstanding {
			return
		}
		s.pendingCond.Wait()
	}
}

func (s *Store) isPendingAppend(id int64) bool {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return s.pendingAppend[id] > 0
}

// rewindRollups pulls a series' 1m rollup watermark back behind any sample that
// arrived from the past — an offline agent draining hours of WAL backlog. The
// watermarks advance with wall time whether or not a series receives anything,
// and each pass re-reads only rollupOverlap behind them, so backlog inserted
// below that line would otherwise NEVER be aggregated: invisible to every chart
// wider than the raw tier and to the availability math, and deleted with the
// raw tier two days later.
//
// ONLY the 1m tier is rewound here, deliberately. It is the only tier that reads
// raw samples, so it is the only one this function can speak for; 1h and 1d are
// dragged down by the tier below them, inside the transaction that writes the
// repair (rollupBatch's cascade). Rewinding all three from here instead looks
// equivalent and is not: a rollup pass already in flight has snapshotted the
// coarse watermarks, and would write them forward again over this rewind — the
// repair would be lost with nothing left to re-trigger it.
//
// This runs on the hot ingest path, so the cost matters: live samples sit AHEAD
// of the watermark (rollup lags the present by up to its cadence, and the
// overlap absorbs ordinary upload jitter), so for them the guarded UPDATE
// matches nothing and dirties no page. Only a genuine backfill writes, and then
// only one small rollup_state row per affected series.
func rewindRollups(ctx context.Context, tx store.WriteTx, oldest map[int64]int64) error {
	if len(oldest) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		UPDATE rollup_state SET last_ts=? WHERE resolution='1m' AND series_id=? AND last_ts > ? + `+
		strconv.Itoa(rollupOverlap))
	if err != nil {
		return err
	}
	defer stmt.Close()
	for id, ts := range oldest {
		if _, err := stmt.ExecContext(ctx, ts, id, ts); err != nil {
			return err
		}
	}
	return nil
}

// UpdateLatest folds a committed batch into the in-memory latest cache. Call
// after the ingest transaction commits.
//
// Purge interleaving: ingest can commit its tx, then lose the race for s.mu to
// a PurgeRange that deletes the just-committed rows — after which this fold
// would resurrect a deleted sample as "latest". PurgeRange records the window
// it deleted; any fold whose ts lands inside that window re-reads the actual
// newest row from the DB instead of trusting the batch value. If that re-read
// fails the cache entry is evicted (not left stale): the next reader misses the
// cache and the next successful fold or warm-up repopulates it — a deleted
// sample must never be served as current.
func (s *Store) UpdateLatest(agentID string, ids map[string]int64, ms []telemetry.Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range ms {
		m := &ms[i]
		id, ok := ids[seriesKey(agentID, m.MonitorID, string(m.Kind), m.Target, m.ConfigSerial)]
		if !ok {
			continue
		}
		ts := m.TS.Unix()
		if w, purgedOK := s.purged[id]; purgedOK {
			if time.Now().Unix() > w.until {
				delete(s.purged, id) // guard expired; no racing fold can remain in flight
			} else if ts >= w.from && ts < w.to {
				if err := s.refreshLatestLocked(context.Background(), id); err != nil {
					delete(s.latest, id) // never risk serving the purged value; next fold repopulates
				}
				continue
			}
		}
		if cur, ok := s.latest[id]; !ok || ts >= cur.ts {
			s.latest[id] = latestVal{ts: ts, value: m.Value}
		}
	}
}

// LatestSample is one cached newest observation, as served to targetstatus.
type LatestSample struct {
	TS    int64
	Value float64
}

// LatestForSeries returns the cached newest sample per series id, warming each
// named agent's cache first. A series with no cached value (nothing ingested,
// or everything hidden behind its purge cutoff) is absent from the map — the
// caller's honest no_data.
func (s *Store) LatestForSeries(ctx context.Context, agentIDs []string, ids []int64) (map[int64]LatestSample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range agentIDs {
		if err := s.warmAgentLocked(ctx, a); err != nil {
			return nil, err
		}
	}
	out := make(map[int64]LatestSample, len(ids))
	for _, id := range ids {
		if lv, ok := s.latest[id]; ok {
			out[id] = LatestSample{TS: lv.ts, Value: lv.value}
		}
	}
	return out, nil
}

// refreshLatestLocked re-reads a series' newest surviving sample from the data
// plane into the latest cache (tombstones are applied at read time there, and
// the purge cutoff clamps a full-history clear), or evicts the entry when none
// remain. Caller holds s.mu and decides how to handle a read failure.
func (s *Store) refreshLatestLocked(ctx context.Context, id int64) error {
	var cutoff int64
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT purge_cutoff FROM series WHERE id=?`, id).Scan(&cutoff); err != nil && err != sql.ErrNoRows {
		return err
	}
	latest, err := s.ts.RawLatest(ctx, []int64{id}, cutoff)
	if err != nil {
		return err
	}
	if smp, ok := latest[id]; ok {
		s.latest[id] = latestVal{ts: smp.TS, value: smp.Value}
	} else {
		delete(s.latest, id)
	}
	return nil
}

// Point is a returned time-series point.
type Point struct {
	TS        time.Time `json:"ts"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Layer     string    `json:"layer"`
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"`
	MonitorID string    `json:"monitor_id,omitempty"`
}

// Query filters a read. SinceUnix=0 defaults to the last 2h.
//
// UntilUnix bounds the window at the top (inclusive); 0 or any value at/after
// now means "up to now", which is the unbounded behavior. It is not merely a
// filter: the resolution tier is chosen from the window's SIZE, so without an
// upper bound every window reaches now and a two-hour slice of a five-day-old
// session is served from the daily rollups — coarse buckets that describe days
// the caller did not ask about. Bounding the window is what lets a historical
// range be read at the same resolution a live one would be.
type Query struct {
	AgentID   string
	Kind      string
	Target    string // optional; empty = all targets for the kind
	MonitorID string // optional; set = only that monitor's series
	SinceUnix int64
	UntilUnix int64
	Limit     int
}

// tierLadder is the resolution ladder, finest first. Selection only ever moves
// DOWN it (coarser), so "the finest tier that still works" is one pass.
var tierLadder = []struct {
	table string
	raw   bool
}{
	{"samples", true},
	{"rollup_1m", false},
	{"rollup_1h", false},
	{"rollup_1d", false},
}

// pickTier chooses a resolution table for a range (seconds) so the point count
// stays bounded. It answers on WIDTH alone; pickTierFor adds the second half of
// the question.
func pickTier(rangeSec int64) (table string, raw bool) {
	switch {
	case rangeSec <= 2*3600:
		return "samples", true
	case rangeSec <= 2*86400:
		return "rollup_1m", false
	case rangeSec <= 90*86400:
		return "rollup_1h", false
	default:
		return "rollup_1d", false
	}
}

// pickTierFor chooses the finest tier that suits BOTH the window's width and its
// AGE: a tier whose retention no longer covers the window's start has already
// been pruned there, so reading it returns nothing.
//
// Width alone was enough while every window ended at now — a narrow window was
// necessarily recent. An upper bound breaks that: a one-hour window three days
// old is narrow enough for raw samples and older than the two days raw is kept,
// so the width-only answer is an empty chart standing next to minute rollups
// that have the data. Falling to the next coarser tier is what makes bounded
// historical reads work at all.
func pickTierFor(rangeSec, windowStart, now int64, ret RetentionConfig) (table string, raw bool) {
	start, _ := pickTier(rangeSec)
	from := 0
	for i, t := range tierLadder {
		if t.table == start {
			from = i
			break
		}
	}
	for _, t := range tierLadder[from:] {
		if ret.covers(t.table, windowStart, now) {
			return t.table, t.raw
		}
	}
	// Every tier's retention has passed the window: answer from the coarsest one,
	// which is the only place anything could still be, and let the caller see the
	// empty result honestly rather than reading a tier that certainly has nothing.
	last := tierLadder[len(tierLadder)-1]
	return last.table, last.raw
}

type seriesMeta struct {
	id          int64
	monitorID   string
	kind        string
	target      string
	layer       string
	unit        string
	purgeCutoff int64
}

// tierOf maps the ladder's table names (kept for pickTier/retention symmetry)
// onto data-plane tiers.
func tierOf(table string) tsstore.Tier {
	switch table {
	case "rollup_1m":
		return tsstore.TierM1
	case "rollup_1h":
		return tsstore.TierH1
	default:
		return tsstore.TierD1
	}
}

// Query returns points for the matching series at a resolution appropriate to
// the range. Rollup values are bucket averages (total/cnt). Runs on the read
// pool so a long chart query never stalls ingest. Series are matched across ALL
// generations (config_serial is ignored) and the merged points are ordered by
// (kind, target, monitor, ts) so history stays continuous across material edits.
//
// The window is [since, until] with both ends inclusive, and the tier follows
// its width rather than the distance to now — see Query.UntilUnix. An inverted
// window (until before since) selects nothing and is answered with no points
// rather than an error: it is an empty range, not a malformed one.
func (s *Store) Query(ctx context.Context, q Query) ([]Point, error) {
	now := time.Now().Unix()
	since := q.SinceUnix
	if since == 0 {
		since = now - 2*3600
	}
	// A bound is honored only when it is in the PAST; at or after now it is treated
	// as absent and no upper bound is applied at all.
	//
	// That is not just a shortcut for "there is nothing past now" — there is.
	// Agent device clocks run ahead of the server's, so samples arrive stamped
	// slightly (occasionally wildly) in the future, and this store deliberately
	// keeps them as history. Clamping every unbounded read to now would hide them,
	// silently changing what a live chart shows.
	until := int64(0)
	if q.UntilUnix > 0 && q.UntilUnix < now {
		until = q.UntilUnix
	}
	// The tier still follows the window's width, with a future bound contributing
	// nothing beyond now — otherwise "until = next week" would select a coarser
	// resolution than the data behind it warrants.
	tierEnd := now
	if until > 0 {
		tierEnd = until
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 1000
	}

	sqlSeries := `SELECT id, COALESCE(monitor_id,''), kind, COALESCE(target,''), COALESCE(layer,''), COALESCE(unit,''), purge_cutoff FROM series WHERE agent_id=? AND kind=?`
	args := []any{q.AgentID, q.Kind}
	if q.Target != "" {
		sqlSeries += ` AND target=?`
		args = append(args, q.Target)
	}
	if q.MonitorID != "" {
		sqlSeries += ` AND monitor_id=?`
		args = append(args, q.MonitorID)
	}
	rows, err := s.db.Read().QueryContext(ctx, sqlSeries, args...)
	if err != nil {
		return nil, err
	}
	var series []seriesMeta
	for rows.Next() {
		var m seriesMeta
		if err := rows.Scan(&m.id, &m.monitorID, &m.kind, &m.target, &m.layer, &m.unit, &m.purgeCutoff); err != nil {
			rows.Close()
			return nil, err
		}
		series = append(series, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	table, raw := pickTierFor(tierEnd-since, since, now, s.retentionCfg())
	// The interface ranges are half-open; this API's until is inclusive, so the
	// data-plane bound is until+1 (0 stays "unbounded", preserving the
	// future-samples-kept semantics above).
	untilX := int64(0)
	if until > 0 {
		untilX = until + 1
	}
	var out []Point
	for _, sm := range series {
		// A full-history clear (series.purge_cutoff) hides everything before the
		// cutoff without a single tombstone; the clamp is the entire mechanism.
		effSince := since
		if sm.purgeCutoff > effSince {
			effSince = sm.purgeCutoff
		}
		if untilX > 0 && effSince >= untilX {
			continue
		}
		if raw {
			samples, err := s.ts.RawRange(ctx, sm.id, effSince, untilX, limit)
			if err != nil {
				return nil, err
			}
			for _, smp := range samples {
				out = append(out, Point{
					TS: time.Unix(smp.TS, 0).UTC(), Kind: sm.kind, Target: sm.target,
					Layer: sm.layer, Value: smp.Value, Unit: sm.unit, MonitorID: sm.monitorID,
				})
			}
			continue
		}
		buckets, err := s.ts.ReadBuckets(ctx, tierOf(table), sm.id, effSince, untilX)
		if err != nil {
			return nil, err
		}
		if len(buckets) > limit {
			buckets = buckets[:limit] // earliest points, matching the raw branch
		}
		for _, b := range buckets {
			if b.Cnt == 0 {
				continue
			}
			out = append(out, Point{
				TS: time.Unix(b.TS, 0).UTC(), Kind: sm.kind, Target: sm.target,
				Layer: sm.layer, Value: b.Sum / float64(b.Cnt), Unit: sm.unit, MonitorID: sm.monitorID,
			})
		}
	}
	// Merge generations: same (kind, target, monitor) logical series may now span
	// several config_serial rows; order deterministically by ts within each.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		if out[i].MonitorID != out[j].MonitorID {
			return out[i].MonitorID < out[j].MonitorID
		}
		return out[i].TS.Before(out[j].TS)
	})
	return out, nil
}

// summaryDefaultWindowSec is Summarize's default window: the raw tier boundary
// (pickTier's samples cutoff), matching the status page's 2h P95 cards.
const summaryDefaultWindowSec = 2 * 3600

// summaryMaxWindowSec caps Summarize at the raw retention default (2d):
// percentiles are only meaningful over raw observations (rollups store bucket
// averages, and a percentile of averages is not a percentile of observations),
// so summaries always scan the samples table — unlike Query, which switches to
// rollups past 2h to bound the point count of its response. An aggregate
// response is a handful of numbers regardless of window, so the only cost is
// the scan itself, bounded by retention.
const summaryMaxWindowSec = 2 * 86400

// ErrSummaryWindow is returned when a Summarize window exceeds raw retention.
var ErrSummaryWindow = errors.New("metrics: summary window exceeds raw retention (2d)")

// ErrSummaryReduce is returned for an unknown SummaryQuery.Reduce mode.
var ErrSummaryReduce = errors.New("metrics: unknown summary reduce mode")

// ReduceWorstByTS collapses the merged samples to one per timestamp, keeping
// the worst (max) value across series — "how bad was the worst target each
// second". Used by the dashboard quality cards.
const ReduceWorstByTS = "worst"

// SummaryQuery asks for per-kind aggregates over a raw window. The window is a
// length, not an absolute timestamp, so validation can't race the caller's
// clock against Summarize's own time.Now.
type SummaryQuery struct {
	AgentID        string
	Kinds          []string
	MonitorID      string   // optional; set = only that monitor's series
	Target         string   // optional; set = only series for that target string
	ExcludeTargets []string // optional; series with these target strings are skipped
	Reduce         string   // "" = plain merge; ReduceWorstByTS = per-ts max across series
	WindowSeconds  int64    // 0 => 2h; must fit raw retention (≤2d)
}

// LatestPoint is the newest observation inside the window.
type LatestPoint struct {
	TS    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

// KindSummary aggregates one kind's raw samples: newest value, nearest-rank
// P95, mean, and the (post-reduce) sample count the aggregates were computed
// from. LatestNonzero is the newest sample whose value rounds to a nonzero
// integer — categorical code cards (NAT type etc.) use it to fall back past a
// transient "unknown" (code 0) probe to the most recent determinate result.
type KindSummary struct {
	Latest        *LatestPoint `json:"latest"`         // nil when no samples in window
	LatestNonzero *LatestPoint `json:"latest_nonzero"` // nil when no nonzero sample in window
	P95           *float64     `json:"p95"`            // nil when no samples in window
	Avg           *float64     `json:"avg"`            // nil when no samples in window
	Count         int          `json:"count"`
}

// Summarize computes latest/P95 per kind server-side so status cards don't pull
// the raw window into the browser. Series resolution mirrors Query — matched
// across ALL generations, merged in (target, monitor, ts) order — so the numbers
// equal what a client would compute from the same Query results. The result map
// always carries every requested kind; kinds with no samples get a zero summary.
func (s *Store) Summarize(ctx context.Context, q SummaryQuery) (map[string]KindSummary, error) {
	rangeSec := q.WindowSeconds
	if rangeSec == 0 {
		rangeSec = summaryDefaultWindowSec
	}
	if rangeSec < 0 || rangeSec > summaryMaxWindowSec {
		return nil, ErrSummaryWindow
	}
	if q.Reduce != "" && q.Reduce != ReduceWorstByTS {
		return nil, ErrSummaryReduce
	}
	excluded := make(map[string]bool, len(q.ExcludeTargets))
	for _, target := range q.ExcludeTargets {
		excluded[target] = true
	}
	since := time.Now().Unix() - rangeSec
	// The inclusive `ts >= since` predicate admits rangeSec+1 integer timestamps
	// at the fastest supported probe interval (1s); a lower per-series cap would
	// silently drop the NEWEST samples (ORDER BY ts keeps oldest) and skew both
	// latest and P95.
	perSeriesLimit := rangeSec + 1

	out := make(map[string]KindSummary, len(q.Kinds))
	for _, kind := range q.Kinds {
		sqlSeries := `SELECT id, COALESCE(monitor_id,''), COALESCE(target,''), purge_cutoff FROM series WHERE agent_id=? AND kind=?`
		args := []any{q.AgentID, kind}
		if q.Target != "" {
			sqlSeries += ` AND target=?`
			args = append(args, q.Target)
		}
		if q.MonitorID != "" {
			sqlSeries += ` AND monitor_id=?`
			args = append(args, q.MonitorID)
		}
		rows, err := s.db.Read().QueryContext(ctx, sqlSeries, args...)
		if err != nil {
			return nil, err
		}
		type seriesRef struct {
			id                int64
			monitorID, target string
			purgeCutoff       int64
		}
		var series []seriesRef
		for rows.Next() {
			var sr seriesRef
			if err := rows.Scan(&sr.id, &sr.monitorID, &sr.target, &sr.purgeCutoff); err != nil {
				rows.Close()
				return nil, err
			}
			if excluded[sr.target] {
				continue
			}
			series = append(series, sr)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}

		type sample struct {
			ts                int64
			value             float64
			target, monitorID string
		}
		var merged []sample
		// The worst reduction folds per-timestamp maxima WHILE scanning so memory
		// scales with distinct timestamps, not series × timestamps: 50 one-second
		// targets over 24h would otherwise materialize ~4.3M rows per kind before
		// collapsing to at most 86401.
		var worst map[int64]float64
		if q.Reduce == ReduceWorstByTS {
			worst = make(map[int64]float64)
		}
		for _, sr := range series {
			effSince := since
			if sr.purgeCutoff > effSince {
				effSince = sr.purgeCutoff
			}
			samples, err := s.ts.RawRange(ctx, sr.id, effSince, 0, int(perSeriesLimit))
			if err != nil {
				return nil, err
			}
			for _, smp := range samples {
				if worst != nil {
					if prev, ok := worst[smp.TS]; !ok || smp.Value > prev {
						worst[smp.TS] = smp.Value
					}
					continue
				}
				merged = append(merged, sample{ts: smp.TS, value: smp.Value, target: sr.target, monitorID: sr.monitorID})
			}
		}
		if worst != nil {
			merged = make([]sample, 0, len(worst))
			for ts, value := range worst {
				merged = append(merged, sample{ts: ts, value: value})
			}
		}
		if len(merged) == 0 {
			out[kind] = KindSummary{}
			continue
		}
		if worst == nil {
			// Query's merge order with kind fixed; on tied timestamps the latest
			// scan below keeps the earlier entry, matching a strictly-greater
			// reduce over Query output. The worst reduction needs no ordering:
			// its timestamps are unique, so the aggregates below are order-free.
			sort.SliceStable(merged, func(i, j int) bool {
				if merged[i].target != merged[j].target {
					return merged[i].target < merged[j].target
				}
				if merged[i].monitorID != merged[j].monitorID {
					return merged[i].monitorID < merged[j].monitorID
				}
				return merged[i].ts < merged[j].ts
			})
		}

		latest := merged[0]
		var latestNonzero *sample
		var sum float64
		values := make([]float64, len(merged))
		for i, sm := range merged {
			values[i] = sm.value
			sum += sm.value
			if sm.ts > latest.ts {
				latest = sm
			}
			if math.Round(sm.value) != 0 && (latestNonzero == nil || sm.ts > latestNonzero.ts) {
				nz := sm
				latestNonzero = &nz
			}
		}
		sort.Float64s(values)
		idx := int(math.Ceil(float64(len(values))*0.95)) - 1
		if idx < 0 {
			idx = 0
		}
		p95 := values[idx]
		avg := sum / float64(len(merged))
		ks := KindSummary{
			Latest: &LatestPoint{TS: time.Unix(latest.ts, 0).UTC(), Value: latest.value},
			P95:    &p95,
			Avg:    &avg,
			Count:  len(merged),
		}
		if latestNonzero != nil {
			ks.LatestNonzero = &LatestPoint{TS: time.Unix(latestNonzero.ts, 0).UTC(), Value: latestNonzero.value}
		}
		out[kind] = ks
	}
	return out, nil
}

// Stats reports the dictionary size and the data plane's per-tier footprint
// (storage visibility for the console's settings page). Row counts died with
// the SQLite tables — counting TSDB samples means decompressing every chunk —
// so the panel shows disk bytes and head series instead, which is what an
// operator sizing a disk actually wants.
type Stats struct {
	Series int64         `json:"series"`
	TSDB   tsstore.Stats `json:"tsdb"`
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	if err := s.db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM series`).Scan(&st.Series); err != nil {
		return st, err
	}
	ts, err := s.ts.Stats(ctx)
	if err != nil {
		return st, err
	}
	st.TSDB = ts
	return st, nil
}

// SeriesInfo describes one stored series, used to populate the console's
// selectors independently of recent activity.
type SeriesInfo struct {
	Kind      string `json:"kind"`
	Target    string `json:"target"`
	Layer     string `json:"layer"`
	Unit      string `json:"unit"`
	MonitorID string `json:"monitor_id,omitempty"`
}

// ListSeries returns every logical series recorded for an agent (from the
// dictionary, regardless of how recently it reported) ordered by kind then target.
// A monitor may now have several stored generations (config_serial) of the same
// (monitor, kind, target); the selector is generation-neutral, so those collapse
// to one row via DISTINCT — the console picks a logical series, not a generation.
//
// A monitor-bound series is listed only when the monitor's CURRENT kind can still
// emit it. Re-typing a monitor in place (dns → http) leaves the old kind's series
// in the dictionary forever; listing them would let a consumer pick a dead
// probe.dns.ok as the monitor's availability band and report a healthy 100% for a
// target whose HTTP probe is failing every cycle. The samples stay in the store —
// they are simply no longer "this monitor's series". A deleted monitor's leftover
// series drop out for the same reason (no owner, no current kind). System series
// (monitor_id=”) have no owning kind and always pass.
func (s *Store) ListSeries(ctx context.Context, agentID string) ([]SeriesInfo, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT DISTINCT s.kind, COALESCE(s.target,''), COALESCE(s.layer,''), COALESCE(s.unit,''),
		       COALESCE(s.monitor_id,''), COALESCE(pt.kind,'')
		FROM series s LEFT JOIN probe_tasks pt ON pt.id = s.monitor_id
		WHERE s.agent_id=? ORDER BY s.kind, s.target`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SeriesInfo
	for rows.Next() {
		var si SeriesInfo
		var probeKind string
		if err := rows.Scan(&si.Kind, &si.Target, &si.Layer, &si.Unit, &si.MonitorID, &probeKind); err != nil {
			return nil, err
		}
		if si.MonitorID != "" && !telemetry.MetricAllowedForProbeKind(probeKind, si.Kind) {
			continue
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// LatestSnapshot returns the newest sample per series for an agent (all kinds)
// within the sinceUnix lower bound — one point per series instead of a full
// range. Served from the in-memory latest cache (warmed from the DB once per
// agent per process), so the dashboard's poll never touches SQLite for samples.
func (s *Store) LatestSnapshot(ctx context.Context, agentID string, sinceUnix int64) ([]Point, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.warmAgentLocked(ctx, agentID); err != nil {
		return nil, err
	}
	// A monitor may now have several stored generations (config_serial). Only its
	// AUTHORITATIVE current generation — probe_tasks.config_serial — may surface as
	// the current value; a cached older-generation sample must never be shown as
	// current even when the current generation has no sample yet (it then yields no
	// value). System series (monitor_id='') are unique per (kind, target) and pass
	// through directly. Resolve the current generation of every monitor referenced
	// by this agent's series from probe_tasks.
	monitorIDs := map[string]bool{}
	for _, si := range s.byAgent[agentID] {
		if si.monitorID != "" {
			monitorIDs[si.monitorID] = true
		}
	}
	currentSerial, err := s.currentSerialsLocked(ctx, monitorIDs)
	if err != nil {
		return nil, err
	}
	var out []Point
	for id, si := range s.byAgent[agentID] {
		// Wi-Fi current values are served from the authoritative interface
		// snapshot (/agents/{id}/interfaces), not this per-series latest cache —
		// a per-series latest could surface an earlier round's value when the
		// current round omitted a field. wifi.* ingestion + Host Metrics history
		// are unaffected; only this snapshot output excludes them.
		if strings.HasPrefix(string(si.kind), "wifi.") {
			continue
		}
		// probe.round.ok is a server-derived bookkeeping series feeding the
		// availability math, not a value any view charts or reads as "current".
		if string(si.kind) == RoundOKKind {
			continue
		}
		if si.monitorID != "" {
			// Drop any generation other than the target's authoritative current one
			// (and any monitor no longer present in probe_tasks).
			cur, ok := currentSerial[si.monitorID]
			if !ok || si.configSerial != cur {
				continue
			}
		}
		lv, ok := s.latest[id]
		if !ok || lv.ts < sinceUnix {
			continue
		}
		out = append(out, Point{
			TS: time.Unix(lv.ts, 0).UTC(), Kind: si.kind, Target: si.target,
			Layer: si.layer, Value: lv.value, Unit: si.unit, MonitorID: si.monitorID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Target < out[j].Target
	})
	return out, nil
}

// currentSerialsLocked resolves each given monitor id to its authoritative current
// generation (probe_tasks.config_serial). A monitor with no probe_tasks row (deleted)
// is absent from the result. Called while s.mu is held (a plain read on the read
// pool, matching warmAgentLocked's pattern).
func (s *Store) currentSerialsLocked(ctx context.Context, monitorIDs map[string]bool) (map[string]int, error) {
	out := make(map[string]int, len(monitorIDs))
	if len(monitorIDs) == 0 {
		return out, nil
	}
	ids := make([]any, 0, len(monitorIDs))
	ph := make([]byte, 0, len(monitorIDs)*2)
	for id := range monitorIDs {
		ids = append(ids, id)
		if len(ph) > 0 {
			ph = append(ph, ',')
		}
		ph = append(ph, '?')
	}
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT id, config_serial FROM probe_tasks WHERE id IN (`+string(ph)+`)`, ids...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var serial int
		if err := rows.Scan(&id, &serial); err != nil {
			return nil, err
		}
		out[id] = serial
	}
	return out, rows.Err()
}

// TargetValue is the latest value of a series, keyed by its target string. TS is
// the sample's unix timestamp, so a caller merging it with an in-flight batch can
// let the newer of the two win.
type TargetValue struct {
	Target string
	Value  float64
	TS     int64
}

// LatestPerSeries returns the newest value per matching SYSTEM series
// (monitor_id=""), newer than sinceUnix. System series are keyed by target
// string rather than by monitor, which is what this exists to look up: the
// system-status detectors need the machine's core count to read a load average,
// and it is reported as an ordinary series. Served from the latest cache; glob
// supports '*' and '?'.
func (s *Store) LatestPerSeries(ctx context.Context, agentID, kind, glob string, sinceUnix int64) ([]TargetValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.warmAgentLocked(ctx, agentID); err != nil {
		return nil, err
	}
	var out []TargetValue
	for id, si := range s.byAgent[agentID] {
		if si.monitorID != "" || si.kind != kind || !globMatch(glob, si.target) {
			continue
		}
		lv, ok := s.latest[id]
		if !ok || lv.ts <= sinceUnix {
			continue
		}
		out = append(out, TargetValue{Target: si.target, Value: lv.value, TS: lv.ts})
	}
	return out, nil
}

// LatestByMonitor returns the newest value of one monitor's series for a kind and
// exact target generation (configSerial) since sinceUnix — probe rules bind by
// monitor id, and requiring the current generation keeps an obsolete generation's
// sample from being read as current. Served from the latest cache.
func (s *Store) LatestByMonitor(ctx context.Context, agentID, kind, monitorID string, configSerial int, sinceUnix int64) ([]TargetValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.warmAgentLocked(ctx, agentID); err != nil {
		return nil, err
	}
	var out []TargetValue
	for id, si := range s.byAgent[agentID] {
		if si.monitorID != monitorID || si.kind != kind || si.configSerial != configSerial {
			continue
		}
		lv, ok := s.latest[id]
		if !ok || lv.ts <= sinceUnix {
			continue
		}
		out = append(out, TargetValue{Target: si.target, Value: lv.value, TS: lv.ts})
	}
	return out, nil
}

// globMatch implements SQLite-GLOB-style matching for '*' (any run) and '?'
// (any one char); other characters match literally. Rule targets are usually
// literal strings, so the no-metacharacter fast path covers almost every call.
func globMatch(pat, s string) bool {
	if !strings.ContainsAny(pat, "*?") {
		return pat == s
	}
	// Iterative wildcard match with backtracking on the last '*'.
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pat) && (pat[pi] == '?' || pat[pi] == s[si]):
			pi++
			si++
		case pi < len(pat) && pat[pi] == '*':
			star = pi
			mark = si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}
