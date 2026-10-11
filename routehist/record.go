package routehist

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/asnlookup"
	"github.com/nettact/server-core/store"
)

// ipTouchEvery throttles the last_seen refresh of a dictionary row: a hop seen
// every ten minutes would otherwise rewrite its row on every run, which is the
// write volume the dictionaries exist to avoid. last_seen is informational
// (retention is by reference), so a few hours of lag cost nothing.
const ipTouchEvery = 6 * time.Hour

// ApplyTx records scheduled route sweeps for one agent inside the caller's
// write transaction.
//
// The caller has already established that every result is a scheduled sweep
// of a trace monitor that belongs to this agent's scope at the generation the
// result carries (ingest does it against the same transaction); ApplyTx
// trusts that and does not re-read probe_tasks. res may be nil: hops then
// carry no AS, AS paths are empty, and no AS-level change is ever confirmed —
// the IP-level history is still recorded.
//
// It is idempotent per (agent, report id): a sweep already recorded is
// skipped, so a replayed batch changes nothing. Runs are applied per monitor
// in time order; a run older than the monitor's last applied run is skipped,
// since the detector state can only move forward.
func ApplyTx(ctx context.Context, scope store.Scope, wtx store.WriteTx, res asnlookup.Resolver,
	agentID string, results []telemetry.TraceResult, now time.Time) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if wtx.Scope() != scope {
		return errors.New("routehist: write transaction scope does not match the call's scope")
	}
	if len(results) == 0 {
		return nil
	}
	type item struct {
		monitorID string
		serial    int
		run       normRun
	}
	var items []item
	for _, tr := range results {
		if tr.MonitorID == "" {
			continue
		}
		if r, ok := normalize(tr, now); ok {
			items = append(items, item{tr.MonitorID, tr.ConfigSerial, r})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].monitorID != items[j].monitorID {
			return items[i].monitorID < items[j].monitorID
		}
		return items[i].run.ts < items[j].run.ts
	})
	rec := &recorder{ctx: ctx, tx: wtx, res: res, now: now, ips: map[ipKey]int64{}, asns: map[uint32]bool{}}
	if res != nil {
		rec.version = res.Version()
	}
	for _, it := range items {
		if err := rec.apply(agentID, it.monitorID, it.serial, it.run); err != nil {
			return err
		}
	}
	return nil
}

// recorder carries one ApplyTx call's transaction and per-call caches.
type recorder struct {
	ctx     context.Context
	tx      store.WriteTx
	res     asnlookup.Resolver
	version string
	now     time.Time
	ips     map[ipKey]int64
	asns    map[uint32]bool
}

type ipKey struct{ ip, host string }

// runFacts is everything about one run that an era aggregates or a change
// cites. It is also the element of the pending candidate's JSON document.
type runFacts struct {
	TS          int64     `json:"ts"`
	PathID      int64     `json:"path_id"`
	DetailID    int64     `json:"detail_id"`
	Reached     bool      `json:"reached"`
	AS          []uint32  `json:"as"`
	DestIP      string    `json:"dest_ip,omitempty"`
	LocalASN    uint32    `json:"local_asn,omitempty"`
	LocalPrefix string    `json:"local_prefix,omitempty"`
	RTTs        []float64 `json:"rtts,omitempty"`
	Probes      int       `json:"probes,omitempty"`
	Replies     int       `json:"replies,omitempty"`
}

func (f runFacts) shape() pathShape { return pathShape{as: f.AS, reached: f.Reached} }

// pendingState is the not-yet-confirmed candidate route: the representative
// path of the disagreeing runs so far and the runs themselves (at most
// ConfirmRuns-1 between calls; the ConfirmRuns-th confirms).
type pendingState struct {
	PathID  int64      `json:"path_id"`
	AS      []uint32   `json:"as"`
	Reached bool       `json:"reached"`
	Runs    []runFacts `json:"runs"`
}

func (p *pendingState) shape() pathShape { return pathShape{as: p.AS, reached: p.Reached} }

type monitorState struct {
	exists     bool
	epochID    sql.NullInt64
	serial     int
	lastRunAt  int64
	lastPathID sql.NullInt64
	lastRunID  sql.NullInt64
	pending    *pendingState
}

func (r *recorder) loadState(agentID, monitorID string) (monitorState, error) {
	var st monitorState
	var pending string
	err := r.tx.QueryRowContext(r.ctx, `
		SELECT epoch_id, config_serial, last_run_at, last_path_id, last_run_id, pending
		FROM route_monitor_state WHERE agent_id=? AND monitor_id=?`, agentID, monitorID).
		Scan(&st.epochID, &st.serial, &st.lastRunAt, &st.lastPathID, &st.lastRunID, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.exists = true
	if pending != "" {
		var p pendingState
		if json.Unmarshal([]byte(pending), &p) == nil && len(p.Runs) > 0 {
			st.pending = &p
		}
	}
	return st, nil
}

func (r *recorder) saveState(agentID, monitorID string, st monitorState) error {
	pending := ""
	if st.pending != nil {
		b, err := json.Marshal(st.pending)
		if err != nil {
			return err
		}
		pending = string(b)
	}
	_, err := r.tx.ExecContext(r.ctx, `
		INSERT INTO route_monitor_state(agent_id, monitor_id, epoch_id, config_serial, last_run_at, last_path_id, last_run_id, pending)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id, monitor_id) DO UPDATE SET
		  epoch_id=excluded.epoch_id, config_serial=excluded.config_serial, last_run_at=excluded.last_run_at,
		  last_path_id=excluded.last_path_id, last_run_id=excluded.last_run_id, pending=excluded.pending`,
		agentID, monitorID, st.epochID, st.serial, st.lastRunAt, st.lastPathID, st.lastRunID, pending)
	return err
}

// apply runs one sweep through the detector.
func (r *recorder) apply(agentID, monitorID string, serial int, run normRun) error {
	var seen int
	if err := r.tx.QueryRowContext(r.ctx,
		`SELECT COUNT(*) FROM route_runs_detail WHERE agent_id=? AND report_id=?`, agentID, run.reportID).Scan(&seen); err != nil {
		return err
	}
	if seen > 0 {
		return nil // replay
	}
	st, err := r.loadState(agentID, monitorID)
	if err != nil {
		return err
	}
	if st.exists && run.ts < st.lastRunAt {
		return nil // older than what the detector has already moved past
	}

	facts, err := r.storeRun(agentID, monitorID, run)
	if err != nil {
		return err
	}
	st.exists = true
	st.lastRunAt = max(st.lastRunAt, run.ts)

	// No open era, or the monitor was materially edited since (a new
	// destination, mode or port): this run is a new baseline, not a change.
	if !st.epochID.Valid || st.serial != serial {
		id, err := r.openEpoch(agentID, monitorID, serial, facts.PathID, []runFacts{facts})
		if err != nil {
			return err
		}
		st.epochID = sql.NullInt64{Int64: id, Valid: true}
		st.serial = serial
		st.pending = nil
		st.lastPathID = sql.NullInt64{Int64: facts.PathID, Valid: true}
		st.lastRunID = sql.NullInt64{Int64: facts.DetailID, Valid: true}
		return r.saveState(agentID, monitorID, st)
	}

	ep, err := r.loadEpoch(st.epochID.Int64)
	if err != nil {
		return err
	}
	same := consistent(facts.shape(), ep.shape)
	if !same {
		if same, err = r.sameRouteReattributed(&ep, facts); err != nil {
			return err
		}
	}
	if same {
		// The route holds. A pending candidate that the route has just come
		// back from was a flap: its runs already counted as deviations, and
		// nothing else of it is kept.
		newPath := ep.pathID
		if consistent(facts.shape(), ep.shape) && refines(facts.shape(), ep.shape) {
			newPath = facts.PathID
		}
		if err := r.extendEpoch(ep, newPath, facts); err != nil {
			return err
		}
		st.pending = nil
		st.lastPathID = sql.NullInt64{Int64: facts.PathID, Valid: true}
		st.lastRunID = sql.NullInt64{Int64: facts.DetailID, Valid: true}
		return r.saveState(agentID, monitorID, st)
	}

	// A disagreeing run: a deviation of the open era, and a vote for a
	// candidate route.
	if _, err := r.tx.ExecContext(r.ctx,
		`UPDATE route_epochs SET deviation_count=deviation_count+1 WHERE id=?`, ep.id); err != nil {
		return err
	}
	if st.pending != nil && consistent(facts.shape(), st.pending.shape()) {
		if refines(facts.shape(), st.pending.shape()) {
			st.pending.PathID, st.pending.AS, st.pending.Reached = facts.PathID, facts.AS, facts.Reached
		}
		st.pending.Runs = append(st.pending.Runs, facts)
	} else {
		st.pending = &pendingState{PathID: facts.PathID, AS: facts.AS, Reached: facts.Reached, Runs: []runFacts{facts}}
	}
	if len(st.pending.Runs) < ConfirmRuns {
		return r.saveState(agentID, monitorID, st)
	}

	newID, err := r.confirm(agentID, monitorID, serial, ep, st)
	if err != nil {
		return err
	}
	last := st.pending.Runs[len(st.pending.Runs)-1]
	st.epochID = sql.NullInt64{Int64: newID, Valid: true}
	st.lastPathID = sql.NullInt64{Int64: last.PathID, Valid: true}
	st.lastRunID = sql.NullInt64{Int64: last.DetailID, Valid: true}
	st.pending = nil
	return r.saveState(agentID, monitorID, st)
}

// sameRouteReattributed decides, for a run whose AS path disagrees with the
// open era's, whether the disagreement is only a lookup-table refresh rather
// than a different route — and, when the era's attribution is stale, brings it
// up to the current table either way.
//
// AS paths are derived, not observed: the agent reports addresses, and the AS
// of each comes from whatever table was loaded when the run was recorded. When
// the host swaps in a newer table, a prefix that moved between ASes (a
// transfer, a corrected registration, a more specific announcement) gives the
// very same IP route a different AS path, and judging it against the era's
// old-table AS path would walk it through confirmation into a "route change"
// nobody's packets ever took. Two rules keep that from happening:
//
//   - re-attribution: when any hop of the era's representative path was
//     resolved under a table other than the current one, the path is
//     re-resolved under the current table (new dictionary rows and a new path
//     row, same addresses and names) and the era is repointed at it, local
//     egress facts included. The run is then judged against that, so hops
//     whose AS merely moved between table versions no longer differ. This is
//     done even when the run still disagrees — a real change that coincides
//     with a refresh is then classified against an era described in the same
//     table as the new route, not a mixture of two.
//   - same addresses: a run whose IP path — compared by address, not by
//     dictionary id, since ids are per attribution — equals one the era has
//     already counted as a variant is the same route by definition, whatever
//     its AS path now reads. This catches the case re-attributing the
//     representative alone would miss: an ECMP variant whose own hop moved AS
//     while the representative's did not.
//
// Both only ever continue an era; neither can open one, so a real change is
// still confirmed by ConfirmRuns runs as before.
func (r *recorder) sameRouteReattributed(ep *epochRow, facts runFacts) (bool, error) {
	if err := r.reattributeEpoch(ep); err != nil {
		return false, err
	}
	if consistent(facts.shape(), ep.shape) {
		return true, nil
	}
	return r.matchesVariant(ep.id, facts.PathID)
}

// reattributeEpoch re-resolves the era's representative path under the
// current table when any of its hops was resolved under another one, and
// repoints the era at the result. Without a resolver there is nothing to
// re-resolve against and the era is left as it is.
func (r *recorder) reattributeEpoch(ep *epochRow) error {
	if r.res == nil {
		return nil
	}
	ip, reached, err := r.pathIPs(ep.pathID)
	if err != nil {
		return err
	}
	rows, err := r.ipRows(ip)
	if err != nil {
		return err
	}
	stale := false
	for _, row := range rows {
		if row.version != r.version {
			stale = true
		}
	}
	if !stale {
		return nil
	}
	fresh := make(ipPath, len(ip))
	asnOf := map[int64]uint32{}
	var localASN uint32
	localPrefix, localFound := "", false
	for i, hop := range ip {
		ids := make([]int64, 0, len(hop))
		for _, old := range hop {
			row, ok := rows[old]
			if !ok {
				continue
			}
			id, info, resolved, err := r.ensureIP(row.ip, row.host)
			if err != nil {
				return err
			}
			if resolved {
				asnOf[id] = info.ASN
			}
			ids = append(ids, id)
			if !localFound {
				if addr, err := netip.ParseAddr(row.ip); err == nil && asnlookup.IsPublicIPv4(addr) {
					localFound = true
					if resolved {
						localASN, localPrefix = info.ASN, info.Prefix
					}
				}
			}
		}
		sort.Slice(ids, func(x, y int) bool { return ids[x] < ids[y] })
		fresh[i] = ids
	}
	as := asPathOf(fresh, asnOf)
	pathID, err := r.ensurePath(fresh, as, reached)
	if err != nil {
		return err
	}
	var local sql.NullInt64
	if localASN != 0 {
		local = sql.NullInt64{Int64: int64(localASN), Valid: true}
	}
	if _, err := r.tx.ExecContext(r.ctx,
		`UPDATE route_epochs SET path_id=?, local_asn=?, local_prefix=? WHERE id=?`,
		pathID, local, localPrefix, ep.id); err != nil {
		return err
	}
	ep.pathID = pathID
	ep.shape = pathShape{as: as, reached: reached}
	ep.facts.localASN, ep.facts.localPrefix = localASN, localPrefix
	return nil
}

// matchesVariant reports whether the run's path names, TTL by TTL, the same
// addresses as a path already counted as a variant of the era.
func (r *recorder) matchesVariant(epochID, runPathID int64) (bool, error) {
	runIP, _, err := r.pathIPs(runPathID)
	if err != nil {
		return false, err
	}
	// Collect before decoding: the write transaction is the only connection,
	// so no query may run while these rows are open.
	rows, err := r.tx.QueryContext(r.ctx, `
		SELECT p.ip_path FROM route_epoch_variants v JOIN route_paths p ON p.id = v.path_id
		WHERE v.epoch_id=? AND v.path_id<>?`, epochID, runPathID)
	if err != nil {
		return false, err
	}
	var blobs [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return false, err
		}
		blobs = append(blobs, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	paths := []ipPath{runIP}
	for _, b := range blobs {
		p, err := decodeIPPath(b)
		if err != nil {
			return false, err
		}
		paths = append(paths, p)
	}
	ipr, err := r.ipRows(paths...)
	if err != nil {
		return false, err
	}
	want := addrPath(runIP, ipr)
	for _, p := range paths[1:] {
		if equalAddrPath(addrPath(p, ipr), want) {
			return true, nil
		}
	}
	return false, nil
}

// attrRow is what re-attribution and address comparison need of a dictionary row.
type attrRow struct{ ip, host, version string }

func (r *recorder) pathIPs(pathID int64) (ipPath, bool, error) {
	var blob []byte
	var reached int
	if err := r.tx.QueryRowContext(r.ctx, `SELECT ip_path, reached FROM route_paths WHERE id=?`, pathID).
		Scan(&blob, &reached); err != nil {
		return nil, false, err
	}
	ip, err := decodeIPPath(blob)
	return ip, reached == 1, err
}

// ipRows loads the dictionary rows every id in the given paths names.
func (r *recorder) ipRows(paths ...ipPath) (map[int64]attrRow, error) {
	out := map[int64]attrRow{}
	var ids []any
	seen := map[int64]bool{}
	for _, p := range paths {
		for _, hop := range p {
			for _, id := range hop {
				if !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.tx.QueryContext(r.ctx,
		`SELECT id, ip, hostname, asn_db_version FROM route_ips WHERE id IN (`+placeholders(len(ids))+`)`, ids...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var row attrRow
		if err := rows.Scan(&id, &row.ip, &row.host, &row.version); err != nil {
			return nil, err
		}
		out[id] = row
	}
	return out, rows.Err()
}

// addrPath renders a path as its per-TTL sorted, distinct addresses.
func addrPath(ip ipPath, rows map[int64]attrRow) [][]string {
	out := make([][]string, len(ip))
	for i, hop := range ip {
		var as []string
		for _, id := range hop {
			if a := rows[id].ip; a != "" && !slices.Contains(as, a) {
				as = append(as, a)
			}
		}
		sort.Strings(as)
		out[i] = as
	}
	return out
}

func equalAddrPath(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !slices.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// confirm closes the open era in favour of the pending candidate: the
// candidate's runs become a new era, they stop counting as deviations of the
// old one (they were the new route, not noise on the old), and the change is
// recorded with its classification and evidence.
func (r *recorder) confirm(agentID, monitorID string, serial int, old epochRow, st monitorState) (int64, error) {
	p := st.pending
	newID, err := r.openEpoch(agentID, monitorID, serial, p.PathID, p.Runs)
	if err != nil {
		return 0, err
	}
	if _, err := r.tx.ExecContext(r.ctx,
		`UPDATE route_epochs SET deviation_count=MAX(deviation_count-?,0) WHERE id=?`, len(p.Runs), old.id); err != nil {
		return 0, err
	}
	first := p.Runs[0]
	newF := endpointFacts{destIP: first.DestIP, localASN: first.LocalASN, localPrefix: first.LocalPrefix}
	kind, segment, diverge := classifyChange(old.shape, p.shape(), old.facts, newF)

	var divergeTTL sql.NullInt64
	if diverge < len(p.AS) {
		ttl, err := r.firstTTLInAS(p.PathID, p.AS[diverge])
		if err != nil {
			return 0, err
		}
		if ttl > 0 {
			divergeTTL = sql.NullInt64{Int64: int64(ttl), Valid: true}
		}
	}
	before, err := r.existingDetail(st.lastRunID)
	if err != nil {
		return 0, err
	}
	after, err := r.existingDetail(sql.NullInt64{Int64: first.DetailID, Valid: first.DetailID > 0})
	if err != nil {
		return 0, err
	}
	last := p.Runs[len(p.Runs)-1]
	_, err = r.tx.ExecContext(r.ctx, `
		INSERT INTO route_changes(agent_id, monitor_id, from_epoch_id, to_epoch_id, kind, segment, diverge_ttl,
		                          confirmed_at, before_run_id, after_run_id)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		agentID, monitorID, old.id, newID, kind, segment, divergeTTL, last.TS, before, after)
	return newID, err
}

// existingDetail returns id when that detail row still exists, else NULL: a
// cited run may have aged out (a monitor that stopped reporting for longer
// than the detail window and then resumed on a new route).
func (r *recorder) existingDetail(id sql.NullInt64) (sql.NullInt64, error) {
	if !id.Valid {
		return id, nil
	}
	var n int
	if err := r.tx.QueryRowContext(r.ctx, `SELECT COUNT(*) FROM route_runs_detail WHERE id=?`, id.Int64).Scan(&n); err != nil {
		return sql.NullInt64{}, err
	}
	if n == 0 {
		return sql.NullInt64{}, nil
	}
	return id, nil
}

// firstTTLInAS returns the first TTL of a path at which a responder belongs
// to asn, or 0.
func (r *recorder) firstTTLInAS(pathID int64, asn uint32) (int, error) {
	var blob []byte
	if err := r.tx.QueryRowContext(r.ctx, `SELECT ip_path FROM route_paths WHERE id=?`, pathID).Scan(&blob); err != nil {
		return 0, err
	}
	ip, err := decodeIPPath(blob)
	if err != nil {
		return 0, err
	}
	asOf, err := ipASNs(r.ctx, r.tx, ip)
	if err != nil {
		return 0, err
	}
	for i, hop := range ip {
		for _, id := range hop {
			if asOf[id] == asn {
				return i + 1, nil
			}
		}
	}
	return 0, nil
}

// ipASNs maps every route_ips id named in a path to its AS.
func ipASNs(ctx context.Context, q store.Executor, ip ipPath) (map[int64]uint32, error) {
	out := map[int64]uint32{}
	var ids []any
	for _, hop := range ip {
		for _, id := range hop {
			if _, ok := out[id]; !ok {
				out[id] = 0
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT id, asn FROM route_ips WHERE id IN (`+placeholders(len(ids))+`)`, ids...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var asn uint32
		if err := rows.Scan(&id, &asn); err != nil {
			return nil, err
		}
		out[id] = asn
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}

// ---- storing a run ----

// storeRun resolves the run's hops into dictionary ids, stores (or finds) its
// path, writes the run's detail row, and returns the run's facts.
func (r *recorder) storeRun(agentID, monitorID string, run normRun) (runFacts, error) {
	f := runFacts{TS: run.ts, Reached: run.reached, DestIP: run.destIP}

	// One hostname per address per run: attempts at one TTL may carry the name
	// on some and not others (the reverse lookup budget ran out), and picking
	// the named one keeps a flaky lookup from minting dictionary variants.
	hostOf := map[string]string{}
	for _, h := range run.hops {
		for _, a := range h.attempts {
			if a.ip != "" && a.host != "" && hostOf[a.ip] == "" {
				hostOf[a.ip] = a.host
			}
		}
	}
	idOf := map[string]int64{}
	asnOf := map[int64]uint32{}
	localFound := false
	for _, h := range run.hops {
		for _, a := range h.attempts {
			if a.ip == "" {
				continue
			}
			if _, done := idOf[a.ip]; done {
				continue
			}
			id, info, ok, err := r.ensureIP(a.ip, hostOf[a.ip])
			if err != nil {
				return f, err
			}
			idOf[a.ip] = id
			if ok {
				asnOf[id] = info.ASN
			}
			// The local egress is the first PUBLIC responder in TTL order —
			// private and CGNAT hops are the home and the carrier's NAT, which
			// say nothing about which line the traffic left on.
			if !localFound {
				if addr, err := netip.ParseAddr(a.ip); err == nil && asnlookup.IsPublicIPv4(addr) {
					localFound = true
					if ok {
						f.LocalASN, f.LocalPrefix = info.ASN, info.Prefix
					}
				}
			}
		}
	}

	n := run.pathLen()
	ip := make(ipPath, n)
	for i := 0; i < n; i++ {
		resp := run.hops[i].responders()
		ids := make([]int64, 0, len(resp))
		for _, a := range resp {
			ids = append(ids, idOf[a])
		}
		sort.Slice(ids, func(x, y int) bool { return ids[x] < ids[y] })
		ip[i] = ids
	}
	f.AS = asPathOf(ip, asnOf)
	pathID, err := r.ensurePath(ip, f.AS, run.reached)
	if err != nil {
		return f, err
	}
	f.PathID = pathID
	f.RTTs, f.Probes, f.Replies = run.destSamples()

	hops := make([]detailHop, 0, len(run.hops))
	for i, h := range run.hops {
		dh := detailHop{ttl: i + 1}
		for _, a := range h.attempts {
			dh.attempts = append(dh.attempts, detailAttempt{ipID: idOf[a.ip], rttMs: a.rttMs, rtt: a.hasRTT})
		}
		hops = append(hops, dh)
	}
	res, err := r.tx.ExecContext(r.ctx, `
		INSERT INTO route_runs_detail(agent_id, monitor_id, report_id, run_ts, path_id, dest_ip, reached, hops)
		VALUES(?,?,?,?,?,?,?,?)`,
		agentID, monitorID, run.reportID, run.ts, pathID, run.destIP, boolInt(run.reached), encodeDetail(hops))
	if err != nil {
		return f, err
	}
	if f.DetailID, err = res.LastInsertId(); err != nil {
		return f, err
	}
	return f, nil
}

// asPathOf derives the AS path: per TTL the distinct ASes of its responders
// (ascending, for determinism), hops without an AS skipped, adjacent repeats
// merged.
func asPathOf(ip ipPath, asnOf map[int64]uint32) []uint32 {
	as := []uint32{}
	for _, hop := range ip {
		var set []uint32
		for _, id := range hop {
			if a := asnOf[id]; a != 0 {
				set = append(set, a)
			}
		}
		sort.Slice(set, func(i, j int) bool { return set[i] < set[j] })
		for _, a := range set {
			if len(as) == 0 || as[len(as)-1] != a {
				as = append(as, a)
			}
		}
	}
	return as
}

// ensureIP returns the dictionary id for an address as seen now, creating
// the row on first sight of this (address, AS, prefix, name) combination.
//
// A run that has NO name for an address reuses the most recent row for it
// rather than minting a nameless twin, so a reverse lookup that merely timed
// out this run does not look like a different hop.
func (r *recorder) ensureIP(ip, host string) (int64, asnlookup.Info, bool, error) {
	var info asnlookup.Info
	var ok bool
	if r.res != nil {
		if addr, err := netip.ParseAddr(ip); err == nil {
			info, ok = r.res.Lookup(addr)
		}
	}
	key := ipKey{ip, host}
	if id, hit := r.ips[key]; hit {
		return id, info, ok, nil
	}
	if ok && !r.asns[info.ASN] {
		r.asns[info.ASN] = true
		if _, err := r.tx.ExecContext(r.ctx, `
			INSERT INTO asn_info(asn, name, country, updated_at) VALUES(?,?,?,?)
			ON CONFLICT(asn) DO UPDATE SET name=excluded.name, country=excluded.country, updated_at=excluded.updated_at
			WHERE asn_info.name<>excluded.name OR asn_info.country<>excluded.country`,
			info.ASN, info.Name, info.Country, r.now.Unix()); err != nil {
			return 0, info, ok, err
		}
	}
	var asn uint32
	var prefix string
	if ok {
		asn, prefix = info.ASN, info.Prefix
	}
	var id, lastSeen int64
	var err error
	if host != "" {
		err = r.tx.QueryRowContext(r.ctx,
			`SELECT id, last_seen FROM route_ips WHERE ip=? AND asn=? AND prefix=? AND hostname=?`,
			ip, asn, prefix, host).Scan(&id, &lastSeen)
	} else {
		err = r.tx.QueryRowContext(r.ctx,
			`SELECT id, last_seen FROM route_ips WHERE ip=? AND asn=? AND prefix=? ORDER BY last_seen DESC, id DESC LIMIT 1`,
			ip, asn, prefix).Scan(&id, &lastSeen)
	}
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := r.tx.ExecContext(r.ctx, `
			INSERT INTO route_ips(ip, hostname, asn, prefix, asn_db_version, first_seen, last_seen)
			VALUES(?,?,?,?,?,?,?)`, ip, host, asn, prefix, r.version, r.now.Unix(), r.now.Unix())
		if err != nil {
			return 0, info, ok, err
		}
		if id, err = res.LastInsertId(); err != nil {
			return 0, info, ok, err
		}
	case err != nil:
		return 0, info, ok, err
	case r.now.Unix()-lastSeen > int64(ipTouchEvery/time.Second):
		if _, err := r.tx.ExecContext(r.ctx, `UPDATE route_ips SET last_seen=? WHERE id=?`, r.now.Unix(), id); err != nil {
			return 0, info, ok, err
		}
	}
	r.ips[key] = id
	return id, info, ok, nil
}

func (r *recorder) ensurePath(ip ipPath, as []uint32, reached bool) (int64, error) {
	blob := encodeIPPath(ip)
	hash := pathHash(reached, blob)
	var id int64
	err := r.tx.QueryRowContext(r.ctx, `SELECT id FROM route_paths WHERE hash=?`, hash).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	res, err := r.tx.ExecContext(r.ctx,
		`INSERT INTO route_paths(hash, ip_path, as_path, reached, first_seen) VALUES(?,?,?,?,?)`,
		hash, blob, encodeASPath(as), boolInt(reached), r.now.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ---- eras ----

type epochRow struct {
	id     int64
	pathID int64
	shape  pathShape
	facts  endpointFacts
	hist   histogram
}

func (r *recorder) loadEpoch(id int64) (epochRow, error) {
	e := epochRow{id: id}
	var asBlob, histBlob []byte
	var reached int
	var localASN sql.NullInt64
	if err := r.tx.QueryRowContext(r.ctx, `
		SELECT e.path_id, p.as_path, p.reached, e.dest_ip, e.local_asn, e.local_prefix,
		       e.rtt_hist, e.rtt_count, e.rtt_sum, e.rtt_min, e.rtt_max
		FROM route_epochs e JOIN route_paths p ON p.id = e.path_id WHERE e.id=?`, id).
		Scan(&e.pathID, &asBlob, &reached, &e.facts.destIP, &localASN, &e.facts.localPrefix,
			&histBlob, &e.hist.count, &e.hist.sum, &e.hist.min, &e.hist.max); err != nil {
		return e, err
	}
	as, err := decodeASPath(asBlob)
	if err != nil {
		return e, err
	}
	e.shape = pathShape{as: as, reached: reached == 1}
	if localASN.Valid {
		e.facts.localASN = uint32(localASN.Int64)
	}
	h := decodeHist(histBlob)
	h.count, h.sum, h.min, h.max = e.hist.count, e.hist.sum, e.hist.min, e.hist.max
	e.hist = h
	return e, nil
}

func runsHist(runs []runFacts) histogram {
	var h histogram
	for _, f := range runs {
		for _, v := range f.RTTs {
			h.add(v)
		}
	}
	return h
}

// openEpoch starts an era from one or more runs (one for a baseline, the
// candidate's runs for a confirmed change) under representative path pathID.
func (r *recorder) openEpoch(agentID, monitorID string, serial int, pathID int64, runs []runFacts) (int64, error) {
	first, last := runs[0], runs[len(runs)-1]
	h := runsHist(runs)
	var reached, probes, replies int
	var localASN sql.NullInt64
	localPrefix, destIP := "", ""
	for _, f := range runs {
		if f.Reached {
			reached++
		}
		probes += f.Probes
		replies += f.Replies
		if !localASN.Valid && f.LocalASN != 0 {
			localASN = sql.NullInt64{Int64: int64(f.LocalASN), Valid: true}
		}
		if localPrefix == "" {
			localPrefix = f.LocalPrefix
		}
		if destIP == "" {
			destIP = f.DestIP
		}
	}
	res, err := r.tx.ExecContext(r.ctx, `
		INSERT INTO route_epochs(agent_id, monitor_id, config_serial, path_id, start_ts, end_ts, run_count,
		    reached_runs, probes, replies, dest_ip, local_asn, local_prefix,
		    rtt_hist, rtt_count, rtt_sum, rtt_min, rtt_max)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		agentID, monitorID, serial, pathID, first.TS, last.TS, len(runs),
		reached, probes, replies, destIP, localASN, localPrefix,
		encodeHist(h), h.count, h.sum, h.min, h.max)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, f := range runs {
		if err := r.countVariant(id, f.PathID, f.TS); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// extendEpoch folds one consistent run into the open era.
func (r *recorder) extendEpoch(e epochRow, pathID int64, f runFacts) error {
	h := e.hist
	h.merge(runsHist([]runFacts{f}))
	var localASN sql.NullInt64
	if f.LocalASN != 0 {
		localASN = sql.NullInt64{Int64: int64(f.LocalASN), Valid: true}
	}
	if _, err := r.tx.ExecContext(r.ctx, `
		UPDATE route_epochs SET
		  path_id=?, end_ts=MAX(end_ts, ?), run_count=run_count+1, reached_runs=reached_runs+?,
		  probes=probes+?, replies=replies+?,
		  dest_ip=CASE WHEN dest_ip='' THEN ? ELSE dest_ip END,
		  local_asn=COALESCE(local_asn, ?),
		  local_prefix=CASE WHEN local_prefix='' THEN ? ELSE local_prefix END,
		  rtt_hist=?, rtt_count=?, rtt_sum=?, rtt_min=?, rtt_max=?
		WHERE id=?`,
		pathID, f.TS, boolInt(f.Reached), f.Probes, f.Replies, f.DestIP, localASN, f.LocalPrefix,
		encodeHist(h), h.count, h.sum, h.min, h.max, e.id); err != nil {
		return err
	}
	return r.countVariant(e.id, f.PathID, f.TS)
}

func (r *recorder) countVariant(epochID, pathID, ts int64) error {
	_, err := r.tx.ExecContext(r.ctx, `
		INSERT INTO route_epoch_variants(epoch_id, path_id, count, last_ts) VALUES(?,?,1,?)
		ON CONFLICT(epoch_id, path_id) DO UPDATE SET count=count+1, last_ts=MAX(last_ts, excluded.last_ts)`,
		epochID, pathID, ts)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
