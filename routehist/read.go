package routehist

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/asnlookup"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/store"
)

// Read-side errors, mapped by a console host to 404 / 400.
var (
	ErrTargetNotFound = errors.New("routehist: target not found")
	ErrNotTraceTarget = errors.New("routehist: target is not a route monitor")
	ErrChangeNotFound = errors.New("routehist: route change not found")
)

// Service serves route history reads and runs its retention. The write path
// (ApplyTx) needs no Service: it is entered from the ingest transaction.
type Service struct {
	db  *store.DB
	asn asnlookup.Resolver
}

// New returns a Service over db. asn may be nil; it is consulted only for the
// version of the lookup table currently loaded, which the overview reports.
func New(db *store.DB, asn asnlookup.Resolver) *Service {
	return &Service{db: db, asn: asn}
}

// Retention runs RetentionTx in its own transaction, then hands the freed
// pages back to the filesystem. The database runs in incremental auto-vacuum
// mode, which never reclaims on its own; without the explicit pass, a week of
// pruned detail would stay allocated as free pages forever. The vacuum runs
// outside the transaction (SQLite refuses it inside one) and is best-effort:
// a failure there loses nothing but disk space until the next pass.
func (s *Service) Retention(ctx context.Context) error {
	if err := s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		return nil, RetentionTx(ctx, store.Standalone(), wtx, time.Now().UTC())
	}); err != nil {
		return err
	}
	_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	return nil
}

// ---- views (the console's JSON contract) ----

// ASHop is one AS of an AS path.
type ASHop struct {
	ASN       uint32 `json:"asn"`
	ASName    string `json:"as_name"`
	ASCountry string `json:"as_country"`
}

// RouteResponder is one address that answered at a TTL.
type RouteResponder struct {
	IP        string  `json:"ip"`
	Hostname  string  `json:"hostname"`
	ASN       *uint32 `json:"asn"`
	ASName    string  `json:"as_name"`
	ASCountry string  `json:"as_country"`
	Prefix    string  `json:"prefix"`
}

// RouteHopView is one TTL of a path; Timeout means nobody answered at it.
type RouteHopView struct {
	TTL        int              `json:"ttl"`
	Responders []RouteResponder `json:"responders"`
	Timeout    bool             `json:"timeout"`
}

// RoutePathView is a normalized path, hop by hop.
type RoutePathView struct {
	PathID  int64          `json:"path_id"`
	ASPath  []ASHop        `json:"as_path"`
	Hops    []RouteHopView `json:"hops"`
	Reached bool           `json:"reached"`
}

// RouteVariant counts one IP path within an era.
type RouteVariant struct {
	PathID int64 `json:"path_id"`
	Count  int   `json:"count"`
}

// RouteEpoch is one era of one AS path on one agent.
type RouteEpoch struct {
	ID             int64          `json:"id"`
	AgentID        string         `json:"agent_id"`
	PathID         int64          `json:"path_id"`
	ASPath         []ASHop        `json:"as_path"`
	StartAt        string         `json:"start_at"`
	EndAt          string         `json:"end_at"`
	RunCount       int            `json:"run_count"`
	DeviationCount int            `json:"deviation_count"`
	DestIP         string         `json:"dest_ip"`
	LocalASN       *uint32        `json:"local_asn"`
	RTT            *RouteRTT      `json:"rtt"`
	ReachedRatio   float64        `json:"reached_ratio"`
	Variants       []RouteVariant `json:"variants"`
}

// Agent route statuses (RouteAgentView.Status).
const (
	StatusActive               = "active"
	StatusPending              = "pending"
	StatusAgentUpgradeRequired = config.ReasonAgentUpgradeRequired
	StatusPermissionBlocked    = "permission_blocked"
	StatusUnsupported          = "unsupported"
)

// RouteAgentView is one agent's current view of a route monitor.
type RouteAgentView struct {
	AgentID   string         `json:"agent_id"`
	AgentName string         `json:"agent_name"`
	Status    string         `json:"status"`
	LastRunAt *string        `json:"last_run_at"`
	Current   *RouteEpoch    `json:"current"`
	Path      *RoutePathView `json:"path"`
}

// RouteOverview is the per-target overview.
type RouteOverview struct {
	ASNDBVersion string           `json:"asn_db_version"`
	Agents       []RouteAgentView `json:"agents"`
}

// RouteChange is one confirmed change.
type RouteChange struct {
	ID          int64     `json:"id"`
	MonitorID   string    `json:"monitor_id"`
	AgentID     string    `json:"agent_id"`
	AgentName   string    `json:"agent_name"`
	Kind        string    `json:"kind"`
	Segment     string    `json:"segment"`
	DivergeTTL  *int      `json:"diverge_ttl"`
	ConfirmedAt string    `json:"confirmed_at"`
	FromEpochID int64     `json:"from_epoch_id"`
	ToEpochID   int64     `json:"to_epoch_id"`
	FromASPath  []ASHop   `json:"from_as_path"`
	ToASPath    []ASHop   `json:"to_as_path"`
	RTTBefore   *RouteRTT `json:"rtt_before"`
	RTTAfter    *RouteRTT `json:"rtt_after"`
}

// RouteRunAttempt is one probe of a run in full.
type RouteRunAttempt struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	RTTMs    *float64 `json:"rtt_ms"`
	Timeout  bool     `json:"timeout"`
	ASN      *uint32  `json:"asn"`
	ASName   string   `json:"as_name"`
}

// RouteRunHop is one TTL of a run in full.
type RouteRunHop struct {
	TTL      int               `json:"ttl"`
	Attempts []RouteRunAttempt `json:"attempts"`
}

// RouteRunDetail is one run in full.
type RouteRunDetail struct {
	RunAt   string        `json:"run_at"`
	DestIP  string        `json:"dest_ip"`
	Reached bool          `json:"reached"`
	Hops    []RouteRunHop `json:"hops"`
}

// RouteChangeDetail is a change with both paths and the cited runs.
type RouteChangeDetail struct {
	Change    RouteChange     `json:"change"`
	Before    RoutePathView   `json:"before"`
	After     RoutePathView   `json:"after"`
	BeforeRun *RouteRunDetail `json:"before_run"`
	AfterRun  *RouteRunDetail `json:"after_run"`
}

// EpochQuery filters Epochs. Zero From/To leave that side open; Limit <= 0
// means DefaultLimit.
type EpochQuery struct {
	AgentID  string
	From, To time.Time
	Limit    int
}

// ChangeQuery filters Changes: those confirmed strictly before Before (zero =
// now), newest first.
type ChangeQuery struct {
	AgentID string
	Before  time.Time
	Limit   int
}

// List bounds.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

func clampLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	return min(n, MaxLimit)
}

func rfc3339(ts int64) string { return time.Unix(ts, 0).UTC().Format(time.RFC3339) }

// ---- queries ----

type targetRow struct {
	siteID string
	serial int
}

func (s *Service) traceTarget(ctx context.Context, q store.Executor, targetID string) (targetRow, error) {
	var t targetRow
	var kind string
	err := q.QueryRowContext(ctx, `SELECT site_id, kind, config_serial FROM probe_tasks WHERE id=?`, targetID).
		Scan(&t.siteID, &kind, &t.serial)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrTargetNotFound
	}
	if err != nil {
		return t, err
	}
	if kind != config.KindTrace {
		return t, ErrNotTraceTarget
	}
	return t, nil
}

// TargetRoute returns every relevant agent's current route for a monitor: the
// agents currently in its scope, plus any that still hold history for it.
func (s *Service) TargetRoute(ctx context.Context, targetID string) (*RouteOverview, error) {
	q := s.db.Read()
	t, err := s.traceTarget(ctx, q, targetID)
	if err != nil {
		return nil, err
	}
	out := &RouteOverview{Agents: []RouteAgentView{}}
	if s.asn != nil {
		out.ASNDBVersion = s.asn.Version()
	}
	rows, err := q.QueryContext(ctx, `
		SELECT a.id, COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), a.id),
		       ms.status, COALESCE(ms.reason,''), ms.source, ms.target_config_serial,
		       rs.epoch_id, rs.last_run_at, rs.last_path_id
		FROM agents a
		JOIN probe_tasks pt ON pt.id = ?
		LEFT JOIN monitor_status ms ON ms.agent_id = a.id AND ms.monitor_id = pt.id
		LEFT JOIN route_monitor_state rs ON rs.agent_id = a.id AND rs.monitor_id = pt.id
		WHERE a.site_id = pt.site_id AND a.revoked = 0 AND (rs.agent_id IS NOT NULL OR EXISTS(
		    SELECT 1 FROM monitor_groups mg
		    WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
		        SELECT 1 FROM monitor_group_agent_groups mgag
		        JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
		        WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = a.id))))
		ORDER BY 2, 1`, targetID)
	if err != nil {
		return nil, err
	}
	type agentRow struct {
		view              RouteAgentView
		epochID, lastPath sql.NullInt64
	}
	var agents []agentRow
	for rows.Next() {
		var a agentRow
		var status, source sql.NullString
		var reason string
		var msSerial, lastRun sql.NullInt64
		if err := rows.Scan(&a.view.AgentID, &a.view.AgentName, &status, &reason, &source, &msSerial,
			&a.epochID, &lastRun, &a.lastPath); err != nil {
			rows.Close()
			return nil, err
		}
		a.view.Status = agentStatus(status, reason, source, msSerial, t.serial)
		if lastRun.Valid && lastRun.Int64 > 0 {
			v := rfc3339(lastRun.Int64)
			a.view.LastRunAt = &v
		}
		agents = append(agents, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	names := newASNames(q)
	for _, a := range agents {
		if a.epochID.Valid {
			eps, err := s.loadEpochs(ctx, q, names, `e.id=?`, []any{a.epochID.Int64}, 1)
			if err != nil {
				return nil, err
			}
			if len(eps) == 1 {
				a.view.Current = &eps[0]
			}
		}
		pathID := a.lastPath
		if !pathID.Valid && a.view.Current != nil {
			pathID = sql.NullInt64{Int64: a.view.Current.PathID, Valid: true}
		}
		if pathID.Valid {
			pv, err := loadPathView(ctx, q, names, pathID.Int64)
			if err != nil {
				return nil, err
			}
			a.view.Path = pv
		}
		out.Agents = append(out.Agents, a.view)
	}
	return out, nil
}

// agentStatus maps a monitor_status row onto the route view's status.
// Mirrors the target-status reading: only an agent's own report for the
// current generation is believed, except the server-decided upgrade verdict,
// which no report will ever replace. A target blocked by the agent's local
// target policy reads as permission_blocked — it is a local policy refusal,
// remedied the same way.
func agentStatus(status sql.NullString, reason string, source sql.NullString, serial sql.NullInt64, current int) string {
	if !status.Valid || !serial.Valid || int(serial.Int64) != current {
		return StatusPending
	}
	if reason == config.ReasonAgentUpgradeRequired {
		return StatusAgentUpgradeRequired
	}
	if source.String != "reported" {
		return StatusPending
	}
	switch status.String {
	case wire.MonitorStatusActive:
		return StatusActive
	case wire.MonitorStatusPermissionBlocked, wire.MonitorStatusTargetBlocked:
		return StatusPermissionBlocked
	case wire.MonitorStatusUnsupported:
		return StatusUnsupported
	}
	return StatusPending
}

// Epochs lists a monitor's eras overlapping [From, To], newest first.
func (s *Service) Epochs(ctx context.Context, targetID string, eq EpochQuery) ([]RouteEpoch, error) {
	q := s.db.Read()
	if _, err := s.traceTarget(ctx, q, targetID); err != nil {
		return nil, err
	}
	where := `e.monitor_id=?`
	args := []any{targetID}
	if eq.AgentID != "" {
		where += ` AND e.agent_id=?`
		args = append(args, eq.AgentID)
	}
	if !eq.From.IsZero() {
		where += ` AND e.end_ts >= ?`
		args = append(args, eq.From.Unix())
	}
	if !eq.To.IsZero() {
		where += ` AND e.start_ts <= ?`
		args = append(args, eq.To.Unix())
	}
	return s.loadEpochs(ctx, q, newASNames(q), where, args, clampLimit(eq.Limit))
}

func (s *Service) loadEpochs(ctx context.Context, q store.Executor, names *asNames, where string, args []any, limit int) ([]RouteEpoch, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT e.id, e.agent_id, e.path_id, p.as_path, e.start_ts, e.end_ts, e.run_count, e.deviation_count,
		       e.reached_runs, e.dest_ip, e.local_asn, e.rtt_hist, e.rtt_count, e.rtt_sum, e.rtt_min, e.rtt_max
		FROM route_epochs e JOIN route_paths p ON p.id = e.path_id
		WHERE `+where+`
		ORDER BY e.start_ts DESC, e.id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	out := []RouteEpoch{}
	var asBlobs [][]byte
	for rows.Next() {
		var e RouteEpoch
		var asBlob, histBlob []byte
		var start, end int64
		var reached int
		var localASN sql.NullInt64
		var h histogram
		if err := rows.Scan(&e.ID, &e.AgentID, &e.PathID, &asBlob, &start, &end, &e.RunCount, &e.DeviationCount,
			&reached, &e.DestIP, &localASN, &histBlob, &h.count, &h.sum, &h.min, &h.max); err != nil {
			rows.Close()
			return nil, err
		}
		e.StartAt, e.EndAt = rfc3339(start), rfc3339(end)
		if localASN.Valid {
			v := uint32(localASN.Int64)
			e.LocalASN = &v
		}
		full := decodeHist(histBlob)
		full.count, full.sum, full.min, full.max = h.count, h.sum, h.min, h.max
		e.RTT = full.summary()
		if e.RunCount > 0 {
			e.ReachedRatio = round4(float64(reached) / float64(e.RunCount))
		}
		e.Variants = []RouteVariant{}
		out = append(out, e)
		asBlobs = append(asBlobs, asBlob)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		as, err := decodeASPath(asBlobs[i])
		if err != nil {
			return nil, err
		}
		if out[i].ASPath, err = names.hops(ctx, as); err != nil {
			return nil, err
		}
		vrows, err := q.QueryContext(ctx,
			`SELECT path_id, count FROM route_epoch_variants WHERE epoch_id=? ORDER BY count DESC, path_id`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for vrows.Next() {
			var v RouteVariant
			if err := vrows.Scan(&v.PathID, &v.Count); err != nil {
				vrows.Close()
				return nil, err
			}
			out[i].Variants = append(out[i].Variants, v)
		}
		vrows.Close()
		if err := vrows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func round4(v float64) float64 { return float64(int64(v*10000+0.5)) / 10000 }

// Changes lists a monitor's confirmed changes, newest first.
func (s *Service) Changes(ctx context.Context, targetID string, cq ChangeQuery) ([]RouteChange, error) {
	q := s.db.Read()
	if _, err := s.traceTarget(ctx, q, targetID); err != nil {
		return nil, err
	}
	where := `c.monitor_id=?`
	args := []any{targetID}
	if cq.AgentID != "" {
		where += ` AND c.agent_id=?`
		args = append(args, cq.AgentID)
	}
	if !cq.Before.IsZero() {
		where += ` AND c.confirmed_at < ?`
		args = append(args, cq.Before.Unix())
	}
	return s.loadChanges(ctx, q, newASNames(q), where, args, clampLimit(cq.Limit))
}

type changeRefs struct {
	beforeRun, afterRun sql.NullInt64
}

func (s *Service) loadChanges(ctx context.Context, q store.Executor, names *asNames, where string, args []any, limit int) ([]RouteChange, error) {
	out, _, err := s.loadChangesWithRefs(ctx, q, names, where, args, limit)
	return out, err
}

func (s *Service) loadChangesWithRefs(ctx context.Context, q store.Executor, names *asNames, where string, args []any, limit int) ([]RouteChange, []changeRefs, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT c.id, c.monitor_id, c.agent_id, COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), c.agent_id),
		       c.kind, c.segment, c.diverge_ttl, c.confirmed_at, c.from_epoch_id, c.to_epoch_id,
		       c.before_run_id, c.after_run_id
		FROM route_changes c LEFT JOIN agents a ON a.id = c.agent_id
		WHERE `+where+`
		ORDER BY c.confirmed_at DESC, c.id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, nil, err
	}
	out := []RouteChange{}
	var refs []changeRefs
	for rows.Next() {
		var c RouteChange
		var ttl sql.NullInt64
		var at int64
		var ref changeRefs
		if err := rows.Scan(&c.ID, &c.MonitorID, &c.AgentID, &c.AgentName, &c.Kind, &c.Segment, &ttl, &at,
			&c.FromEpochID, &c.ToEpochID, &ref.beforeRun, &ref.afterRun); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if ttl.Valid {
			v := int(ttl.Int64)
			c.DivergeTTL = &v
		}
		c.ConfirmedAt = rfc3339(at)
		out = append(out, c)
		refs = append(refs, ref)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for i := range out {
		for _, side := range []struct {
			id  int64
			as  *[]ASHop
			rtt **RouteRTT
		}{{out[i].FromEpochID, &out[i].FromASPath, &out[i].RTTBefore}, {out[i].ToEpochID, &out[i].ToASPath, &out[i].RTTAfter}} {
			eps, err := s.loadEpochs(ctx, q, names, `e.id=?`, []any{side.id}, 1)
			if err != nil {
				return nil, nil, err
			}
			*side.as = []ASHop{}
			if len(eps) == 1 {
				*side.as = eps[0].ASPath
				*side.rtt = eps[0].RTT
			}
		}
	}
	return out, refs, nil
}

// ChangeDetail returns one change with both eras' paths and the cited runs.
func (s *Service) ChangeDetail(ctx context.Context, id int64) (*RouteChangeDetail, error) {
	q := s.db.Read()
	names := newASNames(q)
	cs, refs, err := s.loadChangesWithRefs(ctx, q, names, `c.id=?`, []any{id}, 1)
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, ErrChangeNotFound
	}
	d := &RouteChangeDetail{Change: cs[0]}
	for _, side := range []struct {
		epoch int64
		path  *RoutePathView
	}{{cs[0].FromEpochID, &d.Before}, {cs[0].ToEpochID, &d.After}} {
		var pathID int64
		if err := q.QueryRowContext(ctx, `SELECT path_id FROM route_epochs WHERE id=?`, side.epoch).Scan(&pathID); err != nil {
			return nil, err
		}
		pv, err := loadPathView(ctx, q, names, pathID)
		if err != nil {
			return nil, err
		}
		*side.path = *pv
	}
	if d.BeforeRun, err = loadRunDetail(ctx, q, names, refs[0].beforeRun); err != nil {
		return nil, err
	}
	if d.AfterRun, err = loadRunDetail(ctx, q, names, refs[0].afterRun); err != nil {
		return nil, err
	}
	return d, nil
}

// ---- path and run rendering ----

type ipRow struct {
	ip, host, prefix string
	asn              uint32
}

func loadIPs(ctx context.Context, q store.Executor, ids map[int64]bool) (map[int64]ipRow, error) {
	out := map[int64]ipRow{}
	var args []any
	for id := range ids {
		if id > 0 {
			args = append(args, id)
		}
	}
	if len(args) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx,
		`SELECT id, ip, hostname, asn, prefix FROM route_ips WHERE id IN (`+placeholders(len(args))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var r ipRow
		if err := rows.Scan(&id, &r.ip, &r.host, &r.asn, &r.prefix); err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, rows.Err()
}

func loadPathView(ctx context.Context, q store.Executor, names *asNames, pathID int64) (*RoutePathView, error) {
	var ipBlob, asBlob []byte
	var reached int
	if err := q.QueryRowContext(ctx, `SELECT ip_path, as_path, reached FROM route_paths WHERE id=?`, pathID).
		Scan(&ipBlob, &asBlob, &reached); err != nil {
		return nil, err
	}
	ip, err := decodeIPPath(ipBlob)
	if err != nil {
		return nil, err
	}
	as, err := decodeASPath(asBlob)
	if err != nil {
		return nil, err
	}
	ids := map[int64]bool{}
	for _, hop := range ip {
		for _, id := range hop {
			ids[id] = true
		}
	}
	ipRows, err := loadIPs(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	pv := &RoutePathView{PathID: pathID, Reached: reached == 1, Hops: []RouteHopView{}}
	if pv.ASPath, err = names.hops(ctx, as); err != nil {
		return nil, err
	}
	for i, hop := range ip {
		hv := RouteHopView{TTL: i + 1, Responders: []RouteResponder{}, Timeout: len(hop) == 0}
		for _, id := range hop {
			r := ipRows[id]
			resp := RouteResponder{IP: r.ip, Hostname: r.host, Prefix: r.prefix}
			if r.asn != 0 {
				a := r.asn
				resp.ASN = &a
				m, err := names.get(ctx, a)
				if err != nil {
					return nil, err
				}
				resp.ASName, resp.ASCountry = m.name, m.country
			}
			hv.Responders = append(hv.Responders, resp)
		}
		sort.SliceStable(hv.Responders, func(x, y int) bool { return hv.Responders[x].IP < hv.Responders[y].IP })
		pv.Hops = append(pv.Hops, hv)
	}
	return pv, nil
}

func loadRunDetail(ctx context.Context, q store.Executor, names *asNames, id sql.NullInt64) (*RouteRunDetail, error) {
	if !id.Valid {
		return nil, nil
	}
	var ts int64
	var reached int
	var blob []byte
	d := &RouteRunDetail{Hops: []RouteRunHop{}}
	err := q.QueryRowContext(ctx, `SELECT run_ts, dest_ip, reached, hops FROM route_runs_detail WHERE id=?`, id.Int64).
		Scan(&ts, &d.DestIP, &reached, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.RunAt, d.Reached = rfc3339(ts), reached == 1
	hops, err := decodeDetail(blob)
	if err != nil {
		return nil, err
	}
	ids := map[int64]bool{}
	for _, h := range hops {
		for _, a := range h.attempts {
			ids[a.ipID] = true
		}
	}
	ipRows, err := loadIPs(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	for _, h := range hops {
		rh := RouteRunHop{TTL: h.ttl, Attempts: []RouteRunAttempt{}}
		for _, a := range h.attempts {
			ra := RouteRunAttempt{Timeout: a.ipID == 0}
			if a.ipID != 0 {
				r := ipRows[a.ipID]
				ra.IP, ra.Hostname = r.ip, r.host
				if r.asn != 0 {
					v := r.asn
					ra.ASN = &v
					m, err := names.get(ctx, v)
					if err != nil {
						return nil, err
					}
					ra.ASName = m.name
				}
				if a.rtt {
					v := a.rttMs
					ra.RTTMs = &v
				}
			}
			rh.Attempts = append(rh.Attempts, ra)
		}
		d.Hops = append(d.Hops, rh)
	}
	return d, nil
}

// asNames is a per-request cache of asn_info.
type asNames struct {
	q     store.Executor
	cache map[uint32]asMeta
}

type asMeta struct{ name, country string }

func newASNames(q store.Executor) *asNames { return &asNames{q: q, cache: map[uint32]asMeta{}} }

func (n *asNames) get(ctx context.Context, asn uint32) (asMeta, error) {
	if m, ok := n.cache[asn]; ok {
		return m, nil
	}
	var m asMeta
	err := n.q.QueryRowContext(ctx, `SELECT name, country FROM asn_info WHERE asn=?`, asn).Scan(&m.name, &m.country)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return m, err
	}
	n.cache[asn] = m
	return m, nil
}

func (n *asNames) hops(ctx context.Context, as []uint32) ([]ASHop, error) {
	out := make([]ASHop, 0, len(as))
	for _, a := range as {
		m, err := n.get(ctx, a)
		if err != nil {
			return nil, err
		}
		out = append(out, ASHop{ASN: a, ASName: m.name, ASCountry: m.country})
	}
	return out, nil
}
