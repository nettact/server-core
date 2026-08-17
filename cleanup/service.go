// Package cleanup runs history-data deletion as durable, restart-safe jobs. A
// job deletes selected time-series history (whole series, or a time range of
// each) either from an explicit user selection or from the set of orphaned series
// left by deleted monitors/agents ("orphans" mode). The API layer creates and
// reads jobs; a server worker drives Tick to execute the queued one, and
// Recover requeues a job interrupted by a restart.
//
// Only metrics tables are touched. Incidents, alerts, snapshots and the audit log
// are stored separately (frozen evidence) and are never deleted here — the
// preview surfaces this explicitly (NotCascaded).
package cleanup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
)

// NotCascaded lists the data classes a cleanup job does NOT remove, returned in
// the preview so the console can state it plainly and the contract can't drift.
var NotCascaded = []string{"incidents", "alerts", "snapshots", "audit"}

// ErrJobRunning is returned by CreateJob when a job is already queued or running
// (one at a time). The handler maps it to 409 with the existing job id.
var ErrJobRunning = errors.New("cleanup job already running")

// ValidationError is a client-fixable rejection (unknown series, blocked live
// item, bad range). The handler maps it to 400.
type ValidationError struct{ Msg string }

func (e ValidationError) Error() string { return e.Msg }

// Service owns cleanup jobs over the metrics store.
type Service struct {
	db      *store.DB
	metrics *metrics.Store
}

func New(db *store.DB, m *metrics.Store) *Service { return &Service{db: db, metrics: m} }

// ---- request/response shapes ----

// ItemKey is one logical series (all generations) addressed by its natural key.
// monitor_id="" is a system series.
type ItemKey struct {
	AgentID   string `json:"agent_id"`
	MonitorID string `json:"monitor_id"`
	Kind      string `json:"kind"`
	Target    string `json:"target"`
}

// Selection is the shared body of preview and create: what to delete and over
// what window. from_ts==0 && to_ts==0 means the whole series; otherwise [from,to).
type Selection struct {
	Mode      string    `json:"mode"` // "selection" | "orphans"
	Items     []ItemKey `json:"items"`
	FromTS    int64     `json:"from_ts"`
	ToTS      int64     `json:"to_ts"`
	AllowLive bool      `json:"allow_live"`
}

// CreateRequest adds the client idempotency token.
type CreateRequest struct {
	Selection
	ClientToken string `json:"client_token"`
}

// PreviewItem is one resolved item with exact per-tier counts and any block.
type PreviewItem struct {
	ItemKey
	Label         string `json:"label"`
	Status        string `json:"status"` // live|deleted|system
	Series        int    `json:"series"`
	Samples       int64  `json:"samples"`
	Rollup1m      int64  `json:"rollup_1m"`
	Rollup1h      int64  `json:"rollup_1h"`
	Rollup1d      int64  `json:"rollup_1d"`
	Blocked       bool   `json:"blocked"`
	BlockedReason string `json:"blocked_reason,omitempty"`
}

// PreviewResponse is the dry-run result.
type PreviewResponse struct {
	Items       []PreviewItem `json:"items"`
	Totals      Totals        `json:"totals"`
	NotCascaded []string      `json:"not_cascaded"`
}

// Totals aggregates the deletable (non-blocked) items.
type Totals struct {
	Series  int   `json:"series"`
	Samples int64 `json:"samples"`
	Rollups int64 `json:"rollups"`
}

// resolved is an item turned into concrete series ids plus display/status.
type resolved struct {
	key    ItemKey
	ids    []int64
	status string
	label  string
}

// ---- classification / naming ----

func classify(agentPresent bool, monitorID string, monitorPresent bool) string {
	if !agentPresent {
		return "deleted"
	}
	if monitorID == "" {
		return "system"
	}
	if monitorPresent {
		return "live"
	}
	return "deleted"
}

// protected reports whether a status is actively-written data of a present agent,
// which live protection guards unless the caller opts in with a bounded range.
func protected(status string) bool { return status == "live" || status == "system" }

// nameSets loads the monitor-id→name and agent-id→display-name maps for a site,
// used for status classification and frozen item labels.
func (s *Service) nameSets(ctx context.Context, siteID string) (monitors, agents map[string]string, err error) {
	monitors = map[string]string{}
	agents = map[string]string{}
	mrows, err := s.db.Read().QueryContext(ctx, `SELECT id, COALESCE(name,'') FROM probe_tasks WHERE site_id=?`, siteID)
	if err != nil {
		return nil, nil, err
	}
	for mrows.Next() {
		var id, name string
		if err := mrows.Scan(&id, &name); err != nil {
			mrows.Close()
			return nil, nil, err
		}
		monitors[id] = name
	}
	mrows.Close()
	if err := mrows.Err(); err != nil {
		return nil, nil, err
	}
	arows, err := s.db.Read().QueryContext(ctx, `SELECT id, COALESCE(NULLIF(display_name,''), hostname, '') FROM agents WHERE site_id=?`, siteID)
	if err != nil {
		return nil, nil, err
	}
	for arows.Next() {
		var id, name string
		if err := arows.Scan(&id, &name); err != nil {
			arows.Close()
			return nil, nil, err
		}
		agents[id] = name
	}
	arows.Close()
	return monitors, agents, arows.Err()
}

func label(monitors, agents map[string]string, k ItemKey) string {
	subject := k.Target
	if name := monitors[k.MonitorID]; name != "" {
		subject = name
	}
	agent := agents[k.AgentID]
	if agent == "" {
		agent = k.AgentID
	}
	var b strings.Builder
	if subject != "" {
		b.WriteString(subject)
		b.WriteString(" · ")
	}
	b.WriteString(k.Kind)
	if k.Target != "" && k.Target != subject {
		b.WriteString(" (")
		b.WriteString(k.Target)
		b.WriteString(")")
	}
	b.WriteString(" @ ")
	b.WriteString(agent)
	return b.String()
}

// ---- orphan resolution ----

// orphanKeys returns the distinct logical series whose monitor or agent no longer
// exists (the one-click "clean deleted targets" set), site-scoped.
func (s *Service) orphanKeys(ctx context.Context, siteID string) ([]ItemKey, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT DISTINCT agent_id, COALESCE(monitor_id,''), kind, COALESCE(target,'')
		FROM series
		WHERE site_id=?
		  AND ( (monitor_id != '' AND monitor_id NOT IN (SELECT id FROM probe_tasks))
		     OR (agent_id NOT IN (SELECT id FROM agents)) )
		ORDER BY agent_id, monitor_id, kind, target`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ItemKey
	for rows.Next() {
		var k ItemKey
		if err := rows.Scan(&k.AgentID, &k.MonitorID, &k.Kind, &k.Target); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// allKeys returns every distinct logical series in the site (the "delete all data"
// set).
func (s *Service) allKeys(ctx context.Context, siteID string) ([]ItemKey, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT DISTINCT agent_id, COALESCE(monitor_id,''), kind, COALESCE(target,'')
		FROM series WHERE site_id=?
		ORDER BY agent_id, monitor_id, kind, target`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ItemKey
	for rows.Next() {
		var k ItemKey
		if err := rows.Scan(&k.AgentID, &k.MonitorID, &k.Kind, &k.Target); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// resolveItems turns a selection into concrete resolved items, validating (in
// selection mode) that each key exists. The "orphans" and "all" modes ignore
// req.Items and derive the key set server-side.
func (s *Service) resolveItems(ctx context.Context, siteID string, sel Selection, monitors, agents map[string]string) ([]resolved, error) {
	keys := sel.Items
	switch sel.Mode {
	case "orphans":
		var err error
		if keys, err = s.orphanKeys(ctx, siteID); err != nil {
			return nil, err
		}
	case "all":
		var err error
		if keys, err = s.allKeys(ctx, siteID); err != nil {
			return nil, err
		}
	}
	if len(keys) == 0 {
		return nil, ValidationError{"no series selected"}
	}
	out := make([]resolved, 0, len(keys))
	for _, k := range keys {
		ids, err := s.metrics.ResolveSeriesIDs(ctx, siteID, k.AgentID, k.MonitorID, k.Kind, k.Target)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			// Never trust a free-text key: an item that matches no stored series is a
			// client/stale error, not a silent no-op.
			return nil, ValidationError{fmt.Sprintf("unknown series: %s/%s/%s/%s", k.AgentID, k.MonitorID, k.Kind, k.Target)}
		}
		_, agentPresent := agents[k.AgentID]
		_, monitorPresent := monitors[k.MonitorID]
		out = append(out, resolved{
			key:    k,
			ids:    ids,
			status: classify(agentPresent, k.MonitorID, monitorPresent),
			label:  label(monitors, agents, k),
		})
	}
	return out, nil
}

// blockReason returns "" when the item is deletable under the selection, or the
// reason it is blocked. Live/system data of a present agent is protected only
// until the caller opts in with allow_live; once opted in, a full or ranged delete
// is permitted (the operator's explicit selection is the consent).
func blockReason(status string, sel Selection) string {
	if !protected(status) {
		return ""
	}
	if !sel.AllowLive {
		return "live_protected"
	}
	return ""
}

// ---- preview ----

func (s *Service) Preview(ctx context.Context, siteID string, sel Selection) (PreviewResponse, error) {
	if err := validateRange(sel); err != nil {
		return PreviewResponse{}, err
	}
	monitors, agents, err := s.nameSets(ctx, siteID)
	if err != nil {
		return PreviewResponse{}, err
	}
	items, err := s.resolveItems(ctx, siteID, sel, monitors, agents)
	if err != nil {
		return PreviewResponse{}, err
	}
	resp := PreviewResponse{NotCascaded: NotCascaded}
	for _, it := range items {
		counts, err := s.metrics.CountRange(ctx, it.ids, sel.FromTS, sel.ToTS)
		if err != nil {
			return PreviewResponse{}, err
		}
		pi := PreviewItem{
			ItemKey: it.key, Label: it.label, Status: it.status,
			Series:   len(it.ids),
			Samples:  counts.Samples,
			Rollup1m: counts.Rollup1m, Rollup1h: counts.Rollup1h, Rollup1d: counts.Rollup1d,
		}
		if reason := blockReason(it.status, sel); reason != "" {
			pi.Blocked = true
			pi.BlockedReason = reason
		} else {
			resp.Totals.Series += pi.Series
			resp.Totals.Samples += counts.Samples
			resp.Totals.Rollups += counts.Rollups()
		}
		resp.Items = append(resp.Items, pi)
	}
	return resp, nil
}

func validateRange(sel Selection) error {
	if sel.FromTS < 0 || sel.ToTS < 0 {
		return ValidationError{"negative timestamp"}
	}
	if (sel.FromTS != 0 || sel.ToTS != 0) && sel.ToTS <= sel.FromTS {
		return ValidationError{"to_ts must be greater than from_ts"}
	}
	return nil
}

// ---- create ----

// CreateJob validates and enqueues a job. Returns (jobID, created): created=false
// means an existing job with the same client_token was returned (idempotent).
func (s *Service) CreateJob(ctx context.Context, siteID string, req CreateRequest) (string, bool, error) {
	if err := validateRange(req.Selection); err != nil {
		return "", false, err
	}
	// Idempotent resubmit: same token → same job.
	if req.ClientToken != "" {
		var existing string
		err := s.db.Read().QueryRowContext(ctx, `SELECT id FROM cleanup_jobs WHERE client_token=?`, req.ClientToken).Scan(&existing)
		if err == nil {
			return existing, false, nil
		}
		if err != sql.ErrNoRows {
			return "", false, err
		}
	}
	// One job at a time.
	var running string
	err := s.db.Read().QueryRowContext(ctx, `SELECT id FROM cleanup_jobs WHERE state IN('queued','running') ORDER BY created_at LIMIT 1`).Scan(&running)
	if err == nil {
		return running, false, fmt.Errorf("%w (job %s)", ErrJobRunning, running)
	}
	if err != sql.ErrNoRows {
		return "", false, err
	}

	monitors, agents, err := s.nameSets(ctx, siteID)
	if err != nil {
		return "", false, err
	}
	items, err := s.resolveItems(ctx, siteID, req.Selection, monitors, agents)
	if err != nil {
		return "", false, err
	}
	// Reject any blocked item: the preview already surfaced it, so a create with one
	// present is a client error, not something to silently drop.
	for _, it := range items {
		if reason := blockReason(it.status, req.Selection); reason != "" {
			return "", false, ValidationError{fmt.Sprintf("%q is protected (%s); deselect it or choose a time range", it.label, reason)}
		}
	}

	jobID := "cj_" + uuid.NewString()
	now := time.Now().UTC()
	// outID/outCreated carry the closure's result out. The ErrJobRunning path
	// returns a value AND an error, so the error branch below must return outID
	// too — for every other failure it is still "".
	var (
		outID      string
		outCreated bool
	)
	if err := s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		// Re-check token dedup and the one-job-at-a-time guarantee INSIDE the write
		// transaction. The read-pool checks above are only a fast path: SQLite has a
		// single writer, so two concurrent creates serialize on this connection, and
		// these in-tx reads see the other's committed job — closing the race where both
		// observed "nothing running" on the read pool and each inserted a job.
		if req.ClientToken != "" {
			var existing string
			err := wtx.QueryRowContext(ctx, `SELECT id FROM cleanup_jobs WHERE client_token=?`, req.ClientToken).Scan(&existing)
			if err == nil {
				// Dedup hit. The pre-contract code reached its deferred Rollback
				// here; returning nil instead commits, but nothing has been
				// written at this point, so the observable effect is identical.
				// Returning a fake error to force a rollback would be worse: it
				// would make a successful dedup indistinguishable from a failure.
				outID, outCreated = existing, false
				return nil, nil
			}
			if err != sql.ErrNoRows {
				return nil, err
			}
		}
		var runningTx string
		err := wtx.QueryRowContext(ctx, `SELECT id FROM cleanup_jobs WHERE state IN('queued','running') ORDER BY created_at LIMIT 1`).Scan(&runningTx)
		if err == nil {
			outID = runningTx
			return nil, fmt.Errorf("%w (job %s)", ErrJobRunning, runningTx)
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
		if _, err := wtx.ExecContext(ctx, `
		INSERT INTO cleanup_jobs(id, site_id, client_token, mode, from_ts, to_ts, allow_live, state, total_items, created_at)
		VALUES(?,?,?,?,?,?,?, 'queued', ?, ?)`,
			jobID, siteID, req.ClientToken, modeOf(req.Mode), req.FromTS, req.ToTS, boolInt(req.AllowLive), len(items), now); err != nil {
			return nil, err
		}
		stmt, err := wtx.PrepareContext(ctx, `
		INSERT INTO cleanup_job_items(job_id, idx, agent_id, monitor_id, kind, target, label, state)
		VALUES(?,?,?,?,?,?,?, 'pending')`)
		if err != nil {
			return nil, err
		}
		defer stmt.Close()
		for i, it := range items {
			if _, err := stmt.ExecContext(ctx, jobID, i, it.key.AgentID, it.key.MonitorID, it.key.Kind, it.key.Target, it.label); err != nil {
				return nil, err
			}
		}
		outID, outCreated = jobID, true
		return nil, nil
	}); err != nil {
		return outID, false, err
	}
	return outID, outCreated, nil
}

func modeOf(m string) string {
	switch m {
	case "orphans":
		return "orphans"
	case "all":
		return "all"
	default:
		return "selection"
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- reads ----

// Job is the full status of one job including its item list.
type Job struct {
	ID          string              `json:"id"`
	State       string              `json:"state"`
	Mode        string              `json:"mode"`
	FromTS      int64               `json:"from_ts"`
	ToTS        int64               `json:"to_ts"`
	TotalItems  int                 `json:"total_items"`
	DoneItems   int                 `json:"done_items"`
	FailedItems int                 `json:"failed_items"`
	Deleted     metrics.PurgeCounts `json:"deleted"`
	Error       string              `json:"error"`
	Items       []JobItem           `json:"items"`
	CreatedAt   *time.Time          `json:"created_at"`
	StartedAt   *time.Time          `json:"started_at"`
	FinishedAt  *time.Time          `json:"finished_at"`
}

// JobItem is one item's frozen label and outcome. The logical key is included so
// the console can build a "retry failed items" job from the failed subset.
type JobItem struct {
	Idx       int    `json:"idx"`
	AgentID   string `json:"agent_id"`
	MonitorID string `json:"monitor_id"`
	Kind      string `json:"kind"`
	Target    string `json:"target"`
	Label     string `json:"label"`
	State     string `json:"state"`
	Detail    string `json:"detail"`
}

// JobSummary is the lightweight per-job row for the recent-jobs list.
type JobSummary struct {
	ID          string     `json:"id"`
	State       string     `json:"state"`
	Mode        string     `json:"mode"`
	TotalItems  int        `json:"total_items"`
	DoneItems   int        `json:"done_items"`
	FailedItems int        `json:"failed_items"`
	CreatedAt   *time.Time `json:"created_at"`
}

func (s *Service) Job(ctx context.Context, id string) (Job, error) {
	var j Job
	var started, finished sql.NullTime
	var created time.Time
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT id, state, mode, from_ts, to_ts, total_items, done_items, failed_items,
		       del_samples, del_rollups, del_series, error, created_at, started_at, finished_at
		FROM cleanup_jobs WHERE id=?`, id).
		Scan(&j.ID, &j.State, &j.Mode, &j.FromTS, &j.ToTS, &j.TotalItems, &j.DoneItems, &j.FailedItems,
			&j.Deleted.Samples, &j.Deleted.Rollups, &j.Deleted.Series, &j.Error, &created, &started, &finished)
	if err == sql.ErrNoRows {
		return Job{}, sql.ErrNoRows
	}
	if err != nil {
		return Job{}, err
	}
	j.CreatedAt = &created
	j.StartedAt = timePtr(started)
	j.FinishedAt = timePtr(finished)

	rows, err := s.db.Read().QueryContext(ctx, `SELECT idx, agent_id, monitor_id, kind, target, label, state, detail FROM cleanup_job_items WHERE job_id=? ORDER BY idx`, id)
	if err != nil {
		return Job{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var it JobItem
		if err := rows.Scan(&it.Idx, &it.AgentID, &it.MonitorID, &it.Kind, &it.Target, &it.Label, &it.State, &it.Detail); err != nil {
			return Job{}, err
		}
		j.Items = append(j.Items, it)
	}
	return j, rows.Err()
}

func (s *Service) ListJobs(ctx context.Context, siteID string, limit int) ([]JobSummary, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, state, mode, total_items, done_items, failed_items, created_at
		FROM cleanup_jobs WHERE site_id=? ORDER BY created_at DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobSummary
	for rows.Next() {
		var js JobSummary
		var created time.Time
		if err := rows.Scan(&js.ID, &js.State, &js.Mode, &js.TotalItems, &js.DoneItems, &js.FailedItems, &created); err != nil {
			return nil, err
		}
		js.CreatedAt = &created
		out = append(out, js)
	}
	return out, rows.Err()
}

func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

// ---- inventory ----

// Inventory is the controlled selectable list, grouped agent -> monitor -> series
// (generations collapsed), plus the orphan summary for the one-click cleanup.
type Inventory struct {
	Agents  []InventoryAgent `json:"agents"`
	Orphans OrphanSummary    `json:"orphans"`
}

type InventoryAgent struct {
	AgentID      string           `json:"agent_id"`
	AgentName    string           `json:"agent_name"`
	AgentPresent bool             `json:"agent_present"`
	Groups       []InventoryGroup `json:"groups"`
}

type InventoryGroup struct {
	MonitorID   string            `json:"monitor_id"`
	MonitorName string            `json:"monitor_name"`
	Status      string            `json:"status"` // live|deleted|system
	Series      []InventorySeries `json:"series"`
}

type InventorySeries struct {
	Kind        string `json:"kind"`
	Target      string `json:"target"`
	Layer       string `json:"layer"`
	Unit        string `json:"unit"`
	Generations int    `json:"generations"`
	Earliest    int64  `json:"earliest_ts"`
	Latest      int64  `json:"latest_ts"`
	EstSamples  int64  `json:"est_samples"`
}

type OrphanSummary struct {
	Series     int   `json:"series"`
	Monitors   int   `json:"monitors"`
	EstSamples int64 `json:"est_samples"`
}

// Inventory reads the site's series, collapses generations, joins human-readable
// names + live/deleted/system status, and summarizes the orphaned set.
func (s *Service) Inventory(ctx context.Context, siteID string) (Inventory, error) {
	entries, err := s.metrics.CleanupInventory(ctx, siteID)
	if err != nil {
		return Inventory{}, err
	}
	monitors, agents, err := s.nameSets(ctx, siteID)
	if err != nil {
		return Inventory{}, err
	}

	// Collapse generations into one logical series per (agent, monitor, kind, target),
	// preserving the ordered entry stream (agent, monitor, kind, target, serial).
	type logical struct {
		agent, monitor, kind, target, layer, unit string
		gens                                      int
		earliest, latest, est                     int64
	}
	order := make([]string, 0)
	byKey := make(map[string]*logical)
	for _, e := range entries {
		lk := e.AgentID + "\x1f" + e.MonitorID + "\x1f" + e.Kind + "\x1f" + e.Target
		lg := byKey[lk]
		if lg == nil {
			lg = &logical{agent: e.AgentID, monitor: e.MonitorID, kind: e.Kind, target: e.Target, layer: e.Layer, unit: e.Unit}
			byKey[lk] = lg
			order = append(order, lk)
		}
		lg.gens++
		lg.est += e.EstSamples
		if e.Earliest != 0 && (lg.earliest == 0 || e.Earliest < lg.earliest) {
			lg.earliest = e.Earliest
		}
		if e.Latest > lg.latest {
			lg.latest = e.Latest
		}
	}

	inv := Inventory{}
	orphanMonitors := map[string]bool{}
	agentIdx := map[string]int{}
	// group index within an agent, keyed by agentID+monitorID
	groupIdx := map[string]int{}
	for _, lk := range order {
		lg := byKey[lk]
		_, agentPresent := agents[lg.agent]
		_, monitorPresent := monitors[lg.monitor]
		status := classify(agentPresent, lg.monitor, monitorPresent)

		ai, ok := agentIdx[lg.agent]
		if !ok {
			ai = len(inv.Agents)
			agentIdx[lg.agent] = ai
			name := agents[lg.agent]
			inv.Agents = append(inv.Agents, InventoryAgent{AgentID: lg.agent, AgentName: name, AgentPresent: agentPresent})
		}
		gk := lg.agent + "\x1f" + lg.monitor
		gi, ok := groupIdx[gk]
		if !ok {
			gi = len(inv.Agents[ai].Groups)
			groupIdx[gk] = gi
			inv.Agents[ai].Groups = append(inv.Agents[ai].Groups, InventoryGroup{
				MonitorID: lg.monitor, MonitorName: monitors[lg.monitor], Status: status,
			})
		}
		inv.Agents[ai].Groups[gi].Series = append(inv.Agents[ai].Groups[gi].Series, InventorySeries{
			Kind: lg.kind, Target: lg.target, Layer: lg.layer, Unit: lg.unit,
			Generations: lg.gens, Earliest: lg.earliest, Latest: lg.latest, EstSamples: lg.est,
		})

		if status == "deleted" {
			inv.Orphans.Series++
			inv.Orphans.EstSamples += lg.est
			if lg.monitor != "" {
				orphanMonitors[lg.monitor] = true
			}
		}
	}
	inv.Orphans.Monitors = len(orphanMonitors)
	return inv, nil
}
