package cleanup

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

// newTestService opens a fresh DB with the minimal fixtures a cleanup job needs
// (site, group, one present agent, one live monitor) and seeds series+samples for
// a live monitor, an orphaned (deleted-monitor) series, and a system series.
func newTestService(t *testing.T) (*store.DB, *metrics.Store, *Service) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id, name) VALUES('site_default','Default')`)
	exec(`INSERT INTO monitor_groups(id, site_id, name) VALUES('g1','site_default','G')`)
	exec(`INSERT INTO agents(id, site_id, public_key, token_hash, hostname, display_name) VALUES('ag1','site_default',x'00','h','host1','Agent One')`)
	exec(`INSERT INTO probe_tasks(id, site_id, group_id, kind, target, name) VALUES('probe_live','site_default','g1','icmp.rtt.ms','1.1.1.1','Live ping')`)

	m := metrics.New(db, tsstoretest.Open(t))
	now := alignDown(time.Now().Unix(), 60)
	seed := func(monitorID, kind, target string) {
		ms := []telemetry.Metric{}
		for i := int64(0); i < 120; i++ {
			ms = append(ms, telemetry.Metric{
				TS: time.Unix(now-3600+i, 0), Kind: telemetry.MetricKind(kind), Target: target,
				Value: 1, Unit: "ms", MonitorID: monitorID,
			})
		}
		ids, err := m.EnsureSeries(ctx, "ag1", "site_default", ms)
		if err != nil {
			t.Fatalf("EnsureSeries: %v", err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		if err := m.RewindForBatch(ctx, store.AdaptTx(tx, store.Standalone()), "ag1", ids, ms); err != nil {
			t.Fatalf("RewindForBatch: %v", err)
		}
		pendingDone := m.BeginPendingAppend(ids)
		defer func() {
			if pendingDone != nil {
				pendingDone()
			}
		}()
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if _, err := m.AppendRawSamples(ctx, "ag1", ids, ms); err != nil {
			t.Fatalf("AppendRawSamples: %v", err)
		}
		pendingDone()
		pendingDone = nil
		m.UpdateLatest("ag1", ids, ms)
	}
	seed("probe_live", "icmp.rtt.ms", "1.1.1.1")
	seed("probe_gone", "icmp.rtt.ms", "9.9.9.9") // no probe_tasks row -> orphan
	seed("", "host.cpu.pct", "host")             // system series

	return db, m, New(db, m)
}

func alignDown(ts, bucket int64) int64 { return (ts / bucket) * bucket }

func TestInventoryOrphans(t *testing.T) {
	_, _, svc := newTestService(t)
	ctx := context.Background()
	inv, err := svc.Inventory(ctx, "site_default")
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if inv.Orphans.Series != 1 || inv.Orphans.Monitors != 1 {
		t.Errorf("orphans = %+v, want 1 series / 1 monitor", inv.Orphans)
	}
	// The live monitor and system series must be classified live/system, not orphan.
	var live, system, deleted int
	for _, a := range inv.Agents {
		for _, g := range a.Groups {
			switch g.Status {
			case "live":
				live += len(g.Series)
			case "system":
				system += len(g.Series)
			case "deleted":
				deleted += len(g.Series)
			}
		}
	}
	if live != 1 || system != 1 || deleted != 1 {
		t.Errorf("status counts live=%d system=%d deleted=%d, want 1/1/1", live, system, deleted)
	}
}

func TestOrphanCleanupJob(t *testing.T) {
	db, m, svc := newTestService(t)
	ctx := context.Background()

	id, created, err := svc.CreateJob(ctx, "site_default", CreateRequest{
		Selection:   Selection{Mode: "orphans"},
		ClientToken: "tok1",
	})
	if err != nil || !created {
		t.Fatalf("CreateJob: id=%s created=%v err=%v", id, created, err)
	}
	if err := svc.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	job, err := svc.Job(ctx, id)
	if err != nil {
		t.Fatalf("Job: %v", err)
	}
	if job.State != "done" || job.DoneItems != 1 || job.Deleted.Series != 1 {
		t.Errorf("job = %+v, want done/1 done/1 series", job)
	}
	// The orphan series is gone; the live monitor's series survives.
	gone, _ := m.ResolveSeriesIDs(ctx, "site_default", "ag1", "probe_gone", "icmp.rtt.ms", "9.9.9.9")
	if len(gone) != 0 {
		t.Errorf("orphan series survived: %v", gone)
	}
	var live int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM series WHERE monitor_id='probe_live'`).Scan(&live)
	if live != 1 {
		t.Errorf("live series count = %d, want 1", live)
	}
}

func TestLiveProtection(t *testing.T) {
	_, _, svc := newTestService(t)
	ctx := context.Background()
	sel := Selection{
		Mode:  "selection",
		Items: []ItemKey{{AgentID: "ag1", MonitorID: "probe_live", Kind: "icmp.rtt.ms", Target: "1.1.1.1"}},
	}
	// Preview: the live item is blocked without allow_live.
	prev, err := svc.Preview(ctx, "site_default", sel)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(prev.Items) != 1 || !prev.Items[0].Blocked || prev.Items[0].BlockedReason != "live_protected" {
		t.Errorf("preview live item = %+v, want blocked/live_protected", prev.Items)
	}
	// Create with a blocked item is rejected as a validation error.
	if _, _, err := svc.CreateJob(ctx, "site_default", CreateRequest{Selection: sel}); err == nil {
		t.Error("CreateJob accepted a live-protected item, want ValidationError")
	} else if _, ok := err.(ValidationError); !ok {
		t.Errorf("CreateJob err = %T %v, want ValidationError", err, err)
	}
	// With allow_live set, a live item is deletable (full or ranged) — the operator's
	// explicit opt-in is the consent, so it is no longer blocked.
	sel.AllowLive = true
	prev, _ = svc.Preview(ctx, "site_default", sel)
	if prev.Items[0].Blocked {
		t.Errorf("allow_live live item still blocked: %+v", prev.Items[0])
	}
	if prev.Totals.Series != 1 {
		t.Errorf("allow_live totals = %+v, want 1 series deletable", prev.Totals)
	}
}

func TestDeleteAllMode(t *testing.T) {
	db, m, svc := newTestService(t)
	ctx := context.Background()
	id, created, err := svc.CreateJob(ctx, "site_default", CreateRequest{
		Selection: Selection{Mode: "all", AllowLive: true},
	})
	if err != nil || !created {
		t.Fatalf("CreateJob(all): id=%s created=%v err=%v", id, created, err)
	}
	if err := svc.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	job, _ := svc.Job(ctx, id)
	if job.State != "done" {
		t.Fatalf("job state = %q, want done", job.State)
	}
	// All sample data is gone. The orphan series' data was purged outright; the
	// live/system series were cut off (series.purge_cutoff), so nothing reads as
	// data anymore.
	entries, err := m.CleanupInventory(ctx, "site_default")
	if err != nil {
		t.Fatalf("CleanupInventory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("series rows after delete-all = %d, want 2 (live + system kept)", len(entries))
	}
	for _, e := range entries {
		if e.Earliest != 0 || e.Latest != 0 || e.EstSamples != 0 {
			t.Errorf("series %s/%s still reports data after delete-all: earliest=%d latest=%d est=%d",
				e.MonitorID, e.Kind, e.Earliest, e.Latest, e.EstSamples)
		}
	}
	// The orphan (deleted-monitor) series row is removed; the live monitor and the
	// present agent's system series rows are KEPT (they may be ingesting), just emptied.
	gone, _ := m.ResolveSeriesIDs(ctx, "site_default", "ag1", "probe_gone", "icmp.rtt.ms", "9.9.9.9")
	if len(gone) != 0 {
		t.Errorf("orphan series row survived delete-all: %v", gone)
	}
	var kept int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM series WHERE monitor_id='probe_live' OR monitor_id=''`).Scan(&kept)
	if kept != 2 {
		t.Errorf("live+system series rows = %d, want 2 (kept, emptied)", kept)
	}
}

// TestCrashWindowCountsPreserved simulates a crash after an item's data was
// deleted but before its completion was recorded: the persisted planned counts
// must be reused so the finished job does not report zero.
func TestCrashWindowCountsPreserved(t *testing.T) {
	db, m, svc := newTestService(t)
	ctx := context.Background()
	id, _, err := svc.CreateJob(ctx, "site_default", CreateRequest{Selection: Selection{Mode: "orphans"}, ClientToken: "cw"})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	// Simulate the interrupted run: planned counts persisted on the item, and the
	// underlying data already deleted (so a naive recompute would see zero).
	if _, err := db.ExecContext(ctx, `UPDATE cleanup_job_items SET detail=? WHERE job_id=?`, `{"s":120,"r":0,"e":1}`, id); err != nil {
		t.Fatalf("persist planned: %v", err)
	}
	ids, _ := m.ResolveSeriesIDs(ctx, "site_default", "ag1", "probe_gone", "icmp.rtt.ms", "9.9.9.9")
	if _, err := m.ClearSeriesHistory(ctx, ids); err != nil {
		t.Fatalf("simulate delete: %v", err)
	}
	if err := svc.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	job, _ := svc.Job(ctx, id)
	if job.State != "done" || job.Deleted.Samples != 120 || job.Deleted.Series != 1 {
		t.Errorf("recovered job = state %q deleted %+v, want done / 120 samples / 1 series", job.State, job.Deleted)
	}
}

func TestOneJobAtATimeAndDedup(t *testing.T) {
	_, _, svc := newTestService(t)
	ctx := context.Background()
	first, _, err := svc.CreateJob(ctx, "site_default", CreateRequest{Selection: Selection{Mode: "orphans"}, ClientToken: "t"})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	// Same token → same job, created=false, no error.
	again, created, err := svc.CreateJob(ctx, "site_default", CreateRequest{Selection: Selection{Mode: "orphans"}, ClientToken: "t"})
	if err != nil || created || again != first {
		t.Errorf("dedup = (%s, created=%v, err=%v), want (%s, false, nil)", again, created, err, first)
	}
	// A different token while one is queued → ErrJobRunning.
	if _, _, err := svc.CreateJob(ctx, "site_default", CreateRequest{Selection: Selection{Mode: "orphans"}, ClientToken: "t2"}); err == nil {
		t.Error("second job accepted while one queued, want ErrJobRunning")
	}
}

func TestRecoverRequeues(t *testing.T) {
	db, _, svc := newTestService(t)
	ctx := context.Background()
	id, _, err := svc.CreateJob(ctx, "site_default", CreateRequest{Selection: Selection{Mode: "orphans"}, ClientToken: "r"})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	// Simulate an interrupted run.
	if _, err := db.ExecContext(ctx, `UPDATE cleanup_jobs SET state='running' WHERE id=?`, id); err != nil {
		t.Fatalf("set running: %v", err)
	}
	if err := svc.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	var state string
	db.QueryRowContext(ctx, `SELECT state FROM cleanup_jobs WHERE id=?`, id).Scan(&state)
	if state != "queued" {
		t.Fatalf("after Recover state = %q, want queued", state)
	}
	if err := svc.Tick(ctx); err != nil {
		t.Fatalf("Tick after recover: %v", err)
	}
	job, _ := svc.Job(ctx, id)
	if job.State != "done" {
		t.Errorf("recovered job state = %q, want done", job.State)
	}
}
