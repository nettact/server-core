package incident

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// seedIncidentEnv wires an alert + incident service over a fresh DB with one site
// and one agent, and returns them (plus the shared bus) for the deletion
// regression tests below.
func seedIncidentEnv(t *testing.T) (*store.DB, *eventbus.Bus, *alert.Service, *Service, context.Context) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name) VALUES('site_default','H')`)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,display_name) VALUES('ag1','site_default',?,?,'raw','imini')`, []byte("k"), "th")

	bus := eventbus.New()
	alertSvc := alert.New(db, bus)
	// Real (channel-less) notification + settings services so onRaised's notify and
	// deep-link build don't nil-panic; with no channels configured, delivery no-ops.
	inc := New(db, bus, notification.New(db), settings.New(db))
	inc.Wire()
	return db, bus, alertSvc, inc, ctx
}

// seedFiringAlert seeds a probe_task + rule + a firing alert, then publishes the
// raised event so the incident opens/updates exactly as the live fire path would.
func seedFiringAlert(t *testing.T, db *store.DB, ctx context.Context, taskID, ruleID, ruleName, target, alertID string) {
	t.Helper()
	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO probe_tasks(id,site_id,kind,target,params,enabled,name,all_agents) VALUES(?,'site_default','icmp',?,'{}',1,?,1)`, taskID, target, ruleName)
	exec(`INSERT INTO alert_rules(id,site_id,probe_task_id,name,metric_kind,comparator,threshold,for_seconds,layer,severity,enabled,is_template) VALUES(?,'site_default',?,?,'probe.icmp.ok','lt',1,0,'wan','error',1,0)`, ruleID, taskID, ruleName)
	exec(`INSERT INTO alerts(id,rule_id,agent_id,site_id,target,state,value,started_at,fired_at) VALUES(?,?,'ag1','site_default',?,'firing',0,?,?)`, alertID, ruleID, target, now, now)
}

func timelineKinds(t *testing.T, inc *Service, ctx context.Context, incID string) []TimelineEntry {
	t.Helper()
	tl, err := inc.Timeline(ctx, incID)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	return tl
}

func hasEntry(tl []TimelineEntry, kind, substr string) bool {
	for _, e := range tl {
		if e.Kind == kind && strings.Contains(e.Message, substr) {
			return true
		}
	}
	return false
}

// TestDeleteLastActiveObjectTerminatesIncident covers acceptance #1/#3: deleting
// the only object with an active alert must close the incident with the deletion
// ("terminated") semantics — not strand it open, and not synthesize a false probe
// recovery.
func TestDeleteLastActiveObjectTerminatesIncident(t *testing.T) {
	db, bus, alertSvc, inc, ctx := seedIncidentEnv(t)
	seedFiringAlert(t, db, ctx, "pt_wlan", "rule_wlan", "WLAN 断开", "wlan", "al_wlan")

	// Raise → incident opens.
	pubRaised(t, bus, "rule_wlan", "WLAN 断开", "wlan", "al_wlan")
	incID := openIncident(t, db, ctx)

	// Delete the WLAN monitor while it is still firing.
	if err := alertSvc.TerminateForTask(ctx, "pt_wlan"); err != nil {
		t.Fatalf("TerminateForTask: %v", err)
	}

	state := incidentState(t, db, ctx, incID)
	if state != "resolved" {
		t.Fatalf("incident state = %q, want resolved (must not stay open)", state)
	}
	tl := timelineKinds(t, inc, ctx, incID)
	if !hasEntry(tl, "alert.terminated", "监控终止（对象已删除）") {
		t.Errorf("timeline missing termination entry: %+v", tl)
	}
	if !hasEntry(tl, "incident.terminated", "监控对象已删除") {
		t.Errorf("timeline missing incident-terminated close: %+v", tl)
	}
	// The bug: a deletion disguised as a healthy recovery. Guard against it.
	if hasEntry(tl, "alert.resolved", "恢复") || hasEntry(tl, "incident.resolved", "所有告警已恢复") {
		t.Errorf("deletion produced a false recovery entry: %+v", tl)
	}
}

// TestDeleteOneOfSeveralActiveObjects covers acceptance #2/#4: deleting one object
// in a multi-alert incident leaves the others firing and the incident open, and a
// later genuine recovery — not the deletion — is what finally closes it, without
// ever mutating the deleted object's timeline attribution.
func TestDeleteOneOfSeveralActiveObjects(t *testing.T) {
	db, bus, alertSvc, inc, ctx := seedIncidentEnv(t)
	seedFiringAlert(t, db, ctx, "pt_wlan", "rule_wlan", "WLAN 断开", "wlan", "al_wlan")
	seedFiringAlert(t, db, ctx, "pt_nat", "rule_nat", "NAT 失败", "stun.example", "al_nat")

	pubRaised(t, bus, "rule_wlan", "WLAN 断开", "wlan", "al_wlan")
	pubRaised(t, bus, "rule_nat", "NAT 失败", "stun.example", "al_nat")
	incID := openIncident(t, db, ctx)

	// Delete the WLAN object; the NAT alert is unaffected and keeps the incident open.
	if err := alertSvc.TerminateForTask(ctx, "pt_wlan"); err != nil {
		t.Fatalf("TerminateForTask: %v", err)
	}
	if s := incidentState(t, db, ctx, incID); s != "open" {
		t.Fatalf("incident closed early on partial deletion: state=%q", s)
	}
	var natFiring int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE id='al_nat' AND state='firing'`).Scan(&natFiring); err != nil {
		t.Fatalf("count nat: %v", err)
	}
	if natFiring != 1 {
		t.Fatalf("NAT alert no longer firing after unrelated deletion")
	}

	// NAT genuinely recovers → this closes the incident as a real recovery.
	if err := alertSvc.Update(ctx, alert.RuleView{ID: "rule_nat", Name: "NAT 失败", Layer: "wan", Severity: "error"},
		"ag1", "site_default", "stun.example", false, 1); err != nil {
		t.Fatalf("Update (nat recover): %v", err)
	}
	if s := incidentState(t, db, ctx, incID); s != "resolved" {
		t.Fatalf("incident not resolved after last alert recovered: state=%q", s)
	}

	tl := timelineKinds(t, inc, ctx, incID)
	// WLAN got a termination entry (never a "恢复" line).
	if !hasEntry(tl, "alert.terminated", "WLAN 断开") {
		t.Errorf("WLAN missing termination entry: %+v", tl)
	}
	// NAT got a genuine recovery entry, and the incident closed as a real recovery.
	if !hasEntry(tl, "alert.resolved", "NAT 失败") {
		t.Errorf("NAT missing recovery entry: %+v", tl)
	}
	if !hasEntry(tl, "incident.resolved", "所有告警已恢复") {
		t.Errorf("incident missing genuine-recovery close: %+v", tl)
	}
	// Second deletion of the already-removed object is idempotent: no new entries.
	before := len(tl)
	if err := alertSvc.TerminateForTask(ctx, "pt_wlan"); err != nil {
		t.Fatalf("TerminateForTask (repeat): %v", err)
	}
	if after := len(timelineKinds(t, inc, ctx, incID)); after != before {
		t.Errorf("repeat deletion added timeline entries: %d -> %d", before, after)
	}
}

func pubRaised(t *testing.T, bus *eventbus.Bus, ruleID, ruleName, target, alertID string) {
	t.Helper()
	bus.Publish(eventbus.TopicAlertRaised, alert.Raised{
		ID: alertID, RuleID: ruleID, RuleName: ruleName, AgentID: "ag1",
		SiteID: "site_default", Target: target, Layer: "wan", Severity: "error",
		Value: 0, At: time.Now().UTC(),
	})
}

func openIncident(t *testing.T, db *store.DB, ctx context.Context) string {
	t.Helper()
	var id string
	if err := db.QueryRowContext(ctx, `SELECT id FROM incidents WHERE site_id='site_default' ORDER BY opened_at DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("no incident opened: %v", err)
	}
	return id
}

func incidentState(t *testing.T, db *store.DB, ctx context.Context, incID string) string {
	t.Helper()
	var s string
	if err := db.QueryRowContext(ctx, `SELECT state FROM incidents WHERE id=?`, incID).Scan(&s); err != nil {
		t.Fatalf("incident state: %v", err)
	}
	return s
}
