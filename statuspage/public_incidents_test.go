package statuspage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nettact/server-core/store"
)

func seedPublicIncident(t *testing.T, db *store.DB, incidentID, signalID, agentID, targetID, severity, state string,
	observed time.Time, resolved *time.Time, secret string) {
	t.Helper()
	signalState := state
	if state == "open" {
		signalState = "firing"
	}
	var resolvedArg any
	if resolved != nil {
		resolvedArg = *resolved
	}
	mustExec(t, db, `
		INSERT INTO incidents(id, site_id, group_id, group_name, open_key, title, state,
		                      severity, summary, opened_at, first_observed_at, resolved_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		incidentID, "site_default", "internal-group", secret, "key-"+incidentID,
		secret, state, severity, secret, observed, observed, resolvedArg)
	mustExec(t, db, `
		INSERT INTO fault_signals(id, site_id, agent_id, target_id, detector_key,
		                          target_name, target_addr, agent_name, severity, state,
		                          observed_at, confirmed_at, resolved_at, incident_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		signalID, "site_default", agentID, targetID, "availability",
		secret, "https://"+secret+".internal", secret, severity, signalState,
		observed, observed, resolvedArg, incidentID)
}

func TestPublicIncidentHistoryIsOptInScopedAndSanitized(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	resolvedAt := now.Add(-2 * time.Hour)

	seedPublicIncident(t, db, "inc_target", "sig_target", "agent_a", "probe_1", "warn", "resolved",
		now.Add(-3*time.Hour), &resolvedAt, "TARGET-SECRET")
	seedPublicIncident(t, db, "inc_agent", "sig_agent", "agent_a", "", "warn", "open",
		now.Add(-time.Hour), nil, "AGENT-SECRET")
	// Neither resource is selected by the page, so this record must not exist from
	// the anonymous reader's point of view.
	seedPublicIncident(t, db, "inc_hidden", "sig_hidden", "agent_b", "probe_2", "critical", "open",
		now.Add(-30*time.Minute), nil, "HIDDEN-SECRET")

	spec := fullSpec()
	page, err := svc.Create(ctx, "site_default", spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.PublicIncidentHistory(ctx, spec.Slug); !errors.Is(err, ErrPageNotFound) {
		t.Fatalf("history while disabled = %v, want ErrPageNotFound", err)
	}

	spec.ShowIncidents = true
	if _, err := svc.Update(ctx, page.ID, spec); err != nil {
		t.Fatalf("enable incidents: %v", err)
	}
	got, err := svc.PublicIncidentHistory(ctx, spec.Slug)
	if err != nil {
		t.Fatalf("PublicIncidentHistory: %v", err)
	}
	if got.WindowStart != now.AddDate(0, 0, -PublicIncidentWindowDays) {
		t.Fatalf("window_start = %v", got.WindowStart)
	}
	if len(got.Incidents) != 2 {
		t.Fatalf("incidents = %+v, want selected target + selected agent only", got.Incidents)
	}
	if got.Incidents[0].State != "open" || got.Incidents[0].Subjects[0].Type != "agent" ||
		got.Incidents[0].Subjects[0].Name != "Alpha" {
		t.Fatalf("open agent incident = %+v", got.Incidents[0])
	}
	if got.Incidents[1].State != "resolved" || got.Incidents[1].Subjects[0].Type != "target" ||
		got.Incidents[1].Subjects[0].Name != "Website" {
		t.Fatalf("resolved target incident = %+v", got.Incidents[1])
	}

	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{
		"inc_target", "sig_target", "agent_a", "probe_1", "site_default",
		"TARGET-SECRET", "AGENT-SECRET", "HIDDEN-SECRET", "internal-group", ".internal",
		"summary", "attribution", "notification", "diagnostic",
	} {
		if strings.Contains(string(body), leak) {
			t.Errorf("public history leaked %q: %s", leak, body)
		}
	}
}

func TestPublicIncidentHistoryKeepsOldOpenIncidentButDropsOldResolvedIncident(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	old := now.AddDate(0, 0, -PublicIncidentWindowDays-10)
	oldResolved := old.Add(time.Hour)
	seedPublicIncident(t, db, "inc_old_open", "sig_old_open", "agent_a", "probe_1", "warn", "open", old, nil, "old-open")
	seedPublicIncident(t, db, "inc_old_resolved", "sig_old_resolved", "agent_a", "", "info", "resolved", old, &oldResolved, "old-resolved")

	spec := fullSpec()
	spec.ShowIncidents = true
	if _, err := svc.Create(ctx, "site_default", spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.PublicIncidentHistory(ctx, spec.Slug)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(got.Incidents) != 1 || got.Incidents[0].State != "open" {
		t.Fatalf("incidents = %+v, want only the old incident that is still open", got.Incidents)
	}
}

func TestPublicIncidentHistoryCachesTheExpensiveSnapshot(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	seedPublicIncident(t, db, "inc_cached", "sig_cached", "agent_a", "probe_1", "warn", "open",
		now.Add(-time.Hour), nil, "cached")

	spec := fullSpec()
	spec.ShowIncidents = true
	if _, err := svc.Create(ctx, "site_default", spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	first, err := svc.PublicIncidentHistory(ctx, spec.Slug)
	if err != nil || len(first.Incidents) != 1 || first.Incidents[0].State != "open" {
		t.Fatalf("first history = %+v, %v", first, err)
	}

	resolved := now.Add(-time.Minute)
	mustExec(t, db, `UPDATE fault_signals SET state='resolved', resolved_at=? WHERE id='sig_cached'`, resolved)
	second, err := svc.PublicIncidentHistory(ctx, spec.Slug)
	if err != nil || second.Incidents[0].State != "open" {
		t.Fatalf("history inside TTL = %+v, %v; want cached open state", second, err)
	}

	now = now.Add(defaultCacheTTL + time.Second)
	third, err := svc.PublicIncidentHistory(ctx, spec.Slug)
	if err != nil || third.Incidents[0].State != "resolved" {
		t.Fatalf("history after TTL = %+v, %v; want refreshed resolved state", third, err)
	}
}

func TestPublicIncidentHistoryCacheIsBoundToCurrentSelection(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	seedPublicIncident(t, db, "inc_one", "sig_one", "agent_a", "", "warn", "open",
		now.Add(-2*time.Hour), nil, "one")
	seedPublicIncident(t, db, "inc_two", "sig_two", "agent_b", "", "warn", "open",
		now.Add(-time.Hour), nil, "two")

	spec := fullSpec()
	spec.ShowIncidents = true
	spec.TargetIDs = nil
	_, err := svc.Create(ctx, "site_default", spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	first, err := svc.PublicIncidentHistory(ctx, spec.Slug)
	if err != nil || len(first.Incidents) != 1 || first.Incidents[0].Subjects[0].Name != "Alpha" {
		t.Fatalf("first selection history = %+v, %v", first, err)
	}

	// Page selection is by group CURRENT membership. Change that membership
	// directly, without touching the page, and the cache key must still change.
	mustExec(t, db, `DELETE FROM agent_group_members WHERE group_id='grp_a' AND agent_id='agent_a'`)
	mustExec(t, db, `INSERT INTO agent_group_members(group_id, agent_id) VALUES('grp_a','agent_b')`)
	second, err := svc.PublicIncidentHistory(ctx, spec.Slug)
	if err != nil || len(second.Incidents) != 1 || second.Incidents[0].Subjects[0].Name != "" {
		t.Fatalf("updated selection history = %+v, %v; cache crossed publication boundary", second, err)
	}
}
