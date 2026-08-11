package statuspage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nettact/server-core/agentstatus"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/targetstatus"
)

func mustExec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// newFixture opens a database with one site, two agents and two targets, and the
// service wired over the real aggregations. A nil metrics store is legal for both
// of them: availability is simply omitted, which is what a fresh install looks
// like anyway.
func newFixture(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	db := storetest.Open(t)
	now := time.Now().UTC()
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, now)
	mustExec(t, db, `INSERT INTO sites(id,name,created_at) VALUES('site_other','other',?)`, now)
	mustExec(t, db, `INSERT INTO monitor_groups(id,site_id,name,is_default) VALUES('mg','site_default','Default',1)`)
	mustExec(t, db, `INSERT INTO monitor_groups(id,site_id,name,is_default) VALUES('mg_other','site_other','Default',1)`)

	seedAgent(t, db, "agent_a", "site_default", "Alpha", "online")
	seedAgent(t, db, "agent_b", "site_default", "", "offline")
	// Pages publish GROUPS, so the fixture gives each agent its own group plus a
	// group holding both — enough to tell "the page's selection" apart from "the
	// group's membership".
	seedAgentGroup(t, db, "grp_a", "site_default", "Alpha group", "agent_a")
	seedAgentGroup(t, db, "grp_b", "site_default", "Beta group", "agent_b")
	seedAgentGroup(t, db, "grp_both", "site_default", "Everything", "agent_a", "agent_b")
	seedTarget(t, db, "probe_1", "site_default", "mg", "http", "https://example.com", "Website")
	seedTarget(t, db, "probe_2", "site_default", "mg", "icmp", "10.0.0.1", "")

	svc := New(db, targetstatus.New(db, nil), agentstatus.New(db, nil, settings.New(db)), nil)
	return svc, db
}

func seedAgent(t *testing.T, db *store.DB, id, siteID, displayName, status string) {
	t.Helper()
	now := time.Now().UTC()
	mustExec(t, db, `INSERT INTO agents(id, site_id, public_key, token_hash, hostname, display_name,
		status, first_connected_at, last_seen_at, created_at)
		VALUES(?,?,x'00',?,?,?,?,?,?,?)`,
		id, siteID, "h_"+id, id+"-internal-hostname", displayName, status, now, now, now)
}

func seedAgentGroup(t *testing.T, db *store.DB, id, siteID, name string, agentIDs ...string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO agent_groups(id, site_id, name) VALUES(?,?,?)`, id, siteID, name)
	for _, agentID := range agentIDs {
		mustExec(t, db, `INSERT INTO agent_group_members(group_id, agent_id) VALUES(?,?)`, id, agentID)
	}
}

func seedTarget(t *testing.T, db *store.DB, id, siteID, groupID, kind, target, name string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO probe_tasks(id, site_id, group_id, kind, target, name, enabled)
		VALUES(?,?,?,?,?,?,1)`, id, siteID, groupID, kind, target, name)
}

func fullSpec() Spec {
	return Spec{
		Slug: "home", Title: "Home lab", Description: "public",
		Enabled: true, ShowAgentView: true, ShowTargetView: true,
		AgentMetrics:  AgentMetricsBasic,
		AgentGroupIDs: []string{"grp_a"}, TargetIDs: []string{"probe_1"},
	}
}

func TestCreateAndGetRoundTripsTheSelection(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()

	spec := fullSpec()
	spec.ShowIncidents = true
	spec.AgentGroupIDs = []string{"grp_a", "grp_b"}
	spec.TargetIDs = []string{"probe_1", "probe_2"}
	created, err := svc.Create(ctx, "site_default", spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" || created.SiteID != "site_default" {
		t.Fatalf("create returned %+v", created)
	}
	got, err := svc.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.AgentGroupIDs) != 2 || len(got.TargetIDs) != 2 {
		t.Fatalf("selection = %v / %v, want both members on each side", got.AgentGroupIDs, got.TargetIDs)
	}
	if !got.Enabled || !got.ShowAgentView || !got.ShowTargetView || !got.ShowIncidents || got.ShowTargetAddress {
		t.Fatalf("toggles = %+v, want the spec's values (address off by default)", got)
	}

	list, err := svc.List(ctx, "site_default")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || len(list[0].AgentGroupIDs) != 2 {
		t.Fatalf("list = %+v, want one page carrying its selection", list)
	}
}

// An empty selection must come back as [] rather than null: the console renders it
// as a list and the public API contract says so.
func TestEmptySelectionIsAnEmptySliceNotNil(t *testing.T) {
	svc, _ := newFixture(t)
	spec := fullSpec()
	spec.AgentGroupIDs = nil
	spec.TargetIDs = nil
	page, err := svc.Create(context.Background(), "site_default", spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if page.AgentGroupIDs == nil || page.TargetIDs == nil {
		t.Fatalf("selection = %v / %v, want empty slices", page.AgentGroupIDs, page.TargetIDs)
	}
}

func TestUpdateReplacesTheWholeSelection(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	spec := fullSpec()
	spec.AgentGroupIDs = []string{"grp_a", "grp_b"}
	page, err := svc.Create(ctx, "site_default", spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	next := fullSpec()
	next.AgentGroupIDs = []string{"grp_b"}
	next.TargetIDs = []string{"probe_2"}
	next.Title = "Renamed"
	updated, err := svc.Update(ctx, page.ID, next)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(updated.AgentGroupIDs) != 1 || updated.AgentGroupIDs[0] != "grp_b" {
		t.Fatalf("agents = %v, want exactly the new set", updated.AgentGroupIDs)
	}
	if len(updated.TargetIDs) != 1 || updated.TargetIDs[0] != "probe_2" {
		t.Fatalf("targets = %v, want exactly the new set", updated.TargetIDs)
	}
	if updated.Title != "Renamed" {
		t.Fatalf("title = %q, want the updated one", updated.Title)
	}
}

func TestDeleteRemovesThePageAndItsSelection(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	page, err := svc.Create(ctx, "site_default", fullSpec())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Delete(ctx, page.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var members int
	if err := db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM status_page_agent_groups) + (SELECT COUNT(*) FROM status_page_targets)`).
		Scan(&members); err != nil {
		t.Fatalf("count members: %v", err)
	}
	if members != 0 {
		t.Fatalf("%d membership rows survived the delete, want 0", members)
	}
	if err := svc.Delete(ctx, page.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}
	if _, err := svc.Get(ctx, page.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
}

func TestSlugMustBeUnique(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, "site_default", fullSpec()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.Create(ctx, "site_default", fullSpec()); !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("duplicate create = %v, want ErrSlugTaken", err)
	}

	second := fullSpec()
	second.Slug = "other"
	page, err := svc.Create(ctx, "site_default", second)
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	taken := fullSpec() // slug "home", owned by the first page
	if _, err := svc.Update(ctx, page.ID, taken); !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("update onto a taken slug = %v, want ErrSlugTaken", err)
	}
	// Keeping your own slug is not a conflict with yourself.
	if _, err := svc.Update(ctx, page.ID, second); err != nil {
		t.Fatalf("update keeping own slug: %v", err)
	}
}

func TestSelectionRejectsWhatTheSiteCannotPublish(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	seedAgent(t, db, "agent_elsewhere", "site_other", "Elsewhere", "online")
	seedAgentGroup(t, db, "grp_elsewhere", "site_other", "Elsewhere group", "agent_elsewhere")
	seedTarget(t, db, "probe_elsewhere", "site_other", "mg_other", "http", "https://other", "Other")

	cases := []struct {
		name string
		spec func(Spec) Spec
	}{
		{"unknown agent group", func(s Spec) Spec { s.AgentGroupIDs = []string{"grp_missing"}; return s }},
		{"cross-site agent group", func(s Spec) Spec { s.AgentGroupIDs = []string{"grp_elsewhere"}; return s }},
		{"unknown target", func(s Spec) Spec { s.TargetIDs = []string{"probe_missing"}; return s }},
		{"cross-site target", func(s Spec) Spec { s.TargetIDs = []string{"probe_elsewhere"}; return s }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Create(ctx, "site_default", tc.spec(fullSpec())); !errors.Is(err, ErrBadSelection) {
				t.Fatalf("create = %v, want ErrBadSelection", err)
			}
		})
	}

	// A rejected create must leave nothing behind — including its slug, which the
	// operator will retry with.
	pages, err := svc.List(ctx, "site_default")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pages) != 0 {
		t.Fatalf("%d pages survived rejected creates, want 0", len(pages))
	}
}

func TestValidateRejectsMalformedSpecs(t *testing.T) {
	cases := []struct {
		name string
		spec func(Spec) Spec
	}{
		{"empty slug", func(s Spec) Spec { s.Slug = ""; return s }},
		{"uppercase slug", func(s Spec) Spec { s.Slug = "Home"; return s }},
		{"slug with slash", func(s Spec) Spec { s.Slug = "home/lab"; return s }},
		{"slug with trailing dash", func(s Spec) Spec { s.Slug = "home-"; return s }},
		{"blank title", func(s Spec) Spec { s.Title = "   "; return s }},
		{"overlong title", func(s Spec) Spec { s.Title = string(make([]rune, MaxTitleLen+1)); return s }},
		{"all views hidden", func(s Spec) Spec {
			s.ShowAgentView, s.ShowTargetView, s.ShowIncidents = false, false, false
			return s
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.spec(fullSpec()).Validate(); !errors.Is(err, ErrBadSpec) {
				t.Fatalf("Validate = %v, want ErrBadSpec", err)
			}
		})
	}
	if err := fullSpec().Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
}

// ---- public reads ----

func TestPublicReadPublishesOnlyTheSelection(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, "site_default", fullSpec()); err != nil {
		t.Fatalf("create: %v", err)
	}

	agents, err := svc.PublicAgentStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("agent statuses: %v", err)
	}
	if len(agents.Agents) != 1 || agents.Agents[0].Name != "Alpha" {
		t.Fatalf("agents = %+v, want only the selected one", agents.Agents)
	}
	if !agents.Agents[0].Online {
		t.Error("selected agent reads offline, want online (its registry status is online)")
	}

	targets, err := svc.PublicTargetStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("target statuses: %v", err)
	}
	if len(targets.Targets) != 1 || targets.Targets[0].Name != "Website" {
		t.Fatalf("targets = %+v, want only the selected one", targets.Targets)
	}
	if targets.Targets[0].Address != "" {
		t.Errorf("address = %q, want it withheld while show_target_address is off", targets.Targets[0].Address)
	}
}

func TestAddressIsPublishedOnlyWhenThePageOptsIn(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	spec := fullSpec()
	spec.ShowTargetAddress = true
	if _, err := svc.Create(ctx, "site_default", spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	targets, err := svc.PublicTargetStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("target statuses: %v", err)
	}
	if targets.Targets[0].Address != "https://example.com" {
		t.Fatalf("address = %q, want the real target once opted in", targets.Targets[0].Address)
	}
}

// The four ways a public read can miss must be indistinguishable from outside.
func TestEveryPublicMissLooksTheSame(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()

	disabled := fullSpec()
	disabled.Slug, disabled.Enabled = "disabled-page", false
	if _, err := svc.Create(ctx, "site_default", disabled); err != nil {
		t.Fatalf("create disabled: %v", err)
	}
	agentsOnly := fullSpec()
	agentsOnly.Slug, agentsOnly.ShowTargetView = "agents-only", false
	if _, err := svc.Create(ctx, "site_default", agentsOnly); err != nil {
		t.Fatalf("create agents-only: %v", err)
	}
	targetsOnly := fullSpec()
	targetsOnly.Slug, targetsOnly.ShowAgentView = "targets-only", false
	if _, err := svc.Create(ctx, "site_default", targetsOnly); err != nil {
		t.Fatalf("create targets-only: %v", err)
	}

	cases := []struct {
		name string
		call func() error
	}{
		{"unknown slug", func() error { _, err := svc.PublicPage(ctx, "never-existed"); return err }},
		{"disabled page", func() error { _, err := svc.PublicPage(ctx, "disabled-page"); return err }},
		{"disabled page agent view", func() error {
			_, err := svc.PublicAgentStatuses(ctx, "disabled-page")
			return err
		}},
		{"target view off", func() error { _, err := svc.PublicTargetStatuses(ctx, "agents-only"); return err }},
		{"agent view off", func() error { _, err := svc.PublicAgentStatuses(ctx, "targets-only"); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrPageNotFound) {
				t.Fatalf("got %v, want ErrPageNotFound", err)
			}
		})
	}

	// The view that IS enabled still works — the toggle hides one list, not the page.
	if _, err := svc.PublicAgentStatuses(ctx, "agents-only"); err != nil {
		t.Fatalf("enabled view: %v", err)
	}
}

func TestPublicPageCarriesOnlyItsOwnDescription(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, "site_default", fullSpec()); err != nil {
		t.Fatalf("create: %v", err)
	}
	page, err := svc.PublicPage(ctx, "home")
	if err != nil {
		t.Fatalf("public page: %v", err)
	}
	if page.Slug != "home" || page.Title != "Home lab" || page.Description != "public" {
		t.Fatalf("page = %+v", page)
	}
	if !page.ShowAgentView || !page.ShowTargetView || page.ShowIncidents || page.ShowTargetAddress {
		t.Fatalf("toggles = %+v, want them mirrored for the frontend", page)
	}
	if page.GeneratedAt.IsZero() {
		t.Error("generated_at is zero")
	}
}

// An agent's hostname must never reach the public payload, named or not: the
// display name is the only label, and an unnamed agent falls back to its ordinal.
func TestUnnamedRowsFallBackToOrdinalsNeverHostnames(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	spec := fullSpec()
	spec.AgentGroupIDs = []string{"grp_a", "grp_b"}
	spec.TargetIDs = []string{"probe_1", "probe_2"}
	if _, err := svc.Create(ctx, "site_default", spec); err != nil {
		t.Fatalf("create: %v", err)
	}

	agents, err := svc.PublicAgentStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("agent statuses: %v", err)
	}
	if len(agents.Agents) != 2 {
		t.Fatalf("agents = %+v, want both", agents.Agents)
	}
	// Named first, unnamed last, ordinals following that order.
	if agents.Agents[0].Name != "Alpha" || agents.Agents[0].Ordinal != 1 {
		t.Errorf("first agent = %+v, want the named one at ordinal 1", agents.Agents[0])
	}
	if agents.Agents[1].Name != "" || agents.Agents[1].Ordinal != 2 {
		t.Errorf("second agent = %+v, want the unnamed one at ordinal 2", agents.Agents[1])
	}

	targets, err := svc.PublicTargetStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("target statuses: %v", err)
	}
	// Ordinals restart per kind, so the sole icmp target is #1 of its kind rather
	// than #2 overall.
	byKind := map[string]PublicTargetRow{}
	for _, row := range targets.Targets {
		byKind[row.Kind] = row
	}
	if got := byKind["icmp"]; got.Name != "" || got.Ordinal != 1 {
		t.Errorf("icmp row = %+v, want the unnamed target at ordinal 1 of its kind", got)
	}
	if got := byKind["http"]; got.Ordinal != 1 {
		t.Errorf("http row = %+v, want ordinal 1 of its kind", got)
	}
}

// Ordinals are a published label, so they have to survive the case the underlying
// aggregation does not order: agents enrolled in the same second.
func TestOrdinalsAreStableForSameSecondAgents(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	same := time.Now().UTC().Truncate(time.Second)
	mustExec(t, db, `UPDATE agents SET display_name='', created_at=? WHERE site_id='site_default'`, same)

	spec := fullSpec()
	spec.AgentGroupIDs = []string{"grp_a", "grp_b"}
	if _, err := svc.Create(ctx, "site_default", spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	svc.ttl = 0 // force a fresh aggregation each call

	var first []PublicAgentRow
	for i := 0; i < 5; i++ {
		got, err := svc.PublicAgentStatuses(ctx, "home")
		if err != nil {
			t.Fatalf("agent statuses: %v", err)
		}
		if first == nil {
			first = got.Agents
			continue
		}
		for j := range got.Agents {
			if got.Agents[j].Ordinal != first[j].Ordinal {
				t.Fatalf("ordinals shifted between reads: %+v vs %+v", first, got.Agents)
			}
		}
	}
}

// A page names groups, so what it publishes tracks their CURRENT membership.
// This is the whole point of selecting by group — and also the trade it makes, so
// both directions are pinned here: joining a published group publishes you,
// leaving it takes you off, and neither requires anyone to re-save the page.
func TestPublishedNodesFollowGroupMembership(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	spec := fullSpec()
	spec.AgentGroupIDs = []string{"grp_a"} // holds agent_a only
	page, err := svc.Create(ctx, "site_default", spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	svc.ttl = 0

	names := func() []string {
		t.Helper()
		got, err := svc.PublicAgentStatuses(ctx, "home")
		if err != nil {
			t.Fatalf("agent statuses: %v", err)
		}
		out := make([]string, 0, len(got.Agents))
		for _, row := range got.Agents {
			out = append(out, row.Name)
		}
		return out
	}
	if got := names(); len(got) != 1 || got[0] != "Alpha" {
		t.Fatalf("published = %v, want just the group's one member", got)
	}

	// An agent joining the published group appears without the page changing.
	mustExec(t, db, `INSERT INTO agent_group_members(group_id, agent_id) VALUES('grp_a','agent_b')`)
	if got := names(); len(got) != 2 {
		t.Fatalf("published = %v, want the new group member to appear", got)
	}

	// And leaving it removes them again.
	mustExec(t, db, `DELETE FROM agent_group_members WHERE group_id='grp_a' AND agent_id='agent_a'`)
	if got := names(); len(got) != 1 || got[0] != "" {
		t.Fatalf("published = %v, want only the remaining member", got)
	}

	// Through all of it the page's own selection is untouched: it names a group,
	// not the machines that happen to be in it.
	stored, err := svc.Get(ctx, page.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(stored.AgentGroupIDs) != 1 || stored.AgentGroupIDs[0] != "grp_a" {
		t.Fatalf("selection = %v, want it unchanged", stored.AgentGroupIDs)
	}
}

// An agent in two selected groups is one published node, not two.
func TestOverlappingGroupsPublishAnAgentOnce(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	spec := fullSpec()
	spec.AgentGroupIDs = []string{"grp_a", "grp_both"} // agent_a is in both
	if _, err := svc.Create(ctx, "site_default", spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.PublicAgentStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("agent statuses: %v", err)
	}
	if len(got.Agents) != 2 {
		t.Fatalf("published = %+v, want two distinct agents", got.Agents)
	}
}

// Deleting a group takes it off every page that published it, with no cleanup
// pass and no dangling row.
func TestDeletedAgentGroupDisappearsFromThePage(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	spec := fullSpec()
	spec.AgentGroupIDs = []string{"grp_a", "grp_b"}
	page, err := svc.Create(ctx, "site_default", spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// registry.DeleteGroup clears the membership rows before the group itself; the
	// page's own reference is what must cascade.
	mustExec(t, db, `DELETE FROM agent_group_members WHERE group_id='grp_a'`)
	mustExec(t, db, `DELETE FROM agent_groups WHERE id='grp_a'`)
	svc.ttl = 0

	agents, err := svc.PublicAgentStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("agent statuses: %v", err)
	}
	if len(agents.Agents) != 1 {
		t.Fatalf("agents = %+v, want only the surviving group's member", agents.Agents)
	}
	stored, err := svc.Get(ctx, page.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(stored.AgentGroupIDs) != 1 || stored.AgentGroupIDs[0] != "grp_b" {
		t.Fatalf("selection = %v, want the cascade to have removed the deleted group", stored.AgentGroupIDs)
	}
}

func TestPublicStatusCoarsensEveryDisplayState(t *testing.T) {
	// Every display state targetstatus can emit, plus a value it cannot: an
	// unrecognized state must read as unknown, never as up.
	cases := map[string]string{
		"healthy":         StatusUp,
		"faulted":         StatusDown,
		"partial_failure": StatusDown,
		"probe_failed":    StatusDown,
		"confirming":      StatusDegraded,
		"stale":           StatusDegraded,
		"pending":         StatusUnknown,
		"no_data":         StatusUnknown,
		"blocked":         StatusUnknown,
		"agent_offline":   StatusUnknown,
		"disabled":        StatusUnknown,
		"unassigned":      StatusUnknown,
		"something_new":   StatusUnknown,
	}
	for state, want := range cases {
		if got := publicStatus(state); got != want {
			t.Errorf("publicStatus(%q) = %q, want %q", state, got, want)
		}
	}
}

// The cache exists to bound anonymous load, so what matters is that a second read
// inside the window does not re-run the aggregation, and that the window expires.
func TestSnapshotCacheServesInsideTheWindowAndExpires(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, "site_default", fullSpec()); err != nil {
		t.Fatalf("create: %v", err)
	}

	clock := time.Now().UTC()
	svc.now = func() time.Time { return clock }
	svc.ttl = 5 * time.Second

	if _, err := svc.PublicTargetStatuses(ctx, "home"); err != nil {
		t.Fatalf("first read: %v", err)
	}
	// A change the aggregation would pick up immediately; the cache must hide it
	// until the window passes.
	mustExec(t, db, `UPDATE probe_tasks SET name='Renamed' WHERE id='probe_1'`)

	cached, err := svc.PublicTargetStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if cached.Targets[0].Name != "Website" {
		t.Fatalf("name = %q inside the cache window, want the cached %q", cached.Targets[0].Name, "Website")
	}

	clock = clock.Add(6 * time.Second)
	fresh, err := svc.PublicTargetStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("post-expiry read: %v", err)
	}
	if fresh.Targets[0].Name != "Renamed" {
		t.Fatalf("name = %q after the window, want the refreshed %q", fresh.Targets[0].Name, "Renamed")
	}
}

// A public read must see ONE committed version of the page. Read separately, the
// flags and the membership can straddle an admin's save — publishing a newly
// selected target under the previous version's show_target_address, which is the
// exact boundary this feature exists to hold. The read transaction is what
// prevents it; this pins the guarantee by hammering reads against a writer.
func TestPublicReadNeverMixesFlagsFromOneSaveWithMembersFromAnother(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	svc.ttl = 0 // never serve a cached aggregation, so every read is a fresh pass

	spec := fullSpec()
	spec.TargetIDs = []string{"probe_1"}
	page, err := svc.Create(ctx, "site_default", spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Two states an admin toggles between. Addresses are shown ONLY in the state
	// that publishes a single target, so any read that reports two targets with
	// addresses has combined halves of different versions.
	withAddress := fullSpec()
	withAddress.ShowTargetAddress = true
	withAddress.TargetIDs = []string{"probe_1"}
	withoutAddress := fullSpec()
	withoutAddress.ShowTargetAddress = false
	withoutAddress.TargetIDs = []string{"probe_1", "probe_2"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 40; i++ {
			next := withAddress
			if i%2 == 0 {
				next = withoutAddress
			}
			if _, err := svc.Update(ctx, page.ID, next); err != nil {
				t.Errorf("update: %v", err)
				return
			}
		}
	}()

	for i := 0; i < 200; i++ {
		got, err := svc.PublicTargetStatuses(ctx, "home")
		if err != nil {
			t.Fatalf("public read: %v", err)
		}
		addressed := 0
		for _, row := range got.Targets {
			if row.Address != "" {
				addressed++
			}
		}
		switch {
		case len(got.Targets) == 1 && (addressed == 0 || addressed == 1):
			// Either saved state is fine for a single-target page.
		case len(got.Targets) == 2 && addressed == 0:
			// The two-target state hides addresses.
		default:
			t.Fatalf("read mixed two saves: %d targets, %d with an address", len(got.Targets), addressed)
		}
	}
	<-done
}
func TestSnapshotCacheIsPerSite(t *testing.T) {
	svc, db := newFixture(t)
	ctx := context.Background()
	seedTarget(t, db, "probe_other", "site_other", "mg_other", "http", "https://other", "Other site")

	if _, err := svc.Create(ctx, "site_default", fullSpec()); err != nil {
		t.Fatalf("create default: %v", err)
	}
	other := fullSpec()
	other.Slug, other.TargetIDs, other.AgentGroupIDs = "other", []string{"probe_other"}, nil
	if _, err := svc.Create(ctx, "site_other", other); err != nil {
		t.Fatalf("create other: %v", err)
	}

	first, err := svc.PublicTargetStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("default site: %v", err)
	}
	second, err := svc.PublicTargetStatuses(ctx, "other")
	if err != nil {
		t.Fatalf("other site: %v", err)
	}
	if first.Targets[0].Name != "Website" || second.Targets[0].Name != "Other site" {
		t.Fatalf("cross-site bleed: %q / %q", first.Targets[0].Name, second.Targets[0].Name)
	}
}
