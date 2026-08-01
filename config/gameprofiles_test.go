package config

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

// gameSvc wires a service with a bus so the announce (and its absence) is
// observable, and returns a counter per topic.
func gameSvc(t *testing.T) (*store.DB, context.Context, *Service, *int, *int) {
	t.Helper()
	db, ctx := openConfigTestDB(t)
	bus := eventbus.New()
	svc := New(db, registry.New(db, 0, nil), bus, nil)
	var configEvents, statusEvents int
	bus.Subscribe(eventbus.TopicConfigChanged, func(eventbus.Message) { configEvents++ })
	bus.Subscribe(eventbus.TopicTargetStatusChanged, func(eventbus.Message) { statusEvents++ })
	return db, ctx, svc, &configEvents, &statusEvents
}

func gameSerials(t *testing.T, db *store.DB, siteID string) (game, probe int) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(),
		`SELECT game_config_serial, config_serial FROM sites WHERE id=?`, siteID).Scan(&game, &probe); err != nil {
		t.Fatalf("read serials: %v", err)
	}
	return game, probe
}

func intp(v int) *int { return &v }

// TestGameProfileCRUD walks a profile through its whole life and pins the stored
// shape at each step, including the normalizations the API contract depends on.
func TestGameProfileCRUD(t *testing.T) {
	_, ctx, svc, configEvents, _ := gameSvc(t)

	created, err := svc.CreateGameProfile(ctx, "site_default", GameProfileRec{
		Name: "  Counter-Strike  ", Exe: []string{"cs2.exe", " CS2.EXE ", "csgo.exe"},
		TargetFPS: intp(240), Tier: GameTierBase, MonitorIDs: []string{"probe_a", "probe_a", " "},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Name != "Counter-Strike" {
		t.Fatalf("name = %q, want it trimmed", created.Name)
	}
	// A tag input can easily emit the same exe twice in different case; matching is
	// case-insensitive, so the duplicate is dropped rather than the save refused.
	if len(created.Exe) != 2 || created.Exe[0] != "cs2.exe" || created.Exe[1] != "csgo.exe" {
		t.Fatalf("exe = %v, want the case-insensitive duplicate dropped", created.Exe)
	}
	if len(created.MonitorIDs) != 1 || created.MonitorIDs[0] != "probe_a" {
		t.Fatalf("monitor_ids = %v, want one entry", created.MonitorIDs)
	}
	if created.TargetFPS == nil || *created.TargetFPS != 240 || created.Tier != GameTierBase {
		t.Fatalf("created = %+v, want 240 fps / base tier", created)
	}
	if created.CreatedAt == 0 || created.UpdatedAt == 0 {
		t.Fatalf("timestamps = %d/%d, want both stamped", created.CreatedAt, created.UpdatedAt)
	}

	list, err := svc.GameProfiles(ctx, "site_default")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("list = %+v, want the created profile", list)
	}

	// A target of 0 is the same answer as "no target", so it is stored as unset
	// rather than as a game expected to render nothing.
	updated, err := svc.UpdateGameProfile(ctx, created.ID, GameProfileRec{
		Name: "CS", Exe: []string{"cs2.exe"}, TargetFPS: intp(0), Tier: GameTierDiag,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.TargetFPS != nil {
		t.Fatalf("target_fps = %d, want nil for a submitted 0", *updated.TargetFPS)
	}
	if updated.Name != "CS" || updated.Tier != GameTierDiag || len(updated.MonitorIDs) != 0 {
		t.Fatalf("updated = %+v", updated)
	}
	if updated.CreatedAt != created.CreatedAt {
		t.Fatalf("created_at moved on update: %d -> %d", created.CreatedAt, updated.CreatedAt)
	}

	siteID, err := svc.DeleteGameProfile(ctx, created.ID)
	if err != nil || siteID != "site_default" {
		t.Fatalf("delete = %q, %v", siteID, err)
	}
	if _, err := svc.GameProfile(ctx, created.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("get after delete = %v, want sql.ErrNoRows", err)
	}
	if _, err := svc.DeleteGameProfile(ctx, created.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second delete = %v, want sql.ErrNoRows", err)
	}
	if _, err := svc.UpdateGameProfile(ctx, created.ID, GameProfileRec{
		Name: "gone", Exe: []string{"a.exe"},
	}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("update after delete = %v, want sql.ErrNoRows", err)
	}

	// create + update + delete each announced once; the failed ones announced nothing.
	if *configEvents != 3 {
		t.Fatalf("config events = %d, want one per successful mutation", *configEvents)
	}
	empty, err := svc.GameProfiles(ctx, "site_default")
	if err != nil || len(empty) != 0 {
		t.Fatalf("list after delete = %+v, %v", empty, err)
	}
}

func TestGameProfileValidation(t *testing.T) {
	_, ctx, svc, configEvents, _ := gameSvc(t)
	cases := []struct {
		name string
		rec  GameProfileRec
	}{
		{"empty name", GameProfileRec{Name: "   ", Exe: []string{"a.exe"}}},
		{"long name", GameProfileRec{Name: strings.Repeat("x", 201), Exe: []string{"a.exe"}}},
		{"no exe", GameProfileRec{Name: "A"}},
		{"blank exe entry", GameProfileRec{Name: "A", Exe: []string{"a.exe", "  "}}},
		{"unknown tier", GameProfileRec{Name: "A", Exe: []string{"a.exe"}, Tier: "ultra"}},
		{"negative fps", GameProfileRec{Name: "A", Exe: []string{"a.exe"}, TargetFPS: intp(-1)}},
		{"absurd fps", GameProfileRec{Name: "A", Exe: []string{"a.exe"}, TargetFPS: intp(1001)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := svc.CreateGameProfile(ctx, "site_default", c.rec); !errors.Is(err, ErrGameProfileInvalid) {
				t.Fatalf("create = %v, want ErrGameProfileInvalid", err)
			}
		})
	}
	// A refused save must not have moved the version axis, or agents would be told
	// to re-read a profile set that never changed.
	if *configEvents != 0 {
		t.Fatalf("rejected saves announced %d times", *configEvents)
	}

	// An omitted tier is the cautious default: a profile the operator did not
	// classify still gets the full diagnostic set rather than silently the least.
	p, err := svc.CreateGameProfile(ctx, "site_default", GameProfileRec{Name: "A", Exe: []string{"a.exe"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.Tier != GameTierDiag {
		t.Fatalf("default tier = %q, want %q", p.Tier, GameTierDiag)
	}
}

// TestGameSerialIsItsOwnAxis is the invariant the whole two-serial design exists
// for: a game mutation must move the game serial and ONLY the game serial, and a
// probe mutation must leave the game serial alone. Either leak would make one
// half of the configuration restart the other for a change it cannot see.
func TestGameSerialIsItsOwnAxis(t *testing.T) {
	db, ctx, svc, configEvents, _ := gameSvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "grp", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	game0, probe0 := gameSerials(t, db, "site_default")

	p, err := svc.CreateGameProfile(ctx, "site_default", GameProfileRec{Name: "A", Exe: []string{"a.exe"}})
	if err != nil {
		t.Fatal(err)
	}
	game1, probe1 := gameSerials(t, db, "site_default")
	if game1 != game0+1 || probe1 != probe0 {
		t.Fatalf("profile create moved serials to game=%d probe=%d, want game=%d probe=%d",
			game1, probe1, game0+1, probe0)
	}

	if _, err := svc.UpdateGameProfile(ctx, p.ID, GameProfileRec{Name: "B", Exe: []string{"b.exe"}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetGameCollection(ctx, "site_default", false); err != nil {
		t.Fatal(err)
	}
	game2, probe2 := gameSerials(t, db, "site_default")
	if game2 != game0+3 || probe2 != probe0 {
		t.Fatalf("after update+collection: game=%d probe=%d, want game=%d probe unchanged", game2, probe2, game0+3)
	}

	// Now the other direction: a probe-target save must not touch the game axis.
	*configEvents = 0
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t1", GroupID: group, Kind: "icmp", Target: "1.1.1.1", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	game3, probe3 := gameSerials(t, db, "site_default")
	if game3 != game2 {
		t.Fatalf("probe save bumped the game serial to %d (was %d)", game3, game2)
	}
	if probe3 != probe2+1 {
		t.Fatalf("probe save left the probe serial at %d, want %d", probe3, probe2+1)
	}
	if *configEvents != 1 {
		t.Fatalf("probe save announced %d times, want 1", *configEvents)
	}
}

func TestGameCollectionRoundTrip(t *testing.T) {
	_, ctx, svc, configEvents, _ := gameSvc(t)
	// Out of the box everything is recorded, which is what makes the feature work
	// before anyone has defined a single profile.
	record, err := svc.GameCollection(ctx, "site_default")
	if err != nil || !record {
		t.Fatalf("default collection = %v, %v; want true", record, err)
	}
	// An unknown site answers with the behavior it would have, not an error.
	if record, err = svc.GameCollection(ctx, "site_missing"); err != nil || !record {
		t.Fatalf("unknown site = %v, %v; want true", record, err)
	}
	if err := svc.SetGameCollection(ctx, "site_missing", false); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("set on unknown site = %v, want sql.ErrNoRows", err)
	}
	if err := svc.SetGameCollection(ctx, "site_default", false); err != nil {
		t.Fatal(err)
	}
	if record, err = svc.GameCollection(ctx, "site_default"); err != nil || record {
		t.Fatalf("collection after set = %v, %v; want false", record, err)
	}
	if *configEvents != 1 {
		t.Fatalf("config events = %d, want only the successful set", *configEvents)
	}
}

// TestDesiredStateForCarriesGameBlock pins what the agent receives: always a
// block (so "the last profile was deleted" is expressible), its own version, and
// strictly this site's profiles.
func TestDesiredStateForCarriesGameBlock(t *testing.T) {
	_, ctx, svc, _, _ := gameSvc(t)

	ds, err := svc.DesiredStateFor(ctx, "agent_a")
	if err != nil {
		t.Fatal(err)
	}
	if ds.Game == nil {
		t.Fatal("game block is nil with no profiles defined; it must always be present")
	}
	if !ds.Game.RecordUnmatched || len(ds.Game.Profiles) != 0 || ds.Game.Version != 0 {
		t.Fatalf("empty game block = %+v, want version 0 / record everything", *ds.Game)
	}

	mine, err := svc.CreateGameProfile(ctx, "site_default", GameProfileRec{
		Name: "Mine", Exe: []string{"Mine.exe"}, TargetFPS: intp(144), Tier: GameTierDiag,
		MonitorIDs: []string{"probe_a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGameProfile(ctx, "site_other", GameProfileRec{
		Name: "Theirs", Exe: []string{"theirs.exe"},
	}); err != nil {
		t.Fatal(err)
	}

	ds, err = svc.DesiredStateFor(ctx, "agent_a")
	if err != nil {
		t.Fatal(err)
	}
	if ds.Game.Version != 1 {
		t.Fatalf("version = %d, want 1 after one mutation", ds.Game.Version)
	}
	if len(ds.Game.Profiles) != 1 {
		t.Fatalf("profiles = %+v, want only this site's", ds.Game.Profiles)
	}
	got := ds.Game.Profiles[0]
	if got.ID != mine.ID || got.Name != "Mine" || got.Tier != GameTierDiag || got.TargetFPS != 144 {
		t.Fatalf("pushed profile = %+v", got)
	}
	if len(got.Exe) != 1 || got.Exe[0] != "Mine.exe" {
		t.Fatalf("pushed exe = %v", got.Exe)
	}
	// The other site's agent must see its own, never this one's.
	other, err := svc.DesiredStateFor(ctx, "agent_other")
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Game.Profiles) != 1 || other.Game.Profiles[0].Name != "Theirs" {
		t.Fatalf("cross-site leak: %+v", other.Game.Profiles)
	}

	// An unset target FPS is 0 on the wire, which is how the agent reads "no target".
	if _, err := svc.UpdateGameProfile(ctx, mine.ID, GameProfileRec{
		Name: "Mine", Exe: []string{"mine.exe"}, Tier: GameTierBase,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetGameCollection(ctx, "site_default", false); err != nil {
		t.Fatal(err)
	}
	ds, err = svc.DesiredStateFor(ctx, "agent_a")
	if err != nil {
		t.Fatal(err)
	}
	if ds.Game.Profiles[0].TargetFPS != 0 || ds.Game.Profiles[0].Tier != GameTierBase {
		t.Fatalf("updated push = %+v", ds.Game.Profiles[0])
	}
	if ds.Game.RecordUnmatched {
		t.Fatal("record_unmatched still true after the site was set to strict")
	}
	if ds.Game.Version != 3 {
		t.Fatalf("version = %d, want 3 after three site mutations", ds.Game.Version)
	}
}
