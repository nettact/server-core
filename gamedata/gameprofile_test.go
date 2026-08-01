package gamedata

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/server-core/store"
)

// seedProfile inserts a game profile directly: gamedata only ever reads the
// table (profiles are written through the config service), so the fixture is the
// row rather than that service.
func seedProfile(t *testing.T, db *store.DB, id, name string) {
	t.Helper()
	now := time.Now().UTC().Unix()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO game_profiles(id, site_id, name, exe_match, tier, monitor_ids, created_at, updated_at)
		 VALUES(?,'site_default',?,'["a.exe"]','diag','[]',?,?)`, id, name, now, now); err != nil {
		t.Fatalf("seed profile %s: %v", id, err)
	}
}

// TestRunProfileStamp pins the round trip of the profile stamp, the two ways it
// can be absent, and its mutability under the same guard as proc and title.
func TestRunProfileStamp(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	seedProfile(t, db, "gprof_cs", "Counter-Strike")

	matched := run("run_game", start, 60)
	matched.ProfileID = "gprof_cs"
	other := run("run_other", start, 60) // matched nothing: "other process"
	apply(t, db, "agent_game", []gamesense.Run{matched, other}, nil)

	got, err := svc.GetRun(ctx, "run_game")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID == nil || *got.ProfileID != "gprof_cs" {
		t.Fatalf("profile_id = %v, want the stamp", got.ProfileID)
	}
	if got.ProfileName == nil || *got.ProfileName != "Counter-Strike" {
		t.Fatalf("profile_name = %v, want the joined name", got.ProfileName)
	}

	// An empty id is stored as NULL, never as "": "matched no game" has to be one
	// value, or every reader would have to test for two.
	unmatched, err := svc.GetRun(ctx, "run_other")
	if err != nil {
		t.Fatal(err)
	}
	if unmatched.ProfileID != nil || unmatched.ProfileName != nil {
		t.Fatalf("unmatched run = %v/%v, want both null", unmatched.ProfileID, unmatched.ProfileName)
	}
	var isNull bool
	if err := db.QueryRowContext(ctx,
		`SELECT profile_id IS NULL FROM game_runs WHERE id='run_other'`).Scan(&isNull); err != nil {
		t.Fatal(err)
	}
	if !isNull {
		t.Fatal("an empty profile id was stored as a value rather than NULL")
	}

	// A profile created mid-session re-classifies the run on the agent's next
	// report, exactly like a window title change.
	later := run("run_other", start, 120)
	later.ProfileID = "gprof_cs"
	apply(t, db, "agent_game", []gamesense.Run{later}, nil)
	if got, err = svc.GetRun(ctx, "run_other"); err != nil || got.ProfileID == nil || *got.ProfileID != "gprof_cs" {
		t.Fatalf("re-stamped run = %v, %v", got.ProfileID, err)
	}

	// ...and a REPLAYED older report must not undo it, for the same reason it
	// cannot rewind the title.
	stale := run("run_other", start, 60)
	apply(t, db, "agent_game", []gamesense.Run{stale}, nil)
	if got, err = svc.GetRun(ctx, "run_other"); err != nil || got.ProfileID == nil {
		t.Fatalf("stale replay cleared the stamp: %v, %v", got.ProfileID, err)
	}
}

// TestRunProfileSurvivesProfileDeletion is the reason profile_id carries no
// foreign key: the stamp records what the configuration said when the run
// happened, so deleting the profile must leave the history intact and merely
// nameless.
func TestRunProfileSurvivesProfileDeletion(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	seedProfile(t, db, "gprof_gone", "Deleted Game")

	r := run("run_1", start, 60)
	r.ProfileID = "gprof_gone"
	apply(t, db, "agent_game", []gamesense.Run{r}, nil)

	if _, err := db.ExecContext(ctx, `DELETE FROM game_profiles WHERE id='gprof_gone'`); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("GetRun after the profile was deleted: %v", err)
	}
	if got.ProfileID == nil || *got.ProfileID != "gprof_gone" {
		t.Fatalf("profile_id = %v, want the stamp to outlive the profile", got.ProfileID)
	}
	if got.ProfileName != nil {
		t.Fatalf("profile_name = %v, want null once the profile is gone", *got.ProfileName)
	}
}

// TestListRunsProfileFilter pins the three listing modes the console's default
// filter is built on.
func TestListRunsProfileFilter(t *testing.T) {
	db, svc := openGameDB(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	seedProfile(t, db, "gprof_a", "A Game")

	game := run("run_game", start, 60)
	game.ProfileID = "gprof_a"
	apply(t, db, "agent_game", []gamesense.Run{game, run("run_browser", start, 60)}, nil)

	for _, c := range []struct {
		filter string
		want   []string
	}{
		{"", []string{"run_browser", "run_game"}},
		{RunsAll, []string{"run_browser", "run_game"}},
		{RunsProfiled, []string{"run_game"}},
		{RunsOther, []string{"run_browser"}},
	} {
		page, err := svc.ListRuns(ctx, RunFilter{AgentID: "agent_game", Runs: c.filter})
		if err != nil {
			t.Fatalf("ListRuns(%q): %v", c.filter, err)
		}
		// Total counts the filter's matches, not the page — a console paging through
		// "other processes" must not be told how many runs exist in total.
		if page.Total != len(c.want) || len(page.Items) != len(c.want) {
			t.Fatalf("runs=%q gave total=%d items=%d, want %d", c.filter, page.Total, len(page.Items), len(c.want))
		}
		got := map[string]bool{}
		for _, r := range page.Items {
			got[r.ID] = true
		}
		for _, id := range c.want {
			if !got[id] {
				t.Fatalf("runs=%q missing %s (got %v)", c.filter, id, got)
			}
		}
	}
}
