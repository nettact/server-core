package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/gamedata"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// seedGameRun stores one run and `seconds` buckets through the ingest write path,
// so the handler tests read exactly what ingest writes rather than a hand-built
// row that could drift from it.
func seedGameRun(t *testing.T, db *store.DB, agentID, runID string, start time.Time, seconds int) {
	t.Helper()
	ctx := context.Background()
	counts := make([]uint32, gamesense.HistBins)
	fast, _ := gamesense.HistBucket(5)
	slow, _ := gamesense.HistBucket(100)
	counts[fast] = 99
	counts[slow] = 1

	var buckets []gamesense.Bucket
	for i := 0; i < seconds; i++ {
		buckets = append(buckets, gamesense.Bucket{
			RunID: runID, TS: start.Add(time.Duration(i) * time.Second),
			Sample: gamesense.Sample{
				Frames: gamesense.Frames{Presented: 100},
				FT:     gamesense.FrameTimes{Avg: 5.77, P50: 5.7, P95: 6.1, P99: 6.4, Max: 7, SD: 0.3},
				Hist:   gamesense.Histogram{Layout: gamesense.HistLayoutLog24V1, Counts: counts},
			},
		})
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := gamedata.Apply(ctx, tx, agentID, "site_default", []gamesense.Run{{
		ID: runID, Proc: "game.exe", Title: "A Game",
		StartedAt: start, LastSeenAt: start.Add(time.Duration(seconds) * time.Second),
		Source: gamesense.SourcePresentMonService, Caps: []string{gamesense.CapDisplayed},
	}}, buckets); err != nil {
		tx.Rollback()
		t.Fatalf("apply: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func openGameAPI(t *testing.T) (*store.DB, Deps) {
	t.Helper()
	db := openStatusDB(t)
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO agents(id,site_id,public_key,token_hash,status,perm_effective)
		 VALUES('agent_game','site_default',x'00','h','online','["game.process.detect","game.performance.read"]')`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return db, Deps{GameData: gamedata.New(db, settings.New(db)), Audit: audit.New(db)}
}

func gameReq(t *testing.T, d Deps, h http.HandlerFunc, method, path, id string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// TestGameRunEndpoints pins the JSON a console will be written against: the run
// list shape, the summary fields, and — most importantly — that a figure the data
// cannot support is null rather than 0.
func TestGameRunEndpoints(t *testing.T) {
	db, d := openGameAPI(t)
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	seedGameRun(t, db, "agent_game", "run_long", start, 100) // 10000 frames
	seedGameRun(t, db, "agent_game", "run_short", start.Add(time.Hour), 3)

	w := gameReq(t, d, d.handleListGameRuns, http.MethodGet, "/api/v1/agents/agent_game/game-runs", "agent_game")
	if w.Code != http.StatusOK {
		t.Fatalf("list: status=%d body=%s", w.Code, w.Body.String())
	}
	var page struct {
		Items []gamedata.Run `json:"items"`
		Total int            `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode list: %v body=%s", err, w.Body.String())
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("list = %+v, want both runs", page)
	}
	// Newest first: the short run started an hour after the long one.
	if page.Items[0].ID != "run_short" {
		t.Fatalf("order = %s first, want the newest run", page.Items[0].ID)
	}
	if page.Items[0].Summary.Low1PctFPS != nil {
		t.Fatalf("a 300-frame run reported a 1%% low (%v); it must be omitted",
			*page.Items[0].Summary.Low1PctFPS)
	}
	long := page.Items[1]
	if long.Summary.MeanFPS == nil || long.Summary.Low1PctFPS == nil || long.Summary.Low01PctFPS == nil {
		t.Fatalf("long run summary = %+v, want all three figures", long.Summary)
	}
	if *long.Summary.Low1PctFPS >= *long.Summary.MeanFPS {
		t.Fatalf("1%% low %.1f is not below the mean %.1f", *long.Summary.Low1PctFPS, *long.Summary.MeanFPS)
	}
	if long.Summary.Presented != 10000 || long.Summary.Displayed != nil || long.Summary.Dropped != nil {
		t.Fatalf("totals = %+v, want presented 10000 and unmeasured nulls", long.Summary)
	}

	// The wire form must carry an explicit null, not an omitted key: a console that
	// sees no key and defaults to 0 is the failure this whole design avoids.
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	summary := raw["items"].([]any)[0].(map[string]any)["summary"].(map[string]any)
	for _, key := range []string{"mean_fps", "low_1pct_fps", "low_0_1pct_fps", "displayed", "dropped"} {
		if _, present := summary[key]; !present {
			t.Fatalf("summary is missing %q entirely; it must be present as null", key)
		}
	}
	if summary["low_1pct_fps"] != nil {
		t.Fatalf("low_1pct_fps = %v, want null", summary["low_1pct_fps"])
	}

	if w := gameReq(t, d, d.handleGetGameRun, http.MethodGet, "/api/v1/game-runs/run_long", "run_long"); w.Code != http.StatusOK {
		t.Fatalf("get run: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := gameReq(t, d, d.handleGetGameRun, http.MethodGet, "/api/v1/game-runs/nope", "nope"); w.Code != http.StatusNotFound {
		t.Fatalf("get unknown run: status=%d", w.Code)
	}
}

// TestGameRunBucketsRange covers the chart endpoint's time bounds and the shape
// it serves, which is the wire shape the agent uploaded.
func TestGameRunBucketsRange(t *testing.T) {
	db, d := openGameAPI(t)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	seedGameRun(t, db, "agent_game", "run_1", start, 10)

	w := gameReq(t, d, d.handleGameRunBuckets, http.MethodGet, "/api/v1/game-runs/run_1/buckets", "run_1")
	if w.Code != http.StatusOK {
		t.Fatalf("buckets: status=%d body=%s", w.Code, w.Body.String())
	}
	var all []gamesense.Bucket
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil {
		t.Fatalf("decode buckets: %v body=%s", err, w.Body.String())
	}
	if len(all) != 10 {
		t.Fatalf("buckets = %d, want 10", len(all))
	}
	if all[0].Frames.Presented != 100 || len(all[0].Hist.Counts) != gamesense.HistBins {
		t.Fatalf("bucket = %+v", all[0])
	}
	if all[0].Frames.Dropped != nil {
		t.Fatalf("an unmeasured drop count surfaced as %v", *all[0].Frames.Dropped)
	}

	path := "/api/v1/game-runs/run_1/buckets?since=" +
		strconv.FormatInt(start.Add(3*time.Second).Unix(), 10) +
		"&until=" + strconv.FormatInt(start.Add(6*time.Second).Unix(), 10)
	w = gameReq(t, d, d.handleGameRunBuckets, http.MethodGet, path, "run_1")
	var ranged []gamesense.Bucket
	if err := json.Unmarshal(w.Body.Bytes(), &ranged); err != nil {
		t.Fatalf("decode ranged: %v", err)
	}
	if len(ranged) != 3 {
		t.Fatalf("ranged buckets = %d, want the half-open [3,6) window", len(ranged))
	}
}

// TestDeleteGameRunCascades: the delete removes the seconds too, and a run in
// another site is invisible to this one rather than deletable through it.
func TestDeleteGameRunCascades(t *testing.T) {
	db, d := openGameAPI(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	seedGameRun(t, db, "agent_game", "run_1", start, 5)

	w := gameReq(t, d, d.handleDeleteGameRun, http.MethodDelete, "/api/v1/game-runs/run_1", "run_1")
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: status=%d body=%s", w.Code, w.Body.String())
	}
	var buckets int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_buckets`).Scan(&buckets); err != nil {
		t.Fatal(err)
	}
	if buckets != 0 {
		t.Fatalf("game_buckets = %d rows after the run was deleted", buckets)
	}
	if w := gameReq(t, d, d.handleDeleteGameRun, http.MethodDelete, "/api/v1/game-runs/run_1", "run_1"); w.Code != http.StatusNotFound {
		t.Fatalf("second delete: status=%d, want 404", w.Code)
	}

	// A run owned by another site must not be reachable through the default one.
	seedGameRun(t, db, "agent_game", "run_2", start, 1)
	if _, err := db.ExecContext(ctx, `UPDATE game_runs SET site_id='site_other' WHERE id='run_2'`); err != nil {
		t.Fatal(err)
	}
	if w := gameReq(t, d, d.handleGetGameRun, http.MethodGet, "/api/v1/game-runs/run_2", "run_2"); w.Code != http.StatusNotFound {
		t.Fatalf("cross-site read: status=%d, want 404", w.Code)
	}
}

// TestGameEndpointsWithoutService: a server-core build wired without the game
// store answers 503 rather than panicking on a nil dependency.
func TestGameEndpointsWithoutService(t *testing.T) {
	d := Deps{}
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
	}{
		{"list", d.handleListGameRuns},
		{"get", d.handleGetGameRun},
		{"buckets", d.handleGameRunBuckets},
		{"delete", d.handleDeleteGameRun},
	} {
		if w := gameReq(t, d, tc.h, http.MethodGet, "/api/v1/game-runs/x", "x"); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s without the service: status=%d, want 503", tc.name, w.Code)
		}
	}
}
