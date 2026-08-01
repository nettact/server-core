package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/gamedata"
	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

func openGameProfileAPI(t *testing.T) (*store.DB, Deps) {
	t.Helper()
	db, d := openGameAPI(t)
	d.Config = config.New(db, registry.New(db, 0, nil), eventbus.New(), nil)
	return db, d
}

// gameProfileReq issues a request with a JSON body and the {id} route param the
// handlers read, the way chi delivers it.
func gameProfileReq(t *testing.T, h http.HandlerFunc, method, path, id string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rdr)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func decodeProfile(t *testing.T, w *httptest.ResponseRecorder) config.GameProfileRec {
	t.Helper()
	var p config.GameProfileRec
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode profile: %v body=%s", err, w.Body.String())
	}
	return p
}

// TestGameProfileEndpoints pins the contract the console is written against: the
// DTO shape, the status codes, and the fields that must be present as null
// rather than omitted.
func TestGameProfileEndpoints(t *testing.T) {
	_, d := openGameProfileAPI(t)

	w := gameProfileReq(t, d.handleListGameProfiles, http.MethodGet,
		"/api/v1/sites/site_default/game-profiles", "site_default", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("empty list: status=%d body=%s", w.Code, w.Body.String())
	}
	// An empty list must be [] and not null, or the console has to special-case it.
	if got := w.Body.String(); !bytes.Contains([]byte(got), []byte(`"items":[]`)) {
		t.Fatalf("empty list body = %s, want an empty items array", got)
	}

	w = gameProfileReq(t, d.handleCreateGameProfile, http.MethodPost,
		"/api/v1/sites/site_default/game-profiles", "site_default", map[string]any{
			"name": "Counter-Strike", "exe": []string{"cs2.exe"},
			"target_fps": 144, "tier": "base", "monitor_ids": []string{"probe_a"},
		})
	if w.Code != http.StatusOK {
		t.Fatalf("create: status=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeProfile(t, w)
	if created.ID == "" || created.SiteID != "site_default" || created.Name != "Counter-Strike" {
		t.Fatalf("created = %+v", created)
	}
	if created.TargetFPS == nil || *created.TargetFPS != 144 || created.Tier != "base" {
		t.Fatalf("created = %+v, want 144 fps / base", created)
	}
	if len(created.Exe) != 1 || len(created.MonitorIDs) != 1 {
		t.Fatalf("created lists = %v / %v", created.Exe, created.MonitorIDs)
	}

	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "site_id", "name", "exe", "target_fps", "tier", "monitor_ids", "created_at", "updated_at"} {
		if _, present := raw[key]; !present {
			t.Fatalf("DTO is missing %q: %s", key, w.Body.String())
		}
	}

	// target_fps must be an explicit null when unset — an omitted key would let a
	// console default it to 0 and render a game targeting no frames at all.
	w = gameProfileReq(t, d.handleUpdateGameProfile, http.MethodPut,
		"/api/v1/game-profiles/"+created.ID, created.ID, map[string]any{
			"name": "CS", "exe": []string{"cs2.exe", "csgo.exe"}, "target_fps": nil, "tier": "diag",
		})
	if w.Code != http.StatusOK {
		t.Fatalf("update: status=%d body=%s", w.Code, w.Body.String())
	}
	updated := decodeProfile(t, w)
	if updated.TargetFPS != nil || updated.Name != "CS" || len(updated.Exe) != 2 || updated.Tier != "diag" {
		t.Fatalf("updated = %+v", updated)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if v, present := raw["target_fps"]; !present || v != nil {
		t.Fatalf("target_fps = %v (present=%v), want an explicit null", v, present)
	}

	w = gameProfileReq(t, d.handleListGameProfiles, http.MethodGet,
		"/api/v1/sites/site_default/game-profiles", "site_default", nil)
	var list struct {
		Items []config.GameProfileRec `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].ID != created.ID {
		t.Fatalf("list = %+v", list.Items)
	}

	if w = gameProfileReq(t, d.handleDeleteGameProfile, http.MethodDelete,
		"/api/v1/game-profiles/"+created.ID, created.ID, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: status=%d body=%s", w.Code, w.Body.String())
	}
	if w = gameProfileReq(t, d.handleDeleteGameProfile, http.MethodDelete,
		"/api/v1/game-profiles/"+created.ID, created.ID, nil); w.Code != http.StatusNotFound {
		t.Fatalf("second delete: status=%d, want 404", w.Code)
	}
	if w = gameProfileReq(t, d.handleUpdateGameProfile, http.MethodPut,
		"/api/v1/game-profiles/gone", "gone", map[string]any{
			"name": "x", "exe": []string{"a.exe"},
		}); w.Code != http.StatusNotFound {
		t.Fatalf("update unknown: status=%d, want 404", w.Code)
	}
}

// TestGameProfileRoutesAreRegisteredAndGuarded pins the six paths the console
// calls, through the real router rather than by invoking handlers directly. A
// registered route answers 401 without a session (the guard ran); an
// unregistered one answers 404 (chi never found it), so this fails loudly if a
// path or method is ever changed out from under the console.
func TestGameProfileRoutesAreRegisteredAndGuarded(t *testing.T) {
	db, d := openGameProfileAPI(t)
	d.Identity = identity.New(db)
	router := Router(d)

	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/sites/site_default/game-profiles"},
		{http.MethodPost, "/api/v1/sites/site_default/game-profiles"},
		{http.MethodPut, "/api/v1/game-profiles/gprof_1"},
		{http.MethodDelete, "/api/v1/game-profiles/gprof_1"},
		{http.MethodGet, "/api/v1/sites/site_default/game-collection"},
		{http.MethodPut, "/api/v1/sites/site_default/game-collection"},
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s = %d, want 401 (a registered, session-guarded route)",
				route.method, route.path, w.Code)
		}
	}
}

func TestGameProfileValidationIsA400(t *testing.T) {
	_, d := openGameProfileAPI(t)
	for name, body := range map[string]any{
		"no name":      map[string]any{"exe": []string{"a.exe"}},
		"no exe":       map[string]any{"name": "A"},
		"blank exe":    map[string]any{"name": "A", "exe": []string{" "}},
		"bad tier":     map[string]any{"name": "A", "exe": []string{"a.exe"}, "tier": "turbo"},
		"absurd fps":   map[string]any{"name": "A", "exe": []string{"a.exe"}, "target_fps": 5000},
		"negative fps": map[string]any{"name": "A", "exe": []string{"a.exe"}, "target_fps": -5},
	} {
		w := gameProfileReq(t, d.handleCreateGameProfile, http.MethodPost,
			"/api/v1/sites/site_default/game-profiles", "site_default", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s, want 400", name, w.Code, w.Body.String())
		}
		var errBody map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil || errBody["error"] == "" {
			t.Fatalf("%s: error body = %s", name, w.Body.String())
		}
	}
}

// A profile belonging to another site must be invisible through this one rather
// than editable through it — the same ownership rule every site-scoped handler
// enforces.
func TestGameProfileCrossSiteIsNotFound(t *testing.T) {
	db, d := openGameProfileAPI(t)
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO sites(id,name) VALUES('site_other','Other')`); err != nil {
		t.Fatal(err)
	}
	w := gameProfileReq(t, d.handleCreateGameProfile, http.MethodPost,
		"/api/v1/sites/site_other/game-profiles", "site_other", map[string]any{
			"name": "Theirs", "exe": []string{"theirs.exe"},
		})
	if w.Code != http.StatusOK {
		t.Fatalf("create in the other site: status=%d body=%s", w.Code, w.Body.String())
	}
	foreign := decodeProfile(t, w)

	// The default site is what siteParam falls back to, so these address site_default.
	if w = gameProfileReq(t, d.handleUpdateGameProfile, http.MethodPut,
		"/api/v1/game-profiles/"+foreign.ID, foreign.ID, map[string]any{
			"name": "Stolen", "exe": []string{"a.exe"},
		}); w.Code != http.StatusNotFound {
		t.Fatalf("cross-site update: status=%d, want 404", w.Code)
	}
	if w = gameProfileReq(t, d.handleDeleteGameProfile, http.MethodDelete,
		"/api/v1/game-profiles/"+foreign.ID, foreign.ID, nil); w.Code != http.StatusNotFound {
		t.Fatalf("cross-site delete: status=%d, want 404", w.Code)
	}
}

func TestGameCollectionEndpoint(t *testing.T) {
	_, d := openGameProfileAPI(t)
	w := gameProfileReq(t, d.handleGetGameCollection, http.MethodGet,
		"/api/v1/sites/site_default/game-collection", "site_default", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status=%d body=%s", w.Code, w.Body.String())
	}
	var got gameCollectionBody
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.RecordUnmatched {
		t.Fatal("default record_unmatched = false, want everything recorded out of the box")
	}

	w = gameProfileReq(t, d.handleUpdateGameCollection, http.MethodPut,
		"/api/v1/sites/site_default/game-collection", "site_default",
		gameCollectionBody{RecordUnmatched: false})
	if w.Code != http.StatusOK {
		t.Fatalf("put: status=%d body=%s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.RecordUnmatched {
		t.Fatalf("put echoed %+v, want the value it stored", got)
	}
	w = gameProfileReq(t, d.handleGetGameCollection, http.MethodGet,
		"/api/v1/sites/site_default/game-collection", "site_default", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.RecordUnmatched {
		t.Fatalf("re-read = %+v, want the stored false", got)
	}
}

// TestListGameRunsProfileFilter covers the query param the console's default
// filter uses, including the refusal that keeps a typo from quietly widening the
// list back to every process on the machine.
func TestListGameRunsProfileFilter(t *testing.T) {
	db, d := openGameProfileAPI(t)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	ctx := context.Background()

	w := gameProfileReq(t, d.handleCreateGameProfile, http.MethodPost,
		"/api/v1/sites/site_default/game-profiles", "site_default", map[string]any{
			"name": "A Game", "exe": []string{"game.exe"},
		})
	if w.Code != http.StatusOK {
		t.Fatalf("create profile: %s", w.Body.String())
	}
	profile := decodeProfile(t, w)

	seedGameRun(t, db, "agent_game", "run_game", start, 3)
	seedGameRun(t, db, "agent_game", "run_browser", start, 3)
	if _, err := db.ExecContext(ctx,
		`UPDATE game_runs SET profile_id=? WHERE id='run_game'`, profile.ID); err != nil {
		t.Fatal(err)
	}

	list := func(query string) []gamedata.Run {
		t.Helper()
		w := gameReq(t, d, d.handleListGameRuns, http.MethodGet,
			"/api/v1/agents/agent_game/game-runs"+query, "agent_game")
		if w.Code != http.StatusOK {
			t.Fatalf("list%s: status=%d body=%s", query, w.Code, w.Body.String())
		}
		var page struct {
			Items []gamedata.Run `json:"items"`
			Total int            `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if page.Total != len(page.Items) {
			t.Fatalf("list%s total=%d items=%d", query, page.Total, len(page.Items))
		}
		return page.Items
	}

	if got := list(""); len(got) != 2 {
		t.Fatalf("default listing = %d runs, want both", len(got))
	}
	if got := list("?runs=all"); len(got) != 2 {
		t.Fatalf("runs=all = %d runs, want both", len(got))
	}
	profiled := list("?runs=profiled")
	if len(profiled) != 1 || profiled[0].ID != "run_game" {
		t.Fatalf("runs=profiled = %+v", profiled)
	}
	if profiled[0].ProfileName == nil || *profiled[0].ProfileName != "A Game" {
		t.Fatalf("profile_name = %v, want the joined name", profiled[0].ProfileName)
	}
	other := list("?runs=other")
	if len(other) != 1 || other[0].ID != "run_browser" || other[0].ProfileID != nil {
		t.Fatalf("runs=other = %+v", other)
	}

	w = gameReq(t, d, d.handleListGameRuns, http.MethodGet,
		"/api/v1/agents/agent_game/game-runs?runs=games-only", "agent_game")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown runs value: status=%d, want 400", w.Code)
	}

	// profile_id / profile_name must be present as explicit nulls on an unmatched
	// run, for the same reason every other optional field here is.
	w = gameReq(t, d, d.handleListGameRuns, http.MethodGet,
		"/api/v1/agents/agent_game/game-runs?runs=other", "agent_game")
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	item := raw["items"].([]any)[0].(map[string]any)
	for _, key := range []string{"profile_id", "profile_name"} {
		v, present := item[key]
		if !present {
			t.Fatalf("run JSON is missing %q entirely; it must be present as null", key)
		}
		if v != nil {
			t.Fatalf("%s = %v on an unmatched run, want null", key, v)
		}
	}
}
