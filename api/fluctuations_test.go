package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The fluctuation endpoint's job is to make an unexplained availability dip
// explainable, so what it must get right is the explanation: the same bilingual
// sentence the fault centre uses (never a second vocabulary for the same failure),
// the per-round causes, and a total that survives paging. These pin that.

func openFluxDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.Open(t)
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return db
}

// insertFlux writes a fluctuation row directly; the engine's own tests cover how
// one comes to exist, so these only need a row to render.
func insertFlux(t *testing.T, db *store.DB, id, targetID string, reason int, detail string, endedAt time.Time) {
	t.Helper()
	rounds, err := json.Marshal([]fault.FailEvidence{
		{TS: endedAt.Unix() - 20, MetricKind: string(telemetry.ICMPLoss), Value: 100,
			ReasonCode: telemetry.ProbeReasonTimeout, ReasonDetail: "i/o timeout"},
		{TS: endedAt.Unix() - 10, MetricKind: string(telemetry.ICMPLoss), Value: 100,
			ReasonCode: reason, ReasonDetail: detail},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO fluctuations(id, site_id, agent_id, agent_name, target_id, target_name, target_addr,
		    probe_kind, layer, fail_rounds, fail_threshold, metric_kind, comparator, value, threshold,
		    reason_code, reason_detail, rounds_json, started_at, ended_at)
		VALUES(?,'site_default','agent_a','node-1',?,'Router','192.168.1.1','icmp','lan',2,3,?,'gte',100,100,?,?,?,?,?)`,
		id, targetID, string(telemetry.ICMPLoss), reason, detail, string(rounds),
		endedAt.Add(-20*time.Second), endedAt); err != nil {
		t.Fatal(err)
	}
}

func getFluctuations(t *testing.T, d Deps, query string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/fluctuations"+query, nil)
	w := httptest.NewRecorder()
	d.handleListFluctuations(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", query, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, w.Body.String())
	}
	return out
}

// TestFluctuationsDescribeTheFailure is the consistency requirement: the reason a
// fluctuation gives must be the reason a fault would give for the same failure. If
// these two rendered independently, an operator comparing a blip against an outage
// would be reading two different vocabularies for one cause.
func TestFluctuationsDescribeTheFailure(t *testing.T) {
	db := openFluxDB(t)
	d := Deps{Fault: fault.New(db, nil, nil)}
	insertFlux(t, db, "flx_1", "t_icmp", telemetry.ProbeReasonUnreachable, "no route to host", time.Now().UTC())

	body := getFluctuations(t, d, "")
	items, ok := body["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected 1 item, got %v", body["items"])
	}
	item := items[0].(map[string]any)

	// The same phrase the notification renderer produces for a fault.
	if zh, _ := item["desc_zh"].(string); !strings.Contains(zh, "网络不可达") {
		t.Errorf("desc_zh must name the cause: %q", zh)
	}
	if en, _ := item["desc_en"].(string); !strings.Contains(en, "network unreachable") {
		t.Errorf("desc_en must name the cause: %q", en)
	}
	// Per-round causes survive the round trip: the first round timed out and the
	// second was unreachable, and both have to be visible.
	rounds, ok := item["rounds"].([]any)
	if !ok || len(rounds) != 2 {
		t.Fatalf("expected 2 rounds, got %v", item["rounds"])
	}
	first := rounds[0].(map[string]any)
	if code, _ := first["reason_code"].(float64); int(code) != telemetry.ProbeReasonTimeout {
		t.Errorf("first round should keep its own cause, got %v", first["reason_code"])
	}
	if detail, _ := first["reason_detail"].(string); detail != "i/o timeout" {
		t.Errorf("raw underlying error must survive verbatim, got %q", detail)
	}
	// "2 of 3" is why no alert fired, and the console renders it as such.
	if n, _ := item["fail_rounds"].(float64); int(n) != 2 {
		t.Errorf("fail_rounds = %v, want 2", item["fail_rounds"])
	}
	if n, _ := item["fail_threshold"].(float64); int(n) != 3 {
		t.Errorf("fail_threshold = %v, want 3", item["fail_threshold"])
	}
}

// TestFluctuationsTotalSurvivesLimit: the availability card shows a count while
// fetching at most a page, so the total must describe the filter and not the page.
func TestFluctuationsTotalSurvivesLimit(t *testing.T) {
	db := openFluxDB(t)
	d := Deps{Fault: fault.New(db, nil, nil)}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		insertFlux(t, db, "flx_"+string(rune('a'+i)), "t_icmp",
			telemetry.ProbeReasonTimeout, "i/o timeout", now.Add(-time.Duration(i)*time.Minute))
	}

	body := getFluctuations(t, d, "?limit=1")
	if items, _ := body["items"].([]any); len(items) != 1 {
		t.Fatalf("limit=1 should return one item, got %d", len(items))
	}
	if total, _ := body["total"].(float64); int(total) != 3 {
		t.Fatalf("total = %v, want 3 regardless of limit", body["total"])
	}
}

// TestFluctuationsFilterByTarget: every surface asks about one target, so an
// unrelated target's dips must not leak into its history.
func TestFluctuationsFilterByTarget(t *testing.T) {
	db := openFluxDB(t)
	d := Deps{Fault: fault.New(db, nil, nil)}
	now := time.Now().UTC()
	insertFlux(t, db, "flx_1", "t_one", telemetry.ProbeReasonTimeout, "i/o timeout", now)
	insertFlux(t, db, "flx_2", "t_two", telemetry.ProbeReasonRefused, "refused", now)

	body := getFluctuations(t, d, "?target=t_one")
	items, _ := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected only t_one's fluctuation, got %d", len(items))
	}
	if got := items[0].(map[string]any)["target_id"]; got != "t_one" {
		t.Fatalf("wrong target returned: %v", got)
	}
	// An empty result is a legitimate answer, and must serialize as [] rather than
	// null so the console can render "no fluctuations" instead of failing on it.
	empty := getFluctuations(t, d, "?target=t_nothing")
	if items, ok := empty["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("expected an empty array, got %#v", empty["items"])
	}
	if total, _ := empty["total"].(float64); int(total) != 0 {
		t.Fatalf("expected total 0, got %v", empty["total"])
	}
}

