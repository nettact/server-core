package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

// openMetricsStore returns a status-fixture DB plus a metrics store over a
// throwaway data plane.
func openMetricsStore(t *testing.T) (*store.DB, *metrics.Store) {
	t.Helper()
	db := openStatusDB(t)
	return db, metrics.New(db, tsstoretest.Open(t))
}

// seedMetrics lands a batch through the production write path: series resolved
// pre-transaction, the 1m rollup watermark rewound inside it, raw samples
// appended after commit, latest cache folded.
func seedMetrics(t *testing.T, db *store.DB, ms *metrics.Store, agentID string, batch []telemetry.Metric) {
	t.Helper()
	ctx := context.Background()
	ids, err := ms.EnsureSeries(ctx, agentID, "site_default", batch)
	if err != nil {
		t.Fatalf("EnsureSeries: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := ms.RewindForBatch(ctx, tx, agentID, ids, batch); err != nil {
		t.Fatalf("RewindForBatch: %v", err)
	}
	pendingDone := ms.BeginPendingAppend(ids)
	defer func() {
		if pendingDone != nil {
			pendingDone()
		}
	}()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := ms.AppendRawSamples(ctx, agentID, ids, batch); err != nil {
		t.Fatalf("AppendRawSamples: %v", err)
	}
	pendingDone()
	pendingDone = nil
	ms.UpdateLatest(agentID, ids, batch)
}

// TestAgentMetricsUntilWindow covers the optional absolute upper bound on the
// series endpoint. since_seconds stays RELATIVE (seconds before now) while until
// is an ABSOLUTE unix timestamp, so the effective window is
// [now − since_seconds, min(now, until)] — which is what lets the console chart a
// historical game run without the range silently stretching to now.
func TestAgentMetricsUntilWindow(t *testing.T) {
	db, ms := openMetricsStore(t)
	d := Deps{Metrics: ms}

	now := time.Now()
	batch := []telemetry.Metric{
		{TS: now.Add(-50 * time.Minute), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 10, Unit: "ms", MonitorID: "target-1"},
		{TS: now.Add(-40 * time.Minute), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 20, Unit: "ms", MonitorID: "target-1"},
		{TS: now.Add(-30 * time.Minute), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 30, Unit: "ms", MonitorID: "target-1"},
	}
	seedMetrics(t, db, ms, "agent-1", batch)

	get := func(query string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-1/metrics"+query, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "agent-1")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()
		d.handleAgentMetrics(w, r)
		return w
	}
	points := func(query string) []metrics.Point {
		t.Helper()
		w := get(query)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", query, w.Code, w.Body.String())
		}
		var pts []metrics.Point
		if err := json.Unmarshal(w.Body.Bytes(), &pts); err != nil {
			t.Fatalf("%s: decode: %v body=%s", query, err, w.Body.String())
		}
		return pts
	}

	const base = "?kind=probe.icmp.rtt_ms&monitor=target-1&since_seconds=3600"
	if pts := points(base); len(pts) != 3 {
		t.Fatalf("unbounded window = %d points, want 3", len(pts))
	}

	// Bounded to the middle sample: inclusive at the top, so two points.
	mid := now.Add(-40 * time.Minute).Unix()
	pts := points(base + "&until=" + strconv.FormatInt(mid, 10))
	if len(pts) != 2 {
		t.Fatalf("until=mid gave %d points, want 2 (inclusive bound)", len(pts))
	}
	if pts[len(pts)-1].Value != 20 {
		t.Fatalf("last point = %v, want the sample at the bound", pts[len(pts)-1].Value)
	}

	// An until in the future is the same as no until: nothing exists past now.
	if pts := points(base + "&until=" + strconv.FormatInt(now.Add(time.Hour).Unix(), 10)); len(pts) != 3 {
		t.Fatalf("future until = %d points, want the unbounded 3", len(pts))
	}

	// An until BEFORE the window start is an empty range, not a bad request.
	w := get(base + "&until=" + strconv.FormatInt(now.Add(-2*time.Hour).Unix(), 10))
	if w.Code != http.StatusOK {
		t.Fatalf("until before the window: status=%d body=%s", w.Code, w.Body.String())
	}
	if body := strings.TrimSpace(w.Body.String()); body != "[]" {
		t.Fatalf("until before the window = %s, want an empty array", body)
	}

	// A malformed bound is refused rather than ignored — silently dropping it would
	// answer with a window the caller did not ask for and nothing would say so.
	for _, bad := range []string{"abc", "0", "-5", "1.5"} {
		if w := get(base + "&until=" + bad); w.Code != http.StatusBadRequest {
			t.Fatalf("until=%s: status=%d, want 400", bad, w.Code)
		}
	}
}

// TestAgentMetricsSummary covers the PERF-001 aggregation endpoint: JSON shape
// (including nulls for kinds with no samples) and the 400 guards.
func TestAgentMetricsSummary(t *testing.T) {
	db, ms := openMetricsStore(t)
	d := Deps{Metrics: ms}

	now := time.Now()
	batch := []telemetry.Metric{
		{TS: now.Add(-30 * time.Second), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 10, Unit: "ms", MonitorID: "target-1"},
		{TS: now.Add(-20 * time.Second), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 20, Unit: "ms", MonitorID: "target-1"},
		{TS: now.Add(-10 * time.Second), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 35, Unit: "ms", MonitorID: "target-1"},
	}
	seedMetrics(t, db, ms, "agent-1", batch)

	get := func(query string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-1/metrics/summary"+query, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "agent-1")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()
		d.handleAgentMetricsSummary(w, r)
		return w
	}

	if w := get(""); w.Code != http.StatusBadRequest {
		t.Fatalf("missing kinds: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := get("?kinds=probe.icmp.rtt_ms&since_seconds=604800"); w.Code != http.StatusBadRequest {
		t.Fatalf("window beyond raw retention: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := get("?kinds=probe.icmp.rtt_ms&reduce=median"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown reduce mode: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := get("?kinds=probe.icmp.rtt_ms&since_seconds=86400&reduce=worst&exclude_targets=gateway"); w.Code != http.StatusOK {
		t.Fatalf("24h worst summary: status=%d body=%s", w.Code, w.Body.String())
	}

	w := get("?kinds=probe.icmp.rtt_ms,probe.icmp.loss_pct&monitor=target-1")
	if w.Code != http.StatusOK {
		t.Fatalf("summary: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		WindowSeconds int64                          `json:"window_seconds"`
		Kinds         map[string]metrics.KindSummary `json:"kinds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	if resp.WindowSeconds != 7200 {
		t.Errorf("window_seconds = %d, want 7200", resp.WindowSeconds)
	}
	rtt, ok := resp.Kinds["probe.icmp.rtt_ms"]
	if !ok || rtt.Count != 3 || rtt.Latest == nil || rtt.Latest.Value != 35 || rtt.P95 == nil || *rtt.P95 != 35 {
		t.Errorf("rtt summary = %+v ok=%v, want count 3 latest 35 p95 35", rtt, ok)
	}
	loss, ok := resp.Kinds["probe.icmp.loss_pct"]
	if !ok || loss.Count != 0 || loss.Latest != nil || loss.P95 != nil {
		t.Errorf("loss summary = %+v ok=%v, want present zero summary with nulls", loss, ok)
	}
}
