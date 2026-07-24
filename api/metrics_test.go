package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/metrics"
)

// TestAgentMetricsSummary covers the PERF-001 aggregation endpoint: JSON shape
// (including nulls for kinds with no samples) and the 400 guards.
func TestAgentMetricsSummary(t *testing.T) {
	db := openStatusDB(t)
	ctx := context.Background()
	ms := metrics.New(db)
	d := Deps{Metrics: ms}

	now := time.Now()
	batch := []telemetry.Metric{
		{TS: now.Add(-30 * time.Second), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 10, Unit: "ms", MonitorID: "target-1"},
		{TS: now.Add(-20 * time.Second), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 20, Unit: "ms", MonitorID: "target-1"},
		{TS: now.Add(-10 * time.Second), Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: "internet", Value: 35, Unit: "ms", MonitorID: "target-1"},
	}
	ids, err := ms.EnsureSeries(ctx, "agent-1", "site_default", batch)
	if err != nil {
		t.Fatalf("EnsureSeries: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := ms.InsertSamples(ctx, tx, "agent-1", ids, batch); err != nil {
		t.Fatalf("InsertSamples: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

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
