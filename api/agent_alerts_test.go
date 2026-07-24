package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/store"
)

func TestHandleAgentAlertsRequiresOneTargetScope(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "agent-alerts.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent-1','site_default',x'00','h','online')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO alerts(id,agent_id,site_id,group_id,state,severity,started_at) VALUES('alert-1','agent-1','site_default','group-1','resolved','warn',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO alert_evidence(id,alert_id,condition_id,target_id,target_addr,metric_kind,comparator,threshold,value,observed_at) VALUES('e-1','alert-1','c-1','monitor-1','example.com','probe.http.ok','lt',1,0,?)`, now); err != nil {
		t.Fatal(err)
	}

	d := Deps{Alert: alert.New(db)}
	call := func(query string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-1/alerts"+query, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "agent-1")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()
		d.handleAgentAlerts(w, r)
		return w
	}

	if w := call(""); w.Code != http.StatusBadRequest {
		t.Fatalf("unscoped status=%d body=%s", w.Code, w.Body.String())
	}
	if w := call("?monitor=monitor-1&target=example.com"); w.Code != http.StatusBadRequest {
		t.Fatalf("double-scoped status=%d body=%s", w.Code, w.Body.String())
	}
	if w := call("?monitor=monitor-1"); w.Code != http.StatusOK || w.Body.String() == "[]\n" {
		t.Fatalf("monitor-scoped status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestHandleListAlertsDescIncludesReason verifies /alerts renders the frozen
// reason (code + raw detail) into desc_zh/desc_en — detailFromAlert must copy
// ReasonCode/ReasonDetail off the evidence, not just the breach facts.
func TestHandleListAlertsDescIncludesReason(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "list-alerts.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent-1','site_default',x'00','h','online')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO alerts(id,agent_id,site_id,group_id,state,severity,started_at) VALUES('alert-1','agent-1','site_default','group-1','firing','warn',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO alert_evidence(id,alert_id,condition_id,target_id,target_addr,probe_kind,metric_kind,comparator,threshold,value,reason_code,reason_detail,observed_at)
		VALUES('e-1','alert-1','c-1','monitor-1','1.1.1.1','icmp','probe.icmp.loss_pct','gte',50,100,?,?,?)`,
		telemetry.ProbeReasonUnreachable, "sendto: network is unreachable", now); err != nil {
		t.Fatal(err)
	}

	d := Deps{Alert: alert.New(db)}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	w := httptest.NewRecorder()
	d.handleListAlerts(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var views []struct {
		DescZh string `json:"desc_zh"`
		DescEn string `json:"desc_en"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &views); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	if len(views) != 1 {
		t.Fatalf("want 1 alert view, got %d", len(views))
	}
	if !strings.Contains(views[0].DescZh, "（原因：网络不可达 · sendto: network is unreachable）") {
		t.Errorf("desc_zh missing reason clause: %q", views[0].DescZh)
	}
	if !strings.Contains(views[0].DescEn, "(reason: network unreachable · sendto: network is unreachable)") {
		t.Errorf("desc_en missing reason clause: %q", views[0].DescEn)
	}
}
