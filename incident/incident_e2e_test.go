package incident

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nettact/server-core/alert"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// TestOnRaisedWebhookEndToEnd drives the real fire path — bus → onRaised →
// diagnose → collectDetails (the alerts⨝rules⨝probe_tasks⨝agents join) → Notify
// → sendWebhook — and asserts the delivered payload states which target, what
// failed, and the measured value, in the channel's configured language.
func TestOnRaisedWebhookEndToEnd(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	// Seed the joined rows: site, agent (with display name), an HTTP probe target
	// named "商城", a rule (HTTP status ≠ 200), and one firing alert at value 503.
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name) VALUES('site_default','Home')`)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,display_name) VALUES('ag1','site_default',?,?,'raw-host','客厅主机')`, []byte("k"), "th")
	exec(`INSERT INTO probe_tasks(id,site_id,kind,target,params,enabled,name,all_agents) VALUES('pt1','site_default','http','https://shop.test','{}',1,'商城',1)`)
	exec(`INSERT INTO alert_rules(id,site_id,probe_task_id,name,metric_kind,comparator,threshold,for_seconds,layer,severity,enabled,is_template) VALUES('rule1','site_default','pt1','商城状态','probe.http.status','eq',200,0,'service','critical',1,0)`)
	exec(`INSERT INTO alerts(id,rule_id,agent_id,site_id,target,state,value,started_at) VALUES('al1','rule1','ag1','site_default','https://shop.test','firing',503,?)`, time.Now().UTC())

	// Webhook receiver capturing every delivered body.
	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	notif := notification.New(db)
	if _, err := notif.Create(ctx, "zh-hook", "webhook", map[string]string{"url": srv.URL, "lang": "zh"}); err != nil {
		t.Fatalf("create zh channel: %v", err)
	}
	if _, err := notif.Create(ctx, "en-hook", "webhook", map[string]string{"url": srv.URL, "lang": "en"}); err != nil {
		t.Fatalf("create en channel: %v", err)
	}

	set := settings.New(db)
	if err := set.Set(ctx, settings.KeyConsoleBaseURL, "http://localhost:8080/"); err != nil {
		t.Fatalf("set console url: %v", err)
	}
	bus := eventbus.New()
	svc := New(db, bus, notif, set)
	svc.Wire()

	// Fire. Publish is synchronous and sendWebhook blocks on the response, so both
	// deliveries have completed by the time Publish returns.
	bus.Publish(eventbus.TopicAlertRaised, alert.Raised{
		ID: "al1", RuleID: "rule1", RuleName: "商城状态", AgentID: "ag1",
		SiteID: "site_default", Target: "https://shop.test", Layer: "service",
		Severity: "critical", Value: 503, At: time.Now().UTC(),
	})

	// Delivery is dispatched off the correlation lock (go s.notify), so wait for
	// both channel deliveries to land.
	var got [][]byte
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		got = append([][]byte(nil), bodies...)
		mu.Unlock()
		if len(got) >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 webhook deliveries, got %d", len(got))
	}

	var zh, en notification.Payload
	type wb struct {
		notification.Payload
		Title string   `json:"title"`
		Lines []string `json:"lines"`
	}
	var zhBody, enBody wb
	for _, b := range got {
		var probe struct {
			Lines []string `json:"lines"`
		}
		_ = json.Unmarshal(b, &probe)
		// Distinguish by language via a token only present in one rendering.
		joined := strings.Join(probe.Lines, " ")
		if strings.Contains(joined, "返回状态码") {
			if err := json.Unmarshal(b, &zhBody); err != nil {
				t.Fatalf("unmarshal zh: %v", err)
			}
		} else if strings.Contains(joined, "returned HTTP") {
			if err := json.Unmarshal(b, &enBody); err != nil {
				t.Fatalf("unmarshal en: %v", err)
			}
		}
	}
	zh, en = zhBody.Payload, enBody.Payload

	// Structured payload must carry the specific facts (not just an aggregate).
	if len(zh.Details) != 1 || zh.Details[0].Target != "https://shop.test" || zh.Details[0].Value != 503 {
		t.Fatalf("zh payload details wrong: %+v", zh.Details)
	}
	if en.Scope != "single" || en.SuspectedLayer != "service" || en.Severity != "critical" {
		t.Fatalf("en payload scope/layer/severity wrong: %+v", en)
	}

	// Deep link: trailing slash on the base is normalized, incident id is included.
	wantURL := "http://localhost:8080/incidents?incident=" + zh.IncidentID
	if zh.URL != wantURL {
		t.Fatalf("deep link = %q, want %q", zh.URL, wantURL)
	}

	// Rendered human lines must name the target, the fault, the value, and host.
	zhLine := strings.Join(zhBody.Lines, " ")
	for _, want := range []string{"网站 商城（https://shop.test）", "返回状态码 503", "来自 客厅主机"} {
		if !strings.Contains(zhLine, want) {
			t.Errorf("zh line %q missing %q", zhLine, want)
		}
	}
	enLine := strings.Join(enBody.Lines, " ")
	for _, want := range []string{"site 商城 (https://shop.test)", "returned HTTP 503", "on 客厅主机"} {
		if !strings.Contains(enLine, want) {
			t.Errorf("en line %q missing %q", enLine, want)
		}
	}
	if zhBody.Title != "网络告警" {
		t.Errorf("zh title = %q", zhBody.Title)
	}

	// The incident summary stored for the UI must state the specific fault (not
	// just a vague "single-host fault, likely service layer") so the console's
	// summary column is readable at a glance.
	inc, err := svc.Get(ctx, zh.IncidentID)
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if !strings.Contains(inc.Summary, "返回状态码 503") {
		t.Errorf("stored summary = %q, want the concrete fault", inc.Summary)
	}

	// Timeline must record the specific fault, not just "rule — target = 503".
	tl, err := svc.Timeline(ctx, zh.IncidentID)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	var raised string
	for _, e := range tl {
		if e.Kind == "alert.raised" {
			raised = e.Message
		}
	}
	if !strings.Contains(raised, "返回状态码 503") {
		t.Errorf("timeline raised line = %q", raised)
	}
}
