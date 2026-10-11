package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/asnlookup"
	"github.com/nettact/server-core/routehist"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// routeASN resolves 11/8 → AS100, 21/8 → AS300, 22/8 → AS400, 31/8 → AS500.
type routeASN struct{}

func (routeASN) Version() string { return "2026-10-01" }
func (routeASN) Lookup(a netip.Addr) (asnlookup.Info, bool) {
	if !asnlookup.IsPublicIPv4(a) {
		return asnlookup.Info{}, false
	}
	m := map[byte]uint32{11: 100, 21: 300, 22: 400, 31: 500}
	b := a.As4()
	asn, ok := m[b[0]]
	if !ok {
		return asnlookup.Info{}, false
	}
	return asnlookup.Info{ASN: asn, Name: fmt.Sprintf("NET-%d", asn), Country: "CN", Prefix: fmt.Sprintf("%d.0.0.0/8", b[0])}, true
}

func seedRouteDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.Open(t)
	now := time.Now().UTC()
	for _, q := range []string{
		`INSERT INTO sites(id,name) VALUES('site_default','Default')`,
		`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,status) VALUES('agent_a','site_default',x'00','h','box-a','online')`,
		`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,display_name,status) VALUES('agent_b','site_default',x'01','h2','box-b','Old box','online')`,
		`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('g1','site_default','All',1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m1','site_default','g1','trace','Route','example.com','{}',1,1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m2','site_default','g1','icmp','Ping','example.com','{}',1,1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m3','site_default','g1','trace','Fresh','example.org','{}',1,1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO monitor_status(agent_id,monitor_id,status,missing_permissions,matched_selector,reason,policy_hash,config_version,target_config_serial,source,assigned_at,updated_at)
		VALUES('agent_a','m1','active','[]','','','',1,1,'reported',?,?),
		      ('agent_b','m1','unsupported','[]','','agent_upgrade_required','',1,1,'predicted',?,?)`, now, now, now, now); err != nil {
		t.Fatal(err)
	}

	ts := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	sweep := func(transit string, rtt float64) telemetry.TraceResult {
		n++
		ts = ts.Add(10 * time.Minute)
		tr := telemetry.TraceResult{
			ReportID: fmt.Sprintf("r%d", n), DestinationIP: "31.0.0.9", Reached: true, ReachedTTL: 4,
			TriggerReason: telemetry.TraceTriggerScheduled, Status: telemetry.TraceStatusSucceeded,
			StartedAt: ts, MonitorID: "m1", ConfigSerial: 1,
		}
		for i, ip := range []string{"192.168.1.1", "11.0.0.1", transit, "31.0.0.9"} {
			hop := telemetry.TraceHop{TTL: i + 1}
			for k := 0; k < 3; k++ {
				r := float64(i + 1)
				if i == 3 {
					r = rtt
				}
				hop.Attempts = append(hop.Attempts, telemetry.TraceAttempt{ResponderAddr: ip, Hostname: "h" + ip, RTTMs: r})
			}
			tr.Hops = append(tr.Hops, hop)
		}
		return tr
	}
	runs := []telemetry.TraceResult{sweep("21.0.0.1", 38), sweep("21.0.0.1", 38), sweep("22.0.0.1", 172), sweep("22.0.0.1", 172), sweep("22.0.0.1", 172)}
	if err := db.WriteTx(context.Background(), store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		return nil, routehist.ApplyTx(context.Background(), store.Standalone(), wtx, routeASN{}, "agent_a", runs, ts.Add(time.Minute))
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

func routeGet(t *testing.T, h http.HandlerFunc, path, id string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h(w, r)
	var out map[string]any
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s: %v (%s)", path, err, w.Body.String())
		}
	}
	return w.Code, out
}

func hasKeys(t *testing.T, what string, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("%s has no %q (got %v)", what, k, m)
		}
	}
}

func asnList(v any) []float64 {
	var out []float64
	for _, h := range v.([]any) {
		out = append(out, h.(map[string]any)["asn"].(float64))
	}
	return out
}

func TestRouteOverviewEndpoint(t *testing.T) {
	db := seedRouteDB(t)
	d := Deps{Routes: routehist.New(db, routeASN{})}

	code, out := routeGet(t, d.handleTargetRoute, "/api/v1/targets/m1/route", "m1")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if out["asn_db_version"] != "2026-10-01" {
		t.Errorf("asn_db_version = %v", out["asn_db_version"])
	}
	agents := out["agents"].([]any)
	if len(agents) != 2 {
		t.Fatalf("agents = %d, want 2", len(agents))
	}
	byID := map[string]map[string]any{}
	for _, a := range agents {
		m := a.(map[string]any)
		hasKeys(t, "agent view", m, "agent_id", "agent_name", "status", "last_run_at", "current", "path")
		byID[m["agent_id"].(string)] = m
	}
	a := byID["agent_a"]
	if a["status"] != "active" || a["last_run_at"] == nil {
		t.Errorf("agent_a = %v", a)
	}
	cur := a["current"].(map[string]any)
	hasKeys(t, "epoch", cur, "id", "agent_id", "path_id", "as_path", "start_at", "end_at", "run_count",
		"deviation_count", "dest_ip", "local_asn", "rtt", "reached_ratio", "variants")
	if fmt.Sprint(asnList(cur["as_path"])) != "[100 400 500]" || cur["run_count"].(float64) != 3 ||
		cur["local_asn"].(float64) != 100 || cur["reached_ratio"].(float64) != 1 || cur["dest_ip"] != "31.0.0.9" {
		t.Errorf("current epoch = %v", cur)
	}
	hop := cur["as_path"].([]any)[0].(map[string]any)
	if hop["as_name"] != "NET-100" || hop["as_country"] != "CN" {
		t.Errorf("AS hop = %v", hop)
	}
	rtt := cur["rtt"].(map[string]any)
	hasKeys(t, "rtt", rtt, "count", "min_ms", "max_ms", "p50_ms", "p95_ms")
	if rtt["min_ms"].(float64) != 172 {
		t.Errorf("rtt = %v", rtt)
	}
	if _, err := time.Parse(time.RFC3339, cur["start_at"].(string)); err != nil {
		t.Errorf("start_at %v: %v", cur["start_at"], err)
	}
	path := a["path"].(map[string]any)
	hasKeys(t, "path", path, "path_id", "as_path", "hops", "reached")
	hops := path["hops"].([]any)
	if len(hops) != 4 || path["reached"] != true {
		t.Fatalf("path = %v", path)
	}
	first := hops[0].(map[string]any)
	resp := first["responders"].([]any)[0].(map[string]any)
	hasKeys(t, "responder", resp, "ip", "hostname", "asn", "as_name", "as_country", "prefix")
	if resp["ip"] != "192.168.1.1" || resp["asn"] != nil || first["timeout"] != false {
		t.Errorf("private first hop = %v / %v", first, resp)
	}
	third := hops[2].(map[string]any)["responders"].([]any)[0].(map[string]any)
	if third["asn"].(float64) != 400 || third["prefix"] != "22.0.0.0/8" || third["hostname"] != "h22.0.0.1" {
		t.Errorf("third hop = %v", third)
	}

	b := byID["agent_b"]
	if b["status"] != "agent_upgrade_required" || b["current"] != nil || b["path"] != nil || b["last_run_at"] != nil {
		t.Errorf("agent_b = %v", b)
	}
	if b["agent_name"] != "Old box" {
		t.Errorf("agent_b name = %v", b["agent_name"])
	}

	// An existing monitor with no history: agents listed, nothing current.
	code, out = routeGet(t, d.handleTargetRoute, "/api/v1/targets/m3/route", "m3")
	if code != http.StatusOK {
		t.Fatalf("empty monitor status %d", code)
	}
	for _, v := range out["agents"].([]any) {
		m := v.(map[string]any)
		if m["current"] != nil || m["path"] != nil {
			t.Errorf("fresh monitor agent = %v", m)
		}
		if m["status"] != "pending" {
			t.Errorf("fresh monitor agent status = %v, want pending", m["status"])
		}
	}

	if code, _ := routeGet(t, d.handleTargetRoute, "/x", "m2"); code != http.StatusBadRequest {
		t.Errorf("non-trace target = %d, want 400", code)
	}
	if code, _ := routeGet(t, d.handleTargetRoute, "/x", "nope"); code != http.StatusNotFound {
		t.Errorf("missing target = %d, want 404", code)
	}
}

func TestRouteEpochsEndpoint(t *testing.T) {
	db := seedRouteDB(t)
	d := Deps{Routes: routehist.New(db, routeASN{})}
	code, out := routeGet(t, d.handleRouteEpochs, "/api/v1/targets/m1/route/epochs?agent_id=agent_a", "m1")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	eps := out["epochs"].([]any)
	if len(eps) != 2 {
		t.Fatalf("epochs = %d", len(eps))
	}
	newest, oldest := eps[0].(map[string]any), eps[1].(map[string]any)
	if newest["start_at"].(string) <= oldest["start_at"].(string) {
		t.Errorf("epochs not newest first: %v then %v", newest["start_at"], oldest["start_at"])
	}
	if fmt.Sprint(asnList(oldest["as_path"])) != "[100 300 500]" || oldest["run_count"].(float64) != 2 {
		t.Errorf("oldest = %v", oldest)
	}
	v := oldest["variants"].([]any)
	if len(v) != 1 || v[0].(map[string]any)["count"].(float64) != 2 {
		t.Errorf("variants = %v", v)
	}

	if _, out := routeGet(t, d.handleRouteEpochs, "/x?limit=1", "m1"); len(out["epochs"].([]any)) != 1 {
		t.Errorf("limit ignored")
	}
	if _, out := routeGet(t, d.handleRouteEpochs, "/x?from=2030-01-01T00:00:00Z", "m1"); len(out["epochs"].([]any)) != 0 {
		t.Errorf("from ignored")
	}
	if _, out := routeGet(t, d.handleRouteEpochs, "/x?to=2026-09-01T00:25:00Z", "m1"); len(out["epochs"].([]any)) != 1 {
		t.Errorf("to ignored: %v", out)
	}
	if _, out := routeGet(t, d.handleRouteEpochs, "/x?agent_id=agent_b", "m1"); out["epochs"] == nil || len(out["epochs"].([]any)) != 0 {
		t.Errorf("empty history must be [] not null: %v", out)
	}
	for _, bad := range []string{"/x?from=yesterday", "/x?to=1", "/x?limit=0", "/x?limit=abc"} {
		if code, _ := routeGet(t, d.handleRouteEpochs, bad, "m1"); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", bad, code)
		}
	}
	if code, _ := routeGet(t, d.handleRouteEpochs, "/x", "m2"); code != http.StatusBadRequest {
		t.Errorf("non-trace = %d", code)
	}
	if code, _ := routeGet(t, d.handleRouteEpochs, "/x", "nope"); code != http.StatusNotFound {
		t.Errorf("missing = %d", code)
	}
}

func TestRouteChangesEndpoints(t *testing.T) {
	db := seedRouteDB(t)
	d := Deps{Routes: routehist.New(db, routeASN{})}
	code, out := routeGet(t, d.handleRouteChanges, "/api/v1/targets/m1/route/changes", "m1")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	cs := out["changes"].([]any)
	if len(cs) != 1 {
		t.Fatalf("changes = %d", len(cs))
	}
	c := cs[0].(map[string]any)
	hasKeys(t, "change", c, "id", "monitor_id", "agent_id", "agent_name", "kind", "segment", "diverge_ttl",
		"confirmed_at", "from_epoch_id", "to_epoch_id", "from_as_path", "to_as_path", "rtt_before", "rtt_after")
	if c["kind"] != "route" || c["segment"] != "isp_backbone" || c["diverge_ttl"].(float64) != 3 ||
		c["agent_name"] != "box-a" || c["monitor_id"] != "m1" {
		t.Errorf("change = %v", c)
	}
	if fmt.Sprint(asnList(c["from_as_path"])) != "[100 300 500]" || fmt.Sprint(asnList(c["to_as_path"])) != "[100 400 500]" {
		t.Errorf("as paths = %v → %v", c["from_as_path"], c["to_as_path"])
	}
	before := c["rtt_before"].(map[string]any)["p50_ms"].(float64)
	after := c["rtt_after"].(map[string]any)["p50_ms"].(float64)
	if before != 38 || after != 172 {
		t.Errorf("rtt p50 before/after = %v/%v", before, after)
	}

	if _, out := routeGet(t, d.handleRouteChanges, "/x?before="+c["confirmed_at"].(string), "m1"); len(out["changes"].([]any)) != 0 {
		t.Errorf("before is not exclusive")
	}
	if _, out := routeGet(t, d.handleRouteChanges, "/x?agent_id=agent_b", "m1"); len(out["changes"].([]any)) != 0 {
		t.Errorf("agent filter ignored")
	}
	if code, _ := routeGet(t, d.handleRouteChanges, "/x?before=nope", "m1"); code != http.StatusBadRequest {
		t.Errorf("bad before = %d", code)
	}
	if code, _ := routeGet(t, d.handleRouteChanges, "/x", "m2"); code != http.StatusBadRequest {
		t.Errorf("non-trace = %d", code)
	}

	id := fmt.Sprint(int64(c["id"].(float64)))
	code, det := routeGet(t, d.handleRouteChange, "/api/v1/route-changes/"+id, id)
	if code != http.StatusOK {
		t.Fatalf("detail status %d", code)
	}
	hasKeys(t, "detail", det, "change", "before", "after", "before_run", "after_run")
	if det["change"].(map[string]any)["id"] != c["id"] {
		t.Errorf("detail change = %v", det["change"])
	}
	if fmt.Sprint(asnList(det["before"].(map[string]any)["as_path"])) != "[100 300 500]" ||
		fmt.Sprint(asnList(det["after"].(map[string]any)["as_path"])) != "[100 400 500]" {
		t.Errorf("detail paths = %v / %v", det["before"], det["after"])
	}
	br := det["before_run"].(map[string]any)
	hasKeys(t, "run", br, "run_at", "dest_ip", "reached", "hops")
	hop := br["hops"].([]any)[2].(map[string]any)
	att := hop["attempts"].([]any)[0].(map[string]any)
	hasKeys(t, "attempt", att, "ip", "hostname", "rtt_ms", "timeout", "asn", "as_name")
	if att["ip"] != "21.0.0.1" || att["asn"].(float64) != 300 || att["rtt_ms"].(float64) != 3 || att["timeout"] != false {
		t.Errorf("before run attempt = %v", att)
	}
	ar := det["after_run"].(map[string]any)
	if ar["hops"].([]any)[2].(map[string]any)["attempts"].([]any)[0].(map[string]any)["ip"] != "22.0.0.1" {
		t.Errorf("after run = %v", ar)
	}

	for _, bad := range []string{"999", "abc", "0"} {
		if code, _ := routeGet(t, d.handleRouteChange, "/x", bad); code != http.StatusNotFound {
			t.Errorf("change %s = %d, want 404", bad, code)
		}
	}
}

func TestRouteSummariesEndpoint(t *testing.T) {
	db := seedRouteDB(t)
	if _, err := db.Exec(`INSERT INTO sites(id,name) VALUES('site_empty','Empty')`); err != nil {
		t.Fatal(err)
	}
	d := Deps{Routes: routehist.New(db, routeASN{})}

	code, out := routeGet(t, d.handleRouteSummaries, "/api/v1/sites/site_default/route-summaries", "site_default")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	hasKeys(t, "summaries", out, "asn_db_version", "targets")
	if out["asn_db_version"] != "2026-10-01" {
		t.Errorf("asn_db_version = %v", out["asn_db_version"])
	}
	targets := out["targets"].([]any)
	var ids []string
	for _, v := range targets {
		m := v.(map[string]any)
		hasKeys(t, "target summary", m, "target_id", "agents")
		ids = append(ids, m["target_id"].(string))
	}
	if fmt.Sprint(ids) != "[m3 m1]" { // ordered by name: Fresh, Route; the icmp target is excluded
		t.Fatalf("targets = %v", ids)
	}
	agents := targets[1].(map[string]any)["agents"].([]any)
	byID := map[string]map[string]any{}
	for _, v := range agents {
		m := v.(map[string]any)
		hasKeys(t, "agent summary", m, "agent_id", "agent_name", "status", "last_run_at", "current_since", "as_path",
			"dest_ip", "reached_ratio", "rtt_p50_ms", "last_change_at", "changes_24h", "changes_7d", "interval_seconds")
		byID[m["agent_id"].(string)] = m
	}
	a := byID["agent_a"]
	if a["status"] != "active" || a["current_since"] == nil || a["dest_ip"] != "31.0.0.9" ||
		fmt.Sprint(asnList(a["as_path"])) != "[100 400 500]" || a["interval_seconds"].(float64) != 600 ||
		a["last_change_at"] == nil || a["rtt_p50_ms"] == nil || a["reached_ratio"].(float64) != 1 {
		t.Errorf("agent_a = %v", a)
	}
	if _, err := time.Parse(time.RFC3339, a["current_since"].(string)); err != nil {
		t.Errorf("current_since %v: %v", a["current_since"], err)
	}
	b := byID["agent_b"]
	if b["status"] != "agent_upgrade_required" || b["current_since"] != nil || b["reached_ratio"] != nil ||
		len(b["as_path"].([]any)) != 0 || b["changes_7d"].(float64) != 0 {
		t.Errorf("agent_b = %v", b)
	}

	code, out = routeGet(t, d.handleRouteSummaries, "/x", "site_empty")
	if code != http.StatusOK || out["targets"] == nil || len(out["targets"].([]any)) != 0 {
		t.Errorf("empty site = %d %v, want 200 with targets:[]", code, out)
	}
	if code, _ := routeGet(t, d.handleRouteSummaries, "/x", "nope"); code != http.StatusNotFound {
		t.Errorf("unknown site = %d, want 404", code)
	}
}
