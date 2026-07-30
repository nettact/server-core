package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/inventory"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store/storetest"
)

func TestHandleAgentInterfacesFreshnessAndShape(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_wifi','site_default',x'00','h','online')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agent_wifi(agent_id,state,reason,sampled_at,last_sequence,default_gateway,default_interface) VALUES('agent_wifi','ok',NULL,?,1,'192.168.1.1','wlan0')`, now.Add(-91*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO interfaces(id,agent_id,name,up,is_wireless,wifi_state,wifi_reason,wifi_signal_dbm,updated_at) VALUES('if1','agent_wifi','wlan0',1,1,'connected','permission',-60,?)`, now); err != nil {
		t.Fatal(err)
	}

	reg := registry.New(db, 0, nil)
	d := Deps{Inventory: inventory.New(db, nil), Config: config.New(db, reg, nil, nil)}
	call := func() map[string]json.RawMessage {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/agents/agent_wifi/interfaces", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "agent_wifi")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()
		d.handleAgentInterfaces(w, r)
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return body
	}

	body := call()
	var col inventory.WiFiCollection
	if err := json.Unmarshal(body["wifi"], &col); err != nil || !col.Stale {
		t.Fatalf("stale collection=%+v err=%v", col, err)
	}
	var ifaces []inventory.Interface
	if err := json.Unmarshal(body["interfaces"], &ifaces); err != nil || len(ifaces) != 1 || ifaces[0].WiFi == nil {
		t.Fatalf("interfaces=%+v err=%v", ifaces, err)
	}
	if ifaces[0].WiFi.Reason != "permission" || ifaces[0].WiFi.SignalDBm == nil || *ifaces[0].WiFi.SignalDBm != -60 {
		t.Fatalf("Wi-Fi API row=%+v", ifaces[0].WiFi)
	}
	var route inventory.DefaultRoute
	if err := json.Unmarshal(body["default_route"], &route); err != nil || route.Gateway != "192.168.1.1" || route.Interface != "wlan0" {
		t.Fatalf("default route=%+v err=%v", route, err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE agent_wifi SET sampled_at=? WHERE agent_id='agent_wifi'`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	body = call()
	if err := json.Unmarshal(body["wifi"], &col); err != nil || col.Stale {
		t.Fatalf("fresh collection=%+v err=%v", col, err)
	}
}
