package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/server-core/store/storetest"
)

// A pinned monitor dials its PROXY, so the diagnostic aimed at a fault on that
// monitor has to know the proxy's address. probeMeta is where it is read, under
// the same transaction that evaluates the round — reading it later would let a
// proxy edit redirect a past fault's diagnostic.
func TestProbeMetaCarriesTheEgressIdentity(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name,created_at) VALUES('site_a','A',?)`, now)
	exec(`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_a','site_a',x'00','h','online')`)
	exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
	      VALUES('mg','site_a','Default',1,0,1)`)
	exec(`INSERT INTO proxies(id,site_id,name,type,host,port,created_at,updated_at)
	      VALUES('px_socks','site_a','Relay','socks5','10.0.0.9',1080,?,?)`, now, now)
	exec(`INSERT INTO proxies(id,site_id,name,type,wg_endpoint,created_at,updated_at)
	      VALUES('px_wg','site_a','Tunnel','wireguard','vpn.example:51820',?,?)`, now, now)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial,proxy_id)
	      VALUES('t_socks','site_a','mg','tcp','Via relay','192.0.2.10','{}',1,1,'px_socks')`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial,proxy_id)
	      VALUES('t_wg','site_a','mg','icmp','Via tunnel','10.7.0.5','{}',1,1,'px_wg')`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
	      VALUES('t_direct','site_a','mg','icmp','Direct','192.168.1.1','{}',1,1)`)

	svc := New(db, nil, nil, nil, nil, nil)
	meta, err := svc.probeMeta(ctx, db.Read(), "agent_a", "site_a", []string{"t_socks", "t_wg", "t_direct"})
	if err != nil {
		t.Fatalf("probeMeta: %v", err)
	}

	if m := meta["t_socks"]; m.ProxyID != "px_socks" || m.ProxyType != "socks5" || m.ProxyAddr != "10.0.0.9:1080" {
		t.Fatalf("socks5 pin = %q/%q/%q, want px_socks/socks5/10.0.0.9:1080", m.ProxyID, m.ProxyType, m.ProxyAddr)
	}
	// A WireGuard peer endpoint is already host:port and is carried verbatim.
	if m := meta["t_wg"]; m.ProxyID != "px_wg" || m.ProxyType != "wireguard" || m.ProxyAddr != "vpn.example:51820" {
		t.Fatalf("wireguard pin = %q/%q/%q, want px_wg/wireguard/vpn.example:51820", m.ProxyID, m.ProxyType, m.ProxyAddr)
	}
	if m := meta["t_direct"]; m.ProxyID != "" || m.ProxyType != "" || m.ProxyAddr != "" {
		t.Fatalf("unpinned target invented an egress: %q/%q/%q", m.ProxyID, m.ProxyType, m.ProxyAddr)
	}

	// An incomplete proxy row yields no address rather than a half-formed one, so
	// the diagnostic reports an unnameable egress instead of tracing a guess. (A
	// truly absent row cannot occur: the probe_tasks.proxy_id foreign key and the
	// in-use delete refusal both prevent it. This is the defensive half.)
	exec(`UPDATE proxies SET port=0 WHERE id='px_socks'`)
	meta, err = svc.probeMeta(ctx, db.Read(), "agent_a", "site_a", []string{"t_socks"})
	if err != nil {
		t.Fatalf("probeMeta after proxy edit: %v", err)
	}
	if m := meta["t_socks"]; m.ProxyID != "px_socks" || m.ProxyAddr != "" {
		t.Fatalf("incomplete proxy = %q/%q, want the id with no address", m.ProxyID, m.ProxyAddr)
	}
}
