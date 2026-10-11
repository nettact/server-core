package agentws

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/hostlive"
	"github.com/nettact/server-core/ingest"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/opissue"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/site"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

// newLocalEnv is newTestEnv without the httptest listener: the in-process
// link (DialLocal) runs the same Hello path and needs no socket.
func newLocalEnv(t *testing.T) *testEnv {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	if err := site.New(db).EnsureDefault(ctx); err != nil {
		t.Fatal(err)
	}
	reg := registry.New(db, 0, nil)
	bus := eventbus.New()
	cfg := config.New(db, reg, bus, nil, nil)
	groupID, err := cfg.EnsureDefaultGroup(ctx, site.DefaultSiteID)
	if err != nil {
		t.Fatal(err)
	}
	hub := New(Deps{
		Registry: reg,
		Ingest:   ingest.New(db, bus, metrics.New(db, tsstoretest.Open(t)), nil, nil, nil),
		Config:   cfg,
		HostLive: hostlive.New(),
		OpIssue:  opissue.New(db, bus),
		Bus:      bus,
	})
	t.Cleanup(func() { hub.CloseAll("test done") })
	return &testEnv{hub: hub, db: db, reg: reg, cfg: cfg, bus: bus, groupID: groupID}
}

// The Hello's capabilities are persisted before the first DesiredState push
// and before the hello-time prediction, so the very first push already
// reflects them: a trace monitor reaches a declaring agent, and an agent that
// does not declare it is never sent it and is marked as needing an upgrade.
func TestHelloCapabilitiesGateTheFirstPush(t *testing.T) {
	for _, declare := range []bool{true, false} {
		name := "without capability"
		if declare {
			name = "with capability"
		}
		t.Run(name, func(t *testing.T) {
			e := newLocalEnv(t)
			e.seedAgent(t, "agent_a", "tok_a")
			if err := e.cfg.SetSiteTargets(context.Background(), site.DefaultSiteID, []config.ProbeTarget{
				{ID: "t_trace", GroupID: e.groupID, Kind: config.KindTrace, Target: "example.com", Enabled: true},
				{ID: "t_icmp", GroupID: e.groupID, Kind: "icmp", Target: "example.com", Enabled: true},
			}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := e.hub.DialLocal(ctx, "tok_a")
			if err != nil {
				t.Fatal(err)
			}
			hello := testHello()
			if declare {
				hello.Hello.Capabilities = append(hello.Hello.Capabilities, wire.CapProbeTraceV1)
			}
			if err := conn.WriteFrame(ctx, hello); err != nil {
				t.Fatal(err)
			}
			f, err := conn.ReadFrame(ctx)
			if err != nil || f.DesiredState == nil {
				t.Fatalf("first push = %+v err=%v", f, err)
			}
			got := map[string]bool{}
			for _, tg := range f.DesiredState.ProbeTargets {
				got[tg.MonitorID] = true
			}
			if got["t_trace"] != declare || !got["t_icmp"] {
				t.Fatalf("pushed %v, want trace=%v", got, declare)
			}
			var status, reason string
			if err := e.db.QueryRow(`SELECT status, reason FROM monitor_status WHERE agent_id='agent_a' AND monitor_id='t_trace'`).
				Scan(&status, &reason); err != nil {
				t.Fatal(err)
			}
			upgrade := status == wire.MonitorStatusUnsupported && reason == config.ReasonAgentUpgradeRequired
			if upgrade == declare {
				t.Errorf("trace status = %s/%s with declare=%v", status, reason, declare)
			}
		})
	}
}
