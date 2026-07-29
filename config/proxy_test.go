package config

import (
	"context"
	"errors"
	"strings"
	"testing"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

func newProxySvc(t *testing.T) (*Service, *store.DB, *eventbus.Bus, context.Context) {
	t.Helper()
	db, ctx := openConfigTestDB(t)
	bus := eventbus.New()
	return New(db, registry.New(db, 0, nil), bus, nil), db, bus, ctx
}

func sampleRelay(name string) Proxy {
	return Proxy{
		Name: name, Type: pcfg.ProxyTypeSOCKS5, Enabled: true,
		Host: "proxy.test", Port: 1080, Username: "u", Password: "p",
		DNSMode: pcfg.ProxyDNSLocal,
	}
}

func mustCreateProxy(t *testing.T, svc *Service, ctx context.Context, siteID string, p Proxy) string {
	t.Helper()
	id, err := svc.CreateProxy(ctx, siteID, p)
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	return id
}

func TestCreateAndListProxies(t *testing.T) {
	svc, _, _, ctx := newProxySvc(t)
	id := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))

	list, err := svc.ListProxies(ctx, "site_default")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("ListProxies = %+v, want the created proxy", list)
	}
	// Credentials come back as stored from the service layer; redaction is the API
	// layer's job (see api.redactProxy) so the downlink can still push real values.
	if list[0].Password != "p" {
		t.Fatalf("service-layer password = %q, want the stored value", list[0].Password)
	}
	if list[0].UsedBy != 0 {
		t.Fatalf("fresh proxy UsedBy = %d, want 0", list[0].UsedBy)
	}
	// A site's proxies must not leak across sites.
	other, err := svc.ListProxies(ctx, "site_other")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("site_other sees %d proxies, want 0", len(other))
	}
}

func TestCreateProxyRejectsDuplicateName(t *testing.T) {
	svc, _, _, ctx := newProxySvc(t)
	mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))
	if _, err := svc.CreateProxy(ctx, "site_default", sampleRelay("office")); !errors.Is(err, ErrProxyNameTaken) {
		t.Fatalf("duplicate name error = %v, want ErrProxyNameTaken", err)
	}
	// The name is only unique per site: two sites may each have an "office" proxy.
	if _, err := svc.CreateProxy(ctx, "site_other", sampleRelay("office")); err != nil {
		t.Fatalf("same name in another site: %v", err)
	}
}

// A material proxy edit must re-generate every pinned target: the site serial
// advances, each target is re-stamped, and DesiredState is re-announced. This is
// what forces the agent to tear down a dialer built on the old credentials.
func TestUpdateProxyRegeneratesPinnedTargets(t *testing.T) {
	svc, db, bus, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyID := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))
	pinned := ProbeTarget{ID: "t_pinned", GroupID: group, Kind: "http", Target: "https://a.test", Enabled: true, ProxyID: proxyID}
	direct := ProbeTarget{ID: "t_direct", GroupID: group, Kind: "http", Target: "https://b.test", Enabled: true}
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{pinned, direct}); err != nil {
		t.Fatal(err)
	}

	var pinnedBefore, directBefore, siteBefore int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t_pinned'`).Scan(&pinnedBefore)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t_direct'`).Scan(&directBefore)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&siteBefore)

	configEvents := 0
	var statusEvents []eventbus.TargetStatusChanged
	bus.Subscribe(eventbus.TopicConfigChanged, func(eventbus.Message) { configEvents++ })
	bus.Subscribe(eventbus.TopicTargetStatusChanged, func(m eventbus.Message) {
		statusEvents = append(statusEvents, m.Payload.(eventbus.TargetStatusChanged))
	})

	next := sampleRelay("office")
	next.Password = "rotated"
	if _, err := svc.UpdateProxy(ctx, proxyID, next); err != nil {
		t.Fatal(err)
	}

	var pinnedAfter, directAfter, siteAfter, proxySerial int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t_pinned'`).Scan(&pinnedAfter)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t_direct'`).Scan(&directAfter)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&siteAfter)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM proxies WHERE id=?`, proxyID).Scan(&proxySerial)

	if siteAfter <= siteBefore {
		t.Fatalf("site serial %d -> %d, want a bump", siteBefore, siteAfter)
	}
	if pinnedAfter <= pinnedBefore {
		t.Fatalf("pinned target serial %d -> %d, want a bump", pinnedBefore, pinnedAfter)
	}
	// A target that does not use this proxy keeps its generation: re-stamping it
	// would make the agent discard perfectly valid in-flight results.
	if directAfter != directBefore {
		t.Fatalf("unpinned target serial %d -> %d, want unchanged", directBefore, directAfter)
	}
	if proxySerial != 2 {
		t.Fatalf("proxy config_serial = %d, want 2 after one material edit", proxySerial)
	}
	if configEvents != 1 {
		t.Fatalf("config events = %d, want 1 announce", configEvents)
	}
	if len(statusEvents) != 1 || len(statusEvents[0].TargetIDs) != 1 || statusEvents[0].TargetIDs[0] != "t_pinned" {
		t.Fatalf("status events = %+v, want exactly the pinned target", statusEvents)
	}
}

// A rename changes no dial, so it must not advance any generation or push config.
// Bumping there would make every pinned monitor's detector restart for a cosmetic
// edit.
func TestUpdateProxyRenameIsNotMaterial(t *testing.T) {
	svc, db, bus, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyID := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t1", GroupID: group, Kind: "tcp", Target: "a.test", Params: pcfg.ProbeParams{Port: 443}, Enabled: true, ProxyID: proxyID},
	}); err != nil {
		t.Fatal(err)
	}
	var targetBefore, siteBefore int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t1'`).Scan(&targetBefore)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&siteBefore)

	configEvents := 0
	bus.Subscribe(eventbus.TopicConfigChanged, func(eventbus.Message) { configEvents++ })

	renamed := sampleRelay("head office")
	if _, err := svc.UpdateProxy(ctx, proxyID, renamed); err != nil {
		t.Fatal(err)
	}
	var targetAfter, siteAfter, proxySerial int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t1'`).Scan(&targetAfter)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&siteAfter)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM proxies WHERE id=?`, proxyID).Scan(&proxySerial)
	if targetAfter != targetBefore || siteAfter != siteBefore || proxySerial != 1 {
		t.Fatalf("rename bumped generations: target %d->%d, site %d->%d, proxy=%d",
			targetBefore, targetAfter, siteBefore, siteAfter, proxySerial)
	}
	if configEvents != 0 {
		t.Fatalf("rename announced config %d times, want 0", configEvents)
	}
}

// Disabling a proxy IS material: the spec drops out of DesiredState so pinned
// monitors fail closed instead of silently dialing direct.
func TestDisablingProxyIsMaterial(t *testing.T) {
	svc, db, _, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyID := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t1", GroupID: group, Kind: "http", Target: "https://a.test", Enabled: true, ProxyID: proxyID},
	}); err != nil {
		t.Fatal(err)
	}
	var before int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t1'`).Scan(&before)

	off := sampleRelay("office")
	off.Enabled = false
	if _, err := svc.UpdateProxy(ctx, proxyID, off); err != nil {
		t.Fatal(err)
	}
	var after int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t1'`).Scan(&after)
	if after <= before {
		t.Fatalf("disabling did not re-generate the pinned target: %d -> %d", before, after)
	}
}

func TestDeleteProxyRefusedWhileReferenced(t *testing.T) {
	svc, _, _, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyID := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t1", GroupID: group, Kind: "http", Name: "Portal", Target: "https://a.test", Enabled: true, ProxyID: proxyID},
	}); err != nil {
		t.Fatal(err)
	}

	_, err = svc.DeleteProxy(ctx, proxyID)
	var inUse *ErrProxyInUse
	if !errors.As(err, &inUse) {
		t.Fatalf("DeleteProxy error = %v, want *ErrProxyInUse", err)
	}
	if inUse.Total != 1 || len(inUse.Monitors) != 1 || inUse.Monitors[0] != "Portal" {
		t.Fatalf("ErrProxyInUse = %+v, want the occupying monitor named", inUse)
	}

	// Unpinning frees it. This is the operator's explicit act — the delete never
	// unpins on its own, because that would change the egress path silently.
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t1", GroupID: group, Kind: "http", Name: "Portal", Target: "https://a.test", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeleteProxy(ctx, proxyID); err != nil {
		t.Fatalf("DeleteProxy after unpin: %v", err)
	}
	list, _ := svc.ListProxies(ctx, "site_default")
	if len(list) != 0 {
		t.Fatalf("proxy survived delete: %+v", list)
	}
}

// Pinning a target is itself a material target change (the egress path moved), and
// the reference count must reflect it.
func TestPinningProxyIsMaterialAndCounted(t *testing.T) {
	svc, db, _, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyID := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))
	direct := ProbeTarget{ID: "t1", GroupID: group, Kind: "http", Target: "https://a.test", Enabled: true}
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{direct}); err != nil {
		t.Fatal(err)
	}
	var before int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t1'`).Scan(&before)

	pinned := direct
	pinned.ProxyID = proxyID
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{pinned}); err != nil {
		t.Fatal(err)
	}
	var after int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t1'`).Scan(&after)
	if after <= before {
		t.Fatalf("pinning a proxy left the generation at %d (was %d) — the egress path changed", after, before)
	}
	p, err := svc.GetProxy(ctx, proxyID)
	if err != nil {
		t.Fatal(err)
	}
	if p.UsedBy != 1 {
		t.Fatalf("UsedBy = %d, want 1", p.UsedBy)
	}
	// Re-submitting the same pinned set is idempotent.
	serialBefore := after
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{pinned}); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t1'`).Scan(&after)
	if after != serialBefore {
		t.Fatalf("identical pinned resubmit bumped the generation: %d -> %d", serialBefore, after)
	}
}

func TestSetSiteTargetsRejectsBadProxyPins(t *testing.T) {
	svc, _, _, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := svc.CreateGroup(ctx, "site_other", "other", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	socks := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))
	foreign := mustCreateProxy(t, svc, ctx, "site_other", sampleRelay("elsewhere"))
	_ = otherGroup

	// Unknown id.
	err = svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t1", GroupID: group, Kind: "http", Target: "https://a.test", Enabled: true, ProxyID: "prx_nope"},
	})
	if !errors.Is(err, ErrTargetProxy) {
		t.Fatalf("unknown proxy id error = %v, want ErrTargetProxy", err)
	}
	// Cross-site id: present in the table, but not this site's to use.
	err = svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t1", GroupID: group, Kind: "http", Target: "https://a.test", Enabled: true, ProxyID: foreign},
	})
	if !errors.Is(err, ErrTargetProxy) {
		t.Fatalf("cross-site proxy error = %v, want ErrTargetProxy", err)
	}
	// Capability: ICMP cannot traverse a SOCKS5 CONNECT tunnel.
	err = svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t1", GroupID: group, Kind: "icmp", Target: "1.1.1.1", Enabled: true, ProxyID: socks},
	})
	if !errors.Is(err, ErrTargetProxy) {
		t.Fatalf("icmp-via-socks5 error = %v, want ErrTargetProxy", err)
	}
	// A rejected save must leave nothing behind.
	targets, err := svc.ListSiteTargets(ctx, "site_default")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("rejected save wrote %d targets, want 0", len(targets))
	}
}

// DesiredStateFor must carry the pin AND the referenced spec, and must omit a
// disabled proxy's spec while KEEPING its target — that asymmetry is what lets the
// agent say "not running, proxy missing" instead of the monitor vanishing.
func TestDesiredStateForCarriesProxies(t *testing.T) {
	svc, _, _, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	live := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("live"))
	offSpec := sampleRelay("off")
	offSpec.Enabled = false
	off := mustCreateProxy(t, svc, ctx, "site_default", offSpec)
	unused := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("unused"))

	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t_live", GroupID: group, Kind: "http", Target: "https://a.test", Enabled: true, ProxyID: live},
		{ID: "t_off", GroupID: group, Kind: "http", Target: "https://b.test", Enabled: true, ProxyID: off},
		{ID: "t_direct", GroupID: group, Kind: "http", Target: "https://c.test", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}

	ds, err := svc.DesiredStateFor(ctx, "agent_a")
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{}
	for _, tg := range ds.ProbeTargets {
		pins[tg.MonitorID] = tg.ProxyID
	}
	if pins["t_live"] != live || pins["t_off"] != off || pins["t_direct"] != "" {
		t.Fatalf("pushed pins = %+v, want live/off pinned and t_direct direct", pins)
	}
	specs := map[string]pcfg.ProxySpec{}
	for _, p := range ds.Proxies {
		specs[p.ID] = p
	}
	if len(specs) != 1 {
		t.Fatalf("pushed %d specs, want only the enabled referenced one: %+v", len(specs), specs)
	}
	if _, ok := specs[live]; !ok {
		t.Fatalf("enabled referenced proxy missing from the push: %+v", specs)
	}
	if _, ok := specs[off]; ok {
		t.Fatal("disabled proxy was pushed — its pinned target must fail closed instead")
	}
	if _, ok := specs[unused]; ok {
		t.Fatal("unreferenced proxy was pushed")
	}
	// The spec must carry the real credential (the wire is the authenticated agent
	// channel; only the read APIs redact) and the proxy's own generation.
	if specs[live].Password != "p" {
		t.Fatalf("pushed password = %q, want the real credential", specs[live].Password)
	}
	if specs[live].ConfigSerial == 0 {
		t.Fatal("pushed spec carries no config_serial — the agent could not detect an edit")
	}
}

func TestMaterialProxyChange(t *testing.T) {
	base := sampleRelay("office")
	cases := []struct {
		name string
		edit func(*Proxy)
		want bool
	}{
		{"identical", func(*Proxy) {}, false},
		{"rename", func(p *Proxy) { p.Name = "other" }, false},
		{"host", func(p *Proxy) { p.Host = "new.test" }, true},
		{"port", func(p *Proxy) { p.Port = 1081 }, true},
		{"username", func(p *Proxy) { p.Username = "v" }, true},
		{"password", func(p *Proxy) { p.Password = "q" }, true},
		{"dns mode", func(p *Proxy) { p.DNSMode = pcfg.ProxyDNSRemote }, true},
		{"connect timeout", func(p *Proxy) { p.ConnectTimeoutMs = 1000 }, true},
		{"type", func(p *Proxy) { p.Type = pcfg.ProxyTypeHTTP }, true},
		{"disabled", func(p *Proxy) { p.Enabled = false }, true},
		{"wg private key", func(p *Proxy) { p.WGPrivateKey = "k" }, true},
		{"wg endpoint", func(p *Proxy) { p.WGEndpoint = "wg.test:51820" }, true},
		{"wg allowed ips", func(p *Proxy) { p.WGAllowedIPs = "10.0.0.0/8" }, true},
		{"wg mtu", func(p *Proxy) { p.WGMTU = 1380 }, true},
		{"wg keepalive", func(p *Proxy) { p.WGKeepaliveSeconds = 25 }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			next := base
			c.edit(&next)
			if got := materialProxyChange(base, next); got != c.want {
				t.Fatalf("materialProxyChange = %v, want %v", got, c.want)
			}
		})
	}
}

// A type change that would strand the monitors pinned to a proxy must be refused
// INSIDE the write transaction, and must leave nothing behind.
//
// Doing it only in the API handler left a real window: a SetSiteTargets committing an
// incompatible pin between the pre-check and this transaction would be validated
// against the OLD type, and the switch would then leave that monitor permanently
// un-runnable with both writes reporting success.
func TestUpdateProxyRefusesTypeChangeThatStrandsTargets(t *testing.T) {
	svc, db, bus, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A WireGuard proxy, which is the only type that can carry ICMP.
	wg := Proxy{
		Name: "tunnel", Type: pcfg.ProxyTypeWireGuard, Enabled: true,
		WGPrivateKey: "k", WGPeerPublicKey: "p", WGEndpoint: "wg.test:51820",
		WGAllowedIPs: "10.7.0.0/24", WGLocalAddrs: "10.7.0.2/32",
	}
	proxyID := mustCreateProxy(t, svc, ctx, "site_default", wg)
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t_ping", GroupID: group, Kind: "icmp", Name: "Router", Target: "10.7.0.1", Enabled: true, ProxyID: proxyID},
	}); err != nil {
		t.Fatal(err)
	}
	var serialBefore, siteBefore int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t_ping'`).Scan(&serialBefore)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&siteBefore)
	configEvents := 0
	bus.Subscribe(eventbus.TopicConfigChanged, func(eventbus.Message) { configEvents++ })

	// SOCKS5 cannot carry ICMP — no relay protocol can.
	relay := sampleRelay("tunnel")
	_, err = svc.UpdateProxy(ctx, proxyID, relay)
	var stranded *ErrProxyStrandsTargets
	if !errors.As(err, &stranded) {
		t.Fatalf("UpdateProxy error = %v, want *ErrProxyStrandsTargets", err)
	}
	if len(stranded.Monitors) != 1 || !strings.Contains(stranded.Monitors[0], "Router") {
		t.Fatalf("stranded monitors = %v, want the ICMP monitor named", stranded.Monitors)
	}

	// A refused update must be a complete no-op: the type, the generations and the
	// config push all unchanged. This is what the in-tx placement buys.
	var gotType string
	_ = db.QueryRowContext(ctx, `SELECT type FROM proxies WHERE id=?`, proxyID).Scan(&gotType)
	if gotType != pcfg.ProxyTypeWireGuard {
		t.Fatalf("proxy type = %q, want the update rolled back", gotType)
	}
	var serialAfter, siteAfter int
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM probe_tasks WHERE id='t_ping'`).Scan(&serialAfter)
	_ = db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id='site_default'`).Scan(&siteAfter)
	if serialAfter != serialBefore || siteAfter != siteBefore {
		t.Fatalf("a refused update advanced generations: target %d->%d, site %d->%d",
			serialBefore, serialAfter, siteBefore, siteAfter)
	}
	if configEvents != 0 {
		t.Fatalf("a refused update announced config %d times", configEvents)
	}
}

// The same check must not block a type change the pinned monitors CAN follow.
func TestUpdateProxyAllowsCompatibleTypeChange(t *testing.T) {
	svc, _, _, ctx := newProxySvc(t)
	group, err := svc.CreateGroup(ctx, "site_default", "g", false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyID := mustCreateProxy(t, svc, ctx, "site_default", sampleRelay("office"))
	// An HTTP monitor rides every transport, so switching relay types is fine.
	if err := svc.SetSiteTargets(ctx, "site_default", []ProbeTarget{
		{ID: "t_web", GroupID: group, Kind: "http", Target: "https://a.test", Enabled: true, ProxyID: proxyID},
	}); err != nil {
		t.Fatal(err)
	}
	next := sampleRelay("office")
	next.Type = pcfg.ProxyTypeHTTP
	if _, err := svc.UpdateProxy(ctx, proxyID, next); err != nil {
		t.Fatalf("a compatible type change was refused: %v", err)
	}
}
