package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/store"
)

// seedPermAgent inserts an agent with a reported permission policy. The three
// sets are stored as the JSON arrays the registry unmarshals.
func seedPermAgent(t *testing.T, db *store.DB, id string, supported, granted, effective []string) {
	t.Helper()
	enc := func(ss []string) string {
		b, err := json.Marshal(ss)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO agents(id,site_id,public_key,token_hash,status,first_connected_at,
		                    perm_supported,perm_granted,perm_effective,policy_source,policy_hash)
		 VALUES(?,'site_default',x'00',?,'online',?,?,?,?,'environment','hash-1')`,
		id, "h_"+id, time.Now().UTC(), enc(supported), enc(granted), enc(effective)); err != nil {
		t.Fatal(err)
	}
}

func getAgentPermissions(t *testing.T, db *store.DB, id string) agentPermissionsResponse {
	t.Helper()
	d := Deps{Registry: registry.New(db, 0, eventbus.New())}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+id+"/permissions", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	d.handleAgentPermissions(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got agentPermissionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	return got
}

func findPerm(t *testing.T, resp agentPermissionsResponse, id permission.ID) agentPermission {
	t.Helper()
	for _, p := range resp.Permissions {
		if p.ID == string(id) {
			return p
		}
	}
	t.Fatalf("permission %q missing from the inventory", id)
	return agentPermission{}
}

// TestAgentPermissionsInventoryCoversWholeCatalog is the point of the endpoint:
// the Agent detail page needs the permissions the agent does NOT have, which its
// own reported sets can never contain. Every compiled permission must appear
// exactly once, in canonical order, with honest granted/supported/effective flags.
func TestAgentPermissionsInventoryCoversWholeCatalog(t *testing.T) {
	db := openStatusDB(t)
	// A plausible non-elevated Linux-ish agent: the default policy, a platform
	// that can't do ICMP, and no host/process grants at all.
	supported := []string{
		"probe.dns", "probe.http", "probe.tcp", "probe.nat",
		"network.interface.status.read", "network.interface.address.read",
		"network.wifi.status.read",
		"host.cpu.read", "host.memory.read",
		"host.process.basic.read", "host.process.owner.read",
	}
	granted := []string{
		"probe.icmp", "probe.dns", "probe.http", "probe.tcp", "probe.nat",
		"network.gateway.probe",
		"network.interface.status.read", "network.interface.address.read",
		"network.wifi.status.read",
		"diagnostic.traceroute.icmp", "diagnostic.traceroute.tcp",
	}
	effective := []string{
		"probe.dns", "probe.http", "probe.tcp", "probe.nat",
		"network.interface.status.read", "network.interface.address.read",
		"network.wifi.status.read",
	}
	seedPermAgent(t, db, "agent-1", supported, granted, effective)

	resp := getAgentPermissions(t, db, "agent-1")
	if resp.AgentID != "agent-1" || resp.PolicySource != "environment" || resp.PolicyHash != "hash-1" {
		t.Fatalf("identity/policy fields wrong: %+v", resp)
	}

	all := permission.All().Sorted()
	if len(resp.Permissions) != len(all) {
		t.Fatalf("inventory size = %d, want the whole catalog (%d)", len(resp.Permissions), len(all))
	}
	for i, id := range all {
		if resp.Permissions[i].ID != string(id) {
			t.Fatalf("inventory[%d] = %q, want canonical order %q", i, resp.Permissions[i].ID, id)
		}
	}

	// effective: granted ∩ supported, nothing to fix.
	if p := findPerm(t, resp, permission.ProbeDNS); !p.Granted || !p.Supported || !p.Effective || p.PermissionsEnv != "" {
		t.Fatalf("probe.dns should be plainly effective with no env line: %+v", p)
	}
	// granted but the platform can't do it — no env line, a policy edit is useless.
	if p := findPerm(t, resp, permission.ProbeICMP); !p.Granted || p.Supported || p.Effective || p.PermissionsEnv != "" {
		t.Fatalf("probe.icmp should be granted-but-unsupported with no env line: %+v", p)
	}
	// not granted, platform-capable: the actionable case the page exists for.
	cpu := findPerm(t, resp, permission.HostCPURead)
	if cpu.Granted || !cpu.Supported || cpu.Effective {
		t.Fatalf("host.cpu.read should be supported-but-ungranted: %+v", cpu)
	}
	if !strings.HasPrefix(cpu.PermissionsEnv, "NETTACT_AGENT_PERMISSIONS=") {
		t.Fatalf("ungranted permission must carry a full policy line, got %q", cpu.PermissionsEnv)
	}
	// The line replaces the whole policy: it keeps what is already granted and
	// adds the requested permission.
	for _, want := range []string{"host.cpu.read", "probe.icmp", "diagnostic.traceroute.tcp"} {
		if !strings.Contains(cpu.PermissionsEnv, want) {
			t.Fatalf("policy line %q must retain/add %q", cpu.PermissionsEnv, want)
		}
	}
	// not granted and not supported: still listed (the operator must see the gap).
	if p := findPerm(t, resp, permission.HostDiskRead); p.Granted || p.Supported || p.Effective || p.PermissionsEnv == "" {
		t.Fatalf("host.disk.read should be listed as ungranted+unsupported with an env line: %+v", p)
	}
}

// TestAgentPermissionsEnvIsDependencyClosed pins that the policy line handed to
// the operator is self-consistent: asking for a child permission must pull in its
// parent, or the agent would reject the value at startup.
func TestAgentPermissionsEnvIsDependencyClosed(t *testing.T) {
	db := openStatusDB(t)
	seedPermAgent(t, db, "agent-2",
		[]string{"host.process.basic.read", "host.process.owner.read"},
		[]string{"probe.icmp"},
		[]string{})

	resp := getAgentPermissions(t, db, "agent-2")
	owner := findPerm(t, resp, permission.HostProcessOwnerRead)
	if want := []string{"host.process.basic.read"}; len(owner.Requires) != 1 || owner.Requires[0] != want[0] {
		t.Fatalf("requires = %v, want %v", owner.Requires, want)
	}
	value := strings.TrimPrefix(owner.PermissionsEnv, "NETTACT_AGENT_PERMISSIONS=")
	set := permission.FromStrings(strings.Split(value, ","))
	if err := permission.Validate(set); err != nil {
		t.Fatalf("suggested policy line %q is not self-consistent: %v", owner.PermissionsEnv, err)
	}
	if !set.Has(permission.HostProcessBasicRead) {
		t.Fatalf("policy line %q must include the required parent", owner.PermissionsEnv)
	}
}

// TestAgentPermissionsKeepsUnknownReportedIDs: a newer agent may report a
// permission this server build doesn't compile. Dropping it would make the page
// claim a capability the agent has doesn't exist, so it is listed too.
func TestAgentPermissionsKeepsUnknownReportedIDs(t *testing.T) {
	db := openStatusDB(t)
	seedPermAgent(t, db, "agent-3",
		[]string{"probe.dns", "future.thing.read"},
		[]string{"probe.dns", "future.thing.read"},
		[]string{"probe.dns", "future.thing.read"})

	resp := getAgentPermissions(t, db, "agent-3")
	p := findPerm(t, resp, "future.thing.read")
	if !p.Granted || !p.Supported || !p.Effective {
		t.Fatalf("unknown reported permission must keep its reported flags: %+v", p)
	}
	// Unknown IDs sort after every known one (Set.Sorted contract).
	if resp.Permissions[len(resp.Permissions)-1].ID != "future.thing.read" {
		t.Fatalf("unknown ID should sort last, got %q", resp.Permissions[len(resp.Permissions)-1].ID)
	}
}

// TestAgentPermissionsUnknownAgent404 keeps the not-found shape consistent with
// the other agent-scoped endpoints.
func TestAgentPermissionsUnknownAgent404(t *testing.T) {
	db := openStatusDB(t)
	d := Deps{Registry: registry.New(db, 0, eventbus.New())}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/agents/nope/permissions", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nope")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	d.handleAgentPermissions(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestPermissionCatalogIsSelfContained: the enrollment screen builds a policy
// from this payload alone, before any agent exists. Every compiled permission
// must be present, each `implies` must be the full transitive requirement set
// (so the console's union is a valid policy), and the presets must be usable
// values.
func TestPermissionCatalogIsSelfContained(t *testing.T) {
	d := Deps{}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/permissions", nil)
	w := httptest.NewRecorder()
	d.handlePermissionCatalog(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got permissionCatalogResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	all := permission.All().Sorted()
	if len(got.Permissions) != len(all) {
		t.Fatalf("catalog has %d entries, want the whole registry (%d)", len(got.Permissions), len(all))
	}
	for i, id := range all {
		if got.Permissions[i].ID != string(id) {
			t.Fatalf("entry %d = %q, want canonical order %q", i, got.Permissions[i].ID, id)
		}
	}

	byID := map[string]permissionCatalogEntry{}
	for _, e := range got.Permissions {
		byID[e.ID] = e
	}
	// A grandchild must carry its whole ancestry, not just its direct parent:
	// wifi.ssid → wifi.status → interface.status.
	ssid := byID[string(permission.NetWiFiSSIDRead)]
	if len(ssid.Requires) != 1 || ssid.Requires[0] != string(permission.NetWiFiStatusRead) {
		t.Fatalf("ssid requires = %v, want the direct parent only", ssid.Requires)
	}
	wantImplies := map[string]bool{
		string(permission.NetWiFiStatusRead):   true,
		string(permission.NetIfaceStatusRead):  true,
	}
	if len(ssid.Implies) != len(wantImplies) {
		t.Fatalf("ssid implies = %v, want the transitive closure %v", ssid.Implies, wantImplies)
	}
	for _, id := range ssid.Implies {
		if !wantImplies[id] {
			t.Fatalf("ssid implies = %v, unexpected %q", ssid.Implies, id)
		}
	}
	// Ticking any single entry must yield a policy the agent accepts.
	for _, e := range got.Permissions {
		set := permission.FromStrings(append([]string{e.ID}, e.Implies...))
		if err := permission.Validate(set); err != nil {
			t.Fatalf("selecting %q alone yields an invalid policy: %v", e.ID, err)
		}
	}

	// The default flag must match the built-in baseline, or the console's
	// "recommended" ticks would not match what an unconfigured agent runs.
	defaults := permission.DefaultStandalone()
	for _, e := range got.Permissions {
		if e.Default != defaults.Has(permission.ID(e.ID)) {
			t.Fatalf("%q default=%v, want %v", e.ID, e.Default, defaults.Has(permission.ID(e.ID)))
		}
	}

	if len(got.Bundles) != len(permission.Bundles()) {
		t.Fatalf("bundles = %d, want %d", len(got.Bundles), len(permission.Bundles()))
	}
	for _, b := range got.Bundles {
		if len(b.Permissions) == 0 {
			t.Fatalf("bundle %q is empty", b.ID)
		}
		if err := permission.Validate(permission.FromStrings(b.Permissions)); err != nil {
			t.Fatalf("bundle %q is not a usable policy: %v", b.ID, err)
		}
	}
}

// TestAgentPermissionsNoRemediationForUnknownIDs: this server cannot see the
// dependencies of a permission only a newer agent compiles, so any policy line it
// produced could omit them — and the agent refuses to start on an unsatisfied
// policy. Showing the gap without a fix beats handing over a line that bricks the
// agent.
func TestAgentPermissionsNoRemediationForUnknownIDs(t *testing.T) {
	db := openStatusDB(t)
	seedPermAgent(t, db, "agent-4",
		[]string{"probe.dns", "future.thing.read"},
		[]string{"probe.dns"},
		[]string{"probe.dns"})

	resp := getAgentPermissions(t, db, "agent-4")
	unknown := findPerm(t, resp, "future.thing.read")
	if unknown.Granted {
		t.Fatalf("precondition: the unknown permission must be ungranted, got %+v", unknown)
	}
	if unknown.PermissionsEnv != "" {
		t.Fatalf("unknown permission must carry no policy line, got %q", unknown.PermissionsEnv)
	}
	// A known ungranted permission still gets one.
	if known := findPerm(t, resp, permission.HostCPURead); known.PermissionsEnv == "" {
		t.Fatalf("a known ungranted permission must still carry a policy line: %+v", known)
	}
}
