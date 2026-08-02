package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/opissue"
)

// agentPermission is one row of the per-agent permission inventory: a compiled
// permission ID with the three booleans the agent reported about it, plus the
// exact policy line that would grant it.
//
// The console must never derive PermissionsEnv itself — the dependency closure
// is server-authoritative — so it is computed here through the same
// opissue.Remediate path that attaches remediation to issues and denied snapshot
// scopes. It is emitted only when the permission is not granted (granting is the
// action that needs a config change); a granted permission that still isn't
// effective is a capability/dependency problem no policy edit can fix.
type agentPermission struct {
	ID        string `json:"id"`
	Granted   bool   `json:"granted"`
	Supported bool   `json:"supported"`
	Effective bool   `json:"effective"`
	// Direct required parents (never transitive). A child is pruned from
	// effective when a parent isn't, so the console can name the real blocker.
	Requires []string `json:"requires,omitempty"`
	// Full `NETTACT_AGENT_PERMISSIONS=…` replacement line that grants this
	// permission (granted ∪ {id}, dependency-closed). Absent when already granted.
	PermissionsEnv string `json:"permissions_env,omitempty"`
	// Stable code naming why the agent's capability probe concluded this
	// permission is unsupported here (`version_mismatch`, `presentmon_missing`,
	// `gpu_telemetry_unavailable`, …). Supported:false alone says nothing about
	// the cause, which leaves a console offering the one remedy it happens to know
	// — telling a user to install software they already have when the real fault
	// was elsewhere.
	//
	// Absent in two distinct cases: the permission IS supported (nothing to
	// explain), and the probe never ran. There is deliberately no placeholder for
	// the second — "we never asked" is not a diagnosis, and dressing it up as one
	// would recreate the guessing this field exists to end.
	//
	// The vocabulary belongs to whichever probe answered, not to this server, so a
	// console must tolerate codes it does not know (a newer agent reporting to an
	// older console is ordinary) and fall back to its own generic text rather than
	// showing a raw identifier.
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

// agentPermissionsResponse is the whole inventory for one agent: every compiled
// permission plus anything the agent reported that this server build doesn't
// know, in canonical order.
type agentPermissionsResponse struct {
	AgentID      string            `json:"agent_id"`
	PolicySource string            `json:"policy_source"`
	PolicyHash   string            `json:"policy_hash"`
	Permissions  []agentPermission `json:"permissions"`
}

// permissionCatalogEntry is one row of the agent-independent permission catalog:
// what exists, what it needs, and whether the built-in default policy grants it.
//
// Implies is the FULL transitive requirement set, not just the direct parents.
// The console builds an enrollment policy by unioning the entries an operator
// ticks, and shipping the closure per entry means that union is a plain set
// union — the dependency rules stay implemented once, here, instead of being
// reimplemented as a graph walk in the browser where they could drift.
type permissionCatalogEntry struct {
	ID       string   `json:"id"`
	Requires []string `json:"requires,omitempty"`
	Implies  []string `json:"implies,omitempty"`
	Default  bool     `json:"default"`
}

// permissionBundle is a named preset an operator can pick instead of choosing
// permission by permission.
type permissionBundle struct {
	ID          string   `json:"id"`
	Permissions []string `json:"permissions"`
}

type permissionCatalogResponse struct {
	Permissions []permissionCatalogEntry `json:"permissions"`
	Bundles     []permissionBundle       `json:"bundles"`
}

// handlePermissionCatalog serves GET /permissions — every permission this build
// compiles, with its dependencies and the enrollment presets.
//
// It is deliberately not scoped to an agent: the console needs it on the
// enrollment screen, where the agent being configured does not exist yet, so the
// per-agent endpoint below cannot answer.
func (d Deps) handlePermissionCatalog(w http.ResponseWriter, r *http.Request) {
	defaults := permission.DefaultStandalone()

	ids := permission.All().Sorted()
	resp := permissionCatalogResponse{Permissions: make([]permissionCatalogEntry, 0, len(ids))}
	for _, id := range ids {
		e := permissionCatalogEntry{ID: string(id), Default: defaults.Has(id)}
		for _, parent := range permission.Dependencies(id) {
			e.Requires = append(e.Requires, string(parent))
		}
		for _, needed := range permission.Closure(permission.NewSet(id)).Sorted() {
			if needed != id {
				e.Implies = append(e.Implies, string(needed))
			}
		}
		resp.Permissions = append(resp.Permissions, e)
	}
	for _, b := range permission.Bundles() {
		resp.Bundles = append(resp.Bundles, permissionBundle{ID: b.ID, Permissions: b.Set.Strings()})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAgentPermissions serves GET /agents/{id}/permissions — the full
// permission catalog for one agent, not just the sets it reported. The Agent
// detail page needs the complement (what is NOT granted) to tell an operator
// which capabilities are still available and exactly what to configure to turn
// them on, which the agent's own supported/granted/effective lists cannot say.
func (d Deps) handleAgentPermissions(w http.ResponseWriter, r *http.Request) {
	a, err := d.Registry.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	supported := permission.FromStrings(a.Supported)
	granted := permission.FromStrings(a.Granted)
	effective := permission.FromStrings(a.Effective)

	// Catalog = everything this build compiles, plus any ID the agent reported
	// that we don't recognize (a newer agent build): those must still be listed
	// rather than silently vanish from the operator's view.
	catalog := permission.All()
	for _, s := range []permission.Set{supported, granted, effective} {
		for id := range s {
			catalog.Add(id)
		}
	}
	// A permission can exist ONLY as a reason. An ID a newer agent compiles and
	// this build doesn't, which that agent found unsupported, is by definition
	// absent from Supported — and if nothing granted it, absent from Granted and
	// Effective too. It then appears in none of the three sets, so building the
	// row set from them alone would drop the ID and, with it, the one thing that
	// explains the gap: exactly the "the console can't say why" silence this
	// field exists to end.
	for id := range a.UnsupportedReasons {
		catalog.Add(permission.ID(id))
	}

	known := permission.All()
	ids := catalog.Sorted()
	resp := agentPermissionsResponse{
		AgentID:      a.ID,
		PolicySource: a.PolicySource,
		PolicyHash:   a.PolicyHash,
		Permissions:  make([]agentPermission, 0, len(ids)),
	}
	for _, id := range ids {
		p := agentPermission{
			ID:        string(id),
			Granted:   granted.Has(id),
			Supported: supported.Has(id),
			Effective: effective.Has(id),
		}
		for _, parent := range permission.Dependencies(id) {
			p.Requires = append(p.Requires, string(parent))
		}
		// The reason map only ever describes unsupported permissions; reading it
		// only for those keeps a misreporting agent from producing the nonsense of
		// a supported permission that also carries a failure code. A missing entry
		// stays the empty string, which omitempty drops — the console reads that as
		// "never probed", not as a reason it failed to recognize.
		if !p.Supported {
			p.UnsupportedReason = a.UnsupportedReasons[string(id)]
		}
		// A policy line is only offered for permissions this build compiles. For an
		// ID only a newer agent knows, this server cannot see its dependencies, so
		// Closure would emit a line that omits them — and the agent rejects an
		// unsatisfied policy at startup. Handing an operator a line that stops their
		// agent from booting is worse than showing the gap with no suggested fix.
		if !p.Granted && known.Has(id) {
			rem := opissue.Remediate(wire.MonitorStatusPermissionBlocked, []string{string(id)}, a.Granted, "")
			p.PermissionsEnv = rem.PermissionsEnv
		}
		resp.Permissions = append(resp.Permissions, p)
	}
	writeJSON(w, http.StatusOK, resp)
}
