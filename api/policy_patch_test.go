package api

import (
	"testing"

	"github.com/nettact/server-core/notifypolicy"
)

// PATCH means "change what I named, leave the rest alone". Decoding a partial
// body into a full struct silently rewrites every field the caller omitted — so
// an operator toggling `enabled` would also wipe the policy's channels and reset
// its delays, and a body without a name would be rejected outright.
func TestPolicyPatchMergesOntoCurrent(t *testing.T) {
	cur := notifypolicy.Policy{
		ID: "np_1", Name: "Core", ScopeKind: notifypolicy.ScopeGroup, ScopeID: "mg",
		Enabled: true, MinSeverity: "warn", WarnDelaySec: 300, CriticalDelaySec: 60,
		NotifyRecovery: true, ChannelIDs: []string{"ch_a", "ch_b"},
	}

	// A single-field patch must leave everything else exactly as it was.
	off := false
	got := policyPatch{Enabled: &off}.apply(cur)
	if got.Enabled {
		t.Fatal("enabled was not applied")
	}
	if got.Name != "Core" || got.MinSeverity != "warn" ||
		got.WarnDelaySec != 300 || got.CriticalDelaySec != 60 ||
		!got.NotifyRecovery || len(got.ChannelIDs) != 2 {
		t.Fatalf("omitted fields were rewritten: %+v", got)
	}

	// A false boolean must be distinguishable from an omitted one.
	noRecovery := false
	got = policyPatch{NotifyRecovery: &noRecovery}.apply(cur)
	if got.NotifyRecovery {
		t.Fatal("an explicit false must turn recovery notices off")
	}

	// An explicitly empty channel list is meaningful ("record only"), not an omission.
	empty := []string{}
	got = policyPatch{ChannelIDs: &empty}.apply(cur)
	if len(got.ChannelIDs) != 0 {
		t.Fatalf("an explicit empty channel list must clear routing, got %v", got.ChannelIDs)
	}

	// Scope and the default flag are not patchable: an edit may never move a
	// policy to a different set of incidents.
	got = policyPatch{Name: strPtr("Renamed")}.apply(cur)
	if got.ScopeKind != notifypolicy.ScopeGroup || got.ScopeID != "mg" {
		t.Fatalf("scope must survive a patch: %+v", got)
	}
}

func strPtr(s string) *string { return &s }
