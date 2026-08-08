package opissue

import (
	"context"
	"testing"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/store/storetest"
)

// TestHostRequiredFollowsEnabledFamilies pins what a host anchor actually needs.
//
// It has to be derived rather than fixed: an anchor watching only disk has no
// business raising a permission issue about an Agent that withholds its CPU
// counters, and an anchor watching CPU that cannot read CPU must not sit green
// while nothing evaluates. This is the regression that mattered when the anchor
// requirement was a stub returning "nothing".
func TestHostRequiredFollowsEnabledFamilies(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO sites(id,name) VALUES('site_default','Default')`)
	exec(`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('mg','site_default','All',1)`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,name)
	      VALUES('h_default','site_default','mg','host','host','{}',1,'Defaults')`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,name)
	      VALUES('h_disk','site_default','mg','host','host','{}',1,'Disk only')`)
	exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,target,params,enabled,name)
	      VALUES('h_off','site_default','mg','host','host','{}',1,'All off')`)
	exec(`INSERT INTO host_detection_settings(target_id, cpu_enabled, mem_enabled, load_enabled,
	        net_enabled, disk_enabled, updated_at)
	      VALUES('h_disk',0,0,0,0,1,CURRENT_TIMESTAMP)`)
	exec(`INSERT INTO host_detection_settings(target_id, cpu_enabled, mem_enabled, load_enabled,
	        net_enabled, disk_enabled, updated_at)
	      VALUES('h_off',0,0,0,0,0,CURRENT_TIMESTAMP)`)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	cases := []struct {
		monitor string
		want    []permission.ID
		absent  []permission.ID
	}{
		{
			// Never configured: the zero-config defaults apply, so the anchor needs
			// everything but the network family it does not watch.
			monitor: "h_default",
			want: []permission.ID{permission.HostCPURead, permission.HostMemoryRead,
				permission.HostLoadRead, permission.HostDiskRead},
			absent: []permission.ID{permission.HostNetworkIORead, permission.HostTemperatureRead},
		},
		{
			monitor: "h_disk",
			want:    []permission.ID{permission.HostDiskRead},
			absent: []permission.ID{permission.HostCPURead, permission.HostMemoryRead,
				permission.HostLoadRead, permission.HostNetworkIORead},
		},
	}
	for _, tc := range cases {
		got, err := hostRequired(ctx, tx, tc.monitor)
		if err != nil {
			t.Fatalf("hostRequired(%s): %v", tc.monitor, err)
		}
		for _, id := range tc.want {
			if !got.Has(id) {
				t.Errorf("%s: missing required permission %q", tc.monitor, id)
			}
		}
		for _, id := range tc.absent {
			if got.Has(id) {
				t.Errorf("%s: requires %q for a family it does not watch", tc.monitor, id)
			}
		}
	}

	// Every family off requires nothing, which leaves the anchor unconditionally
	// active — the same state a host anchor was in before it watched anything.
	off, err := hostRequired(ctx, tx, "h_off")
	if err != nil {
		t.Fatalf("hostRequired(h_off): %v", err)
	}
	if len(off.Sorted()) != 0 {
		t.Errorf("an anchor watching nothing requires %v", off.Sorted())
	}
}
