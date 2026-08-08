package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nettact/server-core/registry"
)

// seedHostAnchor creates one kind='host' anchor and returns the service and its id.
func seedHostAnchor(t *testing.T) (*Service, string) {
	t.Helper()
	db, ctx := openConfigTestDB(t)
	svc := New(db, registry.New(db, 0, nil), nil, nil, nil)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
		 VALUES('mg','site_default','Default',1,0,1)`); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		 VALUES('h1','site_default','mg','host','Server','host','{}',1,1)`); err != nil {
		t.Fatalf("seed anchor: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		 VALUES('p1','site_default','mg','icmp','Router','192.168.1.1','{}',1,1)`); err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	return svc, "h1"
}

func f64(v float64) *float64 { return &v }
func boolp(v bool) *bool     { return &v }

// TestHostDetectionDefaultsWatchTheMachine is the zero-config promise on the host
// side: an anchor nobody has configured is already watching CPU, memory, load and
// disk. Network is the exception, and deliberately so — there is no defensible
// universal Mbps figure.
func TestHostDetectionDefaultsWatchTheMachine(t *testing.T) {
	svc, id := seedHostAnchor(t)
	got, err := svc.GetHostDetection(t.Context(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.CPU.Enabled || !got.Mem.Enabled || !got.Load.Enabled || !got.Disk.Enabled {
		t.Errorf("a family is off by default: %+v", got)
	}
	if got.Net.Enabled {
		t.Error("network alerting is on by default with no threshold anyone chose")
	}
	if got.Net.RxMbps != nil || got.Net.TxMbps != nil {
		t.Error("network thresholds were invented")
	}
	if got.CPU.Pct != 90 || got.CPU.DurationS != 300 || got.Load.PerCore != 2 {
		t.Errorf("unexpected defaults: %+v", got)
	}
	// Never configured, so there is no edit time to report. This is how the console
	// distinguishes "untouched" from "set back to the defaults".
	if got.UpdatedAt != nil {
		t.Error("an untouched anchor reported an update time")
	}
}

// TestHostDetectionPatchIsPartial: an omitted family keeps its stored value, and
// every edit advances the revision that streaks are pinned to.
func TestHostDetectionPatchIsPartial(t *testing.T) {
	svc, id := seedHostAnchor(t)
	ctx := t.Context()

	var p HostDetectionPatch
	p.CPU = &struct {
		Enabled   *bool    `json:"enabled"`
		Pct       *float64 `json:"pct"`
		DurationS *int     `json:"duration_s"`
	}{Pct: f64(95)}
	got, err := svc.UpdateHostDetection(ctx, id, p)
	if err != nil {
		t.Fatalf("patch cpu: %v", err)
	}
	if got.CPU.Pct != 95 || got.CPU.DurationS != 300 || !got.CPU.Enabled {
		t.Errorf("cpu patch rewrote untouched fields: %+v", got.CPU)
	}
	if !got.Disk.Enabled || got.Disk.Pct != 90 {
		t.Errorf("a family nobody mentioned changed: %+v", got.Disk)
	}
	if got.Revision != 2 {
		t.Errorf("revision = %d after one edit, want 2", got.Revision)
	}
	if got.UpdatedAt == nil {
		t.Error("a configured anchor reported no update time")
	}

	var p2 HostDetectionPatch
	p2.Disk = &struct {
		Enabled *bool    `json:"enabled"`
		Pct     *float64 `json:"pct"`
	}{Enabled: boolp(false)}
	got2, err := svc.UpdateHostDetection(ctx, id, p2)
	if err != nil {
		t.Fatalf("patch disk: %v", err)
	}
	if got2.CPU.Pct != 95 {
		t.Errorf("the earlier cpu edit was lost: %+v", got2.CPU)
	}
	if got2.Disk.Enabled {
		t.Error("disk was not switched off")
	}
	if got2.Revision != 3 {
		t.Errorf("revision = %d after two edits, want 3", got2.Revision)
	}
}

// parsePatch decodes a PATCH body exactly as the HTTP handler does. The network
// tests go through JSON deliberately: the three-way distinction between an absent
// key, an explicit null and a number lives in the decoder, so a patch built as a
// Go literal would test a path no client can take.
func parsePatch(t *testing.T, body string) HostDetectionPatch {
	t.Helper()
	var p HostDetectionPatch
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("decode patch %s: %v", body, err)
	}
	return p
}

// TestHostDetectionNetNeedsADirection: enabling the family with neither direction
// set would be an alert the console renders as on and the engine treats as off.
// That disagreement must not be storable.
func TestHostDetectionNetNeedsADirection(t *testing.T) {
	svc, id := seedHostAnchor(t)
	p := parsePatch(t, `{"net":{"enabled":true}}`)
	if _, err := svc.UpdateHostDetection(t.Context(), id, p); err == nil {
		t.Fatal("enabled network alerting with no threshold at all")
	} else if !strings.Contains(err.Error(), "rx_mbps") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestHostDetectionNullClearsADirection: a present-but-null threshold is the only
// way to say "stop alerting on uploads, keep alerting on downloads" — and it has
// to survive the JSON decoder, which writes nil for an absent key too.
func TestHostDetectionNullClearsADirection(t *testing.T) {
	svc, id := seedHostAnchor(t)
	ctx := t.Context()
	got, err := svc.UpdateHostDetection(ctx, id,
		parsePatch(t, `{"net":{"enabled":true,"rx_mbps":200,"tx_mbps":50}}`))
	if err != nil {
		t.Fatalf("set both directions: %v", err)
	}
	if got.Net.RxMbps == nil || *got.Net.RxMbps != 200 || got.Net.TxMbps == nil || *got.Net.TxMbps != 50 {
		t.Fatalf("directions not stored: %+v", got.Net)
	}

	// An OMITTED direction keeps its stored value…
	kept, err := svc.UpdateHostDetection(ctx, id, parsePatch(t, `{"net":{"duration_s":600}}`))
	if err != nil {
		t.Fatalf("touch duration only: %v", err)
	}
	if kept.Net.TxMbps == nil || *kept.Net.TxMbps != 50 {
		t.Fatalf("an omitted direction was cleared: %+v", kept.Net)
	}

	// …and an explicit null clears it, leaving the other one alone.
	got2, err := svc.UpdateHostDetection(ctx, id, parsePatch(t, `{"net":{"tx_mbps":null}}`))
	if err != nil {
		t.Fatalf("clear tx: %v", err)
	}
	if got2.Net.TxMbps != nil {
		t.Errorf("tx threshold survived an explicit null: %v", *got2.Net.TxMbps)
	}
	if got2.Net.RxMbps == nil || *got2.Net.RxMbps != 200 {
		t.Errorf("clearing tx disturbed rx: %+v", got2.Net)
	}
}

// TestHostDetectionRejectsOutOfRange: storing 90 when the caller asked for 900
// would leave them believing the machine is watched far more loosely than it is.
func TestHostDetectionRejectsOutOfRange(t *testing.T) {
	svc, id := seedHostAnchor(t)
	ctx := t.Context()
	cases := []struct {
		name  string
		patch func(*HostDetectionPatch)
		want  string
	}{
		{"cpu over 100", func(p *HostDetectionPatch) {
			p.CPU = &struct {
				Enabled   *bool    `json:"enabled"`
				Pct       *float64 `json:"pct"`
				DurationS *int     `json:"duration_s"`
			}{Pct: f64(900)}
		}, "cpu.pct"},
		{"duration too short", func(p *HostDetectionPatch) {
			p.Mem = &struct {
				Enabled   *bool    `json:"enabled"`
				Pct       *float64 `json:"pct"`
				DurationS *int     `json:"duration_s"`
			}{DurationS: intp(5)}
		}, "mem.duration_s"},
		{"load zero", func(p *HostDetectionPatch) {
			p.Load = &struct {
				Enabled   *bool    `json:"enabled"`
				PerCore   *float64 `json:"per_core"`
				DurationS *int     `json:"duration_s"`
			}{PerCore: f64(0)}
		}, "load.per_core"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p HostDetectionPatch
			tc.patch(&p)
			_, err := svc.UpdateHostDetection(ctx, id, p)
			if err == nil {
				t.Fatal("accepted an out-of-range threshold")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
	// Nothing was stored, so the anchor still runs on the defaults.
	got, err := svc.GetHostDetection(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CPU.Pct != 90 || got.Revision != 1 {
		t.Errorf("a rejected edit left a trace: %+v", got)
	}
}

// TestHostDetectionRejectsNonHostTargets: the thresholds belong to a host anchor,
// and a probe target has no machine to apply them to.
func TestHostDetectionRejectsNonHostTargets(t *testing.T) {
	svc, _ := seedHostAnchor(t)
	if _, err := svc.GetHostDetection(t.Context(), "p1"); err == nil {
		t.Error("read host thresholds off an icmp target")
	}
	if _, err := svc.UpdateHostDetection(t.Context(), "p1", HostDetectionPatch{}); err == nil {
		t.Error("wrote host thresholds onto an icmp target")
	}
}

// TestHostDetectionSettingsGoWithTheAnchor: deleting the anchor must not leave
// orphaned thresholds behind for an id that will never exist again.
func TestHostDetectionSettingsGoWithTheAnchor(t *testing.T) {
	svc, id := seedHostAnchor(t)
	ctx := t.Context()
	var p HostDetectionPatch
	p.CPU = &struct {
		Enabled   *bool    `json:"enabled"`
		Pct       *float64 `json:"pct"`
		DurationS *int     `json:"duration_s"`
	}{Pct: f64(95)}
	if _, err := svc.UpdateHostDetection(ctx, id, p); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if _, err := svc.db.ExecContext(ctx, `DELETE FROM probe_tasks WHERE id=?`, id); err != nil {
		t.Fatalf("delete anchor: %v", err)
	}
	var n int
	if err := svc.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM host_detection_settings WHERE target_id=?`, id).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("%d orphaned threshold rows survived the anchor", n)
	}
}

// TestHostDetectionRejectsZeroNetThreshold: 0 is the engine's internal "unset"
// value, so accepting it as a number would silently switch a direction off while
// telling the caller their threshold was stored. Clearing is spelled null.
func TestHostDetectionRejectsZeroNetThreshold(t *testing.T) {
	svc, id := seedHostAnchor(t)
	ctx := t.Context()
	if _, err := svc.UpdateHostDetection(ctx, id,
		parsePatch(t, `{"net":{"enabled":true,"rx_mbps":100,"tx_mbps":0}}`)); err == nil {
		t.Fatal("accepted a 0 Mbps threshold")
	} else if !strings.Contains(err.Error(), "tx_mbps") {
		t.Errorf("error does not name the field: %v", err)
	}
	if _, err := svc.UpdateHostDetection(ctx, id,
		parsePatch(t, `{"net":{"enabled":true,"rx_mbps":-5}}`)); err == nil {
		t.Fatal("accepted a negative threshold")
	}
	// Nothing was stored.
	got, err := svc.GetHostDetection(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Net.Enabled || got.Revision != 1 {
		t.Errorf("a rejected net edit left a trace: %+v", got)
	}
}
