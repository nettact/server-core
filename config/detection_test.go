package config

import (
	"strings"
	"testing"

	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/registry"
)

// seedDetectionTarget creates one ICMP target and returns the service and its id.
func seedDetectionTarget(t *testing.T) (*Service, string) {
	t.Helper()
	db, ctx := openConfigTestDB(t)
	svc := New(db, registry.New(db, 0, nil), nil, nil)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents)
		 VALUES('mg','site_default','Default',1,0,1)`); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		 VALUES('t1','site_default','mg','icmp','Router','192.168.1.1','{}',1,1)`); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	return svc, "t1"
}

func TestDetectionDefaultsIncludeSmartOn(t *testing.T) {
	svc, id := seedDetectionTarget(t)
	got, err := svc.GetDetectionSettings(t.Context(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Smart detection is on for a target nobody has ever tuned, because its findings
	// are recorded at a severity the default policy will not send — leaving it on
	// costs a quiet user nothing and tells a curious one something.
	if !got.SmartEnabled {
		t.Fatal("smart detection is off by default")
	}
	if got.SmartSensitivity != fault.SmartStandard {
		t.Fatalf("default sensitivity = %q, want %q", got.SmartSensitivity, fault.SmartStandard)
	}
}

func TestUpdateDetectionRoundTripsSmartFields(t *testing.T) {
	svc, id := seedDetectionTarget(t)
	ctx := t.Context()
	in := fault.DefaultDetection()
	in.SmartEnabled = false
	in.SmartSensitivity = fault.SmartSensitive
	out, err := svc.UpdateDetectionSettings(ctx, id, in)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.SmartEnabled || out.SmartSensitivity != fault.SmartSensitive {
		t.Fatalf("returned smart=(%v,%q)", out.SmartEnabled, out.SmartSensitivity)
	}
	got, err := svc.GetDetectionSettings(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.SmartEnabled || got.SmartSensitivity != fault.SmartSensitive {
		t.Fatalf("stored smart=(%v,%q)", got.SmartEnabled, got.SmartSensitivity)
	}
	// A second edit advances the revision, which is what invalidates every
	// detector's streak on the target — including the degradation ones, whose
	// thresholds just changed under them.
	in.SmartSensitivity = fault.SmartLoose
	if _, err := svc.UpdateDetectionSettings(ctx, id, in); err != nil {
		t.Fatalf("second update: %v", err)
	}
	got, err = svc.GetDetectionSettings(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Revision != 2 {
		t.Fatalf("revision = %d after a second edit, want 2", got.Revision)
	}
}

func TestUpdateDetectionRejectsUnknownSensitivity(t *testing.T) {
	svc, id := seedDetectionTarget(t)
	in := fault.DefaultDetection()
	in.SmartSensitivity = "aggressive"
	// Rejected rather than normalized: silently storing "standard" when the caller
	// asked for something else leaves them believing a setting they do not have.
	_, err := svc.UpdateDetectionSettings(t.Context(), id, in)
	if err == nil {
		t.Fatal("accepted an unknown sensitivity")
	}
	if !strings.Contains(err.Error(), "smart_sensitivity") {
		t.Fatalf("error %q does not name the offending field", err)
	}
}
