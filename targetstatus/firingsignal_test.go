package targetstatus

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// One (target, agent) pair can carry several firing signals at once — the
// uniqueness constraint is per DETECTOR, and ALERT-003 added two more of them.
// The status map holds one signal per pair, so which one it holds has to be
// decided rather than left to whatever order SQLite happens to return: an
// arbitrary pick would let the console report an info "slower than usual" about a
// target whose availability fault is the thing the operator needs to see.

func insertSignalFixture(t *testing.T, db *store.DB, id, detectorKey, severity string, confirmedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `
		INSERT OR IGNORE INTO incidents(id, site_id, group_id, group_name, open_key, title,
		    suspected_layer, state, severity, opened_at)
		VALUES(?, 'site_a', '', '', ?, 'x', 'internet', 'open', ?, ?)`,
		"inc_"+id, "key_"+id, severity, confirmedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO fault_signals(id, site_id, agent_id, target_id, detector_key, probe_kind,
		    target_name, target_addr, agent_name, layer, severity, state,
		    observed_at, confirmed_at, incident_id)
		VALUES(?, 'site_a', 'agent_a', 't_one', ?, 'icmp', 'Router', '192.168.1.1', 'node-1',
		       'internet', ?, 'firing', ?, ?, ?)`,
		id, detectorKey, severity, confirmedAt, confirmedAt, "inc_"+id); err != nil {
		t.Fatal(err)
	}
}

func firingFor(t *testing.T, db *store.DB) firingSignal {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	got, err := New(db, nil).loadFiringSignals(ctx, tx, "site_a")
	if err != nil {
		t.Fatalf("loadFiringSignals: %v", err)
	}
	sig, ok := got["t_one\x00agent_a"]
	if !ok {
		t.Fatal("no signal for the pair")
	}
	return sig
}

func TestFiringSignalPrefersTheMoreSevereDetector(t *testing.T) {
	now := time.Now().UTC()
	// Run both insertion orders. With one order an arbitrary last-write-wins map
	// happens to land on the right answer, so a single-order test would pass
	// against the very bug it exists to catch. Severity has to win regardless:
	// "it is unreachable" is what the operator needs, and "it is a bit slow"
	// must not replace it.
	for _, c := range []struct {
		name  string
		first bool // insert the degradation first
	}{{"degradation first", true}, {"availability first", false}} {
		t.Run(c.name, func(t *testing.T) {
			db := storetest.Open(t)
			deg := func() {
				insertSignalFixture(t, db, "sig_deg", fault.DetectorLatencyDegradation, fault.SeverityInfo, now.Add(-time.Hour))
			}
			avail := func() {
				insertSignalFixture(t, db, "sig_avail", fault.DetectorAvailability, fault.SeverityWarn, now)
			}
			if c.first {
				deg()
				avail()
			} else {
				avail()
				deg()
			}
			if got := firingFor(t, db).signalID; got != "sig_avail" {
				t.Fatalf("pair resolved to %q, want the warn availability signal", got)
			}
		})
	}
}

func TestFiringSignalPickIsStableAmongEqualSeverities(t *testing.T) {
	db := storetest.Open(t)
	now := time.Now().UTC()
	// Latency and loss degradation are both info and neither is more fundamental,
	// so the tie-break is "whichever has been true longest" — a rule that gives the
	// same answer on every refresh instead of flickering between the two.
	insertSignalFixture(t, db, "sig_loss", fault.DetectorLossDegradation, fault.SeverityInfo, now)
	insertSignalFixture(t, db, "sig_lat", fault.DetectorLatencyDegradation, fault.SeverityInfo, now.Add(-time.Hour))

	for range 5 {
		if got := firingFor(t, db).signalID; got != "sig_lat" {
			t.Fatalf("pair resolved to %q, want the longest-firing signal", got)
		}
	}
}

func TestFiringSignalStillSurfacesALoneDegradation(t *testing.T) {
	db := storetest.Open(t)
	// A target that is answering fine but degraded has only this signal, and it
	// must still reach the console — surfacing it is the point of the feature.
	insertSignalFixture(t, db, "sig_deg", fault.DetectorLatencyDegradation, fault.SeverityInfo, time.Now().UTC())

	sig := firingFor(t, db)
	if sig.signalID != "sig_deg" || sig.severity != fault.SeverityInfo {
		t.Fatalf("pair resolved to (%q, %q), want the lone degradation", sig.signalID, sig.severity)
	}
}
