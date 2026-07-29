package inventory

import (
	"context"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

const testSite = "site_default"

// Fixture MACs. Note that the usual placeholder "aa:bb:cc:…" is NOT usable as a
// burned-in address here: 0xaa has the locally-administered bit set, so it reads
// as randomized. Burned-in fixtures use a real globally-unique OUI prefix.
const (
	burnedIn   = "00:1a:2b:00:00:0" // 0x00 & 0x02 == 0
	randomized = "a2:bb:cc:00:00:0" // 0xa2 & 0x02 != 0
)

// seedDevices opens a database holding one device per (mac, age) pair. MACs are
// written verbatim so a test can pick a locally-administered first octet (the
// randomized-MAC marker) or a burned-in one.
func seedDevices(t *testing.T, devices map[string]time.Duration) (*store.DB, *settings.Service) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sites(id,name,created_at) VALUES(?,'Default',?)`, testSite, now); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	for mac, age := range devices {
		seen := now.Add(-age)
		if _, err := db.ExecContext(ctx, `
			INSERT INTO devices(id, site_id, mac, ip, hostname, vendor, first_seen, last_seen)
			VALUES(?,?,?,'','','',?,?)`, testSite+"/"+mac, testSite, mac, seen, seen); err != nil {
			t.Fatalf("seed device %s: %v", mac, err)
		}
	}
	return db, settings.New(db)
}

// set writes an integer setting, failing the test rather than the assertion.
func set(t *testing.T, st *settings.Service, key string, v int) {
	t.Helper()
	if err := st.Set(context.Background(), key, strconv.Itoa(v)); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

// remaining returns the MACs still in the table, sorted.
func remaining(t *testing.T, s *Service) []string {
	t.Helper()
	devices, err := s.ListDevices(context.Background(), testSite)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	macs := make([]string, 0, len(devices))
	for _, d := range devices {
		macs = append(macs, d.MAC)
	}
	sort.Strings(macs)
	return macs
}

func assertMACs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("devices = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("devices = %v, want %v", got, want)
		}
	}
}

// The headline behaviour: a randomized MAC and a burned-in MAC of exactly the
// same age get different verdicts, because the randomized one is judged against
// the narrower window.
func TestRetentionRandomMACUsesShorterWindow(t *testing.T) {
	const day = 24 * time.Hour
	db, st := seedDevices(t, map[string]time.Duration{
		burnedIn + "1":   3 * day,     // inside the 7d window
		randomized + "2": 3 * day,     // same age, but past the 2d window
		burnedIn + "3":   9 * day,     // past the 7d window
		randomized + "4": time.Hour,   // randomized but seen recently
		burnedIn + "5":   time.Minute, // seen recently
	})
	set(t, st, settings.KeyDeviceRetentionDays, 7)
	set(t, st, settings.KeyDeviceRandomMACRetentionDays, 2)

	s := New(db, st)
	n, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted = %d, want 2", n)
	}
	assertMACs(t, remaining(t, s), []string{
		burnedIn + "1", burnedIn + "5", randomized + "4",
	})
}

// Every locally-administered first octet must be recognized, and every
// globally-unique one must be left on the master window. Getting this table
// wrong is silent: devices simply live too long or too short.
func TestRetentionLocallyAdministeredBit(t *testing.T) {
	const day = 24 * time.Hour
	seed := map[string]time.Duration{}
	// Second hex digit 0-f; 2,3,6,7,a,b,e,f have 0x02 set.
	for _, d := range "0123456789abcdef" {
		seed["a"+string(d)+":00:00:00:00:01"] = 3 * day
	}
	db, st := seedDevices(t, seed)
	set(t, st, settings.KeyDeviceRetentionDays, 7)
	set(t, st, settings.KeyDeviceRandomMACRetentionDays, 2)

	s := New(db, st)
	if _, err := s.Retention(context.Background()); err != nil {
		t.Fatalf("retention: %v", err)
	}
	assertMACs(t, remaining(t, s), []string{
		"a0:00:00:00:00:01", "a1:00:00:00:00:01", "a4:00:00:00:00:01", "a5:00:00:00:00:01",
		"a8:00:00:00:00:01", "a9:00:00:00:00:01", "ac:00:00:00:00:01", "ad:00:00:00:00:01",
	})
}

// 0 on the master key is the off switch for the whole feature, including
// randomized addresses that are well past their own window.
func TestRetentionDisabled(t *testing.T) {
	const day = 24 * time.Hour
	db, st := seedDevices(t, map[string]time.Duration{
		burnedIn + "1":   400 * day,
		randomized + "2": 400 * day,
	})
	set(t, st, settings.KeyDeviceRetentionDays, 0)
	set(t, st, settings.KeyDeviceRandomMACRetentionDays, 1)

	s := New(db, st)
	n, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if n != 0 {
		t.Fatalf("deleted = %d, want 0", n)
	}
	assertMACs(t, remaining(t, s), []string{burnedIn + "1", randomized + "2"})
}

// 0 on the random key means "don't single them out" — not "keep them forever".
// Randomized and burned-in addresses of the same age must then agree.
func TestRetentionRandomWindowZeroInheritsMaster(t *testing.T) {
	const day = 24 * time.Hour
	db, st := seedDevices(t, map[string]time.Duration{
		burnedIn + "1":   3 * day,
		randomized + "2": 3 * day,
		burnedIn + "3":   9 * day,
		randomized + "4": 9 * day,
	})
	set(t, st, settings.KeyDeviceRetentionDays, 7)
	set(t, st, settings.KeyDeviceRandomMACRetentionDays, 0)

	s := New(db, st)
	if _, err := s.Retention(context.Background()); err != nil {
		t.Fatalf("retention: %v", err)
	}
	assertMACs(t, remaining(t, s), []string{burnedIn + "1", randomized + "2"})
}

// A randomized window wider than the master window must not extend the life of a
// randomized address — the knob only ever narrows. The API rejects this pair, so
// this covers the clamp itself: values written straight to the DB, or a future
// caller that skips the API, must still not let throwaway addresses outlive real
// devices. Both fixtures are older than the master window and younger than the
// (ignored) 30-day randomized window, so an unclamped implementation keeps the
// randomized one and this assertion fails.
func TestRetentionRandomWindowNeverWidensMaster(t *testing.T) {
	const day = 24 * time.Hour
	db, st := seedDevices(t, map[string]time.Duration{
		burnedIn + "1":   10 * day,
		randomized + "2": 10 * day,
		burnedIn + "3":   3 * day,
		randomized + "4": 3 * day,
	})
	set(t, st, settings.KeyDeviceRetentionDays, 7)
	set(t, st, settings.KeyDeviceRandomMACRetentionDays, 30)

	s := New(db, st)
	n, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted = %d, want 2", n)
	}
	assertMACs(t, remaining(t, s), []string{burnedIn + "3", randomized + "4"})
}

// A nil settings service (tests, hand-built wiring) must behave as the
// registered defaults rather than as "retention off".
func TestRetentionNilSettingsUsesDefaults(t *testing.T) {
	const day = 24 * time.Hour
	db, _ := seedDevices(t, map[string]time.Duration{
		burnedIn + "1":   3 * day, // inside the 7d default
		burnedIn + "2":   9 * day, // past it
		randomized + "3": 3 * day, // past the 1d default for randomized MACs
	})

	s := New(db, nil)
	if _, err := s.Retention(context.Background()); err != nil {
		t.Fatalf("retention: %v", err)
	}
	assertMACs(t, remaining(t, s), []string{burnedIn + "1"})
}

// Retention must be scoped by age only — a row whose last_seen is NULL carries
// no age at all and is left alone instead of being deleted on a NULL comparison.
func TestRetentionKeepsRowsWithoutLastSeen(t *testing.T) {
	db, st := seedDevices(t, map[string]time.Duration{burnedIn + "1": 400 * 24 * time.Hour})
	nullMAC := burnedIn + "9"
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO devices(id, site_id, mac, ip, hostname, vendor, first_seen, last_seen)
		VALUES(?,?,?,'','','',NULL,NULL)`, testSite+"/"+nullMAC, testSite, nullMAC); err != nil {
		t.Fatalf("seed null device: %v", err)
	}
	set(t, st, settings.KeyDeviceRetentionDays, 7)

	s := New(db, st)
	n, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted = %d, want 1", n)
	}
	assertMACs(t, remaining(t, s), []string{nullMAC})
}
