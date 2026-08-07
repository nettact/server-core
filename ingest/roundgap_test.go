package ingest

import (
	"context"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The round-gap tolerance decides when a failing streak is treated as broken by an
// evaluation hole. Deriving it from the wrong schedule is not a cosmetic error: if
// the tolerance comes out shorter than the cadence the agent actually runs, every
// round looks like it followed a gap, the streak resets each time, and no
// multi-round fault can EVER confirm on that agent. These pin the precedence.

func openGapDB(t *testing.T) (*store.DB, *Service) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, []any{now}},
		{`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_a','site_default',x'00','h','online')`, nil},
		{`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents) VALUES('mg','site_default','Default',1,0,1)`, nil},
		{`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		  VALUES('t_icmp','site_default','mg','icmp','Router','192.168.1.1','{}',1,4)`, nil},
	} {
		if _, err := db.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed %q: %v", q.sql, err)
		}
	}
	return db, New(db, nil, nil, nil, nil)
}

func gapFor(t *testing.T, db *store.DB, s *Service) time.Duration {
	t.Helper()
	meta, err := s.probeMeta(context.Background(), db.Read(), "agent_a", "site_default", []string{"t_icmp"})
	if err != nil {
		t.Fatalf("probeMeta: %v", err)
	}
	m, ok := meta["t_icmp"]
	if !ok {
		t.Fatal("target missing from probe meta")
	}
	return m.MaxRoundGap
}

// icmpCycle is the whole-cycle deadline an agent reports for the seeded ICMP
// target, taken from the shared formula rather than a literal so these tests
// cannot drift from it. Spread pacing makes it the check interval.
func icmpCycle(p pcfg.ProbeParams) time.Duration { return pcfg.CycleDeadline("icmp", p) }

// TestRoundGapHonoursAgentReportedFloor: an agent floors every interval at its
// local MinProbeInterval, so a 10s ICMP target on an agent with a 60s floor really
// runs every 60s. The tolerance has to follow the reported cadence, or that agent
// silently loses fault detection entirely.
func TestRoundGapHonoursAgentReportedFloor(t *testing.T) {
	db, svc := openGapDB(t)
	ctx := context.Background()

	// Desired config only: ICMP defaults give StaleAfter(10s, 10s, 30s) = 90s.
	fallback := gapFor(t, db, svc)
	if want := pcfg.StaleAfter(10*time.Second, icmpCycle(pcfg.ProbeParams{}), pcfg.DefaultUploadInterval); fallback != want {
		t.Fatalf("desired-config fallback = %v, want %v", fallback, want)
	}

	// The agent echoes its real schedule for this generation: a 60s floored
	// interval. Its cycle deadline stays the unfloored 10s (see monitoreval's
	// stampSchedule), which the base term absorbs either way.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id, monitor_id, status, config_version, updated_at, source,
		    target_config_serial, effective_interval_seconds, cycle_deadline_ms, upload_interval_seconds)
		VALUES('agent_a','t_icmp','active',1,?,'reported',4,60,10000,5)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	got := gapFor(t, db, svc)
	if want := pcfg.StaleAfter(60*time.Second, 10*time.Second, 5*time.Second); got != want {
		t.Fatalf("reported schedule = %v, want %v", got, want)
	}
	// The whole point: the tolerance now exceeds the real 60s cadence, so consecutive
	// rounds are not mistaken for rounds either side of a hole.
	if got <= 60*time.Second {
		t.Fatalf("tolerance %v must exceed the agent's real 60s cadence, or no fault can confirm", got)
	}
	if got <= fallback {
		t.Fatalf("reported tolerance %v should be wider than the unfloored fallback %v", got, fallback)
	}
}

// TestRoundGapIgnoresStaleGenerationEcho: a monitor_status row for an older target
// generation describes a schedule that is no longer running, so it must not be
// trusted over the current desired config.
func TestRoundGapIgnoresStaleGenerationEcho(t *testing.T) {
	db, svc := openGapDB(t)
	ctx := context.Background()

	// Reported, but for generation 3 while the target is now at 4.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id, monitor_id, status, config_version, updated_at, source,
		    target_config_serial, effective_interval_seconds, cycle_deadline_ms, upload_interval_seconds)
		VALUES('agent_a','t_icmp','active',1,?,'reported',3,600,10000,5)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	want := pcfg.StaleAfter(10*time.Second, icmpCycle(pcfg.ProbeParams{}), pcfg.DefaultUploadInterval)
	if got := gapFor(t, db, svc); got != want {
		t.Fatalf("stale-generation echo must not be used: got %v, want the desired-config %v", got, want)
	}
}

// TestRoundGapIgnoresPredictedSchedule: a predicted row is the server's own guess,
// not the agent's echo, so it carries no knowledge of the agent's floor.
func TestRoundGapIgnoresPredictedSchedule(t *testing.T) {
	db, svc := openGapDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id, monitor_id, status, config_version, updated_at, source,
		    target_config_serial, effective_interval_seconds, cycle_deadline_ms)
		VALUES('agent_a','t_icmp','active',1,?,'predicted',4,600,10000)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	want := pcfg.StaleAfter(10*time.Second, icmpCycle(pcfg.ProbeParams{}), pcfg.DefaultUploadInterval)
	if got := gapFor(t, db, svc); got != want {
		t.Fatalf("predicted schedule must not be used: got %v, want %v", got, want)
	}
}

// TestRoundGapUsesConfiguredInterval: with no echo at all, a target's own
// configured interval still drives the tolerance rather than the kind default.
func TestRoundGapUsesConfiguredInterval(t *testing.T) {
	db, svc := openGapDB(t)
	if _, err := db.ExecContext(context.Background(),
		`UPDATE probe_tasks SET params='{"interval_seconds":300}' WHERE id='t_icmp'`); err != nil {
		t.Fatal(err)
	}
	params := pcfg.ProbeParams{IntervalSeconds: 300}
	want := pcfg.StaleAfter(300*time.Second, icmpCycle(params), pcfg.DefaultUploadInterval)
	if got := gapFor(t, db, svc); got != want {
		t.Fatalf("configured interval = %v, want %v", got, want)
	}
}
