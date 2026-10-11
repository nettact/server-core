package routehist

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/asnlookup"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// fakeASN maps /8s to AS numbers, standing in for a loaded table:
//
//	11/8 → AS100 (local ISP)        12/8 → AS200 (second local line)
//	21/8 → AS300 (transit X)        22/8 → AS400 (transit Y)
//	31/8 → AS500 (destination net)  32/8 → AS600 (another destination net)
//
// 11.1/16 is carved out as a different prefix of AS100, for the local-egress
// prefix rule.
type fakeASN struct{}

func (fakeASN) Version() string { return "test-1" }
func (fakeASN) Lookup(a netip.Addr) (asnlookup.Info, bool) {
	if !asnlookup.IsPublicIPv4(a) {
		return asnlookup.Info{}, false
	}
	b := a.As4()
	m := map[byte]uint32{11: 100, 12: 200, 21: 300, 22: 400, 31: 500, 32: 600}
	asn, ok := m[b[0]]
	if !ok {
		return asnlookup.Info{}, false
	}
	prefix := fmt.Sprintf("%d.0.0.0/8", b[0])
	if b[0] == 11 && b[1] == 1 {
		prefix = "11.1.0.0/16"
	}
	return asnlookup.Info{ASN: asn, Name: fmt.Sprintf("NET-%d", asn), Country: "CN", Prefix: prefix}, true
}

type fixture struct {
	t   *testing.T
	db  *store.DB
	res asnlookup.Resolver
	n   int
	ts  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO sites(id,name) VALUES('site_default','Default')`,
		`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,status) VALUES('agent_a','site_default',x'00','h','box-a','online')`,
		`INSERT INTO agents(id,site_id,public_key,token_hash,hostname,status) VALUES('agent_b','site_default',x'01','h2','box-b','online')`,
		`INSERT INTO monitor_groups(id,site_id,name,all_agents) VALUES('g1','site_default','All',1)`,
		`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('m1','site_default','g1','trace','Route','example.com','{}',1,1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return &fixture{t: t, db: db, res: fakeASN{}, ts: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
}

// sweep builds a scheduled TraceResult. Each hop is "a" (three attempts from
// a, with RTT), "a|b" (attempts alternate a, b, a — ECMP within one TTL) or
// "*" (all three timed out). The destination is reached when the last hop
// answers from dest.
func (f *fixture) sweep(dest string, rtt float64, hops ...string) telemetry.TraceResult {
	f.n++
	f.ts = f.ts.Add(10 * time.Minute)
	tr := telemetry.TraceResult{
		ReportID: fmt.Sprintf("rep-%03d", f.n), DestKey: "host:example.com", DestHost: "example.com",
		Mode: "icmp", DestinationIP: dest, SubjectKind: telemetry.TraceSubjectTarget,
		PathScope: telemetry.TracePathDirect, TriggerReason: telemetry.TraceTriggerScheduled,
		Status: telemetry.TraceStatusSucceeded, StartedAt: f.ts, CompletedAt: f.ts.Add(5 * time.Second),
		MonitorID: "m1", ConfigSerial: 1,
	}
	for i, h := range hops {
		hop := telemetry.TraceHop{TTL: i + 1}
		alts := strings.Split(h, "|")
		for k := 0; k < 3; k++ {
			ip := alts[k%len(alts)]
			if ip == "*" {
				hop.Attempts = append(hop.Attempts, telemetry.TraceAttempt{Timeout: true})
				continue
			}
			r := float64(i+1) * 2
			if ip == dest {
				r = rtt + float64(k)
				tr.Reached, tr.ReachedTTL = true, i+1
			}
			hop.Attempts = append(hop.Attempts, telemetry.TraceAttempt{ResponderAddr: ip, Hostname: "h-" + ip, RTTMs: r})
		}
		tr.Hops = append(tr.Hops, hop)
	}
	if !tr.Reached {
		tr.Status = telemetry.TraceStatusPartial
	}
	return tr
}

func (f *fixture) apply(agentID string, trs ...telemetry.TraceResult) {
	f.t.Helper()
	err := f.db.WriteTx(context.Background(), store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		return nil, ApplyTx(context.Background(), store.Standalone(), wtx, f.res, agentID, trs, f.ts.Add(time.Minute))
	})
	if err != nil {
		f.t.Fatalf("ApplyTx: %v", err)
	}
}

func (f *fixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

type epochSummary struct {
	id                  int64
	as                  []uint32
	runs, deviations    int
	reachedRuns, rttCnt int
}

func (f *fixture) epochs(agentID string) []epochSummary {
	f.t.Helper()
	rows, err := f.db.Query(`SELECT e.id, p.as_path, e.run_count, e.deviation_count, e.reached_runs, e.rtt_count
		FROM route_epochs e JOIN route_paths p ON p.id=e.path_id WHERE e.agent_id=? AND e.monitor_id='m1' ORDER BY e.id`, agentID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []epochSummary
	for rows.Next() {
		var e epochSummary
		var blob []byte
		if err := rows.Scan(&e.id, &blob, &e.runs, &e.deviations, &e.reachedRuns, &e.rttCnt); err != nil {
			f.t.Fatal(err)
		}
		e.as, _ = decodeASPath(blob)
		out = append(out, e)
	}
	return out
}

type changeRow struct {
	kind, segment       string
	divergeTTL          sql.NullInt64
	from, to            int64
	beforeRun, afterRun sql.NullInt64
}

func (f *fixture) changes() []changeRow {
	f.t.Helper()
	rows, err := f.db.Query(`SELECT kind, segment, diverge_ttl, from_epoch_id, to_epoch_id, before_run_id, after_run_id FROM route_changes ORDER BY id`)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []changeRow
	for rows.Next() {
		var c changeRow
		if err := rows.Scan(&c.kind, &c.segment, &c.divergeTTL, &c.from, &c.to, &c.beforeRun, &c.afterRun); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

const (
	dest1 = "31.0.0.9"
	dest2 = "32.0.0.9"
)

func (f *fixture) pathA() telemetry.TraceResult {
	return f.sweep(dest1, 30, "192.168.1.1", "11.0.0.1", "21.0.0.1", dest1)
}
func (f *fixture) pathB() telemetry.TraceResult { // transit X → Y
	return f.sweep(dest1, 170, "192.168.1.1", "11.0.0.1", "22.0.0.1", dest1)
}

func TestARouteThatHoldsExtendsOneEpoch(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 5; i++ {
		f.apply("agent_a", f.pathA())
	}
	eps := f.epochs("agent_a")
	if len(eps) != 1 {
		t.Fatalf("epochs = %d, want 1", len(eps))
	}
	e := eps[0]
	if fmt.Sprint(e.as) != "[100 300 500]" || e.runs != 5 || e.deviations != 0 || e.reachedRuns != 5 || e.rttCnt != 15 {
		t.Errorf("epoch = %+v", e)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_paths`); n != 1 {
		t.Errorf("paths = %d, want 1 (identical runs share one path)", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_runs_detail`); n != 5 {
		t.Errorf("details = %d", n)
	}
	if len(f.changes()) != 0 {
		t.Error("a holding route produced a change")
	}
}

func TestAShortFlapIsADeviationNotAChange(t *testing.T) {
	for flap := 1; flap <= 2; flap++ {
		t.Run(fmt.Sprintf("%d runs", flap), func(t *testing.T) {
			f := newFixture(t)
			f.apply("agent_a", f.pathA(), f.pathA())
			for i := 0; i < flap; i++ {
				f.apply("agent_a", f.pathB())
			}
			f.apply("agent_a", f.pathA())
			eps := f.epochs("agent_a")
			if len(eps) != 1 {
				t.Fatalf("epochs = %d, want 1", len(eps))
			}
			if eps[0].runs != 3 || eps[0].deviations != flap {
				t.Errorf("epoch = %+v, want 3 runs / %d deviations", eps[0], flap)
			}
			if len(f.changes()) != 0 {
				t.Error("a flap confirmed as a change")
			}
			var pending string
			f.db.QueryRow(`SELECT pending FROM route_monitor_state`).Scan(&pending)
			if pending != "" {
				t.Errorf("pending kept after the route came back: %s", pending)
			}
		})
	}
}

func TestThreeRunsOnANewRouteConfirmAChange(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.pathA(), f.pathA())
	f.apply("agent_a", f.pathB(), f.pathB())
	if len(f.changes()) != 0 {
		t.Fatal("confirmed after two runs")
	}
	f.apply("agent_a", f.pathB())
	eps := f.epochs("agent_a")
	if len(eps) != 2 {
		t.Fatalf("epochs = %d, want 2", len(eps))
	}
	if eps[0].deviations != 0 || eps[0].runs != 2 {
		t.Errorf("old epoch = %+v: the confirmed runs must stop counting as its deviations", eps[0])
	}
	if fmt.Sprint(eps[1].as) != "[100 400 500]" || eps[1].runs != 3 || eps[1].rttCnt != 9 {
		t.Errorf("new epoch = %+v", eps[1])
	}
	cs := f.changes()
	if len(cs) != 1 {
		t.Fatalf("changes = %d", len(cs))
	}
	c := cs[0]
	if c.kind != KindRoute || c.segment != SegmentISPBackbone || c.from != eps[0].id || c.to != eps[1].id {
		t.Errorf("change = %+v", c)
	}
	if !c.divergeTTL.Valid || c.divergeTTL.Int64 != 3 {
		t.Errorf("diverge_ttl = %v, want 3 (the first hop in AS400)", c.divergeTTL)
	}
	if !c.beforeRun.Valid || !c.afterRun.Valid {
		t.Errorf("change cites no evidence: %+v", c)
	}
	// After confirmation the new route is the baseline: more runs extend it.
	f.apply("agent_a", f.pathB())
	if eps := f.epochs("agent_a"); len(eps) != 2 || eps[1].runs != 4 {
		t.Errorf("after confirmation: %+v", eps)
	}
}

func TestAnInterruptedCandidateStartsOver(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.pathA())
	f.apply("agent_a", f.pathB(), f.pathB())
	// A third, different route resets the candidate rather than confirming B.
	f.apply("agent_a", f.sweep(dest1, 30, "192.168.1.1", "12.0.0.1", "21.0.0.1", dest1))
	f.apply("agent_a", f.pathB(), f.pathB())
	if len(f.changes()) != 0 {
		t.Fatal("non-consecutive runs confirmed a change")
	}
	f.apply("agent_a", f.pathB())
	if cs := f.changes(); len(cs) != 1 {
		t.Fatalf("changes = %d, want 1 once three consecutive runs agree", len(cs))
	}
}

func TestECMPVariantsDoNotSplitTheEpoch(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a",
		f.sweep(dest1, 30, "192.168.1.1", "11.0.0.1", "21.0.0.1", dest1),
		f.sweep(dest1, 30, "192.168.1.1", "11.0.0.1", "21.0.0.2", dest1),
		f.sweep(dest1, 30, "192.168.1.1", "11.0.0.1", "21.0.0.1|21.0.0.2", dest1),
		f.sweep(dest1, 30, "192.168.1.1", "11.0.0.1", "21.0.0.2", dest1),
	)
	eps := f.epochs("agent_a")
	if len(eps) != 1 || eps[0].runs != 4 || eps[0].deviations != 0 {
		t.Fatalf("epochs = %+v, want one era of 4 runs", eps)
	}
	rows, _ := f.db.Query(`SELECT count FROM route_epoch_variants WHERE epoch_id=? ORDER BY count DESC`, eps[0].id)
	var counts []int
	for rows.Next() {
		var c int
		rows.Scan(&c)
		counts = append(counts, c)
	}
	rows.Close()
	if fmt.Sprint(counts) != "[2 1 1]" {
		t.Errorf("variant counts = %v, want [2 1 1]", counts)
	}
}

func TestPartialSweepsCompareByTheirAnsweredPrefix(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.pathA())
	// Destination filters probes / tail times out: a prefix of the era's route.
	for i := 0; i < 4; i++ {
		f.apply("agent_a", f.sweep(dest1, 0, "192.168.1.1", "11.0.0.1", "21.0.0.1", "*", "*"))
	}
	// A sweep nobody answered is no observation at all: skipped outright.
	f.apply("agent_a", f.sweep(dest1, 0, "*", "*", "*"))
	eps := f.epochs("agent_a")
	if len(eps) != 1 || eps[0].runs != 5 || eps[0].deviations != 0 || eps[0].reachedRuns != 1 {
		t.Fatalf("epochs = %+v, want one era with every partial run counted as the same route", eps)
	}
	// A partial sweep that is NOT a prefix (it went through AS400) is a deviation.
	f.apply("agent_a", f.sweep(dest1, 0, "192.168.1.1", "11.0.0.1", "22.0.0.1", "*"))
	if eps := f.epochs("agent_a"); eps[0].deviations != 1 {
		t.Errorf("non-prefix partial sweep: %+v", eps)
	}
}

func TestAnEpochFirstSeenPartialIsRefinedNotChanged(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.sweep(dest1, 0, "192.168.1.1", "11.0.0.1", "*"))
	f.apply("agent_a", f.pathA(), f.pathA(), f.pathA())
	eps := f.epochs("agent_a")
	if len(eps) != 1 || fmt.Sprint(eps[0].as) != "[100 300 500]" || eps[0].runs != 4 {
		t.Fatalf("epochs = %+v, want one era refined to the full route", eps)
	}
	if len(f.changes()) != 0 {
		t.Error("seeing further was recorded as a route change")
	}
}

func TestChangeKinds(t *testing.T) {
	cases := []struct {
		name          string
		next          func(f *fixture) telemetry.TraceResult
		kind, segment string
	}{
		{"destination moved", func(f *fixture) telemetry.TraceResult {
			return f.sweep(dest2, 30, "192.168.1.1", "11.0.0.1", "21.0.0.1", dest2)
		}, KindDestination, SegmentDestination},
		{"second local line", func(f *fixture) telemetry.TraceResult {
			return f.sweep(dest1, 30, "192.168.1.1", "12.0.0.1", "21.0.0.1", dest1)
		}, KindLocalEgress, SegmentLocalAccess},
		{"transit change", func(f *fixture) telemetry.TraceResult { return f.pathB() }, KindRoute, SegmentISPBackbone},
		{"deeper transit change", func(f *fixture) telemetry.TraceResult {
			return f.sweep(dest1, 30, "192.168.1.1", "11.0.0.1", "21.0.0.1", "22.0.0.1", dest1)
		}, KindRoute, SegmentInterconn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.apply("agent_a", f.pathA())
			f.apply("agent_a", c.next(f), c.next(f), c.next(f))
			cs := f.changes()
			if len(cs) != 1 {
				t.Fatalf("changes = %d", len(cs))
			}
			if cs[0].kind != c.kind || cs[0].segment != c.segment {
				t.Errorf("change = %s/%s, want %s/%s", cs[0].kind, cs[0].segment, c.kind, c.segment)
			}
		})
	}
}

func TestReplayAndOutOfOrderRunsAreNoOps(t *testing.T) {
	f := newFixture(t)
	a1, a2 := f.pathA(), f.pathA()
	f.apply("agent_a", a1, a2)
	f.apply("agent_a", a1, a2) // the same reports again
	if eps := f.epochs("agent_a"); len(eps) != 1 || eps[0].runs != 2 {
		t.Fatalf("replay changed history: %+v", eps)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_runs_detail`); n != 2 {
		t.Errorf("details = %d after replay", n)
	}
	old := a1
	old.ReportID = "late"
	f.apply("agent_a", old) // older than the last applied run
	if eps := f.epochs("agent_a"); eps[0].runs != 2 {
		t.Errorf("an out-of-order run was applied: %+v", eps)
	}
}

func TestAgentsAndGenerationsKeepSeparateHistory(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.pathA(), f.pathA())
	f.apply("agent_b", f.pathB())
	if a, b := f.epochs("agent_a"), f.epochs("agent_b"); len(a) != 1 || len(b) != 1 {
		t.Fatalf("epochs a=%d b=%d", len(a), len(b))
	}
	// A material edit (new generation) starts a new baseline, never a change.
	f.db.Exec(`UPDATE probe_tasks SET config_serial=2 WHERE id='m1'`)
	r := f.pathB()
	r.ConfigSerial = 2
	f.apply("agent_a", r)
	if eps := f.epochs("agent_a"); len(eps) != 2 {
		t.Fatalf("epochs = %d after a generation change, want 2", len(eps))
	}
	if len(f.changes()) != 0 {
		t.Error("a monitor edit was recorded as a route change")
	}
	if n := f.count(`SELECT COUNT(*) FROM route_paths`); n != 2 {
		t.Errorf("paths = %d: agents on the same route must share path rows", n)
	}
}

func TestWithoutAResolverIPHistoryIsRecordedAndNoChangeConfirms(t *testing.T) {
	f := newFixture(t)
	f.res = nil
	f.apply("agent_a", f.pathA(), f.pathB(), f.pathB(), f.pathB())
	eps := f.epochs("agent_a")
	if len(eps) != 1 || len(eps[0].as) != 0 || eps[0].runs != 4 {
		t.Fatalf("epochs = %+v", eps)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_epoch_variants`); n != 2 {
		t.Errorf("variants = %d, want both IP paths counted", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_ips WHERE asn<>0`); n != 0 {
		t.Errorf("%d hops got an AS without a resolver", n)
	}
}

func TestUnusableSweepsAreSkipped(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.pathA())
	unsupported := f.pathA()
	unsupported.Status, unsupported.Reason, unsupported.Hops = telemetry.TraceStatusUnsupported, "raw_socket_unavailable", nil
	failed := f.pathB()
	failed.Status, failed.Reason, failed.Hops = telemetry.TraceStatusFailed, "dns_error", nil
	silent := f.sweep(dest1, 0, "*", "*")
	silent.Status = telemetry.TraceStatusTimedOut
	// Failed sweeps that still carry hops are refused too: the engine's
	// verdict is that the sweep did not run as asked.
	failedWithHops := f.pathB()
	failedWithHops.Status = telemetry.TraceStatusFailed
	for i := 0; i < 3; i++ {
		f.apply("agent_a", unsupported, failed, silent, failedWithHops)
		unsupported.ReportID += "x"
		failed.ReportID += "x"
		silent.ReportID += "x"
		failedWithHops.ReportID += "x"
	}
	if n := f.count(`SELECT COUNT(*) FROM route_runs_detail`); n != 1 {
		t.Errorf("details = %d, want only the one real sweep", n)
	}
	eps := f.epochs("agent_a")
	if len(eps) != 1 || eps[0].runs != 1 || eps[0].deviations != 0 {
		t.Errorf("refused sweeps touched the detector: %+v", eps)
	}
}

func TestRetentionKeepsCitedEvidenceAndDropsTheRest(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.pathA(), f.pathA())
	f.apply("agent_a", f.pathB(), f.pathB(), f.pathB())
	// One more ECMP variant on the new route, then let everything age.
	f.apply("agent_a", f.sweep(dest1, 170, "192.168.1.1", "11.0.0.1", "22.0.0.2", dest1))
	c := f.changes()[0]

	ctx := context.Background()
	future := f.ts.Add(30 * 24 * time.Hour)
	if err := f.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		return nil, RetentionTx(ctx, store.Standalone(), wtx, future)
	}); err != nil {
		t.Fatal(err)
	}
	var kept []int64
	rows, _ := f.db.Query(`SELECT id FROM route_runs_detail ORDER BY id`)
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		kept = append(kept, id)
	}
	rows.Close()
	// The change's before/after runs and the monitor's last run survive.
	want := map[int64]bool{c.beforeRun.Int64: true, c.afterRun.Int64: true}
	var last int64
	f.db.QueryRow(`SELECT last_run_id FROM route_monitor_state`).Scan(&last)
	want[last] = true
	if len(kept) != len(want) {
		t.Errorf("kept details %v, want exactly %v", kept, want)
	}
	for _, id := range kept {
		if !want[id] {
			t.Errorf("detail %d survived without being cited", id)
		}
	}
	// Eras and changes are forever; variants are within the year.
	if n := f.count(`SELECT COUNT(*) FROM route_epochs`); n != 2 {
		t.Errorf("epochs = %d", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_changes`); n != 1 {
		t.Errorf("changes = %d", n)
	}
	// Every surviving reference still resolves (no dangling dictionary ids).
	if n := f.count(`SELECT COUNT(*) FROM route_epochs WHERE path_id NOT IN (SELECT id FROM route_paths)`); n != 0 {
		t.Errorf("%d epochs lost their path", n)
	}

	// A year and more later the old era's variants go, and with them any path
	// and address nothing else names.
	far := f.ts.Add(400 * 24 * time.Hour)
	f.db.Exec(`UPDATE route_epochs SET end_ts=? WHERE id=?`, f.ts.Add(-366*24*time.Hour).Unix(), c.from)
	if err := f.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		return nil, RetentionTx(ctx, store.Standalone(), wtx, far)
	}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_epoch_variants WHERE epoch_id=?`, c.from); n != 0 {
		t.Errorf("old era kept %d variants past a year", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_epochs`); n != 2 {
		t.Errorf("epochs pruned: %d", n)
	}
	// Dictionary integrity: every id a remaining path names exists.
	var blobs [][]byte
	rows, _ = f.db.Query(`SELECT ip_path FROM route_paths`)
	for rows.Next() {
		var blob []byte
		rows.Scan(&blob)
		blobs = append(blobs, blob)
	}
	rows.Close()
	for _, blob := range blobs {
		ip, _ := decodeIPPath(blob)
		for _, hop := range ip {
			for _, id := range hop {
				var n int
				f.db.QueryRow(`SELECT COUNT(*) FROM route_ips WHERE id=?`, id).Scan(&n)
				if n != 1 {
					t.Errorf("path names missing address %d", id)
				}
			}
		}
	}
	if n := f.count(`SELECT COUNT(*) FROM route_ips WHERE ip='21.0.0.1'`); n != 1 {
		t.Errorf("an address still named by the old era's path was dropped")
	}
	// The Service wrapper runs the same pass plus the vacuum.
	if err := New(f.db, nil).Retention(ctx); err != nil {
		t.Errorf("Service.Retention: %v", err)
	}
}

func TestRetentionDropsUnreferencedDictionaryRows(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.pathA())
	f.db.Exec(`INSERT INTO route_ips(ip,first_seen,last_seen) VALUES('99.9.9.9',0,0)`)
	f.db.Exec(`INSERT INTO route_paths(hash,ip_path,as_path,first_seen) VALUES(x'ff',x'',x'',0)`)
	f.db.Exec(`INSERT INTO asn_info(asn,name,updated_at) VALUES(65000,'gone',0)`)
	if err := New(f.db, nil).Retention(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_ips WHERE ip='99.9.9.9'`); n != 0 {
		t.Error("orphan address kept")
	}
	if n := f.count(`SELECT COUNT(*) FROM route_paths WHERE hash=x'ff'`); n != 0 {
		t.Error("orphan path kept")
	}
	if n := f.count(`SELECT COUNT(*) FROM asn_info WHERE asn=65000`); n != 0 {
		t.Error("orphan AS kept")
	}
	if n := f.count(`SELECT COUNT(*) FROM asn_info WHERE asn=300`); n != 1 {
		t.Error("referenced AS dropped")
	}
}

func TestApplyTxRefusesAMismatchedScope(t *testing.T) {
	f := newFixture(t)
	err := f.db.WriteTx(context.Background(), store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		return nil, ApplyTx(context.Background(), store.Scope{TenantID: "t1"}, wtx, nil, "agent_a", []telemetry.TraceResult{f.pathA()}, time.Now())
	})
	if err == nil {
		t.Fatal("mismatched scope accepted")
	}
}

// remappedASN is fakeASN under a newer table version in which some addresses
// moved AS: every address remap selects is attributed to AS400 instead.
type remappedASN struct{ remap func(netip.Addr) bool }

func (remappedASN) Version() string { return "test-2" }
func (m remappedASN) Lookup(a netip.Addr) (asnlookup.Info, bool) {
	info, ok := fakeASN{}.Lookup(a)
	if ok && m.remap(a) {
		info.ASN, info.Name = 400, "NET-400"
	}
	return info, ok
}

// A lookup-table refresh that moves a hop to another AS must not manufacture
// a route change: the same addresses are the same route, so the era continues
// and is re-described under the new table.
func TestATableRefreshDoesNotManufactureAChange(t *testing.T) {
	f := newFixture(t)
	f.apply("agent_a", f.pathA(), f.pathA())
	f.res = remappedASN{remap: func(a netip.Addr) bool { return a.As4()[0] == 21 }}
	for i := 0; i < ConfirmRuns+1; i++ {
		f.apply("agent_a", f.pathA())
	}
	if c := f.changes(); len(c) != 0 {
		t.Fatalf("changes = %+v, want none for an unchanged IP route", c)
	}
	eps := f.epochs("agent_a")
	if len(eps) != 1 {
		t.Fatalf("epochs = %d, want the era to continue", len(eps))
	}
	if e := eps[0]; fmt.Sprint(e.as) != "[100 400 500]" || e.runs != 2+ConfirmRuns+1 || e.deviations != 0 {
		t.Errorf("epoch = %+v, want 6 runs, no deviations, AS path re-described as [100 400 500]", e)
	}
	if n := f.count(`SELECT COUNT(*) FROM route_ips WHERE ip='21.0.0.1' AND asn=400 AND asn_db_version='test-2'`); n != 1 {
		t.Errorf("the re-attributed dictionary row is missing (%d)", n)
	}
	var pending string
	f.db.QueryRow(`SELECT pending FROM route_monitor_state`).Scan(&pending)
	if pending != "" {
		t.Errorf("a refresh left a pending candidate: %s", pending)
	}

	// A real change after the refresh still confirms, classified in one table.
	for i := 0; i < ConfirmRuns; i++ {
		f.apply("agent_a", f.sweep(dest2, 40, "192.168.1.1", "11.0.0.1", "21.0.0.1", dest2))
	}
	if c := f.changes(); len(c) != 1 || c[0].kind != KindDestination {
		t.Errorf("changes = %+v, want one destination change", c)
	}
}

// An ECMP variant whose own hop moved AS — while the representative path's
// did not — is still matched by address and continues the era.
func TestATableRefreshOfAVariantHopDoesNotManufactureAChange(t *testing.T) {
	f := newFixture(t)
	variant := func() telemetry.TraceResult {
		return f.sweep(dest1, 30, "192.168.1.1", "11.0.0.1", "21.0.0.2", dest1)
	}
	f.apply("agent_a", f.pathA(), variant(), f.pathA())
	f.res = remappedASN{remap: func(a netip.Addr) bool { return a == netip.MustParseAddr("21.0.0.2") }}
	for i := 0; i < ConfirmRuns+1; i++ {
		f.apply("agent_a", variant())
	}
	if c := f.changes(); len(c) != 0 {
		t.Fatalf("changes = %+v, want none", c)
	}
	eps := f.epochs("agent_a")
	if len(eps) != 1 || eps[0].runs != 3+ConfirmRuns+1 || eps[0].deviations != 0 {
		t.Fatalf("epochs = %+v, want one continuing era with no deviations", eps)
	}
	if fmt.Sprint(eps[0].as) != "[100 300 500]" {
		t.Errorf("representative AS path = %v, want the re-resolved (unchanged) [100 300 500]", eps[0].as)
	}
}
