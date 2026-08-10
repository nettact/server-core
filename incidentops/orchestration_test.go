package incidentops

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

func openIncidentOpsTest(t *testing.T) (*store.DB, context.Context) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES('site_default','Home')`); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	for _, id := range []string{"agent_a", "agent_b"} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES(?,'site_default',x'00','h','online')`, id); err != nil {
			t.Fatalf("seed agent %s: %v", id, err)
		}
	}
	return db, ctx
}

func seedIncidentSignal(t *testing.T, db *store.DB, incidentID, signalID, agentID, state string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES(?,'site_default','group','Group',?,'open',?)`, incidentID, "sig:"+signalID, now); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO fault_signals(id,agent_id,site_id,target_id,detector_key,group_id,group_name,incident_id,state,observed_at,confirmed_at)
		VALUES(?,?,'site_default',?,'availability','group','Group',?,?,?,?)`,
		signalID, agentID, "probe_"+signalID, incidentID, state, now, now); err != nil {
		t.Fatalf("seed fault signal: %v", err)
	}
}

// seedStoredTrace writes a report as ingest would have, already referenced by an
// incident's signal.
func seedStoredTrace(t *testing.T, db *store.DB, id, incidentID, signalID, agentID, destKey, destHost string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO trace_reports(id,site_id,agent_id,dest_key,dest_host,mode,status,max_hops,attempts,
			path_scope,trigger_reason,trigger_streak,started_at,completed_at,received_at)
		VALUES(?,'site_default',?,?,?,'icmp','partial',30,3,'direct','consecutive_failures',3,?,?,?)`,
		id, agentID, destKey, destHost, now, now, now); err != nil {
		t.Fatalf("seed stored trace: %v", err)
	}
	if incidentID == "" {
		return
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO trace_report_refs(report_id,incident_id,signal_id,active,created_at)
		VALUES(?,?,?,1,?)`, id, incidentID, signalID, now); err != nil {
		t.Fatalf("seed trace ref: %v", err)
	}
}

// The base is capped when it is WRITTEN, because nothing waits on the snapshot
// any more: there is no later moment at which an over-budget total could be
// settled, so an oversized base would simply be stored. The reduction has to stay
// deterministic and has to keep the incident's identifiers — a base truncated
// into invalid JSON, or into a body that no longer says which incident it
// describes, is worse than no base at all.
func TestIncidentBaseIsCappedAtWriteTime(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	set := settings.New(db)
	const budget = 65536
	if err := set.Set(ctx, settings.KeyIncidentSnapshotMaxBytes, fmt.Sprint(budget)); err != nil {
		t.Fatalf("set max bytes: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES('inc','site_default','group','Group','alert:big','open',?)`, now); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	base := SnapshotBase{IncidentID: "inc", SiteID: "site_default", Group: baseGroup{ID: "group", Name: "Group"}, TriggeredAt: now, ReceivedAt: now}
	for i := 0; i < 500; i++ {
		samples := make([]baseSample, 12)
		for j := range samples {
			samples[j] = baseSample{TS: now.Add(time.Duration(j) * time.Second), Value: float64(j)}
		}
		base.Members = append(base.Members, baseMember{
			SignalID: fmt.Sprintf("sig-%d", i), DetectorKey: "availability", AgentID: "agent_a",
			ObservedAt: now, ConfirmedAt: now,
			Evidence: baseEvidence{TargetID: "target", MetricKind: "probe.icmp.loss_pct", Comparator: "gt", RecentSamples: samples},
		})
	}
	raw := mustJSON(base)
	if len(raw) <= budget {
		t.Fatalf("fixture base too small: %d", len(raw))
	}

	capped, changed := truncateBase(raw, budget)
	if !changed {
		t.Fatal("an over-budget base was left untouched")
	}
	if len(capped) > budget {
		t.Fatalf("capped base is %d bytes, over the %d budget", len(capped), budget)
	}
	if !json.Valid([]byte(capped)) {
		t.Fatal("truncation produced invalid JSON")
	}
	var out SnapshotBase
	if err := json.Unmarshal([]byte(capped), &out); err != nil {
		t.Fatalf("decode capped base: %v", err)
	}
	if out.IncidentID != "inc" || out.SiteID != "site_default" || out.Group.ID != "group" {
		t.Fatalf("truncation dropped the incident identifiers: %+v", out)
	}
}

// setAgentPerms writes an agent's three reported permission views (as their
// JSON string-array column encodings).
func setAgentPerms(t *testing.T, db *store.DB, agentID string, supported, granted, effective []permission.ID) {
	t.Helper()
	enc := func(ids []permission.ID) string {
		return mustJSON(permission.NewSet(ids...).Strings())
	}
	if _, err := db.ExecContext(context.Background(),
		`UPDATE agents SET perm_supported=?, perm_granted=?, perm_effective=? WHERE id=?`,
		enc(supported), enc(granted), enc(effective), agentID); err != nil {
		t.Fatalf("set agent perms: %v", err)
	}
}

// seedEvidence freezes a signal's trigger-time evidence — the probe kind, the
// destination and the port the traceroute derivation reads. Subject evidence
// (resolver / STUN / proxy) is seeded by seedSubjectEvidence.
func seedEvidence(t *testing.T, db *store.DB, signalID, probeKind, targetAddr string, targetPort int, metricKind string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		UPDATE fault_signals SET probe_kind=?, target_addr=?, target_port=?, metric_kind=?, comparator='gt', threshold=0, value=1
		WHERE id=?`, probeKind, targetAddr, targetPort, metricKind, signalID); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
}

// TestWriteIncidentBaseDoesNotSelfDeadlockWithProductionSettings exercises the
// real server wiring shape: a non-nil settings service is consulted while
// the fault engine already owns the database's single write connection. Settings
// reads must use the read pool; using the write handle waits forever for the
// surrounding transaction to release its own connection.
func TestWriteIncidentBaseDoesNotSelfDeadlockWithProductionSettings(t *testing.T) {
	db, ctx := openIncidentOpsTest(t)
	now := time.Now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incidents(id,site_id,group_id,group_name,open_key,state,opened_at)
		VALUES('inc_deadlock','site_default','group','Group','alert:deadlock','open',?)`, now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed incident: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- New(db, nil, settings.New(db), nil).WriteIncidentBase(ctx, tx, "inc_deadlock", now)
	}()

	select {
	case err := <-done:
		_ = tx.Rollback()
		if err != nil {
			t.Fatalf("write incident base: %v", err)
		}
	case <-time.After(time.Second):
		_ = tx.Rollback()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("WriteIncidentBase deadlocked reading settings through the single write connection")
	}
}
