package agentstatus

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// seedOverloadEvent inserts one agent-reported probe-overload event.
func seedOverloadEvent(t *testing.T, db *store.DB, id, agentID string, ts time.Time, attrs string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO events(id,agent_id,site_id,ts,type,layer,severity,message,attrs)
		VALUES(?,?,'site_default',?,?,'local','warn','probe concurrency limit reached',?)`,
		id, agentID, ts, string(telemetry.EventProbeOverload), attrs)
}

// The overload notice exists to explain a silence: probes the budget refused
// leave no sample, so their monitors go stale exactly as they would if the
// network had gone away. The console can only tell the two apart if the agent's
// own report reaches it.
func TestProbeOverloadSurfacesOnTheAgent(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	now := time.Now().UTC()
	seedAgent(t, db, "agent_busy", "online", &now)
	seedAgent(t, db, "agent_idle", "online", &now)
	seedOverloadEvent(t, db, "ev1", "agent_busy", now.Add(-time.Minute),
		`{"abandoned":"37","window_s":"300","limit":"16"}`)

	got, err := New(db, nil, settings.New(db)).SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}

	busy := find(got.Agents, "agent_busy").ProbeOverload
	if busy == nil {
		t.Fatal("the reporting agent carries no overload notice")
	}
	if busy.Skipped != 37 || busy.Window != 300 || busy.Limit != 16 {
		t.Errorf("overload = %+v, want skipped 37 / window 300 / limit 16", busy)
	}
	if find(got.Agents, "agent_idle").ProbeOverload != nil {
		t.Error("an agent that reported nothing carries an overload notice")
	}
}

// Only the most recent report is carried: the condition is a standing one, not a
// history. Reporting an older count would understate a worsening agent.
func TestProbeOverloadKeepsTheLatestReport(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	now := time.Now().UTC()
	seedAgent(t, db, "agent_busy", "online", &now)
	seedOverloadEvent(t, db, "old", "agent_busy", now.Add(-10*time.Minute),
		`{"abandoned":"4","window_s":"300","limit":"16"}`)
	seedOverloadEvent(t, db, "new", "agent_busy", now.Add(-time.Minute),
		`{"abandoned":"52","window_s":"300","limit":"16"}`)

	got, err := New(db, nil, settings.New(db)).SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	po := find(got.Agents, "agent_busy").ProbeOverload
	if po == nil || po.Skipped != 52 {
		t.Fatalf("overload = %+v, want the latest report (52 skipped)", po)
	}
}

// The notice has to go away on its own once the agent stops reporting, or it
// accuses a healthy agent for the rest of the day — and an operator who raised
// the limit gets no confirmation that it worked.
func TestProbeOverloadExpires(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	now := time.Now().UTC()
	seedAgent(t, db, "agent_recovered", "online", &now)
	seedOverloadEvent(t, db, "stale", "agent_recovered", now.Add(-probeOverloadFreshFor-time.Minute),
		`{"abandoned":"9","window_s":"300","limit":"16"}`)

	got, err := New(db, nil, settings.New(db)).SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	if po := find(got.Agents, "agent_recovered").ProbeOverload; po != nil {
		t.Fatalf("a report older than the freshness window still shows: %+v", po)
	}
}

// A payload the agent could not fill, or one that arrives malformed, must not
// cost the whole notice — the console renders what it got.
func TestProbeOverloadToleratesPartialAttributes(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	now := time.Now().UTC()
	seedAgent(t, db, "agent_partial", "online", &now)
	seedOverloadEvent(t, db, "ev1", "agent_partial", now.Add(-time.Minute), `{"abandoned":"7"}`)

	got, err := New(db, nil, settings.New(db)).SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	po := find(got.Agents, "agent_partial").ProbeOverload
	if po == nil || po.Skipped != 7 {
		t.Fatalf("overload = %+v, want the count that WAS reported", po)
	}
	if po.Window != 0 || po.Limit != 0 {
		t.Errorf("overload = %+v, want zero for the attributes that were absent", po)
	}
}

// Other event types share the table and must not be mistaken for an overload.
func TestProbeOverloadIgnoresOtherEvents(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	now := time.Now().UTC()
	seedAgent(t, db, "agent_a", "online", &now)
	mustExec(t, db, `INSERT INTO events(id,agent_id,site_id,ts,type,layer,severity,message,attrs)
		VALUES('ev1','agent_a','site_default',?,?,'lan','warn','gateway down','{}')`,
		now.Add(-time.Minute), string(telemetry.EventGatewayUnreachable))

	got, err := New(db, nil, settings.New(db)).SiteAgentStatuses(ctx, "site_default")
	if err != nil {
		t.Fatalf("SiteAgentStatuses: %v", err)
	}
	if po := find(got.Agents, "agent_a").ProbeOverload; po != nil {
		t.Fatalf("an unrelated event was read as an overload: %+v", po)
	}
}
