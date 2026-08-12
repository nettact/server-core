package fault

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/store"
)

// The engine's contract with the notification-policy layer, pinned from this
// side. The layer maintains aggregates over an incident (ALERT-001 storms), so
// it has to be told about EVERY change to that incident's severity — including
// the partial recovery that plans nothing and therefore looks, from the engine's
// point of view, like it needs no notification at all.

type spyPlanner struct {
	opened     []string
	escalated  []string
	resolved   []string
	recomputed []string
}

func (p *spyPlanner) PlanOpenTx(_ context.Context, _ store.Executor, sc IncidentScope, _ time.Time) error {
	p.opened = append(p.opened, sc.IncidentID)
	return nil
}

func (p *spyPlanner) EscalateTx(_ context.Context, _ store.Executor, sc IncidentScope, _ time.Time) error {
	p.escalated = append(p.escalated, sc.IncidentID)
	return nil
}

func (p *spyPlanner) ResolveTx(_ context.Context, _ store.Executor, incidentID, _ string, _ time.Time) error {
	p.resolved = append(p.resolved, incidentID)
	return nil
}

func (p *spyPlanner) RecomputeTx(_ context.Context, _ store.Executor, incidentID string, _ time.Time) error {
	p.recomputed = append(p.recomputed, incidentID)
	return nil
}

// mergedHarness gives the default group a merge policy and a second target, so
// one incident can hold two firing members — the shape a partial recovery needs.
func mergedHarness(t *testing.T) (*harness, *spyPlanner) {
	t.Helper()
	h := newHarness(t)
	p := &spyPlanner{}
	h.svc.SetPlanner(p)
	h.exec(`UPDATE monitor_groups SET merge_enabled=1 WHERE id='mg'`)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial)
		VALUES('t_icmp2','site_default','mg','icmp','Gateway','192.168.1.2','{}',1,1)`)
	return h, p
}

// twoTargetMeta is h.meta plus the second target.
func twoTargetMeta(h *harness, det DetectionSettings) map[string]TargetMeta {
	m := h.meta(det)
	m["t_icmp2"] = TargetMeta{ID: "t_icmp2", Kind: "icmp", GroupID: "mg", Name: "Gateway",
		Addr: "192.168.1.2", Enabled: true, ConfigSerial: 1, Det: det.Normalize()}
	return m
}

func loss2(ts int64, pct float64) telemetry.Metric {
	return telemetry.Metric{
		TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPLoss, Target: "192.168.1.2",
		Value: pct, Unit: telemetry.UnitPct, MonitorID: "t_icmp2", ConfigSerial: 1,
	}
}

func (h *harness) evaluateMeta(det DetectionSettings, ms ...telemetry.Metric) {
	h.t.Helper()
	rounds := BuildRounds(ms, twoTargetMeta(h, det))
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	if _, err := h.svc.EvaluateAgentTx(h.ctx, store.AdaptTx(tx, store.Standalone()), "agent_a", "site_default", rounds); err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("evaluate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
}

// TestPartialRecoveryNotifiesThePlanner is the wiring this pins: one member of a
// merged incident recovering while another still fires lowers the incident's
// severity but plans nothing, so the engine used to return without telling the
// policy layer at all. Anything that layer aggregates over the incident would
// then keep announcing a severity that had already gone away.
func TestPartialRecoveryNotifiesThePlanner(t *testing.T) {
	h, p := mergedHarness(t)
	det := DetectionSettings{FailRounds: 1, RecoverRounds: 1}

	// Both targets fail into ONE merged incident.
	h.evaluateMeta(det, loss(100, 100), loss2(100, 100))
	if len(p.opened) != 1 {
		t.Fatalf("opened %v, want exactly one merged incident", p.opened)
	}
	if n := h.countOpenIncidents(); n != 1 {
		t.Fatalf("open incidents = %d, want 1", n)
	}

	// One member recovers; the other keeps firing.
	h.evaluateMeta(det, loss2(200, 0))
	if len(p.resolved) != 0 {
		t.Fatalf("resolved %v — the incident is still open, nothing may be closed out", p.resolved)
	}
	if len(p.recomputed) != 1 {
		t.Fatalf("recomputed %v, want the policy layer told once about the partial recovery", p.recomputed)
	}

	// The last member recovers: now it is a real close-out, not a recompute.
	h.evaluateMeta(det, loss(300, 0))
	if len(p.resolved) != 1 {
		t.Fatalf("resolved %v, want exactly one close-out", p.resolved)
	}
}
