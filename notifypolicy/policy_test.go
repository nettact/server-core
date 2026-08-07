package notifypolicy

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// These tests pin the promises the notification layer makes to a user who is
// trying to trust their alarms: a fault that cleared inside its delay is never
// announced; a channel never receives a lone "recovered"; a configuration change
// is never dressed up as a recovery; and nothing is ever delivered twice, no
// matter how many times an event is replayed or the server restarts.

type capture struct {
	mu   sync.Mutex
	sent []delivered
}

type delivered struct {
	channels []string
	payload  notification.Payload
}

func (c *capture) Notify(_ context.Context, channels []string, p notification.Payload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, delivered{channels: append([]string(nil), channels...), payload: p})
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

func (c *capture) at(i int) delivered {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent[i]
}

type harness struct {
	t   *testing.T
	db  *store.DB
	svc *Service
	cap *capture
	ctx context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db := storetest.Open(t)
	cap := &capture{}
	h := &harness{t: t, db: db, cap: cap, svc: New(db, cap, settings.New(db), nil), ctx: context.Background()}
	h.exec(`INSERT INTO sites(id,name,created_at) VALUES('site_default','def',?)`, time.Now().UTC())
	h.exec(`INSERT INTO monitor_groups(id,site_id,name,is_default,merge_enabled,all_agents) VALUES('mg','site_default','Default',1,0,1)`)
	h.exec(`INSERT INTO probe_tasks(id,site_id,group_id,kind,name,target,params,enabled,config_serial) VALUES('t1','site_default','mg','icmp','Router','192.168.1.1','{}',1,1)`)
	h.exec(`INSERT INTO notification_channels(id,name,type,config,enabled) VALUES('ch_a','A','webhook','{"url":"http://x"}',1)`)
	h.exec(`INSERT INTO notification_channels(id,name,type,config,enabled) VALUES('ch_b','B','webhook','{"url":"http://y"}',1)`)
	if err := h.svc.EnsureBuiltins(h.ctx, "site_default"); err != nil {
		t.Fatalf("ensure builtins: %v", err)
	}
	return h
}

func (h *harness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(h.ctx, q, args...); err != nil {
		h.t.Fatalf("exec %q: %v", q, err)
	}
}

// setDefaultChannels points the site default policy at the given channels.
func (h *harness) setDefaultChannels(ids ...string) Policy {
	h.t.Helper()
	ps, err := h.svc.List(h.ctx, "site_default")
	if err != nil {
		h.t.Fatalf("list: %v", err)
	}
	var def Policy
	for _, p := range ps {
		if p.IsDefault {
			def = p
		}
	}
	def.ChannelIDs = ids
	out, err := h.svc.Update(h.ctx, def.ID, def)
	if err != nil {
		h.t.Fatalf("update default: %v", err)
	}
	return out
}

// agentPolicy returns the site's built-in Agent-connectivity policy.
// sitePolicy reads the site default policy — the one every incident falls back
// to when no narrower policy claims it.
func (h *harness) sitePolicy() Policy {
	h.t.Helper()
	p, err := h.svc.byScope(h.ctx, "site_default", ScopeSite, "")
	if err != nil {
		h.t.Fatalf("read site default policy: %v", err)
	}
	return p
}

func (h *harness) agentPolicy() Policy {
	h.t.Helper()
	p, err := h.svc.byScope(h.ctx, "site_default", ScopeAgent, "")
	if err != nil {
		h.t.Fatalf("read agent policy: %v", err)
	}
	return p
}

// enableAgentPolicy switches the Agent-connectivity policy on and points it at
// the given channels — the one action that separates Agent-offline routing from
// everything else.
func (h *harness) enableAgentPolicy(ids ...string) Policy {
	h.t.Helper()
	p := h.agentPolicy()
	p.Enabled = true
	p.ChannelIDs = ids
	out, err := h.svc.Update(h.ctx, p.ID, p)
	if err != nil {
		h.t.Fatalf("update agent policy: %v", err)
	}
	return out
}

// openAgentIncident opens an Agent-connectivity incident — no monitor group,
// fixed critical severity — and plans its notice exactly as the liveness
// detector does, AgentConnectivity flag included.
func (h *harness) openAgentIncident(id, agentID string, now time.Time) {
	h.t.Helper()
	h.exec(`INSERT INTO incidents(id,site_id,group_id,open_key,title,state,severity,opened_at)
		VALUES(?,'site_default','',?, 'Agent offline','open','critical',?)`, id, "agent:"+agentID, now)
	h.exec(`INSERT INTO fault_signals(id,site_id,agent_id,agent_name,target_id,detector_key,severity,state,
		reason_detail,observed_at,confirmed_at,incident_id)
		VALUES(?,'site_default',?,'node-1','','agent_connectivity','critical','firing',
		'unexpected',?,?,?)`, "sig_"+id, agentID, now.Add(-time.Minute), now, id)

	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	err = h.svc.PlanOpenTx(h.ctx, tx, fault.IncidentScope{
		IncidentID: id, SiteID: "site_default", Severity: "critical", AgentConnectivity: true,
	}, now)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("plan: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
}

// openIncident opens an incident with one firing member and plans its notice.
// The scope carries NO vantage point, so storm correlation is off — which is
// what almost every test here wants.
func (h *harness) openIncident(id, severity string, now time.Time) {
	h.t.Helper()
	h.openIncidentAs(id, severity, "", now)
}

// openIncidentAs is openIncident with the observing agent named, which is what
// makes the incident eligible for storm correlation.
func (h *harness) openIncidentAs(id, severity, vantageAgentID string, now time.Time) {
	h.t.Helper()
	h.exec(`INSERT INTO incidents(id,site_id,group_id,open_key,title,state,severity,opened_at)
		VALUES(?,'site_default','mg',?, 'Router unreachable','open',?,?)`, id, "sig:"+id, severity, now)
	// One firing signal per (agent, target, detector) is a hard invariant, so each
	// incident in a test gets its own target row.
	h.exec(`INSERT INTO fault_signals(id,site_id,agent_id,agent_name,target_id,target_name,target_addr,
		detector_key,probe_kind,metric_kind,comparator,threshold,value,severity,state,observed_at,confirmed_at,incident_id)
		VALUES(?,'site_default','agent_a','node-1',?, 'Router','192.168.1.1','availability','icmp',
		'probe.icmp.loss_pct','gte',100,100,?, 'firing',?,?,?)`,
		"sig_"+id, "t1_"+id, severity, now, now, id)

	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	err = h.svc.PlanOpenTx(h.ctx, tx, fault.IncidentScope{
		IncidentID: id, SiteID: "site_default", GroupID: "mg",
		AgentID: vantageAgentID, Severity: severity,
	}, now)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("plan: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
}

// resolveIncident closes an incident and its member with the given reason.
func (h *harness) resolveIncident(id, reason string, now time.Time) {
	h.t.Helper()
	h.exec(`UPDATE fault_signals SET state='resolved', resolved_at=?, resolve_reason=? WHERE incident_id=?`, now, reason, id)
	h.exec(`UPDATE incidents SET state='resolved', resolved_at=?, resolve_reason=? WHERE id=?`, now, reason, id)
	tx, err := h.db.BeginTx(h.ctx, nil)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	if err := h.svc.ResolveTx(h.ctx, tx, id, reason, now); err != nil {
		_ = tx.Rollback()
		h.t.Fatalf("resolve: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatalf("commit: %v", err)
	}
}

func (h *harness) deliveries(incidentID string) []Delivery {
	h.t.Helper()
	out, err := h.svc.ListForIncident(h.ctx, incidentID)
	if err != nil {
		h.t.Fatalf("list deliveries: %v", err)
	}
	return out
}

// TestNoChannelsRecordsButSendsNothing is the headline promise: detection and
// notification are independent, so a site with no channel configured still gets
// the full fault record and simply never hears about it.
func TestNoChannelsRecordsButSendsNothing(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)

	if got := h.deliveries("inc_1"); len(got) != 0 {
		t.Fatalf("a policy with no channels must plan nothing, got %+v", got)
	}
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 0 {
		t.Fatal("nothing may be sent when no channel is configured")
	}
	// The incident itself is untouched — that is the point.
	var state string
	if err := h.db.QueryRowContext(h.ctx, `SELECT state FROM incidents WHERE id='inc_1'`).Scan(&state); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	if state != "open" {
		t.Fatalf("incident state = %q, want open", state)
	}
}

// TestDelayHoldsThenSends: the default warn delay is five minutes, so nothing
// leaves before it expires and everything leaves once it has.
func TestDelayHoldsThenSends(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)

	ds := h.deliveries("inc_1")
	if len(ds) != 1 || ds[0].Status != statusPending {
		t.Fatalf("expected one pending delivery, got %+v", ds)
	}
	if !ds[0].DueAt.After(now.Add(4 * time.Minute)) {
		t.Fatalf("due_at = %v, want ~5 minutes out from %v", ds[0].DueAt, now)
	}
	// Not due yet.
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 0 {
		t.Fatal("a notification must not leave before its delay expires")
	}

	// Backdate the due time: this is exactly the state a server finds after being
	// down across the delay, and the first tick must deliver it.
	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE incident_id='inc_1'`, now.Add(-time.Second))
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 1 {
		t.Fatalf("expected one notification, got %d", h.cap.count())
	}
	d := h.cap.at(0)
	if len(d.channels) != 1 || d.channels[0] != "ch_a" {
		t.Fatalf("channels = %v, want [ch_a]", d.channels)
	}
	if d.payload.Event != "incident.opened" || len(d.payload.Details) != 1 {
		t.Fatalf("payload = %+v", d.payload)
	}
	if d.payload.Details[0].Target != "192.168.1.1" {
		t.Fatalf("payload detail lost the target: %+v", d.payload.Details[0])
	}
}

// TestRecoveryInsideDelaySendsNothing: the delay exists so a blip that fixes
// itself never reaches anyone. The fault is still recorded in full.
func TestRecoveryInsideDelaySendsNothing(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)
	h.resolveIncident("inc_1", fault.ReasonRecovered, now.Add(time.Minute))

	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 0 {
		t.Fatalf("a fault that recovered inside its delay must be silent, sent %d", h.cap.count())
	}
	ds := h.deliveries("inc_1")
	if len(ds) != 1 || ds[0].Status != statusCanceled {
		t.Fatalf("expected the pending open notice to be canceled, got %+v", ds)
	}
}

// TestRecoveryOnlyToChannelsThatHeardTheFault: no channel may receive a
// "recovered" for something it was never told about.
func TestRecoveryOnlyToChannelsThatHeardTheFault(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a", "ch_b")
	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)

	// Deliver the open notice to ch_a only; ch_b's row stays pending, as if it had
	// been added after the fact.
	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE incident_id='inc_1' AND channel_id='ch_a'`, now.Add(-time.Second))
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 1 {
		t.Fatalf("expected the open notice to reach one channel, got %d", h.cap.count())
	}

	h.resolveIncident("inc_1", fault.ReasonRecovered, now)
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 2 {
		t.Fatalf("expected exactly one recovery notice, sent %d total", h.cap.count())
	}
	rec := h.cap.at(1)
	if rec.payload.Event != "incident.resolved" {
		t.Fatalf("second notice = %q, want incident.resolved", rec.payload.Event)
	}
	if len(rec.channels) != 1 || rec.channels[0] != "ch_a" {
		t.Fatalf("recovery channels = %v, want only the channel that heard the fault", rec.channels)
	}
	if len(rec.payload.RecoveredTargets) != 1 || rec.payload.RecoveredTargets[0].Addr != "192.168.1.1" {
		t.Fatalf("recovery must name what came back: %+v", rec.payload.RecoveredTargets)
	}
}

// TestConfigurationTerminationSendsNoRecovery: deleting a failing monitor is not
// the monitor coming back, and must never be announced as one.
func TestConfigurationTerminationSendsNoRecovery(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)
	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE incident_id='inc_1'`, now.Add(-time.Second))
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 1 {
		t.Fatalf("expected the open notice, got %d", h.cap.count())
	}

	h.resolveIncident("inc_1", fault.ReasonTargetDeleted, now)
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 1 {
		t.Fatalf("a configuration termination must send nothing further, total sent %d", h.cap.count())
	}
}

// TestDeliveryIsIdempotentAcrossReplayAndRestart: replaying the open event and
// ticking repeatedly must still deliver exactly once. A duplicate alarm erodes
// trust in every future alarm.
func TestDeliveryIsIdempotentAcrossReplayAndRestart(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)

	// Replay the plan several times, as a redelivered event or a restart would.
	for i := 0; i < 3; i++ {
		tx, err := h.db.BeginTx(h.ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := h.svc.PlanOpenTx(h.ctx, tx, fault.IncidentScope{
			IncidentID: "inc_1", SiteID: "site_default", GroupID: "mg", Severity: "warn",
		}, now); err != nil {
			_ = tx.Rollback()
			t.Fatalf("replan: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	if got := len(h.deliveries("inc_1")); got != 1 {
		t.Fatalf("replayed planning created %d rows, want 1", got)
	}

	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE incident_id='inc_1'`, now.Add(-time.Second))
	for i := 0; i < 3; i++ {
		if err := h.svc.Tick(h.ctx); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
	if h.cap.count() != 1 {
		t.Fatalf("repeated ticks delivered %d times, want exactly 1", h.cap.count())
	}
}

// TestGroupPrecedenceIsSingleHit: exactly one policy applies, most specific
// first, so one incident can never reach the same channel through two matching
// policies.
func TestGroupPrecedenceIsSingleHit(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	if _, err := h.svc.Create(h.ctx, "site_default", Policy{
		Name: "group", ScopeKind: ScopeGroup, ScopeID: "mg", Enabled: true,
		MinSeverity: "warn", WarnDelaySec: 60, CriticalDelaySec: 10,
		NotifyRecovery: true, ChannelIDs: []string{"ch_b"},
	}); err != nil {
		t.Fatalf("create group policy: %v", err)
	}

	eff, err := h.svc.ResolveForTarget(h.ctx, "t1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if eff.Source != ScopeGroup || eff.Policy == nil || len(eff.Policy.ChannelIDs) != 1 || eff.Policy.ChannelIDs[0] != "ch_b" {
		t.Fatalf("group override must win over the site default: %+v", eff)
	}
	if len(eff.Chain) != 1 || eff.Chain[0] != ScopeGroup {
		t.Fatalf("resolved chain = %v, want [group]", eff.Chain)
	}

	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)
	ds := h.deliveries("inc_1")
	if len(ds) != 1 || ds[0].ChannelID != "ch_b" {
		t.Fatalf("planned deliveries = %+v, want exactly the group policy's channel", ds)
	}
}

func TestTargetPolicyScopeIsRejected(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Create(h.ctx, "site_default", Policy{
		Name: "target", ScopeKind: "target", ScopeID: "t1", Enabled: true,
		MinSeverity: "warn", ChannelIDs: []string{"ch_a"},
	}); err == nil {
		t.Fatal("target-scoped policy was accepted")
	}
	if _, err := h.db.ExecContext(h.ctx, `
		INSERT INTO notification_policies(id, site_id, name, scope_kind, scope_id)
		VALUES('np_target', 'site_default', 'target', 'target', 't1')`); err == nil {
		t.Fatal("database schema accepted a target-scoped policy")
	}
}

// TestDisabledOverrideFallsBack: turning off a group's override means "use the
// default", not "go quiet" — silence is expressed by an enabled policy with no
// channels, which says so explicitly.
func TestDisabledOverrideFallsBack(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	if _, err := h.svc.Create(h.ctx, "site_default", Policy{
		Name: "group", ScopeKind: ScopeGroup, ScopeID: "mg", Enabled: false,
		MinSeverity: "warn", WarnDelaySec: 60, CriticalDelaySec: 10, ChannelIDs: []string{"ch_b"},
	}); err != nil {
		t.Fatalf("create group policy: %v", err)
	}
	eff, err := h.svc.ResolveForTarget(h.ctx, "t1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if eff.Source != ScopeSite || eff.Policy == nil || eff.Policy.ChannelIDs[0] != "ch_a" {
		t.Fatalf("a disabled override must fall back to the site default: %+v", eff)
	}
	if len(eff.Chain) != 2 || eff.Chain[0] != ScopeGroup || eff.Chain[1] != ScopeSite {
		t.Fatalf("fallback chain = %v, want [group site]", eff.Chain)
	}
}

// TestSeverityFloorAndDelayTier: below the floor nothing is planned; a critical
// waits the short delay rather than the long one.
func TestSeverityFloorAndDelayTier(t *testing.T) {
	h := newHarness(t)
	def := h.setDefaultChannels("ch_a")
	def.MinSeverity = "critical"
	if _, err := h.svc.Update(h.ctx, def.ID, def); err != nil {
		t.Fatalf("raise floor: %v", err)
	}

	now := time.Now().UTC()
	h.openIncident("inc_warn", "warn", now)
	if got := len(h.deliveries("inc_warn")); got != 0 {
		t.Fatalf("a severity below the floor must plan nothing, got %d", got)
	}

	h.openIncident("inc_crit", "critical", now)
	ds := h.deliveries("inc_crit")
	if len(ds) != 1 {
		t.Fatalf("expected one planned delivery for critical, got %+v", ds)
	}
	if ds[0].DueAt.After(now.Add(2 * time.Minute)) {
		t.Fatalf("critical due_at = %v, want the short (1 minute) delay from %v", ds[0].DueAt, now)
	}
}

// TestDefaultPolicyIsUndeletable: every site must always have a policy to fall
// back to, or a target could end up governed by nothing at all.
func TestDefaultPolicyIsUndeletable(t *testing.T) {
	h := newHarness(t)
	ps, err := h.svc.List(h.ctx, "site_default")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var def Policy
	for _, p := range ps {
		if p.IsDefault {
			def = p
		}
	}
	if def.ID == "" {
		t.Fatal("expected a default policy to exist")
	}
	if def.WarnDelaySec != DefaultWarnDelaySec || def.CriticalDelaySec != DefaultCriticalDelaySec {
		t.Fatalf("default delays = %d/%d, want %d/%d", def.WarnDelaySec, def.CriticalDelaySec,
			DefaultWarnDelaySec, DefaultCriticalDelaySec)
	}
	if len(def.ChannelIDs) != 0 {
		t.Fatalf("a new site must not wire up outbound messaging on its own: %v", def.ChannelIDs)
	}
	if err := h.svc.Delete(h.ctx, def.ID); err == nil {
		t.Fatal("deleting the default policy must be refused")
	}

	// EnsureBuiltins is idempotent.
	if err := h.svc.EnsureBuiltins(h.ctx, "site_default"); err != nil {
		t.Fatalf("ensure builtins again: %v", err)
	}
	var n int
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT COUNT(*) FROM notification_policies WHERE site_id='site_default' AND is_default=1`).Scan(&n); err != nil {
		t.Fatalf("count defaults: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly one default policy, got %d", n)
	}
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT COUNT(*) FROM notification_policies WHERE site_id='site_default' AND scope_kind=?`,
		ScopeAgent).Scan(&n); err != nil {
		t.Fatalf("count agent policies: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly one Agent-connectivity policy, got %d", n)
	}
}

// TestOpenNoticeSkippedWhenIncidentAlreadyResolved covers the race where an
// incident resolves between the delay expiring and the worker running: it must
// not announce a fault that is already over.
func TestOpenNoticeSkippedWhenIncidentAlreadyResolved(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)
	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE incident_id='inc_1'`, now.Add(-time.Second))
	// Resolve the incident directly, without going through ResolveTx, to simulate
	// the delivery row surviving into a tick after the fault ended.
	h.exec(`UPDATE incidents SET state='resolved', resolved_at=? WHERE id='inc_1'`, now)

	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 0 {
		t.Fatal("must not announce a fault that already ended")
	}
	ds := h.deliveries("inc_1")
	if len(ds) != 1 || ds[0].Status != statusCanceled {
		t.Fatalf("expected the stale notice to be canceled, got %+v", ds)
	}
}

// TestAgentIncidentUsesAgentWording: an Agent-connectivity incident renders
// through the agent vocabulary, not the per-target one.
func TestAgentIncidentUsesAgentWording(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()
	h.openAgentIncident("inc_ag", "agent_a", now)
	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE incident_id='inc_ag'`, now.Add(-time.Second))
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 1 {
		t.Fatalf("expected one notification, got %d", h.cap.count())
	}
	p := h.cap.at(0).payload
	if p.Event != "agent.offline" || len(p.Agents) != 1 || p.Agents[0].Name != "node-1" {
		t.Fatalf("agent incident payload = %+v", p)
	}
	if p.Agents[0].Reason != "unexpected" {
		t.Fatalf("agent reason = %q, want unexpected", p.Agents[0].Reason)
	}
}

// TestAgentPolicyShipsDisabledSoRoutingIsUnchanged: the Agent-connectivity
// policy exists from the moment a site does, but until someone turns it on the
// site default governs Agent-offline faults exactly as it always did. A built-in
// row that silently started diverting notices to nobody would be worse than not
// having the feature.
func TestAgentPolicyShipsDisabledSoRoutingIsUnchanged(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	if p := h.agentPolicy(); p.Enabled || len(p.ChannelIDs) != 0 {
		t.Fatalf("the Agent policy must ship off and empty: %+v", p)
	}

	eff, err := h.svc.ResolveForAgentConnectivity(h.ctx, "site_default")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if eff.Source != ScopeSite || eff.Policy == nil || eff.Policy.ChannelIDs[0] != "ch_a" {
		t.Fatalf("a disabled Agent policy must fall back to the site default: %+v", eff)
	}
	if len(eff.Chain) != 2 || eff.Chain[0] != ScopeAgent || eff.Chain[1] != ScopeSite {
		t.Fatalf("fallback chain = %v, want [agent site]", eff.Chain)
	}

	now := time.Now().UTC()
	h.openAgentIncident("inc_ag", "agent_a", now)
	ds := h.deliveries("inc_ag")
	if len(ds) != 1 || ds[0].ChannelID != "ch_a" {
		t.Fatalf("planned deliveries = %+v, want the site default's channel", ds)
	}
}

// TestAgentPolicySeparatesOfflineRoutingFromProbeFaults is the point of the
// feature: an enabled Agent-connectivity policy governs Agent-offline faults and
// NOTHING else, so the two kinds of fault can reach different people with
// different delays.
func TestAgentPolicySeparatesOfflineRoutingFromProbeFaults(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	p := h.enableAgentPolicy("ch_b")
	p.CriticalDelaySec = 0
	if _, err := h.svc.Update(h.ctx, p.ID, p); err != nil {
		t.Fatalf("set agent delay: %v", err)
	}

	eff, err := h.svc.ResolveForAgentConnectivity(h.ctx, "site_default")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if eff.Source != ScopeAgent || len(eff.Chain) != 1 || eff.Chain[0] != ScopeAgent {
		t.Fatalf("the Agent policy must win outright: %+v", eff)
	}

	now := time.Now().UTC()
	h.openAgentIncident("inc_ag", "agent_a", now)
	ds := h.deliveries("inc_ag")
	if len(ds) != 1 || ds[0].ChannelID != "ch_b" {
		t.Fatalf("Agent-offline deliveries = %+v, want only the Agent policy's channel", ds)
	}
	if ds[0].DueAt.After(now) {
		t.Fatalf("Agent-offline due_at = %v, want the Agent policy's zero delay from %v", ds[0].DueAt, now)
	}

	// A probe fault in the same site is untouched by it.
	h.openIncident("inc_1", "critical", now)
	pd := h.deliveries("inc_1")
	if len(pd) != 1 || pd[0].ChannelID != "ch_a" {
		t.Fatalf("probe-fault deliveries = %+v, want the site default's channel", pd)
	}
}

// TestAgentPolicyWithNoChannelsIsExplicitSilence: "record Agent outages but stop
// paging me about them" must be expressible without switching the detector off
// (which would lose the fault history) and without touching the site default
// (which governs every probe fault too).
func TestAgentPolicyWithNoChannelsIsExplicitSilence(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	h.enableAgentPolicy()

	now := time.Now().UTC()
	h.openAgentIncident("inc_ag", "agent_a", now)
	if got := h.deliveries("inc_ag"); len(got) != 0 {
		t.Fatalf("an enabled Agent policy with no channels must plan nothing, got %+v", got)
	}
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if h.cap.count() != 0 {
		t.Fatalf("nothing may be sent, sent %d", h.cap.count())
	}
	// The fault itself is recorded in full — that is what makes this different
	// from turning the detector off.
	var state string
	if err := h.db.QueryRowContext(h.ctx, `SELECT state FROM incidents WHERE id='inc_ag'`).Scan(&state); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	if state != "open" {
		t.Fatalf("incident state = %q, want open", state)
	}
}

// TestAgentIncidentIsNeverSweptIntoAStorm guards the separation the Agent policy
// promises. An Agent that reconnects keeps its offline incident open through the
// recovery-confirmation window while it is already reporting probe results, so a
// storm forming in that window would otherwise find the offline incident (its
// signal carries the same agent_id) and swallow it — cancelling the notice the
// Agent policy planned and re-routing it through the other members' channels.
func TestAgentIncidentIsNeverSweptIntoAStorm(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	h.enableAgentPolicy("ch_b")
	// Correlate aggressively: two incidents in the window are a storm.
	h.exec(`INSERT INTO app_settings(key,value) VALUES(?,'2')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, settings.KeyIncidentStormThreshold)

	now := time.Now().UTC()
	h.openAgentIncident("inc_ag", "agent_a", now)
	// Two probe incidents observed by the SAME agent, enough to form a storm.
	// Without the exclusion the FIRST of them already reaches the threshold,
	// because the offline incident counts as the second member.
	h.openIncidentAs("inc_1", "critical", "agent_a", now)
	h.openIncidentAs("inc_2", "critical", "agent_a", now)

	var stormed sql.NullString
	if err := h.db.QueryRowContext(h.ctx, `SELECT storm_id FROM incidents WHERE id='inc_ag'`).Scan(&stormed); err != nil {
		t.Fatalf("read agent incident: %v", err)
	}
	if stormed.Valid {
		t.Fatalf("the Agent-offline incident was swept into storm %q", stormed.String)
	}
	// Its own notice is untouched: still pending, still on the Agent policy's channel.
	ds := h.deliveries("inc_ag")
	if len(ds) != 1 || ds[0].ChannelID != "ch_b" || ds[0].Status != statusPending {
		t.Fatalf("Agent-offline deliveries = %+v, want one pending row on ch_b", ds)
	}
	// The probe incidents did correlate, so the test is proving exclusion rather
	// than that no storm was possible in the first place.
	var storms int
	if err := h.db.QueryRowContext(h.ctx, `SELECT COUNT(*) FROM alert_storms`).Scan(&storms); err != nil {
		t.Fatalf("count storms: %v", err)
	}
	if storms != 1 {
		t.Fatalf("expected the probe incidents to form one storm, got %d", storms)
	}
}

// TestEnsureBuiltinsToleratesAConcurrentFirstRead: two requests hitting the
// notification-policy page before the built-ins exist both see them missing. The
// loser of that race must be a no-op, not a unique-constraint 500.
func TestEnsureBuiltinsToleratesAConcurrentFirstRead(t *testing.T) {
	h := newHarness(t)
	h.exec(`DELETE FROM notification_policies WHERE site_id='site_default'`)

	const racers = 4
	errs := make(chan error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			errs <- h.svc.EnsureBuiltins(context.Background(), "site_default")
		}()
	}
	close(start)
	for i := 0; i < racers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent EnsureBuiltins: %v", err)
		}
	}

	var n int
	if err := h.db.QueryRowContext(h.ctx,
		`SELECT COUNT(*) FROM notification_policies WHERE site_id='site_default'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected exactly the two built-in policies, got %d", n)
	}
}

// TestAgentPolicyIsUndeletable: the resolver expects to find it, and disabling
// is the supported way to go back to the site default.
func TestAgentPolicyIsUndeletable(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.Delete(h.ctx, h.agentPolicy().ID); !errors.Is(err, ErrUndeletablePolicy) {
		t.Fatalf("delete agent policy = %v, want ErrUndeletablePolicy", err)
	}
	if _, err := h.svc.Create(h.ctx, "site_default", Policy{
		Name: "second", ScopeKind: ScopeAgent, Enabled: true, MinSeverity: "warn",
	}); err == nil {
		t.Fatal("a second Agent-connectivity policy was accepted")
	}
}

// TestScopedPolicyDeletionFallsBackToDefault: removing a group override must
// leave the target governed by the site default, never by nothing.
func TestScopedPolicyDeletionFallsBackToDefault(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	p, err := h.svc.Create(h.ctx, "site_default", Policy{
		Name: "group", ScopeKind: ScopeGroup, ScopeID: "mg", Enabled: true,
		MinSeverity: "warn", WarnDelaySec: 30, CriticalDelaySec: 5, ChannelIDs: []string{"ch_b"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := h.svc.Delete(h.ctx, p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	eff, err := h.svc.ResolveForTarget(h.ctx, "t1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if eff.Source != ScopeSite {
		t.Fatalf("expected fallback to the site default, got %+v", eff)
	}
	if _, err := h.svc.Get(h.ctx, p.ID); err == nil {
		t.Fatal("deleted policy still readable")
	}
	var missing sql.NullString
	_ = h.db.QueryRowContext(h.ctx, `SELECT id FROM notification_policies WHERE id=?`, p.ID).Scan(&missing)
	if missing.Valid {
		t.Fatal("deleted policy row survived")
	}
}

// TestNothingIsClaimedWithoutDispatch pins the ordering contract: every step that
// can fail WITHOUT having sent anything runs before the at-most-once claim.
// Claiming first would mark a row sent that was never attempted — and because
// ResolveTx reads a sent open row as "this channel heard about the fault", that
// channel would later be handed a recovery notice for a fault it never received.
//
// A cancelled context is the reachable version of that failure: it is exactly
// what a graceful shutdown does to the tick loop mid-pass.
func TestNothingIsClaimedWithoutDispatch(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")
	now := time.Now().UTC()
	h.openIncident("inc_1", "warn", now)
	h.exec(`UPDATE notification_deliveries SET due_at=? WHERE incident_id='inc_1'`, now.Add(-time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.svc.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("tick: %v", err)
	}

	var status string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT status FROM notification_deliveries WHERE incident_id='inc_1'`).Scan(&status); err != nil {
		t.Fatalf("read delivery: %v", err)
	}
	if status == statusSent && h.cap.count() == 0 {
		t.Fatal("a delivery was marked sent but never dispatched — nothing will ever retry it")
	}
	if status == statusPending && h.cap.count() != 0 {
		t.Fatal("a delivery was dispatched without being claimed — a restart would send it again")
	}

	// Whatever the cancelled pass did, a healthy pass afterwards must still deliver
	// exactly once: the row was either left pending (sent now) or already sent.
	before := h.cap.count()
	if err := h.svc.Tick(h.ctx); err != nil {
		t.Fatalf("recovery tick: %v", err)
	}
	if total := h.cap.count(); total != 1 {
		t.Fatalf("total dispatches = %d (before=%d), want exactly 1", total, before)
	}
}

// TestAttachChannelToBuiltinsChecksBothAndOnlyThem: a newly created channel is
// checked into the site default AND the Agent-connectivity policy, and into
// nothing else. The Agent one matters even though it ships disabled — an
// operator who later switches it on must not find it pointing at no channels.
func TestAttachChannelToBuiltinsChecksBothAndOnlyThem(t *testing.T) {
	h := newHarness(t)
	override, err := h.svc.Create(h.ctx, "site_default", Policy{
		Name: "group override", ScopeKind: ScopeGroup, ScopeID: "mg",
		Enabled: true, MinSeverity: "warn",
	})
	if err != nil {
		t.Fatalf("create override: %v", err)
	}

	if err := h.svc.AttachChannelToBuiltins(h.ctx, "site_default", "ch_a"); err != nil {
		t.Fatalf("attach: %v", err)
	}

	if got := h.sitePolicy().ChannelIDs; !slices.Equal(got, []string{"ch_a"}) {
		t.Fatalf("site default channels = %v, want [ch_a]", got)
	}
	if got := h.agentPolicy().ChannelIDs; !slices.Equal(got, []string{"ch_a"}) {
		t.Fatalf("agent policy channels = %v, want [ch_a]", got)
	}
	// A group override is a deliberate narrowing; widening it back would undo the
	// operator's decision.
	after, err := h.svc.Get(h.ctx, override.ID)
	if err != nil {
		t.Fatalf("get override: %v", err)
	}
	if len(after.ChannelIDs) != 0 {
		t.Fatalf("group override channels = %v, want none touched", after.ChannelIDs)
	}
}

// TestAttachChannelToBuiltinsAppendsWithoutDuplicating: attaching keeps whatever
// the operator already chose, and attaching the same channel twice (a retried
// create) does not list it twice — a duplicate would deliver the same incident
// to the same channel twice.
func TestAttachChannelToBuiltinsAppendsWithoutDuplicating(t *testing.T) {
	h := newHarness(t)
	h.setDefaultChannels("ch_a")

	for range 2 {
		if err := h.svc.AttachChannelToBuiltins(h.ctx, "site_default", "ch_b"); err != nil {
			t.Fatalf("attach: %v", err)
		}
	}

	if got := h.sitePolicy().ChannelIDs; !slices.Equal(got, []string{"ch_a", "ch_b"}) {
		t.Fatalf("site default channels = %v, want [ch_a ch_b]", got)
	}
	if got := h.agentPolicy().ChannelIDs; !slices.Equal(got, []string{"ch_b"}) {
		t.Fatalf("agent policy channels = %v, want [ch_b]", got)
	}
}
