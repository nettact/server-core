// Package opissue is the operational-issue engine for the agent local-permission
// policy. It turns "a monitor is not running" into a deduplicated, operator-facing
// list (operational_issues) plus a per-(agent, monitor) status view
// (monitor_status). Inputs come from three places:
//
//   - the agent's wire.MonitorStatus frames (probe monitors), via ApplyMonitorStatus;
//   - server-side host-metric evaluation (host monitors), via ReevaluateHostMonitors;
//   - a save-time prediction of probe monitors, via PredictProbeMonitors.
//
// Scope narrowing / disabling is reconciled by ReconcileScope. Every mutation
// follows commit-then-publish: DB work in one transaction, then a single
// TopicIssueChanged per affected site so the SSE broker refreshes connected
// consoles. Issues are deliberately kept OUT of alert/incident evaluation — they
// describe why telemetry is absent, not a telemetry threshold breach.
package opissue

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/fault"
	"github.com/nettact/server-core/store"
)

const categoryMonitor = "monitor"

// Service owns the operational-issue tables and publishes change notifications.
type Service struct {
	db  *store.DB
	bus *eventbus.Bus
}

// New constructs the service. bus may be nil in tests (change notifications are
// then simply not published).
func New(db *store.DB, bus *eventbus.Bus) *Service {
	return &Service{db: db, bus: bus}
}

// Remediation is the actionable fix rendered next to an issue or a denied
// snapshot scope. permission_blocked yields a full NETTACT_AGENT_PERMISSIONS line
// (granted ∪ missing, closed over dependencies); unsupported yields no env line
// (the build/platform cannot do it); target_blocked yields only the matched
// selector (the resolved private address is never leaked — the agent decides what
// the selector reveals).
type Remediation struct {
	Reason          string `json:"reason"`
	PermissionsEnv  string `json:"permissions_env,omitempty"`
	MatchedSelector string `json:"matched_selector,omitempty"`
}

// Remediate builds the remediation object for a blocked reason. granted and
// missing are wire permission strings; matchedSelector is only used for
// target_blocked.
func Remediate(reason string, missing, granted []string, matchedSelector string) *Remediation {
	rem := &Remediation{Reason: reason}
	switch reason {
	case wire.MonitorStatusPermissionBlocked:
		set := permission.FromStrings(granted)
		for _, id := range permission.FromStrings(missing).Sorted() {
			set.Add(id)
		}
		rem.PermissionsEnv = "NETTACT_AGENT_PERMISSIONS=" + strings.Join(permission.Closure(set).Strings(), ",")
	case wire.MonitorStatusTargetBlocked:
		rem.MatchedSelector = matchedSelector
	case wire.MonitorStatusUnsupported:
		// No env line: the build/platform does not support it, so no policy change helps.
	}
	return rem
}

// Issue is one operational issue enriched with display + remediation fields.
type Issue struct {
	ID          string `json:"id"`
	SiteID      string `json:"site_id"`
	AgentID     string `json:"agent_id"`
	AgentName   string `json:"agent_name"`
	Category    string `json:"category"`
	RefID       string `json:"ref_id"`
	MonitorName string `json:"monitor_name"`
	Reason      string `json:"reason"`
	// DetailReason is the agent's specific cause behind Reason (proxy_missing,
	// literal_denied, method_requires_extended…). Empty for a server-evaluated host
	// monitor, whose status is the whole story.
	DetailReason       string       `json:"detail_reason,omitempty"`
	MissingPermissions []string     `json:"missing_permissions"`
	MatchedSelector    string       `json:"matched_selector"`
	PolicyHash         string       `json:"policy_hash"`
	State              string       `json:"state"`
	Read               bool         `json:"read"`
	Count              int          `json:"count"`
	FirstSeenAt        time.Time    `json:"first_seen_at"`
	LastSeenAt         time.Time    `json:"last_seen_at"`
	ResolvedAt         *time.Time   `json:"resolved_at"`
	Remediation        *Remediation `json:"remediation,omitempty"`
}

// MonitorStatusRow is one row of the per-(agent, monitor) status view.
type MonitorStatusRow struct {
	AgentID            string   `json:"agent_id"`
	AgentName          string   `json:"agent_name,omitempty"`
	MonitorID          string   `json:"monitor_id"`
	MonitorName        string   `json:"monitor_name,omitempty"`
	Kind               string   `json:"kind,omitempty"`
	Target             string   `json:"target,omitempty"`
	Status             string   `json:"status"`
	MissingPermissions []string `json:"missing_permissions"`
	MatchedSelector    string   `json:"matched_selector,omitempty"`
	Reason             string   `json:"reason,omitempty"`
	PolicyHash         string   `json:"policy_hash,omitempty"`
	ConfigVersion      int      `json:"config_version"`
	// Provenance: whether this row is an agent-confirmed report or a server-side
	// prediction, and which target material generation it attests, so a caller can
	// tell predicted capability from confirmed execution and detect a row still on
	// an obsolete generation. EffectiveIntervalSeconds/CycleDeadlineMs are the
	// agent's reported effective schedule; UploadIntervalSeconds is its frame-level
	// WAL batch-upload cadence (all nil on predicted rows / unset host rows).
	Source                   string    `json:"source"`
	TargetConfigSerial       int       `json:"target_config_serial"`
	EffectiveIntervalSeconds *int      `json:"effective_interval_seconds,omitempty"`
	CycleDeadlineMs          *int      `json:"cycle_deadline_ms,omitempty"`
	UploadIntervalSeconds    *int      `json:"upload_interval_seconds,omitempty"`
	UpdatedAt                time.Time `json:"updated_at"`
}

// SaveWarning is a monitor-save pre-check finding: a monitor that some (or all)
// in-scope agents cannot run under their current permission policy. It carries
// both the aggregate counts and the per-agent breakdown so the UI can name the
// capable and blocked agents independently (acceptance criterion 8).
type SaveWarning struct {
	MonitorID          string             `json:"monitor_id"`
	MonitorName        string             `json:"monitor_name"`
	Status             string             `json:"status"` // worst: permission_blocked | unsupported
	AffectedAgents     int                `json:"affected_agents"`
	CapableAgents      int                `json:"capable_agents"`
	MissingPermissions []string           `json:"missing_permissions"`
	BlockedAgents      []SaveWarningAgent `json:"blocked_agents"`
	// CapableAgentList names the in-scope agents that CAN run the monitor, so the UI
	// can present capable and blocked agents independently rather than only a count.
	CapableAgentList []SaveWarningAgent `json:"capable_agent_list"`
}

// SaveWarningAgent is one agent within a SaveWarning: its identity, its block
// status (active when capable), and the permissions it is missing (empty when
// capable).
type SaveWarningAgent struct {
	AgentID            string   `json:"agent_id"`
	AgentName          string   `json:"agent_name"`
	Status             string   `json:"status"` // active | permission_blocked | unsupported
	MissingPermissions []string `json:"missing_permissions"`
}

// ---- ingestion: agent-reported probe monitor status ----

// ApplyMonitorStatus ingests one MonitorStatus frame (the agent's full-state view
// of its probe monitors for a given config_version) and reconciles monitor_status
// rows + operational_issues. The monotonic guard drops a frame whose
// config_version is older than either the newest already accepted or the server's
// current desired config_version for the agent; equal versions are accepted so a
// runtime target-policy transition, or a policy-changing restart with unchanged
// DesiredState, is still recorded.
func (s *Service) ApplyMonitorStatus(ctx context.Context, agentID, siteID string, ms wire.MonitorStatus) error {
	return s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		tx := wtx

		var lastAccepted, desired int
		err := tx.QueryRowContext(ctx,
			`SELECT a.last_status_config_version, COALESCE(st.config_serial,0)
			 FROM agents a JOIN sites st ON st.id = a.site_id WHERE a.id=?`, agentID).
			Scan(&lastAccepted, &desired)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil // agent gone; nothing to reconcile
			}
			return nil, err
		}
		// Monotonic guard: reject stale frames (older than what we accepted or than
		// the desired site config serial we last pushed). Equal is valid.
		if ms.ConfigVersion < lastAccepted || ms.ConfigVersion < desired {
			return nil, nil
		}

		// Only monitors that are enabled and in this agent's scope are valid targets; a
		// stale or misbehaving agent must not create status/issues for monitors it was
		// never assigned. The map value is each monitor's current material generation.
		valid, err := s.probeMonitorSerials(ctx, tx, siteID, agentID)
		if err != nil {
			return nil, err
		}

		now := time.Now().UTC()
		changed := false
		var statusChanged []string // monitor ids whose monitor_status row changed
		current := make([]string, 0, len(ms.Statuses))
		blocked := map[string]bool{} // dedupe_keys reported blocked this frame
		seen := map[string]bool{}    // monitor ids already handled this frame (reject dupes)

		for _, e := range ms.Statuses {
			serial, ok := valid[e.MonitorID]
			if !ok || seen[e.MonitorID] || !validMonitorStatus(e.Status) {
				// Unknown/out-of-scope monitor, a duplicate id, or a non-enum status: ignore
				// rather than mutating status/issues on untrusted input.
				continue
			}
			seen[e.MonitorID] = true
			// The monitor is in scope and named in this frame, so its row is retained
			// (not deleted as absent) regardless of the per-target generation check below.
			current = append(current, e.MonitorID)
			// Exact per-target generation echo: an entry attesting a generation other
			// than the target's current one (stale — the agent has not applied the
			// target's latest material change — or a forged future) is ignored, leaving
			// the row's current state untouched, while the frame's other entries still
			// apply and the whole-frame monotonic guard still governs frame ordering.
			if e.TargetConfigSerial != serial {
				continue
			}
			wrote, err := upsertMonitorStatus(ctx, tx, agentID, e.MonitorID, e.Status,
				e.MissingPermissions, e.MatchedSelector, e.Reason, ms.PolicyHash, ms.ConfigVersion,
				serial, nullPosInt(e.EffectiveIntervalSeconds), nullPosInt(e.CycleDeadlineMs),
				nullPosInt(ms.UploadIntervalSeconds), now)
			if err != nil {
				return nil, err
			}
			if wrote {
				statusChanged = append(statusChanged, e.MonitorID)
			}
			if e.Status == wire.MonitorStatusActive {
				continue
			}
			key := dedupeKey(agentID, categoryMonitor, e.MonitorID, e.Status, e.Reason)
			blocked[key] = true
			wasTransition, err := s.upsertIssue(ctx, tx, issueUpsert{
				siteID: siteID, agentID: agentID, refID: e.MonitorID, reason: e.Status,
				detailReason: e.Reason,
				dedupeKey:    key, missing: e.MissingPermissions, matchedSelector: e.MatchedSelector,
				policyHash: ms.PolicyHash, now: now,
			})
			if err != nil {
				return nil, err
			}
			changed = changed || wasTransition
		}

		// Delete this agent's PROBE monitor_status rows absent from the frame; host
		// rows are owned by ReevaluateHostMonitors and never touched here.
		deleted, err := deleteAbsentProbeStatus(ctx, tx, agentID, current)
		if err != nil {
			return nil, err
		}
		statusChanged = append(statusChanged, deleted...)

		// Resolve any active PROBE issue for this agent whose exact reason is no longer
		// reported (recovered, or transitioned to a different block reason).
		resolvedAny, err := s.resolveIssuesNotIn(ctx, tx,
			`SELECT oi.id, oi.dedupe_key FROM operational_issues oi
			   JOIN probe_tasks pt ON pt.id = oi.ref_id
			  WHERE oi.agent_id=? AND oi.category=? AND oi.state='active' AND pt.kind<>'host'`,
			[]any{agentID, categoryMonitor}, blocked, now)
		if err != nil {
			return nil, err
		}
		changed = changed || resolvedAny

		// The upload cadence rides the same frame and is recorded here as well as on
		// the per-monitor rows: it describes the whole outbox, and an agent whose only
		// subject is a host anchor sends a frame with no entries, so the per-monitor
		// rows would carry no cadence at all. A frame that omits it (0) leaves the
		// last known value standing rather than resetting to the default.
		if _, err := tx.ExecContext(ctx,
			`UPDATE agents SET last_status_config_version=?,
			        upload_interval_seconds=CASE WHEN ?>0 THEN ? ELSE upload_interval_seconds END
			 WHERE id=?`,
			ms.ConfigVersion, ms.UploadIntervalSeconds, ms.UploadIntervalSeconds, agentID); err != nil {
			return nil, err
		}
		return func() {
			s.publish(changed, siteID)
			s.publishStatus(siteID, statusChanged)
		}, nil
	})
}

// ---- server-side host monitor evaluation ----

// ReevaluateHostMonitors recomputes permission blocks for the agent's in-scope
// host monitors: for each host probe_task, the required host permissions are the
// union of permission.RequiredForHostMetric over its ENABLED bound alert rules,
// closed over dependencies, compared against the agent's stored effective set. A
// host monitor with no bound rules requires nothing and is active. Called after a
// Hello refreshes the agent's permission policy.
func (s *Service) ReevaluateHostMonitors(ctx context.Context, agentID string) error {
	var siteID, effStr, supStr, grantStr, policyHash string
	var configVersion int
	err := s.db.QueryRowContext(ctx,
		`SELECT a.site_id, COALESCE(st.config_serial,0), COALESCE(a.perm_effective,'[]'), COALESCE(a.perm_supported,'[]'), COALESCE(a.perm_granted,'[]'), COALESCE(a.policy_hash,'')
		 FROM agents a JOIN sites st ON st.id = a.site_id WHERE a.id=?`, agentID).
		Scan(&siteID, &configVersion, &effStr, &supStr, &grantStr, &policyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	effective := permission.FromStrings(decodeStrings(effStr))
	supported := permission.FromStrings(decodeStrings(supStr))
	granted := permission.FromStrings(decodeStrings(grantStr))

	rows, err := s.db.QueryContext(ctx, `
		SELECT pt.id, pt.config_serial FROM probe_tasks pt
		 WHERE pt.site_id=? AND pt.enabled=1 AND pt.kind='host' AND `+config.AgentScopePredicate,
		siteID, agentID)
	if err != nil {
		return err
	}
	type hostMon struct {
		id           string
		configSerial int
	}
	var hostMons []hostMon
	for rows.Next() {
		var hm hostMon
		if err := rows.Scan(&hm.id, &hm.configSerial); err != nil {
			rows.Close()
			return err
		}
		hostMons = append(hostMons, hm)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	return s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		tx := wtx
		now := time.Now().UTC()
		changed := false
		var statusChanged []string
		for _, hm := range hostMons {
			monitorID := hm.id
			required, err := hostRequired(ctx, tx, monitorID)
			if err != nil {
				return nil, err
			}
			// Classify like the agent (monitoreval.evaluate): a required permission that
			// is granted but not platform-supported is `unsupported`; one that is not
			// granted (or otherwise not effective) is `permission_blocked`. A locally
			// denied permission takes precedence over an unsupported one.
			var missing, unsupported []string
			for _, id := range diff(required, effective) {
				if granted.Has(id) && !supported.Has(id) {
					unsupported = append(unsupported, string(id))
				} else {
					missing = append(missing, string(id))
				}
			}

			status := wire.MonitorStatusActive
			var reasonList []string
			switch {
			case len(missing) > 0:
				status = wire.MonitorStatusPermissionBlocked
				reasonList = missing
			case len(unsupported) > 0:
				status = wire.MonitorStatusUnsupported
				reasonList = unsupported
			}

			// Host rows are server-authoritative reports at the target's own generation;
			// they carry no agent-reported effective schedule or upload cadence.
			wrote, err := upsertMonitorStatus(ctx, tx, agentID, monitorID, status,
				reasonList, "", "", policyHash, configVersion, hm.configSerial,
				sql.NullInt64{}, sql.NullInt64{}, sql.NullInt64{}, now)
			if err != nil {
				return nil, err
			}
			if wrote {
				statusChanged = append(statusChanged, monitorID)
			}
			if status == wire.MonitorStatusActive {
				// Resolve any active issue for this pair regardless of prior reason.
				resolved, err := s.resolveMonitorIssuesExcept(ctx, tx, agentID, monitorID, "", now)
				if err != nil {
					return nil, err
				}
				changed = changed || resolved
				continue
			}
			wasTransition, err := s.upsertIssue(ctx, tx, issueUpsert{
				siteID: siteID, agentID: agentID, refID: monitorID, reason: status,
				// A host monitor is evaluated server-side, so there is no agent-reported detail
				// reason to carry — the status is the whole story.
				dedupeKey: dedupeKey(agentID, categoryMonitor, monitorID, status, ""),
				missing:   reasonList, policyHash: policyHash, now: now,
			})
			if err != nil {
				return nil, err
			}
			changed = changed || wasTransition
			// If the monitor flipped between block reasons (e.g. permission_blocked →
			// unsupported), resolve the stale issue of the other reason.
			resolved, err := s.resolveMonitorIssuesExcept(ctx, tx, agentID, monitorID, status, now)
			if err != nil {
				return nil, err
			}
			changed = changed || resolved
		}
		return func() {
			s.publish(changed, siteID)
			s.publishStatus(siteID, statusChanged)
		}, nil
	})
}

// ReevaluateHostMonitorsForSite reevaluates host monitors for every non-revoked
// agent in the site. It is called wherever a host monitor, its bound rules, or an
// agent's group scope changes — none of which arrive via an agent frame, so the
// server must recompute the affected pairs immediately rather than wait for a
// reconnect.
func (s *Service) ReevaluateHostMonitorsForSite(ctx context.Context, siteID string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM agents WHERE site_id=? AND revoked=0`, siteID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.ReevaluateHostMonitors(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// hostRequired returns the closure of host permissions a host monitor requires:
// the union over the metric families its system-status detection has switched on.
//
// It has to be derived from the thresholds rather than fixed, because a host
// anchor requires nothing in particular by itself. An anchor watching only disk
// has no business raising a permission issue about an Agent that withholds its
// temperature sensors, and an anchor watching CPU that cannot read CPU must not
// sit green and silent while nothing evaluates. A missing settings row means the
// zero-config defaults, so the requirement is computed the same way whether or
// not anyone ever opened the form. All families off requires nothing, which
// leaves the anchor unconditionally active.
func hostRequired(ctx context.Context, tx store.Executor, monitorID string) (permission.Set, error) {
	def := fault.DefaultHostSettings()
	cpuOn, memOn, loadOn, netOn, diskOn := def.CPUEnabled, def.MemEnabled, def.LoadEnabled, def.NetEnabled, def.DiskEnabled
	var cpu, mem, load, net, disk int
	err := tx.QueryRowContext(ctx, `
		SELECT cpu_enabled, mem_enabled, load_enabled, net_enabled, disk_enabled
		FROM host_detection_settings WHERE target_id=?`, monitorID).
		Scan(&cpu, &mem, &load, &net, &disk)
	switch {
	case errors.Is(err, sql.ErrNoRows): // never configured: the defaults apply
	case err != nil:
		return permission.Set{}, err
	default:
		cpuOn, memOn, loadOn = cpu != 0, mem != 0, load != 0
		netOn, diskOn = net != 0, disk != 0
	}

	var ids []permission.ID
	// One representative kind per family; RequiredForHostMetric maps by prefix, so
	// naming the family's primary series names the whole family's permission.
	// Load asks only for the load permission: the core count it divides by rides
	// along under either the cpu or the load grant, by construction on the agent.
	for _, f := range []struct {
		on   bool
		kind telemetry.MetricKind
	}{
		{cpuOn, telemetry.HostCPUPct},
		{memOn, telemetry.HostMemPct},
		{loadOn, telemetry.HostLoad1},
		{netOn, telemetry.HostNetRxBps},
		{diskOn, telemetry.HostDiskPct},
	} {
		if f.on {
			ids = append(ids, permission.RequiredForHostMetric(string(f.kind))...)
		}
	}
	if len(ids) == 0 {
		return permission.Set{}, nil
	}
	return permission.Closure(permission.NewSet(ids...)), nil
}

// ---- scope reconciliation ----

// ReconcileScope resolves issues and drops monitor_status rows for monitors that
// are now disabled or out of an agent's group/site scope, even while the agent is
// offline (deletion of a monitor is handled separately by FK ON DELETE CASCADE).
// Call it wherever monitoring scope mutates — the same sites that call
// alert.Service.ResolveOutOfScope.
func (s *Service) ReconcileScope(ctx context.Context, siteID string) error {
	// Correlated NOT-in-scope predicate: a monitor_status row is stranded when its
	// monitor is disabled, or the row's agent is not covered by the monitor group's
	// Agent scope (group broadcasts, or the agent is in one of its agent groups).
	// Correlated on ms.agent_id (so it is NOT the shared single-placeholder
	// config.AgentScopePredicate).
	rows, err := s.db.QueryContext(ctx, `
		SELECT ms.agent_id, ms.monitor_id FROM monitor_status ms
		  JOIN probe_tasks pt ON pt.id = ms.monitor_id
		 WHERE pt.site_id=? AND (pt.enabled=0 OR NOT EXISTS(
		    SELECT 1 FROM monitor_groups mg
		    WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
		        SELECT 1 FROM monitor_group_agent_groups mgag
		        JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
		        WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = ms.agent_id))))`, siteID)
	if err != nil {
		return err
	}
	type row struct{ agentID, monitorID string }
	var stranded []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.agentID, &r.monitorID); err != nil {
			rows.Close()
			return err
		}
		stranded = append(stranded, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(stranded) == 0 {
		return nil
	}

	return s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		tx := wtx
		now := time.Now().UTC()
		changed := false
		statusChanged := make([]string, 0, len(stranded))
		for _, r := range stranded {
			res, err := tx.ExecContext(ctx,
				`DELETE FROM monitor_status WHERE agent_id=? AND monitor_id=?`, r.agentID, r.monitorID)
			if err != nil {
				return nil, err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				statusChanged = append(statusChanged, r.monitorID)
			}
			// Clear this pair's detector counters as it leaves scope. The target stops
			// being evaluated for the agent once out of scope, so a retained failing streak
			// would resume counting if the pair later re-enters scope without a material
			// target edit (the generation, and thus its samples/series, are unchanged).
			// Recorded fault signals are immutable history and untouched; this is live
			// detector state only.
			res, err = tx.ExecContext(ctx,
				`DELETE FROM detector_state WHERE agent_id=? AND target_id=?`, r.agentID, r.monitorID)
			if err != nil {
				return nil, err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				statusChanged = append(statusChanged, r.monitorID)
			}
			res, err = tx.ExecContext(ctx,
				`UPDATE operational_issues SET state='resolved', resolved_at=?
				  WHERE agent_id=? AND category=? AND ref_id=? AND state='active'`,
				now, r.agentID, categoryMonitor, r.monitorID)
			if err != nil {
				return nil, err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				changed = true
			}
		}
		return func() {
			s.publish(changed, siteID)
			s.publishStatus(siteID, statusChanged)
		}, nil
	})
}

// ---- monitor-save prediction ----

// PredictProbeMonitors upserts predicted monitor_status rows for every in-scope
// agent of every enabled probe monitor in the site, using each agent's stored
// permission policy, and returns per-monitor warnings for monitors that some or
// all in-scope agents cannot run. It is a save-and-warn pass: it never blocks the
// save, and the agent's real MonitorStatus frame later overwrites the prediction.
func (s *Service) PredictProbeMonitors(ctx context.Context, siteID string) ([]SaveWarning, error) {
	var siteSerial int
	if err := s.db.QueryRowContext(ctx, `SELECT config_serial FROM sites WHERE id=?`, siteID).Scan(&siteSerial); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, COALESCE(name,''), COALESCE(target,''), COALESCE(params,''), config_serial FROM probe_tasks
		  WHERE site_id=? AND kind<>'host' AND enabled=1`, siteID)
	if err != nil {
		return nil, err
	}
	type predTarget struct {
		id           string
		configSerial int
		pt           pcfg.ProbeTarget
	}
	var targets []predTarget
	for rows.Next() {
		var t predTarget
		var params string
		if err := rows.Scan(&t.id, &t.pt.Kind, &t.pt.Name, &t.pt.Target, &params, &t.configSerial); err != nil {
			rows.Close()
			return nil, err
		}
		if params != "" {
			_ = json.Unmarshal([]byte(params), &t.pt.Params)
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	var warnings []SaveWarning
	var statusChanged []string
	if err := s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		tx := wtx
		for _, t := range targets {
			required := permission.Closure(permission.NewSet(permission.RequiredForTarget(t.pt)...))
			agents, err := scopedAgents(ctx, tx, siteID, t.id)
			if err != nil {
				return nil, err
			}
			capable, affected := 0, 0
			worst := ""
			missingUnion := permission.Set{}
			var blockedAgents, capableAgents []SaveWarningAgent
			for _, a := range agents {
				status, reasonList := classifyMonitor(required, a.effective, a.granted, a.supported)
				if status == wire.MonitorStatusActive {
					capable++
					capableAgents = append(capableAgents, SaveWarningAgent{
						AgentID: a.id, AgentName: a.name, Status: status,
					})
				} else {
					affected++
					for _, id := range reasonList {
						missingUnion.Add(id)
					}
					if worst == "" || status == wire.MonitorStatusUnsupported {
						worst = status
					}
					blockedAgents = append(blockedAgents, SaveWarningAgent{
						AgentID: a.id, AgentName: a.name, Status: status,
						MissingPermissions: setStrings(reasonList),
					})
				}
				// The predicted row attests the target's own generation (t.configSerial);
				// the whole-site watermark advances via siteSerial.
				wrote, err := upsertPredictedStatus(ctx, tx, a.id, t.id, status,
					setStrings(reasonList), a.policyHash, siteSerial, t.configSerial, now)
				if err != nil {
					return nil, err
				}
				if wrote {
					statusChanged = append(statusChanged, t.id)
				}
			}
			if affected > 0 || len(agents) == 0 {
				if worst == "" {
					worst = wire.MonitorStatusPermissionBlocked
				}
				warnings = append(warnings, SaveWarning{
					MonitorID: t.id, MonitorName: monitorLabel(t.pt.Name, t.pt.Target),
					Status: worst, AffectedAgents: affected, CapableAgents: capable,
					MissingPermissions: missingUnion.Strings(),
					BlockedAgents:      blockedAgents,
					CapableAgentList:   capableAgents,
				})
			}
		}
		return func() {
			s.publishStatus(siteID, statusChanged)
		}, nil
	}); err != nil {
		return nil, err
	}
	return warnings, nil
}

type scopedAgent struct {
	id         string
	name       string
	effective  permission.Set
	granted    permission.Set
	supported  permission.Set
	policyHash string
}

// scopedAgents returns the non-revoked agents in a monitor's scope, with their
// stored permission policy, for prediction.
func scopedAgents(ctx context.Context, tx store.Executor, siteID, monitorID string) ([]scopedAgent, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), a.id),
		       COALESCE(a.perm_effective,'[]'), COALESCE(a.perm_granted,'[]'), COALESCE(a.perm_supported,'[]'), COALESCE(a.policy_hash,'')
		FROM agents a, probe_tasks pt
		WHERE pt.id=? AND a.site_id=? AND a.revoked=0 AND EXISTS(
		    SELECT 1 FROM monitor_groups mg
		    WHERE mg.id = pt.group_id AND (mg.all_agents=1 OR EXISTS(
		        SELECT 1 FROM monitor_group_agent_groups mgag
		        JOIN agent_group_members agm ON agm.group_id = mgag.agent_group_id
		        WHERE mgag.monitor_group_id = mg.id AND agm.agent_id = a.id)))`, monitorID, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scopedAgent
	for rows.Next() {
		var a scopedAgent
		var eff, grant, sup string
		if err := rows.Scan(&a.id, &a.name, &eff, &grant, &sup, &a.policyHash); err != nil {
			return nil, err
		}
		a.effective = permission.FromStrings(decodeStrings(eff))
		a.granted = permission.FromStrings(decodeStrings(grant))
		a.supported = permission.FromStrings(decodeStrings(sup))
		out = append(out, a)
	}
	return out, rows.Err()
}

// classifyMonitor classifies a monitor for an agent's stored permission policy
// exactly like the agent (monitoreval / ReevaluateHostMonitors): a required
// permission that is granted but not platform-supported is `unsupported`; one
// that is not granted (or otherwise not effective) is `permission_blocked` and
// remedied by an environment grant. A locally denied permission takes precedence
// over an unsupported one. Returns the worst status and the permission ids that
// caused it (nil when active).
func classifyMonitor(required, effective, granted, supported permission.Set) (string, []permission.ID) {
	var missBlocked, missUnsupported []permission.ID
	for _, id := range diff(required, effective) {
		if granted.Has(id) && !supported.Has(id) {
			missUnsupported = append(missUnsupported, id)
		} else {
			missBlocked = append(missBlocked, id)
		}
	}
	switch {
	case len(missBlocked) > 0:
		return wire.MonitorStatusPermissionBlocked, missBlocked
	case len(missUnsupported) > 0:
		return wire.MonitorStatusUnsupported, missUnsupported
	default:
		return wire.MonitorStatusActive, nil
	}
}

// PredictProbeMonitorsForAgent upserts predicted monitor_status rows for every
// enabled probe monitor currently in ONE agent's scope, using the agent's stored
// permission policy, so a newly enrolled/reconnected agent's applicable pairs
// promptly have rows (predicted) with assigned_at = now. The generation-keyed
// predicted upsert leaves same-generation reported rows untouched, so re-running
// it on every hello never resets a confirmed pair. Silent no-op when the agent is
// gone.
func (s *Service) PredictProbeMonitorsForAgent(ctx context.Context, agentID string) error {
	var siteID, effStr, supStr, grantStr, policyHash string
	var siteSerial int
	err := s.db.QueryRowContext(ctx, `
		SELECT a.site_id, COALESCE(st.config_serial,0), COALESCE(a.perm_effective,'[]'),
		       COALESCE(a.perm_supported,'[]'), COALESCE(a.perm_granted,'[]'), COALESCE(a.policy_hash,'')
		FROM agents a JOIN sites st ON st.id = a.site_id WHERE a.id=?`, agentID).
		Scan(&siteID, &siteSerial, &effStr, &supStr, &grantStr, &policyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	effective := permission.FromStrings(decodeStrings(effStr))
	supported := permission.FromStrings(decodeStrings(supStr))
	granted := permission.FromStrings(decodeStrings(grantStr))

	rows, err := s.db.QueryContext(ctx, `
		SELECT pt.id, pt.kind, COALESCE(pt.name,''), COALESCE(pt.target,''), COALESCE(pt.params,''), pt.config_serial
		FROM probe_tasks pt
		WHERE pt.site_id=? AND pt.enabled=1 AND pt.kind<>'host' AND `+config.AgentScopePredicate,
		siteID, agentID)
	if err != nil {
		return err
	}
	type predTarget struct {
		id           string
		configSerial int
		pt           pcfg.ProbeTarget
	}
	var targets []predTarget
	for rows.Next() {
		var t predTarget
		var params string
		if err := rows.Scan(&t.id, &t.pt.Kind, &t.pt.Name, &t.pt.Target, &params, &t.configSerial); err != nil {
			rows.Close()
			return err
		}
		if params != "" {
			_ = json.Unmarshal([]byte(params), &t.pt.Params)
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}

	return s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		tx := wtx
		now := time.Now().UTC()
		var statusChanged []string
		for _, t := range targets {
			required := permission.Closure(permission.NewSet(permission.RequiredForTarget(t.pt)...))
			status, reasonList := classifyMonitor(required, effective, granted, supported)
			wrote, err := upsertPredictedStatus(ctx, tx, agentID, t.id, status,
				setStrings(reasonList), policyHash, siteSerial, t.configSerial, now)
			if err != nil {
				return nil, err
			}
			if wrote {
				statusChanged = append(statusChanged, t.id)
			}
		}
		return func() {
			s.publishStatus(siteID, statusChanged)
		}, nil
	})
}

// ---- read side ----

// List returns the site's active operational issues, newest first, each with a
// remediation object.
func (s *Service) List(ctx context.Context, siteID string) ([]Issue, error) {
	return s.queryIssues(ctx,
		`WHERE oi.site_id=? AND oi.state='active' ORDER BY oi.last_seen_at DESC`, siteID)
}

// ListForConsole returns the site's active issues plus the most recently resolved
// ones so a connected console can show a resolution (the requirement that
// resolution is also visible), not just have the row vanish. Active issues sort
// first (newest by last_seen), then resolved (newest by resolved_at), bounded so
// the history cannot grow without limit.
func (s *Service) ListForConsole(ctx context.Context, siteID string) ([]Issue, error) {
	return s.queryIssues(ctx,
		`WHERE oi.site_id=? AND (oi.state='active' OR oi.resolved_at IS NOT NULL)
		 ORDER BY CASE WHEN oi.state='active' THEN 0 ELSE 1 END,
		          COALESCE(oi.resolved_at, oi.last_seen_at) DESC
		 LIMIT 200`, siteID)
}

// ListForAgent returns an agent's active operational issues, newest first.
func (s *Service) ListForAgent(ctx context.Context, agentID string) ([]Issue, error) {
	return s.queryIssues(ctx,
		`WHERE oi.agent_id=? AND oi.state='active' ORDER BY oi.last_seen_at DESC`, agentID)
}

func (s *Service) queryIssues(ctx context.Context, where string, args ...any) ([]Issue, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT oi.id, oi.site_id, oi.agent_id,
		       COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), oi.agent_id),
		       oi.category, COALESCE(oi.ref_id,''),
		       COALESCE(NULLIF(pt.name,''), COALESCE(pt.target,''), ''),
		       oi.reason, oi.detail_reason, oi.missing_permissions, oi.matched_selector, oi.policy_hash,
		       oi.state, oi.read, oi.count, oi.first_seen_at, oi.last_seen_at, oi.resolved_at,
		       COALESCE(a.perm_granted,'[]')
		FROM operational_issues oi
		LEFT JOIN agents a ON a.id = oi.agent_id
		LEFT JOIN probe_tasks pt ON pt.id = oi.ref_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Issue
	for rows.Next() {
		var i Issue
		var missing, granted string
		var read int
		var resolvedAt sql.NullTime
		if err := rows.Scan(&i.ID, &i.SiteID, &i.AgentID, &i.AgentName, &i.Category, &i.RefID,
			&i.MonitorName, &i.Reason, &i.DetailReason, &missing, &i.MatchedSelector, &i.PolicyHash,
			&i.State, &read, &i.Count, &i.FirstSeenAt, &i.LastSeenAt, &resolvedAt, &granted); err != nil {
			return nil, err
		}
		i.MissingPermissions = decodeStrings(missing)
		i.Read = read == 1
		if resolvedAt.Valid {
			t := resolvedAt.Time
			i.ResolvedAt = &t
		}
		i.Remediation = Remediate(i.Reason, i.MissingPermissions, decodeStrings(granted), i.MatchedSelector)
		out = append(out, i)
	}
	return out, rows.Err()
}

// UnreadCount returns the number of active, unread issues for a site.
func (s *Service) UnreadCount(ctx context.Context, siteID string) (int, error) {
	var n int
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM operational_issues WHERE site_id=? AND state='active' AND read=0`, siteID).Scan(&n)
	return n, err
}

// MarkRead marks the given active issues read (all active issues of the site when
// ids is empty) and publishes a change so consoles refresh their unread badge.
func (s *Service) MarkRead(ctx context.Context, siteID string, ids []string) error {
	var res sql.Result
	var err error
	if len(ids) == 0 {
		res, err = s.db.ExecContext(ctx,
			`UPDATE operational_issues SET read=1 WHERE site_id=? AND state='active' AND read=0`, siteID)
	} else {
		q := `UPDATE operational_issues SET read=1 WHERE site_id=? AND state='active' AND read=0 AND id IN (` +
			placeholders(len(ids)) + `)`
		args := make([]any, 0, len(ids)+1)
		args = append(args, siteID)
		for _, id := range ids {
			args = append(args, id)
		}
		res, err = s.db.ExecContext(ctx, q, args...)
	}
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	s.publish(n > 0, siteID)
	return nil
}

// AgentStatuses returns the per-monitor status rows for one agent.
func (s *Service) AgentStatuses(ctx context.Context, agentID string) ([]MonitorStatusRow, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT ms.agent_id, ms.monitor_id, COALESCE(pt.name,''), COALESCE(pt.kind,''), COALESCE(pt.target,''),
		       ms.status, ms.missing_permissions, ms.matched_selector, ms.reason, ms.policy_hash, ms.config_version,
		       ms.source, ms.target_config_serial, ms.effective_interval_seconds, ms.cycle_deadline_ms,
		       ms.upload_interval_seconds, ms.updated_at
		FROM monitor_status ms LEFT JOIN probe_tasks pt ON pt.id = ms.monitor_id
		WHERE ms.agent_id=? ORDER BY pt.kind, pt.target`, agentID)
	if err != nil {
		return nil, err
	}
	return scanMonitorRows(rows)
}

func scanMonitorRows(rows *sql.Rows) ([]MonitorStatusRow, error) {
	defer rows.Close()
	var out []MonitorStatusRow
	for rows.Next() {
		var m MonitorStatusRow
		var missing string
		var effIv, cycleMs, uploadIv sql.NullInt64
		if err := rows.Scan(&m.AgentID, &m.MonitorID, &m.MonitorName, &m.Kind, &m.Target, &m.Status,
			&missing, &m.MatchedSelector, &m.Reason, &m.PolicyHash, &m.ConfigVersion,
			&m.Source, &m.TargetConfigSerial, &effIv, &cycleMs, &uploadIv, &m.UpdatedAt); err != nil {
			return nil, err
		}
		m.MissingPermissions = decodeStrings(missing)
		if effIv.Valid {
			v := int(effIv.Int64)
			m.EffectiveIntervalSeconds = &v
		}
		if cycleMs.Valid {
			v := int(cycleMs.Int64)
			m.CycleDeadlineMs = &v
		}
		if uploadIv.Valid {
			v := int(uploadIv.Int64)
			m.UploadIntervalSeconds = &v
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- shared write helpers ----

type issueUpsert struct {
	siteID, agentID, refID, reason, dedupeKey string
	// detailReason is the agent's specific cause behind the coarse status (proxy_missing,
	// literal_denied, method_requires_extended…). Stored so the issues list can say what
	// to fix instead of only naming the status class.
	detailReason                string
	missing                     []string
	matchedSelector, policyHash string
	now                         time.Time
}

// upsertIssue inserts or refreshes a blocked issue and reports whether this was a
// real transition (a newly created issue, or a resolved→active reactivation) — a
// pure repeat report of an already-active issue only bumps count/last_seen and is
// not treated as a change.
func (s *Service) upsertIssue(ctx context.Context, tx store.Executor, u issueUpsert) (bool, error) {
	var prevState string
	err := tx.QueryRowContext(ctx,
		`SELECT state FROM operational_issues WHERE dedupe_key=?`, u.dedupeKey).Scan(&prevState)
	transition := err == sql.ErrNoRows || prevState == "resolved"
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO operational_issues(id, site_id, agent_id, category, ref_id, reason, detail_reason,
		                               dedupe_key, missing_permissions, matched_selector, policy_hash,
		                               state, read, count, first_seen_at, last_seen_at, resolved_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?, 'active', 0, 1, ?, ?, NULL)
		ON CONFLICT(dedupe_key) DO UPDATE SET
		  count = count + 1,
		  last_seen_at = excluded.last_seen_at,
		  state = 'active',
		  read = CASE WHEN operational_issues.state='resolved' THEN 0 ELSE operational_issues.read END,
		  missing_permissions = excluded.missing_permissions,
		  matched_selector = excluded.matched_selector,
		  detail_reason = excluded.detail_reason,
		  policy_hash = excluded.policy_hash,
		  resolved_at = NULL`,
		"issue_"+uuid.NewString(), u.siteID, u.agentID, categoryMonitor, u.refID, u.reason, u.detailReason,
		u.dedupeKey, marshalStrings(u.missing), u.matchedSelector, u.policyHash, u.now, u.now)
	return transition, err
}

// resolveMonitorIssuesExcept resolves every active issue for (agent, monitor)
// whose reason differs from keepReason (pass "" to resolve all reasons, e.g. when
// the monitor is now active). Reports whether any row changed.
func (s *Service) resolveMonitorIssuesExcept(ctx context.Context, tx store.Executor, agentID, monitorID, keepReason string, now time.Time) (bool, error) {
	res, err := tx.ExecContext(ctx,
		`UPDATE operational_issues SET state='resolved', resolved_at=?
		  WHERE agent_id=? AND category=? AND ref_id=? AND state='active' AND reason<>?`,
		now, agentID, categoryMonitor, monitorID, keepReason)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// resolveIssuesNotIn resolves every active issue matched by selectSQL whose
// dedupe_key is not in keep, reporting whether any row changed.
func (s *Service) resolveIssuesNotIn(ctx context.Context, tx store.Executor, selectSQL string, args []any, keep map[string]bool, now time.Time) (bool, error) {
	rows, err := tx.QueryContext(ctx, selectSQL, args...)
	if err != nil {
		return false, err
	}
	type cand struct{ id, key string }
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.key); err != nil {
			rows.Close()
			return false, err
		}
		cands = append(cands, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	changed := false
	for _, c := range cands {
		if keep[c.key] {
			continue
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE operational_issues SET state='resolved', resolved_at=? WHERE id=? AND state='active'`, now, c.id)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			changed = true
		}
	}
	return changed, nil
}

// upsertMonitorStatus writes an authoritative REPORTED status (agent-confirmed
// probe entry, or server-evaluated host row) at the target's generation. A
// matching report always overrides prior predicted state. assigned_at is reset
// only when this report attests a newer target generation than the stored row;
// otherwise it is preserved so the pending clock is not restarted. Reports whether
// a row was written (always true for a matching call — a report is a change).
func upsertMonitorStatus(ctx context.Context, tx store.Executor, agentID, monitorID, status string,
	missing []string, matchedSelector, reason, policyHash string, configVersion, targetConfigSerial int,
	effInterval, cycleDeadline, uploadInterval sql.NullInt64, now time.Time) (bool, error) {
	res, err := tx.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id, monitor_id, status, missing_permissions, matched_selector,
		                           reason, policy_hash, config_version, source, target_config_serial,
		                           assigned_at, effective_interval_seconds, cycle_deadline_ms,
		                           upload_interval_seconds, updated_at)
		VALUES(?,?,?,?,?,?,?,?, 'reported', ?, ?, ?, ?, ?, ?)
		ON CONFLICT(agent_id, monitor_id) DO UPDATE SET
		  status=excluded.status, missing_permissions=excluded.missing_permissions,
		  matched_selector=excluded.matched_selector, reason=excluded.reason,
		  policy_hash=excluded.policy_hash, config_version=excluded.config_version,
		  source='reported', target_config_serial=excluded.target_config_serial,
		  assigned_at=CASE WHEN excluded.target_config_serial > monitor_status.target_config_serial
		                   THEN excluded.updated_at ELSE monitor_status.assigned_at END,
		  effective_interval_seconds=excluded.effective_interval_seconds,
		  cycle_deadline_ms=excluded.cycle_deadline_ms,
		  upload_interval_seconds=excluded.upload_interval_seconds, updated_at=excluded.updated_at`,
		agentID, monitorID, status, marshalStrings(missing), matchedSelector, reason, policyHash,
		configVersion, targetConfigSerial, now, effInterval, cycleDeadline, uploadInterval, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// upsertPredictedStatus writes a save-time / hello-time predicted status keyed to
// the target's generation. It replaces any older-generation row (reported or
// predicted) and refreshes a same-generation predicted row, but a same-generation
// REPORTED row fails the WHERE and is left untouched (an agent-confirmed status is
// never overwritten by a prediction). assigned_at is only reset when the target
// generation advances, so repeated predictions for the same pending generation
// preserve the grace clock while the whole-site watermark may advance.
func upsertPredictedStatus(ctx context.Context, tx store.Executor, agentID, monitorID, status string,
	missing []string, policyHash string, configVersion, targetConfigSerial int, now time.Time) (bool, error) {
	res, err := tx.ExecContext(ctx, `
		INSERT INTO monitor_status(agent_id, monitor_id, status, missing_permissions, matched_selector,
		    reason, policy_hash, config_version, target_config_serial, source, assigned_at,
		    effective_interval_seconds, cycle_deadline_ms, upload_interval_seconds, updated_at)
		VALUES(?,?,?,?, '','', ?, ?, ?, 'predicted', ?, NULL, NULL, NULL, ?)
		ON CONFLICT(agent_id, monitor_id) DO UPDATE SET
		  status=excluded.status, missing_permissions=excluded.missing_permissions,
		  matched_selector='', reason='', policy_hash=excluded.policy_hash,
		  config_version=excluded.config_version,
		  target_config_serial=excluded.target_config_serial,
		  source='predicted',
		  assigned_at=CASE WHEN excluded.target_config_serial > monitor_status.target_config_serial
		                   THEN excluded.assigned_at ELSE monitor_status.assigned_at END,
		  effective_interval_seconds=NULL, cycle_deadline_ms=NULL, upload_interval_seconds=NULL,
		  updated_at=excluded.updated_at
		WHERE monitor_status.target_config_serial < excluded.target_config_serial
		   OR (monitor_status.target_config_serial = excluded.target_config_serial
		       AND monitor_status.source = 'predicted')`,
		agentID, monitorID, status, marshalStrings(missing), policyHash, configVersion, targetConfigSerial, now, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// nullPosInt maps a non-positive int (unset) to SQL NULL and a positive value to
// a valid integer — used for the agent's reported effective schedule fields.
func nullPosInt(v int) sql.NullInt64 {
	if v > 0 {
		return sql.NullInt64{Int64: int64(v), Valid: true}
	}
	return sql.NullInt64{}
}

func deleteAbsentProbeStatus(ctx context.Context, tx store.Executor, agentID string, keep []string) ([]string, error) {
	sel := `SELECT monitor_id FROM monitor_status WHERE agent_id=?
		AND monitor_id IN (SELECT id FROM probe_tasks WHERE kind<>'host')`
	args := []any{agentID}
	if len(keep) > 0 {
		sel += ` AND monitor_id NOT IN (` + placeholders(len(keep)) + `)`
		for _, id := range keep {
			args = append(args, id)
		}
	}
	rows, err := tx.QueryContext(ctx, sel, args...)
	if err != nil {
		return nil, err
	}
	var deleted []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		deleted = append(deleted, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(deleted) == 0 {
		return nil, nil
	}
	delArgs := make([]any, len(deleted))
	for i, id := range deleted {
		delArgs[i] = id
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM monitor_status WHERE agent_id=? AND monitor_id IN (`+placeholders(len(deleted))+`)`,
		append([]any{agentID}, delArgs...)...); err != nil {
		return nil, err
	}
	return deleted, nil
}

func (s *Service) probeMonitorSerials(ctx context.Context, tx store.Executor, siteID, agentID string) (map[string]int, error) {
	// Only enabled, non-host monitors currently in THIS agent's server-owned scope
	// are valid targets for an agent-reported status. An agent must not be able to
	// create status/issues for a monitor it was never assigned (or a disabled one).
	// The value is each monitor's current material generation, used to validate the
	// agent's echoed target_config_serial exactly.
	rows, err := tx.QueryContext(ctx,
		`SELECT pt.id, pt.config_serial FROM probe_tasks pt WHERE pt.site_id=? AND pt.kind<>'host' AND pt.enabled=1 AND `+config.AgentScopePredicate,
		siteID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var serial int
		if err := rows.Scan(&id, &serial); err != nil {
			return nil, err
		}
		out[id] = serial
	}
	return out, rows.Err()
}

func (s *Service) publish(changed bool, siteID string) {
	if changed && s.bus != nil {
		s.bus.Publish(eventbus.TopicIssueChanged, eventbus.IssueChanged{SiteID: siteID})
	}
}

// publishStatus emits one precise TopicTargetStatusChanged over the monitor ids
// whose execution-dimension rows changed (upserted or deleted) this commit. Empty
// sets publish nothing. Distinct from publish (TopicIssueChanged drives the
// operational-issue console; this drives authoritative target status).
func (s *Service) publishStatus(siteID string, monitorIDs []string) {
	if s.bus == nil {
		return
	}
	seen := make(map[string]bool, len(monitorIDs))
	ids := make([]string, 0, len(monitorIDs))
	for _, id := range monitorIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return
	}
	s.bus.Publish(eventbus.TopicTargetStatusChanged, eventbus.TargetStatusChanged{SiteID: siteID, TargetIDs: ids})
}

// ---- small utilities ----

// dedupeKey identifies one operational issue. detailReason participates so a monitor
// whose CAUSE changes — proxy_missing becoming proxy_unsupported after a proxy type
// edit — surfaces as a new issue rather than silently mutating the existing row's
// text, and so the previous cause is resolved rather than left active.
func dedupeKey(agentID, category, refID, reason, detailReason string) string {
	return agentID + "|" + category + "|" + refID + "|" + reason + "|" + detailReason
}

// validMonitorStatus reports whether s is a known agent-reportable monitor status
// (agent_offline / probe_failed are server/console-derived and never agent-sent).
func validMonitorStatus(s string) bool {
	switch s {
	case wire.MonitorStatusActive, wire.MonitorStatusPermissionBlocked,
		wire.MonitorStatusTargetBlocked, wire.MonitorStatusUnsupported:
		return true
	}
	return false
}

func decodeStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func marshalStrings(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

// setStrings returns the wire strings for an ID slice in canonical order.
func setStrings(ids []permission.ID) []string {
	return permission.NewSet(ids...).Strings()
}

// diff returns required \ have as a sorted ID slice.
func diff(required, have permission.Set) []permission.ID {
	var out []permission.ID
	for _, id := range required.Sorted() {
		if !have.Has(id) {
			out = append(out, id)
		}
	}
	return out
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func monitorLabel(name, target string) string {
	if name != "" {
		return name
	}
	return target
}
