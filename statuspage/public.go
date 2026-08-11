package statuspage

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nettact/server-core/agentstatus"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/targetstatus"
)

// ---- public DTOs ----
//
// These are the anonymous wire contract. They are defined as their own structs
// rather than reusing the console's rows precisely so that adding a field to
// AgentStatusRow or TargetStatus can never publish it by accident: anything that
// reaches the outside has to be written down here on purpose.

// PublicPage is the page's own description — enough to render a header and decide
// which lists to request. It carries no ids and no site.
type PublicPage struct {
	Slug              string    `json:"slug"`
	Title             string    `json:"title"`
	Description       string    `json:"description,omitempty"`
	ShowAgentView     bool      `json:"show_agent_view"`
	ShowTargetView    bool      `json:"show_target_view"`
	ShowIncidents     bool      `json:"show_incidents"`
	ShowTargetAddress bool      `json:"show_target_address"`
	GeneratedAt       time.Time `json:"generated_at"`
}

// PublicAgentRow is one published agent. Name is the operator-set display name
// and is empty when unset — the hostname is NEVER substituted, because a hostname
// is exactly the kind of internal detail publishing an availability figure should
// not also disclose. An unnamed agent is rendered from Ordinal instead.
type PublicAgentRow struct {
	Name        string     `json:"name"`
	Ordinal     int        `json:"ordinal"`
	Online      bool       `json:"online"`
	StatusSince *time.Time `json:"status_since,omitempty"`
	// Resources is present only when the page's agent_metrics is not "off".
	Resources *PublicResources `json:"resources,omitempty"`
}

// PublicResources is what a published node says about its own load. Every field is
// a pointer and every one of them is genuinely optional: the host metric families
// are permission-gated per agent, so a denied family has no samples at all and
// must render as a gap. A zero would be a lie — "0% CPU" and "not allowed to say"
// are not the same claim.
//
// The byte totals and the mount name are populated only under agent_metrics=full.
// They are separated from the percentages because they describe the MACHINE (how
// much RAM it has, how its disks are laid out) rather than how the service it
// hosts is doing, and only the latter is inherent to publishing a status page.
type PublicResources struct {
	CPUPct *float64 `json:"cpu_pct,omitempty"`
	// Load is the 1/5/15-minute load average, in that order — the order every
	// tool prints it in, so the page does not have to label three numbers.
	Load *[3]float64 `json:"load,omitempty"`

	MemPct   *float64 `json:"mem_pct,omitempty"`
	MemUsed  *float64 `json:"mem_used,omitempty"`  // bytes; full only
	MemTotal *float64 `json:"mem_total,omitempty"` // bytes; full only

	// Disk is the BUSIEST mount, matching what the console's agent list shows: a
	// public page has one line per node, and the mount closest to full is the one
	// worth that line. DiskMounts says how many there were so a single figure
	// cannot be mistaken for the whole story.
	DiskPct    *float64 `json:"disk_pct,omitempty"`
	DiskUsed   *float64 `json:"disk_used,omitempty"`  // bytes; full only
	DiskTotal  *float64 `json:"disk_total,omitempty"` // bytes; full only
	DiskMount  string   `json:"disk_mount,omitempty"` // full only
	DiskMounts int      `json:"disk_mounts,omitempty"`

	RxBps *float64 `json:"rx_bps,omitempty"`
	TxBps *float64 `json:"tx_bps,omitempty"`

	UptimeSec *float64 `json:"uptime_s,omitempty"`

	// Stale marks readings the agent stopped refreshing — the page dims them
	// rather than presenting a frozen number as current.
	Stale bool `json:"stale,omitempty"`
}

// PublicAgentStatuses is the agent view's payload.
type PublicAgentStatuses struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Agents      []PublicAgentRow `json:"agents"`
}

// PublicAvailability is one published window's reliability figure. Ratio is nil
// when the window holds no verdict at all, because "unknown" and "0%" are
// different answers and must look it; Rounds travels with it so a reader can tell
// a figure backed by a million probes from one backed by three.
type PublicAvailability struct {
	Window string   `json:"window"` // one of PublicAvailabilityWindows' tokens
	Ratio  *float64 `json:"ratio"`
	Rounds int64    `json:"rounds"`
}

// PublicDailyAvailability is one UTC day in the uptime strip. Ratio is null
// when no probe reached a verdict; the counts make the hover summary auditable
// without exposing a series, Agent or monitor id.
type PublicDailyAvailability struct {
	Ratio    *float64 `json:"ratio"`
	Rounds   int64    `json:"rounds"`
	OKRounds int64    `json:"ok_rounds"`
}

// PublicTargetRow is one published monitoring target. Address is present only
// when the page opted into showing addresses.
type PublicTargetRow struct {
	Name    string `json:"name"`
	Ordinal int    `json:"ordinal"`
	Kind    string `json:"kind"`
	Address string `json:"address,omitempty"`
	Status  string `json:"status"`
	// Availability is one entry per PublicAvailabilityWindows, in that order, so
	// the page renders a fixed set of columns without looking anything up.
	Availability []PublicAvailability `json:"availability"`
	// Days is the uptime bar: metrics.DailyCells UTC-day summaries, oldest first.
	// A zero-round day has a null ratio and is a hole rather than an outage.
	Days []PublicDailyAvailability `json:"days"`
}

// PublicTargetStatuses is the target view's payload.
type PublicTargetStatuses struct {
	GeneratedAt time.Time `json:"generated_at"`
	// DaysFrom is the UTC date of Days[0] on every row (YYYY-MM-DD). It is sent
	// once for the whole payload rather than per row because every row shares the
	// same strip, and repeating it per target is pure bytes.
	DaysFrom string            `json:"days_from"`
	Targets  []PublicTargetRow `json:"targets"`
}

const (
	// PublicIncidentWindowDays is the fixed history window. Anonymous callers do
	// not choose a range: arbitrary ranges would turn this bounded status view
	// into a general incident query API.
	PublicIncidentWindowDays = 90
	// PublicIncidentLimit bounds both response size and the work behind a popular
	// anonymous page. Truncated tells the renderer when this cap was reached.
	PublicIncidentLimit = 50
)

// PublicIncidentSubject is one published resource affected by an incident. It
// deliberately carries no internal id. Name/Ordinal/Kind use the same labeling
// contract as the live target and agent views, so an unnamed resource remains an
// anonymous placeholder instead of falling back to an address or hostname.
type PublicIncidentSubject struct {
	Type    string `json:"type"` // target | agent
	Name    string `json:"name"`
	Ordinal int    `json:"ordinal"`
	Kind    string `json:"kind,omitempty"` // probe kind; target only
}

// PublicIncident is the anonymous lifecycle record. The internal incident title,
// summary, group, suspected layer, attribution, ids, notifications and diagnostic
// counts are intentionally absent. Subjects are the only public naming source.
type PublicIncident struct {
	State      string                  `json:"state"`  // open | resolved
	Impact     string                  `json:"impact"` // degraded | outage
	StartedAt  time.Time               `json:"started_at"`
	ResolvedAt *time.Time              `json:"resolved_at,omitempty"`
	Subjects   []PublicIncidentSubject `json:"subjects"`
}

// PublicIncidentHistory is the bounded incident view for one page.
type PublicIncidentHistory struct {
	GeneratedAt time.Time        `json:"generated_at"`
	WindowStart time.Time        `json:"window_start"`
	Incidents   []PublicIncident `json:"incidents"`
	Truncated   bool             `json:"truncated,omitempty"`
}

// The public status vocabulary. Four values, against the twelve display states
// the console renders: the internal set names internal causes (permission
// blocked, agent offline, awaiting first report), and those are operator
// diagnostics, not something an anonymous reader should be handed.
const (
	StatusUp       = "up"
	StatusDown     = "down"
	StatusDegraded = "degraded"
	StatusUnknown  = "unknown"
)

// publicStatus coarsens one display_state (targetstatus's twelve-value enum) into
// the public four. Anything unrecognized becomes "unknown" rather than defaulting
// to "up": a state this function has not been taught about must never be
// published as healthy.
func publicStatus(displayState string) string {
	switch displayState {
	case "healthy":
		return StatusUp
	case "faulted", "partial_failure", "probe_failed":
		return StatusDown
	case "confirming", "stale":
		return StatusDegraded
	default:
		// pending, no_data, blocked, agent_offline, disabled, unassigned — and
		// anything added later.
		return StatusUnknown
	}
}

// ---- public reads ----

// pageRow is the resolved public page, minus everything the outside never sees.
type pageRow struct {
	id                string
	siteID            string
	slug              string
	title             string
	description       string
	showTargetAddress bool
	showAgentView     bool
	showTargetView    bool
	showIncidents     bool
	agentMetrics      string
}

// PublicPage resolves a slug to its public description.
func (s *Service) PublicPage(ctx context.Context, slug string) (PublicPage, error) {
	p, err := s.resolve(ctx, slug)
	if err != nil {
		return PublicPage{}, err
	}
	return PublicPage{
		Slug:              p.slug,
		Title:             p.title,
		Description:       p.description,
		ShowAgentView:     p.showAgentView,
		ShowTargetView:    p.showTargetView,
		ShowIncidents:     p.showIncidents,
		ShowTargetAddress: p.showTargetAddress,
		GeneratedAt:       s.now().UTC(),
	}, nil
}

// PublicAgentStatuses serves the agent view. A page with the agent view turned off
// answers ErrPageNotFound, identically to an unknown slug: the toggle is enforced
// here rather than by the frontend declining to ask, because this endpoint is
// directly reachable.
func (s *Service) PublicAgentStatuses(ctx context.Context, slug string) (PublicAgentStatuses, error) {
	// The page selects GROUPS; what it publishes is their current membership. So
	// this resolves through agent_group_members on every read rather than storing
	// a frozen agent list — an agent added to a published group is meant to appear,
	// and one removed from it is meant to vanish, without anyone re-saving the page.
	// Reading it inside the same transaction as the flags keeps that resolution on
	// the same committed state as the toggles that govern it.
	p, selected, err := s.resolveWithSelection(ctx, slug, `
		SELECT m.agent_id FROM agent_group_members m
		 WHERE m.group_id IN (SELECT group_id FROM status_page_agent_groups WHERE page_id=?)`,
		func(p pageRow) bool { return p.showAgentView })
	if err != nil {
		return PublicAgentStatuses{}, err
	}
	snap, err := s.agentSnapshot(ctx, p.siteID)
	if err != nil {
		return PublicAgentStatuses{}, err
	}

	// Filtering against the live aggregation is also the backstop for stale
	// selections: an id that no longer resolves to a real agent simply has no row
	// to publish.
	rows := make([]agentstatus.AgentStatusRow, 0, len(selected))
	for _, row := range snap.Agents {
		if selected[row.ID] {
			rows = append(rows, row)
		}
	}
	// The aggregation orders by created_at, whose second-level precision leaves
	// same-second enrollments in an arbitrary order — fine for a console list,
	// not for ordinals that end up in a published label. Re-sort with the id as
	// the tiebreak so the numbering is stable across polls.
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if (a.DisplayName == "") != (b.DisplayName == "") {
			return a.DisplayName != "" // unnamed agents last
		}
		if a.DisplayName != b.DisplayName {
			return a.DisplayName < b.DisplayName
		}
		return a.ID < b.ID
	})

	out := make([]PublicAgentRow, 0, len(rows))
	for i, row := range rows {
		out = append(out, PublicAgentRow{
			Name:        row.DisplayName,
			Ordinal:     i + 1,
			Online:      row.Presence == "online",
			StatusSince: row.StatusSince,
			Resources:   publicResources(row.Resources, p.agentMetrics),
		})
	}
	return PublicAgentStatuses{GeneratedAt: snap.GeneratedAt, Agents: out}, nil
}

// publicResources projects the console's resource rollup onto the public one,
// field by field, under the page's disclosure setting.
//
// Written out longhand rather than copied wholesale on purpose: agentstatus.
// Resources is a console DTO that will grow fields, and a struct copy or an
// embedded type would publish each new one the moment it was added. Everything
// below has to be typed out to escape, which is exactly the property this
// package's doc comment promises.
func publicResources(r agentstatus.Resources, mode string) *PublicResources {
	if mode == AgentMetricsOff {
		return nil
	}
	full := mode == AgentMetricsFull
	out := &PublicResources{}
	// A reading is stale if any family that reported is stale — the page dims the
	// node as a whole, and one frozen family means the node is not fully current.
	if r.CPU != nil {
		v := r.CPU.Value
		out.CPUPct = &v
		out.Stale = out.Stale || r.CPU.Stale
	}
	if r.Load != nil {
		l := [3]float64{r.Load.Load1, r.Load.Load5, r.Load.Load15}
		out.Load = &l
		out.Stale = out.Stale || r.Load.Stale
	}
	if r.Memory != nil {
		v := r.Memory.Pct
		out.MemPct = &v
		if full {
			used, total := r.Memory.Used, r.Memory.Total
			out.MemUsed, out.MemTotal = &used, &total
		}
		out.Stale = out.Stale || r.Memory.Stale
	}
	if r.Disk != nil {
		v := r.Disk.Pct
		out.DiskPct = &v
		out.DiskMounts = r.Disk.Mounts
		if full {
			used, total := r.Disk.Used, r.Disk.Total
			out.DiskUsed, out.DiskTotal = &used, &total
			// The mount NAME is a filesystem path — "/mnt/backup-nas" says
			// something about the machine that "61% full" does not.
			out.DiskMount = r.Disk.Mount
		}
		out.Stale = out.Stale || r.Disk.Stale
	}
	if r.Net != nil {
		rx, tx := r.Net.RxBps, r.Net.TxBps
		out.RxBps, out.TxBps = &rx, &tx
		out.Stale = out.Stale || r.Net.Stale
	}
	if r.Uptime != nil {
		v := r.Uptime.Value
		out.UptimeSec = &v
		out.Stale = out.Stale || r.Uptime.Stale
	}
	if *out == (PublicResources{}) {
		// Every family was denied or has never reported. Omit the object rather
		// than publishing an empty one: "{}" invites a renderer to draw six blank
		// gauges, while an absent field says plainly that there is nothing here.
		return nil
	}
	return out
}

// PublicTargetStatuses serves the target view, with the same server-side toggle
// enforcement as the agent view.
func (s *Service) PublicTargetStatuses(ctx context.Context, slug string) (PublicTargetStatuses, error) {
	p, selected, err := s.resolveWithSelection(ctx, slug,
		`SELECT target_id FROM status_page_targets WHERE page_id=?`,
		func(p pageRow) bool { return p.showTargetView })
	if err != nil {
		return PublicTargetStatuses{}, err
	}
	snap, err := s.targetSnapshot(ctx, p.siteID)
	if err != nil {
		return PublicTargetStatuses{}, err
	}
	// The reliability breakdown is read on its own cadence (see availSnapshot):
	// it is the one figure here measured in months, and pinning it to the live
	// board's five seconds would re-scan ninety days of buckets twelve times a
	// minute to publish a number that cannot have changed.
	avail, err := s.availabilitySnapshot(ctx, p.siteID)
	if err != nil {
		return PublicTargetStatuses{}, err
	}

	rows := make([]targetstatus.TargetStatus, 0, len(selected))
	for _, row := range snap.Targets {
		if selected[row.TargetID] {
			rows = append(rows, row)
		}
	}
	// Group by kind, named before unnamed, id as the final tiebreak. Ordinals are
	// assigned within a kind in exactly this order, which is what makes the label
	// an unnamed target renders ("HTTP target 3") the same on every poll.
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if (a.Name == "") != (b.Name == "") {
			return a.Name != ""
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.TargetID < b.TargetID
	})

	perKind := map[string]int{}
	out := make([]PublicTargetRow, 0, len(rows))
	for _, row := range rows {
		perKind[row.Kind]++
		br := avail.Targets[row.TargetID]
		pub := PublicTargetRow{
			Name:         row.Name,
			Ordinal:      perKind[row.Kind],
			Kind:         row.Kind,
			Status:       publicStatus(row.DisplayState),
			Availability: publicAvailability(br.Windows),
			Days:         publicDays(br.Days),
		}
		if p.showTargetAddress {
			pub.Address = row.Target
		}
		out = append(out, pub)
	}
	return PublicTargetStatuses{
		GeneratedAt: snap.GeneratedAt,
		DaysFrom:    time.Unix(avail.DayFrom, 0).UTC().Format("2006-01-02"),
		Targets:     out,
	}, nil
}

type publicSubjectRef struct {
	id string
	PublicIncidentSubject
}

type publicIncidentAccum struct {
	row       PublicIncident
	latest    time.Time
	targetIDs map[string]bool
	agentIDs  map[string]bool
}

// incidentSelectionKey is the exact publication boundary behind one cached
// incident response. Length-prefixing keeps arbitrary operator names from
// colliding with separators; sorted subject slices make the result stable.
func incidentSelectionKey(p pageRow, targets, agents []publicSubjectRef) string {
	var b strings.Builder
	write := func(v string) {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	write(p.id)
	write(p.siteID)
	for _, subject := range targets {
		b.WriteByte('t')
		write(subject.id)
		write(subject.Name)
		write(subject.Kind)
		write(strconv.Itoa(subject.Ordinal))
	}
	for _, subject := range agents {
		b.WriteByte('a')
		write(subject.id)
		write(subject.Name)
		write(strconv.Itoa(subject.Ordinal))
	}
	return b.String()
}

// PublicIncidentHistory serves the page's opt-in incident record. Its state and
// time span are recomputed from the MATCHING public signals rather than copied
// from the parent incident. That distinction matters for a merged incident: an
// unselected target must not keep a selected target looking down after its own
// signal recovered.
func (s *Service) PublicIncidentHistory(ctx context.Context, slug string) (PublicIncidentHistory, error) {
	now := s.now().UTC()
	windowStart := now.AddDate(0, 0, -PublicIncidentWindowDays)
	tx, err := s.db.Read().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PublicIncidentHistory{}, err
	}
	defer func() { _ = tx.Rollback() }()

	p, err := scanPageRow(tx.QueryRowContext(ctx, publicPageQuery, slug))
	if err != nil {
		return PublicIncidentHistory{}, err
	}
	if !p.showIncidents {
		return PublicIncidentHistory{}, ErrPageNotFound
	}
	targets, agents, err := loadPublicIncidentSubjects(ctx, tx, p.id)
	if err != nil {
		return PublicIncidentHistory{}, err
	}
	selection := incidentSelectionKey(p, targets, agents)
	s.incidentMu.Lock()
	defer s.incidentMu.Unlock()
	if cached, ok := s.incidentCache[p.id]; ok && cached.selection == selection && now.Sub(cached.at) < s.ttl {
		return cached.data, nil
	}

	// Candidate selection is capped BEFORE the outer join expands incidents into
	// their matching signals. Open incidents are retained even when they started
	// before the window; resolved ones qualify when either their start or recovery
	// landed inside it.
	rows, err := tx.QueryContext(ctx, `
		WITH
		selected_targets(target_id) AS (
			SELECT target_id FROM status_page_targets WHERE page_id=?
		),
		selected_agents(agent_id) AS (
			SELECT DISTINCT m.agent_id
			  FROM agent_group_members m
			 WHERE m.group_id IN (
				SELECT group_id FROM status_page_agent_groups WHERE page_id=?
			 )
		),
		matching_signals AS (
			SELECT s.*
			  FROM fault_signals s
			  JOIN incidents i ON i.id=s.incident_id
			 WHERE i.site_id=?
			   AND (s.target_id IN selected_targets OR s.agent_id IN selected_agents)
		),
		candidates AS (
			SELECT incident_id,
			       MAX(CASE WHEN state='firing' THEN 1 ELSE 0 END) AS open_rank,
			       MAX(observed_at) AS last_observed
			  FROM matching_signals
			 WHERE state='firing' OR observed_at>=? OR resolved_at>=?
			 GROUP BY incident_id
			 ORDER BY open_rank DESC, last_observed DESC, incident_id
			 LIMIT ?
		)
		SELECT s.incident_id, s.agent_id, s.target_id, s.severity, s.state,
		       s.observed_at, s.resolved_at
		  FROM candidates c
		  JOIN matching_signals s ON s.incident_id=c.incident_id
		 ORDER BY c.open_rank DESC, c.last_observed DESC, s.incident_id, s.id`,
		p.id, p.id, p.siteID, windowStart, windowStart, PublicIncidentLimit+1)
	if err != nil {
		return PublicIncidentHistory{}, err
	}
	defer rows.Close()

	byID := map[string]*publicIncidentAccum{}
	order := make([]string, 0, PublicIncidentLimit+1)
	for rows.Next() {
		var incidentID, agentID, targetID, severity, state string
		var observed time.Time
		var resolved sql.NullTime
		if err := rows.Scan(&incidentID, &agentID, &targetID, &severity, &state, &observed, &resolved); err != nil {
			return PublicIncidentHistory{}, err
		}
		a := byID[incidentID]
		if a == nil {
			a = &publicIncidentAccum{
				row:    PublicIncident{State: "resolved", Impact: "degraded", StartedAt: observed},
				latest: observed, targetIDs: map[string]bool{}, agentIDs: map[string]bool{},
			}
			byID[incidentID] = a
			order = append(order, incidentID)
		}
		if observed.Before(a.row.StartedAt) {
			a.row.StartedAt = observed
		}
		if observed.After(a.latest) {
			a.latest = observed
		}
		if state == "firing" {
			a.row.State = "open"
		}
		if severity != "info" {
			a.row.Impact = "outage"
		}
		if resolved.Valid {
			r := resolved.Time
			if r.After(a.latest) {
				a.latest = r
			}
			if a.row.ResolvedAt == nil || r.After(*a.row.ResolvedAt) {
				a.row.ResolvedAt = &r
			}
		}
		if targetID != "" {
			a.targetIDs[targetID] = true
		}
		if agentID != "" {
			a.agentIDs[agentID] = true
		}
	}
	if err := rows.Err(); err != nil {
		return PublicIncidentHistory{}, err
	}

	out := PublicIncidentHistory{
		GeneratedAt: now,
		WindowStart: windowStart,
		Incidents:   []PublicIncident{},
		Truncated:   len(order) > PublicIncidentLimit,
	}
	if len(order) > PublicIncidentLimit {
		order = order[:PublicIncidentLimit]
	}
	for _, id := range order {
		a := byID[id]
		if a.row.State == "open" {
			a.row.ResolvedAt = nil
		}
		// A target-scoped signal is named by its monitor. Agent subjects are the
		// fallback for connectivity and host faults, where no selected probe target
		// exists. This avoids saying "Website + Node A" for one target outage.
		for _, subject := range targets {
			if a.targetIDs[subject.id] {
				a.row.Subjects = append(a.row.Subjects, subject.PublicIncidentSubject)
			}
		}
		if len(a.row.Subjects) == 0 {
			for _, subject := range agents {
				if a.agentIDs[subject.id] {
					a.row.Subjects = append(a.row.Subjects, subject.PublicIncidentSubject)
				}
			}
		}
		// matching_signals only admits selected target/agent ids, so a valid
		// database always resolves at least one subject. Keep the frontend's
		// anonymous fallback useful if that invariant is ever violated rather
		// than silently dropping a row after Truncated was computed.
		out.Incidents = append(out.Incidents, a.row)
	}
	s.incidentCache[p.id] = incidentSnapshot{at: now, selection: selection, data: out}
	return out, nil
}

// loadPublicIncidentSubjects builds the same stable anonymous labels used by the
// live views, inside the incident read's transaction. Current selection and
// labels therefore come from one committed page version.
func loadPublicIncidentSubjects(ctx context.Context, tx *sql.Tx, pageID string) ([]publicSubjectRef, []publicSubjectRef, error) {
	targetRows, err := tx.QueryContext(ctx, `
		SELECT t.id, COALESCE(t.name,''), t.kind
		  FROM probe_tasks t
		  JOIN status_page_targets m ON m.target_id=t.id
		 WHERE m.page_id=?`, pageID)
	if err != nil {
		return nil, nil, err
	}
	var targets []publicSubjectRef
	for targetRows.Next() {
		var s publicSubjectRef
		s.Type = "target"
		if err := targetRows.Scan(&s.id, &s.Name, &s.Kind); err != nil {
			targetRows.Close()
			return nil, nil, err
		}
		targets = append(targets, s)
	}
	if err := targetRows.Close(); err != nil {
		return nil, nil, err
	}
	sort.Slice(targets, func(i, j int) bool {
		a, b := targets[i], targets[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if (a.Name == "") != (b.Name == "") {
			return a.Name != ""
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.id < b.id
	})
	perKind := map[string]int{}
	for i := range targets {
		perKind[targets[i].Kind]++
		targets[i].Ordinal = perKind[targets[i].Kind]
	}

	agentRows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT a.id, COALESCE(a.display_name,'')
		  FROM agents a
		  JOIN agent_group_members m ON m.agent_id=a.id
		 WHERE m.group_id IN (
			SELECT group_id FROM status_page_agent_groups WHERE page_id=?
		 )`, pageID)
	if err != nil {
		return nil, nil, err
	}
	var agents []publicSubjectRef
	for agentRows.Next() {
		var s publicSubjectRef
		s.Type = "agent"
		if err := agentRows.Scan(&s.id, &s.Name); err != nil {
			agentRows.Close()
			return nil, nil, err
		}
		agents = append(agents, s)
	}
	if err := agentRows.Close(); err != nil {
		return nil, nil, err
	}
	sort.Slice(agents, func(i, j int) bool {
		a, b := agents[i], agents[j]
		if (a.Name == "") != (b.Name == "") {
			return a.Name != ""
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.id < b.id
	})
	for i := range agents {
		agents[i].Ordinal = i + 1
	}
	return targets, agents, nil
}

// publicAvailability turns the breakdown's parallel window slice into the labelled
// public one, always full length and always in PublicAvailabilityWindows' order.
// A target the breakdown has never seen still gets five entries, each reporting
// zero rounds — the page renders "no data yet" rather than omitting a column and
// misaligning every row beside it.
func publicAvailability(windows []metrics.AvailabilityRatio) []PublicAvailability {
	out := make([]PublicAvailability, len(PublicAvailabilityWindows))
	for i, w := range PublicAvailabilityWindows {
		out[i] = PublicAvailability{Window: w.Token}
		if i < len(windows) && windows[i].Rounds > 0 {
			ratio := windows[i].Ratio
			out[i].Ratio = &ratio
			out[i].Rounds = windows[i].Rounds
		}
	}
	return out
}

// publicDays normalises the strip to exactly metrics.DailyCells entries so the
// bar has a fixed width regardless of what the aggregation returned. It maps
// fields explicitly so no internal series identity can reach the public DTO.
func publicDays(days []metrics.AvailabilityRatio) []PublicDailyAvailability {
	out := make([]PublicDailyAvailability, metrics.DailyCells)
	for i := 0; i < len(days) && i < len(out); i++ {
		day := days[i]
		out[i].Rounds = day.Rounds
		out[i].OKRounds = day.OKRounds
		if day.Rounds > 0 {
			ratio := day.Ratio
			out[i].Ratio = &ratio
		}
	}
	return out
}

// resolve looks up an enabled page by slug. A disabled page and an unknown slug
// return the same error on purpose — taking a page down must not confirm that it
// once existed.
func (s *Service) resolve(ctx context.Context, slug string) (pageRow, error) {
	return scanPageRow(s.db.Read().QueryRowContext(ctx, publicPageQuery, slug))
}

const publicPageQuery = `
	SELECT id, site_id, slug, title, description, show_target_address, show_agent_view,
	       show_target_view, show_incidents, agent_metrics
	FROM status_pages WHERE slug=? AND enabled=1`

func scanPageRow(row *sql.Row) (pageRow, error) {
	var p pageRow
	err := row.Scan(&p.id, &p.siteID, &p.slug, &p.title, &p.description,
		&p.showTargetAddress, &p.showAgentView, &p.showTargetView, &p.showIncidents,
		&p.agentMetrics)
	if errors.Is(err, sql.ErrNoRows) {
		return pageRow{}, ErrPageNotFound
	}
	if err != nil {
		return pageRow{}, err
	}
	return p, nil
}

// resolveWithSelection reads a page's publication flags AND its membership inside
// ONE read transaction, then checks the caller's view gate.
//
// The transaction is the point, not an optimization. Read separately, the two
// queries can straddle an admin's save and combine flags from one version of the
// page with membership from another — publishing a newly selected target under
// the previous version's show_target_address, which is precisely the boundary
// this feature exists to hold. WAL isolation makes a single read transaction see
// one committed state, the same reason targetstatus takes one for its snapshot.
//
// The gate is evaluated after the reads rather than short-circuiting before them:
// it costs one cheap query on a hidden view and keeps both branches returning the
// same indistinguishable ErrPageNotFound.
func (s *Service) resolveWithSelection(ctx context.Context, slug, memberQuery string,
	visible func(pageRow) bool) (pageRow, map[string]bool, error) {
	tx, err := s.db.Read().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return pageRow{}, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	p, err := scanPageRow(tx.QueryRowContext(ctx, publicPageQuery, slug))
	if err != nil {
		return pageRow{}, nil, err
	}
	if !visible(p) {
		return pageRow{}, nil, ErrPageNotFound
	}
	rows, err := tx.QueryContext(ctx, memberQuery, p.id)
	if err != nil {
		return pageRow{}, nil, err
	}
	defer rows.Close()
	selected := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return pageRow{}, nil, err
		}
		selected[id] = true
	}
	if err := rows.Err(); err != nil {
		return pageRow{}, nil, err
	}
	return p, selected, nil
}

// ---- snapshot cache ----
//
// Both helpers hold the mutex across the aggregation call. That collapses a burst
// of anonymous readers into one query instead of one query each, which is the
// whole reason the cache exists; the lock is per-service, and every caller here
// is a read that was going to wait on the same database anyway.

func (s *Service) targetSnapshot(ctx context.Context, siteID string) (targetstatus.SiteStatuses, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.targetCache[siteID]; ok && s.now().Sub(e.at) < s.ttl {
		return e.data, nil
	}
	data, err := s.targets.SiteStatuses(ctx, siteID)
	if err != nil {
		return targetstatus.SiteStatuses{}, err
	}
	s.targetCache[siteID] = targetSnapshot{at: s.now(), data: data}
	return data, nil
}

func (s *Service) agentSnapshot(ctx context.Context, siteID string) (agentstatus.SiteAgentStatuses, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.agentCache[siteID]; ok && s.now().Sub(e.at) < s.ttl {
		return e.data, nil
	}
	data, err := s.agents.SiteAgentStatuses(ctx, siteID)
	if err != nil {
		return agentstatus.SiteAgentStatuses{}, err
	}
	s.agentCache[siteID] = agentSnapshot{at: s.now(), data: data}
	return data, nil
}

// availabilitySnapshot is the reliability breakdown on its own lock and its own,
// much longer TTL. Both differences are deliberate: this read scans months of
// rollup buckets rather than one SQLite snapshot, and what it produces — 24h
// through 1y ratios and ninety day cells — is by definition slow-moving. Held
// under the board's mutex it would stall every live poll behind it; refreshed at
// the board's cadence it would be the most expensive thing on the anonymous
// surface, twelve times a minute, to republish an identical number.
//
// A missing metrics store yields an empty breakdown rather than an error: the
// page still has statuses to publish, and every row degrades to "no data yet".
func (s *Service) availabilitySnapshot(ctx context.Context, siteID string) (metrics.SiteAvailabilityBreakdown, error) {
	now := s.now()
	if s.metrics == nil {
		return metrics.SiteAvailabilityBreakdown{
			DayFrom: dayFromFor(now),
			Targets: map[string]metrics.TargetBreakdown{},
		}, nil
	}
	s.availMu.Lock()
	defer s.availMu.Unlock()
	if e, ok := s.availCache[siteID]; ok && now.Sub(e.at) < s.availTTL {
		return e.data, nil
	}
	windows := make([]time.Duration, len(PublicAvailabilityWindows))
	for i, w := range PublicAvailabilityWindows {
		windows[i] = w.Dur
	}
	data, err := s.metrics.AvailabilityBreakdownForSite(ctx, siteID, now, windows)
	if err != nil {
		return metrics.SiteAvailabilityBreakdown{}, err
	}
	s.availCache[siteID] = availSnapshot{at: now, data: data}
	return data, nil
}

// dayFromFor mirrors the aggregation's own strip origin so a page with no metrics
// store still labels its (empty) bar with the right dates.
func dayFromFor(now time.Time) int64 {
	return now.UTC().Truncate(24*time.Hour).Unix() - int64(metrics.DailyCells-1)*86400
}
