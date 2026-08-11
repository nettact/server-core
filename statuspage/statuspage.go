// Package statuspage owns the public status pages: the admin CRUD over a page
// and its agent-group/target selection, and the anonymous, sanitized reads that
// serve it to the world.
//
// It is the only place in server-core that answers a request with no session
// behind it, so its shape is defensive on purpose:
//
//   - It derives nothing. Health comes from targetstatus/agentstatus, the same
//     aggregations the console reads; this package filters and redacts, and never
//     re-decides whether something is up. Two sources for "is it down" is exactly
//     the drift a status page must not have.
//   - Publication is by selection, never by existence: nothing reaches a page
//     because it exists, only because an operator chose it. Targets are chosen one
//     at a time. AGENTS ARE CHOSEN BY GROUP, and that difference is worth stating
//     plainly — a page publishes each selected group's current membership, so an
//     agent added to a published group becomes public with it, and one removed
//     from it disappears. That is the point (the page tracks the fleet the
//     operator already curates instead of drifting out of date) and it is also the
//     trade, which is why the console spells it out on the form.
//   - Redaction happens HERE, in the DTO mapping, not in the frontend. The public
//     endpoints are directly callable, so anything the UI would hide has to be
//     absent from the payload rather than merely unrendered.
//
// The visibility toggles (enabled, show_agent_view, show_target_view,
// show_incidents) are read as route existence rather than as flags: when one is
// off, the public read returns ErrPageNotFound and the API answers exactly as it
// would for a slug that was never created. Nothing distinguishes "taken down",
// "view disabled" and "never existed" from outside.
package statuspage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/agentstatus"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/targetstatus"
)

var (
	// ErrNotFound is an admin-facing miss: no such page id, or one belonging to a
	// different site. Both map to 404 — a page id is not a capability, but there is
	// no reason for the API to confirm one exists in a site the caller didn't ask
	// about.
	ErrNotFound = errors.New("statuspage: page not found")
	// ErrSlugTaken means the requested public address is already in use. Slugs are
	// unique across sites because the public route resolves by slug alone.
	ErrSlugTaken = errors.New("statuspage: slug already in use")
	// ErrBadSelection means the selection named an agent group or target that this
	// site cannot publish (unknown, or belonging to another site). It is a typed
	// sentinel rather than a bare formatted error so the API can answer 400 instead
	// of 500: the operator picked something invalid, the server is fine.
	ErrBadSelection = errors.New("statuspage: invalid selection")
	// ErrPageNotFound is the ONLY public-facing miss. Unknown slug, disabled page,
	// and disabled view all return it, so the anonymous 404s are indistinguishable.
	ErrPageNotFound = errors.New("statuspage: no such public page")
)

// SlugPattern is the accepted public address: lowercase alphanumerics and
// interior dashes, 1–64 characters. It is deliberately narrow — the slug lands in
// a URL, in copy-pasted links, and in the page's own hash route, so anything
// requiring escaping anywhere is rejected at the door rather than encoded later.
var SlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// Field limits. Title and description are rendered verbatim on an anonymous page;
// the caps exist so a mistake cannot turn the page into a payload delivery.
const (
	MaxTitleLen       = 128
	MaxDescriptionLen = 1024
)

// defaultCacheTTL bounds how stale a public read may be. It exists to bound
// anonymous load, not to be fast: SiteStatuses is a whole-site snapshot
// aggregation, and without a cache every viewer of a popular page would run one.
// Five seconds is invisible under the page's 30s poll and still lets an admin see
// an edit land almost immediately.
const defaultCacheTTL = 5 * time.Second

// defaultAvailabilityTTL bounds the reliability breakdown separately, and much
// more loosely, because it is a different kind of read: five nested windows and
// ninety day cells scanned from the rollup tiers, against a snapshot that is one
// SQLite transaction. A 90-day ratio does not move in a minute — it cannot, by
// construction — so refreshing it at the live board's cadence would buy nothing
// and cost the most expensive query on the anonymous surface.
const defaultAvailabilityTTL = 60 * time.Second

// How much a published node discloses about itself. Off is up/down only; basic is
// percentages and rates; full adds the byte totals and the busiest mount's name.
// See the agent_metrics column comment in the schema for why this is an enum.
const (
	AgentMetricsOff   = "off"
	AgentMetricsBasic = "basic"
	AgentMetricsFull  = "full"
)

// DefaultAgentMetrics is what a page publishes when the field is omitted.
const DefaultAgentMetrics = AgentMetricsBasic

// validAgentMetrics is the whitelist. An unrecognised value is rejected rather
// than coerced: silently downgrading a typo to "off" would hide nodes the
// operator meant to publish, and silently upgrading it would disclose more than
// they asked for. Neither is a guess worth making on their behalf.
func validAgentMetrics(v string) bool {
	switch v {
	case AgentMetricsOff, AgentMetricsBasic, AgentMetricsFull:
		return true
	}
	return false
}

// PublicAvailabilityWindows are the reliability windows every public page
// publishes, narrowest first. The list is fixed server-side rather than taken
// from the query string: an anonymous caller choosing arbitrary windows would
// make the cache useless and the scan unbounded, and a status page's job is to
// answer one well-known question, not to be a query API.
var PublicAvailabilityWindows = []struct {
	Token string
	Dur   time.Duration
}{
	{"24h", 24 * time.Hour},
	{"7d", 7 * 24 * time.Hour},
	{"30d", 30 * 24 * time.Hour},
	{"90d", 90 * 24 * time.Hour},
	{"1y", 365 * 24 * time.Hour},
}

// Page is the admin-facing view of a status page, selection included.
type Page struct {
	ID                string `json:"id"`
	SiteID            string `json:"site_id"`
	Slug              string `json:"slug"`
	Title             string `json:"title"`
	Description       string `json:"description"`
	Enabled           bool   `json:"enabled"`
	ShowTargetAddress bool   `json:"show_target_address"`
	ShowAgentView     bool   `json:"show_agent_view"`
	ShowTargetView    bool   `json:"show_target_view"`
	ShowIncidents     bool   `json:"show_incidents"`
	// AgentMetrics is off|basic|full — how much resource detail published nodes
	// disclose. It only means anything when ShowAgentView is on.
	AgentMetrics string `json:"agent_metrics"`
	// IsHome marks this page as the server's front door: an anonymous GET / is
	// redirected to it instead of the console shell. At most one page carries it,
	// and setting it on a page clears it from whichever page held it before.
	IsHome bool `json:"is_home"`
	// Agents are published by GROUP, so what a page names is the operator's own
	// curation rather than a list of machines that goes stale the moment one is
	// enrolled. The published node list is each selected group's CURRENT members.
	AgentGroupIDs []string  `json:"agent_group_ids"`
	TargetIDs     []string  `json:"target_ids"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Spec is a page's complete editable state. Create and Update both take the whole
// thing and the selection is replaced wholesale rather than diffed — the console
// edits a page as one form, and a partial-update API would only invite a client
// that forgets to send a field to silently unpublish half a page.
type Spec struct {
	Slug              string
	Title             string
	Description       string
	Enabled           bool
	ShowTargetAddress bool
	ShowAgentView     bool
	ShowTargetView    bool
	ShowIncidents     bool
	AgentMetrics      string
	IsHome            bool
	AgentGroupIDs     []string
	TargetIDs         []string
}

// Validate checks the operator-supplied text fields. Selection validity is not
// checked here: it needs the database, and is enforced inside the write
// transaction where it cannot race a concurrent delete.
func (s Spec) Validate() error {
	if !SlugPattern.MatchString(s.Slug) {
		return fmt.Errorf("%w: slug must be 1-64 lowercase letters, digits or interior dashes", ErrBadSpec)
	}
	title := strings.TrimSpace(s.Title)
	if title == "" {
		return fmt.Errorf("%w: title is required", ErrBadSpec)
	}
	if len([]rune(title)) > MaxTitleLen {
		return fmt.Errorf("%w: title must be at most %d characters", ErrBadSpec, MaxTitleLen)
	}
	if len([]rune(s.Description)) > MaxDescriptionLen {
		return fmt.Errorf("%w: description must be at most %d characters", ErrBadSpec, MaxDescriptionLen)
	}
	if !s.ShowAgentView && !s.ShowTargetView && !s.ShowIncidents {
		return fmt.Errorf("%w: at least one public view must be shown", ErrBadSpec)
	}
	if !validAgentMetrics(s.AgentMetrics) {
		return fmt.Errorf("%w: agent_metrics must be one of %q, %q or %q",
			ErrBadSpec, AgentMetricsOff, AgentMetricsBasic, AgentMetricsFull)
	}
	return nil
}

// ErrBadSpec is a malformed page definition (bad slug, empty title, no visible
// view). Separate from ErrBadSelection because they fail for different reasons,
// but both are 400s.
var ErrBadSpec = errors.New("statuspage: invalid page")

// Service reads and writes status pages. It owns the page tables; every status
// value it publishes comes from the two aggregation services it wraps.
type Service struct {
	db      *store.DB
	targets *targetstatus.Service
	agents  *agentstatus.Service
	metrics *metrics.Store

	ttl      time.Duration
	availTTL time.Duration
	now      func() time.Time

	// mu guards the snapshot cache AND is held across the aggregation call, which
	// makes concurrent public readers single-flight into one query instead of a
	// thundering herd. Serializing them is the point, not a cost: the whole reason
	// the cache exists is that these snapshots are expensive and anonymous.
	mu          sync.Mutex
	targetCache map[string]targetSnapshot
	agentCache  map[string]agentSnapshot

	// availMu is deliberately NOT mu. The reliability breakdown is the slowest
	// read here by an order of magnitude and the only one refreshed by the minute;
	// sharing a lock with the five-second board would make every live poll queue
	// behind a ninety-day scan that it does not even need.
	availMu    sync.Mutex
	availCache map[string]availSnapshot

	// incidentMu is separate for the same reason: the incident CTE is an
	// anonymous, multi-table history read and must neither block live status
	// snapshots nor execute once per viewer. Page visibility and the selected
	// subjects are still read before this cache, so a configuration edit cannot
	// reuse data published under a different selection.
	incidentMu    sync.Mutex
	incidentCache map[string]incidentSnapshot
}

type targetSnapshot struct {
	at   time.Time
	data targetstatus.SiteStatuses
}

type agentSnapshot struct {
	at   time.Time
	data agentstatus.SiteAgentStatuses
}

type availSnapshot struct {
	at   time.Time
	data metrics.SiteAvailabilityBreakdown
}

type incidentSnapshot struct {
	at        time.Time
	selection string
	data      PublicIncidentHistory
}

// New constructs the service over the shared store and the two status
// aggregations it republishes.
func New(db *store.DB, ts *targetstatus.Service, as *agentstatus.Service, m *metrics.Store) *Service {
	return &Service{
		db:            db,
		targets:       ts,
		agents:        as,
		metrics:       m,
		ttl:           defaultCacheTTL,
		availTTL:      defaultAvailabilityTTL,
		now:           time.Now,
		targetCache:   map[string]targetSnapshot{},
		agentCache:    map[string]agentSnapshot{},
		availCache:    map[string]availSnapshot{},
		incidentCache: map[string]incidentSnapshot{},
	}
}

// ---- admin CRUD ----

// List returns a site's pages, each with its selection, oldest first.
func (s *Service) List(ctx context.Context, siteID string) ([]Page, error) {
	rows, err := s.db.Read().QueryContext(ctx, `
		SELECT id, site_id, slug, title, description, enabled,
		       show_target_address, show_agent_view, show_target_view, show_incidents,
		       agent_metrics, is_home,
		       created_at, updated_at
		FROM status_pages WHERE site_id=? ORDER BY created_at, id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Page{}
	for rows.Next() {
		p, err := scanPage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}

	byID := make(map[string]*Page, len(out))
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	if err := s.loadMembers(ctx, siteID, byID); err != nil {
		return nil, err
	}
	return out, nil
}

// Get returns one page with its selection. ErrNotFound when there is no such id.
func (s *Service) Get(ctx context.Context, id string) (Page, error) {
	row := s.db.Read().QueryRowContext(ctx, `
		SELECT id, site_id, slug, title, description, enabled,
		       show_target_address, show_agent_view, show_target_view, show_incidents,
		       agent_metrics, is_home,
		       created_at, updated_at
		FROM status_pages WHERE id=?`, id)
	p, err := scanPage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Page{}, ErrNotFound
	}
	if err != nil {
		return Page{}, err
	}
	byID := map[string]*Page{p.ID: &p}
	if err := s.loadMembers(ctx, p.SiteID, byID); err != nil {
		return Page{}, err
	}
	return p, nil
}

// Create adds a page to a site and returns it as stored.
func (s *Service) Create(ctx context.Context, siteID string, spec Spec) (Page, error) {
	if err := spec.Validate(); err != nil {
		return Page{}, err
	}
	id := "spg_" + uuid.NewString()
	now := s.now().UTC()
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := ensureSlugFree(ctx, tx, spec.Slug, ""); err != nil {
			return err
		}
		if err := clearHome(ctx, tx, spec, "", now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO status_pages(id, site_id, slug, title, description, enabled,
			                         show_target_address, show_agent_view, show_target_view,
			                         show_incidents, agent_metrics, is_home, created_at, updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, siteID, spec.Slug, strings.TrimSpace(spec.Title), spec.Description, spec.Enabled,
			spec.ShowTargetAddress, spec.ShowAgentView, spec.ShowTargetView, spec.ShowIncidents,
			spec.AgentMetrics, spec.IsHome,
			now, now); err != nil {
			return err
		}
		return replaceMembers(ctx, tx, id, siteID, spec)
	})
	if err != nil {
		return Page{}, err
	}
	return s.Get(ctx, id)
}

// Update rewrites a page and replaces its selection wholesale.
func (s *Service) Update(ctx context.Context, id string, spec Spec) (Page, error) {
	if err := spec.Validate(); err != nil {
		return Page{}, err
	}
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var siteID string
		if err := tx.QueryRowContext(ctx,
			`SELECT site_id FROM status_pages WHERE id=?`, id).Scan(&siteID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if err := ensureSlugFree(ctx, tx, spec.Slug, id); err != nil {
			return err
		}
		now := s.now().UTC()
		if err := clearHome(ctx, tx, spec, id, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE status_pages
			   SET slug=?, title=?, description=?, enabled=?,
			       show_target_address=?, show_agent_view=?, show_target_view=?,
			       show_incidents=?, agent_metrics=?, is_home=?, updated_at=?
			 WHERE id=?`,
			spec.Slug, strings.TrimSpace(spec.Title), spec.Description, spec.Enabled,
			spec.ShowTargetAddress, spec.ShowAgentView, spec.ShowTargetView, spec.ShowIncidents,
			spec.AgentMetrics, spec.IsHome,
			now, id); err != nil {
			return err
		}
		return replaceMembers(ctx, tx, id, siteID, spec)
	})
	if err != nil {
		return Page{}, err
	}
	s.invalidateIncidentCache(id)
	return s.Get(ctx, id)
}

// Delete removes a page; its selection rows cascade.
func (s *Service) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM status_pages WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.invalidateIncidentCache(id)
	return nil
}

func (s *Service) invalidateIncidentCache(pageID string) {
	s.incidentMu.Lock()
	delete(s.incidentCache, pageID)
	s.incidentMu.Unlock()
}

// ---- internals ----

// rowScanner is the shared shape of *sql.Row and *sql.Rows, so one scanPage
// serves both the list and the single-row read.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanPage(sc rowScanner) (Page, error) {
	var p Page
	err := sc.Scan(&p.ID, &p.SiteID, &p.Slug, &p.Title, &p.Description, &p.Enabled,
		&p.ShowTargetAddress, &p.ShowAgentView, &p.ShowTargetView, &p.ShowIncidents,
		&p.AgentMetrics, &p.IsHome,
		&p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return Page{}, err
	}
	// Never nil: the console renders these as lists and the API contract says an
	// empty selection is [], not null.
	p.AgentGroupIDs = []string{}
	p.TargetIDs = []string{}
	return p, nil
}

// loadMembers fills the selection of every page in byID with two site-wide
// queries, rather than two per page.
func (s *Service) loadMembers(ctx context.Context, siteID string, byID map[string]*Page) error {
	load := func(query string, assign func(p *Page, id string)) error {
		rows, err := s.db.Read().QueryContext(ctx, query, siteID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pageID, memberID string
			if err := rows.Scan(&pageID, &memberID); err != nil {
				return err
			}
			if p := byID[pageID]; p != nil {
				assign(p, memberID)
			}
		}
		return rows.Err()
	}
	if err := load(`
		SELECT m.page_id, m.group_id FROM status_page_agent_groups m
		  JOIN status_pages p ON p.id = m.page_id
		 WHERE p.site_id=? ORDER BY m.group_id`,
		func(p *Page, id string) { p.AgentGroupIDs = append(p.AgentGroupIDs, id) }); err != nil {
		return err
	}
	return load(`
		SELECT m.page_id, m.target_id FROM status_page_targets m
		  JOIN status_pages p ON p.id = m.page_id
		 WHERE p.site_id=? ORDER BY m.target_id`,
		func(p *Page, id string) { p.TargetIDs = append(p.TargetIDs, id) })
}

// clearHome demotes whatever page currently holds the home flag, so the caller
// can claim it. A no-op unless the spec is actually claiming it.
//
// Setting a home page TAKES it rather than being refused, and that is a UX
// decision worth writing down. The alternative — answer 409 and make the
// operator go clear the other page first — is more explicit but describes a
// state nobody wants to be in: two pages cannot both be the front door, so the
// second save is unambiguous about intent. The console says which page is about
// to lose the flag before the save, which is where that information is useful;
// discovering it as an error afterwards is not.
//
// It must run BEFORE the caller writes its own row. The partial unique index
// admits exactly one is_home=1 row, so claiming first and demoting second would
// trip the constraint inside the same statement pair. Both live in the caller's
// transaction, which is what makes the swap atomic — a reader can see the old
// home or the new one, never two and never none.
//
// exceptID keeps an update of the page that ALREADY holds the flag from
// demoting itself (Create passes "", which matches no id).
func clearHome(ctx context.Context, tx *sql.Tx, spec Spec, exceptID string, now time.Time) error {
	if !spec.IsHome {
		return nil
	}
	_, err := tx.ExecContext(ctx,
		`UPDATE status_pages SET is_home=0, updated_at=? WHERE is_home=1 AND id<>?`, now, exceptID)
	return err
}

// HomeSlug returns the slug of the published page nominated as this server's
// home page, and whether there is one.
//
// enabled=1 is part of the query rather than a caller's check: a page taken down
// reads as "no such page" everywhere else in this package, and the root URL is
// not the place to start making an exception. An unpublished home page simply
// means the root serves the console again, and republishing brings it back.
//
// Uncached on purpose. It hits a partial unique index and returns at most one
// row, and it only runs for document-level GET / — the status board's 30s poll
// talks to /api/v1/public/*, which never reaches here. That is cheaper than the
// file I/O the SPA fallback was about to do anyway.
func (s *Service) HomeSlug(ctx context.Context) (string, bool, error) {
	var slug string
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT slug FROM status_pages WHERE is_home=1 AND enabled=1`).Scan(&slug)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return slug, true, nil
}

func (s *Service) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ensureSlugFree rejects a slug already used by another page. The UNIQUE index is
// still the real guarantee; this exists so the common case reports ErrSlugTaken
// (409, "pick another address") instead of surfacing a driver constraint string.
func ensureSlugFree(ctx context.Context, tx *sql.Tx, slug, exceptID string) error {
	var found string
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM status_pages WHERE slug=? AND id<>?`, slug, exceptID).Scan(&found)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	default:
		return ErrSlugTaken
	}
}

// replaceMembers rewrites a page's selection inside the caller's transaction.
//
// Each insert is an INSERT..SELECT filtered by site, so an id this site cannot
// publish inserts no row and is rejected with ErrBadSelection rather than being
// silently dropped. Silently dropping is the dangerous half of that choice in the
// other direction too: an operator who pasted the wrong id would get a page that
// looks saved and publishes less than they think.
func replaceMembers(ctx context.Context, tx *sql.Tx, pageID, siteID string, spec Spec) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM status_page_agent_groups WHERE page_id=?`, pageID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM status_page_targets WHERE page_id=?`, pageID); err != nil {
		return err
	}
	for _, groupID := range dedupe(spec.AgentGroupIDs) {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO status_page_agent_groups(page_id, group_id)
			SELECT ?, id FROM agent_groups WHERE id=? AND site_id=?`, pageID, groupID, siteID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: agent group %q is not available in site %s", ErrBadSelection, groupID, siteID)
		}
	}
	for _, targetID := range dedupe(spec.TargetIDs) {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO status_page_targets(page_id, target_id)
			SELECT ?, id FROM probe_tasks WHERE id=? AND site_id=?`, pageID, targetID, siteID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: target %q is not available in site %s", ErrBadSelection, targetID, siteID)
		}
	}
	return nil
}

// dedupe removes repeated ids while preserving order, so a client that sends the
// same selection twice writes one row rather than failing on the primary key. An
// empty string is NOT filtered out: it matches no agent or target, so it fails
// through replaceMembers as ErrBadSelection like any other id this site cannot
// publish, rather than being silently dropped.
func dedupe(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
