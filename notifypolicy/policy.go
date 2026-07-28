// Package notifypolicy decides whether, when and where a recorded fault is
// announced. It consumes incidents; it takes no part in detecting them.
//
// That separation is the point of ALERT-002: whether the system KNOWS about a
// fault and whether it should DISTURB someone used to be the same switch, so a
// user who had configured no notification channel also had no fault history.
// Here, detection always runs and always records; a policy with no channels is a
// legal, meaningful configuration meaning "record everything, send nothing".
//
// Exactly one policy applies to any incident, resolved by a fixed precedence
// with no stacking:
//
//	target policy > monitor-group policy > site default policy
//
// Stacking would let one incident reach the same channel twice through two
// matching policies, so the resolver stops at the first enabled match.
package notifypolicy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/notification"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// ErrNotFound is returned when a policy lookup misses.
var ErrNotFound = errors.New("notification policy not found")

// ErrDefaultPolicy is returned when a caller tries to delete a site's default
// policy, which is undeletable (but fully editable).
var ErrDefaultPolicy = errors.New("the default notification policy cannot be deleted")

// Scope kinds, in precedence order.
const (
	ScopeTarget = "target"
	ScopeGroup  = "group"
	ScopeSite   = "site"
)

// Default policy values (ALERT-002 §8.2). A warning waits five minutes so a
// blip that clears itself is recorded but never announced; a critical waits one.
const (
	DefaultWarnDelaySec     = 300
	DefaultCriticalDelaySec = 60
	defaultPolicyName       = "默认通知策略"
)

var severityRank = map[string]int{"info": 0, "warn": 1, "error": 2, "critical": 3}

// Policy is one notification policy.
type Policy struct {
	ID               string    `json:"id"`
	SiteID           string    `json:"site_id"`
	Name             string    `json:"name"`
	ScopeKind        string    `json:"scope_kind"`
	ScopeID          string    `json:"scope_id"`
	Enabled          bool      `json:"enabled"`
	MinSeverity      string    `json:"min_severity"`
	WarnDelaySec     int       `json:"warn_delay_sec"`
	CriticalDelaySec int       `json:"critical_delay_sec"`
	NotifyRecovery   bool      `json:"notify_recovery"`
	ChannelIDs       []string  `json:"channel_ids"`
	IsDefault        bool      `json:"is_default"`
	CreatedAt        time.Time `json:"created_at"`
}

// Delay returns the notification delay this policy applies to a severity. The
// two-tier mapping (info/warn slow, error/critical fast) keeps the UI to two
// numbers while still covering the full severity enum.
func (p Policy) Delay(severity string) time.Duration {
	if severityRank[severity] >= severityRank["error"] {
		return time.Duration(p.CriticalDelaySec) * time.Second
	}
	return time.Duration(p.WarnDelaySec) * time.Second
}

// Covers reports whether an incident of this severity clears the policy's floor.
func (p Policy) Covers(severity string) bool {
	return severityRank[severity] >= severityRank[p.MinSeverity]
}

// Effective is a resolved policy plus where it came from and the chain that was
// consulted, so the console's "preview effective policy" shows the same answer
// the delivery planner will actually use.
type Effective struct {
	Policy *Policy  `json:"policy"`
	Source string   `json:"source"` // target | group | site | none
	Chain  []string `json:"chain"`  // scopes consulted, most specific first
}

// Notifier is the delivery surface (satisfied by *notification.Service).
type Notifier interface {
	Notify(ctx context.Context, channelIDs []string, p notification.Payload)
}

type Service struct {
	db    *store.DB
	notif Notifier
	set   *settings.Service
	bus   *eventbus.Bus
}

func New(db *store.DB, notif Notifier, set *settings.Service, bus *eventbus.Bus) *Service {
	return &Service{db: db, notif: notif, set: set, bus: bus}
}

// ---- CRUD ----

const policyCols = `id, site_id, name, scope_kind, scope_id, enabled, min_severity,
	warn_delay_sec, critical_delay_sec, notify_recovery, channel_ids, is_default, created_at`

// EnsureDefault creates the site's undeletable default policy if it is missing
// and returns it. Idempotent (the partial unique index on is_default guards a
// second default per site).
//
// It ships with no channels on purpose: creating a site must never wire up
// outbound messaging the operator did not ask for. The console shows the empty
// state explicitly as "faults are recorded, external notification not
// configured" so it can never be mistaken for detection being off.
func (s *Service) EnsureDefault(ctx context.Context, siteID string) (Policy, error) {
	p, err := s.byScope(ctx, siteID, ScopeSite, "")
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Policy{}, err
	}
	id := "np_" + uuid.NewString()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_policies(id, site_id, name, scope_kind, scope_id, enabled,
		    min_severity, warn_delay_sec, critical_delay_sec, notify_recovery, channel_ids, is_default, created_at)
		VALUES(?,?,?,?,'',1,'warn',?,?,1,'[]',1,?)`,
		id, siteID, defaultPolicyName, ScopeSite, DefaultWarnDelaySec, DefaultCriticalDelaySec, time.Now().UTC()); err != nil {
		return Policy{}, err
	}
	return s.byScope(ctx, siteID, ScopeSite, "")
}

// List returns a site's policies, default first then by scope kind and name.
func (s *Service) List(ctx context.Context, siteID string) ([]Policy, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT `+policyCols+` FROM notification_policies WHERE site_id=?
		 ORDER BY is_default DESC, scope_kind, name`, siteID)
	if err != nil {
		return nil, err
	}
	return scanPolicies(rows)
}

// Get returns one policy by id.
func (s *Service) Get(ctx context.Context, id string) (Policy, error) {
	rows, err := s.db.Read().QueryContext(ctx, `SELECT `+policyCols+` FROM notification_policies WHERE id=?`, id)
	if err != nil {
		return Policy{}, err
	}
	out, err := scanPolicies(rows)
	if err != nil {
		return Policy{}, err
	}
	if len(out) == 0 {
		return Policy{}, ErrNotFound
	}
	return out[0], nil
}

func (s *Service) byScope(ctx context.Context, siteID, kind, scopeID string) (Policy, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT `+policyCols+` FROM notification_policies WHERE site_id=? AND scope_kind=? AND scope_id=?`,
		siteID, kind, scopeID)
	if err != nil {
		return Policy{}, err
	}
	out, err := scanPolicies(rows)
	if err != nil {
		return Policy{}, err
	}
	if len(out) == 0 {
		return Policy{}, ErrNotFound
	}
	return out[0], nil
}

// Create stores a new scope override. A site-scope policy cannot be created —
// every site has exactly one, made by EnsureDefault.
func (s *Service) Create(ctx context.Context, siteID string, p Policy) (Policy, error) {
	p.SiteID = siteID
	p.ScopeKind = strings.TrimSpace(p.ScopeKind)
	if p.ScopeKind == ScopeSite {
		return Policy{}, fmt.Errorf("the site policy already exists; edit it instead")
	}
	if err := validate(&p); err != nil {
		return Policy{}, err
	}
	id := "np_" + uuid.NewString()
	chans, _ := json.Marshal(p.ChannelIDs)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_policies(id, site_id, name, scope_kind, scope_id, enabled,
		    min_severity, warn_delay_sec, critical_delay_sec, notify_recovery, channel_ids, is_default, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?)`,
		id, siteID, p.Name, p.ScopeKind, p.ScopeID, boolInt(p.Enabled), p.MinSeverity,
		p.WarnDelaySec, p.CriticalDelaySec, boolInt(p.NotifyRecovery), string(chans), time.Now().UTC()); err != nil {
		return Policy{}, err
	}
	return s.Get(ctx, id)
}

// Update edits a policy in place. Scope is immutable (a policy that changed
// scope would silently start governing a different set of incidents), and the
// default flag cannot be moved.
func (s *Service) Update(ctx context.Context, id string, p Policy) (Policy, error) {
	cur, err := s.Get(ctx, id)
	if err != nil {
		return Policy{}, err
	}
	p.ScopeKind, p.ScopeID, p.SiteID = cur.ScopeKind, cur.ScopeID, cur.SiteID
	if err := validate(&p); err != nil {
		return Policy{}, err
	}
	chans, _ := json.Marshal(p.ChannelIDs)
	if _, err := s.db.ExecContext(ctx, `
		UPDATE notification_policies SET name=?, enabled=?, min_severity=?, warn_delay_sec=?,
		    critical_delay_sec=?, notify_recovery=?, channel_ids=? WHERE id=?`,
		p.Name, boolInt(p.Enabled), p.MinSeverity, p.WarnDelaySec, p.CriticalDelaySec,
		boolInt(p.NotifyRecovery), string(chans), id); err != nil {
		return Policy{}, err
	}
	return s.Get(ctx, id)
}

// Delete removes a scope override; the affected targets fall back to the next
// policy in the chain on their next incident. The default policy is undeletable.
// Already-planned deliveries keep the routing frozen when their incident opened.
func (s *Service) Delete(ctx context.Context, id string) error {
	cur, err := s.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if cur.IsDefault {
		return ErrDefaultPolicy
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM notification_policies WHERE id=?`, id)
	return err
}

// validate normalizes and range-checks a submitted policy.
func validate(p *Policy) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return errors.New("policy name is required")
	}
	switch p.ScopeKind {
	case ScopeSite:
		p.ScopeID = ""
	case ScopeGroup, ScopeTarget:
		if strings.TrimSpace(p.ScopeID) == "" {
			return fmt.Errorf("a %s policy needs a scope id", p.ScopeKind)
		}
	default:
		return fmt.Errorf("invalid scope kind %q", p.ScopeKind)
	}
	if p.MinSeverity == "" {
		p.MinSeverity = "warn"
	}
	if _, ok := severityRank[p.MinSeverity]; !ok {
		return fmt.Errorf("invalid min severity %q", p.MinSeverity)
	}
	if p.WarnDelaySec < 0 || p.WarnDelaySec > 86400 {
		return errors.New("warn delay out of range (0-86400s)")
	}
	if p.CriticalDelaySec < 0 || p.CriticalDelaySec > 86400 {
		return errors.New("critical delay out of range (0-86400s)")
	}
	if p.ChannelIDs == nil {
		p.ChannelIDs = []string{}
	}
	return nil
}

func scanPolicies(rows *sql.Rows) ([]Policy, error) {
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		var p Policy
		var chans string
		var enabled, notifyRecovery, isDefault int
		if err := rows.Scan(&p.ID, &p.SiteID, &p.Name, &p.ScopeKind, &p.ScopeID, &enabled,
			&p.MinSeverity, &p.WarnDelaySec, &p.CriticalDelaySec, &notifyRecovery, &chans,
			&isDefault, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled == 1
		p.NotifyRecovery = notifyRecovery == 1
		p.IsDefault = isDefault == 1
		p.ChannelIDs = []string{}
		if chans != "" {
			_ = json.Unmarshal([]byte(chans), &p.ChannelIDs)
		}
		p.CreatedAt = p.CreatedAt.UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
