package config

// Egress proxies (PROBE-001).
//
// A proxy is a site-scoped, named, reusable egress path a monitoring target may
// be pinned to. It lives in the config package rather than its own because a
// proxy edit IS a target edit for every target referencing it: the same fault
// terminator, the same site-serial bump, the same DesiredState announce, and the
// same target-status publication all have to happen, in the same write
// transaction, for exactly the reasons SetSiteTargets does them. A separate
// package would have to re-import all of that and could only drift.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"
)

// ErrProxyInUse reports an attempt to delete a proxy that targets still
// reference. It carries the occupying monitors so the API can name them.
//
// Refusing is the deliberate choice over ON DELETE SET NULL: silently unpinning
// would convert "monitor through the office proxy" into "monitor directly",
// changing where probes egress from — and what a green check means — without
// anyone asking. That is precisely the failure the fail-closed design exists to
// prevent, so the operator has to unpin (or delete) the monitors first.
type ErrProxyInUse struct {
	ProxyID string
	// Monitors are the display names (falling back to target strings) of the
	// targets still pinned to this proxy, capped for message sanity.
	Monitors []string
	// Total is the full reference count, which may exceed len(Monitors).
	Total int
}

func (e *ErrProxyInUse) Error() string {
	names := strings.Join(e.Monitors, ", ")
	if e.Total > len(e.Monitors) {
		names = fmt.Sprintf("%s (+%d more)", names, e.Total-len(e.Monitors))
	}
	return fmt.Sprintf("proxy is still used by %d monitor(s): %s", e.Total, names)
}

// ErrProxyNameTaken reports a create/update that would give two proxies in one
// site the same name. Names are how a proxy is picked from a dropdown, so a
// duplicate is an unresolvable choice, not a cosmetic clash.
var ErrProxyNameTaken = errors.New("a proxy with this name already exists in the site")

// proxyInUseSample caps how many monitor names an ErrProxyInUse carries.
const proxyInUseSample = 5

// Proxy is one egress proxy as managed through the API. Credential fields carry
// real values on write and are redacted by the API layer on read — this type is
// the storage/domain shape, not the wire shape.
type Proxy struct {
	ID      string `json:"id"`
	SiteID  string `json:"site_id"`
	Name    string `json:"name"`
	Type    string `json:"type"` // pcfg.ProxyType* — socks5 | http | wireguard
	Enabled bool   `json:"enabled"`

	// socks5 / http
	Host             string `json:"host,omitempty"`
	Port             int    `json:"port,omitempty"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	DNSMode          string `json:"dns_mode,omitempty"`
	ConnectTimeoutMs int    `json:"connect_timeout_ms,omitempty"`

	// wireguard
	WGPrivateKey       string `json:"wg_private_key,omitempty"`
	WGPeerPublicKey    string `json:"wg_peer_public_key,omitempty"`
	WGPresharedKey     string `json:"wg_preshared_key,omitempty"`
	WGEndpoint         string `json:"wg_endpoint,omitempty"`
	WGAllowedIPs       string `json:"wg_allowed_ips,omitempty"`
	WGLocalAddrs       string `json:"wg_local_addrs,omitempty"`
	WGDNS              string `json:"wg_dns,omitempty"`
	WGMTU              int    `json:"wg_mtu,omitempty"`
	WGKeepaliveSeconds int    `json:"wg_keepalive_seconds,omitempty"`

	// UsedBy is the number of targets pinned to this proxy. Read-only, filled by
	// ListProxies/GetProxy so the console can show usage and explain a refused
	// delete before the user attempts it.
	UsedBy int `json:"used_by"`
}

// Spec projects the stored proxy onto the wire type pushed to agents.
func (p Proxy) Spec(configSerial int) pcfg.ProxySpec {
	return pcfg.ProxySpec{
		ID:                 p.ID,
		Name:               p.Name,
		Type:               p.Type,
		ConfigSerial:       configSerial,
		Host:               p.Host,
		Port:               p.Port,
		Username:           p.Username,
		Password:           p.Password,
		DNSMode:            p.DNSMode,
		ConnectTimeoutMs:   p.ConnectTimeoutMs,
		WGPrivateKey:       p.WGPrivateKey,
		WGPeerPublicKey:    p.WGPeerPublicKey,
		WGPresharedKey:     p.WGPresharedKey,
		WGEndpoint:         p.WGEndpoint,
		WGAllowedIPs:       p.WGAllowedIPs,
		WGLocalAddrs:       p.WGLocalAddrs,
		WGDNS:              p.WGDNS,
		WGMTU:              p.WGMTU,
		WGKeepaliveSeconds: p.WGKeepaliveSeconds,
	}
}

// proxyColumns is the shared SELECT list, so every reader scans the same shape
// through scanProxy.
const proxyColumns = `id, site_id, name, type, enabled,
	host, port, username, password, dns_mode, connect_timeout_ms,
	wg_private_key, wg_peer_public_key, wg_preshared_key, wg_endpoint,
	wg_allowed_ips, wg_local_addrs, wg_dns, wg_mtu, wg_keepalive_seconds`

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanProxy(sc rowScanner) (Proxy, error) {
	var p Proxy
	var enabled int
	err := sc.Scan(&p.ID, &p.SiteID, &p.Name, &p.Type, &enabled,
		&p.Host, &p.Port, &p.Username, &p.Password, &p.DNSMode, &p.ConnectTimeoutMs,
		&p.WGPrivateKey, &p.WGPeerPublicKey, &p.WGPresharedKey, &p.WGEndpoint,
		&p.WGAllowedIPs, &p.WGLocalAddrs, &p.WGDNS, &p.WGMTU, &p.WGKeepaliveSeconds)
	if err != nil {
		return Proxy{}, err
	}
	p.Enabled = enabled == 1
	return p, nil
}

// ListProxies returns the site's proxies with their reference counts, by name.
func (s *Service) ListProxies(ctx context.Context, siteID string) ([]Proxy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+proxyColumns+` FROM proxies WHERE site_id=? ORDER BY name`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	counts, err := s.proxyUseCounts(ctx, siteID)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].UsedBy = counts[out[i].ID]
	}
	return out, nil
}

// GetProxy returns one proxy by id, or sql.ErrNoRows when absent.
func (s *Service) GetProxy(ctx context.Context, proxyID string) (Proxy, error) {
	p, err := scanProxy(s.db.QueryRowContext(ctx,
		`SELECT `+proxyColumns+` FROM proxies WHERE id=?`, proxyID))
	if err != nil {
		return Proxy{}, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM probe_tasks WHERE proxy_id=?`, proxyID).Scan(&p.UsedBy); err != nil {
		return Proxy{}, err
	}
	return p, nil
}

// proxyUseCounts maps the site's proxy ids to how many targets reference them.
func (s *Service) proxyUseCounts(ctx context.Context, siteID string) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT proxy_id, COUNT(*) FROM probe_tasks
		 WHERE site_id=? AND proxy_id IS NOT NULL AND proxy_id<>'' GROUP BY proxy_id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// CreateProxy inserts a proxy and returns its id. A brand-new proxy is referenced
// by no target yet, so nothing needs a config bump or an announce until a target
// is pinned to it (which goes through SetSiteTargets and bumps there).
func (s *Service) CreateProxy(ctx context.Context, siteID string, p Proxy) (string, error) {
	id := "prx_" + uuid.NewString()
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO proxies(id, site_id, name, type, enabled,
			host, port, username, password, dns_mode, connect_timeout_ms,
			wg_private_key, wg_peer_public_key, wg_preshared_key, wg_endpoint,
			wg_allowed_ips, wg_local_addrs, wg_dns, wg_mtu, wg_keepalive_seconds,
			config_serial, created_at, updated_at)
		 VALUES(?,?,?,?,?, ?,?,?,?,?,?, ?,?,?,?, ?,?,?,?,?, 1,?,?)`,
		id, siteID, p.Name, p.Type, boolInt(p.Enabled),
		p.Host, p.Port, p.Username, p.Password, p.DNSMode, p.ConnectTimeoutMs,
		p.WGPrivateKey, p.WGPeerPublicKey, p.WGPresharedKey, p.WGEndpoint,
		p.WGAllowedIPs, p.WGLocalAddrs, p.WGDNS, p.WGMTU, p.WGKeepaliveSeconds,
		now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return "", ErrProxyNameTaken
		}
		return "", err
	}
	return id, nil
}

// UpdateProxy rewrites a proxy and, when the change is MATERIAL (anything that
// alters how the agent dials, or disabling it), re-generates every target pinned
// to it: the site serial is bumped, each referencing target is re-stamped with
// the new generation, its firing fault signals are force-resolved as
// configuration_changed, and its detector counters are cleared — all inside this
// one write transaction.
//
// That cascade is the point. A failure streak measured through the OLD proxy says
// nothing about the new one, and the agent must be forced to tear the old dialer
// down rather than keep serving probes over a connection opened with credentials
// the operator just revoked. Re-stamping the targets is also what makes the agent
// drop in-flight results from the superseded generation.
//
// A rename alone is not material: it changes no dial, so the targets keep their
// generation and no DesiredState push happens. Returns the site id, or
// sql.ErrNoRows when the proxy is gone.
func (s *Service) UpdateProxy(ctx context.Context, proxyID string, p Proxy) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Read the stored proxy inside the write tx: SQLite serializes writers, so this
	// is the state the UPDATE below actually replaces — a pre-transaction snapshot
	// could classify the edit against a generation someone else already changed.
	old, err := scanProxy(tx.QueryRowContext(ctx,
		`SELECT `+proxyColumns+` FROM proxies WHERE id=?`, proxyID))
	if err != nil {
		return "", err
	}
	siteID := old.SiteID
	material := materialProxyChange(old, p)

	// The capability of the CURRENTLY pinned targets is enforced here, inside the write
	// transaction, rather than only in the API handler.
	//
	// SQLite serializes writers, so an in-tx read sees every committed target — which
	// closes a real window: a SetSiteTargets that commits an ICMP pin after the
	// handler's pre-check but before this transaction would have been validated against
	// the OLD proxy type, and the switch would then leave that monitor permanently
	// un-runnable with both writes reporting success. Rolling back here is what makes
	// the invariant hold rather than merely usually hold.
	if err := validateProxyPinsTx(ctx, tx, proxyID, p.Type); err != nil {
		return "", err
	}

	targetIDs, err := proxyTargetIDs(ctx, tx, proxyID)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	// config_serial is the proxy's own material generation; it advances only on a
	// material edit so a rename cannot invalidate agent-side dialers.
	serialExpr := "config_serial"
	if material {
		serialExpr = "config_serial+1"
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE proxies SET name=?, type=?, enabled=?,
			host=?, port=?, username=?, password=?, dns_mode=?, connect_timeout_ms=?,
			wg_private_key=?, wg_peer_public_key=?, wg_preshared_key=?, wg_endpoint=?,
			wg_allowed_ips=?, wg_local_addrs=?, wg_dns=?, wg_mtu=?, wg_keepalive_seconds=?,
			config_serial=`+serialExpr+`, updated_at=?
		 WHERE id=?`,
		p.Name, p.Type, boolInt(p.Enabled),
		p.Host, p.Port, p.Username, p.Password, p.DNSMode, p.ConnectTimeoutMs,
		p.WGPrivateKey, p.WGPeerPublicKey, p.WGPresharedKey, p.WGEndpoint,
		p.WGAllowedIPs, p.WGLocalAddrs, p.WGDNS, p.WGMTU, p.WGKeepaliveSeconds,
		now, proxyID); err != nil {
		if isUniqueViolation(err) {
			return "", ErrProxyNameTaken
		}
		return "", err
	}

	var termPubs []PostCommit
	var termAffected []string
	if material && len(targetIDs) > 0 {
		// Force-resolve the affected targets' firing signals BEFORE the new generation
		// is stamped, under the reason that actually applies. A proxy edit is a
		// reconfiguration, never a recovery: announcing "recovered" at the moment the
		// operator changed the egress path would be a lie.
		if s.term != nil {
			affected, pub, terr := s.term.TerminateForTargetsTx(ctx, tx, targetIDs, ReasonConfigChanged)
			if terr != nil {
				return "", terr
			}
			termAffected = append(termAffected, affected...)
			if pub != nil {
				termPubs = append(termPubs, pub)
			}
			// Targets whose generation advances without anything firing still need their
			// counters cleared, or a streak measured through the old proxy continues
			// through the new one.
			if terr := s.term.ClearDetectorStateTx(ctx, tx, targetIDs); terr != nil {
				return "", terr
			}
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE sites SET config_serial=config_serial+1 WHERE id=?`, siteID); err != nil {
			return "", err
		}
		var newSerial int
		if err := tx.QueryRowContext(ctx,
			`SELECT config_serial FROM sites WHERE id=?`, siteID).Scan(&newSerial); err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE probe_tasks SET config_serial=?, config_changed_at=? WHERE proxy_id=?`,
			newSerial, now, proxyID); err != nil {
			return "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	for _, pub := range termPubs {
		pub(ctx)
	}
	if material && len(targetIDs) > 0 {
		s.announce(siteID)
	}
	// The status event fires even for a rename: the proxy name is user-visible on
	// the affected monitors, so the console must re-read them either way.
	s.publishTargetStatus(siteID, append(targetIDs, termAffected...))
	return siteID, nil
}

// DeleteProxy removes a proxy that no target references. A referenced proxy is
// refused with *ErrProxyInUse naming the occupying monitors (see ErrProxyInUse
// for why unpinning automatically is not an option). Returns the site id, or
// sql.ErrNoRows when the proxy is gone.
func (s *Service) DeleteProxy(ctx context.Context, proxyID string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	var siteID string
	if err := tx.QueryRowContext(ctx,
		`SELECT site_id FROM proxies WHERE id=?`, proxyID).Scan(&siteID); err != nil {
		return "", err
	}
	// The reference check runs inside the write tx, so a target pinned to this proxy
	// by a concurrent save cannot slip in between the check and the delete.
	users, total, err := proxyUsers(ctx, tx, proxyID)
	if err != nil {
		return "", err
	}
	if total > 0 {
		return "", &ErrProxyInUse{ProxyID: proxyID, Monitors: users, Total: total}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM proxies WHERE id=?`, proxyID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	committed = true
	// No announce: an unreferenced proxy was never in any DesiredState, so no
	// agent's config changed.
	return siteID, nil
}

// materialProxyChange reports whether the edit changes how the agent dials — i.e.
// whether every target pinned to this proxy has to be re-generated.
//
// name is NOT material (it changes no dial). enabled IS: disabling drops the spec
// out of DesiredState, which fails the pinned targets closed rather than letting
// them fall back to a direct dial.
func materialProxyChange(old, next Proxy) bool {
	return old.Type != next.Type ||
		old.Enabled != next.Enabled ||
		old.Host != next.Host ||
		old.Port != next.Port ||
		old.Username != next.Username ||
		old.Password != next.Password ||
		old.DNSMode != next.DNSMode ||
		old.ConnectTimeoutMs != next.ConnectTimeoutMs ||
		old.WGPrivateKey != next.WGPrivateKey ||
		old.WGPeerPublicKey != next.WGPeerPublicKey ||
		old.WGPresharedKey != next.WGPresharedKey ||
		old.WGEndpoint != next.WGEndpoint ||
		old.WGAllowedIPs != next.WGAllowedIPs ||
		old.WGLocalAddrs != next.WGLocalAddrs ||
		old.WGDNS != next.WGDNS ||
		old.WGMTU != next.WGMTU ||
		old.WGKeepaliveSeconds != next.WGKeepaliveSeconds
}

// ErrProxyStrandsTargets reports a proxy type change that the currently pinned
// monitors cannot run through. It carries their descriptions so the refusal names
// what has to be re-pointed first.
type ErrProxyStrandsTargets struct {
	NewType  string
	Monitors []string
}

func (e *ErrProxyStrandsTargets) Error() string {
	return fmt.Sprintf("a %s proxy cannot carry %s — unpin or re-point those monitors first",
		e.NewType, strings.Join(e.Monitors, ", "))
}

// validateProxyPinsTx checks every target pinned to this proxy against a prospective
// type, inside the caller's write transaction.
func validateProxyPinsTx(ctx context.Context, tx txExec, proxyID, newType string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT kind, COALESCE(name,''), COALESCE(target,''), COALESCE(params,'')
		 FROM probe_tasks WHERE proxy_id=?`, proxyID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var stranded []string
	for rows.Next() {
		var kind, name, target, params string
		if err := rows.Scan(&kind, &name, &target, &params); err != nil {
			return err
		}
		var p pcfg.ProbeParams
		if params != "" {
			_ = json.Unmarshal([]byte(params), &p)
		}
		if pcfg.ProxyCapable(kind, p, newType) {
			continue
		}
		if name == "" {
			name = target
		}
		stranded = append(stranded, fmt.Sprintf("%s monitor %q", kind, name))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(stranded) > 0 {
		return &ErrProxyStrandsTargets{NewType: newType, Monitors: stranded}
	}
	return nil
}

// proxyTargetIDs returns the ids of the targets pinned to a proxy, inside tx.
func proxyTargetIDs(ctx context.Context, tx txExec, proxyID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM probe_tasks WHERE proxy_id=?`, proxyID)
	if err != nil {
		return nil, err
	}
	return scanIDs(rows)
}

// proxyUsers returns up to proxyInUseSample display names of the targets pinned
// to a proxy plus the full count, inside tx. A target with no name falls back to
// its target string so the refusal message always identifies something the
// operator recognizes.
func proxyUsers(ctx context.Context, tx txExec, proxyID string) ([]string, int, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(name,''), COALESCE(target,''), id) FROM probe_tasks
		 WHERE proxy_id=? ORDER BY name, target`, proxyID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var names []string
	total := 0
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, 0, err
		}
		total++
		if len(names) < proxyInUseSample {
			names = append(names, n)
		}
	}
	return names, total, rows.Err()
}

// ProxyTypesByID maps the site's proxy ids to their type and enabled flag. The
// API layer uses it to validate a submitted target set against the capability
// matrix (pcfg.ProxyCapable) before any target is written.
func (s *Service) ProxyTypesByID(ctx context.Context, siteID string) (map[string]ProxyRef, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, type, enabled FROM proxies WHERE site_id=?`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ProxyRef{}
	for rows.Next() {
		var r ProxyRef
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		out[r.ID] = r
	}
	return out, rows.Err()
}

// ProxyRef is the minimal identity + type of a proxy, enough to validate a
// target's pin without loading credentials.
type ProxyRef struct {
	ID      string
	Name    string
	Type    string
	Enabled bool
}

// proxySpecsFor loads the ProxySpecs to push alongside a set of targets: the
// ENABLED proxies referenced by those targets, and nothing else.
//
// A referenced-but-DISABLED proxy is deliberately omitted while its targets stay
// in the push. That is what makes the agent report proxy_missing as an
// operational issue ("this monitor is not running, and here is why") instead of
// the monitor quietly vanishing from the agent's view, which is indistinguishable
// from a deletion.
func proxySpecsFor(ctx context.Context, q scopeQueryer, siteID string, proxyIDs map[string]bool) ([]pcfg.ProxySpec, error) {
	if len(proxyIDs) == 0 {
		return nil, nil
	}
	ids := make([]any, 0, len(proxyIDs))
	for id := range proxyIDs {
		ids = append(ids, id)
	}
	rows, err := q.QueryContext(ctx,
		`SELECT `+proxyColumns+`, config_serial FROM proxies
		 WHERE site_id=? AND enabled=1 AND id IN (`+placeholders(len(ids))+`)`,
		append([]any{siteID}, ids...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pcfg.ProxySpec
	for rows.Next() {
		var p Proxy
		var enabled, serial int
		if err := rows.Scan(&p.ID, &p.SiteID, &p.Name, &p.Type, &enabled,
			&p.Host, &p.Port, &p.Username, &p.Password, &p.DNSMode, &p.ConnectTimeoutMs,
			&p.WGPrivateKey, &p.WGPeerPublicKey, &p.WGPresharedKey, &p.WGEndpoint,
			&p.WGAllowedIPs, &p.WGLocalAddrs, &p.WGDNS, &p.WGMTU, &p.WGKeepaliveSeconds,
			&serial); err != nil {
			return nil, err
		}
		out = append(out, p.Spec(serial))
	}
	return out, rows.Err()
}

// isUniqueViolation reports whether err is a UNIQUE constraint failure. The
// driver's error is matched by text because modernc/sqlite does not expose a
// typed constraint error, and the alternative — a pre-check SELECT — would be
// racy for exactly the case this guards.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") || strings.Contains(msg, "constraint failed: unique")
}
