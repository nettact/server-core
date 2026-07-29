package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/server-core/config"
)

// Egress proxy API (PROBE-001).
//
// Credentials are WRITE-ONLY across this surface: reads return a fixed
// placeholder instead of the stored secret, and a write that sends the
// placeholder back means "keep what is stored". That is what lets the console
// round-trip an edit form without ever holding the real password — the form is
// populated from a read, so if the read carried the secret it would sit in the
// browser (and in every proxy log and screenshot) for no reason.

// redactedSecret is what reads return in place of a stored credential, and what a
// write may send back to mean "unchanged". It is deliberately not empty: empty
// has to keep meaning "clear this credential", or a proxy's password could never
// be removed once set.
const redactedSecret = "••••••"

const maxProxyBodyBytes = 1 << 16

// proxyBody is the create/update payload. Every field is a pointer-free scalar
// mirroring config.Proxy; enabled defaults to true on create when omitted, which
// is why it is a *bool.
type proxyBody struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Enabled *bool  `json:"enabled"`

	Host             string `json:"host"`
	Port             int    `json:"port"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	DNSMode          string `json:"dns_mode"`
	ConnectTimeoutMs int    `json:"connect_timeout_ms"`

	WGPrivateKey       string `json:"wg_private_key"`
	WGPeerPublicKey    string `json:"wg_peer_public_key"`
	WGPresharedKey     string `json:"wg_preshared_key"`
	WGEndpoint         string `json:"wg_endpoint"`
	WGAllowedIPs       string `json:"wg_allowed_ips"`
	WGLocalAddrs       string `json:"wg_local_addrs"`
	WGDNS              string `json:"wg_dns"`
	WGMTU              int    `json:"wg_mtu"`
	WGKeepaliveSeconds int    `json:"wg_keepalive_seconds"`
}

func (b proxyBody) toProxy() config.Proxy {
	enabled := true
	if b.Enabled != nil {
		enabled = *b.Enabled
	}
	return config.Proxy{
		Name: b.Name, Type: b.Type, Enabled: enabled,
		Host: b.Host, Port: b.Port, Username: b.Username, Password: b.Password,
		DNSMode: b.DNSMode, ConnectTimeoutMs: b.ConnectTimeoutMs,
		WGPrivateKey: b.WGPrivateKey, WGPeerPublicKey: b.WGPeerPublicKey,
		WGPresharedKey: b.WGPresharedKey, WGEndpoint: b.WGEndpoint,
		WGAllowedIPs: b.WGAllowedIPs, WGLocalAddrs: b.WGLocalAddrs, WGDNS: b.WGDNS,
		WGMTU: b.WGMTU, WGKeepaliveSeconds: b.WGKeepaliveSeconds,
	}
}

// redactProxy blanks the stored credentials for a read response, replacing each
// non-empty one with redactedSecret so the console can render "a password is
// set" without receiving it.
func redactProxy(p config.Proxy) config.Proxy {
	if p.Password != "" {
		p.Password = redactedSecret
	}
	if p.WGPrivateKey != "" {
		p.WGPrivateKey = redactedSecret
	}
	if p.WGPresharedKey != "" {
		p.WGPresharedKey = redactedSecret
	}
	return p
}

// keepRedactedSecrets substitutes the stored value wherever the submitted one is
// the redaction placeholder. Called BEFORE validation, so a placeholder is never
// parsed as key material.
func keepRedactedSecrets(next *config.Proxy, stored config.Proxy) {
	if next.Password == redactedSecret {
		next.Password = stored.Password
	}
	if next.WGPrivateKey == redactedSecret {
		next.WGPrivateKey = stored.WGPrivateKey
	}
	if next.WGPresharedKey == redactedSecret {
		next.WGPresharedKey = stored.WGPresharedKey
	}
}

// proxyAuditDetail describes a proxy for the append-only audit trail WITHOUT any
// credential: the type, and the endpoint it dials. A tunnel reports its peer
// endpoint; a relay reports host:port.
func proxyAuditDetail(p config.Proxy) string {
	switch p.Type {
	case pcfg.ProxyTypeWireGuard:
		if p.WGEndpoint != "" {
			return "wireguard " + p.WGEndpoint
		}
		return "wireguard"
	default:
		if p.Host != "" && p.Port > 0 {
			return p.Type + " " + net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
		}
		return p.Type
	}
}

func (d Deps) handleListProxies(w http.ResponseWriter, r *http.Request) {
	proxies, err := d.Config.ListProxies(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]config.Proxy, 0, len(proxies))
	for _, p := range proxies {
		out = append(out, redactProxy(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (d Deps) handleCreateProxy(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	var body proxyBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxProxyBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p := body.toProxy()
	// A create has nothing stored to keep, so a placeholder here is a client bug
	// rather than "unchanged" — clear it so it can never be stored as a literal
	// password of bullet characters.
	clearRedactedPlaceholders(&p)
	if err := validateProxy(&p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := d.Config.CreateProxy(r.Context(), siteID, p)
	if err != nil {
		if errors.Is(err, config.ErrProxyNameTaken) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "proxy.create", id, p.Name+" · "+proxyAuditDetail(p))
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (d Deps) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	stored, err := d.Config.GetProxy(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "proxy not found")
		return
	}
	if stored.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "proxy not found")
		return
	}
	var body proxyBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxProxyBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p := body.toProxy()
	keepRedactedSecrets(&p, stored)
	if err := validateProxy(&p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A type switch (or a param edit) can invalidate the capability of monitors already
	// pinned to this proxy. UpdateProxy enforces that INSIDE its write transaction —
	// which is what makes it race-free against a concurrent target save — and rolls
	// back, so a rejected request leaves no terminated incidents behind.
	siteID, err := d.Config.UpdateProxy(r.Context(), id, p)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "proxy not found")
			return
		}
		if errors.Is(err, config.ErrProxyNameTaken) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		// Stranded monitors are a bad request naming what to fix, not a server fault.
		var stranded *config.ErrProxyStrandsTargets
		if errors.As(err, &stranded) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Disabling a proxy takes its pinned monitors out of service (they fail closed
	// rather than dialing directly), which strands their monitor_status and
	// operational-issue rows exactly like a scope narrowing does.
	if err := d.reconcileScope(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "proxy.update", id, p.Name+" · "+proxyAuditDetail(p))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d Deps) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	stored, err := d.Config.GetProxy(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "proxy not found")
		return
	}
	if stored.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "proxy not found")
		return
	}
	if _, err := d.Config.DeleteProxy(r.Context(), id); err != nil {
		// A proxy still in use is a CONFLICT, not a server fault: the response names
		// the occupying monitors so the operator knows what to unpin first.
		var inUse *config.ErrProxyInUse
		if errors.As(err, &inUse) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":    err.Error(),
				"monitors": inUse.Monitors,
				"used_by":  inUse.Total,
			})
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "proxy not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "proxy.delete", id, stored.Name+" · "+proxyAuditDetail(stored))
	w.WriteHeader(http.StatusNoContent)
}

// clearRedactedPlaceholders drops a submitted secret that is exactly the read
// placeholder. Used on create, where there is no stored value to fall back to.
func clearRedactedPlaceholders(p *config.Proxy) {
	if p.Password == redactedSecret {
		p.Password = ""
	}
	if p.WGPrivateKey == redactedSecret {
		p.WGPrivateKey = ""
	}
	if p.WGPresharedKey == redactedSecret {
		p.WGPresharedKey = ""
	}
}
