package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/site"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The enrollment handshake tests drive handleEnroll through httptest so the
// HTTP surface — status codes, response body shape, token consumption — is the
// thing under test. The registry is real (SQLite) so the "refused enrollment
// must not consume the one-time token" contract is exercised end to end.

func newEnrollEnv(t *testing.T) (*store.DB, Deps) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	if err := site.New(db).EnsureDefault(ctx); err != nil {
		t.Fatalf("ensure default site: %v", err)
	}
	return db, Deps{Registry: registry.New(db, 0, nil), Audit: audit.New(db)}
}

func enrollRequest(t *testing.T, schema int, token string) enroll.EnrollRequest {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const nonce = "e-nonce"
	return enroll.EnrollRequest{
		SchemaVersion:   schema,
		PublicKey:       pub,
		Nonce:           nonce,
		Signature:       ed25519.Sign(priv, []byte(nonce)),
		EnrollmentToken: token,
		Hostname:        "e-host",
		Platform:        "linux",
		AgentVersion:    "test",
		Permissions:     permission.PermissionReport{},
	}
}

func postEnroll(t *testing.T, d Deps, req enroll.EnrollRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal enroll request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	d.handleEnroll(w, r)
	return w
}

// TestEnrollSchema7ServesLegacyShape (E1): a schema 7 enrollment succeeds, the
// HTTP response carries no enrollment_epoch key, the credential row still gets
// its generation (epoch 1 — the response merely cannot carry it), and the
// issued token authenticates normally.
func TestEnrollSchema7ServesLegacyShape(t *testing.T) {
	db, d := newEnrollEnv(t)
	ctx := context.Background()
	token, err := d.Registry.CreateEnrollmentToken(ctx, site.DefaultSiteID, "e7", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	w := postEnroll(t, d, enrollRequest(t, 7, token))
	if w.Code != http.StatusOK {
		t.Fatalf("schema 7 enroll status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "enrollment_epoch") {
		t.Errorf("schema 7 response carries the enrollment_epoch key: %s", body)
	}
	var resp enroll.EnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.AgentID == "" || resp.AgentToken == "" {
		t.Fatalf("response missing identity: %+v", resp)
	}
	if resp.EnrollmentEpoch != 0 {
		t.Errorf("decoded schema 7 response epoch = %d, want 0 (no key)", resp.EnrollmentEpoch)
	}
	// The credential row has generation 1 regardless of what the response could
	// carry — the generation is a server fact, the v7 shape just can't deliver
	// it.
	var epoch int64
	if err := db.QueryRowContext(ctx, `SELECT enrollment_epoch FROM agents WHERE id=?`, resp.AgentID).Scan(&epoch); err != nil {
		t.Fatalf("read agent epoch: %v", err)
	}
	if epoch != 1 {
		t.Errorf("credential row epoch = %d, want 1", epoch)
	}
	// The issued token authenticates: the session machinery depends on it.
	auth, err := d.Registry.AuthenticateAgent(ctx, resp.AgentToken)
	if err != nil || auth.AgentID != resp.AgentID {
		t.Fatalf("issued token auth = %+v, %v; want %q", auth, err, resp.AgentID)
	}
}

// TestEnrollSchema8CanonicalUnchanged (E2): a schema 8 enrollment produces the
// canonical response — enrollment_epoch key present — byte-for-byte what the
// previous encoder wrote (the JSON encoder appends one trailing newline).
func TestEnrollSchema8CanonicalUnchanged(t *testing.T) {
	_, d := newEnrollEnv(t)
	ctx := context.Background()
	token, err := d.Registry.CreateEnrollmentToken(ctx, site.DefaultSiteID, "e8", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	w := postEnroll(t, d, enrollRequest(t, protocol.SchemaVersion, token))
	if w.Code != http.StatusOK {
		t.Fatalf("schema 8 enroll status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	var resp enroll.EnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.EnrollmentEpoch != 1 {
		t.Errorf("schema 8 response epoch = %d, want 1", resp.EnrollmentEpoch)
	}
	want, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal reference: %v", err)
	}
	want = append(want, '\n')
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Errorf("schema 8 response bytes =\n%s\nwant\n%s", w.Body.Bytes(), want)
	}
}

// TestEnrollUnknownSchemaRefuses500 (E3): an unsupported schema is refused with
// HTTP 500 (never 4xx) and a body naming the mismatch — the discriminator the
// peer's downgrade retry keys on. The 500 shape matters: a 400 would read as a
// terminal rejection and the N+1 agent's retry would never fire.
func TestEnrollUnknownSchemaRefuses500(t *testing.T) {
	_, d := newEnrollEnv(t)
	ctx := context.Background()
	token, err := d.Registry.CreateEnrollmentToken(ctx, site.DefaultSiteID, "e9", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	w := postEnroll(t, d, enrollRequest(t, 9, token))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("schema 9 enroll status = %d, want 500; body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unsupported schema_version") {
		t.Errorf("schema 9 refusal body missing the discriminator: %s", w.Body.String())
	}
}

// TestEnrollMissingSchemaRefused (E4): a request whose schema version decodes
// to 0 (the field omitted) is refused fail-closed — never silently treated as
// the native schema.
func TestEnrollMissingSchemaRefused(t *testing.T) {
	_, d := newEnrollEnv(t)
	ctx := context.Background()
	token, err := d.Registry.CreateEnrollmentToken(ctx, site.DefaultSiteID, "e0", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	req := enrollRequest(t, 0, token)
	req.SchemaVersion = 0
	w := postEnroll(t, d, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("missing schema status = %d, want 500; body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unsupported schema_version 0") {
		t.Errorf("missing schema refusal = %s, want it to name 0", w.Body.String())
	}
}

// TestRefusedSchemaDoesNotConsumeToken (E5): an enrollment refused over an
// unknown schema leaves the one-time token spendable — the agent's downgrade
// retry depends on re-enrolling with the other schema using the SAME token.
func TestRefusedSchemaDoesNotConsumeToken(t *testing.T) {
	_, d := newEnrollEnv(t)
	ctx := context.Background()
	token, err := d.Registry.CreateEnrollmentToken(ctx, site.DefaultSiteID, "e5", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	first := postEnroll(t, d, enrollRequest(t, 9, token))
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("first (schema 9) status = %d, want 500", first.Code)
	}
	second := postEnroll(t, d, enrollRequest(t, protocol.SchemaVersion, token))
	if second.Code != http.StatusOK {
		t.Fatalf("second (schema 8) status = %d, want 200; body %s", second.Code, second.Body.String())
	}
}

// TestEnrollSchema7ReinstallServesLegacyShape (E6): the reinstall branch
// (token bound to an existing agent) goes through the same response encoder —
// a schema 7 reinstall gets 200 and no enrollment_epoch key.
func TestEnrollSchema7ReinstallServesLegacyShape(t *testing.T) {
	db, d := newEnrollEnv(t)
	ctx := context.Background()
	// A prior schema 8 enrollment establishes the agent.
	token, err := d.Registry.CreateEnrollmentToken(ctx, site.DefaultSiteID, "e6-first", time.Hour)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	w := postEnroll(t, d, enrollRequest(t, protocol.SchemaVersion, token))
	if w.Code != http.StatusOK {
		t.Fatalf("first enroll status = %d; body %s", w.Code, w.Body.String())
	}
	var first enroll.EnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first response: %v", err)
	}

	reToken, err := d.Registry.CreateReinstallToken(ctx, first.AgentID, time.Hour)
	if err != nil {
		t.Fatalf("CreateReinstallToken: %v", err)
	}
	w2 := postEnroll(t, d, enrollRequest(t, 7, reToken))
	if w2.Code != http.StatusOK {
		t.Fatalf("schema 7 reinstall status = %d, want 200; body %s", w2.Code, w2.Body.String())
	}
	if strings.Contains(w2.Body.String(), "enrollment_epoch") {
		t.Errorf("schema 7 reinstall response carries the enrollment_epoch key: %s", w2.Body.String())
	}
	var epoch int64
	if err := db.QueryRowContext(ctx, `SELECT enrollment_epoch FROM agents WHERE id=?`, first.AgentID).Scan(&epoch); err != nil {
		t.Fatalf("read agent epoch: %v", err)
	}
	if epoch != 2 {
		t.Errorf("reinstall epoch = %d, want 2", epoch)
	}
}
