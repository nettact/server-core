package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/audit"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/eventbus"
	"github.com/nettact/server-core/hostlive"
	"github.com/nettact/server-core/ingest"
	"github.com/nettact/server-core/inventory"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/registry"
	"github.com/nettact/server-core/site"
	"github.com/nettact/server-core/store"
)

// buildTestServer wires the minimal real services handleEnroll + handleTelemetry
// need against a throwaway SQLite DB and returns a running httptest.Server.
func buildTestServer(t *testing.T) (*httptest.Server, *registry.Service) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	siteSvc := site.New(db)
	if err := siteSvc.EnsureDefault(ctx); err != nil {
		t.Fatalf("ensure default site: %v", err)
	}
	reg := registry.New(db, 0)
	cfg := config.New(db, reg)
	if err := cfg.SeedDefaults(ctx, site.DefaultSiteID); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	bus := eventbus.New()
	metricsStore := metrics.New(db)
	ing := ingest.New(db, bus, metricsStore)

	h := Router(Deps{
		Registry:  reg,
		Ingest:    ing,
		Metrics:   metricsStore,
		Config:    cfg,
		Site:      siteSvc,
		Inventory: inventory.New(db),
		Audit:     audit.New(db),
		HostLive:  hostlive.New(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, reg
}

// enrollTestAgent mints a token and performs the real ed25519 enroll handshake,
// returning the agent's bearer token.
func enrollTestAgent(t *testing.T, srv *httptest.Server, reg *registry.Service) string {
	t.Helper()
	token, err := reg.CreateEnrollmentToken(context.Background(), site.DefaultSiteID, "test", time.Hour)
	if err != nil {
		t.Fatalf("create enroll token: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	nonceBytes := make([]byte, 32)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	req := enroll.EnrollRequest{
		SchemaVersion:   protocol.SchemaVersion,
		EnrollmentToken: token,
		PublicKey:       pub,
		Nonce:           nonce,
		Signature:       ed25519.Sign(priv, []byte(nonce)),
		Hostname:        "test-host",
		Platform:        "linux",
		AgentVersion:    "test",
	}
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("enroll POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll status %d: %s", resp.StatusCode, msg)
	}
	var er enroll.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode enroll resp: %v", err)
	}
	return er.AgentToken
}

// postTelemetry uploads a packet in the given wire format (gzip + Content-Type +
// Accept) exactly as the agent does, and returns the decoded ack.
func postTelemetry(t *testing.T, srv *httptest.Server, agentToken, format string, pkt telemetry.Packet) wire.Ack {
	t.Helper()
	raw, err := wire.MarshalPacket(pkt, format)
	if err != nil {
		t.Fatalf("marshal packet (%s): %v", format, err)
	}
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	_, _ = gz.Write(raw)
	_ = gz.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/telemetry", &body)
	req.Header.Set("Content-Type", format)
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", wire.ContentTypeProtobuf+", "+wire.ContentTypeJSON)
	req.Header.Set("Authorization", "Bearer "+agentToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("telemetry POST (%s): %v", format, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("telemetry status %d (%s): %s", resp.StatusCode, format, msg)
	}
	// The agent-style Accept prefers protobuf, so the ack should come back protobuf.
	respCT := resp.Header.Get("Content-Type")
	rawResp, _ := io.ReadAll(resp.Body)
	ack, err := wire.UnmarshalAck(rawResp, respCT)
	if err != nil {
		t.Fatalf("decode ack (%s, ct=%s): %v", format, respCT, err)
	}
	if wire.Negotiate(respCT) != wire.ContentTypeProtobuf {
		t.Errorf("expected protobuf ack (Accept preferred it), got Content-Type %q", respCT)
	}
	return ack
}

func testPacket(seq uint64) telemetry.Packet {
	now := time.Now().UTC().Truncate(time.Second)
	return telemetry.Packet{
		SchemaVersion:         protocol.SchemaVersion,
		AgentID:               "ignored-server-uses-token",
		SiteID:                site.DefaultSiteID,
		Sequence:              seq,
		SentAt:                now,
		ReportedConfigVersion: 0,
		Metrics: []telemetry.Metric{
			{TS: now, Kind: telemetry.ICMPRTTms, Target: "1.1.1.1", Layer: telemetry.HealthLayer("internet"), Value: 11.2, Unit: telemetry.UnitMs, Labels: map[string]string{"iface": "eth0"}},
		},
		Events: []telemetry.Event{
			{ID: "evt-" + base64.RawURLEncoding.EncodeToString([]byte{byte(seq)}), TS: now, Type: telemetry.EventProbeFailed, Severity: telemetry.SeverityWarn, Message: "probe failed"},
		},
	}
}

// TestTelemetryProtobufIngest drives the real router: enroll, then upload a
// protobuf packet exactly as the agent does, and assert it ingests and the ack
// round-trips. This exercises Content-Type decode negotiation + gzip + protobuf.
func TestTelemetryProtobufIngest(t *testing.T) {
	srv, reg := buildTestServer(t)
	agentToken := enrollTestAgent(t, srv, reg)

	ack := postTelemetry(t, srv, agentToken, wire.ContentTypeProtobuf, testPacket(1))
	if ack.HighestSequence != 1 {
		t.Errorf("protobuf: highest_sequence = %d, want 1", ack.HighestSequence)
	}
	if ack.ServerTime.IsZero() {
		t.Error("protobuf: ack server_time is zero")
	}
}

// TestTelemetryJSONFallback proves the pre-protobuf agent path still works: a
// JSON Content-Type is decoded server-side and ingests identically.
func TestTelemetryJSONFallback(t *testing.T) {
	srv, reg := buildTestServer(t)
	agentToken := enrollTestAgent(t, srv, reg)

	ack := postTelemetry(t, srv, agentToken, wire.ContentTypeJSON, testPacket(1))
	if ack.HighestSequence != 1 {
		t.Errorf("json: highest_sequence = %d, want 1", ack.HighestSequence)
	}
}

// TestTelemetryRejectsGzipBomb proves the decompressed body is bounded: a tiny
// gzip stream that inflates past the packet-size limit is rejected with 413
// rather than read fully into memory.
func TestTelemetryRejectsGzipBomb(t *testing.T) {
	srv, reg := buildTestServer(t)
	agentToken := enrollTestAgent(t, srv, reg)

	// ~9 MiB of a single byte compresses to a few KiB but exceeds maxPacketBytes
	// (8 MiB) once inflated.
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	for i := 0; i < 9; i++ {
		_, _ = gz.Write(chunk)
	}
	_ = gz.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/telemetry", &body)
	req.Header.Set("Content-Type", wire.ContentTypeJSON)
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+agentToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("gzip bomb: status = %d, want 413", resp.StatusCode)
	}
}

// TestTelemetryDedupAcrossFormats confirms the sequence watermark advances and
// dedups regardless of which format each packet used (format is a wire concern
// only; ingest sees identical decoded structs).
func TestTelemetryDedupAcrossFormats(t *testing.T) {
	srv, reg := buildTestServer(t)
	agentToken := enrollTestAgent(t, srv, reg)

	if ack := postTelemetry(t, srv, agentToken, wire.ContentTypeProtobuf, testPacket(1)); ack.HighestSequence != 1 {
		t.Fatalf("seq1 protobuf: got watermark %d", ack.HighestSequence)
	}
	if ack := postTelemetry(t, srv, agentToken, wire.ContentTypeJSON, testPacket(2)); ack.HighestSequence != 2 {
		t.Fatalf("seq2 json: got watermark %d", ack.HighestSequence)
	}
	// Re-send seq 1 (protobuf) — watermark must stay at 2 (idempotent dedup).
	if ack := postTelemetry(t, srv, agentToken, wire.ContentTypeProtobuf, testPacket(1)); ack.HighestSequence != 2 {
		t.Fatalf("replayed seq1: watermark regressed to %d, want 2", ack.HighestSequence)
	}
}
