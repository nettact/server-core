package ingest

import (
	"context"
	"strings"
	"testing"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

// TestPrepareRequiresNegotiatedSchema (I2): an admission principal with no wire
// schema is refused, fail closed. Zero never silently means "the native
// schema" — an unfilled principal is the admission layer not having spoken,
// and admitting it would unpin the session the packet's series identity
// depends on.
func TestPrepareRequiresNegotiatedSchema(t *testing.T) {
	s := &Service{}
	pkt := charPacket(1, nil)
	_, err := s.Prepare(context.Background(),
		AgentPrincipal{AgentID: "agent_a", SiteID: "site_default", EnrollmentEpoch: 1}, pkt)
	if err == nil {
		t.Fatal("Prepare with WireSchema=0 succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), "no wire schema") {
		t.Errorf("zero-schema error = %v, want it to name the missing schema", err)
	}
}

// TestPrepareRequiresExactWireSchema (I1): the packet's declared schema must
// EQUAL the session's negotiated schema — an equality check, not a membership
// check, and not a range. A schema 7 session with a schema 7 packet passes the
// gate; a native (schema 8) session with a schema 7 packet is refused as a
// mismatch.
func TestPrepareRequiresExactWireSchema(t *testing.T) {
	h := newCharHarness(t, tsstoretest.Open(t))
	svc := New(h.db, h.bus, h.m, nil, nil, nil)
	ctx := context.Background()

	// Negotiated 7, packet declares 7: the gate passes and Prepare completes.
	p7 := applyPrincipal()
	p7.WireSchema = 7
	pkt7 := charPacket(1, nil)
	pkt7.SchemaVersion = 7
	in, err := svc.Prepare(ctx, p7, pkt7)
	if err != nil {
		t.Fatalf("schema 7 session, schema 7 packet: %v", err)
	}
	defer in.ReleasePending()

	// Negotiated 8 (native), packet declares 7: refused as a mismatch.
	_, err = svc.Prepare(ctx, applyPrincipal(), pkt7)
	if err == nil {
		t.Fatal("native session, schema 7 packet succeeded, want a mismatch refusal")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("mismatch error = %v, want it to name the mismatch", err)
	}

	// The same packet under a schema 7 session is not refused — the equality is
	// against the session, not against any fixed set of "known" schemas.
	if _, err := svc.Prepare(ctx, p7, telemetry.Packet{SchemaVersion: 8}); err == nil {
		t.Fatal("schema 7 session, schema 8 packet succeeded, want a mismatch refusal")
	}
}
