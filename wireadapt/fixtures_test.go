package wireadapt

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/wire"
)

// The golden fixtures in testdata are the frozen wire shapes this registry
// serves: a schema 7 and a schema 8 Hello as they arrive over the wire, the
// same-shaped enrollment requests, the schema 7 enrollment response (which must
// not carry the enrollment_epoch key), and the exact refusal body for an
// unsupported schema. They are driven through the real codec where the wire
// has one — the Hello frames go through wire.UnmarshalFrame so the byte-level
// decode -> accept round trip runs in this package, not just the hub — and
// their byte forms are the truth the adapters must reproduce. Trailing
// whitespace is stripped before comparison so the files stay readable.

// consumed tracks every fixture file actually loaded by the tests below, so a
// fixture that lands in testdata but is never executed fails the G2 guard.
var consumed = struct {
	sync.Mutex
	set map[string]bool
}{set: map[string]bool{}}

func markConsumed(t *testing.T, name string) {
	t.Helper()
	consumed.Lock()
	defer consumed.Unlock()
	consumed.set[name] = true
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	markConsumed(t, name)
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// TestHelloFixturesRoundTripThroughTheCodec (A8, hello half): the frozen Hello
// frames decode through the real codec and are admitted by their schema's
// adapter. This is the byte-level decode -> accept path the plan runs in this
// package instead of the hub.
func TestHelloFixturesRoundTripThroughTheCodec(t *testing.T) {
	cases := []struct {
		file   string
		schema int
	}{
		{"hello_v7.json", 7},
		{"hello_v8.json", 8},
	}
	for _, c := range cases {
		data := readFixture(t, c.file)
		f, err := wire.UnmarshalFrame(bytes.TrimSpace(data), wire.ContentTypeJSON)
		if err != nil {
			t.Fatalf("%s: unmarshal: %v", c.file, err)
		}
		if f.Hello == nil {
			t.Fatalf("%s: decoded frame carries no Hello", c.file)
		}
		if f.Hello.SchemaVersion != c.schema {
			t.Errorf("%s: hello schema = %d, want %d", c.file, f.Hello.SchemaVersion, c.schema)
		}
		a, ok := Lookup(c.schema)
		if !ok {
			t.Fatalf("%s: Lookup(%d) miss", c.file, c.schema)
		}
		if err := a.ValidateHello(*f.Hello); err != nil {
			t.Errorf("%s: ValidateHello: %v", c.file, err)
		}
		if err := a.AcceptUplink(f); err != nil {
			t.Errorf("%s: AcceptUplink: %v", c.file, err)
		}
	}
}

// TestEnrollRequestsAreSameShapedAcrossSchemas (A8, enrollment request half):
// the two schema enrollment requests are byte-different only in the
// schema_version value — schema 8 added a field to the RESPONSE, never to the
// request — and each is accepted by its own adapter. Both are refused by the
// other adapter's membership check, which is what the fail-closed guard is for.
func TestEnrollRequestsAreSameShapedAcrossSchemas(t *testing.T) {
	var req7, req8 enroll.EnrollRequest
	if err := json.Unmarshal(readFixture(t, "enroll_request_v7.json"), &req7); err != nil {
		t.Fatalf("enroll_request_v7.json: %v", err)
	}
	if err := json.Unmarshal(readFixture(t, "enroll_request_v8.json"), &req8); err != nil {
		t.Fatalf("enroll_request_v8.json: %v", err)
	}
	if req7.SchemaVersion != 7 || req8.SchemaVersion != 8 {
		t.Fatalf("fixtures carry schema %d/%d, want 7/8", req7.SchemaVersion, req8.SchemaVersion)
	}
	// Same shape: the non-version fields are identical.
	req8.SchemaVersion = req7.SchemaVersion
	a, _ := json.Marshal(req7)
	b, _ := json.Marshal(req8)
	if !bytes.Equal(a, b) {
		t.Errorf("enrollment requests differ beyond schema_version:\n7: %s\n8: %s", a, b)
	}

	a7, _ := Lookup(7)
	a8, _ := Lookup(8)
	req7.SchemaVersion, req8.SchemaVersion = 7, 8
	if _, err := a7.AcceptEnrollRequest(req7); err != nil {
		t.Errorf("schema 7 request on its own adapter: %v", err)
	}
	if _, err := a8.AcceptEnrollRequest(req8); err != nil {
		t.Errorf("schema 8 request on its own adapter: %v", err)
	}
	if _, err := a8.AcceptEnrollRequest(req7); err == nil {
		t.Error("schema 7 request accepted by the schema 8 adapter, want refusal")
	}
	if _, err := a7.AcceptEnrollRequest(req8); err == nil {
		t.Error("schema 8 request accepted by the schema 7 adapter, want refusal")
	}
}

// TestEnrollResponseV7Shape (A8, enrollment response half): the schema 7
// response is byte-frozen — it must not carry the enrollment_epoch key, which
// is exactly the difference from the canonical schema 8 response. The fixture
// pins the whole v7 shape; the "no key" property is asserted on the raw bytes
// so a future field that happens to be zero can't slip through a struct-level
// comparison.
func TestEnrollResponseV7Shape(t *testing.T) {
	want := bytes.TrimSpace(readFixture(t, "enroll_response_v7.json"))
	resp := enroll.EnrollResponse{
		AgentID:         "agent_fixture",
		SiteID:          "site_default",
		AgentToken:      "fixture-agent-token",
		ServerTime:      time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC),
		ConfigVersion:   3,
		EnrollmentEpoch: 7, // non-zero on purpose: the v7 encoder must drop it anyway
	}
	a7, _ := Lookup(7)
	got, err := a7.EncodeEnrollResponse(resp)
	if err != nil {
		t.Fatalf("v7 encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("v7 response bytes =\n%s\nwant (fixture)\n%s", got, want)
	}
	if bytes.Contains(got, []byte("enrollment_epoch")) {
		t.Errorf("v7 response carries the enrollment_epoch key: %s", got)
	}

	// The canonical schema 8 encoder DOES carry the key — that is the schema-8
	// half of the same boundary.
	a8, _ := Lookup(8)
	got8, err := a8.EncodeEnrollResponse(resp)
	if err != nil {
		t.Fatalf("v8 encode: %v", err)
	}
	if !bytes.Contains(got8, []byte("enrollment_epoch")) {
		t.Errorf("v8 response lost the enrollment_epoch key: %s", got8)
	}
}

// TestRefusalShape (A8, refusal half): the refusal body for an unsupported
// schema is frozen — the downgrade retry on the other side keys on the 5xx
// status plus this substring, so the body must keep naming the mismatch and
// stay comfortably inside the peer's 4096-byte read bound.
func TestRefusalShape(t *testing.T) {
	want := bytes.TrimSpace(readFixture(t, "refusal_v9.json"))
	got := UnsupportedSchema(9).Error()
	if got != string(want) {
		t.Errorf("refusal = %q, want (fixture) %q", got, want)
	}
	if !strings.Contains(got, "unsupported schema_version") {
		t.Errorf("refusal %q lost the discriminator substring", got)
	}
	if len(got) >= 4096 {
		t.Errorf("refusal body is %d bytes, want < 4096", len(got))
	}
}

// TestEveryFixtureIsConsumed (G2): no fixture file may sit in testdata unused.
// A frozen golden shape nobody executes is the same as no fixture at all.
func TestEveryFixtureIsConsumed(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("list testdata: %v", err)
	}
	consumed.Lock()
	defer consumed.Unlock()
	for _, e := range entries {
		if !e.IsDir() && !consumed.set[e.Name()] {
			t.Errorf("fixture %s is never consumed by any test", e.Name())
		}
	}
}
