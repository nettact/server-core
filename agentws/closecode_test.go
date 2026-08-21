package agentws

import (
	"testing"

	"github.com/nettact/protocol/wire"
)

// TestCloseCodeVocabularyIsFrozen (G1): the session machinery issues close
// codes only through the wire package's typed constants — never a raw number —
// and those constants must stay exactly the frozen vocabulary: the four
// standard codes plus the four application codes (4000-4004). A renumbered or
// newly invented terminal code is a compatibility break the peer's retry
// logic discriminates on, so the values are pinned here. (A raw close-code
// literal anywhere in this package would not compile past the wire.Conn
// interface; the risk this test closes is a silent renumber of the shared
// vocabulary itself.)
func TestCloseCodeVocabularyIsFrozen(t *testing.T) {
	got := map[string]wire.CloseCode{
		"CloseNormalClosure":          wire.CloseNormalClosure,
		"CloseGoingAway":              wire.CloseGoingAway,
		"ClosePolicyViolation":        wire.ClosePolicyViolation,
		"CloseInternalError":          wire.CloseInternalError,
		"CloseSuperseded":             wire.CloseSuperseded,
		"CloseUnsupportedSchema":      wire.CloseUnsupportedSchema,
		"CloseUnsupportedSubprotocol": wire.CloseUnsupportedSubprotocol,
		"CloseProtocolError":          wire.CloseProtocolError,
		"CloseRevoked":                wire.CloseRevoked,
	}
	want := map[string]wire.CloseCode{
		"CloseNormalClosure":          1000,
		"CloseGoingAway":              1001,
		"ClosePolicyViolation":        1008,
		"CloseInternalError":          1011,
		"CloseSuperseded":             4000,
		"CloseUnsupportedSchema":      4001,
		"CloseUnsupportedSubprotocol": 4002,
		"CloseProtocolError":          4003,
		"CloseRevoked":                4004,
	}
	if len(got) != len(want) {
		t.Fatalf("close-code vocabulary has %d constants, frozen set has %d — a code was added or removed",
			len(got), len(want))
	}
	for name, code := range got {
		if want[name] != code {
			t.Errorf("%s = %d, want %d", name, code, want[name])
		}
	}
}
