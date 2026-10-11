package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/nettact/protocol/wire"
	"github.com/nettact/server-core/store"
)

// KindTrace is the periodic route-monitor probe kind. Named because several
// packages branch on it: it is pushed only to agents that declared
// wire.CapProbeTraceV1, has no availability verdict, and its sweeps feed route
// history instead of the metric-driven detectors.
const KindTrace = "trace"

// ReasonAgentUpgradeRequired is the monitor-status reason recorded for a
// capability-gated monitor on an agent whose build does not declare the
// capability. Unlike every other block reason it is decided by the server, not
// reported by the agent — the monitor is never pushed to such an agent, so no
// report will ever arrive to confirm or overturn it — and readers therefore
// treat it as authoritative even on a predicted row.
const ReasonAgentUpgradeRequired = "agent_upgrade_required"

// RequiredCapability returns the Hello capability an agent must have declared
// to be sent a target of the given kind, or "" when the kind predates
// capability negotiation.
//
// Why a capability and not a permission: permissions are evaluated by the
// agent, against requirements the AGENT computes for the kind. A build that
// predates a kind has no requirement for it, so it would classify the monitor
// active, report so, and then never run it — the console would show a running
// monitor that never produces data. Only the server can withhold what an old
// build does not understand, and the capability list is how the agent says
// what it understands.
func RequiredCapability(kind string) string {
	if kind == KindTrace {
		return wire.CapProbeTraceV1
	}
	return ""
}

// KindSupportedBy reports whether an agent with the declared capabilities can
// be sent a target of the given kind.
func KindSupportedBy(kind string, caps []string) bool {
	need := RequiredCapability(kind)
	return need == "" || wire.HasCapability(caps, need)
}

// DecodeCapabilities parses the agents.capabilities column. A malformed value
// decodes as "declares nothing", the fail-safe reading: a gated kind is then
// withheld until the next Hello rewrites the column.
func DecodeCapabilities(raw string) []string {
	var caps []string
	if raw == "" || json.Unmarshal([]byte(raw), &caps) != nil {
		return nil
	}
	return caps
}

// AgentCapabilities reads one agent's stored capability list. A missing agent
// reads as declaring nothing.
func AgentCapabilities(ctx context.Context, q store.Executor, agentID string) ([]string, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT COALESCE(capabilities,'[]') FROM agents WHERE id=?`, agentID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return DecodeCapabilities(raw), nil
}
