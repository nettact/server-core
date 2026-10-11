package ingest

import (
	"context"
	"log"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/config"
	"github.com/nettact/server-core/routehist"
	"github.com/nettact/server-core/store"
)

// splitTraces separates a packet's traceroutes into the diagnosis reports the
// agent ran on its own initiative (which keep their historic path into the
// trace-report store, untouched) and the scheduled sweeps of route monitors.
// A sweep is routed by its declared trigger AND a monitor id: one without the
// id cannot be filed under any monitor, so it keeps the diagnosis path, where
// it is stored as an unattached report exactly as any unknown trigger was.
func splitTraces(all []telemetry.TraceResult) (diag, route []telemetry.TraceResult) {
	if len(all) == 0 {
		return nil, nil
	}
	for _, tr := range all {
		if tr.TriggerReason == telemetry.TraceTriggerScheduled && tr.MonitorID != "" {
			route = append(route, tr)
		} else {
			diag = append(diag, tr)
		}
	}
	return diag, route
}

// applyRouteTraces admits scheduled sweeps the same way probe samples are
// admitted — the monitor must still belong to this site and to the sending
// agent's scope, be a route monitor, be enabled, and carry exactly the
// target's current generation — and hands the survivors to route history.
//
// A sweep that fails admission is dropped, and the packet is still acked:
// it is obsolete backlog (the monitor was edited, re-scoped or deleted while
// the sweep sat in the agent's outbox), and refusing the packet would only
// make the agent replay it forever. The check reads through the packet's own
// transaction, so a config edit cannot slip between check and write.
//
// Proxied sweeps are dropped as well: a route monitor never runs through a
// proxy, so a sweep claiming another path scope is not a route observation of
// this vantage point.
func (s *Service) applyRouteTraces(ctx context.Context, scope store.Scope, wtx store.WriteTx,
	p AgentPrincipal, results []telemetry.TraceResult, now time.Time) error {
	ids := make([]string, 0, len(results))
	for _, tr := range results {
		ids = append(ids, tr.MonitorID)
	}
	meta, err := s.probeMeta(ctx, wtx, p.AgentID, p.SiteID, dedupeStrings(ids))
	if err != nil {
		return err
	}
	kept := results[:0:0]
	for _, tr := range results {
		m, ok := meta[tr.MonitorID]
		if !ok || !m.Enabled || m.Kind != config.KindTrace || m.ConfigSerial != tr.ConfigSerial ||
			(tr.PathScope != "" && tr.PathScope != telemetry.TracePathDirect) || tr.EgressProxyID != "" {
			continue
		}
		kept = append(kept, tr)
	}
	if dropped := len(results) - len(kept); dropped > 0 {
		log.Printf("ingest: dropped %d obsolete or out-of-scope route sweeps from agent %s", dropped, p.AgentID)
	}
	if len(kept) == 0 {
		return nil
	}
	return routehist.ApplyTx(ctx, scope, wtx, s.ASN, p.AgentID, kept, now)
}
