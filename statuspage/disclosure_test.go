package statuspage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nettact/server-core/agentstatus"
	"github.com/nettact/server-core/metrics"
)

// What a published node and a published target are allowed to say.
//
// These assertions sit on the DTO mapping rather than on HTTP, because the mapping
// IS the boundary: the endpoint gets no second chance to redact a field the
// mapping already returned. api/statuspage_test.go covers the wire shape; this
// covers the decision.

// fullResources is one agent reporting every host family, with values distinct
// enough that a field landing in the wrong slot is obvious.
func fullResources() agentstatus.Resources {
	diskAggregatePct := 280_000_000_000.0 / 460_000_000_000.0 * 100
	return agentstatus.Resources{
		CPU:    &agentstatus.ScalarSample{Value: 12.5, Unit: "pct"},
		Load:   &agentstatus.LoadSample{Load1: 0.42, Load5: 0.31, Load15: 0.28},
		Memory: &agentstatus.MemSample{Pct: 48, Used: 8_160_000_000, Total: 17_000_000_000},
		Disk: &agentstatus.DiskSample{
			Pct: 82, AggregatePct: &diskAggregatePct, Used: 280_000_000_000, Total: 460_000_000_000,
			Mount: "/mnt/backup-nas", Mounts: 3,
		},
		Net:    &agentstatus.NetSample{RxBps: 1_200_000, TxBps: 340_000},
		Uptime: &agentstatus.ScalarSample{Value: 1_051_200, Unit: "s"},
	}
}

// TestPublicResourcesDisclosureGate is the whole point of the agent_metrics enum:
// each level publishes strictly more than the one below it, and "basic" must not
// disclose a single byte figure or filesystem path.
func TestPublicResourcesDisclosureGate(t *testing.T) {
	r := fullResources()

	if got := publicResources(r, AgentMetricsOff); got != nil {
		t.Fatalf("agent_metrics=off published %+v, want nothing at all", got)
	}

	basic := publicResources(r, AgentMetricsBasic)
	if basic == nil {
		t.Fatal("agent_metrics=basic published nothing")
	}
	// Present: how the node is doing.
	for name, got := range map[string]*float64{
		"cpu_pct": basic.CPUPct, "mem_pct": basic.MemPct, "disk_pct": basic.DiskPct,
		"disk_aggregate_pct": basic.DiskAggregatePct,
		"rx_bps":             basic.RxBps, "tx_bps": basic.TxBps, "uptime_s": basic.UptimeSec,
	} {
		if got == nil {
			t.Errorf("basic omitted %s, which is not machine detail", name)
		}
	}
	if basic.Load == nil || *basic.Load != [3]float64{0.42, 0.31, 0.28} {
		t.Errorf("basic load = %v, want 1/5/15 in that order", basic.Load)
	}
	if basic.DiskPct == nil || *basic.DiskPct != r.Disk.Pct {
		t.Errorf("basic legacy disk pct = %v, want %v", basic.DiskPct, r.Disk.Pct)
	}
	if basic.DiskAggregatePct == nil || *basic.DiskAggregatePct != *r.Disk.AggregatePct {
		t.Errorf("basic disk aggregate = %v, want %v", basic.DiskAggregatePct, *r.Disk.AggregatePct)
	}
	// Absent: what the node is made of.
	if basic.MemUsed != nil || basic.MemTotal != nil || basic.DiskUsed != nil || basic.DiskTotal != nil {
		t.Errorf("basic leaked byte totals: %+v", basic)
	}
	full := publicResources(r, AgentMetricsFull)
	if full == nil {
		t.Fatal("agent_metrics=full published nothing")
	}
	if full.MemUsed == nil || *full.MemUsed != 8_160_000_000 || full.MemTotal == nil {
		t.Errorf("full omitted the memory totals: %+v", full)
	}
	if full.DiskUsed == nil || full.DiskTotal == nil {
		t.Errorf("full omitted the disk detail: %+v", full)
	}
}

// Filesystem names and counts are internal topology. Even full resource
// disclosure publishes capacity figures only; it never identifies a volume.
func TestPublicResourcesNeverExposeFilesystemLayout(t *testing.T) {
	got := publicResources(fullResources(), AgentMetricsFull)
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"disk_mount", "disk_mounts"} {
		if strings.Contains(string(body), field) {
			t.Errorf("full resources leaked %q: %s", field, body)
		}
	}
}

// TestPublicResourcesKeepsDeniedFamiliesAbsent: host metrics are permission-gated
// per agent, so a denied family has no samples at all. It must arrive as a gap,
// never as a zero — "0% CPU" and "not permitted to say" are different claims, and a
// status page that confuses them is publishing a falsehood.
func TestPublicResourcesKeepsDeniedFamiliesAbsent(t *testing.T) {
	only := agentstatus.Resources{CPU: &agentstatus.ScalarSample{Value: 7}}
	got := publicResources(only, AgentMetricsFull)
	if got == nil || got.CPUPct == nil || *got.CPUPct != 7 {
		t.Fatalf("cpu missing: %+v", got)
	}
	if got.MemPct != nil || got.DiskPct != nil || got.DiskAggregatePct != nil || got.RxBps != nil || got.Load != nil || got.UptimeSec != nil {
		t.Fatalf("a denied family was published as a value: %+v", got)
	}
	// Nothing reported at all: the object itself goes away, so a renderer is not
	// handed an empty shell to draw six blank gauges from.
	if got := publicResources(agentstatus.Resources{}, AgentMetricsFull); got != nil {
		t.Fatalf("an agent with no host data published %+v, want nothing", got)
	}
}

// TestPublicResourcesStaleIsSticky: one frozen family makes the node stale. A node
// whose memory reading stopped an hour ago is not "current except for memory" — it
// is a node the reader should not trust, and the page dims the whole row.
func TestPublicResourcesStaleIsSticky(t *testing.T) {
	r := fullResources()
	r.Memory.Stale = true
	got := publicResources(r, AgentMetricsBasic)
	if got == nil || !got.Stale {
		t.Fatalf("one stale family did not mark the node stale: %+v", got)
	}
	if got := publicResources(fullResources(), AgentMetricsBasic); got.Stale {
		t.Fatal("all-fresh readings were marked stale")
	}
}

// TestAgentMetricsValidation: the enum is a whitelist. A typo is rejected rather
// than coerced in either direction — quietly reading "bacis" as "off" would hide
// nodes the operator published, and reading it as "full" would disclose more than
// they asked for.
func TestAgentMetricsValidation(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()

	spec := fullSpec()
	spec.AgentMetrics = "bacis"
	if _, err := svc.Create(ctx, "site_default", spec); !errors.Is(err, ErrBadSpec) {
		t.Fatalf("create with a bad agent_metrics: err=%v, want ErrBadSpec", err)
	}

	for _, mode := range []string{AgentMetricsOff, AgentMetricsBasic, AgentMetricsFull} {
		spec := fullSpec()
		spec.Slug, spec.AgentMetrics = "p-"+mode, mode
		page, err := svc.Create(ctx, "site_default", spec)
		if err != nil {
			t.Fatalf("create %s: %v", mode, err)
		}
		if page.AgentMetrics != mode {
			t.Fatalf("stored agent_metrics = %q, want %q", page.AgentMetrics, mode)
		}
	}
}

// TestPublicAgentStatusesRespectsMetricsGate walks the gate through the real read,
// confirming the PAGE's setting decides — not a caller's argument, and not the
// frontend declining to render.
func TestPublicAgentStatusesRespectsMetricsGate(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()

	spec := fullSpec()
	spec.AgentMetrics = AgentMetricsOff
	if _, err := svc.Create(ctx, "site_default", spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.PublicAgentStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("PublicAgentStatuses: %v", err)
	}
	if len(got.Agents) == 0 {
		t.Fatal("no agents published")
	}
	for _, a := range got.Agents {
		if a.Resources != nil {
			t.Fatalf("agent %q published resources under agent_metrics=off: %+v", a.Name, a.Resources)
		}
	}
}

// TestPublicTargetStatusesAlwaysCarriesEveryWindow: the page renders a fixed set of
// columns, so a target with no history yet must still return all five windows in
// order and a full-length strip. Ragged rows would misalign the whole board.
func TestPublicTargetStatusesAlwaysCarriesEveryWindow(t *testing.T) {
	svc, _ := newFixture(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, "site_default", fullSpec()); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := svc.PublicTargetStatuses(ctx, "home")
	if err != nil {
		t.Fatalf("PublicTargetStatuses: %v", err)
	}
	if len(got.Targets) == 0 {
		t.Fatal("no targets published")
	}
	if got.DaysFrom == "" {
		t.Fatal("days_from is empty; the bar has no dates to label")
	}
	for _, tg := range got.Targets {
		if len(tg.Availability) != len(PublicAvailabilityWindows) {
			t.Fatalf("target %q has %d windows, want %d", tg.Name, len(tg.Availability), len(PublicAvailabilityWindows))
		}
		for i, w := range PublicAvailabilityWindows {
			if tg.Availability[i].Window != w.Token {
				t.Fatalf("window %d = %q, want %q — this order IS the page's column order",
					i, tg.Availability[i].Window, w.Token)
			}
			// No history in the fixture: unknown, and unknown is not 0%.
			if tg.Availability[i].Ratio != nil {
				t.Fatalf("window %s reported %v with no probe history, want null",
					w.Token, *tg.Availability[i].Ratio)
			}
		}
		if len(tg.Days) != metrics.DailyCells {
			t.Fatalf("target %q strip is %d cells, want %d", tg.Name, len(tg.Days), metrics.DailyCells)
		}
		for i, day := range tg.Days {
			if day.Ratio != nil || day.Rounds != 0 || day.OKRounds != 0 {
				t.Fatalf("target %q day %d = %+v with no probe history, want an empty summary", tg.Name, i, day)
			}
		}
	}
}
