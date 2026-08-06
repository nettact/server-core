package ingest

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/baseline"
	"github.com/nettact/server-core/fault"
)

// degRound builds one healthy ICMP round's metrics at ts.
func degRound(ts int64) []telemetry.Metric {
	return []telemetry.Metric{
		{TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPLoss, Target: "192.168.1.1",
			Value: 0, Unit: telemetry.UnitPct, MonitorID: "t1", ConfigSerial: 3},
		{TS: time.Unix(ts, 0).UTC(), Kind: telemetry.ICMPRTTms, Target: "192.168.1.1",
			Value: 42, Unit: telemetry.UnitMs, MonitorID: "t1", ConfigSerial: 3},
	}
}

func degMetaMap(det fault.DetectionSettings) map[string]fault.TargetMeta {
	return map[string]fault.TargetMeta{
		"t1": {ID: "t1", Kind: "icmp", Name: "Router", Addr: "192.168.1.1",
			Enabled: true, ConfigSerial: 3, Det: det.Normalize()},
	}
}

func TestBandRequestsUseTheRoundsOwnBucket(t *testing.T) {
	// Two rounds a day apart in different dayparts. A lookup keyed off the wall
	// clock would ask about the same bucket twice and compare last night's latency
	// against this morning's normal.
	early := time.Date(2026, 3, 4, 2, 0, 0, 0, time.Local).Unix()    // daypart 0
	evening := time.Date(2026, 3, 4, 21, 0, 0, 0, time.Local).Unix() // daypart 3
	ms := append(degRound(early), degRound(evening)...)
	rounds := fault.BuildRounds(ms, degMetaMap(fault.DefaultDetection()))
	if len(rounds) != 2 {
		t.Fatalf("built %d rounds, want 2", len(rounds))
	}
	reqs := bandRequests(rounds)
	// Two metrics (rtt + loss) × two dayparts.
	if len(reqs) != 4 {
		t.Fatalf("requested %d bands, want 4: %v", len(reqs), reqs)
	}
	for k, serial := range reqs {
		if serial != 3 {
			t.Fatalf("band %v pinned to generation %d, want the round's own 3", k, serial)
		}
		if k.Daypart != 0 && k.Daypart != 3 {
			t.Fatalf("unexpected daypart %d", k.Daypart)
		}
	}
}

func TestBandRequestsEmptyWhenSmartOff(t *testing.T) {
	det := fault.DefaultDetection()
	det.SmartEnabled = false
	rounds := fault.BuildRounds(degRound(time.Now().Unix()), degMetaMap(det))
	if got := bandRequests(rounds); got != nil {
		t.Fatalf("requested %v with smart detection off", got)
	}
}

func TestAttachBaselinesOnlyMatchesTheRoundsBucket(t *testing.T) {
	ts := time.Date(2026, 3, 4, 21, 0, 0, 0, time.Local).Unix()
	rounds := fault.BuildRounds(degRound(ts), degMetaMap(fault.DefaultDetection()))
	_, daypart, weekend := baseline.BucketOf(ts)
	band := baseline.Band{P50: 40, P95: 45, Days: 7, Samples: 900}

	// A band for a DIFFERENT daypart must not be attached: it is the answer to a
	// question about a different time of day.
	attachBaselines(rounds, map[baseline.BandKey]baseline.Band{
		{TargetID: "t1", MetricKind: string(telemetry.ICMPRTTms), Daypart: (daypart + 1) % 4, Weekend: weekend}: band,
	})
	if rounds[0].Baselines != nil {
		t.Fatalf("attached a band from another daypart: %v", rounds[0].Baselines)
	}

	attachBaselines(rounds, map[baseline.BandKey]baseline.Band{
		{TargetID: "t1", MetricKind: string(telemetry.ICMPRTTms), Daypart: daypart, Weekend: weekend}: band,
	})
	if got := rounds[0].Baselines[string(telemetry.ICMPRTTms)]; got != band {
		t.Fatalf("band = %+v, want %+v", got, band)
	}
}
