package fault

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// A fluctuation is a failing streak that recovered before it could confirm a
// fault: the target failed 1..N-1 consecutive rounds and then answered again.
//
// It exists because of a gap the availability figure exposes but nothing else
// explained. A single failed round out of a hundred shows up as 99% availability,
// yet the fault centre is empty: the streak never reached the confirmation
// threshold, and the recovering round wipes fail_rounds and first_fail_ts from
// detector_state (engine.go's success branch), leaving no trace of when it
// happened or why. The raw 0 sample in probe.round.ok survives for two days and
// carries no cause at all. So the dip was real, visible, and unexplainable —
// which is the one thing a monitoring product must not do.
//
// A fluctuation is therefore materialised at the moment of recovery, with the
// cause of EVERY failing round frozen into it, and it is recorded only: it never
// notifies and never opens an incident of its own. Two failures out of a hundred
// rounds is not an outage, and paging someone about it would train them to
// ignore the alerts that matter.
//
// One exception ties the two together: when a later fault IS confirmed on the
// same target and agent, the fluctuations that led up to it stop being trivia and
// become that incident's precursor evidence (see linkPrecursors). Those are
// exempt from retention and are deleted with the incident.

// fluctuationLinkWindow is how far back a newly confirmed fault looks for its own
// precursors. An hour is long enough to catch the "it was flapping all morning
// and then died" pattern that makes a fault legible, and short enough that an
// unrelated blip from yesterday is not presented as a warning sign.
const fluctuationLinkWindow = time.Hour

// FailEvidence is one failing round's frozen cause. Stored as a JSON array in
// both detector_state.pending_fails (the streak in progress) and the
// rounds_json column of fluctuations and fault_signals (the streak, frozen), so
// a fault and a fluctuation explain themselves the same way.
type FailEvidence struct {
	TS           int64   `json:"ts"` // the round's timestamp, epoch seconds
	MetricKind   string  `json:"metric_kind"`
	Value        float64 `json:"value"`
	ReasonCode   int     `json:"reason_code"` // telemetry.ProbeReason*
	ReasonDetail string  `json:"reason_detail"`
}

// Fluctuation is one recorded sub-threshold streak. Every display fact is frozen
// at recovery time, exactly as a Signal's are at confirmation time.
type Fluctuation struct {
	ID         string `json:"id"`
	SiteID     string `json:"site_id"`
	AgentID    string `json:"agent_id"`
	AgentName  string `json:"agent_name"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	TargetAddr string `json:"target_addr"`
	Port       int    `json:"target_port,omitempty"`
	ProbeKind  string `json:"probe_kind"`
	GroupID    string `json:"group_id,omitempty"`
	Layer      string `json:"layer"`
	// DetectorKey names which detector recorded the streak, in the same vocabulary
	// as a signal's (see detector_state.detector_key). Without it a system-status
	// dip and an availability dip on the same host anchor are indistinguishable.
	DetectorKey string `json:"detector_key"`
	// FailRounds is how many consecutive rounds failed; FailThreshold is the
	// sensitivity it did not reach. Rendered together as "2 of 3", which tells the
	// operator both what happened and why no fault was raised.
	FailRounds    int     `json:"fail_rounds"`
	FailThreshold int     `json:"fail_threshold"`
	MetricKind    string  `json:"metric_kind"`
	Comparator    string  `json:"comparator"`
	Value         float64 `json:"value"`
	Threshold     float64 `json:"threshold"`
	ReasonCode    int     `json:"reason_code"`
	ReasonDetail  string  `json:"reason_detail"`
	// Rounds is every failing round of the streak, oldest first.
	Rounds    []FailEvidence `json:"rounds"`
	StartedAt time.Time      `json:"started_at"`
	EndedAt   time.Time      `json:"ended_at"`
	// IncidentID is set when a later fault on the same target+agent claimed this
	// fluctuation as a precursor; "" while unlinked.
	IncidentID string `json:"incident_id,omitempty"`
	// ConcurrentTargets is a read-time overlay, not stored: how many OTHER targets on
	// the same Agent were also failing over this fluctuation's window. It answers the
	// question the record raises — was this the link, or was it just this target?
	//
	// It is a DISTINCT count over both kinds of trouble, which is why the caller must
	// use it instead of adding the two breakdowns below: a neighbour that dipped and
	// then failed outright appears in both, and is still one other target.
	ConcurrentTargets int `json:"concurrent_targets"`
	// ConcurrentFluctuations / ConcurrentFaults break the same set down by kind, for
	// a tooltip. Each is distinct within itself but they may overlap each other.
	ConcurrentFluctuations int `json:"concurrent_fluctuations"`
	ConcurrentFaults       int `json:"concurrent_faults"`
}

// fluctuationCols is the stored projection, in Fluctuation field order.
const fluctuationCols = `id, site_id, agent_id, agent_name, target_id, target_name, target_addr,
	target_port, probe_kind, group_id, layer, detector_key, fail_rounds, fail_threshold, metric_kind,
	comparator, value, threshold, reason_code, reason_detail, rounds_json, started_at, ended_at,
	COALESCE(incident_id,'')`

// insertFluctuation records a recovered or abandoned sub-threshold streak inside
// the ingest transaction. r is the round that ENDS the streak (the source of the
// current display facts); st is the detector state as it stood BEFORE it was
// cleared, holding the streak's length, start and per-round evidence. ended is
// when the streak actually stopped failing.
//
// ended is a parameter rather than r.TS because the two callers end a streak for
// different reasons. A recovering round ends it at its own timestamp — the
// failure stopped when the success arrived. A round beyond the consecutive-rounds
// gap ends it at the last FAILING round instead: the streak was abandoned for
// want of evidence, and stamping it with the far side of the gap would file a dip
// as wide as the hole the gap rule exists to refuse to reason across.
//
// Idempotent on (target, agent, detector, started_at): a streak begins once, so a
// replay of the same rounds updates nothing rather than filing the same dip twice.
func insertFluctuation(ctx context.Context, tx *sql.Tx, agentID, siteID, agentName string, r Round, st detectorState, ended time.Time) error {
	started := timeFromUnix(r.TS)
	if st.firstFailTS.Valid {
		started = timeFromUnix(st.firstFailTS.Int64)
	}
	// The summary columns describe the streak's LAST failing round, mirroring how a
	// signal's summary describes its confirming round: the most recent evidence is
	// the one that characterises the streak. Every round is kept in rounds_json.
	//
	// comparator/threshold come from the ending round rather than the staged
	// evidence because they are properties of the probe kind and the sensitivity, not
	// of an individual round, and a sensitivity change would have reset the streak
	// before it could be recorded here.
	return insertFluctuationRow(ctx, tx, fluctuationRow{
		SiteID: siteID, AgentID: agentID, AgentName: agentName,
		TargetID: r.TargetID, TargetName: r.Meta.Name, TargetAddr: r.Meta.Addr, Port: r.Meta.Port,
		ProbeKind: r.Kind, GroupID: r.GroupID, Layer: r.Layer, DetectorKey: DetectorAvailability,
		FailRounds: st.failRounds, FailThreshold: r.Det.FailRounds,
		Comparator: r.Comparator, Threshold: r.Threshold,
		Rounds: st.pendingFails, StartedAt: started, EndedAt: ended,
	})
}

// fluctuationRow is one recorded streak as it goes to storage. It exists because
// two detector families record through the same table from different shapes: the
// availability detector has a probe Round to describe itself with, and the
// system-status detectors have no probe at all. Threading a probe-shaped Round
// through the host path would mean fabricating a probe for a CPU reading.
type fluctuationRow struct {
	SiteID, AgentID, AgentName       string
	TargetID, TargetName, TargetAddr string
	Port                             int
	ProbeKind, GroupID, Layer        string
	DetectorKey                      string
	FailRounds, FailThreshold        int
	Comparator                       string
	Threshold                        float64
	// Rounds is every failing round of the streak, oldest first; the last one
	// supplies the summary columns.
	Rounds             []FailEvidence
	StartedAt, EndedAt time.Time
}

// insertFluctuationRow is the single write path into fluctuations.
func insertFluctuationRow(ctx context.Context, tx *sql.Tx, f fluctuationRow) error {
	summary := FailEvidence{}
	if n := len(f.Rounds); n > 0 {
		summary = f.Rounds[n-1]
	}
	roundsJSON, err := encodeRounds(f.Rounds)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO fluctuations(id, site_id, agent_id, agent_name, target_id, target_name, target_addr,
		    target_port, probe_kind, group_id, layer, detector_key, fail_rounds, fail_threshold,
		    metric_kind, comparator, value, threshold, reason_code, reason_detail, rounds_json,
		    started_at, ended_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, agent_id, detector_key, started_at) DO NOTHING`,
		"flx_"+uuid.NewString(), f.SiteID, f.AgentID, f.AgentName, f.TargetID, f.TargetName, f.TargetAddr,
		f.Port, f.ProbeKind, f.GroupID, f.Layer, f.DetectorKey, f.FailRounds, f.FailThreshold,
		summary.MetricKind, f.Comparator, summary.Value, f.Threshold,
		summary.ReasonCode, summary.ReasonDetail, roundsJSON, f.StartedAt, f.EndedAt)
	return err
}

// linkPrecursors attaches the fluctuations that preceded a just-confirmed fault to
// its incident, and notes on the timeline that they exist.
//
// The claim is deliberately narrow: same target, same agent, recovered within
// fluctuationLinkWindow of when this streak began. That is a statement the data
// supports — this target was already faltering before it failed outright.
// Fluctuations on OTHER targets are left alone even when they overlap; whether an
// unrelated target's blip shares a cause is a correlation for the reader to draw
// (the read layer surfaces it as a concurrency count), not a lifecycle to weld
// onto this incident.
//
// The incident_id IS NULL guard makes the first fault to claim a fluctuation the
// owner: a precursor belongs to the outage it preceded, and a later fault
// re-pointing it would rewrite the earlier incident's evidence.
//
// The window is bounded at BOTH ends. The upper bound is not redundant: a merged
// monitor group shares one incident across many members' confirmations, so an
// incident can already be hours old when this target joins it, and a fluctuation
// from twenty minutes ago would otherwise be filed as a warning sign of something
// that began long before it. A precursor has to precede.
//
// A failure here is advisory. The fault itself is already recorded, and losing the
// precursor annotation must never roll back the confirmation.
func linkPrecursors(ctx context.Context, tx *sql.Tx, incidentID, targetID, agentID string, streakStart, now time.Time) {
	res, err := tx.ExecContext(ctx, `
		UPDATE fluctuations SET incident_id=?
		WHERE target_id=? AND agent_id=? AND incident_id IS NULL
		  AND ended_at >= ? AND ended_at <= ?`,
		incidentID, targetID, agentID, streakStart.Add(-fluctuationLinkWindow), streakStart)
	if err != nil {
		log.Printf("fault: link precursor fluctuations for %s: %v", incidentID, err)
		return
	}
	n, _ := res.RowsAffected()
	if n <= 0 {
		return
	}
	// The count alone is the message: the kind carries the wording and the console
	// localizes it, so this entry reads correctly in both languages (unlike the
	// timeline entries whose message is a rendered Chinese title).
	addTimeline(ctx, tx, incidentID, "fluctuation.linked", strconv.FormatInt(n, 10), "", now)
}

// PruneFluctuations ages out recorded fluctuations, returning how many went.
//
// Two clocks, because a fluctuation can be one of two things. An unlinked one is a
// diagnostic and goes on the fluctuation retention window. A linked one is an
// incident's precursor evidence, so it goes when the rest of that incident's
// evidence does — when incidentops.Retention has marked it evidence_expired. Its
// own age is irrelevant there: the point of linking was to put it on the
// incident's lifecycle, not to make it immortal, and nothing in the product ever
// deletes an incident row, so relying on the foreign key's cascade alone would
// mean linked rows never expired at all.
func (s *Service) PruneFluctuations(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM fluctuations
		WHERE (incident_id IS NULL AND ended_at < ?)
		   OR incident_id IN (SELECT id FROM incidents WHERE evidence_expired=1)`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// encodeRounds renders round evidence for storage, using "[]" rather than JSON
// null for an empty set so every row in these columns holds a readable array.
func encodeRounds(rounds []FailEvidence) (string, error) {
	if len(rounds) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(rounds)
	return string(b), err
}

// decodeRounds unmarshals a rounds_json / pending_fails column, tolerating an
// empty string as "no rounds" rather than failing the whole read.
func decodeRounds(raw string) []FailEvidence {
	if raw == "" || raw == "[]" {
		return nil
	}
	var out []FailEvidence
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		log.Printf("fault: decode round evidence: %v", err)
		return nil
	}
	return out
}
