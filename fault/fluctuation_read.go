package fault

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// FluctuationFilter narrows a fluctuation listing. Zero values mean "no
// constraint". Since/Until bound ended_at (the recovery moment), in epoch
// seconds, because that is what the console's range picker selects on.
type FluctuationFilter struct {
	SiteID     string
	AgentID    string
	TargetID   string
	IncidentID string // an incident's precursors
	Since      int64
	Until      int64
	Limit      int // default 50, max 500 (same clamp as ListSignals)
}

// FluctuationPage is a listing plus the filter's TOTAL match count, which is not
// the same as len(Items) once the limit bites. The console needs the total for
// "N fluctuations in 24h" beside an availability figure — a badge that fetched
// only one row to learn there were forty would otherwise have to lie or paginate.
type FluctuationPage struct {
	Items []Fluctuation `json:"items"`
	Total int           `json:"total"`
}

// concurrencyWindowSlack widens each fluctuation's window before testing overlap
// with another target's trouble. Probes on different targets run on independent
// schedules, so the same upstream blip lands in rounds a cycle or two apart; an
// exact-overlap test would call those unrelated and silently answer "only this
// target" to the question the operator most needs answered.
const concurrencyWindowSlack = time.Minute

// concurrencySpanLimit caps how many neighbouring spans one Agent's window may
// contribute. The window is bounded by time, not by rows, so a page covering weeks
// of a flapping Agent could otherwise pull an unbounded set into memory and then
// compare it against every item. The count is an advisory "was anything else
// affected" signal, and a ceiling this high can only understate a number that is
// already emphatically "yes" — a far better failure than a slow console.
const concurrencySpanLimit = 5000

// ListFluctuations returns the fluctuations matching the filter, newest first,
// each annotated with how many OTHER targets on the same Agent were failing over
// its window.
//
// That annotation is the whole point of the record. A fluctuation on its own says
// "this target blipped"; knowing that four other targets on the same Agent
// blipped in the same seconds says "the link blipped", and knowing that none did
// says "look at this target". It is computed at read time rather than frozen
// because it is a correlation over other records, not a fact about this one — and
// because the answer legitimately changes as neighbouring history arrives.
func (s *Service) ListFluctuations(ctx context.Context, f FluctuationFilter) (FluctuationPage, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	where, args := f.where()
	page := FluctuationPage{Items: []Fluctuation{}}

	q := `SELECT COUNT(*) FROM fluctuations`
	if where != "" {
		q += ` WHERE ` + where
	}
	if err := s.db.Read().QueryRowContext(ctx, q, args...).Scan(&page.Total); err != nil {
		return page, err
	}

	q = `SELECT ` + fluctuationCols + ` FROM fluctuations`
	if where != "" {
		q += ` WHERE ` + where
	}
	// Ordered by when the dip STARTED, which is the column the console shows. Sorting
	// on ended_at instead would put rows of differing duration out of visible order
	// for no gain. The filter still bounds ended_at — that is the moment a dip became
	// a complete, recorded fact.
	q += ` ORDER BY started_at DESC, id DESC LIMIT ?`
	items, err := s.queryFluctuations(ctx, q, append(args, limit)...)
	if err != nil {
		return page, err
	}
	page.Items = items
	if err := s.annotateConcurrency(ctx, page.Items); err != nil {
		return page, err
	}
	return page, nil
}

func (f FluctuationFilter) where() (string, []any) {
	var where []string
	var args []any
	if f.SiteID != "" {
		where = append(where, "site_id=?")
		args = append(args, f.SiteID)
	}
	if f.AgentID != "" {
		where = append(where, "agent_id=?")
		args = append(args, f.AgentID)
	}
	if f.TargetID != "" {
		where = append(where, "target_id=?")
		args = append(args, f.TargetID)
	}
	if f.IncidentID != "" {
		where = append(where, "incident_id=?")
		args = append(args, f.IncidentID)
	}
	if f.Since > 0 {
		where = append(where, "ended_at >= ?")
		args = append(args, timeFromUnix(f.Since))
	}
	if f.Until > 0 {
		where = append(where, "ended_at < ?")
		args = append(args, timeFromUnix(f.Until))
	}
	return strings.Join(where, " AND "), args
}

func (s *Service) queryFluctuations(ctx context.Context, q string, args ...any) ([]Fluctuation, error) {
	rows, err := s.db.Read().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Fluctuation{}
	for rows.Next() {
		var fl Fluctuation
		var roundsJSON string
		if err := rows.Scan(&fl.ID, &fl.SiteID, &fl.AgentID, &fl.AgentName, &fl.TargetID,
			&fl.TargetName, &fl.TargetAddr, &fl.Port, &fl.ProbeKind, &fl.GroupID, &fl.Layer,
			&fl.DetectorKey, &fl.FailRounds, &fl.FailThreshold, &fl.MetricKind, &fl.Comparator,
			&fl.Value, &fl.Threshold, &fl.ReasonCode, &fl.ReasonDetail, &roundsJSON,
			&fl.StartedAt, &fl.EndedAt, &fl.IncidentID); err != nil {
			return nil, err
		}
		fl.Rounds = decodeRounds(roundsJSON)
		fl.StartedAt = fl.StartedAt.UTC()
		fl.EndedAt = fl.EndedAt.UTC()
		out = append(out, fl)
	}
	return out, rows.Err()
}

// interval is one span of trouble on one target, used for overlap testing.
type interval struct {
	targetID string
	from, to time.Time
}

// annotateConcurrency fills in ConcurrentFluctuations / ConcurrentFaults for a
// page of fluctuations.
//
// Two batch queries feed an in-memory overlap test rather than a correlated
// subquery per row: a page of 500 rows would otherwise mean 1000 range scans, and
// the overlap predicate itself (with slack, excluding the same target) is easier
// to get right — and to read — in Go than in SQL.
func (s *Service) annotateConcurrency(ctx context.Context, items []Fluctuation) error {
	if len(items) == 0 {
		return nil
	}
	// One window per Agent covering all of that Agent's rows on this page.
	type window struct{ from, to time.Time }
	windows := map[string]*window{}
	for _, fl := range items {
		w := windows[fl.AgentID]
		if w == nil {
			windows[fl.AgentID] = &window{from: fl.StartedAt, to: fl.EndedAt}
			continue
		}
		if fl.StartedAt.Before(w.from) {
			w.from = fl.StartedAt
		}
		if fl.EndedAt.After(w.to) {
			w.to = fl.EndedAt
		}
	}

	now := time.Now().UTC()
	flucByAgent := map[string][]interval{}
	faultByAgent := map[string][]interval{}
	for agentID, w := range windows {
		from, to := w.from.Add(-concurrencyWindowSlack), w.to.Add(concurrencyWindowSlack)

		rows, err := s.db.Read().QueryContext(ctx, `
			SELECT target_id, started_at, ended_at FROM fluctuations
			WHERE agent_id=? AND ended_at >= ? AND started_at <= ?
			LIMIT ?`, agentID, from, to, concurrencySpanLimit)
		if err != nil {
			return err
		}
		spans, err := scanIntervals(rows, now)
		if err != nil {
			return err
		}
		flucByAgent[agentID] = spans

		// A fault's span runs from the first round of its streak to its resolution;
		// one still firing is trouble that is happening right now, hence `now`.
		rows, err = s.db.Read().QueryContext(ctx, `
			SELECT target_id, observed_at, resolved_at FROM fault_signals
			WHERE agent_id=? AND target_id <> '' AND COALESCE(resolved_at, ?) >= ? AND observed_at <= ?
			LIMIT ?`,
			agentID, now, from, to, concurrencySpanLimit)
		if err != nil {
			return err
		}
		spans, err = scanIntervals(rows, now)
		if err != nil {
			return err
		}
		faultByAgent[agentID] = spans
	}

	for i := range items {
		fl := &items[i]
		from, to := fl.StartedAt.Add(-concurrencyWindowSlack), fl.EndedAt.Add(concurrencyWindowSlack)
		dips := overlappingTargets(flucByAgent[fl.AgentID], fl.TargetID, from, to)
		faults := overlappingTargets(faultByAgent[fl.AgentID], fl.TargetID, from, to)
		fl.ConcurrentFluctuations = len(dips)
		fl.ConcurrentFaults = len(faults)
		// The headline is the union, not the sum: a neighbour that dipped and then
		// failed outright is in both sets and is still one other target. Adding them
		// would overstate exactly the number an operator uses to decide whether to go
		// looking at the link or at this one target.
		for target := range faults {
			dips[target] = true
		}
		fl.ConcurrentTargets = len(dips)
	}
	return nil
}

// scanIntervals reads (target, from, to) triples, substituting fallback for a
// NULL end (an unresolved fault runs to now).
func scanIntervals(rows *sql.Rows, fallback time.Time) ([]interval, error) {
	defer rows.Close()
	var out []interval
	for rows.Next() {
		var iv interval
		var to sql.NullTime
		if err := rows.Scan(&iv.targetID, &iv.from, &to); err != nil {
			return nil, err
		}
		iv.to = fallback
		if to.Valid {
			iv.to = to.Time.UTC()
		}
		iv.from = iv.from.UTC()
		out = append(out, iv)
	}
	return out, rows.Err()
}

// overlappingTargets returns the DISTINCT other targets whose span overlaps
// [from, to]. A set rather than a count, so the caller can union two of them
// without double-counting a target that appears in both; distinct within itself,
// because one neighbour flapping five times in the window is one other target in
// trouble, not five.
func overlappingTargets(spans []interval, selfTarget string, from, to time.Time) map[string]bool {
	seen := map[string]bool{}
	for _, iv := range spans {
		if iv.targetID == selfTarget || seen[iv.targetID] {
			continue
		}
		if iv.from.After(to) || iv.to.Before(from) {
			continue
		}
		seen[iv.targetID] = true
	}
	return seen
}
