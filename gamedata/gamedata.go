// Package gamedata stores and serves game presentation data: runs (one
// continuous stretch of a game presenting frames) and the per-second buckets
// hanging from them.
//
// It is deliberately outside the time-series store. A second of rendering is a
// distribution rather than a scalar, and the figures players compare sessions by
// — the mean frame rate of a run, its slowest 1% of frames — are properties of
// every frame in the run. Averaging per-second summaries cannot produce them, so
// each bucket carries the second's frame-time histogram and whole-run figures come
// from adding those histograms together (gamesense.HistAdd). The arithmetic lives
// in protocol/gamesense so the sensor, the agent and the server can never disagree
// about where a bin begins.
//
// Every optional measurement is a nullable column and NULL means NOT MEASURED.
// Reads restore an absent value as absent: a source that cannot see dropped frames
// must come back nil, never as a zero that reads like a flawless result.
package gamedata

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
)

// Service owns the game_runs / game_buckets tables: the read surface the console
// charts from, and the retention that bounds them. The write path is Apply, which
// runs inside the ingest transaction and therefore takes a *sql.Tx instead.
type Service struct {
	db       *store.DB
	settings *settings.Service
}

// New takes the settings service for the retention windows. It may be nil, in
// which case retention falls back to the registered defaults.
func New(db *store.DB, st *settings.Service) *Service {
	return &Service{db: db, settings: st}
}

// Run is one recorded game session together with the whole-run figures a reader
// compares runs by. Caps and Source say how it was measured, which is what makes
// two runs comparable at all.
//
// ProfileID is the game profile the session matched, null for one that matched
// none ("other process"). ProfileName is resolved on read and is null both for
// those AND for a run whose profile has since been deleted — the stamp is history
// and outlives the configuration, so they are two fields rather than one that
// would have to lie about one of the cases.
//
// StutterCount and StutterExcessMs are the run's long-frame totals, summed from
// the seconds that carried a stutter block. They are pointers because a capture
// that never watched for long frames must not report a run that never hitched:
// that claim is the single most misleading zero this package could produce, so it
// is reserved for runs in which at least one second actually looked.
type Run struct {
	ID              string     `json:"id"`
	AgentID         string     `json:"agent_id"`
	SiteID          string     `json:"site_id"`
	Proc            string     `json:"proc"`
	Title           string     `json:"title,omitempty"`
	ProfileID       *string    `json:"profile_id"`
	ProfileName     *string    `json:"profile_name"`
	StartedAt       time.Time  `json:"started_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	EndedAt         *time.Time `json:"ended_at"`
	Source          string     `json:"source,omitempty"`
	Caps            []string   `json:"caps"`
	StutterCount    *int64     `json:"stutter_count"`
	StutterExcessMs *float64   `json:"stutter_excess_ms"`
	Summary         Summary    `json:"summary"`
}

// Summary is a run's whole-run figures, derived by summing its buckets'
// histograms rather than by averaging their per-second statistics — the latter is
// not the run's distribution and answers no question anyone asked.
//
// The three FPS figures are pointers because "too few frames to say" is a real
// answer. A 1% low over two hundred frames is one slow frame, not a statistic;
// gamesense.HistLowFPS declines it, and this reports null rather than 0. Sending 0
// would read as "the run stuttered to a standstill", which is the opposite of what
// happened.
//
// Displayed and Dropped are pointers for the same reason one level down: they are
// totals over the buckets that actually carried the count, and stay nil when no
// bucket did.
type Summary struct {
	DurationSeconds int64    `json:"duration_seconds"`
	MeanFPS         *float64 `json:"mean_fps"`
	Low1PctFPS      *float64 `json:"low_1pct_fps"`
	Low01PctFPS     *float64 `json:"low_0_1pct_fps"`
	Presented       int64    `json:"presented"`
	Displayed       *int64   `json:"displayed"`
	Dropped         *int64   `json:"dropped"`
}

// histBytes is the stored width of a log24_v1 histogram blob.
const histBytes = gamesense.HistBins * 4

// encodeHist renders bin counts as the stored blob: uint32 little-endian, one per
// bin. A fixed encoding rather than JSON because these are the bulk of the table —
// one row per second of play — and because a numeric text form would reintroduce
// the float/locale questions the bins exist to avoid.
func encodeHist(counts []uint32) []byte {
	b := make([]byte, len(counts)*4)
	for i, c := range counts {
		binary.LittleEndian.PutUint32(b[i*4:], c)
	}
	return b
}

// decodeHist reverses encodeHist. A blob whose length is not a whole number of
// bins yields nil, so a truncated row is read as "no counts" rather than as counts
// that silently shifted by one bin.
func decodeHist(b []byte) []uint32 {
	if len(b) == 0 || len(b)%4 != 0 {
		return nil
	}
	out := make([]uint32, len(b)/4)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(b[i*4:])
	}
	return out
}

// encodeStrings stores a string list as a JSON array, or NULL when it is empty —
// so "no flags" and "no list" read back identically as an absent slice.
func encodeStrings(ss []string) sql.NullString {
	if len(ss) == 0 {
		return sql.NullString{}
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

func decodeStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
}

// nullInt/nullFloat/nullBool carry an optional measurement to SQL. They exist so
// the "unknown is not zero" rule is applied in exactly one place per type rather
// than restated at every column.
func nullInt(v *int) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}

func nullFloat(v float64, ok bool) sql.NullFloat64 {
	if !ok {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: v, Valid: true}
}

// nullUint64 carries an optional byte count. SQLite's INTEGER is signed, which
// costs nothing at the magnitudes involved here — a process's memory footprint —
// and keeps the column readable by every tool that opens the file.
func nullUint64(v *uint64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}

func nullBool(v *bool) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	n := int64(0)
	if *v {
		n = 1
	}
	return sql.NullInt64{Int64: n, Valid: true}
}

func nullStr(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func intPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int64)
	return &n
}

func int64Ptr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

func uint64Ptr(v sql.NullInt64) *uint64 {
	if !v.Valid {
		return nil
	}
	n := uint64(v.Int64)
	return &n
}

// float64Ptr is int64Ptr for a real column: an absent reading stays absent
// rather than becoming the 0.0 a NullFloat64 carries when invalid.
func float64Ptr(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

// strPtr keeps an absent text column absent. A NULL profile stamp is "this
// session matched no game", which the empty string could not say without also
// being a legitimate id of nothing.
func strPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

func boolPtr(v sql.NullInt64) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Int64 != 0
	return &b
}

func floatPtr(v float64) *float64 { return &v }

// unixTime converts stored unix seconds to a UTC time.
func unixTime(sec int64) time.Time { return time.Unix(sec, 0).UTC() }
