package config

// Game profiles (GAME-001).
//
// A profile is a named game: the process names that count as it, how closely it
// is measured, and which monitors its runs are charted against. Profiles live in
// the config package because they ARE desired state — the agent's sensor is
// configured from them — so the same announce that pushes a target edit pushes a
// profile edit, and a separate package could only re-import all of it.
//
// They ride their OWN serial (sites.game_config_serial), never config_serial.
// The two axes describe unrelated things and are bumped by disjoint sets of
// mutations: nothing here touches the probe serial, and nothing on the probe side
// touches this one. That is what keeps a renamed game from restarting every ping
// monitor, and a new ping monitor from restarting the frame sensor. Both blocks
// ride the same DesiredState push, and an unchanged version on either axis is a
// no-op for the side that reads it — so re-pushing is always safe.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	pcfg "github.com/nettact/protocol/config"

	"github.com/nettact/server-core/store"
)

// Game profile tiers. base is the always-affordable measurement every run gets;
// diag additionally polls the per-process and GPU counters that cost something.
const (
	GameTierBase = "base"
	GameTierDiag = "diag"
)

// Field limits. They exist to keep one save from turning into a payload the push
// has to carry to every agent forever, not to express a product opinion.
const (
	maxGameProfileNameRunes = 200
	maxGameProfileExe       = 64
	maxGameProfileExeRunes  = 200
	maxGameProfileMonitors  = 64
	maxGameTargetFPS        = 1000
)

// ErrGameProfileInvalid reports a profile the server refuses to store. Like
// ErrDuplicateTargetID it is a bad REQUEST — the API layer matches it with
// errors.Is and answers 400, because no retry of the same payload can succeed.
var ErrGameProfileInvalid = errors.New("invalid game profile")

// GameProfileRec is one stored profile as the console manages it. Exe is matched
// case-insensitively against process names elsewhere; the entries are stored
// exactly as typed so the form round-trips what the operator wrote.
//
// TargetFPS is a pointer because "no target set" and "a target of zero" are
// different answers, and the console renders the first as an empty field rather
// than as a game expected to render nothing.
type GameProfileRec struct {
	ID         string   `json:"id"`
	SiteID     string   `json:"site_id"`
	Name       string   `json:"name"`
	Exe        []string `json:"exe"`
	TargetFPS  *int     `json:"target_fps"`
	Tier       string   `json:"tier"`
	MonitorIDs []string `json:"monitor_ids"`
	CreatedAt  int64    `json:"created_at"` // unix seconds
	UpdatedAt  int64    `json:"updated_at"`
}

// GameProfiles returns the site's profiles by name.
func (s *Service) GameProfiles(ctx context.Context, siteID string) ([]GameProfileRec, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, site_id, name, exe_match, target_fps, tier, monitor_ids, created_at, updated_at
		 FROM game_profiles WHERE site_id=? ORDER BY name, id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GameProfileRec{}
	for rows.Next() {
		p, err := scanGameProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GameProfile returns one profile by id, or sql.ErrNoRows when absent.
func (s *Service) GameProfile(ctx context.Context, id string) (GameProfileRec, error) {
	return scanGameProfile(s.db.QueryRowContext(ctx,
		`SELECT id, site_id, name, exe_match, target_fps, tier, monitor_ids, created_at, updated_at
		 FROM game_profiles WHERE id=?`, id))
}

func scanGameProfile(sc rowScanner) (GameProfileRec, error) {
	var (
		p         GameProfileRec
		exe, mon  string
		targetFPS sql.NullInt64
	)
	if err := sc.Scan(&p.ID, &p.SiteID, &p.Name, &exe, &targetFPS, &p.Tier, &mon,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return GameProfileRec{}, err
	}
	p.Exe = decodeStringList(exe)
	p.MonitorIDs = decodeStringList(mon)
	if targetFPS.Valid {
		n := int(targetFPS.Int64)
		p.TargetFPS = &n
	}
	return p, nil
}

// CreateGameProfile stores a new profile and returns it as stored. The site's
// game serial is bumped inside the same transaction as the insert, so no agent
// can be pushed a profile set under a version that does not cover it.
func (s *Service) CreateGameProfile(ctx context.Context, siteID string, p GameProfileRec) (GameProfileRec, error) {
	if err := normalizeGameProfile(&p); err != nil {
		return GameProfileRec{}, err
	}
	p.ID = "gprof_" + uuid.NewString()
	p.SiteID = siteID
	now := time.Now().UTC().Unix()
	p.CreatedAt, p.UpdatedAt = now, now

	if err := s.inGameTx(ctx, siteID, func(tx store.Executor) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO game_profiles(id, site_id, name, exe_match, target_fps, tier, monitor_ids, created_at, updated_at)
			 VALUES(?,?,?,?,?,?,?,?,?)`,
			p.ID, p.SiteID, p.Name, encodeStringList(p.Exe), nullGameFPS(p.TargetFPS), p.Tier,
			encodeStringList(p.MonitorIDs), p.CreatedAt, p.UpdatedAt)
		return err
	}); err != nil {
		return GameProfileRec{}, err
	}
	return p, nil
}

// UpdateGameProfile rewrites a profile and returns it as stored, or sql.ErrNoRows
// when it is gone. The serial is bumped unconditionally rather than only for a
// material edit: everything a profile holds except monitor_ids is pushed down, and
// a re-push under an equal version is a no-op for the agent anyway — so paying for
// one redundant push is cheaper than a "material" list that silently stops
// covering a field someone adds later.
func (s *Service) UpdateGameProfile(ctx context.Context, id string, p GameProfileRec) (GameProfileRec, error) {
	if err := normalizeGameProfile(&p); err != nil {
		return GameProfileRec{}, err
	}
	var out GameProfileRec
	siteID, err := s.gameProfileSite(ctx, id)
	if err != nil {
		return GameProfileRec{}, err
	}
	if err := s.inGameTx(ctx, siteID, func(tx store.Executor) error {
		now := time.Now().UTC().Unix()
		res, err := tx.ExecContext(ctx,
			`UPDATE game_profiles SET name=?, exe_match=?, target_fps=?, tier=?, monitor_ids=?, updated_at=?
			 WHERE id=?`,
			p.Name, encodeStringList(p.Exe), nullGameFPS(p.TargetFPS), p.Tier,
			encodeStringList(p.MonitorIDs), now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		out, err = scanGameProfile(tx.QueryRowContext(ctx,
			`SELECT id, site_id, name, exe_match, target_fps, tier, monitor_ids, created_at, updated_at
			 FROM game_profiles WHERE id=?`, id))
		return err
	}); err != nil {
		return GameProfileRec{}, err
	}
	return out, nil
}

// DeleteGameProfile removes a profile and returns its site id, or sql.ErrNoRows
// when it is already gone.
//
// The runs it stamped keep their profile_id. The stamp records which game the
// server believed was running at the time, and rewriting history because the
// operator reorganized their profile list would erase the only record of it —
// readers show the id without a name instead (see game_runs.profile_id).
func (s *Service) DeleteGameProfile(ctx context.Context, id string) (string, error) {
	siteID, err := s.gameProfileSite(ctx, id)
	if err != nil {
		return "", err
	}
	if err := s.inGameTx(ctx, siteID, func(tx store.Executor) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM game_profiles WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	}); err != nil {
		return "", err
	}
	return siteID, nil
}

// GameCollection reports whether processes matching no profile are recorded. An
// unknown site reads as the default (record everything), so a console asking
// about a site that has not been written yet gets the behavior it will observe.
func (s *Service) GameCollection(ctx context.Context, siteID string) (bool, error) {
	var v int
	err := s.db.QueryRowContext(ctx,
		`SELECT game_record_unmatched FROM sites WHERE id=?`, siteID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return v == 1, nil
}

// SetGameCollection writes the site's record-unmatched choice, bumps the game
// serial and announces. It is the same axis as a profile edit because it is the
// same decision for the sensor: both change which processes it captures.
func (s *Service) SetGameCollection(ctx context.Context, siteID string, recordUnmatched bool) error {
	return s.inGameTx(ctx, siteID, func(tx store.Executor) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE sites SET game_record_unmatched=? WHERE id=?`, boolInt(recordUnmatched), siteID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

// inGameTx runs a game-config mutation, bumps sites.game_config_serial in the
// SAME transaction, and announces after the commit.
//
// Doing the bump here rather than at each call site is what makes the invariant
// checkable in one place: a mutation that committed without advancing the serial
// would be pushed to agents under a version they have already applied, and the
// change would simply never take effect. The probe serial is deliberately
// untouched.
func (s *Service) inGameTx(ctx context.Context, siteID string, fn func(tx store.Executor) error) error {
	return s.db.WriteTx(ctx, store.Standalone(), func(wtx store.WriteTx) (func(), error) {
		if err := fn(wtx); err != nil {
			return nil, err
		}
		if _, err := wtx.ExecContext(ctx,
			`UPDATE sites SET game_config_serial=game_config_serial+1 WHERE id=?`, siteID); err != nil {
			return nil, err
		}
		return func() { s.announce(siteID) }, nil
	})
}

// gameProfileSite resolves a profile's site, so the serial bump and the announce
// address the site that actually changed rather than one the caller guessed.
func (s *Service) gameProfileSite(ctx context.Context, id string) (string, error) {
	var siteID string
	err := s.db.QueryRowContext(ctx, `SELECT site_id FROM game_profiles WHERE id=?`, id).Scan(&siteID)
	return siteID, err
}

// normalizeGameProfile trims and checks a submitted profile in place, so the
// stored row and the pushed one are the same thing the validation passed.
//
// An exe list is required: a profile that matches no process cannot classify
// anything, and storing one would produce a game that silently never appears.
func normalizeGameProfile(p *GameProfileRec) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return fmt.Errorf("%w: name is required", ErrGameProfileInvalid)
	}
	if utf8.RuneCountInString(p.Name) > maxGameProfileNameRunes {
		return fmt.Errorf("%w: name is longer than %d characters", ErrGameProfileInvalid, maxGameProfileNameRunes)
	}

	exe := make([]string, 0, len(p.Exe))
	seen := map[string]bool{}
	for _, e := range p.Exe {
		e = strings.TrimSpace(e)
		if e == "" {
			return fmt.Errorf("%w: a process name cannot be empty", ErrGameProfileInvalid)
		}
		if utf8.RuneCountInString(e) > maxGameProfileExeRunes {
			return fmt.Errorf("%w: process name %q is too long", ErrGameProfileInvalid, e)
		}
		// Duplicates are dropped rather than refused: matching is case-insensitive, so
		// "CS2.exe" and "cs2.exe" are one entry that a tag input can easily produce
		// twice, and refusing the save would be pedantry about a form's behavior.
		key := strings.ToLower(e)
		if seen[key] {
			continue
		}
		seen[key] = true
		exe = append(exe, e)
	}
	if len(exe) == 0 {
		return fmt.Errorf("%w: at least one process name is required", ErrGameProfileInvalid)
	}
	if len(exe) > maxGameProfileExe {
		return fmt.Errorf("%w: at most %d process names", ErrGameProfileInvalid, maxGameProfileExe)
	}
	p.Exe = exe

	switch p.Tier {
	case "":
		p.Tier = GameTierDiag
	case GameTierBase, GameTierDiag:
	default:
		return fmt.Errorf("%w: tier must be %q or %q", ErrGameProfileInvalid, GameTierBase, GameTierDiag)
	}

	// 0 and null are the same answer here — "no target" — so a submitted 0 is
	// stored as NULL rather than as a game expected to render nothing.
	if p.TargetFPS != nil {
		if *p.TargetFPS < 0 || *p.TargetFPS > maxGameTargetFPS {
			return fmt.Errorf("%w: target FPS must be between 0 and %d", ErrGameProfileInvalid, maxGameTargetFPS)
		}
		if *p.TargetFPS == 0 {
			p.TargetFPS = nil
		}
	}

	mon := make([]string, 0, len(p.MonitorIDs))
	monSeen := map[string]bool{}
	for _, id := range p.MonitorIDs {
		id = strings.TrimSpace(id)
		if id == "" || monSeen[id] {
			continue
		}
		monSeen[id] = true
		mon = append(mon, id)
	}
	if len(mon) > maxGameProfileMonitors {
		return fmt.Errorf("%w: at most %d linked monitors", ErrGameProfileInvalid, maxGameProfileMonitors)
	}
	p.MonitorIDs = mon
	return nil
}

// gameConfigFor loads the site's game block for a DesiredState push: the serial,
// the record-unmatched choice, and every profile. monitor_ids are deliberately
// not included — see pcfg.GameProfile.
func (s *Service) gameConfigFor(ctx context.Context, siteID string) (*pcfg.GameConfig, error) {
	cfg := pcfg.GameConfig{RecordUnmatched: true}
	var record int
	err := s.db.QueryRowContext(ctx,
		`SELECT game_config_serial, game_record_unmatched FROM sites WHERE id=?`, siteID).
		Scan(&cfg.Version, &record)
	if errors.Is(err, sql.ErrNoRows) {
		return &cfg, nil
	}
	if err != nil {
		return nil, err
	}
	cfg.RecordUnmatched = record == 1
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, exe_match, target_fps, tier FROM game_profiles WHERE site_id=? ORDER BY name, id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			p         pcfg.GameProfile
			exe       string
			targetFPS sql.NullInt64
		)
		if err := rows.Scan(&p.ID, &p.Name, &exe, &targetFPS, &p.Tier); err != nil {
			return nil, err
		}
		p.Exe = decodeStringList(exe)
		p.TargetFPS = int(targetFPS.Int64) // NULL reads as 0, which is "unset" on the wire
		cfg.Profiles = append(cfg.Profiles, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// encodeStringList stores a list as a JSON array, never as NULL: the columns are
// NOT NULL with a '[]' default, so an empty list stays an empty list.
func encodeStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// decodeStringList reads one back, always as a non-nil slice so the JSON the
// console receives carries [] rather than null.
func decodeStringList(s string) []string {
	out := []string{}
	if s == "" {
		return out
	}
	if json.Unmarshal([]byte(s), &out) != nil {
		return []string{}
	}
	if out == nil {
		return []string{}
	}
	return out
}

func nullGameFPS(v *int) sql.NullInt64 {
	if v == nil || *v <= 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}
