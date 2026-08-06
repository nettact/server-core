package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nettact/server-core/fault"
)

// Detection sensitivity is server-side semantics, not probe configuration: it
// changes when the server calls a target broken, never what or how often the
// Agent probes. So it lives in its own table rather than in probe_tasks.params,
// does NOT bump the site config serial, and does NOT re-push DesiredState —
// tuning a threshold must not restart every Agent's probe schedule.
//
// What it does do is invalidate the current streak. A counter accumulated under
// "3 failures to confirm" says nothing under "5 failures to confirm", so the edit
// terminates any firing signal as a configuration change and clears the
// detector's counters; the next round starts a clean streak under the new rule.

// DetectionSettings is one target's built-in detector sensitivity, plus the
// target identity the console needs to render it.
type DetectionSettings struct {
	TargetID string `json:"target_id"`
	Kind     string `json:"kind"`
	fault.DetectionSettings
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// GetDetectionSettings returns a target's sensitivity, falling back to the
// balanced defaults when the target has never been tuned. Returns sql.ErrNoRows
// when the target does not exist.
func (s *Service) GetDetectionSettings(ctx context.Context, targetID string) (DetectionSettings, error) {
	out := DetectionSettings{TargetID: targetID, DetectionSettings: fault.DefaultDetection()}
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT kind FROM probe_tasks WHERE id=?`, targetID).Scan(&out.Kind); err != nil {
		return DetectionSettings{}, err
	}
	var updated sql.NullTime
	var d fault.DetectionSettings
	var smartEnabled int
	err := s.db.Read().QueryRowContext(ctx, `
		SELECT profile, fail_rounds, recover_rounds, icmp_loss_pct,
		       smart_enabled, smart_sensitivity, revision, updated_at
		FROM probe_detection_settings WHERE target_id=?`, targetID).
		Scan(&d.Profile, &d.FailRounds, &d.RecoverRounds, &d.ICMPLossPct,
			&smartEnabled, &d.SmartSensitivity, &d.Revision, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return DetectionSettings{}, err
	}
	d.SmartEnabled = smartEnabled == 1
	out.DetectionSettings = d.Normalize()
	if updated.Valid {
		t := updated.Time.UTC()
		out.UpdatedAt = &t
	}
	return out, nil
}

// UpdateDetectionSettings stores a target's sensitivity, terminates its firing
// signals as a configuration change and clears its detector counters, all in one
// transaction. A named profile ignores the submitted round counts; "custom"
// takes them as given (clamped to the supported 1..20 range).
func (s *Service) UpdateDetectionSettings(ctx context.Context, targetID string, in fault.DetectionSettings) (DetectionSettings, error) {
	if fail, recover, ok := fault.ProfileRounds(in.Profile); ok {
		in.FailRounds, in.RecoverRounds = fail, recover
	}
	// Reject an out-of-range request rather than clamping it: silently storing 3
	// when the caller asked for 99 would leave them believing the target is far
	// less trigger-happy than it is.
	if in.FailRounds < 1 || in.FailRounds > 20 || in.RecoverRounds < 1 || in.RecoverRounds > 20 {
		return DetectionSettings{}, fmt.Errorf("fail_rounds and recover_rounds must be between 1 and 20")
	}
	if !(in.ICMPLossPct > 0) || in.ICMPLossPct > 100 {
		return DetectionSettings{}, fmt.Errorf("icmp_loss_pct must be greater than 0 and at most 100")
	}
	switch in.SmartSensitivity {
	case fault.SmartLoose, fault.SmartStandard, fault.SmartSensitive:
	default:
		return DetectionSettings{}, fmt.Errorf("smart_sensitivity must be one of loose, standard, sensitive")
	}
	in = in.Normalize()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DetectionSettings{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var siteID, kind string
	if err := tx.QueryRowContext(ctx,
		`SELECT site_id, kind FROM probe_tasks WHERE id=?`, targetID).Scan(&siteID, &kind); err != nil {
		return DetectionSettings{}, err
	}
	if fault.SuccessMetricKind(kind) == "" {
		return DetectionSettings{}, fmt.Errorf("target kind %q has no built-in availability detector", kind)
	}

	now := time.Now().UTC()
	smartEnabled := 0
	if in.SmartEnabled {
		smartEnabled = 1
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO probe_detection_settings(target_id, profile, fail_rounds, recover_rounds, icmp_loss_pct,
		    smart_enabled, smart_sensitivity, revision, updated_at)
		VALUES(?,?,?,?,?,?,?,1,?)
		ON CONFLICT(target_id) DO UPDATE SET
		  profile=excluded.profile, fail_rounds=excluded.fail_rounds,
		  recover_rounds=excluded.recover_rounds, icmp_loss_pct=excluded.icmp_loss_pct,
		  smart_enabled=excluded.smart_enabled, smart_sensitivity=excluded.smart_sensitivity,
		  revision=probe_detection_settings.revision+1, updated_at=excluded.updated_at`,
		targetID, in.Profile, in.FailRounds, in.RecoverRounds, in.ICMPLossPct,
		smartEnabled, in.SmartSensitivity, now); err != nil {
		return DetectionSettings{}, err
	}

	var termPub PostCommit
	if s.term != nil {
		_, pub, err := s.term.TerminateForTargetsTx(ctx, tx, []string{targetID}, ReasonConfigChanged)
		if err != nil {
			return DetectionSettings{}, err
		}
		termPub = pub
		if err := s.term.ClearDetectorStateTx(ctx, tx, []string{targetID}); err != nil {
			return DetectionSettings{}, err
		}
	}

	var revision int
	if err := tx.QueryRowContext(ctx,
		`SELECT revision FROM probe_detection_settings WHERE target_id=?`, targetID).Scan(&revision); err != nil {
		return DetectionSettings{}, err
	}
	if err := tx.Commit(); err != nil {
		return DetectionSettings{}, err
	}
	committed = true
	if termPub != nil {
		termPub(ctx)
	}
	s.publishTargetStatus(siteID, []string{targetID})

	in.Revision = revision
	return DetectionSettings{TargetID: targetID, Kind: kind, DetectionSettings: in, UpdatedAt: &now}, nil
}
