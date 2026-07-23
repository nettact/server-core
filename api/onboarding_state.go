package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/nettact/server-core/settings"
)

const (
	onboardingStateVersion  = 1
	maxOnboardingBodySize   = 4 << 10
	maxOnboardingFieldRunes = 32
	maxOnboardingRegions    = 16
)

// onboardingState is the console's first-run onboarding progress. status/step
// carry the resume point; regions is the set of catalog regions the user picked
// (opaque short strings owned by the console, so adding a region needs no server
// change). See settings.KeyOnboardingState.
type onboardingState struct {
	Version         int      `json:"version"`
	Status          string   `json:"status"` // "in_progress" | "done"
	Step            string   `json:"step"`
	Regions         []string `json:"regions"`
	BannerDismissed bool     `json:"banner_dismissed"`
}

// handleGetOnboardingState returns null until the console has started onboarding.
// A null response is the signal for the console to auto-open the wizard exactly
// once; any saved state (in_progress/done) suppresses the auto-open.
func (d Deps) handleGetOnboardingState(w http.ResponseWriter, r *http.Request) {
	raw, err := d.Settings.Get(r.Context(), settings.KeyOnboardingState)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if raw == "" {
		writeJSON(w, http.StatusOK, nil)
		return
	}

	var state onboardingState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		writeError(w, http.StatusInternalServerError, "stored onboarding state is invalid")
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (d Deps) handleUpdateOnboardingState(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxOnboardingBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var state onboardingState
	if err := decoder.Decode(&state); err != nil {
		writeError(w, http.StatusBadRequest, "invalid onboarding state")
		return
	}
	if err := ensureJSONEnd(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid onboarding state")
		return
	}
	if err := validateOnboardingState(state); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if state.Regions == nil {
		state.Regions = []string{}
	}

	raw, err := json.Marshal(state)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := d.Settings.Set(r.Context(), settings.KeyOnboardingState, string(raw)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func validateOnboardingState(s onboardingState) error {
	if s.Version != onboardingStateVersion {
		return errors.New("unsupported onboarding state version")
	}
	switch s.Status {
	case "in_progress", "done":
	default:
		return errors.New("onboarding status is invalid")
	}
	if !validOnboardingField(s.Step) || s.Step == "" {
		return errors.New("onboarding step is invalid")
	}
	if len(s.Regions) > maxOnboardingRegions {
		return errors.New("too many onboarding regions")
	}
	seen := make(map[string]struct{}, len(s.Regions))
	for _, region := range s.Regions {
		if !validOnboardingField(region) || region == "" {
			return errors.New("onboarding region is invalid")
		}
		if _, dup := seen[region]; dup {
			return errors.New("onboarding regions must be unique")
		}
		seen[region] = struct{}{}
	}
	return nil
}

// validOnboardingField enforces the shared shape for the opaque step/region
// strings: trimmed, valid UTF-8, and bounded length. Empty is allowed here and
// rejected separately where a value is required.
func validOnboardingField(v string) bool {
	return v == strings.TrimSpace(v) && utf8.ValidString(v) && utf8.RuneCountInString(v) <= maxOnboardingFieldRunes
}
