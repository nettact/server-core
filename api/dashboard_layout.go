package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/nettact/server-core/settings"
)

const (
	dashboardLayoutVersion     = 1
	maxDashboardLayoutBodySize = 32 << 10
	maxDashboardLayoutCards    = 64
	maxDashboardCardIDLength   = 64
)

type dashboardLayout struct {
	Version int                   `json:"version"`
	Cards   []dashboardLayoutCard `json:"cards"`
}

type dashboardLayoutCard struct {
	ID      string `json:"id"`
	Visible bool   `json:"visible"`
	Size    string `json:"size"`
}

// handleGetDashboardLayout returns null until a layout has been saved. This
// lets the console apply its own current defaults without duplicating widget
// definitions in the server.
func (d Deps) handleGetDashboardLayout(w http.ResponseWriter, r *http.Request) {
	raw, err := d.Settings.Get(r.Context(), settings.KeyDashboardLayout)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if raw == "" {
		writeJSON(w, http.StatusOK, nil)
		return
	}

	var layout dashboardLayout
	if err := json.Unmarshal([]byte(raw), &layout); err != nil {
		writeError(w, http.StatusInternalServerError, "stored dashboard layout is invalid")
		return
	}
	writeJSON(w, http.StatusOK, layout)
}

func (d Deps) handleUpdateDashboardLayout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxDashboardLayoutBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var layout dashboardLayout
	if err := decoder.Decode(&layout); err != nil {
		writeError(w, http.StatusBadRequest, "invalid dashboard layout")
		return
	}
	if err := ensureJSONEnd(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid dashboard layout")
		return
	}
	if err := validateDashboardLayout(layout); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	raw, err := json.Marshal(layout)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := d.Settings.Set(r.Context(), settings.KeyDashboardLayout, string(raw)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, layout)
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func validateDashboardLayout(layout dashboardLayout) error {
	if layout.Version != dashboardLayoutVersion {
		return errors.New("unsupported dashboard layout version")
	}
	if layout.Cards == nil {
		return errors.New("dashboard layout cards are required")
	}
	if len(layout.Cards) > maxDashboardLayoutCards {
		return errors.New("dashboard layout has too many cards")
	}

	seen := make(map[string]struct{}, len(layout.Cards))
	for _, card := range layout.Cards {
		if card.ID == "" || card.ID != strings.TrimSpace(card.ID) || !utf8.ValidString(card.ID) || utf8.RuneCountInString(card.ID) > maxDashboardCardIDLength {
			return errors.New("dashboard card id is invalid")
		}
		if _, ok := seen[card.ID]; ok {
			return errors.New("dashboard card ids must be unique")
		}
		seen[card.ID] = struct{}{}
		switch card.Size {
		case "compact", "medium", "wide", "tall":
		default:
			return errors.New("dashboard card size is invalid")
		}
	}
	return nil
}
