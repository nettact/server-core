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
	dashboardLayoutVersion     = 2
	maxDashboardLayoutBodySize = 32 << 10
	maxDashboardLayoutCards    = 64
	maxDashboardCardIDLength   = 64
	maxDashboardCardTypeLength = 64
	maxDashboardTargetIDLength = 128

	// The one card type that is instanced: several cards share it, each with
	// its own id and target_id. Every other type is a singleton whose id
	// equals its type.
	monitorTargetCardType = "monitor-target"
)

type dashboardLayout struct {
	Version int                   `json:"version"`
	Cards   []dashboardLayoutCard `json:"cards"`
}

type dashboardLayoutCard struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Visible  bool   `json:"visible"`
	Size     string `json:"size"`
	TargetID string `json:"target_id,omitempty"`
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
		if card.Type == "" || card.Type != strings.TrimSpace(card.Type) || !utf8.ValidString(card.Type) || utf8.RuneCountInString(card.Type) > maxDashboardCardTypeLength {
			return errors.New("dashboard card type is invalid")
		}
		if card.Type == monitorTargetCardType {
			if card.TargetID == "" || card.TargetID != strings.TrimSpace(card.TargetID) || !utf8.ValidString(card.TargetID) || utf8.RuneCountInString(card.TargetID) > maxDashboardTargetIDLength {
				return errors.New("dashboard target card target id is invalid")
			}
		} else {
			if card.TargetID != "" {
				return errors.New("dashboard card target id is not allowed")
			}
			// Only target cards are instanced. Letting a static card carry an
			// id that differs from its type would let one card claim another
			// card's slot in the console's layout map.
			if card.ID != card.Type {
				return errors.New("dashboard static card id must match its type")
			}
		}
		switch card.Size {
		case "compact", "medium", "wide", "tall":
		default:
			return errors.New("dashboard card size is invalid")
		}
	}
	return nil
}
