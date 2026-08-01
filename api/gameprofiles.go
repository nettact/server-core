package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/config"
)

// Game profiles (GAME-001).
//
// A profile names a game by the processes it runs as, and is what turns a list
// of processes that presented frames into a list of games that were played.
// Profiles are configuration, so they live behind config.Service alongside
// monitoring targets: every mutation here bumps the site's game serial and
// re-pushes DesiredState, exactly as a target edit does on its own axis.
//
// Collection (record_unmatched) is a separate endpoint rather than a field on
// the profile list, because it is a site-wide privacy choice about the machine
// and not a property of any one game.

const maxGameProfileBodyBytes = 1 << 16

// gameProfileBody is the create/update payload. TargetFPS is a pointer so the
// console can clear a target by sending null; 0 means the same thing.
type gameProfileBody struct {
	Name       string   `json:"name"`
	Exe        []string `json:"exe"`
	TargetFPS  *int     `json:"target_fps"`
	Tier       string   `json:"tier"`
	MonitorIDs []string `json:"monitor_ids"`
}

func (b gameProfileBody) toRec() config.GameProfileRec {
	return config.GameProfileRec{
		Name:       b.Name,
		Exe:        b.Exe,
		TargetFPS:  b.TargetFPS,
		Tier:       b.Tier,
		MonitorIDs: b.MonitorIDs,
	}
}

// gameProfileAuditDetail describes a profile for the append-only audit trail: the
// name and the processes it claims, which is what an operator reading the trail
// later needs to tell one edit from another.
func gameProfileAuditDetail(p config.GameProfileRec) string {
	if len(p.Exe) == 0 {
		return p.Name
	}
	return p.Name + " · " + strings.Join(p.Exe, ", ")
}

func (d Deps) handleListGameProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := d.Config.GameProfiles(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items []config.GameProfileRec `json:"items"`
	}{Items: profiles})
}

func (d Deps) handleCreateGameProfile(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	var body gameProfileBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxGameProfileBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p, err := d.Config.CreateGameProfile(r.Context(), siteID, body.toRec())
	if err != nil {
		if errors.Is(err, config.ErrGameProfileInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "game_profile.create", p.ID, gameProfileAuditDetail(p))
	writeJSON(w, http.StatusOK, p)
}

func (d Deps) handleUpdateGameProfile(w http.ResponseWriter, r *http.Request) {
	stored, ok := d.gameProfile(w, r)
	if !ok {
		return
	}
	var body gameProfileBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxGameProfileBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p, err := d.Config.UpdateGameProfile(r.Context(), stored.ID, body.toRec())
	if err != nil {
		if errors.Is(err, config.ErrGameProfileInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "game profile not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "game_profile.update", p.ID, gameProfileAuditDetail(p))
	writeJSON(w, http.StatusOK, p)
}

func (d Deps) handleDeleteGameProfile(w http.ResponseWriter, r *http.Request) {
	stored, ok := d.gameProfile(w, r)
	if !ok {
		return
	}
	if _, err := d.Config.DeleteGameProfile(r.Context(), stored.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "game profile not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "game_profile.delete", stored.ID, gameProfileAuditDetail(stored))
	w.WriteHeader(http.StatusNoContent)
}

// gameCollectionBody is the site-wide capture choice, in and out.
type gameCollectionBody struct {
	RecordUnmatched bool `json:"record_unmatched"`
}

func (d Deps) handleGetGameCollection(w http.ResponseWriter, r *http.Request) {
	record, err := d.Config.GameCollection(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, gameCollectionBody{RecordUnmatched: record})
}

func (d Deps) handleUpdateGameCollection(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	var body gameCollectionBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxGameProfileBodyBytes)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := d.Config.SetGameCollection(r.Context(), siteID, body.RecordUnmatched); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "site not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.Audit.Log(r.Context(), "admin", "game_collection.update", siteID,
		"record_unmatched="+boolWord(body.RecordUnmatched))
	writeJSON(w, http.StatusOK, body)
}

// gameProfile loads the addressed profile and enforces site ownership, writing
// the response and returning false when it cannot. Every profile-scoped handler
// goes through it so the ownership check cannot be forgotten on one of them.
func (d Deps) gameProfile(w http.ResponseWriter, r *http.Request) (config.GameProfileRec, bool) {
	p, err := d.Config.GameProfile(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "game profile not found")
			return config.GameProfileRec{}, false
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return config.GameProfileRec{}, false
	}
	if p.SiteID != siteParam(r) {
		writeError(w, http.StatusNotFound, "game profile not found")
		return config.GameProfileRec{}, false
	}
	return p, true
}

func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
