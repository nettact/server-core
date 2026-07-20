package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/nettact/server-core/cleanup"
)

// handleCleanupSeries returns the controlled series inventory for a site: every
// stored series grouped by agent -> monitor with human-readable names, data
// extent, an approximate sample count, live/deleted/system status, and the
// orphan summary that drives the one-click "clean deleted targets" action.
func (d Deps) handleCleanupSeries(w http.ResponseWriter, r *http.Request) {
	inv, err := d.Cleanup.Inventory(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

// handleCleanupPreview dry-runs a selection: exact per-tier counts, blocked (live-
// protected) items, and the explicit not-cascaded note. No data is touched.
func (d Deps) handleCleanupPreview(w http.ResponseWriter, r *http.Request) {
	var sel cleanup.Selection
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&sel); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	resp, err := d.Cleanup.Preview(r.Context(), chi.URLParam(r, "id"), sel)
	if err != nil {
		writeCleanupErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleCreateCleanupJob validates and enqueues an async delete job. A resubmit
// with the same client_token returns the existing job (200); a fresh job is 202.
// A job already queued/running yields 409 with its id.
func (d Deps) handleCreateCleanupJob(w http.ResponseWriter, r *http.Request) {
	var req cleanup.CreateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	siteID := chi.URLParam(r, "id")
	jobID, created, err := d.Cleanup.CreateJob(r.Context(), siteID, req)
	if err != nil {
		if errors.Is(err, cleanup.ErrJobRunning) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error(), "job_id": jobID})
			return
		}
		writeCleanupErr(w, err)
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	if created {
		d.Audit.Log(r.Context(), "admin", "metrics.cleanup", jobID, d.cleanupAuditDetail(r.Context(), jobID, req))
	}
	writeJSON(w, status, map[string]string{"job_id": jobID})
}

// cleanupAuditDetail records the mode, the RESOLVED item count (orphans/all modes
// derive their key set server-side, so req.Items is empty), and any time range.
func (d Deps) cleanupAuditDetail(ctx context.Context, jobID string, req cleanup.CreateRequest) string {
	mode := req.Mode
	if mode == "" {
		mode = "selection"
	}
	n := len(req.Items)
	if job, err := d.Cleanup.Job(ctx, jobID); err == nil {
		mode, n = job.Mode, job.TotalItems
	}
	detail := mode + ", " + strconv.Itoa(n) + " items"
	if req.FromTS != 0 || req.ToTS != 0 {
		detail += ", range " + strconv.FormatInt(req.FromTS, 10) + "-" + strconv.FormatInt(req.ToTS, 10)
	}
	return detail
}

// handleGetCleanupJob returns one job's full status including its item list.
func (d Deps) handleGetCleanupJob(w http.ResponseWriter, r *http.Request) {
	job, err := d.Cleanup.Job(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleListCleanupJobs returns the site's recent jobs so the console can resume
// polling after a reload.
func (d Deps) handleListCleanupJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	jobs, err := d.Cleanup.ListJobs(r.Context(), chi.URLParam(r, "id"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if jobs == nil {
		jobs = []cleanup.JobSummary{}
	}
	writeJSON(w, http.StatusOK, jobs)
}

// writeCleanupErr maps a client-fixable ValidationError to 400 and anything else
// to 500.
func writeCleanupErr(w http.ResponseWriter, err error) {
	var ve cleanup.ValidationError
	if errors.As(err, &ve) {
		writeError(w, http.StatusBadRequest, ve.Msg)
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}
