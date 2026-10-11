package api

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ASNTableAPI is the host's IP→ASN table, reported on the settings page.
//
// The table belongs to the host, not to server-core: where it comes from (an
// operator file, a download the host keeps current, a file packaged with an
// application) and when it refreshes are deployment decisions, so server-core
// only defines what the console needs to see and the one action it may take.
// A nil Deps.ASNTable means the host attributes no hops to autonomous systems
// at all; the routes then answer 404 and server-info omits the asn_table bit,
// the same optional-capability shape LocalAgent uses.
type ASNTableAPI interface {
	// ASNTableStatus reports the table's current state. It must be cheap and
	// never block on a check in progress.
	ASNTableStatus() ASNTableStatus
	// CheckASNTable runs one refresh now — re-reading a file, or asking the
	// update source for a newer snapshot — and returns the resulting status.
	// ErrASNTableCheckUnsupported means this mode has nothing to refresh.
	CheckASNTable(ctx context.Context) (ASNTableStatus, error)
}

// ErrASNTableCheckUnsupported is returned by CheckASNTable when the table has
// no refresh source (mode "off").
var ErrASNTableCheckUnsupported = errors.New("asn table: nothing to check in this mode")

// ASN table modes (ASNTableStatus.Mode).
const (
	ASNTableModeFile    = "file"    // a fixed file the host was pointed at
	ASNTableModeManaged = "managed" // snapshots the host downloads and updates
	ASNTableModeOff     = "off"     // no table configured
)

// ASNTableStatus is the settings-page view of the IP→ASN table.
type ASNTableStatus struct {
	Mode        string     `json:"mode"`
	Location    string     `json:"location"` // file path (file) or install directory (managed)
	Source      string     `json:"source"`   // update source base URL (managed)
	Loaded      bool       `json:"loaded"`
	Version     string     `json:"version"`
	Ranges      int        `json:"ranges"`
	LoadedAt    *time.Time `json:"loaded_at"`
	LastCheckAt *time.Time `json:"last_check_at"`
	NextCheckAt *time.Time `json:"next_check_at"`
	LastError   string     `json:"last_error"`
	LastErrorAt *time.Time `json:"last_error_at"`
	Checking    bool       `json:"checking"`
	CanCheck    bool       `json:"can_check"`
}

func (d Deps) handleGetASNTable(w http.ResponseWriter, r *http.Request) {
	if d.ASNTable == nil {
		writeError(w, http.StatusNotFound, "no asn table on this host")
		return
	}
	writeJSON(w, http.StatusOK, d.ASNTable.ASNTableStatus())
}

func (d Deps) handleCheckASNTable(w http.ResponseWriter, r *http.Request) {
	if d.ASNTable == nil {
		writeError(w, http.StatusNotFound, "no asn table on this host")
		return
	}
	st, err := d.ASNTable.CheckASNTable(r.Context())
	if errors.Is(err, ErrASNTableCheckUnsupported) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	// A failed check is reported through the status (last_error), not as an
	// HTTP failure: the request did what it was asked — it checked — and the
	// console renders the outcome from the same fields either way.
	writeJSON(w, http.StatusOK, st)
}
