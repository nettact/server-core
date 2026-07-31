package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v1.2.3", "v1.2.2", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.3", "v1.3.0", false},
		{"v1.2.3", "dev", true},   // unstamped build: every release is newer
		{"v1.2", "v1.2.0", false}, // shorter form pads with zeros
		{"v1.2.1", "v1.2", true},
		{"v1.2.3", "v1.2.3-rc1", true},  // release beats pre-release
		{"v1.2.3-rc1", "v1.2.3", false}, // pre-release loses to release
		{"v1.2.3-rc2", "v1.2.3-rc1", true},
		{"not-a-version", "v1.0.0", false}, // unparsable latest is never newer
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

// catalog serves a minimal /api/releases with the given product→tag pairs.
// A tag of "" is rendered as JSON null, which is what the real worker emits for
// a product whose releases could not be listed.
func catalog(t *testing.T, tags map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/releases" {
			http.NotFound(w, r)
			return
		}
		type product struct {
			ID        string  `json:"id"`
			LatestTag *string `json:"latestTag"`
		}
		var out struct {
			Products []product `json:"products"`
		}
		for id, tag := range tags {
			p := product{ID: id}
			if tag != "" {
				v := tag
				p.LatestTag = &v
			}
			out.Products = append(out.Products, p)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckServerInstall(t *testing.T) {
	srv := catalog(t, map[string]string{
		"server-lite": "v0.4.0",
		"desktop":     "v9.9.9", // must not be consulted for a server install
		"agent":       "v0.3.1",
	})
	s := New(Config{
		InstallType:    InstallServer,
		CurrentVersion: "v0.3.0",
		BaseURL:        srv.URL,
	})
	st, err := s.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if st.LatestVersion != "v0.4.0" || !st.UpdateAvailable || !st.ProductChecked {
		t.Errorf("product leg = %q/%v/%v, want v0.4.0/true/true", st.LatestVersion, st.UpdateAvailable, st.ProductChecked)
	}
	if st.LatestAgentVersion != "v0.3.1" {
		t.Errorf("LatestAgentVersion = %q, want v0.3.1", st.LatestAgentVersion)
	}
	if st.DownloadURL != DownloadPageURL {
		t.Errorf("DownloadURL = %q, want the download center", st.DownloadURL)
	}
	if got, ok := s.Status(); !ok || got.LatestVersion != "v0.4.0" {
		t.Errorf("Status() = %+v, %v; want the checked status", got, ok)
	}
}

func TestCheckDesktopInstallUpToDate(t *testing.T) {
	srv := catalog(t, map[string]string{"desktop": "v1.0.0", "agent": "v1.0.0"})
	s := New(Config{InstallType: InstallDesktop, CurrentVersion: "v1.0.0", BaseURL: srv.URL})
	st, err := s.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if st.UpdateAvailable {
		t.Error("UpdateAvailable = true for an up-to-date build")
	}
}

func TestCheckStoreInstallUsesCheckerAndCatalogAgent(t *testing.T) {
	srv := catalog(t, map[string]string{
		"desktop": "v2.0.0", // the catalog must NOT decide a Store install's answer
		"agent":   "v1.5.0",
	})
	s := New(Config{
		InstallType:    InstallStore,
		CurrentVersion: "v1.0.0",
		BaseURL:        srv.URL,
		Checker: func(context.Context) (CheckResult, error) {
			return CheckResult{LatestVersion: "v1.1.0", Available: true}, nil
		},
	})
	st, err := s.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if st.LatestVersion != "v1.1.0" {
		t.Errorf("LatestVersion = %q, want the Store's v1.1.0", st.LatestVersion)
	}
	if st.LatestAgentVersion != "v1.5.0" {
		t.Errorf("LatestAgentVersion = %q, want the catalog's v1.5.0", st.LatestAgentVersion)
	}
	if st.DownloadURL != StorePageURL {
		t.Errorf("DownloadURL = %q, want the Store page", st.DownloadURL)
	}
}

// A Store query that cannot run (sideloaded package, no Store license) must not
// also cost the console its agent version.
func TestCheckStoreFailureKeepsAgentVersion(t *testing.T) {
	srv := catalog(t, map[string]string{"agent": "v1.5.0"})
	s := New(Config{
		InstallType:    InstallStore,
		CurrentVersion: "v1.0.0",
		BaseURL:        srv.URL,
		Checker: func(context.Context) (CheckResult, error) {
			return CheckResult{}, fmt.Errorf("no store license")
		},
	})
	if _, err := s.CheckNow(context.Background()); err == nil {
		t.Fatal("CheckNow: want the Store error surfaced to the caller")
	}
	st, ok := s.Status()
	if !ok || st.LatestAgentVersion != "v1.5.0" {
		t.Errorf("Status() = %+v, %v; want the agent version published anyway", st, ok)
	}
	if st.UpdateAvailable {
		t.Error("UpdateAvailable = true despite the Store query failing")
	}
	// The block reaching the console with only an agent version must not read as
	// "you are up to date" — that would turn a failed check into an assurance.
	if st.ProductChecked {
		t.Error("ProductChecked = true although the product leg never answered")
	}
	if !st.CheckedAt.IsZero() {
		t.Errorf("CheckedAt = %v, want the zero value on a never-completed product check", st.CheckedAt)
	}
}

// A cycle whose product leg failed still republishes what it carried forward,
// but must not claim it just verified it — the console renders CheckedAt.
func TestCheckedAtOnlyMovesOnAProductAnswer(t *testing.T) {
	srv := catalog(t, map[string]string{"agent": "v1.5.0"})
	first := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	now := first
	var storeErr error
	s := New(Config{
		InstallType:    InstallStore,
		CurrentVersion: "v1.0.0",
		BaseURL:        srv.URL,
		Now:            func() time.Time { return now },
		Checker: func(context.Context) (CheckResult, error) {
			return CheckResult{LatestVersion: "v1.1.0", Available: true}, storeErr
		},
	})
	if _, err := s.CheckNow(context.Background()); err != nil {
		t.Fatalf("first CheckNow: %v", err)
	}

	now = first.Add(24 * time.Hour)
	storeErr = fmt.Errorf("no store license")
	if _, err := s.CheckNow(context.Background()); err == nil {
		t.Fatal("second CheckNow: want the Store error")
	}
	st, _ := s.Status()
	if !st.CheckedAt.Equal(first) {
		t.Errorf("CheckedAt = %v, want it left at %v — the product leg never answered", st.CheckedAt, first)
	}
	if st.LatestVersion != "v1.1.0" || !st.UpdateAvailable {
		t.Errorf("status = %+v; want the previous product answer carried forward", st)
	}
}

// A Store install with no Store query must not fall back to the release
// catalog: the .msix is deliberately absent there, so the catalog's answer would
// point a Store user at a channel they cannot use.
func TestStoreInstallWithoutCheckerDoesNotUseCatalog(t *testing.T) {
	srv := catalog(t, map[string]string{"desktop": "v2.0.0", "agent": "v1.0.0"})
	s := New(Config{InstallType: InstallStore, CurrentVersion: "v1.0.0", BaseURL: srv.URL})
	if _, err := s.CheckNow(context.Background()); err == nil {
		t.Fatal("CheckNow succeeded without a Store query configured")
	}
	if st, ok := s.Status(); ok && st.UpdateAvailable {
		t.Errorf("status = %+v; want no product answer from the catalog", st)
	}
}

func TestCheckCatalogFailureKeepsPreviousStatus(t *testing.T) {
	var fail atomic.Bool
	inner := catalog(t, map[string]string{"server-lite": "v0.4.0", "agent": "v0.3.1"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, inner.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)

	s := New(Config{InstallType: InstallServer, CurrentVersion: "v0.3.0", BaseURL: srv.URL})
	if _, err := s.CheckNow(context.Background()); err != nil {
		t.Fatalf("first CheckNow: %v", err)
	}
	fail.Store(true)
	if _, err := s.CheckNow(context.Background()); err == nil {
		t.Fatal("second CheckNow: want an error")
	}
	st, ok := s.Status()
	if !ok || st.LatestVersion != "v0.4.0" {
		t.Errorf("Status() = %+v, %v; want the last good answer retained", st, ok)
	}
}

func TestCheckMissingProductIsAnError(t *testing.T) {
	srv := catalog(t, map[string]string{"server-lite": "", "agent": "v1.0.0"})
	s := New(Config{InstallType: InstallServer, CurrentVersion: "v0.1.0", BaseURL: srv.URL})
	if _, err := s.CheckNow(context.Background()); err == nil {
		t.Fatal("CheckNow: want an error when the product has no published release")
	}
	// The agent leg still succeeded, so the console keeps something useful.
	if st, ok := s.Status(); !ok || st.LatestAgentVersion != "v1.0.0" {
		t.Errorf("Status() = %+v, %v; want the agent version published", st, ok)
	}
}

func TestStatusUnknownBeforeFirstSuccess(t *testing.T) {
	s := New(Config{InstallType: InstallServer, CurrentVersion: "v1.0.0", BaseURL: "http://127.0.0.1:1"})
	if _, ok := s.Status(); ok {
		t.Error("Status() reported known before any successful check")
	}
	s.RunOnce(context.Background()) // must not panic; failure is logged and dropped
	if _, ok := s.Status(); ok {
		t.Error("Status() reported known after a failed check")
	}
}

func TestRunOnceFiresOnUpdateOnlyWhenNewer(t *testing.T) {
	srv := catalog(t, map[string]string{"server-lite": "v1.0.0", "agent": "v1.0.0"})
	var fired atomic.Int32
	newSvc := func(current string) *Service {
		return New(Config{
			InstallType:    InstallServer,
			CurrentVersion: current,
			BaseURL:        srv.URL,
			OnUpdate:       func(Status) { fired.Add(1) },
		})
	}
	newSvc("v1.0.0").RunOnce(context.Background())
	if fired.Load() != 0 {
		t.Fatalf("OnUpdate fired %d times for an up-to-date build", fired.Load())
	}
	newSvc("v0.9.0").RunOnce(context.Background())
	if fired.Load() != 1 {
		t.Fatalf("OnUpdate fired %d times, want 1", fired.Load())
	}
}

// CheckNow is a person clicking "check for updates"; the result is already on
// screen, so it must not also fire the background notification path.
func TestCheckNowDoesNotFireOnUpdate(t *testing.T) {
	srv := catalog(t, map[string]string{"server-lite": "v2.0.0", "agent": "v1.0.0"})
	var fired atomic.Int32
	s := New(Config{
		InstallType:    InstallServer,
		CurrentVersion: "v1.0.0",
		BaseURL:        srv.URL,
		OnUpdate:       func(Status) { fired.Add(1) },
	})
	if _, err := s.CheckNow(context.Background()); err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if fired.Load() != 0 {
		t.Errorf("OnUpdate fired %d times from CheckNow", fired.Load())
	}
}

func TestNewDisabledByEnv(t *testing.T) {
	t.Setenv(EnvBaseURL, "off")
	s := New(Config{InstallType: InstallServer, CurrentVersion: "v1.0.0"})
	if s != nil {
		t.Fatal("New returned a service despite the off switch")
	}
	// Every method must stay usable on the nil service.
	s.RunOnce(context.Background())
	if _, ok := s.Status(); ok {
		t.Error("nil Service reported a known status")
	}
	if s.NoticesDisabled(context.Background()) {
		t.Error("nil Service reported notices disabled")
	}
	if _, err := s.CheckNow(context.Background()); err == nil {
		t.Error("nil Service CheckNow returned no error")
	}
}

func TestNewReadsEnvBaseURL(t *testing.T) {
	srv := catalog(t, map[string]string{"server-lite": "v3.0.0", "agent": "v1.0.0"})
	t.Setenv(EnvBaseURL, srv.URL+"/")
	s := New(Config{InstallType: InstallServer, CurrentVersion: "v1.0.0"})
	st, err := s.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if st.LatestVersion != "v3.0.0" {
		t.Errorf("LatestVersion = %q, want the mirror's v3.0.0", st.LatestVersion)
	}
}

func TestCheckedAtUsesClockSeam(t *testing.T) {
	srv := catalog(t, map[string]string{"server-lite": "v1.0.0", "agent": "v1.0.0"})
	want := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	s := New(Config{
		InstallType:    InstallServer,
		CurrentVersion: "v1.0.0",
		BaseURL:        srv.URL,
		Now:            func() time.Time { return want },
	})
	st, err := s.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if !st.CheckedAt.Equal(want) {
		t.Errorf("CheckedAt = %v, want %v", st.CheckedAt, want)
	}
}
