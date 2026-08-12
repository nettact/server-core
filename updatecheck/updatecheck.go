// Package updatecheck reports whether a newer NetTact release exists for the
// running install, and what the newest agent release is (so the console can flag
// agents left behind).
//
// It is deliberately a *detector*, not an updater: it downloads nothing and
// installs nothing. The only outputs are a Status the console renders and an
// OnUpdate callback the desktop turns into one balloon.
//
// Where "latest" comes from depends on the install:
//
//   - Microsoft Store desktop builds ask the Store itself (the host injects
//     Config.Checker, which on Windows wraps the WinRT StoreContext API). The
//     Store owns their updates, and the download center deliberately 404s the
//     .msix, so the catalog could not answer for them anyway.
//   - Everything else — non-Store desktop builds and standalone servers — reads
//     the public release catalog at d.nettact.org.
//
// The agent's latest version always comes from the catalog, including on Store
// installs: agents are enrolled from anywhere and are not Store-managed.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nettact/server-core/settings"
)

// Install types. They decide both where "latest" comes from and where a user is
// sent to get it.
const (
	InstallStore   = "store"   // desktop app installed from the Microsoft Store (MSIX)
	InstallDesktop = "desktop" // desktop app installed from the download center
	InstallServer  = "server"  // standalone server (binary or container)
)

const (
	// DownloadPageURL is the human-facing download center — where every
	// non-Store install is sent to upgrade.
	DownloadPageURL = "https://d.nettact.org/"

	// StoreProductID is the Microsoft Store product id for the desktop app. It
	// identifies the app in three places that must never drift apart: the web
	// product page below, the ms-windows-store:// protocol URL the desktop opens
	// instead, and the Store catalog query the desktop uses to name a pending
	// update.
	StoreProductID = "9NX7VNLL0QSG"

	// StorePageURL is the Microsoft Store product page for the desktop app. Store
	// installs are sent here; the desktop host opens the ms-windows-store:// form
	// instead so the Store app itself comes up.
	StorePageURL = "https://apps.microsoft.com/store/detail/" + StoreProductID + "?cid=DevShareMCLPCS"

	defaultBaseURL = "https://d.nettact.org"

	// EnvBaseURL overrides the release-catalog origin (air-gapped installs can
	// point it at a mirror). The literal "off" disables update checking entirely:
	// New then returns nil and nothing ever leaves the machine.
	EnvBaseURL = "NETTACT_UPDATE_BASE_URL"

	// EnvAutoUpdate and EnvUpdateCron tell the server whether a host systemd
	// timer manages it, and on what cron. The Docker compose file injects them
	// from .env (NETTACT_AUTO_UPDATE / NETTACT_UPDATE_CRON). Only meaningful for
	// the standalone server; the desktop never sets them.
	EnvAutoUpdate = "NETTACT_AUTO_UPDATE"
	EnvUpdateCron = "NETTACT_UPDATE_CRON"

	// DefaultUpdateCron is the schedule reported when an auto-updating install did
	// not bake NETTACT_UPDATE_CRON. The installer normally always writes it, but a
	// useful default keeps manually assembled deployments from showing no time.
	DefaultUpdateCron = "0 0 3 * * *"
)

// Catalog product ids, as served by GET {base}/api/releases.
const (
	productDesktop = "desktop"
	productServer  = "server"
	productAgent   = "agent"
)

// CheckResult is one product-latest answer from an injected Checker.
type CheckResult struct {
	// LatestVersion is the newest available version ("vX.Y.Z"). It may be empty
	// when the source knows an update exists but cannot name it — the Store
	// reports a pending package update whose version is not always readable.
	LatestVersion string
	Available     bool
}

// Config drives one Service.
type Config struct {
	// InstallType is one of InstallStore / InstallDesktop / InstallServer. It
	// selects the catalog product and the download URL handed to the console.
	InstallType string

	// CurrentVersion is the running build's stamped version ("vX.Y.Z", or "dev"
	// for an unstamped build — which compares as older than every release).
	CurrentVersion string

	// BaseURL overrides the catalog origin for this service (tests). Empty reads
	// EnvBaseURL and falls back to the download center.
	BaseURL string

	// Checker, when non-nil, answers "is there a newer build of this product"
	// instead of the catalog. The desktop passes its Store query here. A failure
	// is not fatal: the cycle keeps whatever it already knew and logs.
	Checker func(ctx context.Context) (CheckResult, error)

	// OnUpdate fires from the daily worker after a check that found a newer
	// version, unless update notices are switched off. The desktop turns it into
	// a tray balloon; it fires on every such cycle, so the caller owns any
	// once-per-version dedup.
	OnUpdate func(Status)

	// Settings reads the update_notice_disabled switch, which the console and the
	// desktop tray share: turning notices off in either place silences both.
	Settings *settings.Service

	Client *http.Client     // nil selects a 30s-timeout client
	Now    func() time.Time // nil selects time.Now
}

// Status is the last check's outcome, serialized into GET /api/v1/server-info
// under "update". It is published from the moment the service exists, so its
// presence means "this install checks for updates" rather than "a check has
// succeeded" — see ProductChecked for the latter.
type Status struct {
	InstallType     string `json:"install_type"`
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`

	// ProductChecked says the three fields above came from a check that actually
	// completed. It exists because the block is also published for the agent
	// version alone — a Store install whose Store query keeps failing reaches the
	// console with nothing but LatestAgentVersion filled in. Without this flag
	// UpdateAvailable=false there is indistinguishable from a real "you are up to
	// date", and the console would turn a failed check into an assurance.
	ProductChecked bool `json:"product_checked"`

	// DownloadURL is where this install upgrades from: the Store product page for
	// a Store install, the download center for everything else.
	DownloadURL string `json:"download_url"`

	// LatestAgentVersion is the newest agent release, used by the console to flag
	// outdated agents. Empty when the catalog has not been read successfully.
	LatestAgentVersion string `json:"latest_agent_version,omitempty"`

	// AutoUpdate reports whether a host timer manages this install, so
	// the console can say "will update itself" instead of offering a manual
	// download. Set from the NETTACT_AUTO_UPDATE environment variable, which the
	// Docker compose file injects from .env. Only the server image sets it; the
	// desktop never does, so this stays false there.
	AutoUpdate bool `json:"auto_update"`

	// UpdateSchedule is the 6-field cron (host-local time) the timer runs on,
	// e.g. "0 30 3 * * *". Empty when auto-update is off. From
	// NETTACT_UPDATE_CRON.
	UpdateSchedule string `json:"update_schedule,omitempty"`

	CheckedAt time.Time `json:"checked_at"`
}

// Service performs update checks and caches the last useful answer.
type Service struct {
	cfg         Config
	baseURL     string
	productID   string
	downloadURL string
	client      *http.Client
	now         func() time.Time

	// checkMu serialises whole check cycles. One cycle reads the last result,
	// spends seconds on the network, then writes the merged result back, so two
	// overlapping cycles would each publish over the other's findings. That is
	// reachable in normal use: the daily worker and a tray "check for updates"
	// click run on different goroutines.
	checkMu sync.Mutex

	mu     sync.Mutex
	status Status
	known  bool
}

// New builds the service, or returns nil when update checking is switched off
// (EnvBaseURL="off"). Every method is nil-safe, so callers never branch on it.
func New(cfg Config) *Service {
	base := cfg.BaseURL
	if base == "" {
		base = strings.TrimSpace(os.Getenv(EnvBaseURL))
	}
	if strings.EqualFold(base, "off") {
		log.Printf("updatecheck: disabled by %s=off", EnvBaseURL)
		return nil
	}
	if base == "" {
		base = defaultBaseURL
	}
	s := &Service{
		cfg:         cfg,
		baseURL:     strings.TrimRight(base, "/"),
		productID:   productServer,
		downloadURL: DownloadPageURL,
		client:      cfg.Client,
		now:         cfg.Now,
	}
	if cfg.InstallType == InstallStore || cfg.InstallType == InstallDesktop {
		s.productID = productDesktop
	}
	if cfg.InstallType == InstallStore {
		s.downloadURL = StorePageURL
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 30 * time.Second}
	}
	if s.now == nil {
		s.now = time.Now
	}
	// Publish a baseline before the first check runs. The console gates its whole
	// software-update panel — including the notice switch shared with the desktop
	// tray — on this block being present, and a check that has not finished yet
	// (or cannot finish: no network, a Store query with no license) must not take
	// the switch away from the person trying to turn notices back on.
	//
	// ProductChecked stays false until a check actually answers, which is what
	// stops the empty LatestVersion here from reading as "you are up to date".
	s.status = Status{
		InstallType:    s.cfg.InstallType,
		CurrentVersion: s.cfg.CurrentVersion,
		DownloadURL:    s.downloadURL,
	}
	// A host update timer (Docker standalone-server deployments only) declares
	// itself through these environment variables, which the compose file injects
	// from .env. They ride along in the baseline status so the console's update
	// panel can pick the right wording even before the first catalog check lands.
	// Desktop/Store installs can never have this timer, so they are gated out even
	// if an inherited environment happens to set the variable.
	if s.cfg.InstallType == InstallServer {
		autoUpdate := envBool(os.Getenv(EnvAutoUpdate))
		// Only a real auto-update reports a schedule, and it must not read as
		// "off" just because the cron is unset; report the documented default.
		var schedule string
		if autoUpdate {
			schedule = strings.TrimSpace(os.Getenv(EnvUpdateCron))
			if schedule == "" {
				schedule = DefaultUpdateCron
			}
		}
		s.status.AutoUpdate = autoUpdate
		s.status.UpdateSchedule = schedule
	}
	s.known = true
	return s
}

// envBool parses the 1/true/empty forms the compose file writes for an on/off
// flag. Anything else reads as false — an unset variable is the norm on the
// desktop and for manual compose users, and must not claim auto-update.
func envBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true":
		return true
	default:
		return false
	}
}

// RunOnce performs one check for the daily worker: failures are logged and
// dropped (a missed check is not worth waking anyone over), and a found update
// fires OnUpdate unless notices are switched off.
func (s *Service) RunOnce(ctx context.Context) {
	if s == nil {
		return
	}
	st, err := s.check(ctx)
	if err != nil {
		log.Printf("updatecheck: %v", err)
		return
	}
	if !st.UpdateAvailable || s.cfg.OnUpdate == nil || s.NoticesDisabled(ctx) {
		return
	}
	s.cfg.OnUpdate(st)
}

// CheckNow performs an immediate check on behalf of a person who asked for one
// (the desktop tray menu) and reports the outcome. It never fires OnUpdate: the
// caller is already showing the result, and a second balloon would be noise.
func (s *Service) CheckNow(ctx context.Context) (Status, error) {
	if s == nil {
		return Status{}, fmt.Errorf("updatecheck: disabled")
	}
	return s.check(ctx)
}

// Status returns the last useful check result, or the baseline New published
// when no check has answered yet. ok is false only for a nil service — update
// checking switched off — which is what keeps the server-info payload free of an
// update block on an install that will never fill one in.
func (s *Service) Status() (Status, bool) {
	if s == nil {
		return Status{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, s.known
}

// NoticesDisabled reports whether the user switched update notices off. The flag
// is a server setting rather than desktop-local state precisely so that turning
// it off in the web console also silences the tray balloon.
func (s *Service) NoticesDisabled(ctx context.Context) bool {
	if s == nil {
		return false
	}
	return s.cfg.Settings.Bool(ctx, settings.KeyUpdateNoticeDisabled)
}

// check runs one cycle. It refreshes each leg independently — the product's own
// latest version and the newest agent release — and carries the previous answer
// forward for whichever leg failed, so a Store query that cannot run (sideloaded
// package, no Store license) does not also cost the console its agent versions.
//
// The returned error describes the PRODUCT leg only: it is what a person who
// clicked "check for updates" is waiting on. A catalog failure that only cost
// the agent version is logged instead.
func (s *Service) check(ctx context.Context) (Status, error) {
	s.checkMu.Lock()
	defer s.checkMu.Unlock()

	st, _ := s.Status()
	st.InstallType = s.cfg.InstallType
	st.CurrentVersion = s.cfg.CurrentVersion
	st.DownloadURL = s.downloadURL
	progress := false

	tags, catErr := s.fetchCatalog(ctx)
	if catErr == nil {
		if v := tags[productAgent]; v != "" {
			st.LatestAgentVersion = v
			progress = true
		}
	} else if s.cfg.Checker != nil {
		// The product leg does not need the catalog here, so this failure only
		// costs the agent version — report it where it will not be mistaken for a
		// failed update check.
		log.Printf("updatecheck: release catalog: %v", catErr)
	}

	var err error
	switch {
	case s.cfg.Checker != nil:
		res, cerr := s.cfg.Checker(ctx)
		if cerr != nil {
			err = fmt.Errorf("store update query: %w", cerr)
			break
		}
		st.LatestVersion, st.UpdateAvailable = res.LatestVersion, res.Available
		// A Checker decides whether an update exists — that is the whole reason it
		// displaces the catalog — so Available is taken verbatim. The name it
		// attaches gets one sanity check: a version that is not newer than what is
		// running cannot be the name of a pending update, and publishing it
		// produces the worst reading available. The console draws "latest version:
		// <the version you are already on>" directly beside a live update notice,
		// and the tray announces the release the user has installed. The
		// unnamed-update path says the same thing honestly, and every consumer
		// already handles it.
		//
		// Not hypothetical tidiness: the Store checker used to read its version
		// off StorePackageUpdate.Package — the *installed* package, per the WinRT
		// contract — so it produced exactly this shape on every Store install with
		// an update pending, and nothing here caught it.
		if st.UpdateAvailable && st.LatestVersion != "" && !Newer(st.LatestVersion, s.cfg.CurrentVersion) {
			log.Printf("updatecheck: checker reported an update but named %q, which is not newer than %q; reporting it unnamed",
				st.LatestVersion, s.cfg.CurrentVersion)
			st.LatestVersion = ""
		}
		progress = true
	case s.cfg.InstallType == InstallStore:
		// A Store install with no Store query has no answer to give: the catalog
		// deliberately omits the .msix, so consulting it would report an update
		// through a channel this install cannot use.
		err = fmt.Errorf("store install has no update source configured")
	case catErr != nil:
		err = fmt.Errorf("release catalog: %w", catErr)
	default:
		v := tags[s.productID]
		if v == "" {
			err = fmt.Errorf("release catalog: no published release for %s", s.productID)
			break
		}
		st.LatestVersion, st.UpdateAvailable = v, Newer(v, s.cfg.CurrentVersion)
		progress = true
	}

	if progress {
		// ProductChecked and CheckedAt only move when the product leg answered. A
		// cycle whose Store query failed still republishes the previous product
		// answer (that is the point of carrying it forward), but must not claim to
		// have just verified it: stamping a fresh timestamp would turn a stale
		// cache into an assertion, and on a first-ever check there is no previous
		// answer at all — the zero value would read as "up to date".
		if err == nil {
			st.ProductChecked = true
			st.CheckedAt = s.now()
		}
		s.publish(st)
	}
	if err != nil {
		return Status{}, err
	}
	return st, nil
}

func (s *Service) publish(st Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.known = st, true
}

// fetchCatalog reads the public release catalog and returns product id →
// latest published tag. Products the catalog could not resolve carry a null tag,
// which arrives here as an empty string and is treated as "unknown" by callers
// rather than as "no release".
func (s *Service) fetchCatalog(ctx context.Context) (map[string]string, error) {
	url := s.baseURL + "/api/releases"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %d", url, resp.StatusCode)
	}
	var body struct {
		Products []struct {
			ID        string `json:"id"`
			LatestTag string `json:"latestTag"`
		} `json:"products"`
	}
	// The catalog carries every release with its assets; only two tags are read
	// from it, so cap the read rather than trusting the origin to stay small.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("%s: decode: %w", url, err)
	}
	out := make(map[string]string, len(body.Products))
	for _, p := range body.Products {
		out[p.ID] = strings.TrimSpace(p.LatestTag)
	}
	return out, nil
}

// Newer reports whether latest is a newer version than current. A current of
// "dev" or anything unparsable is treated as oldest, so an unstamped local build
// sees every release as an update.
func Newer(latest, current string) bool {
	cur, ok := parse(current)
	if !ok {
		return true
	}
	lat, ok := parse(latest)
	if !ok {
		return false
	}
	for i := 0; i < len(lat.nums) || i < len(cur.nums); i++ {
		l, c := 0, 0
		if i < len(lat.nums) {
			l = lat.nums[i]
		}
		if i < len(cur.nums) {
			c = cur.nums[i]
		}
		if l != c {
			return l > c
		}
	}
	// Equal numeric parts: a release beats a pre-release; between two
	// pre-releases compare suffixes lexically.
	if lat.pre == cur.pre {
		return false
	}
	if lat.pre == "" {
		return true
	}
	if cur.pre == "" {
		return false
	}
	return lat.pre > cur.pre
}

type semver struct {
	nums []int
	pre  string
}

func parse(v string) (semver, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var s semver
	if i := strings.IndexByte(v, '-'); i >= 0 {
		s.pre = v[i+1:]
		v = v[:i]
	}
	if v == "" {
		return semver{}, false
	}
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return semver{}, false
		}
		s.nums = append(s.nums, n)
	}
	return s, true
}
