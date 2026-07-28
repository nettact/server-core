package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/nettact/server-core/identity"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store/storetest"
)

func TestOnboardingStateRoundTrip(t *testing.T) {
	db := storetest.Open(t)
	d := Deps{Settings: settings.New(db)}

	get := httptest.NewRecorder()
	d.handleGetOnboardingState(get, httptest.NewRequest(http.MethodGet, "/api/v1/onboarding", nil))
	if get.Code != http.StatusOK || strings.TrimSpace(get.Body.String()) != "null" {
		t.Fatalf("unset GET status=%d body=%q", get.Code, get.Body.String())
	}

	payload := `{"version":1,"status":"in_progress","step":"targets","regions":["cn","apac"],"banner_dismissed":false}`
	put := httptest.NewRecorder()
	d.handleUpdateOnboardingState(put, httptest.NewRequest(http.MethodPut, "/api/v1/onboarding", strings.NewReader(payload)))
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", put.Code, put.Body.String())
	}

	get = httptest.NewRecorder()
	d.handleGetOnboardingState(get, httptest.NewRequest(http.MethodGet, "/api/v1/onboarding", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", get.Code, get.Body.String())
	}
	var got onboardingState
	if err := json.Unmarshal(get.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got.Version != 1 || got.Status != "in_progress" || got.Step != "targets" ||
		len(got.Regions) != 2 || got.Regions[0] != "cn" || got.Regions[1] != "apac" {
		t.Fatalf("GET state=%+v", got)
	}
	raw, err := d.Settings.Get(context.Background(), settings.KeyOnboardingState)
	if err != nil || raw == "" {
		t.Fatalf("stored state=%q err=%v", raw, err)
	}

	publicSettings := httptest.NewRecorder()
	d.handleGetSettings(publicSettings, httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil))
	var settingsBody map[string]string
	if err := json.Unmarshal(publicSettings.Body.Bytes(), &settingsBody); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if _, exposed := settingsBody[settings.KeyOnboardingState]; exposed {
		t.Fatal("onboarding state leaked through generic settings API")
	}
}

func TestOnboardingStateAcceptsEmptyRegions(t *testing.T) {
	db := storetest.Open(t)
	d := Deps{Settings: settings.New(db)}

	// A null regions field must round-trip as an empty array, not null, so the
	// console never has to guard against a null.
	payload := `{"version":1,"status":"done","step":"done","banner_dismissed":true}`
	put := httptest.NewRecorder()
	d.handleUpdateOnboardingState(put, httptest.NewRequest(http.MethodPut, "/api/v1/onboarding", strings.NewReader(payload)))
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", put.Code, put.Body.String())
	}
	var got onboardingState
	if err := json.Unmarshal(put.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode PUT: %v", err)
	}
	if got.Regions == nil {
		t.Fatal("regions should be normalized to an empty slice")
	}
	if len(got.Regions) != 0 {
		t.Fatalf("regions=%v", got.Regions)
	}
}

func TestOnboardingStateRouteRequiresSession(t *testing.T) {
	db := storetest.Open(t)
	d := Deps{Identity: identity.New(db), Settings: settings.New(db)}

	w := httptest.NewRecorder()
	Router(d).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/onboarding", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateOnboardingStateRejectsInvalidPayloads(t *testing.T) {
	db := storetest.Open(t)
	d := Deps{Settings: settings.New(db)}

	cases := map[string]string{
		"malformed":        `{"version":`,
		"wrong version":    `{"version":2,"status":"done","step":"done"}`,
		"bad status":       `{"version":1,"status":"new","step":"welcome"}`,
		"empty status":     `{"version":1,"status":"","step":"welcome"}`,
		"empty step":       `{"version":1,"status":"in_progress","step":""}`,
		"padded step":      `{"version":1,"status":"in_progress","step":" welcome "}`,
		"long step":        `{"version":1,"status":"in_progress","step":"` + strings.Repeat("x", maxOnboardingFieldRunes+1) + `"}`,
		"empty region":     `{"version":1,"status":"in_progress","step":"region","regions":[""]}`,
		"padded region":    `{"version":1,"status":"in_progress","step":"region","regions":[" cn "]}`,
		"long region":      `{"version":1,"status":"in_progress","step":"region","regions":["` + strings.Repeat("x", maxOnboardingFieldRunes+1) + `"]}`,
		"duplicate region": `{"version":1,"status":"in_progress","step":"region","regions":["cn","cn"]}`,
		"unknown field":    `{"version":1,"status":"done","step":"done","extra":true}`,
		"multiple values":  `{"version":1,"status":"done","step":"done"} {}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			d.handleUpdateOnboardingState(w, httptest.NewRequest(http.MethodPut, "/api/v1/onboarding", strings.NewReader(payload)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	t.Run("too many regions", func(t *testing.T) {
		regions := make([]string, maxOnboardingRegions+1)
		for i := range regions {
			regions[i] = "r" + strconv.Itoa(i)
		}
		raw, _ := json.Marshal(regions)
		payload := `{"version":1,"status":"in_progress","step":"region","regions":` + string(raw) + `}`
		w := httptest.NewRecorder()
		d.handleUpdateOnboardingState(w, httptest.NewRequest(http.MethodPut, "/api/v1/onboarding", strings.NewReader(payload)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("oversized", func(t *testing.T) {
		oversized := strings.Repeat(" ", maxOnboardingBodySize) + `{"version":1,"status":"done","step":"done"}`
		w := httptest.NewRecorder()
		d.handleUpdateOnboardingState(w, httptest.NewRequest(http.MethodPut, "/api/v1/onboarding", strings.NewReader(oversized)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})
}
