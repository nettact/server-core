package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeASNTable struct {
	st      ASNTableStatus
	checked int
	err     error
}

func (f *fakeASNTable) ASNTableStatus() ASNTableStatus { return f.st }

func (f *fakeASNTable) CheckASNTable(context.Context) (ASNTableStatus, error) {
	f.checked++
	return f.st, f.err
}

func asnCall(t *testing.T, h http.HandlerFunc, method string) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(method, "/api/v1/asn-table", nil))
	var out map[string]any
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, out
}

func TestASNTableRoutesAbsentWithoutHost(t *testing.T) {
	d := Deps{}
	if code, _ := asnCall(t, d.handleGetASNTable, http.MethodGet); code != http.StatusNotFound {
		t.Fatalf("GET without host = %d, want 404", code)
	}
	if code, _ := asnCall(t, d.handleCheckASNTable, http.MethodPost); code != http.StatusNotFound {
		t.Fatalf("POST without host = %d, want 404", code)
	}
}

func TestASNTableStatusAndCheck(t *testing.T) {
	f := &fakeASNTable{st: ASNTableStatus{Mode: ASNTableModeManaged, Location: "/data/asn", Loaded: true, Version: "20261012", Ranges: 458952, CanCheck: true}}
	d := Deps{ASNTable: f}

	code, out := asnCall(t, d.handleGetASNTable, http.MethodGet)
	if code != http.StatusOK || out["mode"] != "managed" || out["version"] != "20261012" || out["ranges"] != float64(458952) {
		t.Fatalf("GET = %d %v", code, out)
	}
	for _, k := range []string{"location", "source", "loaded", "loaded_at", "last_check_at", "next_check_at", "last_error", "last_error_at", "checking", "can_check"} {
		if _, ok := out[k]; !ok {
			t.Errorf("status JSON missing %q", k)
		}
	}

	if code, _ := asnCall(t, d.handleCheckASNTable, http.MethodPost); code != http.StatusOK || f.checked != 1 {
		t.Fatalf("POST check = %d (checked %d)", code, f.checked)
	}

	f.err = ErrASNTableCheckUnsupported
	if code, _ := asnCall(t, d.handleCheckASNTable, http.MethodPost); code != http.StatusConflict {
		t.Fatalf("POST check in off mode = %d, want 409", code)
	}
}
