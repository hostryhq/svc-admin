package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hostryhq/svc-admin/internal/testenv"
)

const org = testenv.OrgID

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("body is not the expected JSON (%v): %s", err, rec.Body.String())
	}
	return v
}

func code(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("status %d has content type %q, want problem+json (body %s)", rec.Code, ct, rec.Body.String())
	}
	return decodeBody[struct {
		Code string `json:"code"`
	}](t, rec).Code
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d (body %s)", rec.Code, status, rec.Body.String())
	}
}

func wantProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, wantCode string) {
	t.Helper()
	wantStatus(t, rec, status)
	if got := code(t, rec); got != wantCode {
		t.Fatalf("problem code %q, want %q", got, wantCode)
	}
}

func get(e *testenv.Env, s *testenv.Session, path string, opts ...testenv.Opt) *httptest.ResponseRecorder {
	return e.Request(http.MethodGet, path, nil, s, opts...)
}

// orgForm is a valid create-organisation request (a fictional business and number).
func orgForm() map[string]any {
	return map[string]any{
		"name":             "Example Hospitality",
		"outlet":           map[string]any{"name": "Main Restaurant", "kind": "restaurant", "state_code": "33"},
		"tax_registration": map[string]any{"legal_name": "Example Hospitality Pvt Ltd", "regime": "regular", "gstin": "33ABCDE1234F1Z5"},
		"owner":            map[string]any{"name": "Asha", "mobile_e164": "+919876543210"},
	}
}
