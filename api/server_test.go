package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hostryhq/svc-admin/internal/testenv"
)

func TestUnknownRoutesAreProblemJSONAndWrongMethodsAre405(t *testing.T) {
	e := testenv.New(t)
	wantProblem(t, get(e, nil, "/v1/nothing-here"), http.StatusNotFound, "not_found")
	wantProblem(t, get(e, nil, "/nothing"), http.StatusNotFound, "not_found")
	rec := e.Request(http.MethodPost, "/v1/sessions/current", nil, nil)
	wantProblem(t, rec, http.StatusMethodNotAllowed, "method_not_allowed")
	if !strings.Contains(rec.Header().Get("Allow"), "GET") {
		t.Errorf("Allow = %q", rec.Header().Get("Allow"))
	}
	// the generic proxy does not exist: tenant and internal paths are not admin routes
	for _, p := range []string{"/internal/v1/vendor/users", "/v1/members", "/v1/devices", "/v1/brands"} {
		wantStatus(t, get(e, e.SignIn(), p), http.StatusNotFound)
	}
}

// Security headers on every answer; CORS is off (no Access-Control header, preflights are not answered).
func TestSecurityHeadersAndNoCORS(t *testing.T) {
	e := testenv.New(t)
	rec := get(e, nil, "/v1/sessions/current", testenv.WithHeader("Origin", "https://evil.example"))
	h := rec.Header()
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
	} {
		if h.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, h.Get(k), want)
		}
	}
	if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	if h.Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing")
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			t.Errorf("CORS header %s must never be set", k)
		}
	}
	pre := e.Request(http.MethodOptions, "/v1/organisations", nil, nil, testenv.WithHeader("Origin", "https://evil.example"), testenv.WithHeader("Access-Control-Request-Method", "POST"))
	if pre.Header().Get("Access-Control-Allow-Origin") != "" || pre.Code < 400 {
		t.Errorf("a preflight must not be allowed: %d %v", pre.Code, pre.Header())
	}
}

func TestStaticAdminWebIsServedFromTheSameOrigin(t *testing.T) {
	dir := t.TempDir()
	must := func(name, content string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("index.html", "<html>admin</html>")
	must("assets/app.abc123.js", "console.log(1)")
	must("assets/secret/nested.txt", "x")
	secret := filepath.Join(filepath.Dir(dir), "outside-secret.txt")
	if err := os.WriteFile(secret, []byte("do not serve"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := testenv.New(t, testenv.Options{StaticDir: dir})

	idx := get(e, nil, "/")
	wantStatus(t, idx, http.StatusOK)
	if !strings.Contains(idx.Body.String(), "admin") || idx.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("index: %q %v", idx.Body.String(), idx.Header())
	}
	if !strings.Contains(idx.Header().Get("Content-Security-Policy"), "script-src 'self'") || strings.Contains(idx.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Errorf("the page needs a strict CSP without inline script: %q", idx.Header().Get("Content-Security-Policy"))
	}
	if get(e, nil, "/organisations/abc").Body.String() != idx.Body.String() {
		t.Error("a client-side route must fall back to index.html")
	}
	js := get(e, nil, "/assets/app.abc123.js")
	wantStatus(t, js, http.StatusOK)
	if !strings.Contains(js.Header().Get("Cache-Control"), "immutable") {
		t.Error("hashed assets are immutable")
	}
	wantStatus(t, get(e, nil, "/assets/missing.js"), http.StatusNotFound)
	if r := get(e, nil, "/assets/"); strings.Contains(r.Body.String(), "nested") || strings.Contains(r.Body.String(), "secret") {
		t.Error("no directory listing")
	}
	for _, p := range []string{"/../outside-secret.txt", "/%2e%2e/outside-secret.txt", "/assets/../../outside-secret.txt"} {
		if r := get(e, nil, p); strings.Contains(r.Body.String(), "do not serve") {
			t.Errorf("path traversal served a file outside the build: %s", p)
		}
	}
	wantStatus(t, e.Request(http.MethodPost, "/", nil, nil), http.StatusMethodNotAllowed)
	// the API still wins over the static fallback
	wantProblem(t, get(e, nil, "/v1/nothing-here"), http.StatusNotFound, "not_found")
}

func TestHealthEndpoints(t *testing.T) {
	e := testenv.New(t)
	rec := httptest.NewRecorder()
	e.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	wantStatus(t, rec, http.StatusOK)
	rec = httptest.NewRecorder()
	e.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	wantStatus(t, rec, http.StatusOK)
}
