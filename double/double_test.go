package double_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/hostryhq/svc-admin/double"
)

type client struct {
	t   *testing.T
	srv *httptest.Server
	n   int
}

func newClient(t *testing.T, d *double.Double) *client {
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	return &client{t: t, srv: srv}
}

func (c *client) do(method, path, body string, h map[string]string) (*http.Response, string) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.srv.URL+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", c.srv.URL)
		c.n++
		req.Header.Set("Idempotency-Key", "k-"+strconv.Itoa(c.n))
		req.Header.Set("X-CSRF-Token", double.CSRFToken)
	}
	for k, v := range h {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func seed() map[string]string {
	return map[string]string{"Cookie": double.CookieName + "=" + double.SeedCookie}
}

func codeOf(t *testing.T, body string) string {
	var p struct{ Code string }
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("not a problem: %s", body)
	}
	return p.Code
}

func TestRefusesWhatTheRealServiceRefuses(t *testing.T) {
	c := newClient(t, double.New(double.Options{}))
	if r, b := c.do("GET", "/v1/organisations", "", nil); r.StatusCode != 401 || codeOf(t, b) != "auth.invalid_token" {
		t.Errorf("no cookie: %d %s", r.StatusCode, b)
	}
	if r, _ := c.do("GET", "/v1/organisations", "", map[string]string{"Cookie": double.CookieName + "=unknown"}); r.StatusCode != 401 {
		t.Errorf("unknown cookie: %d", r.StatusCode)
	}
	h := seed()
	h["Authorization"] = "Bearer abc"
	if r, _ := c.do("GET", "/v1/organisations", "", h); r.StatusCode != 401 {
		t.Errorf("a bearer token must be refused: %d", r.StatusCode)
	}
	for name, hdr := range map[string]map[string]string{
		"no csrf token": {"X-CSRF-Token": ""}, "wrong csrf token": {"X-CSRF-Token": "x"},
		"foreign origin": {"Origin": "https://evil.example"}, "no origin": {"Origin": ""},
	} {
		h := seed()
		for k, v := range hdr {
			h[k] = v
		}
		r, b := c.do("POST", "/v1/organisations", "{}", h)
		if r.StatusCode != 403 || codeOf(t, b) != "csrf_failed" {
			t.Errorf("%s: %d %s", name, r.StatusCode, b)
		}
	}
	if r, b := c.do("POST", "/v1/organisations", "{}", merge(seed(), map[string]string{"Idempotency-Key": ""})); r.StatusCode != 422 || codeOf(t, b) != "idempotency.key_invalid" {
		t.Errorf("no key: %d %s", r.StatusCode, b)
	}
}

func merge(a, b map[string]string) map[string]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// A signed-in support role gets the role matrix; the seed platform admin may do everything.
func TestSignInCreatesRoleLimitedSessions(t *testing.T) {
	c := newClient(t, double.New(double.Options{}))
	in := func(email string) string {
		r, _ := c.do("POST", "/v1/sessions", `{"email":"`+email+`","password":"correct-horse-battery-staple","totp_code":"123456"}`, merge(map[string]string{}, nil))
		if r.StatusCode != 201 {
			t.Fatalf("sign-in %s: %d", email, r.StatusCode)
		}
		for _, ck := range r.Cookies() {
			if ck.Name == double.CookieName {
				if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode {
					t.Errorf("cookie attributes: %+v", ck)
				}
				return ck.Name + "=" + ck.Value
			}
		}
		t.Fatal("no cookie")
		return ""
	}
	support := in("staff@example.invalid")
	if r, b := c.do("POST", "/v1/organisations", "{}", map[string]string{"Cookie": support}); r.StatusCode != 403 || codeOf(t, b) != "forbidden" {
		t.Errorf("a support role must not create organisations: %d %s", r.StatusCode, b)
	}
	if r, _ := c.do("GET", "/v1/organisations", "", map[string]string{"Cookie": support}); r.StatusCode != 200 {
		t.Errorf("support may read organisations: %d", r.StatusCode)
	}
	admin := in(double.SeedUserEmail)
	if r, _ := c.do("POST", "/v1/organisations", "{}", map[string]string{"Cookie": admin}); r.StatusCode != 201 {
		t.Errorf("platform admin may create: %d", r.StatusCode)
	}
	if r, _ := c.do("POST", "/v1/sessions", `{"email":"staff@example.invalid","password":"nope","totp_code":"123456"}`, nil); r.StatusCode != 401 {
		t.Errorf("wrong password: %d", r.StatusCode)
	}
	// signing out ends the session
	if r, _ := c.do("DELETE", "/v1/sessions/current", "", map[string]string{"Cookie": admin}); r.StatusCode != 204 {
		t.Fatalf("sign-out: %d", r.StatusCode)
	}
	if r, _ := c.do("GET", "/v1/organisations", "", map[string]string{"Cookie": admin}); r.StatusCode != 401 {
		t.Errorf("a signed-out session must be dead: %d", r.StatusCode)
	}
}

func TestIdempotentReplayAndMismatch(t *testing.T) {
	c := newClient(t, double.New(double.Options{}))
	body := `{"name":"A"}`
	same := merge(seed(), map[string]string{"Idempotency-Key": "same-key"})
	r1, b1 := c.do("POST", "/v1/organisations", body, same)
	r2, b2 := c.do("POST", "/v1/organisations", body, same)
	if r1.StatusCode != 201 || r2.StatusCode != 201 || b1 != b2 || r2.Header.Get("Idempotent-Replayed") != "true" {
		t.Errorf("replay: %d %d same=%v", r1.StatusCode, r2.StatusCode, b1 == b2)
	}
	if r, b := c.do("POST", "/v1/organisations", `{"name":"B"}`, same); r.StatusCode != 422 || codeOf(t, b) != "idempotency.mismatch" {
		t.Errorf("mismatch: %d %s", r.StatusCode, b)
	}
}

// Failure injection drives a client's error states.
func TestFailureInjectionAndScenarioHeader(t *testing.T) {
	d := double.New(double.Options{})
	c := newClient(t, d)
	d.Fail("listOrganisations", 503, 2, "")
	for i := 0; i < 2; i++ {
		if r, b := c.do("GET", "/v1/organisations", "", seed()); r.StatusCode != 503 || codeOf(t, b) != "upstream_unavailable" {
			t.Errorf("injected %d: %d %s", i, r.StatusCode, b)
		}
	}
	if r, _ := c.do("GET", "/v1/organisations", "", seed()); r.StatusCode != 200 {
		t.Errorf("after the injected failures: %d", r.StatusCode)
	}
	d.Fail("createOrganisation", 409, 1, "gstin")
	if r, b := c.do("POST", "/v1/organisations", "{}", seed()); r.StatusCode != 409 || codeOf(t, b) != "gstin_in_use" {
		t.Errorf("named example: %d %s", r.StatusCode, b)
	}
	h := seed()
	h["X-Double-Scenario"] = "409:ended"
	if r, b := c.do("GET", "/v1/organisations/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60/support-view/profile", "", h); r.StatusCode != 409 || codeOf(t, b) != "support_session_ended" {
		t.Errorf("scenario header: %d %s", r.StatusCode, b)
	}
	var seen []string
	for _, call := range d.Calls() {
		seen = append(seen, call.Op)
	}
	if len(seen) == 0 {
		t.Error("the double should record what it served")
	}
}

func TestUnknownRouteAndStatic(t *testing.T) {
	static := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "app") })
	c := newClient(t, double.New(double.Options{StaticHandler: static}))
	if r, b := c.do("GET", "/v1/nothing", "", seed()); r.StatusCode != 404 || codeOf(t, b) != "not_found" {
		t.Errorf("%d %s", r.StatusCode, b)
	}
	if r, b := c.do("GET", "/", "", nil); r.StatusCode != 200 || b != "app" {
		t.Errorf("static: %d %q", r.StatusCode, b)
	}
}

// Approvals: the gate permission is not enough, the kind needs its own (x-permission-by-kind), and
// the seed platform admin holds every one of them.
func TestApprovalKindsNeedTheirOwnPermission(t *testing.T) {
	c := newClient(t, double.New(double.Options{}))
	r, _ := c.do("POST", "/v1/sessions", `{"email":"staff@example.invalid","password":"correct-horse-battery-staple","totp_code":"123456"}`, nil)
	var support map[string]string
	for _, ck := range r.Cookies() {
		support = map[string]string{"Cookie": ck.Name + "=" + ck.Value}
	}
	file := func(kind string, h map[string]string) int {
		body := `{"kind":"` + kind + `","organisation_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60","ticket_reference":"SUP-2041","reason":"Owner phoned to report a lost tablet.","verification_method":"callback_to_registered_number"}`
		r, _ := c.do("POST", "/v1/approvals", body, h)
		return r.StatusCode
	}
	if got := file("device_revoke_over_quota", support); got != 201 {
		t.Errorf("support role, device revoke approval: %d", got)
	}
	if got := file("org_close", support); got != 403 {
		t.Errorf("support role, org_close: %d, want 403", got)
	}
	if got := file("org_close", seed()); got != 201 {
		t.Errorf("platform admin, org_close: %d", got)
	}
}

func TestSeedWorldAcceptsDeclaredWorldsOnly(t *testing.T) {
	d := double.New(double.Options{})
	if err := d.SeedWorld(context.Background(), "approval-pending"); err != nil {
		t.Errorf("declared world refused: %v", err)
	}
	if err := d.SeedWorld(context.Background(), "no-such-world"); err == nil {
		t.Error("an undeclared world must be refused")
	}
}

// An approval executes once (the grant behind it is single use); SeedWorld starts a fresh fixture.
func TestAnApprovalExecutesOnceAndTheNextTryIsRefusedAsExecuted(t *testing.T) {
	d := double.New(double.Options{})
	c := newClient(t, d)
	path := "/v1/organisations/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60/closure"
	body := `{"approval_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6d","ticket":"SUP-2041","reason":"Owner asked to close the outlet group."}`
	if r, b := c.do("POST", path, body, seed()); r.StatusCode != 200 {
		t.Fatalf("first execution: %d %s", r.StatusCode, b)
	}
	r, b := c.do("POST", path, body, seed())
	var p struct{ Code, Reason string }
	_ = json.Unmarshal([]byte(b), &p)
	if r.StatusCode != 409 || p.Code != "approval_not_executable" || p.Reason != "executed" {
		t.Fatalf("second execution: %d %s", r.StatusCode, b)
	}
	if err := d.SeedWorld(context.Background(), "org-active-approved-close"); err != nil {
		t.Fatal(err)
	}
	if r, b := c.do("POST", path, body, seed()); r.StatusCode != 200 {
		t.Errorf("a fresh world executes again: %d %s", r.StatusCode, b)
	}
	// the other reasons are driven by scenario, with the spec's own example
	r, b = c.do("POST", "/v1/tax-rule-sets/72bdd3f5-68b5-59b0-8e62-2075a1f43c47/publication", `{"approval_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6d"}`,
		merge(seed(), map[string]string{"X-Double-Scenario": "409:approval"}))
	if r.StatusCode != 409 || !strings.Contains(b, `"reason":"not_approved"`) {
		t.Errorf("scenario: %d %s", r.StatusCode, b)
	}
}

func TestTheLedgerExportIsServedAsCSV(t *testing.T) {
	c := newClient(t, double.New(double.Options{}))
	r, b := c.do("GET", "/v1/ledger-exports", "", seed())
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/csv") || !strings.HasPrefix(b, "organisation_id,") {
		t.Errorf("export: %d %q %q", r.StatusCode, r.Header.Get("Content-Type"), b)
	}
}
