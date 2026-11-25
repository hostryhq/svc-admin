package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"

	"github.com/hostryhq/svc-admin/api"
	"github.com/hostryhq/svc-admin/internal/fakeup"
	"github.com/hostryhq/svc-admin/internal/testenv"
	"github.com/hostryhq/svc-admin/service"
)

// AD2: the cookie is HttpOnly, Secure, SameSite=Strict, host-bound and unguessable.
func TestSignInSetsAHardenedCookie(t *testing.T) {
	e := testenv.New(t)
	rec := e.Request(http.MethodPost, "/v1/sessions", map[string]string{"email": testenv.Email, "password": testenv.Password, "totp_code": testenv.TOTP}, nil)
	wantStatus(t, rec, http.StatusCreated)
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == api.CookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Errorf("cookie attributes wrong: %+v", cookie)
	}
	if !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Errorf("cookie must carry the __Host- prefix, got %q", cookie.Name)
	}
	if len(cookie.Value) < 43 { // 256 bits in base64url
		t.Errorf("session id too short: %d characters", len(cookie.Value))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("API answers must not be cached")
	}
}

// AD2: after sign-in and inside a support session no token reaches the browser, in any body,
// header or cookie; the tokens the service holds are the ones it sent upstream.
func TestNoTokenEverReachesTheBrowser(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	var seen []string
	for _, path := range []string{
		"/v1/sessions/current", "/v1/support-sessions/current", "/v1/organisations", "/v1/organisations/" + org,
		"/v1/organisations/" + org + "/support-view/profile", "/v1/organisations/" + org + "/support-view/members",
		"/v1/organisations/" + org + "/support-view/brands", "/v1/vendor-users", "/v1/audit-entries",
	} {
		rec := get(e, s, path)
		wantStatus(t, rec, http.StatusOK)
		seen = append(seen, rec.Body.String(), headersOf(rec))
	}
	browser := strings.Join(seen, "\n") + s.Cookie

	tokens := map[string]bool{}
	for _, c := range e.Identity.Calls("") {
		collect(tokens, c.Header.Get("Authorization"), c.Body)
	}
	for _, c := range e.Tenancy.Calls("") {
		collect(tokens, c.Header.Get("Authorization"), c.Body)
	}
	if len(tokens) < 2 {
		t.Fatalf("expected the service to have used vendor and support tokens upstream, found %d", len(tokens))
	}
	for tok := range tokens {
		if strings.Contains(browser, tok) {
			t.Fatalf("a token reached the browser: %.12s...", tok)
		}
	}
	if !strings.Contains(browser, s.CSRF) {
		t.Fatal("test setup: the CSRF token should be visible to the browser")
	}
}

func headersOf(rec *httptest.ResponseRecorder) string {
	var b strings.Builder
	for k, v := range rec.Header() {
		b.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	return b.String()
}

func collect(into map[string]bool, authz string, body []byte) {
	if tok, ok := strings.CutPrefix(authz, "Bearer "); ok && tok != "" {
		into[tok] = true
	}
	if i := strings.Index(string(body), "renew-"); i >= 0 {
		end := strings.IndexAny(string(body[i:]), `"`)
		if end > 0 {
			into[string(body[i:i+end])] = true
		}
	}
}

// AD2: a state-changing request with no CSRF token, a wrong one, a foreign Origin or no Origin
// changes nothing: the services see no call.
func TestStateChangesNeedCSRFTokenAndOrigin(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	before := len(e.Tenancy.Calls("")) + len(e.Identity.Calls(""))
	cases := []struct {
		name string
		opts []testenv.Opt
	}{
		{"no csrf token", []testenv.Opt{testenv.WithoutHeader("X-CSRF-Token")}},
		{"wrong csrf token", []testenv.Opt{testenv.WithHeader("X-CSRF-Token", "guess")}},
		{"foreign origin", []testenv.Opt{testenv.WithHeader("Origin", "https://evil.example")}},
		{"no origin", []testenv.Opt{testenv.WithoutHeader("Origin")}},
		{"null origin", []testenv.Opt{testenv.WithHeader("Origin", "null")}},
	}
	targets := []struct{ method, path string }{
		{http.MethodPost, "/v1/organisations"},
		{http.MethodPost, "/v1/vendor-users"},
		{http.MethodPost, "/v1/support-sessions"},
		{http.MethodPut, "/v1/organisations/" + org + "/devices/" + testenv.UserID + "/revocation"},
		{http.MethodDelete, "/v1/sessions/current"},
	}
	for _, c := range cases {
		for _, tg := range targets {
			t.Run(c.name+" "+tg.method+" "+tg.path, func(t *testing.T) {
				rec := e.Request(tg.method, tg.path, orgForm(), s, c.opts...)
				wantProblem(t, rec, http.StatusForbidden, "csrf_failed")
			})
		}
	}
	if after := len(e.Tenancy.Calls("")) + len(e.Identity.Calls("")); after != before {
		t.Fatalf("refused requests reached a service: %d calls before, %d after", before, after)
	}
	// and the session is intact
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusOK)
}

// AD1: the admin API takes the cookie only; a bearer token of any realm is refused.
func TestBearerTokenOfAnyRealmIsRefused(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	vendor := e.VendorIs.Mint(authtest.Spec{Subject: testenv.UserID})
	tenant := e.TenantIs.Mint(authtest.Spec{Tenant: ids.ID(org), Subject: "member-1"})
	for name, tok := range map[string]string{"vendor": vendor, "tenant": tenant, "garbage": "abc"} {
		t.Run(name+" alone", func(t *testing.T) {
			wantProblem(t, get(e, nil, "/v1/organisations", testenv.WithHeader("Authorization", "Bearer "+tok)), http.StatusUnauthorized, "auth.invalid_token")
		})
		t.Run(name+" beside a valid cookie", func(t *testing.T) {
			wantProblem(t, get(e, s, "/v1/organisations", testenv.WithHeader("Authorization", "Bearer "+tok)), http.StatusUnauthorized, "auth.invalid_token")
		})
	}
	if n := len(e.Tenancy.Calls("")); n != 0 {
		t.Fatalf("a refused request reached tenancy (%d calls)", n)
	}
}

func TestNoCookieOrUnknownCookieIsUnauthorised(t *testing.T) {
	e := testenv.New(t)
	wantProblem(t, get(e, nil, "/v1/sessions/current"), http.StatusUnauthorized, "auth.invalid_token")
	wantProblem(t, get(e, &testenv.Session{Cookie: "not-a-session"}, "/v1/organisations"), http.StatusUnauthorized, "auth.invalid_token")
}

// Idle timeout 30 minutes by default: activity extends it, silence ends it.
func TestIdleTimeoutEndsTheSessionAndActivityExtendsIt(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.Clock.Advance(20 * time.Minute)
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusOK) // activity
	e.Clock.Advance(20 * time.Minute)
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusOK) // 40 minutes in, 20 idle
	e.Clock.Advance(31 * time.Minute)
	wantProblem(t, get(e, s, "/v1/sessions/current"), http.StatusUnauthorized, "auth.invalid_token")
	if e.Svc.SessionCount() != 0 {
		t.Error("an idle session must be dropped from memory")
	}
}

func TestIdleTimeoutIsConfigurableAndReportedToTheBrowser(t *testing.T) {
	e := testenv.New(t, testenv.Options{Service: service.Config{IdleTimeout: 5 * time.Minute, AbsoluteTimeout: time.Hour}})
	s := e.SignIn()
	v := decodeBody[struct {
		Idle int `json:"idle_timeout_seconds"`
	}](t, get(e, s, "/v1/sessions/current"))
	if v.Idle != 300 {
		t.Errorf("idle_timeout_seconds = %d, want 300", v.Idle)
	}
	e.Clock.Advance(6 * time.Minute)
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusUnauthorized)
}

func TestAbsoluteTimeoutEndsAnActiveSession(t *testing.T) {
	e := testenv.New(t, testenv.Options{Service: service.Config{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: time.Hour}})
	s := e.SignIn()
	for i := 0; i < 2; i++ { // keep it active for 50 minutes
		e.Clock.Advance(25 * time.Minute)
		wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusOK)
	}
	e.Clock.Advance(15 * time.Minute) // 65 minutes since sign-in, only 15 idle
	wantProblem(t, get(e, s, "/v1/sessions/current"), http.StatusUnauthorized, "auth.invalid_token")
}

// A new session id at every sign-in; an id the client supplies is never adopted; signing in
// again ends the session the browser still held.
func TestSignInIssuesAFreshSessionAndNeverAdoptsAClientId(t *testing.T) {
	e := testenv.New(t)
	first := e.SignIn()
	body := map[string]string{"email": testenv.Email, "password": testenv.Password, "totp_code": testenv.TOTP}

	rec := e.Request(http.MethodPost, "/v1/sessions", body, &testenv.Session{Cookie: "attacker-chosen-id"})
	wantStatus(t, rec, http.StatusCreated)
	var got string
	for _, c := range rec.Result().Cookies() {
		got = c.Value
	}
	if got == "" || got == "attacker-chosen-id" || got == first.Cookie {
		t.Fatalf("sign-in must mint a fresh id, got %q", got)
	}
	wantStatus(t, get(e, &testenv.Session{Cookie: "attacker-chosen-id"}, "/v1/sessions/current"), http.StatusUnauthorized)

	// signing in while holding a live session ends it
	rec = e.Request(http.MethodPost, "/v1/sessions", body, first)
	wantStatus(t, rec, http.StatusCreated)
	wantStatus(t, get(e, first, "/v1/sessions/current"), http.StatusUnauthorized)
}

// Wrong password, unknown email, wrong TOTP and a deactivated account look identical.
func TestSignInFailuresAreIndistinguishable(t *testing.T) {
	e := testenv.New(t)
	e.AddUser(testenv.User{ID: ids.New().String(), Email: "gone@example.invalid", Role: "support", Deactivated: true})
	attempts := []map[string]string{
		{"email": testenv.Email, "password": "wrong-password-value", "totp_code": testenv.TOTP},
		{"email": "nobody@example.invalid", "password": testenv.Password, "totp_code": testenv.TOTP},
		{"email": testenv.Email, "password": testenv.Password, "totp_code": "000000"},
		{"email": "gone@example.invalid", "password": testenv.Password, "totp_code": testenv.TOTP},
		{"email": "", "password": "", "totp_code": ""},
		{"email": "not-an-email", "password": testenv.Password, "totp_code": testenv.TOTP},
	}
	var first string
	for i, a := range attempts {
		rec := e.Request(http.MethodPost, "/v1/sessions", a, nil)
		wantProblem(t, rec, http.StatusUnauthorized, "sign_in_failed")
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("attempt %d set a cookie", i)
		}
		type p struct{ Type, Title, Detail string }
		got := decodeBody[p](t, rec)
		sig := got.Type + "|" + got.Title + "|" + got.Detail
		if i == 0 {
			first = sig
		} else if sig != first {
			t.Errorf("attempt %d answers differently: %q vs %q", i, sig, first)
		}
	}
}

func TestSignInRateLimitPassesThroughWithRetryAfter(t *testing.T) {
	e := testenv.New(t)
	// identity's vendor session operations declare 429; script the answer with the Retry-After a limiter gives
	e.Identity.On("createVendorSession", func(_ fakeup.Call, w http.ResponseWriter) bool {
		w.Header().Set("Retry-After", "30")
		fakeup.Problem(w, http.StatusTooManyRequests, "rate_limited")
		return true
	})
	rec := e.Request(http.MethodPost, "/v1/sessions", map[string]string{"email": testenv.Email, "password": testenv.Password, "totp_code": testenv.TOTP}, nil)
	wantStatus(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") != "30" {
		t.Error("a rate limit must carry Retry-After")
	}
}

// A replay of the same Idempotency-Key within the idle window returns the same body, sets no
// second cookie and does not ask identity again (a TOTP code is accepted once).
func TestSignInReplayReturnsTheSameAnswerWithoutASecondCookie(t *testing.T) {
	e := testenv.New(t)
	body := map[string]string{"email": testenv.Email, "password": testenv.Password, "totp_code": testenv.TOTP}
	first := e.Request(http.MethodPost, "/v1/sessions", body, nil, testenv.WithKey("signin-1"))
	again := e.Request(http.MethodPost, "/v1/sessions", body, nil, testenv.WithKey("signin-1"))
	wantStatus(t, first, http.StatusCreated)
	wantStatus(t, again, http.StatusCreated)
	if first.Body.String() != again.Body.String() {
		t.Error("a replay must return the same body")
	}
	if len(first.Result().Cookies()) != 1 || len(again.Result().Cookies()) != 0 {
		t.Errorf("cookies: first %d, replay %d; want 1 and 0", len(first.Result().Cookies()), len(again.Result().Cookies()))
	}
	if n := len(e.Identity.Calls("createVendorSession")); n != 1 {
		t.Errorf("identity saw %d sign-ins, want 1", n)
	}
	other := map[string]string{"email": testenv.Email, "password": "another-password-value", "totp_code": testenv.TOTP}
	wantProblem(t, e.Request(http.MethodPost, "/v1/sessions", other, nil, testenv.WithKey("signin-1")), http.StatusUnprocessableEntity, "idempotency.mismatch")
}

func TestMissingIdempotencyKeyIsRefused(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	wantProblem(t, e.Request(http.MethodPost, "/v1/organisations", orgForm(), s, testenv.WithoutHeader("Idempotency-Key")), http.StatusUnprocessableEntity, "idempotency.key_invalid")
	wantProblem(t, e.Request(http.MethodPost, "/v1/sessions", map[string]string{}, nil, testenv.WithoutHeader("Idempotency-Key")), http.StatusUnprocessableEntity, "idempotency.key_invalid")
}

// Sign-out drops the session server-side (the old cookie is dead), ends an open support session
// and the vendor session upstream, and a replay still answers 204.
func TestSignOutDropsTheSessionEverywhereAndIsIdempotent(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	rec := e.Request(http.MethodDelete, "/v1/sessions/current", nil, s, testenv.WithKey("out-1"))
	wantStatus(t, rec, http.StatusNoContent)
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Errorf("the cookie must be cleared: %+v", c)
	}
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusUnauthorized)
	if len(e.Identity.Calls("endSupportSession")) != 1 || len(e.Identity.Calls("endVendorSession")) != 1 {
		t.Error("sign-out must end the support session and the vendor session at identity")
	}
	again := e.Request(http.MethodDelete, "/v1/sessions/current", nil, s, testenv.WithKey("out-1"))
	wantStatus(t, again, http.StatusNoContent)
	// another key on the dead cookie is simply unauthorised
	wantStatus(t, e.Request(http.MethodDelete, "/v1/sessions/current", nil, s, testenv.WithKey("out-2")), http.StatusUnauthorized)
}

// Deactivating (or resetting the TOTP of) a vendor user drops that user's sessions in the same
// operation: their next request is refused.
func TestDeactivationDropsTheTargetUsersSessionsImmediately(t *testing.T) {
	e := testenv.New(t)
	other := testenv.User{ID: ids.New().String(), Email: "other@example.invalid", DisplayName: "Other", Role: "support", Permissions: []string{"admin.org.read"}}
	e.AddUser(other)
	admin, victim := e.SignIn(), e.SignInAs(other.Email)
	wantStatus(t, get(e, victim, "/v1/organisations"), http.StatusOK)

	rec := e.Request(http.MethodPatch, "/v1/vendor-users/"+other.ID, map[string]string{"status": "deactivated"}, admin)
	wantStatus(t, rec, http.StatusOK)
	wantStatus(t, get(e, victim, "/v1/organisations"), http.StatusUnauthorized)
	wantStatus(t, get(e, admin, "/v1/organisations"), http.StatusOK)

	// and a deactivated user cannot sign in again
	rec = e.Request(http.MethodPost, "/v1/sessions", map[string]string{"email": other.Email, "password": testenv.Password, "totp_code": testenv.TOTP}, nil)
	wantProblem(t, rec, http.StatusUnauthorized, "sign_in_failed")
}

func TestTotpResetDropsTheTargetUsersSessions(t *testing.T) {
	e := testenv.New(t)
	other := testenv.User{ID: ids.New().String(), Email: "other@example.invalid", DisplayName: "Other", Role: "support", Permissions: []string{"admin.org.read"}}
	e.AddUser(other)
	admin, victim := e.SignIn(), e.SignInAs(other.Email)
	wantStatus(t, e.Request(http.MethodPost, "/v1/vendor-users/"+other.ID+"/totp-resets", nil, admin), http.StatusCreated)
	wantStatus(t, get(e, victim, "/v1/organisations"), http.StatusUnauthorized)
}
