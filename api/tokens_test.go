package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-admin/internal/testenv"
)

// The vendor access token (10 minutes in the fake) is renewed inside the session, before it
// expires; the renewed token is the one used from then on.
func TestVendorTokenIsRenewedBeforeItExpires(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	wantStatus(t, get(e, s, "/v1/vendor-users"), http.StatusOK)
	first := e.Identity.Calls("listVendorUsers")[0].Header.Get("Authorization")
	e.Clock.Advance(9*time.Minute + 45*time.Second)
	wantStatus(t, get(e, s, "/v1/vendor-users"), http.StatusOK)
	if n := len(e.Identity.Calls("renewVendorSession")); n != 1 {
		t.Fatalf("expected one renewal, got %d", n)
	}
	second := e.Identity.Calls("listVendorUsers")[1].Header.Get("Authorization")
	if second == first || second == "" {
		t.Error("the renewed token must be used for the next call")
	}
	// and the handle was spent: a further renewal uses the new one (the fake refuses a reused handle)
	e.Clock.Advance(9*time.Minute + 45*time.Second)
	wantStatus(t, get(e, s, "/v1/vendor-users"), http.StatusOK)
}

// Spec BR-13: with identity down, directory reads keep working until the current token expires;
// after that the answer is 503 and nothing is shown.
func TestIdentityDownKeepsReadsAliveUntilTheTokenExpires(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.Identity.DropNext("renewVendorSession", 12)
	e.Clock.Advance(9*time.Minute + 45*time.Second) // renewal due, token valid for 15 more seconds
	wantStatus(t, get(e, s, "/v1/organisations/"+org), http.StatusOK)
	e.Clock.Advance(30 * time.Second) // expired
	wantProblem(t, get(e, s, "/v1/organisations/"+org), http.StatusServiceUnavailable, "upstream_unavailable")
	e.Identity.Reset()
	wantStatus(t, get(e, s, "/v1/organisations/"+org), http.StatusOK) // identity is back: the handle still works
}

// A vendor user deactivated at identity is refused at the next renewal, which ends the session.
func TestRenewalRefusedByIdentityEndsTheSession(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.Deactivate(testenv.UserID)
	e.Clock.Advance(9*time.Minute + 45*time.Second)
	wantProblem(t, get(e, s, "/v1/organisations"), http.StatusUnauthorized, "auth.invalid_token")
	if e.Sessions.Len() != 0 {
		t.Error("the session must be dropped")
	}
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusUnauthorized)
}

// A 401 from a service means the token was refused: renew once and retry; refused again, the
// session is over.
func TestARefusedTokenIsRenewedOnceThenTheSessionEnds(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.Identity.FailNext("listVendorUsers", http.StatusUnauthorized, 1, "")
	wantStatus(t, get(e, s, "/v1/vendor-users"), http.StatusOK)
	if len(e.Identity.Calls("renewVendorSession")) != 1 {
		t.Error("the refusal should trigger exactly one renewal")
	}
	e.Identity.FailNext("listVendorUsers", http.StatusUnauthorized, 2, "")
	wantProblem(t, get(e, s, "/v1/vendor-users"), http.StatusUnauthorized, "auth.invalid_token")
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusUnauthorized)
}

// The staff session ends when identity's vendor session does, whatever the idle clock says.
func TestSessionEndsWhenIdentityEndsTheVendorSession(t *testing.T) {
	e := testenv.New(t) // the fake identity ends vendor sessions after 12 hours
	s := e.SignIn()
	for i := 0; i < 25; i++ { // stay active for 12.5 hours
		e.Clock.Advance(29 * time.Minute)
		get(e, s, "/v1/sessions/current")
	}
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusUnauthorized)
}

// What the browser sees of a failing service: a stable problem, never upstream text.
func TestUpstreamFailuresBecomeStableProblems(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.Tenancy.FailNext("getOrganisationDirectoryEntry", http.StatusInternalServerError, 1, "") // a 500 is not retried
	rec := get(e, s, "/v1/organisations/"+org)
	wantProblem(t, rec, http.StatusServiceUnavailable, "upstream_unavailable")
	for _, leak := range []string{"injected", "SQL", "stack", "tenancy"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("upstream detail %q leaked: %s", leak, rec.Body.String())
		}
	}
	// a refusal keeps its problem (404, 409, 422 reach the browser as the service said them)
	e.Tenancy.FailNext("getOrganisationDirectoryEntry", http.StatusNotFound, 1, "")
	wantProblem(t, get(e, s, "/v1/organisations/"+org), http.StatusNotFound, "not_found")
}

// A call is retried once, inside the request, with the same Idempotency-Key.
func TestAWriteIsRetriedOnceWithTheSameKey(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.Identity.FailNext("createVendorUser", http.StatusServiceUnavailable, 1, "")
	user := map[string]string{"id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a66", "email": "new@example.invalid", "display_name": "New", "role": "support"}
	wantStatus(t, e.Request(http.MethodPost, "/v1/vendor-users", user, s, testenv.WithKey("create-1")), http.StatusCreated)
	calls := e.Identity.Calls("createVendorUser")
	if len(calls) != 2 {
		t.Fatalf("expected the call and one retry, got %d", len(calls))
	}
	if calls[0].Header.Get("Idempotency-Key") != "create-1" || calls[1].Header.Get("Idempotency-Key") != "create-1" {
		t.Error("the retry must reuse the key")
	}
	// a hard failure is not retried in the background: nothing happens after the response
	e.Identity.FailNext("createVendorUser", http.StatusServiceUnavailable, 5, "")
	before := len(e.Identity.Calls("createVendorUser"))
	wantProblem(t, e.Request(http.MethodPost, "/v1/vendor-users", user, s, testenv.WithKey("create-2")), http.StatusServiceUnavailable, "upstream_unavailable")
	time.Sleep(50 * time.Millisecond)
	if got := len(e.Identity.Calls("createVendorUser")) - before; got != 2 {
		t.Errorf("a failing write made %d attempts, want 2 (the call and one retry)", got)
	}
	// and the failure is not stored: the same key may be tried again
	e.Identity.Reset()
	wantStatus(t, e.Request(http.MethodPost, "/v1/vendor-users", user, s, testenv.WithKey("create-2")), http.StatusCreated)
}
