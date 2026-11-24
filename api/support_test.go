package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"

	"github.com/hostryhq/svc-admin/internal/fakeup"
	"github.com/hostryhq/svc-admin/internal/testenv"
)

var supportViewPaths = []string{
	"/profile", "/brands", "/outlets", "/tax-registrations", "/document-series", "/settings", "/members", "/roles", "/devices",
}

func supportView(p string) string { return "/v1/organisations/" + org + "/support-view" + p }

func startBody(o string) map[string]any {
	return map[string]any{"organisation_id": o, "ticket_reference": "SUP-2041", "reason": "Owner phoned to report a lost tablet.", "duration_minutes": 30, "mode": "view"}
}

// AD1: a support read carries the support token and the admin service token, never the vendor token.
func TestSupportReadsUseTheSupportTokenWithTheAdminServiceToken(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	for _, p := range supportViewPaths {
		wantStatus(t, get(e, s, supportView(p)), http.StatusOK)
	}
	n := 0
	for _, f := range []*fakeup.Fake{e.Identity, e.Tenancy} {
		for _, c := range f.Calls("") {
			if strings.Contains(c.Path, "/internal/v1/vendor/") {
				continue
			}
			n++
			if c.Bearer == nil || c.Bearer.Type != auth.TypeSupport || c.ServiceCaller != "admin" {
				t.Errorf("%s: a support read must carry a support token and the admin service token", c.Op)
			}
			if c.Bearer != nil && c.Bearer.TenantID != org {
				t.Errorf("%s: the support token names organisation %q", c.Op, c.Bearer.TenantID)
			}
		}
	}
	if n != len(supportViewPaths) {
		t.Errorf("%d support reads reached the services, want %d", n, len(supportViewPaths))
	}
}

// AD1 (admin side): every call to identity or tenancy carries the admin service token, and a call
// on a vendor route carries a vendor token, not a tenant or support one.
func TestEveryUpstreamCallCarriesTheServiceTokenAndTheRightUserToken(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	wantStatus(t, get(e, s, "/v1/organisations"), http.StatusOK)
	wantStatus(t, get(e, s, "/v1/organisations/"+org), http.StatusOK)
	wantStatus(t, get(e, s, "/v1/organisations/"+org+"/devices"), http.StatusOK)
	wantStatus(t, get(e, s, supportView("/members")), http.StatusOK)
	wantStatus(t, e.Request(http.MethodDelete, "/v1/support-sessions/current", nil, s), http.StatusNoContent)
	total := 0
	for _, f := range []*fakeup.Fake{e.Identity, e.Tenancy} {
		for _, c := range f.Calls("") {
			total++
			if c.ServiceCaller != "admin" {
				t.Errorf("%s %s: no admin service token", c.Method, c.Path)
			}
			if strings.HasPrefix(c.Path, "/internal/v1/vendor/") && c.Bearer != nil && c.Bearer.Realm != auth.RealmVendor {
				t.Errorf("%s: a vendor route was called with a %s-realm token", c.Op, c.Bearer.Realm)
			}
		}
	}
	if total < 6 {
		t.Fatalf("only %d calls recorded", total)
	}
}

func TestSupportSessionLifecycle(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	wantProblem(t, get(e, s, "/v1/support-sessions/current"), http.StatusNotFound, "not_found")

	rec := e.Request(http.MethodPost, "/v1/support-sessions", startBody(org), s)
	wantStatus(t, rec, http.StatusCreated)
	v := decodeBody[struct {
		Session   struct{ ID, Status, OrganisationID string }
		Remaining int `json:"seconds_remaining"`
	}](t, rec)
	if v.Remaining != 1800 {
		t.Errorf("seconds_remaining = %d, want 1800", v.Remaining)
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("the support token must stay in the service")
	}

	e.Clock.Advance(5 * time.Minute)
	cur := get(e, s, "/v1/support-sessions/current")
	wantStatus(t, cur, http.StatusOK)
	if r := decodeBody[struct {
		R int `json:"seconds_remaining"`
	}](t, cur).R; r != 1500 {
		t.Errorf("after 5 minutes %d seconds remain, want 1500", r)
	}
	// the session shows on getSession for the banner
	if !strings.Contains(get(e, s, "/v1/sessions/current").Body.String(), "support_session") {
		t.Error("getSession must include the active support session")
	}

	wantStatus(t, e.Request(http.MethodDelete, "/v1/support-sessions/current", nil, s), http.StatusNoContent)
	wantStatus(t, e.Request(http.MethodDelete, "/v1/support-sessions/current", nil, s), http.StatusNoContent) // idempotent
	wantProblem(t, get(e, s, supportView("/profile")), http.StatusForbidden, "support_session_required")
	wantProblem(t, get(e, s, "/v1/support-sessions/current"), http.StatusNotFound, "not_found")
}

func TestSecondStartWhileActiveIsRefusedAndActModeIsNotSupported(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	wantProblem(t, e.Request(http.MethodPost, "/v1/support-sessions", startBody(org), s), http.StatusConflict, "support_session_active")

	s2 := testenv.New(t)
	act := startBody(org)
	act["mode"] = "act"
	wantProblem(t, s2.Request(http.MethodPost, "/v1/support-sessions", act, s2.SignIn()), http.StatusUnprocessableEntity, "mode_not_supported")
	if len(s2.Identity.Calls("startSupportSession")) != 0 {
		t.Error("act mode must be refused before identity is asked")
	}
}

// Reads need a session for exactly that organisation: none is 403, another organisation 404.
func TestSupportReadsNeedASessionForThatOrganisation(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	wantProblem(t, get(e, s, supportView("/members")), http.StatusForbidden, "support_session_required")
	e.StartSupport(s, org)
	other := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4aff"
	wantProblem(t, get(e, s, "/v1/organisations/"+other+"/support-view/members"), http.StatusNotFound, "not_found")
	for _, c := range e.Identity.Calls("listMembers") {
		t.Errorf("a read of another organisation reached identity: %s", c.Path)
	}
}

// A support session that identity ended (time up, deactivation) ends here too, with no stale data.
func TestSupportSessionEndedAtIdentityEndsHere(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	wantStatus(t, get(e, s, supportView("/members")), http.StatusOK)
	e.EndSupportAtIdentity()
	e.Clock.Advance(10 * time.Minute) // the cached support token is now past its expiry
	rec := get(e, s, supportView("/members"))
	wantProblem(t, rec, http.StatusConflict, "support_session_ended")
	wantProblem(t, get(e, s, supportView("/members")), http.StatusForbidden, "support_session_required")
}

func TestSupportSessionExpiresWithTheClock(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org) // 30 minutes
	e.Clock.Advance(29 * time.Minute)
	wantStatus(t, get(e, s, "/v1/support-sessions/current"), http.StatusOK)
	wantStatus(t, get(e, s, "/v1/sessions/current"), http.StatusOK)
	e.Clock.Advance(2 * time.Minute)
	wantProblem(t, get(e, s, supportView("/profile")), http.StatusConflict, "support_session_ended")
	wantProblem(t, get(e, s, "/v1/support-sessions/current"), http.StatusNotFound, "not_found")
}

// Inside the session the support token is renewed by admin before it expires.
func TestSupportTokenIsRenewedInsideTheSession(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	wantStatus(t, get(e, s, supportView("/members")), http.StatusOK)
	first := e.Identity.Calls("listMembers")[0].Header.Get("Authorization")
	e.Clock.Advance(9*time.Minute + 45*time.Second) // inside the 30 s refresh window of a 10 minute token
	wantStatus(t, get(e, s, supportView("/members")), http.StatusOK)
	if len(e.Identity.Calls("renewSupportToken")) != 1 {
		t.Fatalf("expected one renewal, got %d", len(e.Identity.Calls("renewSupportToken")))
	}
	if second := e.Identity.Calls("listMembers")[1].Header.Get("Authorization"); second == first {
		t.Error("the renewed token must be used")
	}
}

// When identity is unreachable the support token keeps working until it expires, then reads fail
// with 503 and show nothing.
func TestSupportRenewalWhileIdentityIsDown(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	e.Identity.DropNext("renewSupportToken", 8)
	e.Clock.Advance(9*time.Minute + 45*time.Second)
	wantStatus(t, get(e, s, supportView("/members")), http.StatusOK) // the token still has 15 seconds
	e.Clock.Advance(30 * time.Second)
	wantProblem(t, get(e, s, supportView("/members")), http.StatusServiceUnavailable, "upstream_unavailable")
}

func TestEndSupportKeepsTheSessionWhenIdentityCannotBeReached(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	e.Identity.DropNext("endSupportSession", 8)
	wantProblem(t, e.Request(http.MethodDelete, "/v1/support-sessions/current", nil, s), http.StatusServiceUnavailable, "upstream_unavailable")
	e.Identity.Reset()                                                      // identity is back
	wantStatus(t, get(e, s, "/v1/support-sessions/current"), http.StatusOK) // retryable
	wantStatus(t, e.Request(http.MethodDelete, "/v1/support-sessions/current", nil, s), http.StatusNoContent)
}

// A support read answers only what the contract names; anything else is dropped, and a body that
// would show a customer's full number or a key is refused rather than forwarded.
func TestSupportAnswersAreClosedAndScrubbed(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.StartSupport(s, org)
	member := func(extra map[string]any) map[string]any {
		m := map[string]any{"id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a64", "display_name": "Asha", "status": "active", "created_at": "2026-11-24T13:05:11.120Z"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	serve := func(extra map[string]any) {
		e.Identity.On("listMembers", func(_ fakeup.Call, w http.ResponseWriter) bool {
			fakeup.WriteJSON(w, http.StatusOK, map[string]any{"items": []any{member(extra)}})
			return true
		})
	}
	serve(map[string]any{"mobile_e164": "+919876543210", "email": "owner@customer.example", "pin_verifier": "x", "public_key": "k"})
	rec := get(e, s, supportView("/members"))
	if rec.Code == http.StatusOK {
		for _, bad := range []string{"9876543210", "owner@customer.example", "pin_verifier", "public_key"} {
			if strings.Contains(rec.Body.String(), bad) {
				t.Errorf("%q reached the browser: %s", bad, rec.Body.String())
			}
		}
	}
	serve(map[string]any{"display_name": "Call +919876543210 now"}) // a known field carrying a full number
	wantProblem(t, get(e, s, supportView("/members")), http.StatusServiceUnavailable, "upstream_unavailable")
}
