package api_test

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hostryhq/svc-admin/internal/fakeup"
	"github.com/hostryhq/svc-admin/internal/testenv"
)

type onboarding struct {
	State     string `json:"state"`
	RetryHint string `json:"retry_hint"`
	Created   struct {
		Organisation struct {
			ID string `json:"id"`
		} `json:"organisation"`
	} `json:"created"`
	OwnerInvitation *struct {
		ID           string `json:"id"`
		MobileMasked string `json:"mobile_masked"`
	} `json:"owner_invitation"`
}

// countCreations makes the fake tenancy issue a new organisation id per fresh request, so the
// number of distinct ids is the number of organisations that exist.
func countCreations(e *testenv.Env) *atomic.Int32 {
	var n atomic.Int32
	e.Tenancy.On("createOrganisation", func(_ fakeup.Call, w http.ResponseWriter) bool {
		i := n.Add(1)
		id := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b0" + string(rune('0'+i%10))
		fakeup.WriteJSON(w, http.StatusCreated, map[string]any{
			"organisation": map[string]any{"id": id, "name": "Example Hospitality", "status": "trial", "created_at": "2026-11-24T13:05:11.120Z", "updated_at": "2026-11-24T13:05:11.120Z"},
			"brand":        map[string]any{"id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6a", "name": "Example Hospitality", "is_default": true, "created_at": "2026-11-24T13:05:11.120Z"},
			"outlet": map[string]any{"id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61", "brand_id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6a", "name": "Main Restaurant", "kind": "restaurant",
				"status": "active", "state_code": "33", "tax_registration_id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6b", "timezone": "Asia/Kolkata", "created_at": "2026-11-24T13:05:11.120Z"},
			"tax_registration": map[string]any{"id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6b", "legal_name": "Example Hospitality Pvt Ltd", "regime": "regular", "gstin": "33ABCDE1234F1Z5",
				"state_code": "33", "verification": map[string]any{"state": "unverified"}, "status": "open", "created_at": "2026-11-24T13:05:11.120Z"},
		})
		return true
	})
	return &n
}

// AD4: both steps, the same key to both services, the number only in the identity call.
func TestCreateOrganisationRunsTenancyThenIdentityWithOneKey(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	rec := e.Request(http.MethodPost, "/v1/organisations", orgForm(), s, testenv.WithKey("onboard-1"))
	wantStatus(t, rec, http.StatusCreated)
	got := decodeBody[onboarding](t, rec)
	if got.State != "complete" || got.OwnerInvitation == nil || got.Created.Organisation.ID == "" {
		t.Fatalf("unexpected result: %s", rec.Body.String())
	}
	tenancy, identity := e.Tenancy.Calls("createOrganisation"), e.Identity.Calls("createOwnerInvitation")
	if len(tenancy) != 1 || len(identity) != 1 {
		t.Fatalf("calls: tenancy %d, identity %d, want 1 and 1", len(tenancy), len(identity))
	}
	if tenancy[0].Header.Get("Idempotency-Key") != "onboard-1" || identity[0].Header.Get("Idempotency-Key") != "onboard-1" {
		t.Error("the browser's Idempotency-Key must reach both services")
	}
	if !strings.Contains(identity[0].Path, got.Created.Organisation.ID) {
		t.Error("the invitation must be created for the organisation tenancy just made")
	}
	if strings.Contains(string(tenancy[0].Body), "9876543210") || strings.Contains(string(tenancy[0].Body), "owner") {
		t.Error("tenancy must not receive the owner or the number")
	}
	if !strings.Contains(string(identity[0].Body), "+919876543210") {
		t.Error("identity must receive the number")
	}
	if strings.Contains(rec.Body.String(), "9876543210") {
		t.Error("the full number must not come back to the browser")
	}
}

// Same key and body twice: one organisation, one invitation, the same answer.
func TestSameKeyAndBodyTwiceCreatesOneOrganisationAndOneInvitation(t *testing.T) {
	e := testenv.New(t)
	n := countCreations(e)
	s := e.SignIn()
	first := e.Request(http.MethodPost, "/v1/organisations", orgForm(), s, testenv.WithKey("k"))
	again := e.Request(http.MethodPost, "/v1/organisations", orgForm(), s, testenv.WithKey("k"))
	wantStatus(t, first, http.StatusCreated)
	wantStatus(t, again, http.StatusCreated)
	if first.Body.String() != again.Body.String() {
		t.Error("a replay must return the same answer")
	}
	if n.Load() != 1 || len(e.Identity.Calls("createOwnerInvitation")) != 1 {
		t.Errorf("organisations created %d, invitations asked for %d; want 1 and 1", n.Load(), len(e.Identity.Calls("createOwnerInvitation")))
	}
}

// Two concurrent requests with one key: one organisation exists.
func TestConcurrentRequestsWithOneKeyCreateOneOrganisation(t *testing.T) {
	e := testenv.New(t)
	n := countCreations(e)
	s := e.SignIn()
	var wg sync.WaitGroup
	results := make([]int, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = e.Request(http.MethodPost, "/v1/organisations", orgForm(), s, testenv.WithKey("race")).Code
		}()
	}
	wg.Wait()
	for _, c := range results {
		if c != http.StatusCreated && c != http.StatusConflict {
			t.Errorf("unexpected status %d (want 201, or 409 while the first is in progress)", c)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("%d organisations were created for one key, want 1", n.Load())
	}
}

func TestSameKeyWithADifferentBodyIsRefused(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	wantStatus(t, e.Request(http.MethodPost, "/v1/organisations", orgForm(), s, testenv.WithKey("k")), http.StatusCreated)
	other := orgForm()
	other["name"] = "A Different Name"
	wantProblem(t, e.Request(http.MethodPost, "/v1/organisations", other, s, testenv.WithKey("k")), http.StatusUnprocessableEntity, "idempotency.mismatch")
	if len(e.Tenancy.Calls("createOrganisation")) != 1 {
		t.Error("the refused request must not reach tenancy")
	}
}

// AD4: identity failing after step one gives "incomplete"; replaying the same request completes
// it with no second organisation.
func TestIdentityFailureAfterStepOneIsIncompleteAndAReplayCompletesIt(t *testing.T) {
	e := testenv.New(t)
	n := countCreations(e)
	s := e.SignIn()
	e.Identity.FailNext("createOwnerInvitation", http.StatusServiceUnavailable, 2, "") // the call and its one retry

	first := e.Request(http.MethodPost, "/v1/organisations", orgForm(), s, testenv.WithKey("k"))
	wantStatus(t, first, http.StatusCreated)
	a := decodeBody[onboarding](t, first)
	if a.State != "incomplete" || a.OwnerInvitation != nil || a.RetryHint != "replay_request" || a.Created.Organisation.ID == "" {
		t.Fatalf("expected an incomplete result with the organisation: %s", first.Body.String())
	}

	second := e.Request(http.MethodPost, "/v1/organisations", orgForm(), s, testenv.WithKey("k"))
	wantStatus(t, second, http.StatusCreated)
	b := decodeBody[onboarding](t, second)
	if b.State != "complete" || b.OwnerInvitation == nil {
		t.Fatalf("the replay must complete onboarding: %s", second.Body.String())
	}
	if b.Created.Organisation.ID != a.Created.Organisation.ID || n.Load() != 1 {
		t.Errorf("the replay must not create a second organisation (created %d, ids %q vs %q)", n.Load(), a.Created.Organisation.ID, b.Created.Organisation.ID)
	}
}

// When identity refuses the details (not an outage) the hint is the organisation page, not a replay.
func TestIdentityRefusalLeavesTheOrganisationAndPointsToTheInvitationForm(t *testing.T) {
	e := testenv.New(t)
	e.Identity.FailNext("createOwnerInvitation", http.StatusUnprocessableEntity, 1, "")
	rec := e.Request(http.MethodPost, "/v1/organisations", orgForm(), e.SignIn())
	wantStatus(t, rec, http.StatusCreated)
	if got := decodeBody[onboarding](t, rec); got.State != "incomplete" || got.RetryHint != "create_owner_invitation" {
		t.Fatalf("got %s", rec.Body.String())
	}
}

func TestGstinInUseCreatesNothingAndNoInvitation(t *testing.T) {
	e := testenv.New(t)
	e.Tenancy.FailNext("createOrganisation", http.StatusConflict, 1, "gstin")
	rec := e.Request(http.MethodPost, "/v1/organisations", orgForm(), e.SignIn())
	wantProblem(t, rec, http.StatusConflict, "gstin_in_use")
	if len(e.Identity.Calls("createOwnerInvitation")) != 0 {
		t.Error("no invitation may be asked for when no organisation was created")
	}
}

func TestOrganisationFormIsValidatedBeforeAnyServiceIsCalled(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	bad := orgForm()
	bad["name"] = ""
	bad["owner"] = map[string]any{"name": "Asha", "mobile_e164": "98765"}
	rec := e.Request(http.MethodPost, "/v1/organisations", bad, s)
	wantProblem(t, rec, http.StatusUnprocessableEntity, "validation")
	fields := decodeBody[struct {
		Errors []struct{ Field, Code string } `json:"errors"`
	}](t, rec).Errors
	if len(fields) < 2 {
		t.Errorf("expected field errors for name and owner.mobile_e164, got %+v", fields)
	}
	if len(e.Tenancy.Calls("")) != 0 || len(e.Identity.Calls("createOwnerInvitation")) != 0 {
		t.Error("an invalid form must reach no service")
	}
	wantProblem(t, e.Request(http.MethodPost, "/v1/organisations", "{not json", s), http.StatusUnprocessableEntity, "validation")
}

// Verification in the same submit needs admin.registration.verify; without it the registration
// starts unverified (the request to tenancy carries no verification).
func TestVerificationInTheFormNeedsThePermission(t *testing.T) {
	e := testenv.New(t)
	e.AddUser(testenv.User{ID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a70", Email: "onb@example.invalid", Role: "onboarding", Permissions: []string{"admin.org.read", "admin.org.create", "admin.owner_invite.manage"}})
	form := orgForm()
	form["verification"] = map[string]any{"method": "certificate_seen"}

	wantStatus(t, e.Request(http.MethodPost, "/v1/organisations", form, e.SignInAs("onb@example.invalid")), http.StatusCreated)
	wantStatus(t, e.Request(http.MethodPost, "/v1/organisations", form, e.SignIn()), http.StatusCreated)
	calls := e.Tenancy.Calls("createOrganisation")
	if len(calls) != 2 {
		t.Fatalf("got %d tenancy calls", len(calls))
	}
	if strings.Contains(string(calls[0].Body), "verification") {
		t.Error("a user without admin.registration.verify must not send a verification")
	}
	if !strings.Contains(string(calls[1].Body), "verification") {
		t.Error("a platform admin's verification must reach tenancy")
	}
}

// Role matrix: refusal happens in admin, before any service is called.
func TestRolesAreCheckedBeforeAnyServiceIsCalled(t *testing.T) {
	e := testenv.New(t)
	e.AddUser(testenv.User{ID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a71", Email: "sup@example.invalid", Role: "support",
		Permissions: []string{"admin.org.read", "admin.device.read", "admin.device.revoke", "admin.support.session.start", "admin.audit.read_own"}})
	e.AddUser(testenv.User{ID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a72", Email: "bill@example.invalid", Role: "billing", Permissions: []string{"admin.org.read"}})
	sup, bill := e.SignInAs("sup@example.invalid"), e.SignInAs("bill@example.invalid")
	dev := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e"
	denied := []struct {
		who          string
		s            *testenv.Session
		method, path string
		body         any
	}{
		{"support", sup, http.MethodPost, "/v1/organisations", orgForm()},
		{"support", sup, http.MethodGet, "/v1/vendor-users", nil},
		{"support", sup, http.MethodPost, "/v1/vendor-users", map[string]string{}},
		{"support", sup, http.MethodPost, "/v1/organisations/" + org + "/owner-invitations", map[string]string{"name": "A", "mobile_e164": "+919876543210"}},
		{"support", sup, http.MethodPut, "/v1/organisations/" + org + "/tax-registrations/" + dev + "/verification", map[string]string{"method": "certificate_seen"}},
		{"billing", bill, http.MethodGet, "/v1/organisations/" + org + "/devices", nil},
		{"billing", bill, http.MethodPost, "/v1/support-sessions", map[string]string{}},
		{"billing", bill, http.MethodGet, "/v1/audit-entries", nil},
		{"billing", bill, http.MethodGet, "/v1/organisations/" + org + "/support-view/profile", nil},
	}
	for _, d := range denied {
		t.Run(d.who+" "+d.method+" "+d.path, func(t *testing.T) {
			wantProblem(t, e.Request(d.method, d.path, d.body, d.s), http.StatusForbidden, "forbidden")
		})
	}
	for _, c := range e.Tenancy.Calls("") {
		t.Errorf("a refused request reached tenancy: %s", c.Op)
	}
	for _, c := range e.Identity.Calls("") {
		if strings.HasPrefix(c.Path, "/internal/v1/vendor/users") || strings.Contains(c.Path, "owner-invitations") || strings.Contains(c.Path, "support-sessions") {
			t.Errorf("a refused request reached identity: %s", c.Op)
		}
	}
	// what they may do works
	wantStatus(t, get(e, bill, "/v1/organisations"), http.StatusOK)
	wantStatus(t, get(e, sup, "/v1/audit-entries"), http.StatusOK)
}
