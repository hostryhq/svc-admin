package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hostryhq/svc-admin/internal/fakeup"
	"github.com/hostryhq/svc-admin/internal/testenv"
)

type orgList struct {
	Items []struct {
		ID          string `json:"id"`
		OwnerStatus string `json:"owner_status"`
	} `json:"items"`
	Available bool `json:"owner_status_available"`
}

func TestDirectoryListsFromTenancyAndAddsOwnerStatusFromIdentity(t *testing.T) {
	e := testenv.New(t)
	rec := get(e, e.SignIn(), "/v1/organisations?q=Example&status=trial&limit=10")
	wantStatus(t, rec, http.StatusOK)
	l := decodeBody[orgList](t, rec)
	if len(l.Items) != 1 || l.Items[0].OwnerStatus != "pending" || !l.Available {
		t.Fatalf("got %s", rec.Body.String())
	}
	c := e.Tenancy.Calls("listOrganisationDirectory")[0]
	if c.Query.Get("q") != "Example" || c.Query.Get("status") != "trial" || c.Query.Get("limit") != "10" {
		t.Errorf("filters did not reach tenancy: %v", c.Query)
	}
	if c.Header.Get("X-Vendor-Client-Address") != "203.0.113.7" {
		t.Errorf("the staff address must be passed down for the audit record, got %q", c.Header.Get("X-Vendor-Client-Address"))
	}
	if c.Bearer == nil || c.ServiceCaller != "admin" {
		t.Error("a directory call carries the vendor token and the admin service token")
	}
}

// With identity down the directory still loads from tenancy and says so.
func TestDirectoryLoadsWhenIdentityIsDown(t *testing.T) {
	e := testenv.New(t)
	e.Identity.DropNext("getOwnerStatuses", 8) // the Go transport also retries a dropped GET itself
	rec := get(e, e.SignIn(), "/v1/organisations")
	wantStatus(t, rec, http.StatusOK)
	l := decodeBody[orgList](t, rec)
	if l.Available || len(l.Items) != 1 || l.Items[0].OwnerStatus != "unknown" {
		t.Fatalf("got %s", rec.Body.String())
	}
}

func TestDirectoryNeedsTenancy(t *testing.T) {
	e := testenv.New(t)
	e.Tenancy.FailNext("listOrganisationDirectory", http.StatusServiceUnavailable, 2, "up")
	rec := get(e, e.SignIn(), "/v1/organisations")
	wantProblem(t, rec, http.StatusServiceUnavailable, "upstream_unavailable")
}

// An exact owner mobile is looked up in identity, which answers with ids only; tenancy is then
// asked for those ids and never sees the number. A partial number is just a name search.
func TestOwnerMobileSearchGoesThroughIdentityAndNeverToTenancy(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	for _, q := range []string{"9876543210", "+919876543210", "98765%2043210"} {
		rec := get(e, s, "/v1/organisations?q="+strings.ReplaceAll(q, "+", "%2B"))
		wantStatus(t, rec, http.StatusOK)
		if strings.Contains(rec.Body.String(), "9876543210") {
			t.Fatalf("the number came back to the browser for q=%q", q)
		}
	}
	lookups := e.Identity.Calls("lookupOrganisationsByOwnerMobile")
	if len(lookups) != 3 {
		t.Fatalf("%d lookups, want 3", len(lookups))
	}
	for _, l := range lookups {
		if !strings.Contains(string(l.Body), "+919876543210") {
			t.Errorf("lookup body %s", l.Body)
		}
	}
	for _, c := range e.Tenancy.Calls("listOrganisationDirectory") {
		if c.Query.Get("q") != "" || c.Query.Get("organisation_ids") == "" {
			t.Errorf("tenancy must be asked by ids, not by number: %v", c.Query)
		}
		if strings.Contains(c.Path+c.Query.Encode(), "9876543210") {
			t.Error("tenancy saw the number")
		}
	}

	before := len(e.Identity.Calls("lookupOrganisationsByOwnerMobile"))
	wantStatus(t, get(e, s, "/v1/organisations?q=98765"), http.StatusOK)
	if len(e.Identity.Calls("lookupOrganisationsByOwnerMobile")) != before {
		t.Error("a partial number must never be looked up")
	}
	if got := e.Tenancy.Calls("listOrganisationDirectory"); got[len(got)-1].Query.Get("q") != "98765" {
		t.Error("a partial number is an ordinary name search")
	}
}

func TestOwnerMobileWithNoMatchIsAnEmptyListWithoutAskingTenancy(t *testing.T) {
	e := testenv.New(t)
	e.Identity.On("lookupOrganisationsByOwnerMobile", func(_ fakeup.Call, w http.ResponseWriter) bool {
		fakeup.WriteJSON(w, http.StatusOK, map[string]any{"organisation_ids": []string{}})
		return true
	})
	rec := get(e, e.SignIn(), "/v1/organisations?q=9876543210")
	wantStatus(t, rec, http.StatusOK)
	if l := decodeBody[orgList](t, rec); len(l.Items) != 0 || !l.Available {
		t.Fatalf("got %s", rec.Body.String())
	}
	if len(e.Tenancy.Calls("")) != 0 {
		t.Error("nothing to ask tenancy for")
	}
}

// "Onboarding incomplete" is derived from identity's answer, never stored.
func TestOnboardingStateIsDerived(t *testing.T) {
	cases := []struct {
		name, owner string
		invs        []map[string]any
		down        bool
		wantOwner   string
		wantState   string
	}{
		{"pending invitation", "pending", []map[string]any{{"status": "pending"}}, false, "pending", "complete"},
		{"owner accepted", "accepted", []map[string]any{{"status": "accepted"}}, false, "accepted", "complete"},
		{"no owner, no invitation", "none", nil, false, "none", "incomplete"},
		{"only an expired invitation", "expired", []map[string]any{{"status": "expired"}}, false, "expired", "incomplete"},
		{"identity down", "", nil, true, "unknown", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := testenv.New(t)
			e.Identity.On("getOwnerStatuses", func(call fakeup.Call, w http.ResponseWriter) bool {
				fakeup.WriteJSON(w, http.StatusOK, map[string]any{"items": []map[string]any{{"organisation_id": org, "owner_status": c.owner}}})
				return true
			})
			e.Identity.On("listOwnerInvitations", func(_ fakeup.Call, w http.ResponseWriter) bool {
				items := []map[string]any{}
				for _, i := range c.invs {
					items = append(items, map[string]any{"id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a67", "organisation_id": org, "status": i["status"],
						"mobile_masked": "+91*******210", "owner_name": "Asha", "expires_at": "2026-12-08T13:05:11.120Z", "created_at": "2026-11-24T13:05:11.120Z"})
				}
				fakeup.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
				return true
			})
			if c.down {
				e.Identity.DropNext("getOwnerStatuses", 8) // the Go transport also retries a dropped GET itself
			}
			rec := get(e, e.SignIn(), "/v1/organisations/"+org)
			wantStatus(t, rec, http.StatusOK)
			v := decodeBody[struct {
				OwnerStatus string `json:"owner_status"`
				State       string `json:"onboarding_state"`
			}](t, rec)
			if v.OwnerStatus != c.wantOwner || v.State != c.wantState {
				t.Errorf("owner_status %q onboarding_state %q, want %q and %q", v.OwnerStatus, v.State, c.wantOwner, c.wantState)
			}
		})
	}
}

func TestUnknownOrganisationIsNotFoundAndMalformedIdsNeverReachTenancy(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	e.Tenancy.FailNext("getOrganisationDirectoryEntry", http.StatusNotFound, 1, "")
	wantProblem(t, get(e, s, "/v1/organisations/"+org), http.StatusNotFound, "not_found")
	before := len(e.Tenancy.Calls(""))
	for _, id := range []string{"1", "../../internal/v1/vendor/users", "0190a1b2-c3d4-4e5f-8a9b-0c1d2e3f4a60"} {
		wantProblem(t, get(e, s, "/v1/organisations/"+strings.ReplaceAll(id, "/", "%2F")), http.StatusNotFound, "not_found")
	}
	if len(e.Tenancy.Calls("")) != before {
		t.Error("a malformed id must not be forwarded")
	}
}

func TestOwnerInvitationOperationsPassThroughWithMaskedNumbers(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	inv := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a67"
	base := "/v1/organisations/" + org + "/owner-invitations"
	wantStatus(t, get(e, s, base), http.StatusOK)
	rec := e.Request(http.MethodPost, base, map[string]string{"name": "Asha", "mobile_e164": "+919876543210"}, s)
	wantStatus(t, rec, http.StatusCreated)
	if strings.Contains(rec.Body.String(), "9876543210") {
		t.Error("only a masked number may come back")
	}
	wantStatus(t, e.Request(http.MethodPost, base+"/"+inv+"/renewals", nil, s), http.StatusOK)
	wantStatus(t, e.Request(http.MethodPut, base+"/"+inv+"/cancellation", nil, s), http.StatusOK)
	e.Identity.FailNext("createOwnerInvitation", http.StatusConflict, 1, "owner")
	wantProblem(t, e.Request(http.MethodPost, base, map[string]string{"name": "Asha", "mobile_e164": "+919876543210"}, s), http.StatusConflict, "owner_exists")
	wantProblem(t, e.Request(http.MethodPost, base, map[string]string{"name": "Asha", "mobile_e164": "12345"}, s), http.StatusUnprocessableEntity, "validation")
}

func TestVerifyRegistrationAndDevicesPassThrough(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	dev := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e"
	reg := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6b"
	wantStatus(t, e.Request(http.MethodPut, "/v1/organisations/"+org+"/tax-registrations/"+reg+"/verification", map[string]string{"method": "certificate_seen"}, s), http.StatusOK)
	wantStatus(t, get(e, s, "/v1/organisations/"+org+"/devices?limit=5"), http.StatusOK)
	wantStatus(t, get(e, s, "/v1/organisations/"+org+"/devices/"+dev), http.StatusOK)
	if got := e.Identity.Calls("listOrganisationDevices")[0].Query.Get("limit"); got != "5" {
		t.Errorf("limit not passed: %q", got)
	}
	e.Tenancy.FailNext("verifyTaxRegistration", http.StatusConflict, 1, "gstin")
	wantProblem(t, e.Request(http.MethodPut, "/v1/organisations/"+org+"/tax-registrations/"+reg+"/verification", map[string]string{"method": "certificate_seen"}, s), http.StatusConflict, "gstin_in_use")
}

// Device revoke: identity applies the two-person rule and the daily quota; its 409 passes through
// unchanged, and a second approver's approval id travels in the body.
func TestRevokePassesTheQuotaRefusalAndTheApprovalIDThrough(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	path := "/v1/organisations/" + org + "/devices/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e/revocation"
	body := map[string]any{"ticket_reference": "SUP-2041", "reason": "Owner phoned to report a lost tablet.", "verification_method": "callback_to_registered_number", "confirm": true}
	e.Identity.FailNext("revokeOrganisationDevice", http.StatusConflict, 1, "quota")
	wantProblem(t, e.Request(http.MethodPut, path, body, s), http.StatusConflict, "vendor_approval_required")
	body["approval_id"] = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6d"
	rec := e.Request(http.MethodPut, path, body, s)
	wantStatus(t, rec, http.StatusOK)
	calls := e.Identity.Calls("revokeOrganisationDevice")
	if !strings.Contains(string(calls[len(calls)-1].Body), "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6d") {
		t.Error("the approval id must reach identity")
	}
}

func TestAuditFiltersReachIdentityAndEitherPermissionOpensTheLog(t *testing.T) {
	e := testenv.New(t)
	rec := get(e, e.SignIn(), "/v1/audit-entries?organisation_id="+org+"&action=vendor.device.revoked&limit=7")
	wantStatus(t, rec, http.StatusOK)
	q := e.Identity.Calls("listVendorAuditEntries")[0].Query
	if q.Get("organisation_id") != org || q.Get("action") != "vendor.device.revoked" || q.Get("limit") != "7" {
		t.Errorf("filters: %v", q)
	}
	e.AddUser(testenv.User{ID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a73", Email: "own@example.invalid", Role: "support", Permissions: []string{"admin.audit.read_own"}})
	wantStatus(t, get(e, e.SignInAs("own@example.invalid"), "/v1/audit-entries"), http.StatusOK)
}

func TestVendorStaffOperations(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	wantStatus(t, get(e, s, "/v1/vendor-users"), http.StatusOK)
	user := map[string]string{"id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a66", "email": "new@example.invalid", "display_name": "New", "role": "support"}
	rec := e.Request(http.MethodPost, "/v1/vendor-users", user, s)
	wantStatus(t, rec, http.StatusCreated)
	if strings.Contains(strings.ToLower(rec.Body.String()), "setup_token") || strings.Contains(rec.Body.String(), "setup_link") {
		t.Error("the setup link is never returned")
	}
	e.Identity.FailNext("updateVendorUser", http.StatusConflict, 1, "last")
	wantProblem(t, e.Request(http.MethodPatch, "/v1/vendor-users/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a66", map[string]string{"status": "deactivated"}, s), http.StatusConflict, "last_platform_admin")
	if n := e.Sessions.Len(); n != 1 {
		t.Errorf("a refused deactivation must not drop sessions (have %d)", n)
	}
}

// Account setup is public: no session, the service token alone, nothing cached.
func TestAccountSetupIsPublicAndCarriesOnlyTheServiceToken(t *testing.T) {
	e := testenv.New(t)
	rec := e.Request(http.MethodPost, "/v1/account-setups", map[string]string{"setup_token": "setup_example"}, nil)
	wantStatus(t, rec, http.StatusCreated)
	rec = e.Request(http.MethodPost, "/v1/account-setup-completions", map[string]string{"setup_token": "setup_example", "password": "example-passphrase-twelve", "totp_code": "123456"}, nil)
	wantStatus(t, rec, http.StatusOK)
	for _, c := range e.Identity.Calls("") {
		if c.ServiceCaller != "admin" || c.Header.Get("Authorization") != "" {
			t.Errorf("%s: public setup must carry the admin service token and no bearer", c.Op)
		}
	}
	e.Identity.FailNext("completeVendorSetup", http.StatusUnprocessableEntity, 1, "invalid")
	wantProblem(t, e.Request(http.MethodPost, "/v1/account-setup-completions", map[string]string{"setup_token": "used", "password": "example-passphrase-twelve", "totp_code": "123456"}, nil), http.StatusUnprocessableEntity, "setup_link_invalid")
}
