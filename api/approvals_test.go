package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hostryhq/svc-admin/internal/fakeup"
	"github.com/hostryhq/svc-admin/internal/testenv"
	"github.com/hostryhq/svc-admin/repository"
)

const (
	approvalID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6d"
	deviceID   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e"
	arunID     = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a78"
)

// second adds the second vendor user (Arun) and signs him in.
func second(e *testenv.Env, perms ...string) *testenv.Session {
	if len(perms) == 0 {
		perms = testenv.AllAdminPermissions()
	}
	e.AddUser(testenv.User{ID: arunID, Email: "arun@example.invalid", DisplayName: "Arun", Role: "platform_admin", Permissions: perms})
	return e.SignInAs("arun@example.invalid")
}

func deviceApproval() map[string]any {
	return map[string]any{
		"kind": "device_revoke_over_quota", "organisation_id": org, "subject_id": deviceID,
		"ticket_reference": "SUP-2041", "reason": "Owner phoned to report a lost tablet.",
		"verification_method": "callback_to_registered_number",
	}
}

func TestFilingAnApprovalCarriesBothTokensAndAnOwnPermissionPerKind(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	wantStatus(t, e.Request(http.MethodPost, "/v1/approvals", deviceApproval(), s), http.StatusCreated)
	c := e.Identity.Calls("createVendorApproval")
	if len(c) != 1 || c[0].ServiceCaller != "admin" || c[0].Bearer == nil {
		t.Fatalf("filing must reach identity with the admin service token and the vendor token: %+v", c)
	}

	// The gate permission alone is not enough: the kind needs its own (x-permission-by-kind).
	e.AddUser(testenv.User{ID: arunID, Email: "gate@example.invalid", Role: "support", Permissions: []string{"admin.approval.create", "admin.approval.read"}})
	g := e.SignInAs("gate@example.invalid")
	for _, kind := range []string{"org_close", "tax_rule_set_publish", "sign_in_code"} {
		body := deviceApproval()
		body["kind"] = kind
		body["rule_set_id"], body["rule_set_content_hash"], body["effective_date"] = arunID, "sha256:"+strings.Repeat("a", 64), "2026-12-01"
		wantProblem(t, e.Request(http.MethodPost, "/v1/approvals", body, g), http.StatusForbidden, "forbidden")
	}
	if n := len(e.Identity.Calls("createVendorApproval")); n != 1 {
		t.Errorf("a refused kind must not reach identity, calls: %d", n)
	}
}

func TestFilingValidatesTheFieldsOfTheKind(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	body := deviceApproval()
	body["kind"] = "tax_rule_set_publish" // no rule set named
	wantProblem(t, e.Request(http.MethodPost, "/v1/approvals", body, s), http.StatusUnprocessableEntity, "validation")
	body["kind"] = "unheard_of"
	wantProblem(t, e.Request(http.MethodPost, "/v1/approvals", body, s), http.StatusUnprocessableEntity, "validation")
	if n := len(e.Identity.Calls("createVendorApproval")); n != 0 {
		t.Errorf("invalid requests must not reach identity, calls: %d", n)
	}
}

// With fewer than two eligible users identity refuses; there is no single-person override.
func TestNoSecondApproverIsRefusedAsIdentityAnswers(t *testing.T) {
	e := testenv.New(t)
	e.Identity.FailNext("createVendorApproval", http.StatusConflict, 1, "second")
	wantProblem(t, e.Request(http.MethodPost, "/v1/approvals", deviceApproval(), e.SignIn()), http.StatusConflict, "second_approver_unavailable")
}

// The example approval was requested by Priya, the default user: she may not approve it, whatever
// permissions she holds; a different vendor user may.
func TestTheRequesterCannotApproveAndAnotherUserCan(t *testing.T) {
	e := testenv.New(t)
	path := "/v1/approvals/" + approvalID + "/decision"
	wantProblem(t, e.Request(http.MethodPut, path, map[string]string{"totp_code": "123456"}, e.SignIn()), http.StatusConflict, "second_approver_unavailable")
	if n := len(e.Identity.Calls("approveVendorApproval")); n != 0 {
		t.Fatalf("a self-approval must not reach identity, calls: %d", n)
	}
	rec := e.Request(http.MethodPut, path, map[string]string{"totp_code": "123456"}, second(e))
	wantStatus(t, rec, http.StatusOK)
	c := e.Identity.Calls("approveVendorApproval")
	if len(c) != 1 || c[0].ServiceCaller != "admin" || c[0].Bearer == nil || c[0].Bearer.Subject != arunID {
		t.Errorf("the decision must carry the admin service token and the approver's own token: %+v", c)
	}
}

func TestApprovingNeedsThePermissionOfTheKind(t *testing.T) {
	e := testenv.New(t)
	// Identity answers that the approval is a tax rule set publication.
	e.Identity.On("getVendorApproval", func(_ fakeup.Call, w http.ResponseWriter) bool {
		fakeup.WriteJSON(w, http.StatusOK, approvalJSON("tax_rule_set_publish", "pending"))
		return true
	})
	s := second(e, "admin.approval.read", "admin.approval.decide", "admin.org.lifecycle.approve")
	wantProblem(t, e.Request(http.MethodPut, "/v1/approvals/"+approvalID+"/decision", map[string]string{"totp_code": "123456"}, s), http.StatusForbidden, "forbidden")
	if n := len(e.Identity.Calls("approveVendorApproval")); n != 0 {
		t.Errorf("a refused approval must not reach identity, calls: %d", n)
	}
}

func approvalJSON(kind, state string) map[string]any {
	return map[string]any{
		"id": approvalID, "kind": kind, "state": state, "organisation_id": org,
		"requested_by": testenv.UserID, "ticket_reference": "SUP-2041",
		"verification_method": "callback_to_registered_number",
		"created_at":          "2026-11-24T13:05:11.120Z", "expires_at": "2026-11-25T13:05:11.120Z",
	}
}

// The grant for an executing kind is kept in memory against the approver's session, never
// returned, and works once.
func TestTheApprovalGrantStaysInTheSession(t *testing.T) {
	e := testenv.New(t)
	e.Identity.On("getVendorApproval", func(_ fakeup.Call, w http.ResponseWriter) bool {
		fakeup.WriteJSON(w, http.StatusOK, approvalJSON("org_close", "pending"))
		return true
	})
	e.Identity.On("approveVendorApproval", func(_ fakeup.Call, w http.ResponseWriter) bool {
		fakeup.WriteJSON(w, http.StatusOK, map[string]any{
			"approval": approvalJSON("org_close", "approved"),
			"grant":    map[string]any{"token": "grant.secret.value", "expires_at": "2026-11-24T13:10:00Z"},
		})
		return true
	})
	s := second(e)
	rec := e.Request(http.MethodPut, "/v1/approvals/"+approvalID+"/decision", map[string]string{"totp_code": "123456"}, s)
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "grant") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("the grant must not reach the browser: %s", rec.Body.String())
	}
	sess, ok := e.Sessions.Get(s.Cookie)
	if !ok {
		t.Fatal("no session")
	}
	g, ok := e.Svc.TakeGrant(sess, approvalID)
	if !ok || g.Token != "grant.secret.value" || g.Kind != "org_close" {
		t.Fatalf("grant not kept: %+v %v", g, ok)
	}
	if _, again := e.Svc.TakeGrant(sess, approvalID); again {
		t.Error("a grant is single use")
	}
}

func TestAnExpiredGrantIsNotHandedOut(t *testing.T) {
	e := testenv.New(t)
	sess := &repository.Session{Grants: map[string]repository.Grant{
		approvalID: {ApprovalID: approvalID, Token: "x", Expires: e.Clock.Now().Add(-1)},
	}}
	if _, ok := e.Svc.TakeGrant(sess, approvalID); ok {
		t.Error("an expired grant must be refused")
	}
}

// The code half is shown once: a second claim is not answered from admin's replay store.
func TestCodeHalfIsClaimedAtIdentityEachTimeAndNeverCached(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	path := "/v1/approvals/" + approvalID + "/code-half-claims"
	first := e.Request(http.MethodPost, path, nil, s, testenv.WithKey("claim-1"))
	again := e.Request(http.MethodPost, path, nil, s, testenv.WithKey("claim-1"))
	wantStatus(t, first, http.StatusCreated)
	wantStatus(t, again, http.StatusCreated)
	if again.Header().Get("Idempotent-Replayed") != "" {
		t.Error("admin must not keep a code half for a replay")
	}
	c := e.Identity.Calls("claimCodeHalf")
	if len(c) != 2 || c[0].Header.Get("Idempotency-Key") != "claim-1" || c[1].Header.Get("Idempotency-Key") != "claim-1" {
		t.Errorf("both claims must reach identity under the same key: %d calls", len(c))
	}
	e.Identity.FailNext("claimCodeHalf", http.StatusConflict, 1, "state")
	wantProblem(t, e.Request(http.MethodPost, path, nil, s), http.StatusConflict, "approval_not_pending")
}

func TestApprovalReadsAndCancelPassThrough(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	wantStatus(t, get(e, s, "/v1/approvals?state=pending&limit=5"), http.StatusOK)
	if c := e.Identity.Calls("listVendorApprovals")[0]; c.Query.Get("state") != "pending" || c.Query.Get("limit") != "5" {
		t.Errorf("filters did not reach identity: %v", c.Query)
	}
	wantStatus(t, get(e, s, "/v1/approvals/"+approvalID), http.StatusOK)
	wantProblem(t, get(e, s, "/v1/approvals/not-an-id"), http.StatusNotFound, "not_found")
	rec := e.Request(http.MethodPut, "/v1/approvals/"+approvalID+"/cancellation", map[string]string{"reason": "Requester could not be verified by callback."}, s)
	wantStatus(t, rec, http.StatusOK)

	e.AddUser(testenv.User{ID: arunID, Email: "ro@example.invalid", Role: "support", Permissions: []string{"admin.org.read"}})
	ro := e.SignInAs("ro@example.invalid")
	wantProblem(t, get(e, ro, "/v1/approvals"), http.StatusForbidden, "forbidden")
}

// A device revoke over the quota is resolved by two vendor users: the first revoke answers 409, the
// requester files an approval for the device, a second user approves, and the repeated revoke
// carries the approval id.
func TestRevokeOverQuotaIsResolvedByAFiledAndApprovedRequest(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	path := "/v1/organisations/" + org + "/devices/" + deviceID + "/revocation"
	revoke := map[string]any{"ticket_reference": "SUP-2041", "reason": "Owner phoned to report a lost tablet.", "verification_method": "callback_to_registered_number", "confirm": true}
	e.Identity.FailNext("revokeOrganisationDevice", http.StatusConflict, 1, "quota")
	wantProblem(t, e.Request(http.MethodPut, path, revoke, s), http.StatusConflict, "vendor_approval_required")

	wantStatus(t, e.Request(http.MethodPost, "/v1/approvals", deviceApproval(), s), http.StatusCreated)
	wantStatus(t, e.Request(http.MethodPut, "/v1/approvals/"+approvalID+"/decision", map[string]string{"totp_code": "123456"}, second(e)), http.StatusOK)

	revoke["approval_id"] = approvalID
	wantStatus(t, e.Request(http.MethodPut, path, revoke, s), http.StatusOK)
	calls := e.Identity.Calls("revokeOrganisationDevice")
	if last := calls[len(calls)-1]; !strings.Contains(string(last.Body), approvalID) {
		t.Error("the approval id must reach identity")
	}
}
