package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/hostryhq/svc-admin/internal/fakeup"
	"github.com/hostryhq/svc-admin/internal/testenv"
)

const (
	grantToken = "grant.secret.value"
	ruleSetID  = "72bdd3f5-68b5-59b0-8e62-2075a1f43c47" // a UUIDv5: billing derives the id from the version
)

// approval scripts identity's view of approval 4a6d: its kind, its state, and the grant issued at
// approval. state changes when the approval is decided, as identity would.
type approval struct {
	mu       sync.Mutex
	kind     string
	state    string
	approver string
	subject  string // rule set id for tax_rule_set_publish, shown on the record
}

func (a *approval) json() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := approvalJSON(a.kind, a.state)
	m["reason"] = "Owner asked to close the outlet group."
	if a.state == "approved" {
		m["approved_by"] = a.approver
	}
	if a.kind == "tax_rule_set_publish" {
		delete(m, "organisation_id")
		if a.subject != "" {
			m["subject_id"] = a.subject
		}
	}
	return m
}

func scriptApproval(e *testenv.Env, kind, subject string) *approval {
	a := &approval{kind: kind, state: "pending", subject: subject}
	e.Identity.On("getVendorApproval", func(_ fakeup.Call, w http.ResponseWriter) bool {
		fakeup.WriteJSON(w, http.StatusOK, a.json())
		return true
	})
	e.Identity.On("approveVendorApproval", func(c fakeup.Call, w http.ResponseWriter) bool {
		a.mu.Lock()
		a.state, a.approver = "approved", c.Bearer.Subject
		a.mu.Unlock()
		fakeup.WriteJSON(w, http.StatusOK, map[string]any{
			"approval": a.json(),
			"grant":    map[string]any{"token": grantToken, "expires_at": "2026-11-24T13:10:00Z"},
		})
		return true
	})
	return a
}

func approve(t *testing.T, e *testenv.Env, s *testenv.Session) map[string]any {
	t.Helper()
	rec := e.Request(http.MethodPut, "/v1/approvals/"+approvalID+"/decision", map[string]string{"totp_code": "123456"}, s)
	wantStatus(t, rec, http.StatusOK)
	return decodeBody[map[string]any](t, rec)
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func ruleSetDraft() map[string]any {
	return map[string]any{
		"name": "GST restaurant services 2026 B", "effective_date": "2026-12-15", "calc_v": 1,
		"rules": []map[string]any{{
			"tax_class": "fnb_standard", "regime": "regular", "specified_premises": false, "order_channel": "dine_in",
			"doc_type": "tax_invoice", "gst_applies": true, "cgst_bp": 250, "sgst_bp": 250, "igst_bp": 0,
		}},
	}
}

func execBody() map[string]any {
	return map[string]any{"approval_id": approvalID, "ticket": "SUP-2041", "reason": "Owner asked to close the outlet group."}
}

// Approving an executing kind approves and executes in one request. The grant goes to tenancy in
// Hostry-Vendor-Approval with the admin service token and the approver's own token, and never to the
// browser; a second execution of the same approval is refused as executed.
func TestApprovingASuspensionExecutesItWithTheGrantAndTheApproversToken(t *testing.T) {
	e := testenv.New(t)
	scriptApproval(e, "org_suspend", "")
	s := second(e)
	view := approve(t, e, s)
	if ex, _ := view["execution"].(map[string]any); ex["state"] != "executed" {
		t.Fatalf("approval must execute: %v", view)
	}
	calls := e.Tenancy.Calls("suspendOrganisation")
	if len(calls) != 1 {
		t.Fatalf("tenancy calls: %d", len(calls))
	}
	c := calls[0]
	if c.Header.Get("Hostry-Vendor-Approval") != grantToken || c.ServiceCaller != "admin" || c.Bearer == nil || c.Bearer.Subject != arunID {
		t.Errorf("execution must carry the grant, the service token and the approver's token: %+v", c.Header)
	}
	if c.Header.Get("Idempotency-Key") == "" || c.Header.Get("X-Vendor-Client-Address") != "203.0.113.7" {
		t.Errorf("idempotency key and client address must reach tenancy: %v", c.Header)
	}
	var sent map[string]any
	_ = c.JSON(&sent)
	if _, has := sent["approval_id"]; has || sent["ticket"] != "SUP-2041" {
		t.Errorf("approval_id is a parameter of the facade only: %v", sent)
	}

	// Identity records the execution later; until then the session knows it ran.
	a := scriptApproval(e, "org_suspend", "")
	a.state, a.approver = "approved", arunID
	rec := e.Request(http.MethodPost, "/v1/organisations/"+org+"/suspension", execBody(), s)
	wantProblem(t, rec, http.StatusConflict, "approval_not_executable")
	if r := decodeBody[map[string]any](t, rec)["reason"]; r != "executed" {
		t.Errorf("reason %v", r)
	}
	if n := len(e.Tenancy.Calls("suspendOrganisation")); n != 1 {
		t.Errorf("a spent grant must not be sent twice: %d calls", n)
	}
}

// A guard's refusal leaves the approval approved and the grant good: the answer says refused with the
// guard's code, and the named operation retries with the same grant.
func TestAGuardRefusalAtApprovalIsReportedAndTheNamedOperationRetries(t *testing.T) {
	e := testenv.New(t)
	scriptApproval(e, "org_suspend", "")
	e.Tenancy.FailNext("suspendOrganisation", http.StatusConflict, 1, "")
	s := second(e)
	view := approve(t, e, s)
	ex, _ := view["execution"].(map[string]any)
	if ex["state"] != "refused" || ex["code"] != "open_trading_day" {
		t.Fatalf("execution: %v", ex)
	}
	if strings.Contains(strings.ToLower(jsonString(view)), "grant") {
		t.Errorf("the grant must not reach the browser: %v", view)
	}
	rec := e.Request(http.MethodPost, "/v1/organisations/"+org+"/suspension", execBody(), s)
	wantStatus(t, rec, http.StatusOK)
	calls := e.Tenancy.Calls("suspendOrganisation")
	if len(calls) != 2 || calls[1].Header.Get("Hostry-Vendor-Approval") != grantToken {
		t.Errorf("the retry must use the same grant: %d calls", len(calls))
	}
}

func TestTheNamedExecutionsRefuseWithAReasonWhenTheApprovalCannotRun(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(a *approval)
		caller func(e *testenv.Env) *testenv.Session // nil: the approver
		kind   string
		path   string
		reason string
	}{
		{"pending", func(a *approval) { a.state = "pending" }, nil, "org_close", "/closure", "not_approved"},
		{"rejected", func(a *approval) { a.state = "rejected" }, nil, "org_close", "/closure", "not_approved"},
		{"lapsed state", func(a *approval) { a.state = "expired" }, nil, "org_close", "/closure", "lapsed"},
		{"already completed", func(a *approval) { a.state, a.approver = "completed", arunID }, nil, "org_close", "/closure", "executed"},
		{"another approver", func(a *approval) { a.state, a.approver = "approved", "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99" }, nil, "org_close", "/closure", "not_approver"},
		{"grant gone with the session", func(a *approval) { a.state, a.approver = "approved", arunID }, nil, "org_close", "/closure", "lapsed"},
		{"another kind", func(a *approval) { a.state, a.approver = "approved", arunID }, nil, "org_suspend", "/closure", "subject_changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testenv.New(t)
			a := scriptApproval(e, tc.kind, "")
			tc.setup(a)
			rec := e.Request(http.MethodPost, "/v1/organisations/"+org+tc.path, execBody(), second(e))
			wantProblem(t, rec, http.StatusConflict, "approval_not_executable")
			if r := decodeBody[map[string]any](t, rec)["reason"]; r != tc.reason {
				t.Errorf("reason %v, want %s", r, tc.reason)
			}
			if n := len(e.Tenancy.Calls("")); n != 0 {
				t.Errorf("a refused execution must not reach tenancy: %d calls", n)
			}
		})
	}
}

// Whatever the executing service says about the grant maps to a reason; the browser never sees grant.*.
func TestAGrantRefusalOfTheExecutingServiceBecomesAReason(t *testing.T) {
	for code, reason := range map[string]string{
		"grant.used": "executed", "grant.expired": "lapsed", "grant.subject_mismatch": "subject_changed", "grant.invalid": "not_approver",
	} {
		t.Run(code, func(t *testing.T) {
			e := testenv.New(t)
			scriptApproval(e, "org_close", "")
			s := second(e)
			e.Tenancy.FailNext("closeOrganisation", http.StatusConflict, 1, "") // a guard stops the first try; the grant stays good
			approve(t, e, s)
			e.Tenancy.On("closeOrganisation", func(_ fakeup.Call, w http.ResponseWriter) bool {
				fakeup.Problem(w, http.StatusForbidden, code)
				return true
			})
			rec := e.Request(http.MethodPost, "/v1/organisations/"+org+"/closure", execBody(), s)
			wantProblem(t, rec, http.StatusConflict, "approval_not_executable")
			if r := decodeBody[map[string]any](t, rec)["reason"]; r != reason {
				t.Errorf("reason %v, want %s", r, reason)
			}
		})
	}
}

// Publication is executed by billing, with the grant and the bearer of the approver; the rule set id
// is a UUIDv5 and must pass the path check.
func TestPublishingARuleSetCallsBillingWithTheGrant(t *testing.T) {
	e := testenv.New(t)
	scriptApproval(e, "tax_rule_set_publish", "")
	s := second(e)
	view := approve(t, e, s)
	if _, has := view["execution"]; has {
		t.Fatalf("billing cannot be called before the rule set is named: %v", view)
	}
	body := map[string]any{"approval_id": approvalID, "note": "Notified rate change"}
	wantStatus(t, e.Request(http.MethodPost, "/v1/tax-rule-sets/"+ruleSetID+"/publication", body, s), http.StatusOK)
	c := e.Billing.Calls("publishTaxRuleSet")
	if len(c) != 1 || c[0].Header.Get("Hostry-Vendor-Approval") != grantToken || c[0].ServiceCaller != "admin" || c[0].Bearer.Subject != arunID {
		t.Fatalf("billing call: %+v", c)
	}
	if strings.Contains(string(c[0].Body), "approval_id") {
		t.Errorf("approval_id must not reach billing: %s", c[0].Body)
	}
	wantProblem(t, e.Request(http.MethodPost, "/v1/tax-rule-sets/"+ruleSetID+"/publication", body, s), http.StatusConflict, "approval_not_executable")
}

func TestPublishingAtApprovalWhenTheRecordNamesTheRuleSet(t *testing.T) {
	e := testenv.New(t)
	scriptApproval(e, "tax_rule_set_publish", ruleSetID)
	view := approve(t, e, second(e))
	if ex, _ := view["execution"].(map[string]any); ex["state"] != "executed" {
		t.Fatalf("execution: %v", view)
	}
	if n := len(e.Billing.Calls("publishTaxRuleSet")); n != 1 {
		t.Errorf("billing calls: %d", n)
	}
}

// The execution routes are the approver's: another role is refused before anything is sent.
func TestExecutionNeedsTheLifecycleApprovePermission(t *testing.T) {
	e := testenv.New(t)
	e.AddUser(testenv.User{ID: arunID, Email: "gate@example.invalid", Role: "support", Permissions: []string{"admin.org.lifecycle.request", "admin.approval.read"}})
	s := e.SignInAs("gate@example.invalid")
	wantProblem(t, e.Request(http.MethodPost, "/v1/organisations/"+org+"/closure", execBody(), s), http.StatusForbidden, "forbidden")
	wantProblem(t, e.Request(http.MethodPost, "/v1/tax-rule-sets/"+ruleSetID+"/publication", map[string]any{"approval_id": approvalID}, s), http.StatusForbidden, "forbidden")
	if n := len(e.Tenancy.Calls("")) + len(e.Billing.Calls("")) + len(e.Identity.Calls("getVendorApproval")); n != 0 {
		t.Errorf("nothing may be sent: %d calls", n)
	}
	wantProblem(t, e.Request(http.MethodPost, "/v1/organisations/"+org+"/closure", map[string]any{"approval_id": "x", "ticket": "SUP-2041", "reason": "Owner asked to close the outlet group."}, second(e)), http.StatusUnprocessableEntity, "validation")
}

// Every operation keeps to its own permission, and a write passes the browser's key and the staff
// member's address to the serving service.
func TestCommercialOperationsAreGatedAndPassTheKeyAndAddressDown(t *testing.T) {
	e := testenv.New(t)
	e.AddUser(testenv.User{ID: arunID, Email: "reader@example.invalid", Role: "support", Permissions: []string{"admin.subscription.read"}})
	reader := e.SignInAs("reader@example.invalid")
	wantStatus(t, get(e, reader, "/v1/plans?limit=5"), http.StatusOK)
	if c := e.Tenancy.Calls("listPlans"); len(c) != 1 || c[0].Query.Get("limit") != "5" || c[0].Bearer == nil || c[0].ServiceCaller != "admin" {
		t.Errorf("listPlans call: %+v", c)
	}
	for _, g := range []struct{ method, path string }{
		{http.MethodPost, "/v1/plans"},
		{http.MethodPost, "/v1/organisations/" + org + "/subscription"},
		{http.MethodPost, "/v1/organisations/" + org + "/charges"},
		{http.MethodPost, "/v1/tax-rule-sets"},
	} {
		wantProblem(t, e.Request(g.method, g.path, map[string]any{}, reader), http.StatusForbidden, "forbidden")
	}
	wantProblem(t, get(e, reader, "/v1/tax-rule-sets"), http.StatusForbidden, "forbidden")
	wantProblem(t, get(e, reader, "/v1/ledger-exports"), http.StatusForbidden, "forbidden")
	if n := len(e.Tenancy.Calls("")) + len(e.Billing.Calls("")); n != 1 {
		t.Errorf("a refused operation must not reach a service: %d calls", n)
	}

	s := e.SignIn()
	rec := e.Request(http.MethodPost, "/v1/organisations/"+org+"/charges", map[string]any{
		"kind": "period", "period_start": "2026-12-01", "period_end": "2026-12-31",
	}, s, testenv.WithKey("raise-1"))
	wantStatus(t, rec, http.StatusCreated)
	c := e.Tenancy.Calls("raiseCharge")
	if len(c) != 1 || c[0].Header.Get("Idempotency-Key") != "raise-1" || c[0].Header.Get("X-Vendor-Client-Address") != "203.0.113.7" {
		t.Errorf("raiseCharge must carry the key and the address: %+v", c)
	}
}

func TestRuleSetEditsCarryTheEntityTagToBilling(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	path := "/v1/tax-rule-sets/" + ruleSetID
	wantStatus(t, e.Request(http.MethodPatch, path, ruleSetDraft(), s, testenv.WithHeader("If-Match", `"3"`)), http.StatusOK)
	c := e.Billing.Calls("updateTaxRuleSetDraft")
	if len(c) != 1 || c[0].Header.Get("If-Match") != `"3"` || c[0].ServiceCaller != "admin" {
		t.Errorf("If-Match must reach billing: %+v", c)
	}
	e.Billing.FailNext("updateTaxRuleSetDraft", http.StatusPreconditionFailed, 1, "")
	wantProblem(t, e.Request(http.MethodPatch, path, ruleSetDraft(), s, testenv.WithHeader("If-Match", `"2"`)), http.StatusPreconditionFailed, "precondition_failed")
	wantStatus(t, e.Request(http.MethodDelete, path, nil, s), http.StatusNoContent)
	wantProblem(t, get(e, s, "/v1/tax-rule-sets/not-a-uuid"), http.StatusNotFound, "not_found")
}

func TestBillingUnavailableIsA503AndNeverAnInternalError(t *testing.T) {
	e := testenv.New(t)
	e.Billing.FailNext("listTaxRuleSetMasters", http.StatusBadGateway, 2, "")
	rec := get(e, e.SignIn(), "/v1/tax-rule-sets")
	wantProblem(t, rec, http.StatusServiceUnavailable, "upstream_unavailable")
}

func TestTheLedgerExportIsCSVAndRefusesAnythingPersonal(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	rec := get(e, s, "/v1/ledger-exports?from=2026-12-01&to=2026-12-31")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") || !strings.HasPrefix(rec.Body.String(), "organisation_id,") {
		t.Errorf("export: %q %q", ct, rec.Body.String())
	}
	if q := e.Tenancy.Calls("exportLedger")[0].Query; q.Get("from") != "2026-12-01" || q.Get("to") != "2026-12-31" {
		t.Errorf("range: %v", q)
	}
	wantProblem(t, get(e, s, "/v1/ledger-exports?from=2026-12-31&to=2026-12-01"), http.StatusUnprocessableEntity, "validation")
	e.Tenancy.On("exportLedger", func(_ fakeup.Call, w http.ResponseWriter) bool {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("organisation_id,organisation_name\n0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60,Call +919876543210\n"))
		return true
	})
	wantProblem(t, get(e, s, "/v1/ledger-exports"), http.StatusServiceUnavailable, "upstream_unavailable")
}

func TestRejectingARegistrationAndTheLedgerListsKeepToTheirPaths(t *testing.T) {
	e := testenv.New(t)
	s := e.SignIn()
	reg := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6b"
	wantStatus(t, e.Request(http.MethodPut, "/v1/organisations/"+org+"/tax-registrations/"+reg+"/rejection", map[string]any{"reason": "The certificate does not match the legal name."}, s), http.StatusOK)
	if len(e.Tenancy.Calls("rejectTaxRegistration")) != 1 {
		t.Error("rejection must reach tenancy")
	}
	wantStatus(t, get(e, s, "/v1/ledger-lists/overdue_charges"), http.StatusOK)
	wantProblem(t, get(e, s, "/v1/ledger-lists/everything"), http.StatusNotFound, "not_found")
	wantProblem(t, get(e, s, "/v1/plans/Not-A-Key"), http.StatusNotFound, "not_found")
}
