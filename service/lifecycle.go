package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/hostryhq/go-common/apperr"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/upstream"
)

// Reasons of 409 approval_not_executable (ADR-0014 A2.5 item 4).
const (
	ReasonNotApproved    = "not_approved"
	ReasonLapsed         = "lapsed"
	ReasonExecuted       = "executed"
	ReasonNotApprover    = "not_approver"
	ReasonSubjectChanged = "subject_changed"
)

// NotExecutableError is 409 approval_not_executable. Only this service answers it: the executing
// services answer grant.* and the guards' own codes. The api layer adds Reason to the problem.
type NotExecutableError struct{ Reason string }

func (e *NotExecutableError) Error() string { return "approval not executable: " + e.Reason }

// Unwrap lets the generic problem mapping see a 409 with the stable code.
func (e *NotExecutableError) Unwrap() error {
	return apperr.New(apperr.Conflict, "approval_not_executable", "")
}

func notExecutable(reason string) error { return &NotExecutableError{Reason: reason} }

// execution is one execution of an approved action by its serving service.
type execution struct {
	op         string
	kind       admin.ApprovalKind
	approvalID string
	// org is the organisation of the path; empty for a tax rule-set publication.
	org string
	// call performs the executing request with the grant token.
	call func(ctx context.Context, grant string) ([]byte, error)
}

// peekGrant returns the unused, unexpired grant of an approval without consuming it: a guard
// refusal leaves the approval approved and the grant good for a retry until it expires.
func (s *Service) peekGrant(sess *repository.Session, approvalID string) (repository.Grant, bool) {
	sess.Lock()
	defer sess.Unlock()
	g, ok := sess.Grants[approvalID]
	if !ok {
		return repository.Grant{}, false
	}
	if !s.clk.Now().Before(g.Expires) {
		delete(sess.Grants, approvalID)
		return repository.Grant{}, false
	}
	return g, true
}

func (s *Service) spendGrant(sess *repository.Session, approvalID string, executed bool) {
	sess.Lock()
	defer sess.Unlock()
	delete(sess.Grants, approvalID)
	if executed {
		if sess.Spent == nil {
			sess.Spent = map[string]bool{}
		}
		sess.Spent[approvalID] = true
	}
}

func (s *Service) wasSpent(sess *repository.Session, approvalID string) bool {
	sess.Lock()
	defer sess.Unlock()
	return sess.Spent[approvalID]
}

// run executes an approved action. It reads the approval at identity (as the signed-in user, so
// identity's own visibility rule applies), refuses with a reason when the approval cannot be
// executed by this caller, and otherwise calls the executing service with the service token, the
// approver's token and the grant held in this session. The grant is never returned.
//
// A guard refusal (open_trading_day, not_signed, lead time) and an unavailable service keep the
// grant for a retry; a success or a grant.* refusal spends it.
func (s *Service) run(ctx context.Context, sess *repository.Session, x execution) ([]byte, error) {
	ap, err := s.GetVendorApproval(ctx, sess, x.approvalID)
	if err != nil {
		return nil, err
	}
	if ap.Kind != x.kind || (x.org != "" && (ap.OrganisationId == nil || *ap.OrganisationId != x.org)) {
		return nil, notExecutable(ReasonSubjectChanged)
	}
	switch ap.State {
	case "approved":
	case "completed":
		return nil, notExecutable(ReasonExecuted)
	case "expired":
		return nil, notExecutable(ReasonLapsed)
	default:
		return nil, notExecutable(ReasonNotApproved)
	}
	if ap.ApprovedBy == nil || *ap.ApprovedBy != sess.UserID {
		return nil, notExecutable(ReasonNotApprover)
	}
	if !s.clk.Now().Before(ap.ExpiresAt) {
		return nil, notExecutable(ReasonLapsed)
	}
	g, ok := s.peekGrant(sess, x.approvalID)
	if !ok {
		if s.wasSpent(sess, x.approvalID) {
			return nil, notExecutable(ReasonExecuted)
		}
		// The grant lived five minutes and is held in this session's memory only.
		return nil, notExecutable(ReasonLapsed)
	}
	var raw []byte
	err = s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		raw, e = x.call(c, g.Token)
		return e
	})
	if err == nil {
		s.spendGrant(sess, x.approvalID, true)
		return raw, nil
	}
	var ue *upstream.Error
	if errors.As(err, &ue) && !ue.Unavailable && strings.HasPrefix(ue.Problem.Code, "grant.") {
		s.spendGrant(sess, x.approvalID, ue.Problem.Code == "grant.used")
		switch ue.Problem.Code {
		case "grant.used":
			return nil, notExecutable(ReasonExecuted)
		case "grant.expired":
			return nil, notExecutable(ReasonLapsed)
		case "grant.subject_mismatch":
			return nil, notExecutable(ReasonSubjectChanged)
		case "grant.invalid":
			return nil, notExecutable(ReasonNotApprover)
		}
		// grant.required: the service always sends one, so this is our fault, not the staff member's.
		s.log.ErrorContext(ctx, "executing service reports a missing grant", "op", x.op)
		return nil, ErrUnavailable
	}
	return nil, s.mapErr(ctx, x.op, err)
}

func (s *Service) lifecycle(ctx context.Context, sess *repository.Session, kind admin.ApprovalKind, op, org, key string, in admin.ExecuteLifecycle,
	send func(u *upstream.Upstream, c context.Context, org, key, grant string, body []byte) ([]byte, error)) (admin.LifecycleResult, error) {
	body := enc(struct { // the grant's approval id is not part of the executing service's request
		Ticket             string `json:"ticket"`
		Reason             string `json:"reason"`
		OwnerExportOffered *bool  `json:"owner_export_offered,omitempty"`
	}{in.Ticket, in.Reason, in.OwnerExportOffered})
	raw, err := s.run(ctx, sess, execution{
		op: op, kind: kind, approvalID: in.ApprovalId, org: org,
		call: func(c context.Context, grant string) ([]byte, error) { return send(s.up, c, org, key, grant, body) },
	})
	var out admin.LifecycleResult
	if err != nil {
		return out, err
	}
	if json.Unmarshal(raw, &out) != nil || out.OrganisationId == "" {
		s.log.WarnContext(ctx, "upstream answer does not fit the contract", "op", op)
		return out, ErrUnavailable
	}
	return out, nil
}

// SuspendOrganisation executes an approved org_suspend (tenancy, grant, guard: no trading day).
func (s *Service) SuspendOrganisation(ctx context.Context, sess *repository.Session, org, key string, in admin.ExecuteLifecycle) (admin.LifecycleResult, error) {
	return s.lifecycle(ctx, sess, admin.OrgSuspend, "suspendOrganisation", org, key, in, (*upstream.Upstream).SuspendOrganisation)
}

// ReinstateOrganisation executes an approved org_reinstate.
func (s *Service) ReinstateOrganisation(ctx context.Context, sess *repository.Session, org, key string, in admin.ExecuteLifecycle) (admin.LifecycleResult, error) {
	return s.lifecycle(ctx, sess, admin.OrgReinstate, "reinstateOrganisation", org, key, in, (*upstream.Upstream).ReinstateOrganisation)
}

// CloseOrganisation executes an approved org_close.
func (s *Service) CloseOrganisation(ctx context.Context, sess *repository.Session, org, key string, in admin.ExecuteLifecycle) (admin.LifecycleResult, error) {
	return s.lifecycle(ctx, sess, admin.OrgClose, "closeOrganisation", org, key, in, (*upstream.Upstream).CloseOrganisation)
}

// PublishTaxRuleSet executes an approved tax_rule_set_publish (billing: grant, lead time of at
// least 24 hours on billing's own clock). The grant binds the rule set's id, content hash and
// effective date; billing recomputes them from its own stored version.
func (s *Service) PublishTaxRuleSet(ctx context.Context, sess *repository.Session, id, key string, in admin.ExecutePublication) (admin.TaxRuleSetMaster, error) {
	var out admin.TaxRuleSetMaster
	body := enc(struct {
		Note *string `json:"note,omitempty"`
	}{in.Note})
	raw, err := s.run(ctx, sess, execution{
		op: "publishTaxRuleSet", kind: admin.TaxRuleSetPublish, approvalID: in.ApprovalId,
		call: func(c context.Context, grant string) ([]byte, error) {
			return s.up.PublishTaxRuleSet(c, id, key, grant, body)
		},
	})
	if err != nil {
		return out, err
	}
	if json.Unmarshal(raw, &out) != nil || out.Id == "" {
		s.log.WarnContext(ctx, "upstream answer does not fit the contract", "op", "publishTaxRuleSet")
		return out, ErrUnavailable
	}
	return out, nil
}

// executeAtApproval runs the action of an approval just approved by this session, in the same
// request (ADR-0014 A2.5 item 4). A guard's refusal is reported in the answer and leaves the
// approval approved: the named operation with approval_id is the retry. Returns nil for a kind
// that identity does not hand to another service, or one admin cannot name yet.
func (s *Service) executeAtApproval(ctx context.Context, sess *repository.Session, ap admin.VendorApproval) *execState {
	if !executing(ap.Kind) {
		return nil
	}
	key := "adm-x-" + ap.Id // the same approval always executes under the same key: a replay is safe
	in := admin.ExecuteLifecycle{ApprovalId: ap.Id}
	if ap.Reason != nil {
		in.Reason = *ap.Reason
	}
	in.Ticket = ap.TicketReference
	var err error
	switch ap.Kind {
	case admin.OrgSuspend, admin.OrgReinstate, admin.OrgClose:
		if ap.OrganisationId == nil {
			return nil
		}
		org := *ap.OrganisationId
		switch ap.Kind {
		case admin.OrgSuspend:
			_, err = s.SuspendOrganisation(ctx, sess, org, key, in)
		case admin.OrgReinstate:
			_, err = s.ReinstateOrganisation(ctx, sess, org, key, in)
		default:
			// The owner-export confirmation is the approver's to give (BR-A1-72), not part of the
			// request: without it tenancy may refuse, and the approver retries with the named operation.
			_, err = s.CloseOrganisation(ctx, sess, org, key, in)
		}
	case admin.TaxRuleSetPublish:
		if ap.SubjectId == nil {
			return nil // the rule set is not named on the record: the named operation executes it
		}
		_, err = s.PublishTaxRuleSet(ctx, sess, *ap.SubjectId, key, admin.ExecutePublication{ApprovalId: ap.Id})
	}
	if err == nil {
		return &execState{State: admin.ApprovalDecisionViewExecutionStateExecuted}
	}
	code := "upstream_unavailable"
	var ae *apperr.Error
	var ue *upstream.Error
	var nx *NotExecutableError
	switch {
	case errors.As(err, &nx):
		code = "approval_not_executable"
	case errors.As(err, &ue) && !ue.Unavailable && ue.Problem.Code != "":
		code = ue.Problem.Code
	case errors.As(err, &ae):
		code = ae.Code
	}
	return &execState{State: admin.ApprovalDecisionViewExecutionStateRefused, Code: &code}
}

type execState = struct {
	Code  *string                                  `json:"code,omitempty"`
	State admin.ApprovalDecisionViewExecutionState `json:"state"`
}
