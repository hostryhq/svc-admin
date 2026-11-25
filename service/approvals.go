package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hostryhq/go-common/apperr"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/repository"
)

// Permissions of the two-person approval flow (ADR-0005 A2.3, ADR-0014 A1.3).
const (
	PermApprovalCreate = "admin.approval.create"
	PermApprovalRead   = "admin.approval.read"
	PermApprovalDecide = "admin.approval.decide"
)

// Kind-specific permissions: the gate permission is checked first, then the one of the kind
// (x-permission-by-kind of the contract). Identity enforces both again.
var (
	requestPermByKind = map[admin.ApprovalKind]string{
		admin.SignInCode:            "admin.signin_code.create",
		admin.OwnerRecovery:         "admin.recovery.create",
		admin.DeviceRevokeOverQuota: PermDeviceRevoke,
		admin.OrgSuspend:            "admin.org.lifecycle.request",
		admin.OrgReinstate:          "admin.org.lifecycle.request",
		admin.OrgClose:              "admin.org.lifecycle.request",
		admin.TaxRuleSetPublish:     "admin.taxrules.publish",
	}
	approvePermByKind = map[admin.ApprovalKind]string{
		admin.SignInCode:            "admin.signin_code.approve",
		admin.OwnerRecovery:         "admin.recovery.approve",
		admin.DeviceRevokeOverQuota: PermDeviceRevoke,
		admin.OrgSuspend:            "admin.org.lifecycle.approve",
		admin.OrgReinstate:          "admin.org.lifecycle.approve",
		admin.OrgClose:              "admin.org.lifecycle.approve",
		admin.TaxRuleSetPublish:     "admin.taxrules.publish",
	}

	// ErrSecondApprover is the refusal of an approver who is the requester. There is no
	// single-person override in any environment.
	ErrSecondApprover = apperr.New(apperr.Conflict, "second_approver_unavailable", "")
)

// executing reports the kinds whose approval carries a grant for another service.
func executing(k admin.ApprovalKind) bool {
	switch k {
	case admin.OrgSuspend, admin.OrgReinstate, admin.OrgClose, admin.TaxRuleSetPublish:
		return true
	}
	return false
}

func validateApproval(in admin.CreateVendorApproval) error {
	var fe []apperr.FieldError
	missing := func(field string) { fe = append(fe, apperr.FieldError{Field: field, Code: "required"}) }
	if _, known := requestPermByKind[in.Kind]; !known {
		fe = append(fe, apperr.FieldError{Field: "kind", Code: "invalid"})
	} else {
		switch in.Kind {
		case admin.OrgSuspend, admin.OrgReinstate, admin.OrgClose:
			if in.OrganisationId == nil {
				missing("organisation_id")
			}
		case admin.DeviceRevokeOverQuota:
			if in.OrganisationId == nil {
				missing("organisation_id")
			}
			if in.SubjectId == nil {
				missing("subject_id")
			}
		case admin.TaxRuleSetPublish:
			if in.RuleSetId == nil {
				missing("rule_set_id")
			}
			if in.RuleSetContentHash == nil {
				missing("rule_set_content_hash")
			}
			if in.EffectiveDate == nil {
				missing("effective_date")
			}
		}
	}
	if len(fe) > 0 {
		return apperr.New(apperr.Validation, "validation", "").WithFields(fe...)
	}
	return nil
}

// FileVendorApproval files a request that a second vendor user must approve. Admin refuses a
// kind the signed-in role may not request; identity refuses with second_approver_unavailable when
// fewer than two eligible users exist.
func (s *Service) FileVendorApproval(ctx context.Context, sess *repository.Session, in admin.CreateVendorApproval, key string) (admin.VendorApproval, error) {
	if err := validateApproval(in); err != nil {
		return admin.VendorApproval{}, err
	}
	if !s.Can(sess, requestPermByKind[in.Kind]) {
		return admin.VendorApproval{}, Forbidden()
	}
	body, _ := json.Marshal(in) // may carry a mobile number: never logged, never stored here
	return passThrough[admin.VendorApproval](s, ctx, sess, "fileVendorApproval", func(c context.Context) ([]byte, error) {
		return s.up.CreateVendorApproval(c, key, body)
	})
}

// ListVendorApprovals lists the approvals the user requested or may approve.
func (s *Service) ListVendorApprovals(ctx context.Context, sess *repository.Session, p admin.ListVendorApprovalsParams) (admin.VendorApprovalPage, error) {
	var state *string
	if p.State != nil {
		st := string(*p.State)
		state = &st
	}
	return passThrough[admin.VendorApprovalPage](s, ctx, sess, "listVendorApprovals", func(c context.Context) ([]byte, error) {
		return s.up.ListVendorApprovals(c, state, p.Cursor, p.Limit)
	})
}

// GetVendorApproval reads one approval (404 unless the user requested it or may approve it).
func (s *Service) GetVendorApproval(ctx context.Context, sess *repository.Session, id string) (admin.VendorApproval, error) {
	return passThrough[admin.VendorApproval](s, ctx, sess, "getVendorApproval", func(c context.Context) ([]byte, error) {
		return s.up.GetVendorApproval(c, id)
	})
}

// ApproveVendorApproval approves with a fresh TOTP. The approver must differ from the requester
// and hold the kind's approve permission; identity also requires an account older than 7 days.
// There is no single-person override. For the executing kinds the grant identity returns is kept
// in memory against the session and never reaches the browser.
func (s *Service) ApproveVendorApproval(ctx context.Context, sess *repository.Session, id, key string, in admin.ApproveVendorApproval) (admin.ApprovalDecisionView, error) {
	var out admin.ApprovalDecisionView
	ap, err := s.GetVendorApproval(ctx, sess, id)
	if err != nil {
		return out, err
	}
	if !s.Can(sess, approvePermByKind[ap.Kind]) {
		return out, Forbidden()
	}
	if ap.RequestedBy == sess.UserID {
		return out, ErrSecondApprover
	}
	body, _ := json.Marshal(in)
	var raw []byte
	err = s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		raw, e = s.up.ApproveVendorApproval(c, id, key, body)
		return e
	})
	if err != nil {
		return out, s.mapErr(ctx, "approveVendorApproval", err)
	}
	var dec struct {
		Approval admin.VendorApproval `json:"approval"`
		CodeHalf *admin.CodeHalf      `json:"code_half"`
		Grant    *struct {
			Token     string    `json:"token"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"grant"`
	}
	if json.Unmarshal(raw, &dec) != nil || dec.Approval.Id == "" {
		s.log.WarnContext(ctx, "upstream answer does not fit the contract", "op", "approveVendorApproval")
		return out, ErrUnavailable
	}
	if dec.Grant != nil && dec.Grant.Token != "" && executing(dec.Approval.Kind) {
		sess.Lock()
		if sess.Grants == nil {
			sess.Grants = map[string]repository.Grant{}
		}
		sess.Grants[dec.Approval.Id] = repository.Grant{
			ApprovalID: dec.Approval.Id, Kind: string(dec.Approval.Kind), Token: dec.Grant.Token, Expires: dec.Grant.ExpiresAt,
		}
		sess.Unlock()
	}
	return admin.ApprovalDecisionView{Approval: dec.Approval, CodeHalf: dec.CodeHalf}, nil
}

// TakeGrant returns the unused, unexpired grant of an approved approval and forgets it (single
// use). It is for the executing call to tenancy or billing, never for the browser.
func (s *Service) TakeGrant(sess *repository.Session, approvalID string) (repository.Grant, bool) {
	sess.Lock()
	defer sess.Unlock()
	g, ok := sess.Grants[approvalID]
	if !ok {
		return repository.Grant{}, false
	}
	delete(sess.Grants, approvalID)
	if !s.clk.Now().Before(g.Expires) {
		return repository.Grant{}, false
	}
	return g, true
}

// ClaimCodeHalf claims the requester's half (characters 1 to 4) of a sign-in code, once.
func (s *Service) ClaimCodeHalf(ctx context.Context, sess *repository.Session, id, key string) (admin.CodeHalf, error) {
	return passThrough[admin.CodeHalf](s, ctx, sess, "claimCodeHalf", func(c context.Context) ([]byte, error) {
		return s.up.ClaimCodeHalf(c, id, key)
	})
}

// CancelVendorApproval rejects or cancels an approval.
func (s *Service) CancelVendorApproval(ctx context.Context, sess *repository.Session, id, key string, in admin.RejectVendorApproval) (admin.VendorApproval, error) {
	body, _ := json.Marshal(in)
	return passThrough[admin.VendorApproval](s, ctx, sess, "cancelVendorApproval", func(c context.Context) ([]byte, error) {
		return s.up.CancelVendorApproval(c, id, key, body)
	})
}
