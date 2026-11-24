package service

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/hostryhq/go-common/apperr"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/internal/gen/identity"
	"github.com/hostryhq/svc-admin/internal/gen/tenancy"
	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/upstream"
)

// Permissions the service checks to refuse early (the owning service enforces them again).
const (
	PermOrgRead         = "admin.org.read"
	PermOrgCreate       = "admin.org.create"
	PermOwnerInvite     = "admin.owner_invite.manage"
	PermRegistrationVfy = "admin.registration.verify"
	PermDeviceRead      = "admin.device.read"
	PermDeviceRevoke    = "admin.device.revoke"
	PermAuditRead       = "admin.audit.read"
	PermAuditReadOwn    = "admin.audit.read_own"
	PermSupportSession  = "admin.support.session.start"
	PermUserManage      = "admin.user.manage"
	maxOrgIDsPerPage    = 100
	ownerMemberStatus   = "owner"
)

var (
	mobileLike = regexp.MustCompile(`^(\+91)?[6-9][0-9]{9}$`)
	mobileFull = regexp.MustCompile(`^\+91[6-9][0-9]{9}$`)
)

// normaliseMobile returns the +91 form of an exact owner mobile search term.
func normaliseMobile(q string) (string, bool) {
	t := strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(q))
	if !mobileLike.MatchString(t) {
		return "", false
	}
	if !strings.HasPrefix(t, "+91") {
		t = "+91" + t
	}
	return t, true
}

func toOwnerStatus(s identity.OwnerStatus) admin.OwnerStatus {
	switch string(s) {
	case ownerMemberStatus:
		return admin.OwnerStatusAccepted
	case "accepted", "pending", "expired", "cancelled", "none":
		return admin.OwnerStatus(s)
	}
	return admin.OwnerStatusUnknown
}

// ListOrganisations lists and searches the directory (tenancy) and adds each row's owner state
// (identity). Tenancy alone is enough for the list: with identity down, owner_status is
// unknown on every row and owner_status_available is false. An owner-mobile search needs
// identity, which is the only holder of numbers and answers with organisation ids only.
func (s *Service) ListOrganisations(ctx context.Context, sess *repository.Session, p admin.ListOrganisationsParams) (admin.OrganisationList, error) {
	var out admin.OrganisationList
	q := tenancy.ListOrganisationDirectoryParams{Cursor: p.Cursor, Limit: p.Limit}
	if p.Status != nil {
		st := tenancy.OrganisationStatus(*p.Status)
		q.Status = &st
	}
	if p.Q != nil && strings.TrimSpace(*p.Q) != "" {
		if mobile, ok := normaliseMobile(*p.Q); ok {
			var ids []string
			err := s.asVendor(ctx, sess, func(c context.Context) error {
				r, e := s.up.LookupOwnerMobile(c, s.idemKey(), mobile)
				ids = r.OrganisationIds
				return e
			})
			if err != nil {
				return out, s.mapErr(ctx, "listOrganisations", err)
			}
			if len(ids) == 0 {
				return admin.OrganisationList{Items: []admin.OrganisationSummary{}, OwnerStatusAvailable: true}, nil
			}
			if len(ids) > maxOrgIDsPerPage {
				ids = ids[:maxOrgIDsPerPage]
			}
			joined := strings.Join(ids, ",")
			q.OrganisationIds = &joined
		} else {
			term := strings.TrimSpace(*p.Q)
			q.Q = &term
		}
	}
	var page tenancy.DirectoryPage
	err := s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		page, e = s.up.ListOrganisationDirectory(c, q)
		return e
	})
	if err != nil {
		return out, s.mapErr(ctx, "listOrganisations", err)
	}
	ids := make([]string, 0, len(page.Items))
	for _, it := range page.Items {
		ids = append(ids, it.Id)
	}
	statuses, available := s.ownerStatuses(ctx, sess, ids)
	out.OwnerStatusAvailable = available
	out.NextCursor = page.NextCursor
	out.Items = make([]admin.OrganisationSummary, 0, len(page.Items))
	for _, it := range page.Items {
		st, ok := statuses[it.Id]
		if !ok {
			st = admin.OwnerStatusUnknown
		}
		out.Items = append(out.Items, admin.OrganisationSummary{
			Id: it.Id, Name: it.Name, Status: admin.OrganisationStatus(it.Status),
			OutletCount: it.OutletCount, CreatedAt: it.CreatedAt, OwnerStatus: st,
		})
	}
	return out, nil
}

// ownerStatuses asks identity for owner states; any failure degrades to "unavailable".
func (s *Service) ownerStatuses(ctx context.Context, sess *repository.Session, ids []string) (map[string]admin.OwnerStatus, bool) {
	res := map[string]admin.OwnerStatus{}
	if len(ids) == 0 {
		return res, true
	}
	var list identity.OwnerStatusList
	err := s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		list, e = s.up.OwnerStatuses(c, ids)
		return e
	})
	if err != nil {
		s.log.InfoContext(ctx, "owner statuses unavailable", "err_kind", errKind(err))
		return res, false
	}
	for _, it := range list.Items {
		res[it.OrganisationId] = toOwnerStatus(it.OwnerStatus)
	}
	return res, true
}

// GetOrganisation is the detail page: structure from tenancy, owner state and invitations from
// identity. When identity cannot answer the state is "unknown", never a guess.
func (s *Service) GetOrganisation(ctx context.Context, sess *repository.Session, org string) (admin.OrganisationDetailView, error) {
	var out admin.OrganisationDetailView
	var raw []byte
	err := s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		raw, e = s.up.GetOrganisationDirectoryEntry(c, org)
		return e
	})
	if err != nil {
		return out, s.mapErr(ctx, "getOrganisation", err)
	}
	var d struct {
		Organisation  admin.DirectoryOrganisation   `json:"organisation"`
		Brands        []admin.DirectoryBrand        `json:"brands"`
		Outlets       []admin.DirectoryOutlet       `json:"outlets"`
		Registrations []admin.DirectoryRegistration `json:"registrations"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return out, ErrUnavailable
	}
	out.Organisation, out.Brands, out.Outlets, out.Registrations = d.Organisation, nonNil(d.Brands), nonNil(d.Outlets), nonNil(d.Registrations)
	out.OwnerInvitations = []admin.OwnerInvitation{}
	out.OwnerStatus, out.OnboardingState = admin.OwnerStatusUnknown, admin.OnboardingStateUnknown

	statuses, ok := s.ownerStatuses(ctx, sess, []string{org})
	var invs admin.OwnerInvitationList
	var ierr error
	if ok {
		ierr = s.asVendor(ctx, sess, func(c context.Context) error {
			b, e := s.up.ListOwnerInvitations(c, org)
			if e != nil {
				return e
			}
			return json.Unmarshal(b, &invs)
		})
	}
	if ok && ierr == nil {
		st := statuses[org]
		if st == "" {
			st = admin.OwnerStatusNone
		}
		out.OwnerStatus = st
		out.OwnerInvitations = nonNil(invs.Items)
		// Derived, never stored: an owner or a pending invitation means onboarding is done.
		out.OnboardingState = admin.OnboardingStateIncomplete
		if st == admin.OwnerStatusAccepted || st == admin.OwnerStatusPending {
			out.OnboardingState = admin.OnboardingStateComplete
		}
	}
	return out, nil
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// CreateOrganisation runs the two steps of ADR-0013 V4 in order, each idempotent under the
// same key: tenancy creates the organisation, brand, outlet and registration; identity then
// creates the owner invitation. Failure of step two leaves a harmless organisation reported as
// "incomplete", never undone. The mobile number is held in memory for this call only and is
// never logged or stored.
func (s *Service) CreateOrganisation(ctx context.Context, sess *repository.Session, form admin.CreateOrganisationForm, key string) (admin.OnboardingResult, error) {
	var out admin.OnboardingResult
	if err := validateOrgForm(form); err != nil {
		return out, err
	}
	req, err := conv[tenancy.CreateOrganisation](form) // owner is not part of tenancy's request
	if err != nil {
		return out, apperr.New(apperr.Validation, "validation", "")
	}
	if !s.Can(sess, PermRegistrationVfy) {
		req.Verification = nil // the registration then starts unverified
	}
	var raw []byte
	err = s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		raw, e = s.up.CreateOrganisation(c, key, req)
		return e
	})
	if err != nil {
		return out, s.mapErr(ctx, "createOrganisation", err)
	}
	created, err := upstream.Decode[admin.OrganisationCreated](raw, nil)
	if err != nil || created.Organisation.Id == "" {
		return out, ErrUnavailable
	}
	out.Created = created
	// Step two. The same Idempotency-Key reaches identity, whose own rule (same organisation and
	// number returns the same invitation) makes a replay safe.
	var invRaw []byte
	ierr := s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		invRaw, e = s.up.CreateOwnerInvitation(c, created.Organisation.Id, key,
			identity.CreateOwnerInvitation{MobileE164: form.Owner.MobileE164, OwnerName: form.Owner.Name})
		return e
	})
	if ierr == nil {
		var inv admin.OwnerInvitation
		if json.Unmarshal(invRaw, &inv) == nil && inv.Id != "" {
			out.State = admin.OnboardingResultStateComplete
			out.OwnerInvitation = &inv
			return out, nil
		}
	}
	s.log.WarnContext(ctx, "onboarding incomplete", "organisation_id", created.Organisation.Id, "err_kind", errKind(ierr))
	out.State = admin.OnboardingResultStateIncomplete
	hint := admin.ReplayRequest
	var ue *upstream.Error
	if errors.As(ierr, &ue) && !ue.Unavailable {
		hint = admin.CreateOwnerInvitation // identity refused the details: fix them on the organisation page
	}
	out.RetryHint = &hint
	return out, nil
}

func validateOrgForm(f admin.CreateOrganisationForm) error {
	var fe []apperr.FieldError
	req := func(field string, ok bool) {
		if !ok {
			fe = append(fe, apperr.FieldError{Field: field, Code: "required"})
		}
	}
	req("name", strings.TrimSpace(f.Name) != "" && len(f.Name) <= 120)
	req("outlet.name", strings.TrimSpace(f.Outlet.Name) != "")
	req("outlet.state_code", f.Outlet.StateCode != "")
	req("tax_registration.legal_name", strings.TrimSpace(f.TaxRegistration.LegalName) != "")
	req("owner.name", strings.TrimSpace(f.Owner.Name) != "" && len(f.Owner.Name) <= 80)
	if !mobileFull.MatchString(f.Owner.MobileE164) {
		fe = append(fe, apperr.FieldError{Field: "owner.mobile_e164", Code: "invalid_mobile"})
	}
	if len(fe) > 0 {
		return apperr.New(apperr.Validation, "validation", "").WithFields(fe...)
	}
	return nil
}

// ListOwnerInvitations lists an organisation's invitations (masked numbers only).
func (s *Service) ListOwnerInvitations(ctx context.Context, sess *repository.Session, org string) (admin.OwnerInvitationList, error) {
	return passThrough[admin.OwnerInvitationList](s, ctx, sess, "listOwnerInvitations", func(c context.Context) ([]byte, error) {
		return s.up.ListOwnerInvitations(c, org)
	})
}

// CreateOwnerInvitation creates or re-issues an owner invitation (identity refuses it for an
// organisation that already has an owner).
func (s *Service) CreateOwnerInvitation(ctx context.Context, sess *repository.Session, org, key string, in admin.NewOwnerInvitation) (admin.OwnerInvitation, error) {
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 80 {
		return admin.OwnerInvitation{}, apperr.New(apperr.Validation, "validation", "").WithFields(apperr.FieldError{Field: "name", Code: "required"})
	}
	if !mobileFull.MatchString(in.MobileE164) {
		return admin.OwnerInvitation{}, apperr.New(apperr.Validation, "validation", "").WithFields(apperr.FieldError{Field: "mobile_e164", Code: "invalid_mobile"})
	}
	return passThrough[admin.OwnerInvitation](s, ctx, sess, "createOwnerInvitation", func(c context.Context) ([]byte, error) {
		return s.up.CreateOwnerInvitation(c, org, key, identity.CreateOwnerInvitation{MobileE164: in.MobileE164, OwnerName: in.Name})
	})
}

// RenewOwnerInvitation extends a pending invitation.
func (s *Service) RenewOwnerInvitation(ctx context.Context, sess *repository.Session, org, inv, key string) (admin.OwnerInvitation, error) {
	return passThrough[admin.OwnerInvitation](s, ctx, sess, "renewOwnerInvitation", func(c context.Context) ([]byte, error) {
		return s.up.RenewOwnerInvitation(c, org, inv, key)
	})
}

// CancelOwnerInvitation cancels a pending invitation.
func (s *Service) CancelOwnerInvitation(ctx context.Context, sess *repository.Session, org, inv, key string) (admin.OwnerInvitation, error) {
	return passThrough[admin.OwnerInvitation](s, ctx, sess, "cancelOwnerInvitation", func(c context.Context) ([]byte, error) {
		return s.up.CancelOwnerInvitation(c, org, inv, key)
	})
}

// VerifyTaxRegistration records GSTIN verification in tenancy.
func (s *Service) VerifyTaxRegistration(ctx context.Context, sess *repository.Session, org, reg, key string, in admin.VerifyRegistration) (admin.TaxRegistration, error) {
	body, _ := json.Marshal(in)
	return passThrough[admin.TaxRegistration](s, ctx, sess, "verifyTaxRegistration", func(c context.Context) ([]byte, error) {
		return s.up.VerifyTaxRegistration(c, org, reg, key, body)
	})
}

// ListOrganisationDevices lists an organisation's devices (identity's vendor view).
func (s *Service) ListOrganisationDevices(ctx context.Context, sess *repository.Session, org string, p admin.ListOrganisationDevicesParams) (admin.VendorDevicePage, error) {
	return passThrough[admin.VendorDevicePage](s, ctx, sess, "listOrganisationDevices", func(c context.Context) ([]byte, error) {
		return s.up.ListOrganisationDevices(c, org, p.Cursor, p.Limit)
	})
}

// GetOrganisationDevice reads one device.
func (s *Service) GetOrganisationDevice(ctx context.Context, sess *repository.Session, org, device string) (admin.VendorDevice, error) {
	return passThrough[admin.VendorDevice](s, ctx, sess, "getOrganisationDevice", func(c context.Context) ([]byte, error) {
		return s.up.GetOrganisationDevice(c, org, device)
	})
}

// RevokeOrganisationDevice revokes a device. Identity applies the two-person rule and the
// per-organisation daily quota (ADR-0005 A2.3/A2.5): over the quota it answers 409
// vendor_approval_required, which passes through unchanged, and a second approver's approval
// id travels in the body (approval_id).
func (s *Service) RevokeOrganisationDevice(ctx context.Context, sess *repository.Session, org, device, key string, in admin.VendorRevoke) (admin.VendorRevokeResult, error) {
	body, _ := json.Marshal(in)
	return passThrough[admin.VendorRevokeResult](s, ctx, sess, "revokeOrganisationDevice", func(c context.Context) ([]byte, error) {
		return s.up.RevokeOrganisationDevice(c, org, device, key, body)
	})
}

// ListAuditEntries reads the vendor audit log. Identity decides between everyone's entries
// (admin.audit.read) and the caller's own (admin.audit.read_own).
func (s *Service) ListAuditEntries(ctx context.Context, sess *repository.Session, p admin.ListAuditEntriesParams) (admin.VendorAuditPage, error) {
	f := upstream.AuditFilter{
		From: p.From, To: p.To, Actor: p.ActorVendorUserId, Organisation: p.OrganisationId,
		Action: p.Action, Support: p.SupportSessionId, Cursor: p.Cursor, Limit: p.Limit,
	}
	return passThrough[admin.VendorAuditPage](s, ctx, sess, "listAuditEntries", func(c context.Context) ([]byte, error) {
		return s.up.ListVendorAuditEntries(c, f)
	})
}

// passThrough runs one vendor call and re-validates the answer against the admin contract's
// type: fields the contract does not name are dropped, so an upstream that grows a field never
// widens what the browser sees.
func passThrough[T any](s *Service, ctx context.Context, sess *repository.Session, op string, fn func(ctx context.Context) ([]byte, error)) (T, error) {
	var out T
	var raw []byte
	err := s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		raw, e = fn(c)
		return e
	})
	if err != nil {
		return out, s.mapErr(ctx, op, err)
	}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		s.log.WarnContext(ctx, "upstream answer does not fit the contract", "op", op)
		return out, ErrUnavailable
	}
	return out, nil
}
