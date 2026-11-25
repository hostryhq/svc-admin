package service

import (
	"context"
	"encoding/json"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/repository"
)

// publicCall runs an operation identity serves with the service token alone (account setup).
func publicCall[T any](s *Service, ctx context.Context, op string, fn func(ctx context.Context) ([]byte, error)) (T, error) {
	var out T
	raw, err := fn(publicCtx(ctx))
	if err != nil {
		return out, s.mapErr(ctx, op, err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, ErrUnavailable
	}
	return out, nil
}

// BeginAccountSetup starts setup from a one-time link; the TOTP enrolment material it returns
// is shown once and is neither kept nor logged here.
func (s *Service) BeginAccountSetup(ctx context.Context, key string, in admin.BeginVendorSetup) (admin.VendorSetupChallenge, error) {
	body, _ := json.Marshal(in)
	return publicCall[admin.VendorSetupChallenge](s, ctx, "beginAccountSetup", func(c context.Context) ([]byte, error) {
		return s.up.BeginVendorSetup(c, key, body)
	})
}

// CompleteAccountSetup finishes setup. It does not sign the user in.
func (s *Service) CompleteAccountSetup(ctx context.Context, key string, in admin.CompleteVendorSetup) (admin.VendorUser, error) {
	body, _ := json.Marshal(in)
	return publicCall[admin.VendorUser](s, ctx, "completeAccountSetup", func(c context.Context) ([]byte, error) {
		return s.up.CompleteVendorSetup(c, key, body)
	})
}

// ListVendorUsers lists vendor staff.
func (s *Service) ListVendorUsers(ctx context.Context, sess *repository.Session, p admin.ListVendorUsersParams) (admin.VendorUserPage, error) {
	return passThrough[admin.VendorUserPage](s, ctx, sess, "listVendorUsers", func(c context.Context) ([]byte, error) {
		return s.up.ListVendorUsers(c, p.Cursor, p.Limit)
	})
}

// CreateVendorUser creates a user in setup_pending; the setup link goes out by email from
// identity and is never returned.
func (s *Service) CreateVendorUser(ctx context.Context, sess *repository.Session, key string, in admin.CreateVendorUser) (admin.VendorUser, error) {
	body, _ := json.Marshal(in)
	return passThrough[admin.VendorUser](s, ctx, sess, "createVendorUser", func(c context.Context) ([]byte, error) {
		return s.up.CreateVendorUser(c, key, body)
	})
}

// UpdateVendorUser changes a role or deactivates. On success every browser session of that
// user is dropped in this same operation (no bus connection in A0, ADR-0013 V1), which also
// drops any support session held against them.
func (s *Service) UpdateVendorUser(ctx context.Context, sess *repository.Session, id, key string, in admin.UpdateVendorUser) (admin.VendorUser, error) {
	body, _ := json.Marshal(in)
	u, err := passThrough[admin.VendorUser](s, ctx, sess, "updateVendorUser", func(c context.Context) ([]byte, error) {
		return s.up.UpdateVendorUser(c, id, key, body)
	})
	if err == nil {
		s.DropUserSessions(id)
	}
	return u, err
}

// ResetVendorUserTotp returns a user to setup_pending and drops their sessions.
func (s *Service) ResetVendorUserTotp(ctx context.Context, sess *repository.Session, id, key string) (admin.VendorUser, error) {
	u, err := passThrough[admin.VendorUser](s, ctx, sess, "resetVendorUserTotp", func(c context.Context) ([]byte, error) {
		return s.up.ResetVendorUserTotp(c, id, key)
	})
	if err == nil {
		s.DropUserSessions(id)
	}
	return u, err
}

// ---- support view: ordinary read routes called with the support token ---------------------

func supportPage[T any](s *Service, ctx context.Context, sess *repository.Session, org, op string, fn func(ctx context.Context) ([]byte, error)) (T, error) {
	var out T
	raw, err := s.supportRead(ctx, sess, org, op, fn)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		s.log.WarnContext(ctx, "upstream answer does not fit the contract", "op", op)
		return out, ErrUnavailable
	}
	return out, nil
}

// SupportOrganisation is the profile and status of the session's organisation.
func (s *Service) SupportOrganisation(ctx context.Context, sess *repository.Session, org string) (admin.SupportOrganisation, error) {
	return supportPage[admin.SupportOrganisation](s, ctx, sess, org, "getSupportOrganisation", func(c context.Context) ([]byte, error) {
		return s.up.GetCurrentOrganisation(c)
	})
}

// SupportBrands lists brands.
func (s *Service) SupportBrands(ctx context.Context, sess *repository.Session, org string, p admin.ListSupportBrandsParams) (admin.BrandPage, error) {
	return supportPage[admin.BrandPage](s, ctx, sess, org, "listSupportBrands", func(c context.Context) ([]byte, error) {
		return s.up.ListBrands(c, p.Cursor, p.Limit)
	})
}

// SupportOutlets lists outlets.
func (s *Service) SupportOutlets(ctx context.Context, sess *repository.Session, org string, p admin.ListSupportOutletsParams) (admin.OutletPage, error) {
	return supportPage[admin.OutletPage](s, ctx, sess, org, "listSupportOutlets", func(c context.Context) ([]byte, error) {
		return s.up.ListOutlets(c, p.Cursor, p.Limit)
	})
}

// SupportTaxRegistrations lists tax registrations.
func (s *Service) SupportTaxRegistrations(ctx context.Context, sess *repository.Session, org string, p admin.ListSupportTaxRegistrationsParams) (admin.TaxRegistrationPage, error) {
	return supportPage[admin.TaxRegistrationPage](s, ctx, sess, org, "listSupportTaxRegistrations", func(c context.Context) ([]byte, error) {
		return s.up.ListTaxRegistrations(c, p.Cursor, p.Limit)
	})
}

// SupportDocumentSeries lists document series.
func (s *Service) SupportDocumentSeries(ctx context.Context, sess *repository.Session, org string, p admin.ListSupportDocumentSeriesParams) (admin.DocumentSeriesPage, error) {
	return supportPage[admin.DocumentSeriesPage](s, ctx, sess, org, "listSupportDocumentSeries", func(c context.Context) ([]byte, error) {
		return s.up.ListDocumentSeries(c, p.Cursor, p.Limit)
	})
}

// SupportSettings reads the organisation settings.
func (s *Service) SupportSettings(ctx context.Context, sess *repository.Session, org string) (admin.OrganisationSettings, error) {
	return supportPage[admin.OrganisationSettings](s, ctx, sess, org, "getSupportSettings", func(c context.Context) ([]byte, error) {
		return s.up.GetOrganisationSettings(c)
	})
}

// SupportMembers lists members (no phone number, no PIN data: the contract type is closed).
func (s *Service) SupportMembers(ctx context.Context, sess *repository.Session, org string, p admin.ListSupportMembersParams) (admin.MemberPage, error) {
	return supportPage[admin.MemberPage](s, ctx, sess, org, "listSupportMembers", func(c context.Context) ([]byte, error) {
		return s.up.ListMembers(c, p.Cursor, p.Limit)
	})
}

// SupportRoles lists roles and their permission sets.
func (s *Service) SupportRoles(ctx context.Context, sess *repository.Session, org string, p admin.ListSupportRolesParams) (admin.RolePage, error) {
	return supportPage[admin.RolePage](s, ctx, sess, org, "listSupportRoles", func(c context.Context) ([]byte, error) {
		return s.up.ListRoles(c, p.Cursor, p.Limit)
	})
}

// SupportDevices lists devices (no keys, no PIN data).
func (s *Service) SupportDevices(ctx context.Context, sess *repository.Session, org string, p admin.ListSupportDevicesParams) (admin.DevicePage, error) {
	return supportPage[admin.DevicePage](s, ctx, sess, org, "listSupportDevices", func(c context.Context) ([]byte, error) {
		return s.up.ListDevices(c, p.Cursor, p.Limit)
	})
}
