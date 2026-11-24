package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/service"
)

var _ admin.ServerInterface = (*Handler)(nil)

func decode[T any](body []byte) (T, error) {
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		return v, apperr.New(apperr.Validation, "validation", "the request body is not valid JSON for this operation")
	}
	return v, nil
}

// pathID refuses a path id that cannot exist: such a resource is simply not found.
func pathID(id string) error {
	if !idRe.MatchString(id) {
		return service.ErrNotFound
	}
	return nil
}

func ids2(a, b string) error {
	if err := pathID(a); err != nil {
		return err
	}
	return pathID(b)
}

var (
	authed   = access{}
	userMgmt = []string{service.PermUserManage}
)

func perm(p ...string) access    { return access{perms: p} }
func permMut(p ...string) access { return access{perms: p, mutating: true} }
func publicMut() access          { return access{public: true, mutating: true} }
func ok(v any) outcome           { return outcome{status: http.StatusOK, v: v} }
func created(v any) outcome      { return outcome{status: http.StatusCreated, v: v} }
func staff(v any) outcome {
	return outcome{status: http.StatusOK, v: v, scrub: scrubOpts{allowEmail: true}}
}
func staffCreated(v any) outcome {
	return outcome{status: http.StatusCreated, v: v, scrub: scrubOpts{allowEmail: true}}
}

// ---- session -------------------------------------------------------------------------------

// SignIn implements POST /v1/sessions.
func (h *Handler) SignIn(w http.ResponseWriter, r *http.Request, _ admin.SignInParams) {
	q, good := h.admit(w, r, publicMut())
	if !good {
		return
	}
	key, present, err := idempotency.KeyFromRequest(q.r)
	if err != nil || !present {
		h.fail(w, q.r, idempotency.ErrKeyInvalid)
		return
	}
	q.key = key
	old, _ := r.Cookie(CookieName)
	h.runIdempotent(q, true, func(q *req) (outcome, error) {
		in, err := decode[admin.VendorSignIn](q.body)
		if err != nil {
			return outcome{}, service.ErrSignInFailed
		}
		sess, err := h.svc.SignIn(q.r.Context(), in, q.key)
		if err != nil {
			return outcome{}, err
		}
		if old != nil && old.Value != "" {
			h.svc.DropSession(old.Value) // a new id at every sign-in; the previous session is over
		}
		h.setCookie(q.w, sess.ID) // first success only: a replay never reaches here
		return outcome{status: http.StatusCreated, v: h.svc.View(sess), scrub: scrubOpts{skip: true}}, nil
	})
}

// GetSession implements GET /v1/sessions/current.
func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	h.read(w, r, authed, func(q *req) (outcome, error) {
		return outcome{status: http.StatusOK, v: h.svc.View(q.sess), scrub: scrubOpts{skip: true}}, nil
	})
}

// SignOut implements DELETE /v1/sessions/current. It is idempotent by the cookie that signed out,
// so a replay after the session is gone still answers 204.
func (h *Handler) SignOut(w http.ResponseWriter, r *http.Request, _ admin.SignOutParams) {
	if !h.originOK(r) {
		h.fail(w, r, errCSRF)
		return
	}
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		h.fail(w, r, service.ErrUnauthenticated)
		return
	}
	key, present, kerr := idempotency.KeyFromRequest(r)
	if kerr != nil || !present {
		h.fail(w, r, idempotency.ErrKeyInvalid)
		return
	}
	sum := sha256.Sum256([]byte(c.Value))
	scope := ids.ID("signout:" + hex.EncodeToString(sum[:]))
	ctx := service.WithAddress(r.Context(), h.clientAddr(r))
	_, _, derr := idempotency.Do(ctx, h.idem, scope, key, idempotency.Fingerprint(r.Method, r.URL.Path, nil),
		func() (idempotency.Response, error) {
			sess, err := h.svc.Authenticate(c.Value)
			if err != nil {
				return idempotency.Response{}, err
			}
			if !csrfOK(r, sess) {
				return idempotency.Response{}, errCSRF
			}
			h.svc.SignOut(ctx, sess)
			return idempotency.Response{Status: http.StatusNoContent}, nil
		})
	if derr != nil {
		h.fail(w, r, derr)
		return
	}
	h.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func csrfOK(r *http.Request, sess *repository.Session) bool {
	return constantEq(r.Header.Get(CSRFHeader), sess.CSRF)
}

// ---- account setup -------------------------------------------------------------------------

// BeginAccountSetup implements POST /v1/account-setups.
func (h *Handler) BeginAccountSetup(w http.ResponseWriter, r *http.Request, p admin.BeginAccountSetupParams) {
	h.publicOp(w, r, p.IdempotencyKey, func(q *req) (outcome, error) {
		in, err := decode[admin.BeginVendorSetup](q.body)
		if err != nil {
			return outcome{}, err
		}
		out, err := h.svc.BeginAccountSetup(q.r.Context(), q.key, in)
		return staffCreated(out), err
	})
}

// CompleteAccountSetup implements POST /v1/account-setup-completions.
func (h *Handler) CompleteAccountSetup(w http.ResponseWriter, r *http.Request, p admin.CompleteAccountSetupParams) {
	h.publicOp(w, r, p.IdempotencyKey, func(q *req) (outcome, error) {
		in, err := decode[admin.CompleteVendorSetup](q.body)
		if err != nil {
			return outcome{}, err
		}
		out, err := h.svc.CompleteAccountSetup(q.r.Context(), q.key, in)
		return staff(out), err
	})
}

// publicOp runs a public state-changing operation. It forwards the key; identity makes the
// operation idempotent (a setup link works once), so nothing is cached here: the answer holds
// TOTP enrolment material that must not sit in memory longer than the call.
func (h *Handler) publicOp(w http.ResponseWriter, r *http.Request, _ string, fn func(q *req) (outcome, error)) {
	q, good := h.admit(w, r, publicMut())
	if !good {
		return
	}
	key, present, err := idempotency.KeyFromRequest(q.r)
	if err != nil || !present {
		h.fail(w, q.r, idempotency.ErrKeyInvalid)
		return
	}
	q.key = key
	o, err := fn(q)
	if err != nil {
		h.fail(w, q.r, err)
		return
	}
	h.write(w, h.renderJSON(q.r, o.status, o.v, o.scrub))
}

// ---- vendor staff --------------------------------------------------------------------------

// ListVendorUsers implements GET /v1/vendor-users.
func (h *Handler) ListVendorUsers(w http.ResponseWriter, r *http.Request, p admin.ListVendorUsersParams) {
	h.read(w, r, perm(userMgmt...), func(q *req) (outcome, error) {
		out, err := h.svc.ListVendorUsers(q.r.Context(), q.sess, p)
		return staff(out), err
	})
}

// CreateVendorUser implements POST /v1/vendor-users.
func (h *Handler) CreateVendorUser(w http.ResponseWriter, r *http.Request, _ admin.CreateVendorUserParams) {
	h.mutate(w, r, permMut(userMgmt...), func(q *req) (outcome, error) {
		in, err := decode[admin.CreateVendorUser](q.body)
		if err != nil {
			return outcome{}, err
		}
		out, err := h.svc.CreateVendorUser(q.r.Context(), q.sess, q.key, in)
		return staffCreated(out), err
	})
}

// UpdateVendorUser implements PATCH /v1/vendor-users/{vendor_user_id}.
func (h *Handler) UpdateVendorUser(w http.ResponseWriter, r *http.Request, id admin.Id, _ admin.UpdateVendorUserParams) {
	h.mutate(w, r, permMut(userMgmt...), func(q *req) (outcome, error) {
		if err := pathID(id); err != nil {
			return outcome{}, err
		}
		in, err := decode[admin.UpdateVendorUser](q.body)
		if err != nil {
			return outcome{}, err
		}
		out, err := h.svc.UpdateVendorUser(q.r.Context(), q.sess, id, q.key, in)
		return staff(out), err
	})
}

// ResetVendorUserTotp implements POST /v1/vendor-users/{vendor_user_id}/totp-resets.
func (h *Handler) ResetVendorUserTotp(w http.ResponseWriter, r *http.Request, id admin.Id, _ admin.ResetVendorUserTotpParams) {
	h.mutate(w, r, permMut(userMgmt...), func(q *req) (outcome, error) {
		if err := pathID(id); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.ResetVendorUserTotp(q.r.Context(), q.sess, id, q.key)
		return staffCreated(out), err
	})
}

// ---- organisations -------------------------------------------------------------------------

// ListOrganisations implements GET /v1/organisations.
func (h *Handler) ListOrganisations(w http.ResponseWriter, r *http.Request, p admin.ListOrganisationsParams) {
	h.read(w, r, perm(service.PermOrgRead), func(q *req) (outcome, error) {
		out, err := h.svc.ListOrganisations(q.r.Context(), q.sess, p)
		return ok(out), err
	})
}

// CreateOrganisation implements POST /v1/organisations.
func (h *Handler) CreateOrganisation(w http.ResponseWriter, r *http.Request, _ admin.CreateOrganisationParams) {
	h.mutate(w, r, permMut(service.PermOrgCreate), func(q *req) (outcome, error) {
		in, err := decode[admin.CreateOrganisationForm](q.body)
		if err != nil {
			return outcome{}, err
		}
		out, err := h.svc.CreateOrganisation(q.r.Context(), q.sess, in, q.key)
		o := created(out)
		o.noStore = out.State != admin.OnboardingResultStateComplete
		return o, err
	})
}

// GetOrganisation implements GET /v1/organisations/{organisation_id}.
func (h *Handler) GetOrganisation(w http.ResponseWriter, r *http.Request, org admin.Id) {
	h.read(w, r, perm(service.PermOrgRead), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.GetOrganisation(q.r.Context(), q.sess, org)
		return ok(out), err
	})
}

// ListOwnerInvitations implements GET .../owner-invitations.
func (h *Handler) ListOwnerInvitations(w http.ResponseWriter, r *http.Request, org admin.Id) {
	h.read(w, r, perm(service.PermOrgRead), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.ListOwnerInvitations(q.r.Context(), q.sess, org)
		return ok(out), err
	})
}

// CreateOwnerInvitation implements POST .../owner-invitations.
func (h *Handler) CreateOwnerInvitation(w http.ResponseWriter, r *http.Request, org admin.Id, _ admin.CreateOwnerInvitationParams) {
	h.mutate(w, r, permMut(service.PermOwnerInvite), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		in, err := decode[admin.NewOwnerInvitation](q.body)
		if err != nil {
			return outcome{}, err
		}
		out, err := h.svc.CreateOwnerInvitation(q.r.Context(), q.sess, org, q.key, in)
		return created(out), err
	})
}

// RenewOwnerInvitation implements POST .../owner-invitations/{invitation_id}/renewals.
func (h *Handler) RenewOwnerInvitation(w http.ResponseWriter, r *http.Request, org, inv admin.Id, _ admin.RenewOwnerInvitationParams) {
	h.mutate(w, r, permMut(service.PermOwnerInvite), func(q *req) (outcome, error) {
		if err := ids2(org, inv); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.RenewOwnerInvitation(q.r.Context(), q.sess, org, inv, q.key)
		return ok(out), err
	})
}

// CancelOwnerInvitation implements PUT .../owner-invitations/{invitation_id}/cancellation.
func (h *Handler) CancelOwnerInvitation(w http.ResponseWriter, r *http.Request, org, inv admin.Id, _ admin.CancelOwnerInvitationParams) {
	h.mutate(w, r, permMut(service.PermOwnerInvite), func(q *req) (outcome, error) {
		if err := ids2(org, inv); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.CancelOwnerInvitation(q.r.Context(), q.sess, org, inv, q.key)
		return ok(out), err
	})
}

// VerifyTaxRegistration implements PUT .../tax-registrations/{registration_id}/verification.
func (h *Handler) VerifyTaxRegistration(w http.ResponseWriter, r *http.Request, org, reg admin.Id, _ admin.VerifyTaxRegistrationParams) {
	h.mutate(w, r, permMut(service.PermRegistrationVfy), func(q *req) (outcome, error) {
		if err := ids2(org, reg); err != nil {
			return outcome{}, err
		}
		in, err := decode[admin.VerifyRegistration](q.body)
		if err != nil {
			return outcome{}, err
		}
		out, err := h.svc.VerifyTaxRegistration(q.r.Context(), q.sess, org, reg, q.key, in)
		return ok(out), err
	})
}

// ---- devices and audit ---------------------------------------------------------------------

// ListOrganisationDevices implements GET .../devices.
func (h *Handler) ListOrganisationDevices(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListOrganisationDevicesParams) {
	h.read(w, r, perm(service.PermDeviceRead), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.ListOrganisationDevices(q.r.Context(), q.sess, org, p)
		return ok(out), err
	})
}

// GetOrganisationDevice implements GET .../devices/{device_id}.
func (h *Handler) GetOrganisationDevice(w http.ResponseWriter, r *http.Request, org, device admin.Id) {
	h.read(w, r, perm(service.PermDeviceRead), func(q *req) (outcome, error) {
		if err := ids2(org, device); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.GetOrganisationDevice(q.r.Context(), q.sess, org, device)
		return ok(out), err
	})
}

// RevokeOrganisationDevice implements PUT .../devices/{device_id}/revocation.
func (h *Handler) RevokeOrganisationDevice(w http.ResponseWriter, r *http.Request, org, device admin.Id, _ admin.RevokeOrganisationDeviceParams) {
	h.mutate(w, r, permMut(service.PermDeviceRevoke), func(q *req) (outcome, error) {
		if err := ids2(org, device); err != nil {
			return outcome{}, err
		}
		in, err := decode[admin.VendorRevoke](q.body)
		if err != nil {
			return outcome{}, err
		}
		out, err := h.svc.RevokeOrganisationDevice(q.r.Context(), q.sess, org, device, q.key, in)
		return ok(out), err
	})
}

// ListAuditEntries implements GET /v1/audit-entries.
func (h *Handler) ListAuditEntries(w http.ResponseWriter, r *http.Request, p admin.ListAuditEntriesParams) {
	h.read(w, r, perm(service.PermAuditReadOwn, service.PermAuditRead), func(q *req) (outcome, error) {
		out, err := h.svc.ListAuditEntries(q.r.Context(), q.sess, p)
		return ok(out), err
	})
}

// ---- support -------------------------------------------------------------------------------

// StartSupportSession implements POST /v1/support-sessions.
func (h *Handler) StartSupportSession(w http.ResponseWriter, r *http.Request, _ admin.StartSupportSessionParams) {
	h.mutate(w, r, permMut(service.PermSupportSession), func(q *req) (outcome, error) {
		in, err := decode[admin.StartSupport](q.body)
		if err != nil {
			return outcome{}, err
		}
		if err := pathID(in.OrganisationId); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.StartSupport(q.r.Context(), q.sess, in, q.key)
		return created(out), err
	})
}

// GetSupportSession implements GET /v1/support-sessions/current.
func (h *Handler) GetSupportSession(w http.ResponseWriter, r *http.Request) {
	h.read(w, r, perm(service.PermSupportSession), func(q *req) (outcome, error) {
		out, err := h.svc.CurrentSupport(q.sess)
		return ok(out), err
	})
}

// EndSupportSession implements DELETE /v1/support-sessions/current.
func (h *Handler) EndSupportSession(w http.ResponseWriter, r *http.Request, _ admin.EndSupportSessionParams) {
	h.mutate(w, r, permMut(service.PermSupportSession), func(q *req) (outcome, error) {
		return outcome{status: http.StatusNoContent}, h.svc.EndSupport(q.r.Context(), q.sess, q.key)
	})
}

func (h *Handler) supportRead(w http.ResponseWriter, r *http.Request, org admin.Id, fn func(q *req) (any, error)) {
	h.read(w, r, perm(service.PermSupportSession), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		v, err := fn(q)
		return ok(v), err
	})
}

// GetSupportOrganisation implements GET .../support-view/profile.
func (h *Handler) GetSupportOrganisation(w http.ResponseWriter, r *http.Request, org admin.Id) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportOrganisation(q.r.Context(), q.sess, org) })
}

// ListSupportBrands implements GET .../support-view/brands.
func (h *Handler) ListSupportBrands(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListSupportBrandsParams) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportBrands(q.r.Context(), q.sess, org, p) })
}

// ListSupportOutlets implements GET .../support-view/outlets.
func (h *Handler) ListSupportOutlets(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListSupportOutletsParams) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportOutlets(q.r.Context(), q.sess, org, p) })
}

// ListSupportTaxRegistrations implements GET .../support-view/tax-registrations.
func (h *Handler) ListSupportTaxRegistrations(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListSupportTaxRegistrationsParams) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportTaxRegistrations(q.r.Context(), q.sess, org, p) })
}

// ListSupportDocumentSeries implements GET .../support-view/document-series.
func (h *Handler) ListSupportDocumentSeries(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListSupportDocumentSeriesParams) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportDocumentSeries(q.r.Context(), q.sess, org, p) })
}

// GetSupportSettings implements GET .../support-view/settings.
func (h *Handler) GetSupportSettings(w http.ResponseWriter, r *http.Request, org admin.Id) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportSettings(q.r.Context(), q.sess, org) })
}

// ListSupportMembers implements GET .../support-view/members.
func (h *Handler) ListSupportMembers(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListSupportMembersParams) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportMembers(q.r.Context(), q.sess, org, p) })
}

// ListSupportRoles implements GET .../support-view/roles.
func (h *Handler) ListSupportRoles(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListSupportRolesParams) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportRoles(q.r.Context(), q.sess, org, p) })
}

// ListSupportDevices implements GET .../support-view/devices.
func (h *Handler) ListSupportDevices(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListSupportDevicesParams) {
	h.supportRead(w, r, org, func(q *req) (any, error) { return h.svc.SupportDevices(q.r.Context(), q.sess, org, p) })
}
