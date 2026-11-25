package api

import (
	"net/http"
	"regexp"
	"slices"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/hostryhq/go-common/apperr"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/service"
)

// The commercial panel (plans, billing configurations, subscriptions, charges, payments, ledger),
// the tax rule-set lifecycle and the executions of approved actions (ADR-0013 V4, ADR-0014 A1.3,
// A1.4, A2.5). Each handler checks the session, CSRF, Origin and permission (admit), validates the
// ids in the path, decodes the body into the contract's type and calls service. No rule lives here.

var (
	planKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)
	// A rule set id is a UUID of any version: billing derives it from the version (UUIDv5).
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	ledgerKinds = []admin.LedgerListKind{
		admin.ChargesToRaise, admin.ChargesWithoutInvoiceReference, admin.OutletsOverLimit,
		admin.OverdueCharges, admin.PilotsEnding, admin.RetiredVersionSubscriptions,
	}
)

func planPath(key string, version int) error {
	if !planKeyRe.MatchString(key) || version < 1 {
		return service.ErrNotFound
	}
	return nil
}

var errRange = apperr.New(apperr.Validation, "validation", "").WithFields(apperr.FieldError{Field: "to", Code: "before_from"})

// approvalField refuses an approval id that cannot exist, as a validation error on the body.
func approvalField(id string) error {
	if !idRe.MatchString(id) {
		return apperr.New(apperr.Validation, "validation", "").WithFields(apperr.FieldError{Field: "approval_id", Code: "invalid"})
	}
	return nil
}

func ruleSetID(id string) error {
	if !uuidRe.MatchString(id) {
		return service.ErrNotFound
	}
	return nil
}

var (
	subRead   = perm(service.PermSubscriptionRead)
	planWrite = permMut(service.PermPlanManage)
	taxManage = permMut(service.PermTaxRulesManage)
)

// body decodes the request body and runs fn on it, for the many handlers of that shape.
func withBody[T any](q *req, fn func(in T) (outcome, error)) (outcome, error) {
	in, err := decode[T](q.body)
	if err != nil {
		return outcome{}, err
	}
	return fn(in)
}

// ---- plans and billing configurations ------------------------------------------------------

// ListPlans implements GET /v1/plans.
func (h *Handler) ListPlans(w http.ResponseWriter, r *http.Request, p admin.ListPlansParams) {
	h.read(w, r, subRead, func(q *req) (outcome, error) {
		out, err := h.svc.ListPlans(q.r.Context(), q.sess, p)
		return ok(out), err
	})
}

// GetPlan implements GET /v1/plans/{plan_key}.
func (h *Handler) GetPlan(w http.ResponseWriter, r *http.Request, planKey string) {
	h.read(w, r, subRead, func(q *req) (outcome, error) {
		if err := planPath(planKey, 1); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.GetPlan(q.r.Context(), q.sess, planKey)
		return ok(out), err
	})
}

// CreatePlan implements POST /v1/plans.
func (h *Handler) CreatePlan(w http.ResponseWriter, r *http.Request, _ admin.CreatePlanParams) {
	h.mutate(w, r, planWrite, func(q *req) (outcome, error) {
		return withBody(q, func(in admin.CreatePlan) (outcome, error) {
			out, err := h.svc.CreatePlan(q.r.Context(), q.sess, q.key, in)
			return created(out), err
		})
	})
}

// CreatePlanVersion implements POST /v1/plans/{plan_key}/versions.
func (h *Handler) CreatePlanVersion(w http.ResponseWriter, r *http.Request, planKey string, _ admin.CreatePlanVersionParams) {
	h.mutate(w, r, planWrite, func(q *req) (outcome, error) {
		if err := planPath(planKey, 1); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.PlanVersionDraft) (outcome, error) {
			out, err := h.svc.CreatePlanVersion(q.r.Context(), q.sess, planKey, q.key, in)
			return created(out), err
		})
	})
}

// ActivatePlanVersion implements POST /v1/plans/{plan_key}/versions/{version}/activation.
func (h *Handler) ActivatePlanVersion(w http.ResponseWriter, r *http.Request, planKey string, version int, _ admin.ActivatePlanVersionParams) {
	h.mutate(w, r, planWrite, func(q *req) (outcome, error) {
		if err := planPath(planKey, version); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.ActivatePlanVersion(q.r.Context(), q.sess, planKey, version, q.key)
		return ok(out), err
	})
}

// RetirePlanVersion implements POST /v1/plans/{plan_key}/versions/{version}/retirement.
func (h *Handler) RetirePlanVersion(w http.ResponseWriter, r *http.Request, planKey string, version int, _ admin.RetirePlanVersionParams) {
	h.mutate(w, r, planWrite, func(q *req) (outcome, error) {
		if err := planPath(planKey, version); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.RetirePlanVersion(q.r.Context(), q.sess, planKey, version, q.key)
		return ok(out), err
	})
}

// ListBillingConfigurations implements GET /v1/billing-configurations.
func (h *Handler) ListBillingConfigurations(w http.ResponseWriter, r *http.Request, p admin.ListBillingConfigurationsParams) {
	h.read(w, r, subRead, func(q *req) (outcome, error) {
		out, err := h.svc.ListBillingConfigurations(q.r.Context(), q.sess, p)
		return ok(out), err
	})
}

// CreateBillingConfiguration implements POST /v1/billing-configurations.
func (h *Handler) CreateBillingConfiguration(w http.ResponseWriter, r *http.Request, _ admin.CreateBillingConfigurationParams) {
	h.mutate(w, r, planWrite, func(q *req) (outcome, error) {
		return withBody(q, func(in admin.CreateBillingConfiguration) (outcome, error) {
			out, err := h.svc.CreateBillingConfiguration(q.r.Context(), q.sess, q.key, in)
			return created(out), err
		})
	})
}

// ---- subscriptions -------------------------------------------------------------------------

// GetOrganisationSubscription implements GET .../subscription.
func (h *Handler) GetOrganisationSubscription(w http.ResponseWriter, r *http.Request, org admin.Id) {
	h.read(w, r, subRead, func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.GetOrganisationSubscription(q.r.Context(), q.sess, org)
		return ok(out), err
	})
}

// StartSubscription implements POST .../subscription.
func (h *Handler) StartSubscription(w http.ResponseWriter, r *http.Request, org admin.Id, _ admin.StartSubscriptionParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionStart), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.StartSubscription) (outcome, error) {
			out, err := h.svc.StartSubscription(q.r.Context(), q.sess, org, q.key, in)
			return created(out), err
		})
	})
}

// ChangeSubscription implements PUT .../subscription.
func (h *Handler) ChangeSubscription(w http.ResponseWriter, r *http.Request, org admin.Id, _ admin.ChangeSubscriptionParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionManage), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.ChangeSubscription) (outcome, error) {
			out, err := h.svc.ChangeSubscription(q.r.Context(), q.sess, org, q.key, in)
			return ok(out), err
		})
	})
}

// CancelSubscription implements POST .../subscription/cancellation.
func (h *Handler) CancelSubscription(w http.ResponseWriter, r *http.Request, org admin.Id, _ admin.CancelSubscriptionParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionManage), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.CancelSubscription) (outcome, error) {
			out, err := h.svc.CancelSubscription(q.r.Context(), q.sess, org, q.key, in)
			return ok(out), err
		})
	})
}

// ---- charges, payments, ledger -------------------------------------------------------------

// ListCharges implements GET .../charges.
func (h *Handler) ListCharges(w http.ResponseWriter, r *http.Request, org admin.Id, p admin.ListChargesParams) {
	h.read(w, r, subRead, func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.ListCharges(q.r.Context(), q.sess, org, p)
		return ok(out), err
	})
}

// RaiseCharge implements POST .../charges.
func (h *Handler) RaiseCharge(w http.ResponseWriter, r *http.Request, org admin.Id, _ admin.RaiseChargeParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionManage), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.RaiseCharge) (outcome, error) {
			out, err := h.svc.RaiseCharge(q.r.Context(), q.sess, org, q.key, in)
			return created(out), err
		})
	})
}

// GetCharge implements GET .../charges/{charge_id}.
func (h *Handler) GetCharge(w http.ResponseWriter, r *http.Request, org, charge admin.Id) {
	h.read(w, r, subRead, func(q *req) (outcome, error) {
		if err := ids2(org, charge); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.GetCharge(q.r.Context(), q.sess, org, charge)
		return ok(out), err
	})
}

// CancelCharge implements POST .../charges/{charge_id}/cancellation.
func (h *Handler) CancelCharge(w http.ResponseWriter, r *http.Request, org, charge admin.Id, _ admin.CancelChargeParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionAdjust), func(q *req) (outcome, error) {
		if err := ids2(org, charge); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.ReasonBody) (outcome, error) {
			out, err := h.svc.CancelCharge(q.r.Context(), q.sess, org, charge, q.key, in)
			return ok(out), err
		})
	})
}

// SetChargeInvoiceReference implements PUT .../charges/{charge_id}/invoice-reference.
func (h *Handler) SetChargeInvoiceReference(w http.ResponseWriter, r *http.Request, org, charge admin.Id, _ admin.SetChargeInvoiceReferenceParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionManage), func(q *req) (outcome, error) {
		if err := ids2(org, charge); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.SetInvoiceReference) (outcome, error) {
			out, err := h.svc.SetChargeInvoiceReference(q.r.Context(), q.sess, org, charge, q.key, in)
			return ok(out), err
		})
	})
}

// WaiveCharge implements POST .../charges/{charge_id}/waiver.
func (h *Handler) WaiveCharge(w http.ResponseWriter, r *http.Request, org, charge admin.Id, _ admin.WaiveChargeParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionAdjust), func(q *req) (outcome, error) {
		if err := ids2(org, charge); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.ReasonBody) (outcome, error) {
			out, err := h.svc.WaiveCharge(q.r.Context(), q.sess, org, charge, q.key, in)
			return ok(out), err
		})
	})
}

// ListChargePayments implements GET .../charges/{charge_id}/payments.
func (h *Handler) ListChargePayments(w http.ResponseWriter, r *http.Request, org, charge admin.Id, p admin.ListChargePaymentsParams) {
	h.read(w, r, subRead, func(q *req) (outcome, error) {
		if err := ids2(org, charge); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.ListChargePayments(q.r.Context(), q.sess, org, charge, p)
		return ok(out), err
	})
}

// RecordPayment implements POST .../charges/{charge_id}/payments.
func (h *Handler) RecordPayment(w http.ResponseWriter, r *http.Request, org, charge admin.Id, _ admin.RecordPaymentParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionManage), func(q *req) (outcome, error) {
		if err := ids2(org, charge); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.RecordPayment) (outcome, error) {
			out, err := h.svc.RecordPayment(q.r.Context(), q.sess, org, charge, q.key, in)
			return created(out), err
		})
	})
}

// ReversePayment implements POST .../payments/{payment_id}/reversal.
func (h *Handler) ReversePayment(w http.ResponseWriter, r *http.Request, org, charge, payment admin.Id, _ admin.ReversePaymentParams) {
	h.mutate(w, r, permMut(service.PermSubscriptionAdjust), func(q *req) (outcome, error) {
		if err := ids2(org, charge); err != nil {
			return outcome{}, err
		}
		if err := pathID(payment); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.ReasonBody) (outcome, error) {
			out, err := h.svc.ReversePayment(q.r.Context(), q.sess, org, charge, payment, q.key, in)
			return created(out), err
		})
	})
}

// ListLedgerEntries implements GET /v1/ledger-lists/{list_kind}.
func (h *Handler) ListLedgerEntries(w http.ResponseWriter, r *http.Request, kind admin.LedgerListKind, p admin.ListLedgerEntriesParams) {
	h.read(w, r, subRead, func(q *req) (outcome, error) {
		if !slices.Contains(ledgerKinds, kind) {
			return outcome{}, service.ErrNotFound
		}
		out, err := h.svc.ListLedgerEntries(q.r.Context(), q.sess, kind, p)
		return ok(out), err
	})
}

func dateOf(d *openapi_types.Date) *time.Time {
	if d == nil {
		return nil
	}
	return &d.Time
}

// ExportLedger implements GET /v1/ledger-exports (text/csv).
func (h *Handler) ExportLedger(w http.ResponseWriter, r *http.Request, p admin.ExportLedgerParams) {
	h.read(w, r, perm(service.PermReportLedger), func(q *req) (outcome, error) {
		if p.From != nil && p.To != nil && p.To.Before(p.From.Time) {
			return outcome{}, errRange
		}
		raw, err := h.svc.ExportLedger(q.r.Context(), q.sess, dateOf(p.From), dateOf(p.To))
		return outcome{status: http.StatusOK, csv: raw}, err
	})
}

// ---- registration rejection ----------------------------------------------------------------

// RejectTaxRegistration implements PUT .../tax-registrations/{registration_id}/rejection.
func (h *Handler) RejectTaxRegistration(w http.ResponseWriter, r *http.Request, org, reg admin.Id, _ admin.RejectTaxRegistrationParams) {
	h.mutate(w, r, permMut(service.PermRegistrationVfy), func(q *req) (outcome, error) {
		if err := ids2(org, reg); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.RejectRegistration) (outcome, error) {
			out, err := h.svc.RejectTaxRegistration(q.r.Context(), q.sess, org, reg, q.key, in)
			return ok(out), err
		})
	})
}

// ---- executions of approved actions --------------------------------------------------------

// lifecycle runs an execution by approval_id. The answer is the organisation after the action.
func (h *Handler) lifecycle(w http.ResponseWriter, r *http.Request, org admin.Id,
	run func(h *Handler, q *req, in admin.ExecuteLifecycle) (admin.LifecycleResult, error)) {
	h.mutate(w, r, permMut(service.PermOrgLifecycle), func(q *req) (outcome, error) {
		if err := pathID(org); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.ExecuteLifecycle) (outcome, error) {
			if err := approvalField(in.ApprovalId); err != nil {
				return outcome{}, err
			}
			out, err := run(h, q, in)
			return ok(out), err
		})
	})
}

// SuspendOrganisation implements POST .../suspension.
func (h *Handler) SuspendOrganisation(w http.ResponseWriter, r *http.Request, org admin.Id, _ admin.SuspendOrganisationParams) {
	h.lifecycle(w, r, org, func(h *Handler, q *req, in admin.ExecuteLifecycle) (admin.LifecycleResult, error) {
		return h.svc.SuspendOrganisation(q.r.Context(), q.sess, org, q.key, in)
	})
}

// ReinstateOrganisation implements POST .../reinstatement.
func (h *Handler) ReinstateOrganisation(w http.ResponseWriter, r *http.Request, org admin.Id, _ admin.ReinstateOrganisationParams) {
	h.lifecycle(w, r, org, func(h *Handler, q *req, in admin.ExecuteLifecycle) (admin.LifecycleResult, error) {
		return h.svc.ReinstateOrganisation(q.r.Context(), q.sess, org, q.key, in)
	})
}

// CloseOrganisation implements POST .../closure.
func (h *Handler) CloseOrganisation(w http.ResponseWriter, r *http.Request, org admin.Id, _ admin.CloseOrganisationParams) {
	h.lifecycle(w, r, org, func(h *Handler, q *req, in admin.ExecuteLifecycle) (admin.LifecycleResult, error) {
		return h.svc.CloseOrganisation(q.r.Context(), q.sess, org, q.key, in)
	})
}

// ---- tax rule sets -------------------------------------------------------------------------

// ListTaxRuleSetMasters implements GET /v1/tax-rule-sets.
func (h *Handler) ListTaxRuleSetMasters(w http.ResponseWriter, r *http.Request, p admin.ListTaxRuleSetMastersParams) {
	h.read(w, r, perm(service.PermTaxRulesManage), func(q *req) (outcome, error) {
		out, err := h.svc.ListTaxRuleSetMasters(q.r.Context(), q.sess, p)
		return ok(out), err
	})
}

// CreateTaxRuleSetDraft implements POST /v1/tax-rule-sets.
func (h *Handler) CreateTaxRuleSetDraft(w http.ResponseWriter, r *http.Request, _ admin.CreateTaxRuleSetDraftParams) {
	h.mutate(w, r, taxManage, func(q *req) (outcome, error) {
		return withBody(q, func(in admin.TaxRuleSetDraft) (outcome, error) {
			out, err := h.svc.CreateTaxRuleSetDraft(q.r.Context(), q.sess, q.key, in)
			return created(out), err
		})
	})
}

// GetTaxRuleSetMaster implements GET /v1/tax-rule-sets/{rule_set_id}.
func (h *Handler) GetTaxRuleSetMaster(w http.ResponseWriter, r *http.Request, id admin.Id) {
	h.read(w, r, perm(service.PermTaxRulesManage), func(q *req) (outcome, error) {
		if err := ruleSetID(id); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.GetTaxRuleSetMaster(q.r.Context(), q.sess, id)
		return ok(out), err
	})
}

// UpdateTaxRuleSetDraft implements PATCH /v1/tax-rule-sets/{rule_set_id} (If-Match).
func (h *Handler) UpdateTaxRuleSetDraft(w http.ResponseWriter, r *http.Request, id admin.Id, p admin.UpdateTaxRuleSetDraftParams) {
	h.mutate(w, r, taxManage, func(q *req) (outcome, error) {
		if err := ruleSetID(id); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.TaxRuleSetDraft) (outcome, error) {
			out, err := h.svc.UpdateTaxRuleSetDraft(q.r.Context(), q.sess, id, q.key, p.IfMatch, in)
			return ok(out), err
		})
	})
}

// DeleteTaxRuleSetDraft implements DELETE /v1/tax-rule-sets/{rule_set_id}.
func (h *Handler) DeleteTaxRuleSetDraft(w http.ResponseWriter, r *http.Request, id admin.Id, _ admin.DeleteTaxRuleSetDraftParams) {
	h.mutate(w, r, taxManage, func(q *req) (outcome, error) {
		if err := ruleSetID(id); err != nil {
			return outcome{}, err
		}
		err := h.svc.DeleteTaxRuleSetDraft(q.r.Context(), q.sess, id, q.key)
		return outcome{status: http.StatusNoContent}, err
	})
}

// ValidateTaxRuleSet implements POST /v1/tax-rule-sets/{rule_set_id}/validation.
func (h *Handler) ValidateTaxRuleSet(w http.ResponseWriter, r *http.Request, id admin.Id, _ admin.ValidateTaxRuleSetParams) {
	h.mutate(w, r, taxManage, func(q *req) (outcome, error) {
		if err := ruleSetID(id); err != nil {
			return outcome{}, err
		}
		out, err := h.svc.ValidateTaxRuleSet(q.r.Context(), q.sess, id, q.key)
		return ok(out), err
	})
}

// SignTaxRuleSet implements POST /v1/tax-rule-sets/{rule_set_id}/signature.
func (h *Handler) SignTaxRuleSet(w http.ResponseWriter, r *http.Request, id admin.Id, _ admin.SignTaxRuleSetParams) {
	h.mutate(w, r, taxManage, func(q *req) (outcome, error) {
		if err := ruleSetID(id); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.SignTaxRuleSet) (outcome, error) {
			out, err := h.svc.SignTaxRuleSet(q.r.Context(), q.sess, id, q.key, in)
			return ok(out), err
		})
	})
}

// PublishTaxRuleSet implements POST /v1/tax-rule-sets/{rule_set_id}/publication.
func (h *Handler) PublishTaxRuleSet(w http.ResponseWriter, r *http.Request, id admin.Id, _ admin.PublishTaxRuleSetParams) {
	h.mutate(w, r, permMut(service.PermTaxRulesPublish), func(q *req) (outcome, error) {
		if err := ruleSetID(id); err != nil {
			return outcome{}, err
		}
		return withBody(q, func(in admin.ExecutePublication) (outcome, error) {
			if err := approvalField(in.ApprovalId); err != nil {
				return outcome{}, err
			}
			out, err := h.svc.PublishTaxRuleSet(q.r.Context(), q.sess, id, q.key, in)
			return ok(out), err
		})
	})
}
