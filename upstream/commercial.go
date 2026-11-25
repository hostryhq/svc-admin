package upstream

import (
	"context"
	"net/http"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/hostryhq/svc-admin/internal/gen/billing"
	"github.com/hostryhq/svc-admin/internal/gen/tenancy"
)

// The commercial and tax-rule routes of ADR-0014 A1.3/A1.4 (tenancy /internal/v1/vendor and
// billing /internal/v1/vendor). Each is one named method. A body is the facade's request, already
// decoded into the contract's type and re-encoded by the caller; the staff member's address and the
// vendor token travel in the context (Cred). An executing route also takes the approval grant,
// which goes to the service in the Hostry-Vendor-Approval header and nowhere else.

func date(t *time.Time) *openapi_types.Date {
	if t == nil {
		return nil
	}
	return &openapi_types.Date{Time: *t}
}

// ---- tenancy: plans and billing configurations ---------------------------------------------

// ListPlans lists plans.
func (u *Upstream) ListPlans(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListPlans(ctx, &tenancy.ListPlansParams{Cursor: cursor, Limit: limit})
	})
}

// GetPlan reads a plan with its versions.
func (u *Upstream) GetPlan(ctx context.Context, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) { return u.ten.GetPlan(ctx, key, &tenancy.GetPlanParams{}) })
}

// CreatePlan creates a plan with its first draft version.
func (u *Upstream) CreatePlan(ctx context.Context, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.CreatePlanWithBody(ctx, &tenancy.CreatePlanParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// CreatePlanVersion adds a draft version to a plan.
func (u *Upstream) CreatePlanVersion(ctx context.Context, plan, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.CreatePlanVersionWithBody(ctx, plan, &tenancy.CreatePlanVersionParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ActivatePlanVersion activates a draft version.
func (u *Upstream) ActivatePlanVersion(ctx context.Context, plan string, version int, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ActivatePlanVersion(ctx, plan, version, &tenancy.ActivatePlanVersionParams{IdempotencyKey: key})
	})
}

// RetirePlanVersion retires an active version.
func (u *Upstream) RetirePlanVersion(ctx context.Context, plan string, version int, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.RetirePlanVersion(ctx, plan, version, &tenancy.RetirePlanVersionParams{IdempotencyKey: key})
	})
}

// ListBillingConfigurations lists the Hostry billing configurations.
func (u *Upstream) ListBillingConfigurations(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListBillingConfigurations(ctx, &tenancy.ListBillingConfigurationsParams{Cursor: cursor, Limit: limit})
	})
}

// CreateBillingConfiguration adds a billing configuration effective from a date.
func (u *Upstream) CreateBillingConfiguration(ctx context.Context, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.CreateBillingConfigurationWithBody(ctx, &tenancy.CreateBillingConfigurationParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ---- tenancy: subscriptions ---------------------------------------------------------------

// GetOrganisationSubscription reads an organisation's subscription.
func (u *Upstream) GetOrganisationSubscription(ctx context.Context, org string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.GetOrganisationSubscription(ctx, org, &tenancy.GetOrganisationSubscriptionParams{})
	})
}

// StartSubscription assigns a plan version to an organisation.
func (u *Upstream) StartSubscription(ctx context.Context, org, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.StartSubscriptionWithBody(ctx, org, &tenancy.StartSubscriptionParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ChangeSubscription changes the plan, cycle or agreed price.
func (u *Upstream) ChangeSubscription(ctx context.Context, org, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ChangeSubscriptionWithBody(ctx, org, &tenancy.ChangeSubscriptionParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// CancelSubscription cancels a subscription.
func (u *Upstream) CancelSubscription(ctx context.Context, org, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.CancelSubscriptionWithBody(ctx, org, &tenancy.CancelSubscriptionParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ---- tenancy: charges, payments and the ledger --------------------------------------------

// ListCharges lists an organisation's charges.
func (u *Upstream) ListCharges(ctx context.Context, org string, status, cursor *string, limit *int) ([]byte, error) {
	p := &tenancy.ListChargesParams{Cursor: cursor, Limit: limit}
	if status != nil {
		st := tenancy.ListChargesParamsStatus(*status)
		p.Status = &st
	}
	return u.do(ctx, func() (*http.Response, error) { return u.ten.ListCharges(ctx, org, p) })
}

// GetCharge reads one charge.
func (u *Upstream) GetCharge(ctx context.Context, org, charge string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.GetCharge(ctx, org, charge, &tenancy.GetChargeParams{})
	})
}

// RaiseCharge raises a one-off charge.
func (u *Upstream) RaiseCharge(ctx context.Context, org, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.RaiseChargeWithBody(ctx, org, &tenancy.RaiseChargeParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// CancelCharge cancels an unpaid charge.
func (u *Upstream) CancelCharge(ctx context.Context, org, charge, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.CancelChargeWithBody(ctx, org, charge, &tenancy.CancelChargeParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// SetChargeInvoiceReference records the invoice number the vendor issued outside the platform.
func (u *Upstream) SetChargeInvoiceReference(ctx context.Context, org, charge, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.SetChargeInvoiceReferenceWithBody(ctx, org, charge, &tenancy.SetChargeInvoiceReferenceParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// WaiveCharge waives an unpaid charge.
func (u *Upstream) WaiveCharge(ctx context.Context, org, charge, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.WaiveChargeWithBody(ctx, org, charge, &tenancy.WaiveChargeParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ListChargePayments lists the payments of a charge.
func (u *Upstream) ListChargePayments(ctx context.Context, org, charge string, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListChargePayments(ctx, org, charge, &tenancy.ListChargePaymentsParams{Cursor: cursor, Limit: limit})
	})
}

// RecordPayment records a payment received outside the platform.
func (u *Upstream) RecordPayment(ctx context.Context, org, charge, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.RecordPaymentWithBody(ctx, org, charge, &tenancy.RecordPaymentParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ReversePayment reverses a recorded payment.
func (u *Upstream) ReversePayment(ctx context.Context, org, charge, payment, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ReversePaymentWithBody(ctx, org, charge, payment, &tenancy.ReversePaymentParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ExportLedger exports the ledger as CSV (organisation ids and names only).
func (u *Upstream) ExportLedger(ctx context.Context, from, to *time.Time) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ExportLedger(ctx, &tenancy.ExportLedgerParams{From: date(from), To: date(to)})
	})
}

// ListLedgerEntries reads one of the ledger lists.
func (u *Upstream) ListLedgerEntries(ctx context.Context, kind string, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListLedgerEntries(ctx, tenancy.LedgerListKind(kind), &tenancy.ListLedgerEntriesParams{Cursor: cursor, Limit: limit})
	})
}

// ---- tenancy: tax registration rejection and lifecycle execution ---------------------------

// RejectTaxRegistration records that a registration could not be verified.
func (u *Upstream) RejectTaxRegistration(ctx context.Context, org, reg, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.RejectTaxRegistrationWithBody(ctx, org, reg, &tenancy.RejectTaxRegistrationParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// SuspendOrganisation executes an approved suspension under its grant.
func (u *Upstream) SuspendOrganisation(ctx context.Context, org, key, grant string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.SuspendOrganisationWithBody(ctx, org, &tenancy.SuspendOrganisationParams{HostryVendorApproval: grant, IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ReinstateOrganisation executes an approved reinstatement under its grant.
func (u *Upstream) ReinstateOrganisation(ctx context.Context, org, key, grant string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ReinstateOrganisationWithBody(ctx, org, &tenancy.ReinstateOrganisationParams{HostryVendorApproval: grant, IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// CloseOrganisation executes an approved closure under its grant.
func (u *Upstream) CloseOrganisation(ctx context.Context, org, key, grant string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.CloseOrganisationWithBody(ctx, org, &tenancy.CloseOrganisationParams{HostryVendorApproval: grant, IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ---- billing: tax rule sets ----------------------------------------------------------------

// ListTaxRuleSetMasters lists rule-set versions, optionally by state.
func (u *Upstream) ListTaxRuleSetMasters(ctx context.Context, state, cursor *string, limit *int) ([]byte, error) {
	p := &billing.ListTaxRuleSetMastersParams{Cursor: cursor, Limit: limit}
	if state != nil {
		st := billing.ListTaxRuleSetMastersParamsState(*state)
		p.State = &st
	}
	return u.do(ctx, func() (*http.Response, error) { return u.bill.ListTaxRuleSetMasters(ctx, p) })
}

// GetTaxRuleSetMaster reads one rule-set version.
func (u *Upstream) GetTaxRuleSetMaster(ctx context.Context, id string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.bill.GetTaxRuleSetMaster(ctx, id, &billing.GetTaxRuleSetMasterParams{})
	})
}

// CreateTaxRuleSetDraft creates a draft rule set.
func (u *Upstream) CreateTaxRuleSetDraft(ctx context.Context, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.bill.CreateTaxRuleSetDraftWithBody(ctx, &billing.CreateTaxRuleSetDraftParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// UpdateTaxRuleSetDraft replaces a draft's content under its entity tag.
func (u *Upstream) UpdateTaxRuleSetDraft(ctx context.Context, id, key, ifMatch string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.bill.UpdateTaxRuleSetDraftWithBody(ctx, id, &billing.UpdateTaxRuleSetDraftParams{IfMatch: ifMatch, IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// DeleteTaxRuleSetDraft deletes a draft.
func (u *Upstream) DeleteTaxRuleSetDraft(ctx context.Context, id, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.bill.DeleteTaxRuleSetDraft(ctx, id, &billing.DeleteTaxRuleSetDraftParams{IdempotencyKey: key})
	})
}

// ValidateTaxRuleSet validates a draft.
func (u *Upstream) ValidateTaxRuleSet(ctx context.Context, id, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.bill.ValidateTaxRuleSet(ctx, id, &billing.ValidateTaxRuleSetParams{IdempotencyKey: key})
	})
}

// SignTaxRuleSet records the reviewer's sign-off and freezes the version.
func (u *Upstream) SignTaxRuleSet(ctx context.Context, id, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.bill.SignTaxRuleSetWithBody(ctx, id, &billing.SignTaxRuleSetParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// PublishTaxRuleSet executes an approved publication under its grant.
func (u *Upstream) PublishTaxRuleSet(ctx context.Context, id, key, grant string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.bill.PublishTaxRuleSetWithBody(ctx, id, &billing.PublishTaxRuleSetParams{HostryVendorApproval: grant, IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}
