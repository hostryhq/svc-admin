package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/repository"
)

// Permissions of the commercial panel (admin-a1 spec; ADR-0014 A1.3, A1.4). The owning service
// enforces them again; admin refuses early.
const (
	PermSubscriptionRead   = "admin.subscription.read"
	PermSubscriptionStart  = "admin.subscription.start"
	PermSubscriptionManage = "admin.subscription.manage"
	PermSubscriptionAdjust = "admin.subscription.adjust"
	PermPlanManage         = "admin.plan.manage"
	PermReportLedger       = "admin.report.ledger"
	PermTaxRulesManage     = "admin.taxrules.manage"
	PermTaxRulesPublish    = "admin.taxrules.publish"
	PermOrgLifecycle       = "admin.org.lifecycle.approve"
)

// The operations below are named panel needs on tenancy (plans, billing configurations,
// subscriptions, charges, payments, ledger) and billing (tax rule sets). Each one passes the
// browser's Idempotency-Key down, answers with the contract's closed type (so a field the contract
// does not name never reaches the browser) and writes no audit record: the serving service records
// the vendor action in its own transaction.

func enc(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ---- plans and billing configurations ------------------------------------------------------

// ListPlans lists plans.
func (s *Service) ListPlans(ctx context.Context, sess *repository.Session, p admin.ListPlansParams) (admin.PlanPage, error) {
	return passThrough[admin.PlanPage](s, ctx, sess, "listPlans", func(c context.Context) ([]byte, error) {
		return s.up.ListPlans(c, p.Cursor, p.Limit)
	})
}

// GetPlan reads a plan with its versions.
func (s *Service) GetPlan(ctx context.Context, sess *repository.Session, key string) (admin.Plan, error) {
	return passThrough[admin.Plan](s, ctx, sess, "getPlan", func(c context.Context) ([]byte, error) {
		return s.up.GetPlan(c, key)
	})
}

// CreatePlan creates a plan with a first draft version.
func (s *Service) CreatePlan(ctx context.Context, sess *repository.Session, idem string, in admin.CreatePlan) (admin.Plan, error) {
	return passThrough[admin.Plan](s, ctx, sess, "createPlan", func(c context.Context) ([]byte, error) {
		return s.up.CreatePlan(c, idem, enc(in))
	})
}

// CreatePlanVersion adds a draft version.
func (s *Service) CreatePlanVersion(ctx context.Context, sess *repository.Session, plan, idem string, in admin.PlanVersionDraft) (admin.PlanVersion, error) {
	return passThrough[admin.PlanVersion](s, ctx, sess, "createPlanVersion", func(c context.Context) ([]byte, error) {
		return s.up.CreatePlanVersion(c, plan, idem, enc(in))
	})
}

// ActivatePlanVersion activates a draft version.
func (s *Service) ActivatePlanVersion(ctx context.Context, sess *repository.Session, plan string, version int, idem string) (admin.PlanVersion, error) {
	return passThrough[admin.PlanVersion](s, ctx, sess, "activatePlanVersion", func(c context.Context) ([]byte, error) {
		return s.up.ActivatePlanVersion(c, plan, version, idem)
	})
}

// RetirePlanVersion retires an active version.
func (s *Service) RetirePlanVersion(ctx context.Context, sess *repository.Session, plan string, version int, idem string) (admin.PlanVersion, error) {
	return passThrough[admin.PlanVersion](s, ctx, sess, "retirePlanVersion", func(c context.Context) ([]byte, error) {
		return s.up.RetirePlanVersion(c, plan, version, idem)
	})
}

// ListBillingConfigurations lists the Hostry billing configurations.
func (s *Service) ListBillingConfigurations(ctx context.Context, sess *repository.Session, p admin.ListBillingConfigurationsParams) (admin.BillingConfigurationPage, error) {
	return passThrough[admin.BillingConfigurationPage](s, ctx, sess, "listBillingConfigurations", func(c context.Context) ([]byte, error) {
		return s.up.ListBillingConfigurations(c, p.Cursor, p.Limit)
	})
}

// CreateBillingConfiguration adds a billing configuration.
func (s *Service) CreateBillingConfiguration(ctx context.Context, sess *repository.Session, idem string, in admin.CreateBillingConfiguration) (admin.BillingConfiguration, error) {
	return passThrough[admin.BillingConfiguration](s, ctx, sess, "createBillingConfiguration", func(c context.Context) ([]byte, error) {
		return s.up.CreateBillingConfiguration(c, idem, enc(in))
	})
}

// ---- subscriptions -------------------------------------------------------------------------

// GetOrganisationSubscription reads the subscription history of an organisation.
func (s *Service) GetOrganisationSubscription(ctx context.Context, sess *repository.Session, org string) (admin.SubscriptionHistory, error) {
	return passThrough[admin.SubscriptionHistory](s, ctx, sess, "getOrganisationSubscription", func(c context.Context) ([]byte, error) {
		return s.up.GetOrganisationSubscription(c, org)
	})
}

// StartSubscription assigns a plan version to an organisation.
func (s *Service) StartSubscription(ctx context.Context, sess *repository.Session, org, idem string, in admin.StartSubscription) (admin.Subscription, error) {
	return passThrough[admin.Subscription](s, ctx, sess, "startSubscription", func(c context.Context) ([]byte, error) {
		return s.up.StartSubscription(c, org, idem, enc(in))
	})
}

// ChangeSubscription changes the plan, cycle or agreed price.
func (s *Service) ChangeSubscription(ctx context.Context, sess *repository.Session, org, idem string, in admin.ChangeSubscription) (admin.Subscription, error) {
	return passThrough[admin.Subscription](s, ctx, sess, "changeSubscription", func(c context.Context) ([]byte, error) {
		return s.up.ChangeSubscription(c, org, idem, enc(in))
	})
}

// CancelSubscription cancels a subscription.
func (s *Service) CancelSubscription(ctx context.Context, sess *repository.Session, org, idem string, in admin.CancelSubscription) (admin.Subscription, error) {
	return passThrough[admin.Subscription](s, ctx, sess, "cancelSubscription", func(c context.Context) ([]byte, error) {
		return s.up.CancelSubscription(c, org, idem, enc(in))
	})
}

// ---- charges, payments, ledger -------------------------------------------------------------

// ListCharges lists an organisation's charges.
func (s *Service) ListCharges(ctx context.Context, sess *repository.Session, org string, p admin.ListChargesParams) (admin.ChargePage, error) {
	var status *string
	if p.Status != nil {
		st := string(*p.Status)
		status = &st
	}
	return passThrough[admin.ChargePage](s, ctx, sess, "listCharges", func(c context.Context) ([]byte, error) {
		return s.up.ListCharges(c, org, status, p.Cursor, p.Limit)
	})
}

// GetCharge reads one charge.
func (s *Service) GetCharge(ctx context.Context, sess *repository.Session, org, charge string) (admin.Charge, error) {
	return passThrough[admin.Charge](s, ctx, sess, "getCharge", func(c context.Context) ([]byte, error) {
		return s.up.GetCharge(c, org, charge)
	})
}

// RaiseCharge raises a one-off charge.
func (s *Service) RaiseCharge(ctx context.Context, sess *repository.Session, org, idem string, in admin.RaiseCharge) (admin.Charge, error) {
	return passThrough[admin.Charge](s, ctx, sess, "raiseCharge", func(c context.Context) ([]byte, error) {
		return s.up.RaiseCharge(c, org, idem, enc(in))
	})
}

// CancelCharge cancels an unpaid charge.
func (s *Service) CancelCharge(ctx context.Context, sess *repository.Session, org, charge, idem string, in admin.ReasonBody) (admin.Charge, error) {
	return passThrough[admin.Charge](s, ctx, sess, "cancelCharge", func(c context.Context) ([]byte, error) {
		return s.up.CancelCharge(c, org, charge, idem, enc(in))
	})
}

// SetChargeInvoiceReference records the externally issued invoice number.
func (s *Service) SetChargeInvoiceReference(ctx context.Context, sess *repository.Session, org, charge, idem string, in admin.SetInvoiceReference) (admin.Charge, error) {
	return passThrough[admin.Charge](s, ctx, sess, "setChargeInvoiceReference", func(c context.Context) ([]byte, error) {
		return s.up.SetChargeInvoiceReference(c, org, charge, idem, enc(in))
	})
}

// WaiveCharge waives an unpaid charge.
func (s *Service) WaiveCharge(ctx context.Context, sess *repository.Session, org, charge, idem string, in admin.ReasonBody) (admin.Charge, error) {
	return passThrough[admin.Charge](s, ctx, sess, "waiveCharge", func(c context.Context) ([]byte, error) {
		return s.up.WaiveCharge(c, org, charge, idem, enc(in))
	})
}

// ListChargePayments lists the payments of a charge.
func (s *Service) ListChargePayments(ctx context.Context, sess *repository.Session, org, charge string, p admin.ListChargePaymentsParams) (admin.LedgerPaymentPage, error) {
	return passThrough[admin.LedgerPaymentPage](s, ctx, sess, "listChargePayments", func(c context.Context) ([]byte, error) {
		return s.up.ListChargePayments(c, org, charge, p.Cursor, p.Limit)
	})
}

// RecordPayment records a payment received outside the platform.
func (s *Service) RecordPayment(ctx context.Context, sess *repository.Session, org, charge, idem string, in admin.RecordPayment) (admin.LedgerPayment, error) {
	return passThrough[admin.LedgerPayment](s, ctx, sess, "recordPayment", func(c context.Context) ([]byte, error) {
		return s.up.RecordPayment(c, org, charge, idem, enc(in))
	})
}

// ReversePayment reverses a recorded payment.
func (s *Service) ReversePayment(ctx context.Context, sess *repository.Session, org, charge, payment, idem string, in admin.ReasonBody) (admin.LedgerPayment, error) {
	return passThrough[admin.LedgerPayment](s, ctx, sess, "reversePayment", func(c context.Context) ([]byte, error) {
		return s.up.ReversePayment(c, org, charge, payment, idem, enc(in))
	})
}

// ListLedgerEntries reads one of the ledger lists.
func (s *Service) ListLedgerEntries(ctx context.Context, sess *repository.Session, kind admin.LedgerListKind, p admin.ListLedgerEntriesParams) (admin.LedgerListRowPage, error) {
	return passThrough[admin.LedgerListRowPage](s, ctx, sess, "listLedgerEntries", func(c context.Context) ([]byte, error) {
		return s.up.ListLedgerEntries(c, string(kind), p.Cursor, p.Limit)
	})
}

// ExportLedger returns the ledger as CSV. The text is the serving service's own export, which holds
// organisation ids and names only (BR-A1-38); the api layer runs it through the deny list.
func (s *Service) ExportLedger(ctx context.Context, sess *repository.Session, from, to *time.Time) ([]byte, error) {
	var raw []byte
	err := s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		raw, e = s.up.ExportLedger(c, from, to)
		return e
	})
	if err != nil {
		return nil, s.mapErr(ctx, "exportLedger", err)
	}
	return raw, nil
}

// ---- tax registration rejection ------------------------------------------------------------

// RejectTaxRegistration records that a registration could not be verified.
func (s *Service) RejectTaxRegistration(ctx context.Context, sess *repository.Session, org, reg, idem string, in admin.RejectRegistration) (admin.TaxRegistration, error) {
	return passThrough[admin.TaxRegistration](s, ctx, sess, "rejectTaxRegistration", func(c context.Context) ([]byte, error) {
		return s.up.RejectTaxRegistration(c, org, reg, idem, enc(in))
	})
}

// ---- tax rule sets (billing) ---------------------------------------------------------------

// ListTaxRuleSetMasters lists rule-set versions.
func (s *Service) ListTaxRuleSetMasters(ctx context.Context, sess *repository.Session, p admin.ListTaxRuleSetMastersParams) (admin.TaxRuleSetMasterPage, error) {
	var state *string
	if p.State != nil {
		st := string(*p.State)
		state = &st
	}
	return passThrough[admin.TaxRuleSetMasterPage](s, ctx, sess, "listTaxRuleSetMasters", func(c context.Context) ([]byte, error) {
		return s.up.ListTaxRuleSetMasters(c, state, p.Cursor, p.Limit)
	})
}

// GetTaxRuleSetMaster reads one rule-set version.
func (s *Service) GetTaxRuleSetMaster(ctx context.Context, sess *repository.Session, id string) (admin.TaxRuleSetMaster, error) {
	return passThrough[admin.TaxRuleSetMaster](s, ctx, sess, "getTaxRuleSetMaster", func(c context.Context) ([]byte, error) {
		return s.up.GetTaxRuleSetMaster(c, id)
	})
}

// CreateTaxRuleSetDraft creates a draft.
func (s *Service) CreateTaxRuleSetDraft(ctx context.Context, sess *repository.Session, idem string, in admin.TaxRuleSetDraft) (admin.TaxRuleSetMaster, error) {
	return passThrough[admin.TaxRuleSetMaster](s, ctx, sess, "createTaxRuleSetDraft", func(c context.Context) ([]byte, error) {
		return s.up.CreateTaxRuleSetDraft(c, idem, enc(in))
	})
}

// UpdateTaxRuleSetDraft replaces a draft's content under its entity tag (a stale tag is 412).
func (s *Service) UpdateTaxRuleSetDraft(ctx context.Context, sess *repository.Session, id, idem, ifMatch string, in admin.TaxRuleSetDraft) (admin.TaxRuleSetMaster, error) {
	return passThrough[admin.TaxRuleSetMaster](s, ctx, sess, "updateTaxRuleSetDraft", func(c context.Context) ([]byte, error) {
		return s.up.UpdateTaxRuleSetDraft(c, id, idem, ifMatch, enc(in))
	})
}

// DeleteTaxRuleSetDraft deletes a draft.
func (s *Service) DeleteTaxRuleSetDraft(ctx context.Context, sess *repository.Session, id, idem string) error {
	err := s.asVendor(ctx, sess, func(c context.Context) error {
		_, e := s.up.DeleteTaxRuleSetDraft(c, id, idem)
		return e
	})
	return s.mapErr(ctx, "deleteTaxRuleSetDraft", err)
}

// ValidateTaxRuleSet validates a draft.
func (s *Service) ValidateTaxRuleSet(ctx context.Context, sess *repository.Session, id, idem string) (admin.TaxRuleSetValidation, error) {
	return passThrough[admin.TaxRuleSetValidation](s, ctx, sess, "validateTaxRuleSet", func(c context.Context) ([]byte, error) {
		return s.up.ValidateTaxRuleSet(c, id, idem)
	})
}

// SignTaxRuleSet records the reviewer's sign-off.
func (s *Service) SignTaxRuleSet(ctx context.Context, sess *repository.Session, id, idem string, in admin.SignTaxRuleSet) (admin.TaxRuleSetMaster, error) {
	return passThrough[admin.TaxRuleSetMaster](s, ctx, sess, "signTaxRuleSet", func(c context.Context) ([]byte, error) {
		return s.up.SignTaxRuleSet(c, id, idem, enc(in))
	})
}
