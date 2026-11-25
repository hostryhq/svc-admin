# Operations status

Every operationId of `api-specs/openapi/admin/v1` (the contract admin-web calls) and what `svc-admin` calls on identity, tenancy and billing.
Contract commit: see `internal/gen/API_SPECS_COMMIT`. Updated whenever an operation changes.

## Admin API (served): 74 of 74 implemented (39 of Phase 1, 35 of Phase 2)

"Upstream" is the generated-client call the operation is built on; every upstream call carries the `admin` service token plus the vendor user's token (or the support token for support-view reads). The Phase 2 commercial operations call tenancy `/internal/v1/vendor/...` and billing `/internal/v1/vendor/tax-rule-sets`; an executing operation also sends the approval grant in `Hostry-Vendor-Approval`.

| operationId | Method and path | Permission (checked here, enforced again by the owner) | Upstream | Status |
|---|---|---|---|---|
| signIn | POST /v1/sessions | public | identity `createVendorSession` | implemented |
| getSession | GET /v1/sessions/current | authenticated | none (session) | implemented |
| signOut | DELETE /v1/sessions/current | authenticated | identity `endSupportSession`, `endVendorSession` (best effort) | implemented |
| beginAccountSetup | POST /v1/account-setups | public | identity `beginVendorSetup` | implemented |
| completeAccountSetup | POST /v1/account-setup-completions | public | identity `completeVendorSetup` | implemented |
| listVendorUsers | GET /v1/vendor-users | admin.user.manage | identity `listVendorUsers` | implemented |
| createVendorUser | POST /v1/vendor-users | admin.user.manage | identity `createVendorUser` | implemented |
| updateVendorUser | PATCH /v1/vendor-users/{id} | admin.user.manage | identity `updateVendorUser`; drops the target's sessions | implemented |
| resetVendorUserTotp | POST /v1/vendor-users/{id}/totp-resets | admin.user.manage | identity `resetVendorUserTotp`; drops the target's sessions | implemented |
| listOrganisations | GET /v1/organisations | admin.org.read | tenancy `listOrganisationDirectory`; identity `lookupOrganisationsByOwnerMobile` (exact number), `getOwnerStatuses` | implemented |
| createOrganisation | POST /v1/organisations | admin.org.create | tenancy `createOrganisation` then identity `createOwnerInvitation`, same Idempotency-Key | implemented |
| getOrganisation | GET /v1/organisations/{id} | admin.org.read | tenancy `getOrganisationDirectoryEntry`; identity `getOwnerStatuses`, `listOwnerInvitations` | implemented |
| listOwnerInvitations | GET .../owner-invitations | admin.org.read | identity `listOwnerInvitations` | implemented |
| createOwnerInvitation | POST .../owner-invitations | admin.owner_invite.manage | identity `createOwnerInvitation` | implemented |
| renewOwnerInvitation | POST .../owner-invitations/{id}/renewals | admin.owner_invite.manage | identity `renewOwnerInvitation` | implemented |
| cancelOwnerInvitation | PUT .../owner-invitations/{id}/cancellation | admin.owner_invite.manage | identity `cancelOwnerInvitation` | implemented |
| verifyTaxRegistration | PUT .../tax-registrations/{id}/verification | admin.registration.verify | tenancy `verifyTaxRegistration` | implemented |
| listOrganisationDevices | GET .../devices | admin.device.read | identity `listOrganisationDevices` | implemented |
| getOrganisationDevice | GET .../devices/{id} | admin.device.read | identity `getOrganisationDevice` | implemented |
| revokeOrganisationDevice | PUT .../devices/{id}/revocation | admin.device.revoke | identity `revokeOrganisationDevice` (409 `vendor_approval_required` passes through; `approval_id` in the body) | implemented |
| fileVendorApproval | POST /v1/approvals | admin.approval.create, then the kind's permission (x-permission-by-kind) | identity `createVendorApproval` (kinds: sign_in_code, owner_recovery, device_revoke_over_quota, org_suspend, org_reinstate, org_close, tax_rule_set_publish) | implemented |
| listVendorApprovals | GET /v1/approvals | admin.approval.read | identity `listVendorApprovals` | implemented |
| getVendorApproval | GET /v1/approvals/{id} | admin.approval.read | identity `getVendorApproval` | implemented |
| approveVendorApproval | PUT /v1/approvals/{id}/decision | admin.approval.decide, then the kind's approve permission | identity `getVendorApproval` (kind and requester), `approveVendorApproval`; refuses the requester as approver (409 `second_approver_unavailable`); the grant of org_suspend, org_reinstate, org_close and tax_rule_set_publish is kept in the session, never returned, and the action is executed in the same request (`execution` in the answer) | implemented |
| claimCodeHalf | POST /v1/approvals/{id}/code-half-claims | admin.approval.create | identity `claimCodeHalf` (answer not kept for replays) | implemented |
| cancelVendorApproval | PUT /v1/approvals/{id}/cancellation | admin.approval.decide | identity `cancelVendorApproval` | implemented |
| listAuditEntries | GET /v1/audit-entries | admin.audit.read_own or admin.audit.read | identity `listVendorAuditEntries` | implemented |
| startSupportSession | POST /v1/support-sessions | admin.support.session.start | identity `startSupportSession` (token kept in memory) | implemented |
| getSupportSession | GET /v1/support-sessions/current | admin.support.session.start | none (session) | implemented |
| endSupportSession | DELETE /v1/support-sessions/current | admin.support.session.start | identity `endSupportSession` | implemented |
| getSupportOrganisation | GET .../support-view/profile | admin.support.session.start | tenancy `getCurrentOrganisation` (support token) | implemented |
| listSupportBrands | GET .../support-view/brands | admin.support.session.start | tenancy `listBrands` | implemented |
| listSupportOutlets | GET .../support-view/outlets | admin.support.session.start | tenancy `listOutlets` | implemented |
| listSupportTaxRegistrations | GET .../support-view/tax-registrations | admin.support.session.start | tenancy `listTaxRegistrations` | implemented |
| listSupportDocumentSeries | GET .../support-view/document-series | admin.support.session.start | tenancy `listDocumentSeries` | implemented |
| getSupportSettings | GET .../support-view/settings | admin.support.session.start | tenancy `getOrganisationSettings` | implemented |
| listSupportMembers | GET .../support-view/members | admin.support.session.start | identity `listMembers` | implemented |
| listSupportRoles | GET .../support-view/roles | admin.support.session.start | identity `listRoles` | implemented |
| listSupportDevices | GET .../support-view/devices | admin.support.session.start | identity `listDevices` | implemented |
| listPlans | GET /v1/plans | admin.subscription.read | tenancy `listPlans` | implemented |
| createPlan | POST /v1/plans | admin.plan.manage | tenancy `createPlan` | implemented |
| getPlan | GET /v1/plans/{plan_key} | admin.subscription.read | tenancy `getPlan` | implemented |
| createPlanVersion | POST /v1/plans/{plan_key}/versions | admin.plan.manage | tenancy `createPlanVersion` | implemented |
| activatePlanVersion | POST .../versions/{version}/activation | admin.plan.manage | tenancy `activatePlanVersion` | implemented |
| retirePlanVersion | POST .../versions/{version}/retirement | admin.plan.manage | tenancy `retirePlanVersion` | implemented |
| listBillingConfigurations | GET /v1/billing-configurations | admin.subscription.read | tenancy `listBillingConfigurations` | implemented |
| createBillingConfiguration | POST /v1/billing-configurations | admin.plan.manage | tenancy `createBillingConfiguration` | implemented |
| getOrganisationSubscription | GET .../subscription | admin.subscription.read | tenancy `getOrganisationSubscription` | implemented |
| startSubscription | POST .../subscription | admin.subscription.start | tenancy `startSubscription` | implemented |
| changeSubscription | PUT .../subscription | admin.subscription.manage | tenancy `changeSubscription` | implemented |
| cancelSubscription | POST .../subscription/cancellation | admin.subscription.manage | tenancy `cancelSubscription` | implemented |
| listCharges | GET .../charges | admin.subscription.read | tenancy `listCharges` | implemented |
| raiseCharge | POST .../charges | admin.subscription.manage | tenancy `raiseCharge` | implemented |
| getCharge | GET .../charges/{id} | admin.subscription.read | tenancy `getCharge` | implemented |
| cancelCharge | POST .../charges/{id}/cancellation | admin.subscription.adjust | tenancy `cancelCharge` | implemented |
| setChargeInvoiceReference | PUT .../charges/{id}/invoice-reference | admin.subscription.manage | tenancy `setChargeInvoiceReference` | implemented |
| waiveCharge | POST .../charges/{id}/waiver | admin.subscription.adjust | tenancy `waiveCharge` | implemented |
| listChargePayments | GET .../charges/{id}/payments | admin.subscription.read | tenancy `listChargePayments` | implemented |
| recordPayment | POST .../charges/{id}/payments | admin.subscription.manage | tenancy `recordPayment` | implemented |
| reversePayment | POST .../payments/{id}/reversal | admin.subscription.adjust | tenancy `reversePayment` | implemented |
| listLedgerEntries | GET /v1/ledger-lists/{list_kind} | admin.subscription.read | tenancy `listLedgerEntries` | implemented |
| exportLedger | GET /v1/ledger-exports | admin.report.ledger | tenancy `exportLedger` (text/csv; refused if it holds a number or an email) | implemented |
| rejectTaxRegistration | PUT .../tax-registrations/{id}/rejection | admin.registration.verify | tenancy `rejectTaxRegistration` | implemented |
| suspendOrganisation | POST .../suspension | admin.org.lifecycle.approve | identity `getVendorApproval`; tenancy `suspendOrganisation` with the held grant | implemented |
| reinstateOrganisation | POST .../reinstatement | admin.org.lifecycle.approve | identity `getVendorApproval`; tenancy `reinstateOrganisation` with the held grant | implemented |
| closeOrganisation | POST .../closure | admin.org.lifecycle.approve | identity `getVendorApproval`; tenancy `closeOrganisation` with the held grant | implemented |
| listTaxRuleSetMasters | GET /v1/tax-rule-sets | admin.taxrules.manage | billing `listTaxRuleSetMasters` | implemented |
| createTaxRuleSetDraft | POST /v1/tax-rule-sets | admin.taxrules.manage | billing `createTaxRuleSetDraft` | implemented |
| getTaxRuleSetMaster | GET /v1/tax-rule-sets/{id} | admin.taxrules.manage | billing `getTaxRuleSetMaster` | implemented |
| updateTaxRuleSetDraft | PATCH /v1/tax-rule-sets/{id} | admin.taxrules.manage | billing `updateTaxRuleSetDraft` (`If-Match` passes down; a stale tag is 412) | implemented |
| deleteTaxRuleSetDraft | DELETE /v1/tax-rule-sets/{id} | admin.taxrules.manage | billing `deleteTaxRuleSetDraft` | implemented |
| validateTaxRuleSet | POST .../validation | admin.taxrules.manage | billing `validateTaxRuleSet` | implemented |
| signTaxRuleSet | POST .../signature | admin.taxrules.manage | billing `signTaxRuleSet` | implemented |
| publishTaxRuleSet | POST .../publication | admin.taxrules.publish | identity `getVendorApproval`; billing `publishTaxRuleSet` with the held grant | implemented |

Not operations of the contract, also served: `GET /healthz`, `GET /readyz`, and (when `ADMIN_STATIC_DIR` is set) the admin-web build at `/`.

## Upstream operations not used (no admin operation needs them)

| Service | operationId | Why not used |
|---|---|---|
| identity | getSupportSession | The session is held locally; the contract's `getSupportSession` answers from it |

## Approvals (ADR-0005 A2.3, ADR-0014 A1.3)

- The second approver must be a different vendor user with an account older than 7 days; no single-person override exists. Identity enforces the age and the permission; admin refuses the requester early.
- Revoke over quota: the revoke answers 409 `vendor_approval_required`; the staff member files `device_revoke_over_quota` with the device as subject, a second user approves, and the revoke is repeated with `approval_id`. Admin does not file on the staff member's behalf.
- The vendor approval grant (single use, 5 minutes) is held in memory against the approver's session and is never returned to the browser. Approving an executing kind (org_suspend, org_reinstate, org_close; tax_rule_set_publish when the approval record names the rule set in `subject_id`) executes it in the same request and reports `execution: executed` or `refused` with the guard's code. `suspendOrganisation`, `reinstateOrganisation`, `closeOrganisation` and `publishTaxRuleSet` take `approval_id` and are the retry.
- A guard refusal (`open_trading_day`, `not_signed`, lead time) and an unavailable service keep the grant for a retry until it expires; a success or a `grant.*` refusal spends it.
- 409 `approval_not_executable` is answered by this service only, with `reason`: `not_approved` (pending, rejected, cancelled), `lapsed` (expired approval, or the grant lapsed or is not held by this session), `executed` (completed, already executed here, or `grant.used`), `not_approver` (another user approved, or `grant.invalid`), `subject_changed` (the approval's kind or organisation is not this operation's, or `grant.subject_mismatch`).
- Open: identity publishes no operation to issue a fresh grant after the first one lapsed (ADR-0014 A2.5 item 4 says admin asks for one on each call). Until it does, a lapsed grant means a new approval.
- Device revoke over quota executes at approval inside identity (no grant); `revokeOrganisationDevice` with `approval_id` is the retry.
