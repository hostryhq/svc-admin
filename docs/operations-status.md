# Operations status

Every operationId of `api-specs/openapi/admin/v1` (the contract admin-web calls) and what `svc-admin` calls on identity and tenancy.
Contract commit: see `internal/gen/API_SPECS_COMMIT`. Updated whenever an operation changes.

## Admin API (served): 39 of 39 implemented

"Upstream" is the generated-client call the operation is built on; every upstream call carries the `admin` service token plus the vendor user's token (or the support token for support-view reads).

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
| approveVendorApproval | PUT /v1/approvals/{id}/decision | admin.approval.decide, then the kind's approve permission | identity `getVendorApproval` (kind and requester), `approveVendorApproval`; refuses the requester as approver (409 `second_approver_unavailable`); the grant of org_suspend, org_reinstate, org_close and tax_rule_set_publish is kept in the session, never returned | implemented |
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

Not operations of the contract, also served: `GET /healthz`, `GET /readyz`, and (when `ADMIN_STATIC_DIR` is set) the admin-web build at `/`.

## Upstream operations not used (no admin operation needs them)

| Service | operationId | Why not used |
|---|---|---|
| identity | getSupportSession | The session is held locally; the contract's `getSupportSession` answers from it |

## Approvals (ADR-0005 A2.3, ADR-0014 A1.3)

- The second approver must be a different vendor user with an account older than 7 days; no single-person override exists. Identity enforces the age and the permission; admin refuses the requester early.
- Revoke over quota: the revoke answers 409 `vendor_approval_required`; the staff member files `device_revoke_over_quota` with the device as subject, a second user approves, and the revoke is repeated with `approval_id`. Admin does not file on the staff member's behalf.
- The vendor approval grant (single use, 5 minutes) is held in memory against the approver's session (`Service.TakeGrant`). No admin operation executes org_suspend, org_reinstate, org_close or tax_rule_set_publish yet because tenancy and billing publish no such operation at the pinned contract commit.
