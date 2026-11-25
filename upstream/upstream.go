// Package upstream is the admin service's only way to reach identity and tenancy. It wraps the
// generated clients (internal/gen) and adds what ADR-0013 V2 requires of every call: the admin
// service token (ServiceTransport) and the vendor user's or support token in Authorization,
// carried in the request context as a Cred. Calls have a timeout, and a call is retried once
// (with jitter) on a transport failure or 502/503/504, only inside the request and always with
// the same Idempotency-Key, so a retry never repeats an effect.
//
// There is no generic pass-through: each operation the panel needs is a named method here.
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/logx"

	"github.com/hostryhq/svc-admin/internal/gen/billing"
	"github.com/hostryhq/svc-admin/internal/gen/identity"
	"github.com/hostryhq/svc-admin/internal/gen/tenancy"
)

// Cred is the per-call authority. Bearer is the vendor access token or the support token; it
// never leaves this process except in the Authorization header of an upstream call.
type Cred struct {
	Bearer  string
	Address string // staff member's network address, for the audit record only
}

type credKey struct{}

// WithCred returns ctx carrying c.
func WithCred(ctx context.Context, c Cred) context.Context {
	return context.WithValue(ctx, credKey{}, c)
}

// Error is a failed upstream call. The body is never copied into logs or into answers other
// than the sanitised Problem.
type Error struct {
	Status      int // upstream HTTP status; 0 for a transport failure
	Problem     apperr.Problem
	RetryAfter  string
	Unavailable bool // transport failure, timeout, 5xx or an unreadable answer
}

func (e *Error) Error() string {
	if e.Unavailable {
		return "upstream unavailable"
	}
	return "upstream refused: " + e.Problem.Code
}

// IsUnavailable reports an upstream that could not answer.
func IsUnavailable(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Unavailable
}

// StatusOf returns the upstream HTTP status of err, or 0.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// Config configures the upstream clients.
type Config struct {
	IdentityURL string
	TenancyURL  string
	BillingURL  string
	Signer      *auth.ServiceSigner
	Timeout     time.Duration
	Base        http.RoundTripper
	// Retries is the number of extra attempts after a retryable failure (default 1).
	Retries int
	// Sleep waits between attempts; tests replace it.
	Sleep func(ctx context.Context, d time.Duration)
}

// Upstream calls identity and tenancy.
type Upstream struct {
	ident   *identity.Client
	ten     *tenancy.Client
	bill    *billing.Client
	retries int
	sleep   func(ctx context.Context, d time.Duration)
	http    []*http.Client
}

// New builds the clients.
func New(cfg Config) (*Upstream, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	retries := cfg.Retries
	if retries == 0 {
		retries = 1
	} else if retries < 0 {
		retries = 0
	}
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
	}
	mk := func(aud string) *http.Client {
		return &http.Client{
			Timeout:       cfg.Timeout,
			Transport:     &auth.ServiceTransport{Base: cfg.Base, Signer: cfg.Signer, Audience: aud},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	ih, th, bh := mk("identity"), mk("tenancy"), mk("billing")
	ic, err := identity.NewClient(strings.TrimRight(cfg.IdentityURL, "/"), identity.WithHTTPClient(ih), identity.WithRequestEditorFn(editor))
	if err != nil {
		return nil, err
	}
	tc, err := tenancy.NewClient(strings.TrimRight(cfg.TenancyURL, "/"), tenancy.WithHTTPClient(th), tenancy.WithRequestEditorFn(editor))
	if err != nil {
		return nil, err
	}
	bc, err := billing.NewClient(strings.TrimRight(cfg.BillingURL, "/"), billing.WithHTTPClient(bh), billing.WithRequestEditorFn(editor))
	if err != nil {
		return nil, err
	}
	return &Upstream{ident: ic, ten: tc, bill: bc, retries: retries, sleep: sleep, http: []*http.Client{ih, th, bh}}, nil
}

// editor adds the caller's credential and the request id to every call.
func editor(ctx context.Context, req *http.Request) error {
	if c, ok := ctx.Value(credKey{}).(Cred); ok {
		if c.Bearer != "" {
			req.Header.Set("Authorization", "Bearer "+c.Bearer)
		}
		if c.Address != "" {
			req.Header.Set("X-Vendor-Client-Address", c.Address)
		}
	}
	if id := logx.RequestID(ctx); id != "" {
		req.Header.Set("X-Request-Id", id)
	}
	return nil
}

// do sends with retry and returns the body of a 2xx answer, or an *Error.
func (u *Upstream) do(ctx context.Context, send func() (*http.Response, error)) ([]byte, error) {
	var (
		resp *http.Response
		err  error
	)
	for attempt := 0; ; attempt++ {
		resp, err = send()
		retryable := err != nil || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504
		if !retryable || attempt >= u.retries || ctx.Err() != nil {
			break
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
		}
		u.sleep(ctx, time.Duration(50+rand.IntN(100))*time.Millisecond)
	}
	if err != nil {
		return nil, &Error{Unavailable: true}
	}
	defer func() { _ = resp.Body.Close() }()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if rerr != nil {
		return nil, &Error{Status: resp.StatusCode, Unavailable: true}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return body, nil
	}
	e := &Error{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
	if resp.StatusCode >= 500 {
		e.Unavailable = true
		return nil, e
	}
	var p apperr.Problem
	if json.Unmarshal(body, &p) != nil || p.Code == "" {
		p = apperr.Problem{Status: resp.StatusCode, Code: "upstream.refused", Title: "Request refused"}
	}
	// Keep only what the browser may see; never an upstream instance path.
	p.Instance, p.RequestID = "", ""
	e.Problem = p
	return nil, e
}

// Decode parses an upstream body into T. A body that does not parse is an unavailable upstream.
func Decode[T any](b []byte, err error) (T, error) {
	var out T
	if err != nil {
		return out, err
	}
	if len(b) == 0 {
		return out, nil
	}
	if jerr := json.Unmarshal(b, &out); jerr != nil {
		return out, &Error{Unavailable: true}
	}
	return out, nil
}

func jsonReader(b []byte) io.Reader { return bytes.NewReader(b) }

const jsonCT = "application/json"

// ---- identity: vendor realm ------------------------------------------------------------

// VendorSignIn delegates email, password and TOTP to identity's vendor realm.
func (u *Upstream) VendorSignIn(ctx context.Context, key string, body []byte) (identity.VendorSession, error) {
	return Decode[identity.VendorSession](u.do(ctx, func() (*http.Response, error) {
		return u.ident.CreateVendorSessionWithBody(ctx, &identity.CreateVendorSessionParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	}))
}

// RenewVendorSession exchanges a renewal handle for a fresh access token.
func (u *Upstream) RenewVendorSession(ctx context.Context, key, handle string) (identity.VendorSession, error) {
	b, _ := json.Marshal(identity.VendorSessionRenewal{RenewalHandle: handle})
	return Decode[identity.VendorSession](u.do(ctx, func() (*http.Response, error) {
		return u.ident.RenewVendorSessionWithBody(ctx, &identity.RenewVendorSessionParams{IdempotencyKey: key}, jsonCT, jsonReader(b))
	}))
}

// EndVendorSession signs the vendor token out.
func (u *Upstream) EndVendorSession(ctx context.Context, key string) error {
	_, err := u.do(ctx, func() (*http.Response, error) {
		return u.ident.EndVendorSession(ctx, &identity.EndVendorSessionParams{IdempotencyKey: key})
	})
	return err
}

// BeginVendorSetup starts account setup from a one-time link.
func (u *Upstream) BeginVendorSetup(ctx context.Context, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.BeginVendorSetupWithBody(ctx, &identity.BeginVendorSetupParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// CompleteVendorSetup finishes account setup.
func (u *Upstream) CompleteVendorSetup(ctx context.Context, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.CompleteVendorSetupWithBody(ctx, &identity.CompleteVendorSetupParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ListVendorUsers lists vendor staff.
func (u *Upstream) ListVendorUsers(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ListVendorUsers(ctx, &identity.ListVendorUsersParams{Cursor: cursor, Limit: limit})
	})
}

// CreateVendorUser creates a vendor user in setup_pending.
func (u *Upstream) CreateVendorUser(ctx context.Context, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.CreateVendorUserWithBody(ctx, &identity.CreateVendorUserParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// UpdateVendorUser changes a role or deactivates.
func (u *Upstream) UpdateVendorUser(ctx context.Context, id, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.UpdateVendorUserWithBody(ctx, id, &identity.UpdateVendorUserParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ResetVendorUserTotp returns a user to setup_pending.
func (u *Upstream) ResetVendorUserTotp(ctx context.Context, id, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ResetVendorUserTotp(ctx, id, &identity.ResetVendorUserTotpParams{IdempotencyKey: key})
	})
}

// AuditFilter selects vendor audit entries.
type AuditFilter struct {
	From, To                             *time.Time
	Actor, Organisation, Action, Support *string
	Cursor                               *string
	Limit                                *int
}

// ListVendorAuditEntries reads the vendor audit log (identity enforces read_own versus read).
func (u *Upstream) ListVendorAuditEntries(ctx context.Context, f AuditFilter) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ListVendorAuditEntries(ctx, &identity.ListVendorAuditEntriesParams{
			From: f.From, To: f.To, ActorVendorUserId: f.Actor, OrganisationId: f.Organisation,
			Action: f.Action, SupportSessionId: f.Support, Cursor: f.Cursor, Limit: f.Limit,
		})
	})
}

// LookupOwnerMobile finds organisation ids by an exact owner mobile number.
func (u *Upstream) LookupOwnerMobile(ctx context.Context, key, mobile string) (identity.OwnerLookupResult, error) {
	b, _ := json.Marshal(identity.OwnerLookup{MobileE164: mobile})
	return Decode[identity.OwnerLookupResult](u.do(ctx, func() (*http.Response, error) {
		return u.ident.LookupOrganisationsByOwnerMobileWithBody(ctx, &identity.LookupOrganisationsByOwnerMobileParams{IdempotencyKey: key}, jsonCT, jsonReader(b))
	}))
}

// OwnerStatuses returns the owner state of up to 100 organisations.
func (u *Upstream) OwnerStatuses(ctx context.Context, orgIDs []string) (identity.OwnerStatusList, error) {
	return Decode[identity.OwnerStatusList](u.do(ctx, func() (*http.Response, error) {
		return u.ident.GetOwnerStatuses(ctx, &identity.GetOwnerStatusesParams{OrganisationIds: strings.Join(orgIDs, ",")})
	}))
}

// ListOwnerInvitations lists an organisation's invitations.
func (u *Upstream) ListOwnerInvitations(ctx context.Context, org string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ListOwnerInvitations(ctx, org, &identity.ListOwnerInvitationsParams{})
	})
}

// CreateOwnerInvitation creates (or re-issues) an owner invitation. The number travels in the body only.
func (u *Upstream) CreateOwnerInvitation(ctx context.Context, org, key string, in identity.CreateOwnerInvitation) ([]byte, error) {
	b, _ := json.Marshal(in)
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.CreateOwnerInvitationWithBody(ctx, org, &identity.CreateOwnerInvitationParams{IdempotencyKey: key}, jsonCT, jsonReader(b))
	})
}

// RenewOwnerInvitation extends a pending invitation.
func (u *Upstream) RenewOwnerInvitation(ctx context.Context, org, inv, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.RenewOwnerInvitation(ctx, org, inv, &identity.RenewOwnerInvitationParams{IdempotencyKey: key})
	})
}

// CancelOwnerInvitation cancels a pending invitation.
func (u *Upstream) CancelOwnerInvitation(ctx context.Context, org, inv, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.CancelOwnerInvitation(ctx, org, inv, &identity.CancelOwnerInvitationParams{IdempotencyKey: key})
	})
}

// ListOrganisationDevices lists an organisation's devices (vendor view).
func (u *Upstream) ListOrganisationDevices(ctx context.Context, org string, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ListOrganisationDevices(ctx, org, &identity.ListOrganisationDevicesParams{Cursor: cursor, Limit: limit})
	})
}

// GetOrganisationDevice reads one device.
func (u *Upstream) GetOrganisationDevice(ctx context.Context, org, device string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.GetOrganisationDevice(ctx, org, device, &identity.GetOrganisationDeviceParams{})
	})
}

// RevokeOrganisationDevice revokes a device on a verified request.
func (u *Upstream) RevokeOrganisationDevice(ctx context.Context, org, device, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.RevokeOrganisationDeviceWithBody(ctx, org, device, &identity.RevokeOrganisationDeviceParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ---- identity: two-person approvals (ADR-0005 A2.3) ------------------------------------

// CreateVendorApproval files an approval request. The body may carry a mobile number and goes
// straight through; it is never logged.
func (u *Upstream) CreateVendorApproval(ctx context.Context, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.CreateVendorApprovalWithBody(ctx, &identity.CreateVendorApprovalParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ListVendorApprovals lists the approvals the vendor user requested or may approve.
func (u *Upstream) ListVendorApprovals(ctx context.Context, state, cursor *string, limit *int) ([]byte, error) {
	p := &identity.ListVendorApprovalsParams{Cursor: cursor, Limit: limit}
	if state != nil {
		st := identity.ListVendorApprovalsParamsState(*state)
		p.State = &st
	}
	return u.do(ctx, func() (*http.Response, error) { return u.ident.ListVendorApprovals(ctx, p) })
}

// GetVendorApproval reads one approval.
func (u *Upstream) GetVendorApproval(ctx context.Context, id string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.GetVendorApproval(ctx, id, &identity.GetVendorApprovalParams{})
	})
}

// ApproveVendorApproval approves with a fresh TOTP. For the executing kinds the answer carries a
// vendor approval grant, which the caller must keep server-side.
func (u *Upstream) ApproveVendorApproval(ctx context.Context, id, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ApproveVendorApprovalWithBody(ctx, id, &identity.ApproveVendorApprovalParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// ClaimCodeHalf claims the requester's half of a sign-in code (shown once).
func (u *Upstream) ClaimCodeHalf(ctx context.Context, id, key string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ClaimCodeHalf(ctx, id, &identity.ClaimCodeHalfParams{IdempotencyKey: key})
	})
}

// CancelVendorApproval rejects or cancels an approval.
func (u *Upstream) CancelVendorApproval(ctx context.Context, id, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.CancelVendorApprovalWithBody(ctx, id, &identity.CancelVendorApprovalParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// StartSupportSession starts a read-only support session and returns its first support token.
func (u *Upstream) StartSupportSession(ctx context.Context, key string, in identity.StartSupportSession) (identity.SupportSessionStarted, error) {
	b, _ := json.Marshal(in)
	return Decode[identity.SupportSessionStarted](u.do(ctx, func() (*http.Response, error) {
		return u.ident.StartSupportSessionWithBody(ctx, &identity.StartSupportSessionParams{IdempotencyKey: key}, jsonCT, jsonReader(b))
	}))
}

// RenewSupportToken re-issues the support token inside the session.
func (u *Upstream) RenewSupportToken(ctx context.Context, session, key string) (identity.SupportToken, error) {
	return Decode[identity.SupportToken](u.do(ctx, func() (*http.Response, error) {
		return u.ident.RenewSupportToken(ctx, session, &identity.RenewSupportTokenParams{IdempotencyKey: key})
	}))
}

// EndSupportSession ends a support session.
func (u *Upstream) EndSupportSession(ctx context.Context, session, key string) error {
	_, err := u.do(ctx, func() (*http.Response, error) {
		return u.ident.EndSupportSession(ctx, session, &identity.EndSupportSessionParams{IdempotencyKey: key})
	})
	return err
}

// ---- identity: ordinary tenant read routes, called with a support token -----------------

// ListMembers reads members with a support token.
func (u *Upstream) ListMembers(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ListMembers(ctx, &identity.ListMembersParams{Cursor: cursor, Limit: limit})
	})
}

// ListRoles reads roles with a support token.
func (u *Upstream) ListRoles(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ListRoles(ctx, &identity.ListRolesParams{Cursor: cursor, Limit: limit})
	})
}

// ListDevices reads devices with a support token.
func (u *Upstream) ListDevices(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ident.ListDevices(ctx, &identity.ListDevicesParams{Cursor: cursor, Limit: limit})
	})
}

// ---- tenancy ---------------------------------------------------------------------------

// ListOrganisationDirectory reads the vendor directory.
func (u *Upstream) ListOrganisationDirectory(ctx context.Context, p tenancy.ListOrganisationDirectoryParams) (tenancy.DirectoryPage, error) {
	return Decode[tenancy.DirectoryPage](u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListOrganisationDirectory(ctx, &p)
	}))
}

// CreateOrganisation runs step one of onboarding (organisation, brand, outlet, registration).
func (u *Upstream) CreateOrganisation(ctx context.Context, key string, in tenancy.CreateOrganisation) ([]byte, error) {
	b, _ := json.Marshal(in)
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.CreateOrganisationWithBody(ctx, &tenancy.CreateOrganisationParams{IdempotencyKey: key}, jsonCT, jsonReader(b))
	})
}

// GetOrganisationDirectoryEntry reads one organisation's directory detail.
func (u *Upstream) GetOrganisationDirectoryEntry(ctx context.Context, org string) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.GetOrganisationDirectoryEntry(ctx, org, &tenancy.GetOrganisationDirectoryEntryParams{})
	})
}

// VerifyTaxRegistration records GSTIN verification.
func (u *Upstream) VerifyTaxRegistration(ctx context.Context, org, reg, key string, body []byte) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.VerifyTaxRegistrationWithBody(ctx, org, reg, &tenancy.VerifyTaxRegistrationParams{IdempotencyKey: key}, jsonCT, jsonReader(body))
	})
}

// GetCurrentOrganisation reads the support token's organisation.
func (u *Upstream) GetCurrentOrganisation(ctx context.Context) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) { return u.ten.GetCurrentOrganisation(ctx) })
}

// ListBrands reads brands with a support token.
func (u *Upstream) ListBrands(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListBrands(ctx, &tenancy.ListBrandsParams{Cursor: cursor, Limit: limit})
	})
}

// ListOutlets reads outlets with a support token.
func (u *Upstream) ListOutlets(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListOutlets(ctx, &tenancy.ListOutletsParams{Cursor: cursor, Limit: limit})
	})
}

// ListTaxRegistrations reads registrations with a support token.
func (u *Upstream) ListTaxRegistrations(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListTaxRegistrations(ctx, &tenancy.ListTaxRegistrationsParams{Cursor: cursor, Limit: limit})
	})
}

// ListDocumentSeries reads document series with a support token.
func (u *Upstream) ListDocumentSeries(ctx context.Context, cursor *string, limit *int) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) {
		return u.ten.ListDocumentSeries(ctx, &tenancy.ListDocumentSeriesParams{Cursor: cursor, Limit: limit})
	})
}

// GetOrganisationSettings reads settings with a support token.
func (u *Upstream) GetOrganisationSettings(ctx context.Context) ([]byte, error) {
	return u.do(ctx, func() (*http.Response, error) { return u.ten.GetOrganisationSettings(ctx) })
}

// Ping checks that a service answers /healthz (readiness).
func (u *Upstream) Ping(ctx context.Context) error {
	for _, c := range []struct {
		name string
		base string
	}{{"identity", u.ident.Server}, {"tenancy", u.ten.Server}, {"billing", u.bill.Server}} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.base, "/")+"/healthz", nil)
		if err != nil {
			return err
		}
		resp, err := u.http[0].Do(req) // any client: the service token is not needed for /healthz
		if err != nil {
			return errors.New(c.name + " unreachable")
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return errors.New(c.name + " not ready")
		}
	}
	return nil
}
