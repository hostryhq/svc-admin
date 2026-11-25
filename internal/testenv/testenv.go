// Package testenv assembles the admin service against in-process fakes of identity and tenancy
// (internal/fakeup, generated from their OpenAPI documents) with real go-auth token verification
// on the fakes' side. Tests and the contract run use it. Nothing here is a secret: keys are
// generated per run.
package testenv

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/testkit"

	"github.com/hostryhq/svc-admin/api"
	"github.com/hostryhq/svc-admin/internal/fakeup"
	"github.com/hostryhq/svc-admin/internal/specdata"
	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/service"
	"github.com/hostryhq/svc-admin/upstream"
)

// The example ids and credentials of the contract (never real ones).
const (
	UserID   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a66"
	OrgID    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60"
	Email    = "staff@example.invalid"
	Password = "correct-horse-battery-staple"
	TOTP     = "123456"
)

// User is a vendor user known to the fake identity.
type User struct {
	ID          string
	Email       string
	DisplayName string
	Role        string
	Permissions []string
	Deactivated bool
}

type vendorSession struct {
	user string
	ends time.Time
}

type supportSession struct {
	id, org, user, ticket string
	ends                  time.Time
	ended                 bool
}

// Env is the whole world of one test.
type Env struct {
	T        testing.TB
	Clock    *testkit.FakeClock
	Registry *authtest.ServiceRegistry
	VendorIs *authtest.Issuer
	TenantIs *authtest.Issuer
	Identity *fakeup.Fake
	Tenancy  *fakeup.Fake
	Sessions *repository.MemorySessions
	Svc      *service.Service
	API      *api.Handler
	Handler  http.Handler
	Server   *httptest.Server
	Origin   string

	// VendorTTL and SupportTTL are the lifetimes of the access tokens the fake identity issues.
	VendorTTL  time.Duration
	SupportTTL time.Duration

	mu       sync.Mutex
	users    map[string]*User
	handles  map[string]vendorSession
	support  map[string]*supportSession
	seq      int
	keyCount int
}

// Options tune the environment.
type Options struct {
	Service service.Config
	// StaticDir is served at /.
	StaticDir string
}

// AllAdminPermissions is every admin.* permission the contracts mention (a platform_admin).
func AllAdminPermissions() []string {
	set := map[string]bool{}
	for _, s := range []string{"admin", "identity", "tenancy"} {
		for _, op := range specdata.MustLoad(s).Operations {
			if strings.HasPrefix(op.Permission, "admin.") {
				set[op.Permission] = true
			}
			for _, p := range op.PermissionByKind {
				if strings.HasPrefix(p, "admin.") {
					set[p] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// New builds the environment and registers cleanup.
func New(t testing.TB, o ...Options) *Env {
	t.Helper()
	var opt Options
	if len(o) > 0 {
		opt = o[0]
	}
	clk := testkit.NewClock()
	clk.Set(time.Date(2026, 11, 24, 13, 6, 0, 0, time.UTC)) // inside the spec examples' day
	reg := authtest.NewServiceRegistry(clk, "admin", "identity", "tenancy")
	e := &Env{
		T: t, Clock: clk, Registry: reg,
		VendorIs: authtest.NewVendorIssuer(clk), TenantIs: authtest.NewTenantIssuer(clk),
		Sessions:  repository.NewMemorySessions(),
		VendorTTL: 10 * time.Minute, SupportTTL: 10 * time.Minute,
		users: map[string]*User{}, handles: map[string]vendorSession{}, support: map[string]*supportSession{},
	}
	e.AddUser(User{ID: UserID, Email: Email, DisplayName: "Priya", Role: "platform_admin", Permissions: AllAdminPermissions()})
	mk := func(svc string) *fakeup.Fake {
		return fakeup.New(svc, fakeup.Verifiers{Service: reg.Verifier(svc), Vendor: e.VendorIs.Verifier(), Tenant: e.TenantIs.Verifier()})
	}
	e.Identity, e.Tenancy = mk("identity"), mk("tenancy")
	e.scriptIdentity()
	e.scriptSupportGuards()
	t.Cleanup(func() { e.Identity.Close(); e.Tenancy.Close() })

	up, err := upstream.New(upstream.Config{
		IdentityURL: e.Identity.URL(), TenancyURL: e.Tenancy.URL(), Signer: reg.Signer("admin"),
		Timeout: 2 * time.Second, Retries: 1,
		Sleep: func(_ context.Context, _ time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.Svc = service.New(opt.Service, service.Deps{Upstream: up, Sessions: e.Sessions, Clock: clk, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})

	// The server's own URL is the public origin, so a real HTTP client (the contract harness) is
	// "same origin". The handler is wired after the URL is known.
	inner := http.NotFoundHandler()
	var imu sync.RWMutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		imu.RLock()
		h := inner
		imu.RUnlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	e.Server, e.Origin = srv, srv.URL
	e.API = api.New(api.Options{
		Service: e.Svc, PublicOrigin: e.Origin, StaticDir: opt.StaticDir, Clock: clk,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	e.Handler = e.API.Routes()
	imu.Lock()
	inner = e.Handler
	imu.Unlock()
	return e
}

// AddUser registers a vendor user in the fake identity.
func (e *Env) AddUser(u User) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := u
	e.users[u.Email] = &cp
}

// Deactivate marks a user deactivated in the fake identity: renewals and sign-ins are refused.
func (e *Env) Deactivate(userID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, u := range e.users {
		if u.ID == userID {
			u.Deactivated = true
		}
	}
}

func (e *Env) next(prefix string) string {
	e.seq++
	return prefix + strconv.Itoa(e.seq)
}

func principal(u *User) map[string]any {
	return map[string]any{"id": u.ID, "display_name": u.DisplayName, "role": u.Role, "permissions": u.Permissions}
}

func (e *Env) issueVendor(u *User, ends time.Time) map[string]any {
	sid := e.next("vs-")
	tok := e.VendorIs.Mint(authtest.Spec{Type: auth.TypeUser, Subject: u.ID, Session: sid, TTL: e.VendorTTL})
	handle := e.next("renew-")
	e.handles[handle] = vendorSession{user: u.Email, ends: ends}
	return map[string]any{
		"access_token": tok, "expires_at": e.Clock.Now().Add(e.VendorTTL).UTC().Format(time.RFC3339Nano),
		"renewal_handle": handle, "session_ends_at": ends.UTC().Format(time.RFC3339Nano), "user": principal(u),
	}
}

func (e *Env) scriptIdentity() {
	e.Identity.On("createVendorSession", func(c fakeup.Call, w http.ResponseWriter) bool {
		var in struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			TotpCode string `json:"totp_code"`
		}
		_ = c.JSON(&in)
		e.mu.Lock()
		defer e.mu.Unlock()
		u := e.users[in.Email]
		if u == nil || u.Deactivated || in.Password != Password || in.TotpCode != TOTP {
			fakeup.Problem(w, http.StatusUnauthorized, "vendor.sign_in_failed")
			return true
		}
		fakeup.WriteJSON(w, http.StatusCreated, e.issueVendor(u, e.Clock.Now().Add(12*time.Hour)))
		return true
	})
	e.Identity.On("renewVendorSession", func(c fakeup.Call, w http.ResponseWriter) bool {
		var in struct {
			Handle string `json:"renewal_handle"`
		}
		_ = c.JSON(&in)
		e.mu.Lock()
		defer e.mu.Unlock()
		vs, ok := e.handles[in.Handle]
		delete(e.handles, in.Handle) // a handle works once
		u := e.users[vs.user]
		if !ok || u == nil || u.Deactivated || !e.Clock.Now().Before(vs.ends) {
			fakeup.Problem(w, http.StatusUnauthorized, "vendor.sign_in_failed")
			return true
		}
		fakeup.WriteJSON(w, http.StatusOK, e.issueVendor(u, vs.ends))
		return true
	})
	e.Identity.On("updateVendorUser", func(c fakeup.Call, w http.ResponseWriter) bool {
		var in struct {
			Status string `json:"status"`
		}
		_ = c.JSON(&in)
		id := idFromPath(c.Path, "users")
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, u := range e.users {
			if u.ID == id {
				u.Deactivated = u.Deactivated || in.Status == "deactivated"
			}
		}
		return false // the spec example is the answer
	})
	e.Identity.On("startSupportSession", func(c fakeup.Call, w http.ResponseWriter) bool {
		var in struct {
			Org      string `json:"organisation_id"`
			Ticket   string `json:"ticket_reference"`
			Duration int    `json:"duration_minutes"`
		}
		_ = c.JSON(&in)
		if in.Duration == 0 {
			in.Duration = 30
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		user := c.Bearer.Subject
		for _, s := range e.support {
			if s.user == user && !s.ended && e.Clock.Now().Before(s.ends) {
				fakeup.Problem(w, http.StatusConflict, "support_session_active")
				return true
			}
		}
		s := &supportSession{id: ids.New().String(), org: in.Org, user: user, ticket: in.Ticket, ends: e.Clock.Now().Add(time.Duration(in.Duration) * time.Minute)}
		e.support[s.id] = s
		fakeup.WriteJSON(w, http.StatusCreated, map[string]any{
			"session": e.supportJSON(s),
			"token":   map[string]any{"access_token": e.supportToken(s), "expires_at": e.Clock.Now().Add(e.SupportTTL).UTC().Format(time.RFC3339Nano)},
		})
		return true
	})
	e.Identity.On("renewSupportToken", func(c fakeup.Call, w http.ResponseWriter) bool {
		id := idFromPath(c.Path, "support-sessions")
		e.mu.Lock()
		defer e.mu.Unlock()
		s := e.support[id]
		if s == nil || s.ended || !e.Clock.Now().Before(s.ends) {
			fakeup.Problem(w, http.StatusConflict, "support_session_ended")
			return true
		}
		fakeup.WriteJSON(w, http.StatusCreated, map[string]any{"access_token": e.supportToken(s), "expires_at": e.Clock.Now().Add(e.SupportTTL).UTC().Format(time.RFC3339Nano)})
		return true
	})
	e.Identity.On("endSupportSession", func(c fakeup.Call, w http.ResponseWriter) bool {
		id := idFromPath(c.Path, "support-sessions")
		e.mu.Lock()
		defer e.mu.Unlock()
		s := e.support[id]
		if s == nil {
			fakeup.Problem(w, http.StatusNotFound, "not_found")
			return true
		}
		s.ended = true
		fakeup.WriteJSON(w, http.StatusOK, e.supportJSON(s))
		return true
	})
}

func idFromPath(p, after string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range parts {
		if s == after && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func (e *Env) supportToken(s *supportSession) string {
	return e.TenantIs.Mint(authtest.Spec{
		Type: auth.TypeSupport, Tenant: ids.ID(s.org), Subject: "support:" + s.user, Session: s.id,
		Mode: auth.ModeView, Ticket: s.ticket, TTL: e.SupportTTL,
		Grants: authtest.Grants(nil, "organisation.read", "member.read"),
	})
}

func (e *Env) supportJSON(s *supportSession) map[string]any {
	status := "active"
	m := map[string]any{
		"id": s.id, "organisation_id": s.org, "vendor_user_id": s.user, "mode": "view",
		"ticket_reference": s.ticket, "started_at": e.Clock.Now().UTC().Format(time.RFC3339Nano),
		"ends_at": s.ends.UTC().Format(time.RFC3339Nano),
	}
	if s.ended {
		status = "ended"
		m["ended_at"] = e.Clock.Now().UTC().Format(time.RFC3339Nano)
	}
	m["status"] = status
	return m
}

// scriptSupportGuards makes the nine support-view source routes refuse a support token whose
// session identity has ended, like the real services.
func (e *Env) scriptSupportGuards() {
	guard := func(c fakeup.Call, w http.ResponseWriter) bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		if c.Bearer == nil || c.Bearer.Type != auth.TypeSupport {
			fakeup.Problem(w, http.StatusUnauthorized, "auth.invalid_token")
			return true
		}
		s := e.support[c.Bearer.SessionID]
		if s == nil || s.ended || !e.Clock.Now().Before(s.ends) {
			fakeup.Problem(w, http.StatusUnauthorized, "auth.invalid_token")
			return true
		}
		return false // fall back to the spec example
	}
	for _, op := range []string{"listMembers", "listRoles", "listDevices"} {
		e.Identity.On(op, guard)
	}
	for _, op := range []string{"getCurrentOrganisation", "listBrands", "listOutlets", "listTaxRegistrations", "listDocumentSeries", "getOrganisationSettings"} {
		e.Tenancy.On(op, guard)
	}
}

// EndSupportAtIdentity ends every active support session at the fake identity, as identity
// would when the time is up or a vendor user is deactivated.
func (e *Env) EndSupportAtIdentity() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.support {
		s.ended = true
	}
}

// ---- requests ------------------------------------------------------------------------------

// Session is a signed-in browser: the cookie value and the CSRF token.
type Session struct {
	Cookie string
	CSRF   string
}

// Opt adjusts a request.
type Opt func(*http.Request)

// WithHeader sets a header.
func WithHeader(k, v string) Opt { return func(r *http.Request) { r.Header.Set(k, v) } }

// WithoutHeader removes a header.
func WithoutHeader(k string) Opt { return func(r *http.Request) { r.Header.Del(k) } }

// WithKey sets the Idempotency-Key.
func WithKey(k string) Opt { return WithHeader("Idempotency-Key", k) }

// Request sends a request straight into the handler (no network). A state-changing request gets
// the Origin, a fresh Idempotency-Key and, with a session, the CSRF token, unless an Opt changes them.
func (e *Env) Request(method, path string, body any, s *Session, opts ...Opt) *httptest.ResponseRecorder {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.T.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = "203.0.113.7:4242"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		r.Header.Set("Origin", e.Origin)
		e.mu.Lock()
		e.keyCount++
		r.Header.Set("Idempotency-Key", "key-"+strconv.Itoa(e.keyCount))
		e.mu.Unlock()
	}
	if s != nil {
		r.AddCookie(&http.Cookie{Name: api.CookieName, Value: s.Cookie})
		if method != http.MethodGet && method != http.MethodHead {
			r.Header.Set(api.CSRFHeader, s.CSRF)
		}
	}
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	e.Handler.ServeHTTP(rec, r)
	return rec
}

// SignIn signs the default vendor user in through the API and returns the browser's session.
func (e *Env) SignIn() *Session { return e.SignInAs(Email) }

// SignInAs signs in a registered user (password and TOTP are the contract examples).
func (e *Env) SignInAs(email string) *Session {
	e.T.Helper()
	rec := e.Request(http.MethodPost, "/v1/sessions", map[string]string{"email": email, "password": Password, "totp_code": TOTP}, nil)
	if rec.Code != http.StatusCreated {
		e.T.Fatalf("sign-in: status %d: %s", rec.Code, rec.Body.String())
	}
	var v struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		e.T.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == api.CookieName {
			return &Session{Cookie: c.Value, CSRF: v.CSRF}
		}
	}
	e.T.Fatal("sign-in set no session cookie")
	return nil
}

// StartSupport starts a support session for the example organisation and returns its id.
func (e *Env) StartSupport(s *Session, org string) string {
	e.T.Helper()
	rec := e.Request(http.MethodPost, "/v1/support-sessions", map[string]any{
		"organisation_id": org, "ticket_reference": "SUP-2041", "reason": "Owner phoned to report a lost tablet.", "duration_minutes": 30, "mode": "view",
	}, s)
	if rec.Code != http.StatusCreated {
		e.T.Fatalf("start support: status %d: %s", rec.Code, rec.Body.String())
	}
	var v struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	return v.Session.ID
}
