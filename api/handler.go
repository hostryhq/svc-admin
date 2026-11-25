// Package api is the browser-facing HTTP layer of the admin service (controller layer): the
// session cookie, the CSRF and Origin checks, request decoding, the deny list on every answer and
// the mapping of errors to RFC 9457 problems. It contains no business rules; those are in service.
//
// It accepts the session cookie only: a bearer token of any realm is refused, CORS is off, and no
// token of any kind is ever written to a response, a cookie or a log line.
package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"

	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/service"
)

// CookieName is the session cookie. The __Host- prefix makes browsers require Secure, Path=/
// and no Domain.
const CookieName = "__Host-hostry-admin"

// CSRFHeader carries the per-session CSRF token on every state-changing request.
const CSRFHeader = "X-CSRF-Token"

const maxBody = 1 << 20

// Options configure a Handler.
type Options struct {
	Service *service.Service
	// PublicOrigin is the one origin admin-web and the API share, for example
	// https://admin.example.com. A state-changing request must carry exactly this Origin.
	PublicOrigin string
	// ClientIPHeader names a header set by a trusted proxy (for example X-Forwarded-For) whose last
	// value is the staff member's address. Empty means the connection's remote address.
	ClientIPHeader string
	// StaticDir, when set, is the admin-web build served from the same origin.
	StaticDir string
	// Ready are readiness checks for /readyz (identity and tenancy reachable).
	Ready map[string]func(ctx context.Context) error
	// Idempotency stores replays inside a session; default is a 30 minute in-memory store.
	Idempotency idempotency.Store
	Clock       clock.Clock
	Log         *slog.Logger
}

// Handler implements the admin API (admin.ServerInterface).
type Handler struct {
	svc            *service.Service
	origin         string
	clientIPHeader string
	staticDir      string
	ready          map[string]func(ctx context.Context) error
	idem           idempotency.Store
	log            *slog.Logger
}

// New builds the Handler.
func New(o Options) *Handler {
	h := &Handler{
		svc: o.Service, origin: strings.TrimRight(strings.ToLower(o.PublicOrigin), "/"),
		clientIPHeader: o.ClientIPHeader, staticDir: o.StaticDir, ready: o.Ready, idem: o.Idempotency, log: o.Log,
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.idem == nil {
		clk := o.Clock
		if clk == nil {
			clk = clock.System
		}
		h.idem = repository.NewIdempotencyStore(o.Service.Config().IdleTimeout, clk)
	}
	return h
}

// ---- guard ---------------------------------------------------------------------------------

type access struct {
	public   bool     // no session needed (sign-in, account setup)
	mutating bool     // state-changing: Origin and, with a session, the CSRF token
	perms    []string // any of these (empty: just signed in)
}

// req is one admitted request.
type req struct {
	w    http.ResponseWriter
	r    *http.Request
	sess *repository.Session
	body []byte
	key  string
}

func (h *Handler) originOK(r *http.Request) bool {
	o := strings.TrimRight(strings.ToLower(r.Header.Get("Origin")), "/")
	return o != "" && o == h.origin
}

var errCSRF = apperr.New(apperr.Forbidden, "csrf_failed", "")

// admit runs the checks every operation shares, in order: Origin (state-changing), session
// (idle and absolute limits), CSRF token (state-changing), permission, then reads the body.
// It writes the refusal itself and returns false.
func (h *Handler) admit(w http.ResponseWriter, r *http.Request, a access) (*req, bool) {
	q := &req{w: w, r: r}
	if a.mutating && !h.originOK(r) {
		h.fail(w, r, errCSRF)
		return nil, false
	}
	if !a.public {
		c, err := r.Cookie(CookieName)
		if err != nil || c.Value == "" {
			h.fail(w, r, service.ErrUnauthenticated)
			return nil, false
		}
		sess, err := h.svc.Authenticate(c.Value)
		if err != nil {
			h.clearCookie(w)
			h.fail(w, r, err)
			return nil, false
		}
		q.sess = sess
		if a.mutating && !constantEq(r.Header.Get(CSRFHeader), sess.CSRF) {
			h.fail(w, r, errCSRF)
			return nil, false
		}
		if len(a.perms) > 0 && !h.svc.CanAny(sess, a.perms...) {
			h.fail(w, r, service.Forbidden())
			return nil, false
		}
	}
	if a.mutating {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			h.fail(w, r, apperr.New(apperr.Validation, "validation", "request body too large or unreadable"))
			return nil, false
		}
		q.body = b
	}
	// The staff member's address travels in the context, to be passed down for the audit record.
	q.r = r.WithContext(service.WithAddress(r.Context(), h.clientAddr(r)))
	return q, true
}

func (h *Handler) clientAddr(r *http.Request) string {
	raw := r.RemoteAddr
	if h.clientIPHeader != "" {
		if v := r.Header.Get(h.clientIPHeader); v != "" {
			parts := strings.Split(v, ",")
			raw = strings.TrimSpace(parts[len(parts)-1])
		}
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return ap.Addr().String()
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return a.String()
	}
	return ""
}

func (h *Handler) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func (h *Handler) setCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: sessionID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// ---- operation runners ---------------------------------------------------------------------

// outcome is what an operation's body returns.
type outcome struct {
	status int
	v      any
	scrub  scrubOpts
	// noStore keeps the answer out of the idempotency store, so replaying the same key re-runs the
	// operation (an onboarding that ended "incomplete" is completed by replaying it).
	noStore bool
	// csv, when set, is the whole answer (text/csv); it passes the deny list as text.
	csv []byte
}

// read runs a GET: admit, run, answer.
func (h *Handler) read(w http.ResponseWriter, r *http.Request, a access, fn func(q *req) (outcome, error)) {
	q, ok := h.admit(w, r, a)
	if !ok {
		return
	}
	o, err := fn(q)
	if err != nil {
		h.fail(w, q.r, err)
		return
	}
	if o.csv != nil {
		h.write(w, h.renderCSV(q.r, o.status, o.csv))
		return
	}
	h.write(w, h.renderJSON(q.r, o.status, o.v, o.scrub))
}

var idRe = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[0-9A-HJKMNP-TV-Z]{26})$`)

// mutate runs a state-changing operation under its Idempotency-Key: a replay of the same key and
// request inside the session returns the stored answer; the same key with another request is
// refused; a server error, rate limit or refused session is not stored.
func (h *Handler) mutate(w http.ResponseWriter, r *http.Request, a access, fn func(q *req) (outcome, error)) {
	q, ok := h.admit(w, r, a)
	if !ok {
		return
	}
	key, present, err := idempotency.KeyFromRequest(q.r)
	if err != nil || !present {
		h.fail(w, q.r, idempotency.ErrKeyInvalid)
		return
	}
	q.key = key
	h.runIdempotent(q, a.public, fn)
}

func (h *Handler) runIdempotent(q *req, public bool, fn func(q *req) (outcome, error)) {
	scope := ids.ID("public")
	if !public && q.sess != nil {
		scope = ids.ID("s:" + q.sess.ID)
	}
	fp := idempotency.Fingerprint(q.r.Method, q.r.URL.Path, q.body)
	resp, replayed, err := idempotency.Do(q.r.Context(), h.idem, scope, q.key, fp, func() (idempotency.Response, error) {
		o, ferr := fn(q)
		var out rendered
		if ferr != nil {
			out = h.renderError(q.r, ferr)
		} else {
			out = h.renderJSON(q.r, o.status, o.v, o.scrub)
		}
		if !out.cacheable() || o.noStore {
			return idempotency.Response{}, uncached{out}
		}
		return out.response(), nil
	})
	var u uncached
	switch {
	case err == nil:
		if replayed {
			q.w.Header().Set("Idempotent-Replayed", "true")
		}
		if resp.ContentType != "" {
			q.w.Header().Set("Content-Type", resp.ContentType)
		}
		q.w.WriteHeader(resp.Status)
		if len(resp.Body) > 0 {
			_, _ = q.w.Write(resp.Body)
		}
	case asUncached(err, &u):
		h.write(q.w, u.r)
	default:
		h.fail(q.w, q.r, err)
	}
}

func asUncached(err error, u *uncached) bool {
	if e, ok := err.(uncached); ok {
		*u = e
		return true
	}
	return false
}
