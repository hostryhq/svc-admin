// Package double is the in-memory test double of the admin API for admin-web's tests (and for
// any other caller). It implements the contract in api-specs/openapi/admin/v1 with the spec's own
// examples (extracted by make gen, so it cannot drift) and the browser-visible rules that matter
// to a client: the session cookie, the CSRF token and Origin on state-changing requests, the
// permission of the signed-in role, Idempotency-Key replays, and the problem+json errors.
//
// It is example-driven, not stateful: a list answers its example whatever was created before.
// Failure injection (Fail, Delay, the X-Double-Scenario header) lets a client test its error
// states. Verified by the shared contract suite (api-specs/contracttest) with
// ExpectExamples set; a double that fails the suite is a bug in the double.
package double

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hostryhq/svc-admin/internal/specdata"
)

// Fixed values of the double (all fictional).
const (
	// CookieName is the real service's cookie name.
	CookieName = "__Host-hostry-admin"
	// SeedCookie is a pre-authenticated platform_admin session for tests that do not sign in.
	SeedCookie = "double-seed-session"
	// CSRFToken is the CSRF token of every double session (the spec's example).
	CSRFToken = "csrf_example_token"
	// SeedUserEmail signs in a platform_admin; the example account (staff@example.invalid) is a support role.
	SeedUserEmail = "platform@example.invalid"
)

// Options tune the double.
type Options struct {
	// Origin is the only Origin accepted on a state-changing request. Empty accepts an Origin whose
	// host is the request's Host.
	Origin string
	// StaticHandler, when set, serves everything outside /v1 (the admin-web build).
	StaticHandler http.Handler
	// Now supplies the time for the headers the double sets; default time.Now.
	Now func() time.Time
}

type session struct {
	perms []string
	admin bool
}

type failure struct {
	status  int
	example string
}

type stored struct {
	fp     string
	status int
	ct     string
	body   []byte
}

// Double is the http.Handler.
type Double struct {
	opt Options
	doc *specdata.Doc

	mu       sync.Mutex
	sessions map[string]*session
	n        int
	failures map[string][]failure
	delay    map[string]time.Duration
	replays  map[string]stored
	calls    []Call
}

// Call is one request the double served (for assertions in a client's tests).
type Call struct {
	Op     string
	Status int
}

// New returns a double with the seed session installed.
func New(o Options) *Double {
	d := &Double{
		opt: o, doc: specdata.MustLoad("admin"), sessions: map[string]*session{},
		failures: map[string][]failure{}, delay: map[string]time.Duration{}, replays: map[string]stored{},
	}
	d.sessions[SeedCookie] = &session{perms: allPerms(d.doc), admin: true}
	return d
}

func allPerms(doc *specdata.Doc) []string {
	seen := map[string]bool{}
	var out []string
	for _, op := range doc.Operations {
		perms := []string{op.Permission}
		for _, p := range op.PermissionByKind {
			perms = append(perms, p)
		}
		for _, p := range perms {
			if strings.HasPrefix(p, "admin.") && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// Fail makes the next n calls of op answer with the declared response of status (example "" is the
// default or first one). Use it to drive a client's 4xx, 409 and 503 states.
func (d *Double) Fail(op string, status, n int, example string) {
	d.mu.Lock()
	for i := 0; i < n; i++ {
		d.failures[op] = append(d.failures[op], failure{status, example})
	}
	d.mu.Unlock()
}

// Delay makes every call of op wait.
func (d *Double) Delay(op string, dur time.Duration) {
	d.mu.Lock()
	d.delay[op] = dur
	d.mu.Unlock()
}

// Calls returns what the double served, in order.
func (d *Double) Calls() []Call {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Call(nil), d.calls...)
}

// ServeHTTP implements http.Handler.
func (d *Double) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"ok"}`)
			return
		}
		if d.opt.StaticHandler != nil {
			d.opt.StaticHandler.ServeHTTP(w, r)
			return
		}
		d.problem(w, http.StatusNotFound, "not_found", "Not found")
		return
	}
	if r.Header.Get("Authorization") != "" { // the admin API takes the cookie only
		d.respond(w, r, nil, http.StatusUnauthorized, "")
		return
	}
	op, _, known := d.doc.Match(r.Method, r.URL.Path)
	if op == nil {
		st, code := http.StatusNotFound, "not_found"
		if known {
			st, code = http.StatusMethodNotAllowed, "method_not_allowed"
		}
		d.problem(w, st, code, code)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	d.mu.Lock()
	delay := d.delay[op.ID]
	d.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	mutating := r.Method != http.MethodGet

	// Checks in the real service's order: Origin, session, CSRF, permission.
	if mutating && !d.originOK(r) {
		d.respond(w, r, op, http.StatusForbidden, "csrf")
		return
	}
	var sess *session
	if op.Permission != "public" {
		c, err := r.Cookie(CookieName)
		if err != nil {
			d.respond(w, r, op, http.StatusUnauthorized, "")
			return
		}
		d.mu.Lock()
		sess = d.sessions[c.Value]
		d.mu.Unlock()
		if sess == nil {
			d.respond(w, r, op, http.StatusUnauthorized, "")
			return
		}
		if mutating && r.Header.Get("X-CSRF-Token") != CSRFToken {
			d.respond(w, r, op, http.StatusForbidden, "csrf")
			return
		}
		if !allowed(op, sess) || !kindAllowed(op, sess, body) {
			d.respond(w, r, op, http.StatusForbidden, "forbidden")
			return
		}
	}

	// Scripted failures and the scenario header come before the normal answer.
	if f, ok := d.nextFailure(op.ID); ok {
		d.respond(w, r, op, f.status, f.example)
		return
	}
	if sc := r.Header.Get("X-Double-Scenario"); sc != "" {
		status, ex, _ := strings.Cut(sc, ":")
		if st, err := strconv.Atoi(status); err == nil {
			d.respond(w, r, op, st, ex)
			return
		}
	}

	key := r.Header.Get("Idempotency-Key")
	if mutating && op.ID != "signOut" {
		if key == "" || len(key) > 128 {
			d.problem(w, http.StatusUnprocessableEntity, "idempotency.key_invalid", "Idempotency-Key is required")
			return
		}
		if d.replay(w, op.ID, key, r, body) {
			return
		}
	}
	d.success(w, r, op, key, body)
}

func allowed(op *specdata.Operation, s *session) bool {
	switch op.Permission {
	case "authenticated", "public":
		return true
	case "admin.audit.read_own":
		return has(s, "admin.audit.read_own") || has(s, "admin.audit.read")
	}
	return has(s, op.Permission)
}

// kindAllowed applies x-permission-by-kind: the approval kind named in the request body (filing),
// or the kind of the operation's own example approval (the double is not stateful), needs its own
// permission on top of the gate permission.
func kindAllowed(op *specdata.Operation, s *session, body []byte) bool {
	if len(op.PermissionByKind) == 0 {
		return true
	}
	var in struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(body, &in)
	kind := in.Kind
	if kind == "" {
		if ex, ok := op.Success().Example(""); ok {
			m, _ := ex.(map[string]any)
			ap, _ := m["approval"].(map[string]any)
			kind, _ = ap["kind"].(string)
		}
	}
	perm, ok := op.PermissionByKind[kind]
	if !ok {
		return true // an unknown kind is a validation answer, not a permission one
	}
	return has(s, perm)
}

// SeedWorld puts the double into an example world of the contract (info.x-example-worlds). The
// double answers the spec's examples whatever the world, so seeding only checks that the world is
// declared and forgets earlier idempotent replays and scripted failures, like a fresh fixture.
func (d *Double) SeedWorld(_ context.Context, world string) error {
	known := false
	for _, w := range d.doc.Worlds {
		known = known || w == world
	}
	if !known {
		return fmt.Errorf("double: unknown example world %q", world)
	}
	d.mu.Lock()
	d.replays = map[string]stored{}
	d.failures = map[string][]failure{}
	d.mu.Unlock()
	return nil
}

func has(s *session, p string) bool {
	for _, x := range s.perms {
		if x == p {
			return true
		}
	}
	return false
}

func (d *Double) originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	if d.opt.Origin != "" {
		return strings.EqualFold(strings.TrimRight(o, "/"), strings.TrimRight(d.opt.Origin, "/"))
	}
	return strings.HasSuffix(strings.ToLower(o), "://"+strings.ToLower(r.Host))
}

func (d *Double) nextFailure(op string) (failure, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	q := d.failures[op]
	if len(q) == 0 {
		return failure{}, false
	}
	d.failures[op] = q[1:]
	return q[0], true
}

func (d *Double) success(w http.ResponseWriter, r *http.Request, op *specdata.Operation, key string, body []byte) {
	switch op.ID {
	case "signIn":
		if !d.signIn(w, r, op, body) {
			return
		}
	case "signOut":
		if c, err := r.Cookie(CookieName); err == nil && c.Value != SeedCookie {
			d.mu.Lock()
			delete(d.sessions, c.Value)
			d.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	s := op.Success()
	rec := &recorder{ResponseWriter: w, status: s.Status}
	s.Write(rec, "")
	d.note(op.ID, s.Status)
	if key != "" && r.Method != http.MethodGet && op.ID != "signOut" {
		d.mu.Lock()
		d.replays[op.ID+"\x00"+key] = stored{fp: fp(r, body), status: s.Status, ct: s.ContentType, body: rec.buf}
		d.mu.Unlock()
	}
}

// signIn accepts the spec's example account (a support role, answering the example verbatim) and
// the platform_admin seed account. It sets the session cookie; any other credentials are 401.
func (d *Double) signIn(w http.ResponseWriter, r *http.Request, op *specdata.Operation, body []byte) bool {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTP     string `json:"totp_code"`
	}
	_ = json.Unmarshal(body, &in)
	ex, _ := op.Success().Example("")
	exm, _ := ex.(map[string]any)
	user, _ := exm["user"].(map[string]any)
	var perms []string
	if p, ok := user["permissions"].([]any); ok {
		for _, x := range p {
			if s, ok := x.(string); ok {
				perms = append(perms, s)
			}
		}
	}
	switch {
	case in.Email == "staff@example.invalid" && in.Password == "correct-horse-battery-staple" && in.TOTP == "123456":
	case in.Email == SeedUserEmail && in.Password == "correct-horse-battery-staple" && in.TOTP == "123456":
		perms = allPerms(d.doc)
	default:
		d.respond(w, r, op, http.StatusUnauthorized, "")
		return false
	}
	d.mu.Lock()
	d.n++
	id := "double-session-" + strconv.Itoa(d.n)
	d.sessions[id] = &session{perms: perms}
	d.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return true
}

func fp(r *http.Request, body []byte) string { return r.Method + " " + r.URL.Path + " " + string(body) }

func (d *Double) replay(w http.ResponseWriter, op, key string, r *http.Request, body []byte) bool {
	d.mu.Lock()
	s, ok := d.replays[op+"\x00"+key]
	d.mu.Unlock()
	if !ok {
		return false
	}
	if s.fp != fp(r, body) {
		d.problem(w, http.StatusUnprocessableEntity, "idempotency.mismatch", "Idempotency-Key reused with a different request")
		return true
	}
	w.Header().Set("Idempotent-Replayed", "true")
	if s.ct != "" {
		w.Header().Set("Content-Type", s.ct)
	}
	w.WriteHeader(s.status)
	_, _ = w.Write(s.body)
	return true
}

// respond writes a declared response (a refusal or a scripted one). With no op, a bare 401.
func (d *Double) respond(w http.ResponseWriter, r *http.Request, op *specdata.Operation, status int, example string) {
	if op != nil {
		if resp, ok := op.Response(status); ok {
			resp.Write(w, example)
			d.note(op.ID, status)
			return
		}
	}
	code := map[int]string{401: "auth.invalid_token", 403: "forbidden", 404: "not_found", 409: "conflict", 422: "validation", 429: "rate_limited", 503: "upstream_unavailable"}[status]
	if code == "" {
		code = "error"
	}
	d.problem(w, status, code, code)
}

func (d *Double) problem(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:hostry:problem:" + code, "title": title, "status": status, "code": code})
}

func (d *Double) note(op string, status int) {
	d.mu.Lock()
	d.calls = append(d.calls, Call{Op: op, Status: status})
	d.mu.Unlock()
}

// recorder captures the body written so a replay can serve it.
type recorder struct {
	http.ResponseWriter
	status int
	buf    []byte
}

func (r *recorder) Write(b []byte) (int, error) {
	r.buf = append(r.buf, b...)
	return r.ResponseWriter.Write(b)
}
