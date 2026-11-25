// Package fakeup is an in-process fake of an upstream service (identity or tenancy) generated from
// its OpenAPI document: it routes by the spec's paths, answers with the spec's examples, and can be
// scripted per operation. It checks the credentials ADR-0013 V2 requires on every call (the admin
// service token and, per the operation's security, a vendor or support token) with the real
// go-auth verifiers, so a call made without them is refused exactly as the real service would.
// Tests and doubles only.
package fakeup

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	auth "github.com/hostryhq/go-auth"

	"github.com/hostryhq/svc-admin/internal/specdata"
)

// Call is one request the fake received.
type Call struct {
	Op     string
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
	// ServiceCaller is the iss of the verified service token, empty when none came.
	ServiceCaller string
	// Bearer is the verified bearer claims, nil when none came or it was refused.
	Bearer *auth.Claims
}

// JSON decodes the body of the call into v.
func (c Call) JSON(v any) error { return json.Unmarshal(c.Body, v) }

// Handler answers a call. Return false to fall back to the spec example.
type Handler func(c Call, w http.ResponseWriter) bool

// Verifiers are what the fake checks credentials with.
type Verifiers struct {
	Service *auth.ServiceVerifier // service tokens; the fake's own name is its audience
	Vendor  *auth.Verifier        // vendor-realm access tokens
	Tenant  *auth.Verifier        // tenant-realm tokens, including support tokens
}

// Fake is a fake upstream service.
type Fake struct {
	Server *httptest.Server

	doc *specdata.Doc
	v   Verifiers

	mu       sync.Mutex
	calls    []Call
	handlers map[string]Handler
	failures map[string][]failure
	delay    map[string]time.Duration
	replays  map[string]stored
}

type failure struct {
	status    int
	example   string
	transport bool
}

type stored struct {
	fp     string
	status int
	ct     string
	body   []byte
}

// New starts a fake of service ("identity" or "tenancy").
func New(service string, v Verifiers) *Fake {
	f := &Fake{
		doc: specdata.MustLoad(service), v: v,
		handlers: map[string]Handler{}, failures: map[string][]failure{},
		delay: map[string]time.Duration{}, replays: map[string]stored{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// URL is the base URL of the fake.
func (f *Fake) URL() string { return f.Server.URL }

// Close stops the fake.
func (f *Fake) Close() { f.Server.Close() }

// On scripts an operation.
func (f *Fake) On(op string, h Handler) {
	f.mu.Lock()
	f.handlers[op] = h
	f.mu.Unlock()
}

// FailNext makes the next n calls of op answer with the spec's response of that status
// (example "" is the first one declared). The failure is consumed per call, before any handler.
func (f *Fake) FailNext(op string, status, n int, example string) {
	f.mu.Lock()
	for i := 0; i < n; i++ {
		f.failures[op] = append(f.failures[op], failure{status: status, example: example})
	}
	f.mu.Unlock()
}

// DropNext makes the next n calls of op fail at the connection (a transport failure).
func (f *Fake) DropNext(op string, n int) {
	f.mu.Lock()
	for i := 0; i < n; i++ {
		f.failures[op] = append(f.failures[op], failure{transport: true})
	}
	f.mu.Unlock()
}

// Delay makes every call of op wait d before answering.
func (f *Fake) Delay(op string, d time.Duration) {
	f.mu.Lock()
	f.delay[op] = d
	f.mu.Unlock()
}

// Calls returns the calls received for op ("" for all).
func (f *Fake) Calls(op string) []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Call
	for _, c := range f.calls {
		if op == "" || c.Op == op {
			out = append(out, c)
		}
	}
	return out
}

// Reset forgets calls, failures, delays and stored replays (handlers stay).
func (f *Fake) Reset() {
	f.mu.Lock()
	f.calls, f.failures, f.delay, f.replays = nil, map[string][]failure{}, map[string]time.Duration{}, map[string]stored{}
	f.mu.Unlock()
}

func problem(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "urn:hostry:problem:" + code, "title": title, "status": status, "code": code,
	})
}

// WriteJSON writes a JSON answer.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Problem writes a problem+json answer.
func Problem(w http.ResponseWriter, status int, code string) { problem(w, status, code, code) }

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	op, _, known := f.doc.Match(r.Method, r.URL.Path)
	if op == nil {
		code, st := "not_found", http.StatusNotFound
		if known {
			code, st = "method_not_allowed", http.StatusMethodNotAllowed
		}
		problem(w, st, code, code)
		return
	}
	call := Call{Op: op.ID, Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: body}

	if !f.authenticate(op, r, &call) {
		f.record(call)
		problem(w, http.StatusUnauthorized, "auth.invalid_token", "Authentication required")
		return
	}
	f.record(call)
	if op.RequiresGrant && r.Header.Get("Hostry-Vendor-Approval") == "" {
		// An executing route refuses a call with no approval grant (ADR-0014 A2.6).
		problem(w, http.StatusForbidden, "grant.required", "Approval grant required")
		return
	}

	f.mu.Lock()
	d := f.delay[op.ID]
	var fl *failure
	if q := f.failures[op.ID]; len(q) > 0 {
		fl = &q[0]
		f.failures[op.ID] = q[1:]
	}
	h := f.handlers[op.ID]
	f.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
	if fl != nil {
		if fl.transport {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
		}
		if resp, ok := op.Response(fl.status); ok {
			resp.Write(w, fl.example)
			return
		}
		problem(w, fl.status, "injected", "Injected failure")
		return
	}

	mutating := r.Method != http.MethodGet && r.Method != http.MethodHead
	key := r.Header.Get("Idempotency-Key")
	if mutating && key != "" {
		if f.replay(w, op.ID, key, r, body) {
			return
		}
	}
	rec := httptest.NewRecorder()
	handled := false
	if h != nil {
		handled = h(call, rec)
	}
	if !handled {
		rec = httptest.NewRecorder()
		if s := op.Success(); s != nil {
			s.Write(rec, "")
		} else {
			rec.WriteHeader(http.StatusOK)
		}
	}
	if mutating && key != "" && rec.Code < 500 {
		f.mu.Lock()
		f.replays[op.ID+"\x00"+key] = stored{fp: fingerprint(r, body), status: rec.Code, ct: rec.Header().Get("Content-Type"), body: rec.Body.Bytes()}
		f.mu.Unlock()
	}
	copyResult(w, rec)
}

func fingerprint(r *http.Request, body []byte) string {
	return r.Method + " " + r.URL.Path + " " + string(body)
}

func (f *Fake) replay(w http.ResponseWriter, op, key string, r *http.Request, body []byte) bool {
	f.mu.Lock()
	s, ok := f.replays[op+"\x00"+key]
	f.mu.Unlock()
	if !ok {
		return false
	}
	if s.fp != fingerprint(r, body) {
		problem(w, http.StatusUnprocessableEntity, "idempotency.mismatch", "Idempotency key reused")
		return true
	}
	if s.ct != "" {
		w.Header().Set("Content-Type", s.ct)
	}
	w.WriteHeader(s.status)
	_, _ = w.Write(s.body)
	return true
}

func copyResult(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (f *Fake) record(c Call) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
}

// authenticate applies the operation's security (ADR-0013 V2): serviceAuth needs a valid service
// token from a declared caller; vendorBearerAuth a valid vendor token; the default bearerAuth a
// valid tenant-realm token, and a support token is accepted only with an admin service token.
func (f *Fake) authenticate(op *specdata.Operation, r *http.Request, c *Call) bool {
	reqs := op.Security
	if len(reqs) == 0 {
		if op.Permission == "public" {
			return true
		}
		reqs = [][]string{{"bearerAuth"}}
	}
	svc, svcErr := f.serviceToken(r)
	if svcErr == nil {
		c.ServiceCaller = svc.Issuer
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	hasBearer := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && bearer != ""
	for _, req := range reqs {
		ok := true
		for _, scheme := range req {
			switch scheme {
			case "serviceAuth":
				if svcErr != nil || !declared(op, svc.Issuer) {
					ok = false
				}
			case "vendorBearerAuth":
				cl, err := f.verify(f.v.Vendor, bearer, hasBearer)
				if err != nil {
					ok = false
				} else {
					c.Bearer = cl
				}
			case "bearerAuth":
				cl, err := f.verify(f.v.Tenant, bearer, hasBearer)
				if err != nil {
					ok = false
					continue
				}
				if cl.Type == auth.TypeSupport && (svcErr != nil || svc.Issuer != "admin") {
					ok = false // a support token on its own is useless (ADR-0013 V2 item 5)
					continue
				}
				c.Bearer = cl
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func declared(op *specdata.Operation, caller string) bool {
	if len(op.ServiceCallers) == 0 {
		return true
	}
	for _, s := range op.ServiceCallers {
		if s == caller {
			return true
		}
	}
	return false
}

func (f *Fake) serviceToken(r *http.Request) (*auth.Claims, error) {
	return f.v.Service.Verify(r.Header.Get(auth.ServiceTokenHeader))
}

func (f *Fake) verify(v *auth.Verifier, tok string, present bool) (*auth.Claims, error) {
	if !present || v == nil {
		return nil, http.ErrNoCookie
	}
	return v.Verify(tok)
}

// JSONBody decodes a call body strictly into a map (helper for scripted handlers).
func JSONBody(c Call) map[string]any {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(c.Body))
	_ = dec.Decode(&m)
	return m
}
