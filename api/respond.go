package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/logx"

	"github.com/hostryhq/svc-admin/upstream"
)

const (
	jsonCT    = "application/json"
	problemCT = "application/problem+json"
)

// rendered is a response ready to be written, or stored for an idempotent replay.
type rendered struct {
	status     int
	body       []byte
	retryAfter string
}

func (r rendered) response() idempotency.Response {
	ct := ""
	if len(r.body) > 0 {
		ct = jsonCT
		if r.status >= 400 {
			ct = problemCT
		}
	}
	return idempotency.Response{Status: r.status, ContentType: ct, Body: r.body}
}

// cacheable says whether a replay of the same Idempotency-Key may return this answer. A server
// error, a rate limit and a refused session describe the moment, not the request.
func (r rendered) cacheable() bool {
	return r.status < 500 && r.status != http.StatusTooManyRequests && r.status != http.StatusUnauthorized
}

// uncached carries an answer that must not be stored under the key (the key is released).
type uncached struct{ r rendered }

func (u uncached) Error() string { return "uncached response" }

// renderJSON marshals v and runs the deny-list over it (spec: re-validate before answering).
func (h *Handler) renderJSON(r *http.Request, status int, v any, o scrubOpts) rendered {
	if v == nil {
		return rendered{status: status}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return h.renderError(r, errUnavailable)
	}
	if o.skip {
		return rendered{status: status, body: b}
	}
	if err := scrub(b, o); err != nil {
		h.log.ErrorContext(r.Context(), "response refused by the deny list", "reason", err.Error())
		return h.renderError(r, errUnavailable)
	}
	return rendered{status: status, body: b}
}

var errUnavailable = apperr.New(apperr.Unavailable, "upstream_unavailable", "")

// renderError maps any error to a problem+json answer. Upstream refusals keep their sanitised
// problem; anything unexpected is a generic 500 with no internals.
func (h *Handler) renderError(r *http.Request, err error) rendered {
	var ue *upstream.Error
	if errors.As(err, &ue) && !ue.Unavailable {
		p := ue.Problem
		if p.Status == 0 {
			p.Status = ue.Status
		}
		if p.Type == "" {
			p.Type = apperr.TypeBase + p.Code
		}
		p.RequestID = logx.RequestID(r.Context())
		p.Instance = r.URL.Path
		b, _ := json.Marshal(p)
		return rendered{status: p.Status, body: b, retryAfter: ue.RetryAfter}
	}
	if ue != nil { // unavailable upstream
		err = errUnavailable
	}
	p := apperr.ToProblem(r, err)
	if p.Status >= 500 && p.Code != "upstream_unavailable" {
		h.log.ErrorContext(r.Context(), "request failed", "code", p.Code)
	}
	b, _ := json.Marshal(p)
	return rendered{status: p.Status, body: b}
}

func (h *Handler) write(w http.ResponseWriter, r rendered) {
	if len(r.body) > 0 {
		ct := jsonCT
		if r.status >= 400 {
			ct = problemCT
		}
		w.Header().Set("Content-Type", ct)
	}
	if r.retryAfter != "" {
		w.Header().Set("Retry-After", r.retryAfter)
	}
	w.WriteHeader(r.status)
	if len(r.body) > 0 {
		_, _ = w.Write(r.body)
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.write(w, h.renderError(r, err))
}

// ---- the deny list -------------------------------------------------------------------------

type scrubOpts struct {
	skip       bool // the body is the admin session itself (it carries the CSRF token by design)
	allowEmail bool // vendor staff records and account setup carry staff email addresses
}

var (
	// A full Indian mobile number, with or without the country code, anywhere in a string.
	fullMobile = regexp.MustCompile(`(\+91|\b)[6-9][0-9]{9}\b`)
	deniedKeys = map[string]bool{
		"mobile_e164": true, "phone": true, "mobile": true, "phone_number": true,
		"public_key": true, "proof_key": true, "private_key": true, "key_material": true, "jwk": true, "jwks": true,
		"pin": true, "pin_verifier": true, "pin_hash": true, "pin_salt": true,
		"access_token": true, "refresh_token": true, "renewal_handle": true, "support_token": true, "id_token": true,
		"totp_secret": true, "password": true, "password_hash": true, "secret": true,
	}
)

// scrub refuses a body that would show the browser a token, key material, a customer email or a
// full mobile number. Unknown fields are already dropped by decoding into the contract's types;
// this is the second line.
func scrub(b []byte, o scrubOpts) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	return walk(v, "", o)
}

func walk(v any, path string, o scrubOpts) error {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			lk := strings.ToLower(k)
			if deniedKeys[lk] || (lk == "email" && !o.allowEmail) {
				return fmt.Errorf("denied field %q", path+"/"+k)
			}
			if err := walk(c, path+"/"+k, o); err != nil {
				return err
			}
		}
	case []any:
		for _, c := range t {
			if err := walk(c, path+"[]", o); err != nil {
				return err
			}
		}
	case string:
		if fullMobile.MatchString(t) {
			return fmt.Errorf("a full mobile number at %q", path)
		}
	}
	return nil
}
