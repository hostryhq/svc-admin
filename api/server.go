package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/health"
	"github.com/hostryhq/go-common/httpx"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/logx"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/internal/specdata"
	"github.com/hostryhq/svc-admin/service"
)

func constantEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// Routes returns the complete handler: the /v1 API, health, and (when configured) the admin-web
// build from the same origin. CORS is off: no Access-Control-* header is ever set.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	admin.HandlerWithOptions(h, admin.StdHTTPServerOptions{
		BaseRouter:       mux,
		ErrorHandlerFunc: h.badRequest,
	})
	hh := health.New(2 * time.Second)
	for name, check := range h.ready {
		hh.Add(name, health.Check(check))
	}
	hh.Register(mux)
	mux.HandleFunc("/v1/", h.unknownRoute)
	if h.staticDir != "" {
		mux.Handle("/", StaticHandler(h.staticDir))
	} else {
		mux.HandleFunc("/", h.unknownRoute)
	}
	return httpx.Chain(mux, httpx.RequestID, httpx.Recover, h.accessLog, securityHeaders, h.noBearer)
}

// badRequest answers a parameter the generated binder could not read. A missing CSRF token is
// the contract's csrf_failed, a missing or repeated Idempotency-Key is idempotency.key_invalid.
func (h *Handler) badRequest(w http.ResponseWriter, r *http.Request, err error) {
	var missing *admin.RequiredHeaderError
	var many *admin.TooManyValuesForParamError
	name := ""
	switch {
	case errors.As(err, &missing):
		name = missing.ParamName
	case errors.As(err, &many):
		name = many.ParamName
	}
	switch name {
	case CSRFHeader:
		h.fail(w, r, errCSRF)
	case "Idempotency-Key":
		h.fail(w, r, idempotency.ErrKeyInvalid)
	default:
		h.fail(w, r, apperr.New(apperr.Validation, "validation", "a parameter is missing or malformed"))
	}
}

var adminDoc = specdata.MustLoad("admin")

// unknownRoute answers 404 for a route that does not exist and 405 for a known path under
// another method, both as problem+json.
func (h *Handler) unknownRoute(w http.ResponseWriter, r *http.Request) {
	if _, _, known := adminDoc.Match(r.Method, r.URL.Path); known {
		w.Header().Set("Allow", allowed(r.URL.Path))
		h.write(w, rendered{status: http.StatusMethodNotAllowed, body: problemBody(r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")})
		return
	}
	h.write(w, rendered{status: http.StatusNotFound, body: problemBody(r, http.StatusNotFound, "not_found", "Not found")})
}

func allowed(p string) string { return strings.Join(adminDoc.Methods(p), ", ") }

func problemBody(r *http.Request, status int, code, title string) []byte {
	b, _ := json.Marshal(apperr.Problem{
		Type: apperr.TypeBase + code, Title: title, Status: status, Code: code,
		Instance: r.URL.Path, RequestID: logx.RequestID(r.Context()),
	})
	return b
}

// noBearer refuses any Authorization header on the API: the admin API takes the session cookie
// only, and a bearer token of any realm is refused (ADR-0013 V1, AD1).
func (h *Handler) noBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") && r.Header.Get("Authorization") != "" {
			h.fail(w, r, service.ErrUnauthenticated)
			return
		}
		next.ServeHTTP(w, r)
	})
}

const (
	apiCSP    = "default-src 'none'; frame-ancestors 'none'"
	staticCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
		"frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)

// securityHeaders sets the headers of a strict, same-origin, no-framing application.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Cross-Origin-Resource-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			hd.Set("Content-Security-Policy", apiCSP)
			hd.Set("Cache-Control", "no-store")
		} else {
			hd.Set("Content-Security-Policy", staticCSP)
		}
		next.ServeHTTP(w, r)
	})
}

// accessLog logs one line per request: method, path (never the query), status and duration.
// No header, cookie, body or token is logged.
func (h *Handler) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		h.log.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("method", r.Method), slog.String("path", r.URL.Path),
			slog.Int("status", sw.status), slog.Duration("took", time.Since(start)))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) {
	s.status = c
	s.ResponseWriter.WriteHeader(c)
}

// ---- static admin-web ------------------------------------------------------------------------

// StaticHandler serves the admin-web build from dir. Files are served as they are; a path that
// is not a file and has no extension falls back to index.html (client-side routing). There is no
// directory listing, and only GET and HEAD are answered.
func StaticHandler(dir string) http.Handler {
	root, _ := filepath.Abs(dir)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		file := filepath.Join(root, filepath.FromSlash(clean))
		if !strings.HasPrefix(file, root) {
			http.NotFound(w, r)
			return
		}
		fi, err := os.Stat(file)
		switch {
		case err == nil && fi.Mode().IsRegular():
		case path.Ext(clean) == "":
			file = filepath.Join(root, "index.html")
		default:
			http.NotFound(w, r)
			return
		}
		if filepath.Base(file) == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		} else if strings.HasPrefix(clean, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFile(w, r, file)
	})
}
