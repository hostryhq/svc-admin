// Package service holds the admin service's rules: vendor sign-in and the browser session,
// the token held against it, the two-step organisation onboarding (ADR-0013 V4), support
// sessions and the allowlisted operations built on identity and tenancy. It knows nothing of
// HTTP cookies or headers; the api package maps those. The service has no database and writes
// no audit record: the serving services record each vendor action in their own transaction.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/clock"

	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/upstream"
)

// Config holds the session limits (spec BR-5: configuration).
type Config struct {
	IdleTimeout     time.Duration // default 30 minutes
	AbsoluteTimeout time.Duration // default 12 hours
	// RefreshSkew renews a vendor or support token that expires within this window (default 30s).
	RefreshSkew time.Duration
}

func (c *Config) defaults() {
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 30 * time.Minute
	}
	if c.AbsoluteTimeout <= 0 {
		c.AbsoluteTimeout = 12 * time.Hour
	}
	if c.RefreshSkew <= 0 {
		c.RefreshSkew = 30 * time.Second
	}
}

// Service is the admin service.
type Service struct {
	cfg      Config
	up       *upstream.Upstream
	sessions repository.SessionStore
	clk      clock.Clock
	log      *slog.Logger
	rnd      io.Reader
}

// Deps are the collaborators of a Service. Clock, Rand and Log default to production values.
type Deps struct {
	Upstream *upstream.Upstream
	Sessions repository.SessionStore
	Clock    clock.Clock
	Rand     io.Reader
	Log      *slog.Logger
}

// New builds a Service.
func New(cfg Config, d Deps) *Service {
	cfg.defaults()
	s := &Service{cfg: cfg, up: d.Upstream, sessions: d.Sessions, clk: d.Clock, log: d.Log, rnd: d.Rand}
	if s.clk == nil {
		s.clk = clock.System
	}
	if s.rnd == nil {
		s.rnd = rand.Reader
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.sessions == nil {
		s.sessions = repository.NewMemorySessions()
	}
	return s
}

// Config returns the session limits in force.
func (s *Service) Config() Config { return s.cfg }

// Errors the api layer maps to problems. Codes are the stable ones in the admin contract.
var (
	ErrUnauthenticated  = apperr.New(apperr.Unauthenticated, "auth.invalid_token", "")
	ErrSignInFailed     = apperr.New(apperr.Unauthenticated, "sign_in_failed", "")
	ErrUnavailable      = apperr.New(apperr.Unavailable, "upstream_unavailable", "")
	ErrSupportRequired  = apperr.New(apperr.Forbidden, "support_session_required", "")
	ErrSupportEnded     = apperr.New(apperr.Conflict, "support_session_ended", "")
	ErrSupportActive    = apperr.New(apperr.Conflict, "support_session_active", "")
	ErrModeNotSupported = apperr.New(apperr.Validation, "mode_not_supported", "")
	ErrNoSupportSession = apperr.New(apperr.NotFound, "not_found", "")
	ErrNotFound         = apperr.New(apperr.NotFound, "not_found", "")
)

// Forbidden is the refusal for a role that lacks a permission.
func Forbidden() error { return apperr.New(apperr.Forbidden, "forbidden", "") }

type ctxKey int

const addrKey ctxKey = iota

// WithAddress returns ctx carrying the staff member's network address, passed down to the
// serving services for their audit record (ADR-0013 V2 item 9).
func WithAddress(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, addrKey, addr)
}

func addressOf(ctx context.Context) string {
	a, _ := ctx.Value(addrKey).(string)
	return a
}

// publicCtx is the context of an upstream call made with the service token only.
func publicCtx(ctx context.Context) context.Context {
	return upstream.WithCred(ctx, upstream.Cred{Address: addressOf(ctx)})
}

// randomToken returns n random bytes, base64url without padding.
func (s *Service) randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.rnd, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// idemKey makes a key for a call the service makes on its own (renewals, best-effort ends).
func (s *Service) idemKey() string {
	b := make([]byte, 16)
	_, _ = io.ReadFull(s.rnd, b)
	return "adm-" + hex.EncodeToString(b)
}

// conv copies between structurally identical generated types of different packages.
func conv[To any](from any) (To, error) {
	var to To
	b, err := json.Marshal(from)
	if err != nil {
		return to, err
	}
	if err := json.Unmarshal(b, &to); err != nil {
		return to, err
	}
	return to, nil
}

// mapErr turns an upstream failure into what the browser may see. Unavailable and unreadable
// answers become 503; a refusal keeps its sanitised problem; 5xx text never passes.
func (s *Service) mapErr(ctx context.Context, op string, err error) error {
	if err == nil {
		return nil
	}
	var ue *upstream.Error
	if errors.As(err, &ue) {
		if ue.Unavailable {
			s.log.WarnContext(ctx, "upstream unavailable", "op", op, "status", ue.Status)
			return ErrUnavailable
		}
		if ue.Status == 401 {
			// Only a refused service token reaches here (vendor and support tokens are handled by
			// their callers). That is our fault, not the staff member's.
			s.log.ErrorContext(ctx, "upstream refused the service token", "op", op)
			return ErrUnavailable
		}
		return ue
	}
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return err
	}
	s.log.ErrorContext(ctx, "unexpected error", "op", op, "error", err)
	return ErrUnavailable
}

// Can reports whether the session's user holds a permission (admin refuses early; the owning
// service remains the enforcement point).
func (s *Service) Can(sess *repository.Session, perm string) bool {
	sess.Lock()
	defer sess.Unlock()
	return slices.Contains(sess.User.Permissions, perm)
}

// CanAny reports whether the user holds any of the permissions.
func (s *Service) CanAny(sess *repository.Session, perms ...string) bool {
	for _, p := range perms {
		if s.Can(sess, p) {
			return true
		}
	}
	return false
}
