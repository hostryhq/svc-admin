package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/internal/gen/identity"
	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/upstream"
)

// SignIn delegates email, password and TOTP to identity's vendor realm (idempotent under key)
// and opens a browser session holding the vendor access token and renewal handle in memory.
// Every refusal except a rate limit looks the same: wrong password, unknown email, wrong or
// replayed TOTP and lockout.
func (s *Service) SignIn(ctx context.Context, in admin.VendorSignIn, key string) (*repository.Session, error) {
	if in.Email == "" || in.Password == "" || in.TotpCode == "" {
		return nil, ErrSignInFailed
	}
	body, err := json.Marshal(identity.VendorSignIn{Email: in.Email, Password: in.Password, TotpCode: in.TotpCode})
	if err != nil {
		return nil, ErrSignInFailed
	}
	vs, err := s.up.VendorSignIn(publicCtx(ctx), key, body)
	if err != nil {
		var ue *upstream.Error
		if errors.As(err, &ue) && !ue.Unavailable {
			if ue.Status == 429 {
				return nil, ue
			}
			return nil, ErrSignInFailed
		}
		return nil, s.mapErr(ctx, "signIn", err)
	}
	user, err := conv[admin.VendorPrincipal](vs.User)
	if err != nil {
		return nil, s.mapErr(ctx, "signIn", &upstream.Error{Unavailable: true})
	}
	id, err1 := s.randomToken(32) // 256 bits; a fresh id at every sign-in (no fixation)
	csrf, err2 := s.randomToken(24)
	if err1 != nil || err2 != nil {
		return nil, s.mapErr(ctx, "signIn", errors.Join(err1, err2))
	}
	now := s.clk.Now()
	sess := &repository.Session{
		ID: id, CSRF: csrf, UserID: user.Id, User: user,
		AccessToken: vs.AccessToken, AccessExpires: vs.ExpiresAt, RenewalHandle: vs.RenewalHandle,
		IdentityEnds: vs.SessionEndsAt, Created: now, LastSeen: now,
	}
	s.sessions.Create(sess)
	return sess, nil
}

// absoluteLocked is when the session ends whatever the activity.
func (s *Service) absoluteLocked(sess *repository.Session) time.Time {
	abs := sess.Created.Add(s.cfg.AbsoluteTimeout)
	if !sess.IdentityEnds.IsZero() && sess.IdentityEnds.Before(abs) {
		abs = sess.IdentityEnds
	}
	return abs
}

func (s *Service) deadLocked(sess *repository.Session, now time.Time) bool {
	return now.Sub(sess.LastSeen) >= s.cfg.IdleTimeout || !now.Before(s.absoluteLocked(sess))
}

// Authenticate finds the session for a cookie value, enforces the idle and absolute limits and
// counts the request as activity. An unknown, idle or expired session is refused alike.
func (s *Service) Authenticate(sessionID string) (*repository.Session, error) {
	sess, ok := s.sessions.Get(sessionID)
	if !ok {
		return nil, ErrUnauthenticated
	}
	now := s.clk.Now()
	sess.Lock()
	defer sess.Unlock()
	if s.deadLocked(sess, now) {
		s.sessions.Delete(sess.ID)
		return nil, ErrUnauthenticated
	}
	sess.LastSeen = now
	return sess, nil
}

// SweepExpired drops dead sessions; the main loop calls it periodically.
func (s *Service) SweepExpired() int {
	now := s.clk.Now()
	return s.sessions.Sweep(func(sess *repository.Session) bool {
		sess.Lock()
		defer sess.Unlock()
		return s.deadLocked(sess, now)
	})
}

// SessionCount is the number of live sessions.
func (s *Service) SessionCount() int { return s.sessions.Len() }

// View is the browser's picture of a session: the user, the clocks, the CSRF token and the
// active support session. It carries no token of any kind.
func (s *Service) View(sess *repository.Session) admin.AdminSession {
	now := s.clk.Now()
	sess.Lock()
	defer sess.Unlock()
	s.expireSupportLocked(sess, now)
	v := admin.AdminSession{
		User:               sess.User,
		CsrfToken:          sess.CSRF,
		IdleTimeoutSeconds: int(s.cfg.IdleTimeout / time.Second),
		IdleExpiresAt:      sess.LastSeen.Add(s.cfg.IdleTimeout),
		AbsoluteExpiresAt:  s.absoluteLocked(sess),
	}
	if sess.Support != nil {
		sp := sess.Support.Session
		v.SupportSession = &sp
	}
	return v
}

// SignOut drops the session and everything held against it. The upstream sign-out and the
// end of an open support session are best effort: the local session is gone either way.
func (s *Service) SignOut(ctx context.Context, sess *repository.Session) {
	s.sessions.Delete(sess.ID)
	if sp := s.takeSupport(sess); sp != nil {
		if cctx, err := s.vendorCtxNoRenew(ctx, sess); err == nil {
			_ = s.up.EndSupportSession(cctx, sp.Session.Id, s.idemKey())
		}
	}
	if cctx, err := s.vendorCtxNoRenew(ctx, sess); err == nil {
		if err := s.up.EndVendorSession(cctx, s.idemKey()); err != nil {
			s.log.InfoContext(ctx, "upstream sign-out failed", "err_kind", errKind(err))
		}
	}
	sess.Lock()
	sess.AccessToken, sess.RenewalHandle = "", ""
	sess.Unlock()
}

func errKind(err error) string {
	if upstream.IsUnavailable(err) {
		return "unavailable"
	}
	return "refused"
}

// DropUserSessions ends every browser session of a vendor user (after deactivation, a role
// change or a TOTP reset) in the same operation, as the contract requires.
func (s *Service) DropUserSessions(userID string) int { return s.sessions.DeleteByUser(userID) }

// ---- the vendor token held against a session ---------------------------------------------

// vendorCtxNoRenew returns a context carrying the session's current vendor token, if any.
func (s *Service) vendorCtxNoRenew(ctx context.Context, sess *repository.Session) (context.Context, error) {
	sess.Lock()
	defer sess.Unlock()
	if sess.AccessToken == "" {
		return nil, ErrUnauthenticated
	}
	return upstream.WithCred(ctx, upstream.Cred{Bearer: sess.AccessToken, Address: addressOf(ctx)}), nil
}

// ensureVendorTokenLocked renews the vendor access token when it is near expiry (or force).
// While identity is down the current token keeps working until it expires (spec BR-13).
// A renewal identity refuses ends the session. The caller holds the session lock.
func (s *Service) ensureVendorTokenLocked(ctx context.Context, sess *repository.Session, force bool) error {
	now := s.clk.Now()
	if !force && sess.AccessExpires.Sub(now) > s.cfg.RefreshSkew {
		return nil
	}
	vs, err := s.up.RenewVendorSession(publicCtx(ctx), s.idemKey(), sess.RenewalHandle)
	if err != nil {
		if upstream.IsUnavailable(err) {
			if !force && now.Before(sess.AccessExpires) {
				return nil
			}
			return ErrUnavailable
		}
		// Refused: deactivated user, ended vendor session or a spent handle.
		s.sessions.Delete(sess.ID)
		return ErrUnauthenticated
	}
	sess.AccessToken, sess.AccessExpires, sess.RenewalHandle = vs.AccessToken, vs.ExpiresAt, vs.RenewalHandle
	if !vs.SessionEndsAt.IsZero() {
		sess.IdentityEnds = vs.SessionEndsAt
	}
	if user, err := conv[admin.VendorPrincipal](vs.User); err == nil && user.Id == sess.User.Id {
		sess.User = user // permissions follow the role as identity now sees it
	}
	return nil
}

// asVendor runs fn with the vendor token in the context. A 401 from the service means the
// token was refused: renew once and retry, and if it is refused again the session is over.
func (s *Service) asVendor(ctx context.Context, sess *repository.Session, fn func(ctx context.Context) error) error {
	call := func(force bool) (context.Context, error) {
		sess.Lock()
		defer sess.Unlock()
		if err := s.ensureVendorTokenLocked(ctx, sess, force); err != nil {
			return nil, err
		}
		return upstream.WithCred(ctx, upstream.Cred{Bearer: sess.AccessToken, Address: addressOf(ctx)}), nil
	}
	cctx, err := call(false)
	if err != nil {
		return err
	}
	err = fn(cctx)
	if upstream.StatusOf(err) == 401 {
		if cctx, err = call(true); err != nil {
			return err
		}
		if err = fn(cctx); upstream.StatusOf(err) == 401 {
			s.sessions.Delete(sess.ID)
			return ErrUnauthenticated
		}
	}
	return err
}

// DropSession ends a browser session by id without calling upstream (used when a sign-in
// replaces the session the browser still held).
func (s *Service) DropSession(id string) { s.sessions.Delete(id) }
