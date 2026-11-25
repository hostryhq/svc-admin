package service

import (
	"context"
	"time"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
	"github.com/hostryhq/svc-admin/internal/gen/identity"
	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/upstream"
)

// expireSupportLocked clears a support session whose time is up. The caller holds the lock.
func (s *Service) expireSupportLocked(sess *repository.Session, now time.Time) bool {
	if sess.Support != nil && !now.Before(sess.Support.EndsAt) {
		sess.Support = nil
		return true
	}
	return false
}

// takeSupport removes and returns the session's support state.
func (s *Service) takeSupport(sess *repository.Session) *repository.Support {
	sess.Lock()
	defer sess.Unlock()
	sp := sess.Support
	sess.Support = nil
	return sp
}

func (s *Service) supportView(sp *repository.Support, now time.Time) admin.SupportSessionView {
	rem := int(sp.EndsAt.Sub(now) / time.Second)
	if rem < 0 {
		rem = 0
	}
	return admin.SupportSessionView{Session: sp.Session, SecondsRemaining: rem}
}

// StartSupport starts a read-only support session. Act mode is refused in Phase 1, and a
// second start while one is active is refused. The support token stays in the session.
func (s *Service) StartSupport(ctx context.Context, sess *repository.Session, in admin.StartSupport, key string) (admin.SupportSessionView, error) {
	var zero admin.SupportSessionView
	if in.Mode != nil && *in.Mode != admin.StartSupportModeView {
		return zero, ErrModeNotSupported
	}
	now := s.clk.Now()
	sess.Lock()
	s.expireSupportLocked(sess, now)
	active := sess.Support != nil
	sess.Unlock()
	if active {
		return zero, ErrSupportActive
	}
	req := identity.StartSupportSession{
		OrganisationId: in.OrganisationId, TicketReference: in.TicketReference, Reason: in.Reason,
		DurationMinutes: in.DurationMinutes,
	}
	if in.Mode != nil {
		m := identity.StartSupportSessionModeView
		req.Mode = &m
	}
	var started identity.SupportSessionStarted
	err := s.asVendor(ctx, sess, func(c context.Context) error {
		var e error
		started, e = s.up.StartSupportSession(c, key, req)
		return e
	})
	if err != nil {
		return zero, s.mapErr(ctx, "startSupportSession", err)
	}
	view, err := conv[admin.SupportSession](started.Session)
	if err != nil {
		return zero, s.mapErr(ctx, "startSupportSession", &upstream.Error{Unavailable: true})
	}
	sp := &repository.Support{Session: view, Token: started.Token.AccessToken, TokenExpires: started.Token.ExpiresAt, EndsAt: view.EndsAt}
	sess.Lock()
	sess.Support = sp
	sess.Unlock()
	return s.supportView(sp, s.clk.Now()), nil
}

// CurrentSupport returns the active session for the banner, or ErrNoSupportSession.
func (s *Service) CurrentSupport(sess *repository.Session) (admin.SupportSessionView, error) {
	now := s.clk.Now()
	sess.Lock()
	defer sess.Unlock()
	s.expireSupportLocked(sess, now)
	if sess.Support == nil {
		return admin.SupportSessionView{}, ErrNoSupportSession
	}
	return s.supportView(sess.Support, now), nil
}

// EndSupport ends the active session at identity and drops the token. With no active session
// it succeeds (idempotent). If identity cannot be reached the session is kept so the staff
// member can retry, and the answer is 503.
func (s *Service) EndSupport(ctx context.Context, sess *repository.Session, key string) error {
	now := s.clk.Now()
	sess.Lock()
	s.expireSupportLocked(sess, now)
	sp := sess.Support
	sess.Unlock()
	if sp == nil {
		return nil
	}
	err := s.asVendor(ctx, sess, func(c context.Context) error {
		return s.up.EndSupportSession(c, sp.Session.Id, key)
	})
	if err != nil && (upstream.IsUnavailable(err) || err == ErrUnavailable) {
		return ErrUnavailable
	}
	if err != nil && upstream.StatusOf(err) != 404 && upstream.StatusOf(err) != 409 {
		if err == ErrUnauthenticated {
			return err
		}
		return s.mapErr(ctx, "endSupportSession", err)
	}
	s.takeSupport(sess)
	return nil
}

// supportCtx returns a context carrying the support token for a read of one organisation. It
// requires an active session for exactly that organisation: none is 403, an ended one 409,
// another organisation 404. The token is renewed inside the session when near expiry.
func (s *Service) supportCtx(ctx context.Context, sess *repository.Session, org string) (context.Context, error) {
	now := s.clk.Now()
	sess.Lock()
	defer sess.Unlock()
	if s.expireSupportLocked(sess, now) {
		return nil, ErrSupportEnded
	}
	sp := sess.Support
	if sp == nil {
		return nil, ErrSupportRequired
	}
	if sp.Session.OrganisationId != org {
		return nil, ErrNotFound
	}
	if sp.TokenExpires.Sub(now) <= s.cfg.RefreshSkew {
		if err := s.renewSupportLocked(ctx, sess, sp, now); err != nil {
			return nil, err
		}
	}
	return upstream.WithCred(ctx, upstream.Cred{Bearer: sp.Token, Address: addressOf(ctx)}), nil
}

// renewSupportLocked re-issues the support token inside the session. While identity is down the
// current token keeps working until it expires. The caller holds the session lock.
func (s *Service) renewSupportLocked(ctx context.Context, sess *repository.Session, sp *repository.Support, now time.Time) error {
	if err := s.ensureVendorTokenLocked(ctx, sess, false); err != nil {
		return err
	}
	vctx := upstream.WithCred(ctx, upstream.Cred{Bearer: sess.AccessToken, Address: addressOf(ctx)})
	tok, err := s.up.RenewSupportToken(vctx, sp.Session.Id, s.idemKey())
	if err != nil {
		if upstream.IsUnavailable(err) {
			if now.Before(sp.TokenExpires) {
				return nil
			}
			return ErrUnavailable
		}
		sess.Support = nil // identity ended the session (409) or refuses it
		return ErrSupportEnded
	}
	sp.Token, sp.TokenExpires = tok.AccessToken, tok.ExpiresAt
	return nil
}

// supportRead runs one support-view read. A 401 from the service means identity has ended
// the session, so the local state is dropped.
func (s *Service) supportRead(ctx context.Context, sess *repository.Session, org, op string, fn func(ctx context.Context) ([]byte, error)) ([]byte, error) {
	cctx, err := s.supportCtx(ctx, sess, org)
	if err != nil {
		return nil, err
	}
	b, err := fn(cctx)
	if upstream.StatusOf(err) == 401 {
		s.takeSupport(sess)
		return nil, ErrSupportEnded
	}
	return b, s.mapErr(ctx, op, err)
}
