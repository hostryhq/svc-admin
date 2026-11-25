package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/testkit"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
)

func TestIdempotencyEntriesAreScopedAndExpire(t *testing.T) {
	clk := testkit.NewClock()
	s := NewIdempotencyStore(30*time.Minute, clk)
	ctx := context.Background()
	if _, started, err := s.Begin(ctx, "a", "k", "fp1"); err != nil || !started {
		t.Fatalf("first begin: %v %v", started, err)
	}
	if _, _, err := s.Begin(ctx, "a", "k", "fp1"); !errors.Is(err, idempotency.ErrInProgress) {
		t.Fatalf("same key while running: %v", err)
	}
	if _, _, err := s.Begin(ctx, "a", "k", "other"); !errors.Is(err, idempotency.ErrMismatch) {
		t.Fatalf("same key, other request: %v", err)
	}
	if _, started, _ := s.Begin(ctx, "b", "k", "other"); !started {
		t.Fatal("keys are scoped per session")
	}
	_ = s.Complete(ctx, "a", "k", idempotency.Response{Status: 201, Body: []byte("x")})
	if r, started, err := s.Begin(ctx, "a", "k", "fp1"); err != nil || started || r.Status != 201 {
		t.Fatalf("replay: %+v %v %v", r, started, err)
	}
	clk.Advance(31 * time.Minute)
	if _, started, _ := s.Begin(ctx, "a", "k", "other"); !started {
		t.Fatal("an expired key may be used again")
	}
	_ = s.Release(ctx, "a", "k")
	if _, started, _ := s.Begin(ctx, "a", "k", "again"); !started {
		t.Fatal("a released key may be used again")
	}
}

func TestSessionsAreDroppedByUserAndBySweep(t *testing.T) {
	m := NewMemorySessions()
	mk := func(id, user string, seen time.Time) *Session {
		s := &Session{ID: id, LastSeen: seen, UserID: user}
		s.User = admin.VendorPrincipal{Id: user}
		m.Create(s)
		return s
	}
	now := time.Now()
	mk("1", "u1", now)
	mk("2", "u1", now)
	mk("3", "u2", now.Add(-time.Hour))
	if n := m.DeleteByUser("u1"); n != 2 {
		t.Fatalf("dropped %d, want 2", n)
	}
	if _, ok := m.Get("1"); ok {
		t.Fatal("session 1 should be gone")
	}
	if n := m.Sweep(func(s *Session) bool { return s.LastSeen.Before(now.Add(-time.Minute)) }); n != 1 || m.Len() != 0 {
		t.Fatalf("sweep dropped %d, left %d", n, m.Len())
	}
}

func TestSessionStoreIsSafeUnderConcurrency(t *testing.T) {
	m := NewMemorySessions()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := string(rune('a' + i%26))
			s := &Session{ID: id, UserID: "u"}
			m.Create(s)
			m.Get(id)
			m.DeleteByUser("u")
			m.Delete(id)
		}()
	}
	wg.Wait()
}
