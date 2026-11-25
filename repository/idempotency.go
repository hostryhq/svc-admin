package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
)

// IdempotencyStore is an in-memory idempotency.Store whose entries expire. The admin service
// uses it for sign-in and for replays inside a session; the owning services keep their own.
type IdempotencyStore struct {
	mu  sync.Mutex
	ttl time.Duration
	clk clock.Clock
	m   map[string]*idemEntry
	// lastSweep bounds the cost of expiry: the map is scanned at most once a minute.
	lastSweep time.Time
}

type idemEntry struct {
	fp      string
	resp    *idempotency.Response
	expires time.Time
}

// NewIdempotencyStore returns a store whose entries live for ttl.
func NewIdempotencyStore(ttl time.Duration, clk clock.Clock) *IdempotencyStore {
	return &IdempotencyStore{ttl: ttl, clk: clk, m: map[string]*idemEntry{}}
}

func idemKey(t ids.ID, key string) string { return string(t) + "\x00" + key }

func (s *IdempotencyStore) sweepLocked(now time.Time) {
	if len(s.m) < 1024 || now.Sub(s.lastSweep) < time.Minute {
		return
	}
	s.lastSweep = now
	for k, e := range s.m {
		if now.After(e.expires) {
			delete(s.m, k)
		}
	}
}

// Begin implements idempotency.Store.
func (s *IdempotencyStore) Begin(_ context.Context, t ids.ID, key, fp string) (*idempotency.Response, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clk.Now()
	s.sweepLocked(now)
	k := idemKey(t, key)
	e, ok := s.m[k]
	if ok && now.After(e.expires) {
		delete(s.m, k)
		ok = false
	}
	if !ok {
		s.m[k] = &idemEntry{fp: fp, expires: now.Add(s.ttl)}
		return nil, true, nil
	}
	if e.fp != fp {
		return nil, false, idempotency.ErrMismatch
	}
	if e.resp == nil {
		return nil, false, idempotency.ErrInProgress
	}
	return e.resp, false, nil
}

// Complete implements idempotency.Store.
func (s *IdempotencyStore) Complete(_ context.Context, t ids.ID, key string, r idempotency.Response) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[idemKey(t, key)]
	if !ok {
		return errors.New("idempotency: complete on unknown key")
	}
	e.resp = &r
	return nil
}

// Release implements idempotency.Store.
func (s *IdempotencyStore) Release(_ context.Context, t ids.ID, key string) error {
	s.mu.Lock()
	delete(s.m, idemKey(t, key))
	s.mu.Unlock()
	return nil
}
