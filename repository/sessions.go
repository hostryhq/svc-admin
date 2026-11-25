// Package repository holds the in-memory stores of the admin service. The service has no
// database (ADR-0013 V1): sessions and the tokens held against them live in the memory of one
// instance, and a restart signs everyone out. Nothing here is ever written to disk.
package repository

import (
	"sync"
	"time"

	"github.com/hostryhq/svc-admin/internal/gen/admin"
)

// Support is the active support session of a browser session, with the support token kept
// server-side (never sent to the browser).
type Support struct {
	Session      admin.SupportSession
	Token        string
	TokenExpires time.Time
	EndsAt       time.Time
}

// Grant is a single-use vendor approval grant issued by identity when an approval of an executing
// kind (org_suspend, org_reinstate, org_close, tax_rule_set_publish) was approved. It is held in
// memory against the session that approved it and is never sent to the browser.
type Grant struct {
	ApprovalID string
	Kind       string
	Token      string
	Expires    time.Time
}

// Session is one signed-in vendor user. Fields are guarded by the session's own lock; hold it
// (Lock/Unlock) around any read or write after the session was handed out by the store.
type Session struct {
	mu sync.Mutex

	ID   string // opaque 256-bit id, the cookie value
	CSRF string // per-session CSRF token
	// UserID is the vendor user's id. It is immutable after Create, so the store may read it without
	// the session lock: a store lock is never held while taking a session lock, or the reverse.
	UserID string

	User admin.VendorPrincipal

	// Vendor-realm credentials, kept in memory only.
	AccessToken   string
	AccessExpires time.Time
	RenewalHandle string
	// IdentityEnds is when identity ends the vendor session (renewal is refused after it).
	IdentityEnds time.Time

	Created  time.Time
	LastSeen time.Time

	Support *Support

	// Grants are the unused vendor approval grants by approval id.
	Grants map[string]Grant
}

// Lock takes the session lock.
func (s *Session) Lock() { s.mu.Lock() }

// Unlock releases the session lock.
func (s *Session) Unlock() { s.mu.Unlock() }

// SessionStore keeps sessions by id.
type SessionStore interface {
	Create(s *Session)
	Get(id string) (*Session, bool)
	Delete(id string)
	// DeleteByUser drops every session of a vendor user and returns how many.
	DeleteByUser(userID string) int
	// Sweep drops sessions for which expired returns true.
	Sweep(expired func(*Session) bool) int
	Len() int
}

// MemorySessions is the in-memory SessionStore.
type MemorySessions struct {
	mu sync.RWMutex
	m  map[string]*Session
}

// NewMemorySessions returns an empty store.
func NewMemorySessions() *MemorySessions { return &MemorySessions{m: map[string]*Session{}} }

// Create stores s under s.ID.
func (m *MemorySessions) Create(s *Session) {
	m.mu.Lock()
	m.m[s.ID] = s
	m.mu.Unlock()
}

// Get returns the session for id.
func (m *MemorySessions) Get(id string) (*Session, bool) {
	m.mu.RLock()
	s, ok := m.m[id]
	m.mu.RUnlock()
	return s, ok
}

// Delete drops a session.
func (m *MemorySessions) Delete(id string) {
	m.mu.Lock()
	delete(m.m, id)
	m.mu.Unlock()
}

// DeleteByUser drops every session of a vendor user.
func (m *MemorySessions) DeleteByUser(userID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.m {
		if s.UserID == userID {
			delete(m.m, id)
			n++
		}
	}
	return n
}

// Sweep drops sessions that expired reports as dead. The predicate takes the session lock itself,
// so it runs outside the store lock.
func (m *MemorySessions) Sweep(expired func(*Session) bool) int {
	m.mu.RLock()
	all := make([]*Session, 0, len(m.m))
	for _, s := range m.m {
		all = append(all, s)
	}
	m.mu.RUnlock()
	n := 0
	for _, s := range all {
		if expired(s) {
			m.Delete(s.ID)
			n++
		}
	}
	return n
}

// Len is the number of live sessions.
func (m *MemorySessions) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.m)
}
