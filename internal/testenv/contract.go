package testenv

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hostryhq/go-common/ids"

	"github.com/hostryhq/svc-admin/internal/specdata"
)

// APISpecsDir returns the directory of the api-specs module the build resolved (its OpenAPI
// documents are part of the module). The contract suite loads the admin document from it.
func APISpecsDir(t testing.TB) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/hostryhq/api-specs").Output()
	if err != nil {
		t.Fatalf("cannot locate the api-specs module: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// AdminSpecPath is the admin OpenAPI document of the resolved api-specs module.
func AdminSpecPath(t testing.TB) string {
	return filepath.Join(APISpecsDir(t), "openapi", "admin", "v1", "openapi.yaml")
}

// ContractTransport gives every request of the shared contract suite its own fresh vendor user,
// browser session and (for support-view operations) support session, so the suite's operations
// do not depend on each other's side effects: signing out in one must not end the next one's
// session. It replaces the example CSRF token with the session's real one. Only the sign-in
// request and routes outside the contract go through untouched.
type ContractTransport struct {
	Env  *Env
	Base http.RoundTripper

	mu    sync.Mutex
	n     int
	byKey map[string]*Session
}

// RoundTrip implements http.RoundTripper.
func (t *ContractTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	signIn := r.Method == http.MethodPost && r.URL.Path == "/v1/sessions"
	if signIn || !strings.HasPrefix(r.URL.Path, "/v1/") || !knownAdminPath(r) {
		return base.RoundTrip(r)
	}
	s := t.session(r)
	r2 := r.Clone(r.Context())
	r2.Header.Set("Cookie", "__Host-hostry-admin="+s.Cookie)
	if r2.Header.Get("X-CSRF-Token") != "" {
		r2.Header.Set("X-CSRF-Token", s.CSRF)
	}
	return base.RoundTrip(r2)
}

// session returns the browser session for a request. A replay (same Idempotency-Key) is the same
// browser retrying, so it gets the same session.
func (t *ContractTransport) session(r *http.Request) *Session {
	key := r.Header.Get("Idempotency-Key")
	if key != "" {
		key += " " + r.Method + " " + r.URL.Path // the suite reuses one key for every operation
	}
	t.mu.Lock()
	if s, ok := t.byKey[key]; ok && key != "" {
		t.mu.Unlock()
		return s
	}
	t.n++
	t.mu.Unlock()

	email := "contract-" + ids.New().String() + "@example.invalid"
	t.Env.AddUser(User{ID: ids.New().String(), Email: email, DisplayName: "Contract", Role: "platform_admin", Permissions: AllAdminPermissions()})
	s := t.Env.SignInAs(email)
	t.Env.holdGrant(s)
	if r.Method != http.MethodPost || r.URL.Path != "/v1/support-sessions" {
		t.Env.StartSupport(s, OrgID)
	}
	if key != "" {
		t.mu.Lock()
		if t.byKey == nil {
			t.byKey = map[string]*Session{}
		}
		t.byKey[key] = s
		t.mu.Unlock()
	}
	return s
}

// SeedWorld puts the fakes into an example world of the admin contract (info.x-example-worlds)
// before one operation of the shared suite runs. The fakes answer the spec's examples whatever the
// world, and every request of the suite gets its own vendor user and session (ContractTransport),
// so seeding checks that the world is declared and starts the operation from fakes with no
// replays or scripted failures left over and with every vendor user active.
func (e *Env) SeedWorld(_ context.Context, world string) error {
	for _, w := range adminDoc().Worlds {
		if w == world {
			e.Identity.Reset()
			e.Tenancy.Reset()
			e.Billing.Reset()
			e.mu.Lock()
			e.approvedKind = approvedWorlds[world]
			e.mu.Unlock()
			// A world starts with every vendor user active: the updateVendorUser example
			// deactivates the example user, which must not leak into the next operation.
			e.mu.Lock()
			for _, u := range e.users {
				u.Deactivated = false
			}
			e.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("testenv: unknown example world %q", world)
}

// approvedWorlds are the example worlds in which vendor approval 4a6d was approved by the caller and
// the admin service holds its grant in memory (kind by world).
var approvedWorlds = map[string]string{
	"org-active-approved-close":        "org_close",
	"org-suspended-approved-reinstate": "org_reinstate",
	"org-active-approved-suspend":      "org_suspend",
	"rule-set-signed-approved":         "tax_rule_set_publish",
}

func adminDoc() *specdata.Doc { return specdata.MustLoad("admin") }

func knownAdminPath(r *http.Request) bool {
	_, _, known := adminDoc().Match(r.Method, r.URL.Path)
	return known
}
