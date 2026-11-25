package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/testkit"
)

type rig struct {
	up    *Upstream
	srv   *httptest.Server
	hits  atomic.Int32
	mu    sync.Mutex
	heads []http.Header
}

func newRig(t *testing.T, timeout time.Duration, h func(w http.ResponseWriter, r *http.Request, n int)) *rig {
	t.Helper()
	r := &rig{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := int(r.hits.Add(1))
		r.mu.Lock()
		r.heads = append(r.heads, req.Header.Clone())
		r.mu.Unlock()
		h(w, req, n)
	}))
	t.Cleanup(r.srv.Close)
	reg := authtest.NewServiceRegistry(testkit.NewClock(), "admin")
	up, err := New(Config{
		IdentityURL: r.srv.URL, TenancyURL: r.srv.URL, Signer: reg.Signer("admin"), Timeout: timeout,
		Sleep: func(context.Context, time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.up = up
	return r
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"type":"urn:hostry:problem:` + code + `","title":"t","status":` + strconv.Itoa(status) + `,"code":"` + code + `","instance":"/internal/secret/path","request_id":"upstream-req"}`))
}

func TestACallCarriesBothCredentialsTheAddressAndTheRequestID(t *testing.T) {
	r := newRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	ctx := WithCred(context.Background(), Cred{Bearer: "vendor-token-value", Address: "203.0.113.7"})
	if _, err := r.up.ListVendorUsers(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	h := r.heads[0]
	if h.Get("Authorization") != "Bearer vendor-token-value" {
		t.Errorf("Authorization = %q", h.Get("Authorization"))
	}
	if h.Get("Hostry-Service-Token") == "" || strings.Count(h.Get("Hostry-Service-Token"), ".") != 2 {
		t.Errorf("the admin service token is missing: %q", h.Get("Hostry-Service-Token"))
	}
	if h.Get("X-Vendor-Client-Address") != "203.0.113.7" {
		t.Errorf("address = %q", h.Get("X-Vendor-Client-Address"))
	}
}

func TestAServiceOnlyCallCarriesNoBearer(t *testing.T) {
	r := newRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte(`{}`)) })
	if _, err := r.up.BeginVendorSetup(context.Background(), "k", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if r.heads[0].Get("Authorization") != "" || r.heads[0].Get("Hostry-Service-Token") == "" {
		t.Errorf("headers: %v", r.heads[0])
	}
}

// A 502, 503 or 504 is retried once with the same key; nothing else is.
func TestRetriesOnceOnGatewayErrorsAndNeverOnRefusals(t *testing.T) {
	cases := []struct {
		status   int
		wantHits int32
	}{{http.StatusBadGateway, 2}, {http.StatusServiceUnavailable, 2}, {http.StatusGatewayTimeout, 2}, {http.StatusInternalServerError, 1}, {http.StatusConflict, 1}, {http.StatusUnprocessableEntity, 1}, {http.StatusUnauthorized, 1}}
	for _, c := range cases {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			r := newRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request, _ int) { problem(w, c.status, "x") })
			_, err := r.up.CreateVendorUser(context.Background(), "the-key", []byte(`{}`))
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := r.hits.Load(); got != c.wantHits {
				t.Errorf("%d attempts, want %d", got, c.wantHits)
			}
			for _, h := range r.heads {
				if h.Get("Idempotency-Key") != "the-key" {
					t.Error("every attempt must carry the same Idempotency-Key")
				}
			}
		})
	}
}

func TestTheSecondAttemptCanSucceed(t *testing.T) {
	r := newRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request, n int) {
		if n == 1 {
			problem(w, http.StatusServiceUnavailable, "busy")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x"}`))
	})
	b, err := r.up.CreateVendorUser(context.Background(), "k", []byte(`{}`))
	if err != nil || string(b) != `{"id":"x"}` {
		t.Fatalf("%s %v", b, err)
	}
}

func TestATimeoutIsUnavailableAndBounded(t *testing.T) {
	r := newRig(t, 40*time.Millisecond, func(w http.ResponseWriter, _ *http.Request, _ int) { time.Sleep(300 * time.Millisecond) })
	start := time.Now()
	_, err := r.up.ListBrands(context.Background(), nil, nil)
	if !IsUnavailable(err) {
		t.Fatalf("err = %v, want unavailable", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("a timeout must bound the call")
	}
}

// A refusal keeps its problem for the browser but loses the upstream's instance and request id;
// a 5xx never carries upstream text.
func TestRefusalsAreSanitisedAndServerErrorsCarryNoText(t *testing.T) {
	r := newRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"type":"urn:hostry:problem:rate","title":"slow down","status":429,"code":"rate","instance":"/internal/secret","request_id":"up-1"}`))
	})
	_, err := r.up.ListBrands(context.Background(), nil, nil)
	var ue *Error
	if !errors.As(err, &ue) || ue.Unavailable || ue.Status != 429 || ue.RetryAfter != "17" {
		t.Fatalf("%+v", ue)
	}
	if ue.Problem.Instance != "" || ue.Problem.RequestID != "" || ue.Problem.Code != "rate" {
		t.Errorf("problem not sanitised: %+v", ue.Problem)
	}

	r = newRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("pq: relation tenants does not exist"))
	})
	_, err = r.up.ListBrands(context.Background(), nil, nil)
	if !errors.As(err, &ue) || !ue.Unavailable || strings.Contains(ue.Error(), "pq") || ue.Problem.Detail != "" {
		t.Errorf("a 5xx must be an opaque unavailable: %+v", ue)
	}
}

func TestAnUnreadableAnswerIsUnavailable(t *testing.T) {
	r := newRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte("<html>not json")) })
	if _, err := r.up.OwnerStatuses(context.Background(), []string{"a"}); !IsUnavailable(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	r := newRig(t, time.Second, func(w http.ResponseWriter, req *http.Request, _ int) {
		http.Redirect(w, req, other.URL, http.StatusFound)
	})
	if _, err := r.up.ListBrands(WithCred(context.Background(), Cred{Bearer: "tok"}), nil, nil); err == nil {
		t.Fatal("a redirect is an error")
	}
	if hits.Load() != 0 {
		t.Error("a credential must never follow a redirect to another host")
	}
}
