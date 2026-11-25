// Package contract runs the shared admin contract suite (api-specs/contracttest) against the real
// service, wired to in-process fakes of identity and tenancy, and against its double. Both must
// pass: a double that fails the suite is a bug in the double.
package contract

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hostryhq/api-specs/contracttest"

	"github.com/hostryhq/svc-admin/double"
	"github.com/hostryhq/svc-admin/internal/testenv"
)

func TestRealServiceAgainstFakes(t *testing.T) {
	env := testenv.New(t)
	h := http.Header{}
	h.Set("Origin", env.Origin)
	contracttest.Run(t, contracttest.Options{
		SpecPath: testenv.AdminSpecPath(t),
		BaseURL:  env.Origin,
		Client:   &http.Client{Transport: &testenv.ContractTransport{Env: env}},
		Header:   h,
		// Each operation runs in the example world its x-example-world names.
		SeedWorld: env.SeedWorld,
	})
}

func TestDoubleServesTheContractAndItsExamples(t *testing.T) {
	dbl := double.New(double.Options{})
	srv := httptest.NewServer(dbl)
	defer srv.Close()
	h := http.Header{}
	h.Set("Origin", srv.URL)
	h.Set("Cookie", double.CookieName+"="+double.SeedCookie)
	contracttest.Run(t, contracttest.Options{
		SpecPath: testenv.AdminSpecPath(t), BaseURL: srv.URL, Header: h, ExpectExamples: true,
		SeedWorld: dbl.SeedWorld,
	})
}
