package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func valid() map[string]string {
	return map[string]string{
		"ADMIN_PUBLIC_ORIGIN":    "https://admin.example.invalid",
		"ADMIN_IDENTITY_URL":     "http://identity.internal:8080",
		"ADMIN_TENANCY_URL":      "http://tenancy.internal:8080",
		"ADMIN_SERVICE_KEY_FILE": "/run/secrets/admin-service-key.pem",
	}
}

// AD7: the service starts with no database credential, and nothing in its configuration names one.
func TestStartsWithNoDatabaseCredential(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.IdleTimeout != 30*time.Minute || c.AbsoluteTimeout != 12*time.Hour || c.UpstreamTimeout != 5*time.Second {
		t.Errorf("defaults: %+v", c)
	}
	// even with database settings in the environment, the service reads none of them
	m := valid()
	m["DATABASE_URL"], m["PGPASSWORD"] = "postgres://x", "x"
	if _, err := Load(env(m)); err != nil {
		t.Fatal(err)
	}
}

func TestEveryProblemIsReportedAtOnceWithoutEchoingValues(t *testing.T) {
	m := map[string]string{
		"ADMIN_PUBLIC_ORIGIN": "http://admin.example.invalid", // plain http on a real host
		"ADMIN_IDENTITY_URL":  "ftp://nope",
	}
	_, err := Load(env(m))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"ADMIN_TENANCY_URL", "ADMIN_SERVICE_KEY_FILE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s: %v", want, err)
		}
	}

	m = valid()
	m["ADMIN_PUBLIC_ORIGIN"] = "http://admin.example.invalid"
	m["ADMIN_IDLE_TIMEOUT"] = "1h"
	m["ADMIN_ABSOLUTE_TIMEOUT"] = "30m"
	_, err = Load(env(m))
	if err == nil || !strings.Contains(err.Error(), "ADMIN_PUBLIC_ORIGIN") || !strings.Contains(err.Error(), "ADMIN_IDLE_TIMEOUT") {
		t.Fatalf("both problems should be reported: %v", err)
	}
	if strings.Contains(err.Error(), "admin.example.invalid") {
		t.Error("values must not be echoed")
	}
}

func TestOriginMustBeHTTPSExceptForLocalhost(t *testing.T) {
	for origin, ok := range map[string]bool{
		"https://admin.example.invalid":      true,
		"https://admin.example.invalid/":     true,
		"http://localhost:8080":              true,
		"http://127.0.0.1:8080":              true,
		"http://admin.example.invalid":       false,
		"https://admin.example.invalid/path": false,
		"https://user@admin.example.invalid": false,
		"admin.example.invalid":              false,
	} {
		m := valid()
		m["ADMIN_PUBLIC_ORIGIN"] = origin
		_, err := Load(env(m))
		if (err == nil) != ok {
			t.Errorf("origin %q: accepted=%v, want %v (%v)", origin, err == nil, ok, err)
		}
	}
}
