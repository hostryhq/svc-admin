// Package config loads the admin service's configuration from the environment (12-factor) and
// validates it at startup. There is no database setting: the service holds no database
// credential of any kind (ADR-0013 V1, test AD7). The service-token signing key is a deploy
// secret, referenced by file path and never read from a variable's value.
package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	gc "github.com/hostryhq/go-common/config"
)

// Config is the validated configuration.
type Config struct {
	Listen          string        // ADMIN_LISTEN (default :8080)
	PublicOrigin    string        // ADMIN_PUBLIC_ORIGIN: the one origin admin-web and the API share
	IdentityURL     string        // ADMIN_IDENTITY_URL
	TenancyURL      string        // ADMIN_TENANCY_URL
	ServiceKeyFile  string        // ADMIN_SERVICE_KEY_FILE: PEM ES256 private key of the admin service token
	StaticDir       string        // ADMIN_STATIC_DIR: admin-web build, optional
	ClientIPHeader  string        // ADMIN_CLIENT_IP_HEADER: trusted proxy header, optional
	IdleTimeout     time.Duration // ADMIN_IDLE_TIMEOUT (default 30m)
	AbsoluteTimeout time.Duration // ADMIN_ABSOLUTE_TIMEOUT (default 12h)
	UpstreamTimeout time.Duration // ADMIN_UPSTREAM_TIMEOUT (default 5s)
	LogLevel        string        // ADMIN_LOG_LEVEL (default info)
}

// Load reads and validates the configuration; every problem is reported at once and no value
// is echoed in an error.
func Load(lookup gc.Lookup) (Config, error) {
	l := gc.New(lookup)
	c := Config{
		Listen:          l.String("ADMIN_LISTEN", ":8080"),
		PublicOrigin:    strings.TrimRight(l.Required("ADMIN_PUBLIC_ORIGIN"), "/"),
		IdentityURL:     l.Required("ADMIN_IDENTITY_URL"),
		TenancyURL:      l.Required("ADMIN_TENANCY_URL"),
		ServiceKeyFile:  l.Required("ADMIN_SERVICE_KEY_FILE"),
		StaticDir:       l.String("ADMIN_STATIC_DIR", ""),
		ClientIPHeader:  l.String("ADMIN_CLIENT_IP_HEADER", ""),
		IdleTimeout:     l.Duration("ADMIN_IDLE_TIMEOUT", 30*time.Minute),
		AbsoluteTimeout: l.Duration("ADMIN_ABSOLUTE_TIMEOUT", 12*time.Hour),
		UpstreamTimeout: l.Duration("ADMIN_UPSTREAM_TIMEOUT", 5*time.Second),
		LogLevel:        l.String("ADMIN_LOG_LEVEL", "info"),
	}
	if err := l.Err(); err != nil {
		return Config{}, err
	}
	var problems []string
	if !originOK(c.PublicOrigin) {
		problems = append(problems, "ADMIN_PUBLIC_ORIGIN must be an https origin (http only for localhost), with no path")
	}
	for name, v := range map[string]string{"ADMIN_IDENTITY_URL": c.IdentityURL, "ADMIN_TENANCY_URL": c.TenancyURL} {
		if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			problems = append(problems, name+" must be an http(s) URL")
		}
	}
	if c.IdleTimeout <= 0 || c.AbsoluteTimeout < c.IdleTimeout {
		problems = append(problems, "ADMIN_IDLE_TIMEOUT must be positive and not exceed ADMIN_ABSOLUTE_TIMEOUT")
	}
	if c.UpstreamTimeout <= 0 {
		problems = append(problems, "ADMIN_UPSTREAM_TIMEOUT must be positive")
	}
	if len(problems) > 0 {
		return Config{}, fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return c, nil
}

func originOK(o string) bool {
	u, err := url.Parse(o)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}
