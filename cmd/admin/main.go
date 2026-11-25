// Command admin is the platform admin backend (ADR-0013): a stateless service with no database.
// This file only wires configuration, clients and the HTTP server together.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/logx"

	"github.com/hostryhq/svc-admin/api"
	"github.com/hostryhq/svc-admin/internal/config"
	"github.com/hostryhq/svc-admin/repository"
	"github.com/hostryhq/svc-admin/service"
	"github.com/hostryhq/svc-admin/upstream"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "admin:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	log := logx.New(os.Stdout, level, "admin")

	key, err := loadKey(cfg.ServiceKeyFile)
	if err != nil {
		return err
	}
	up, err := upstream.New(upstream.Config{
		IdentityURL: cfg.IdentityURL, TenancyURL: cfg.TenancyURL, Timeout: cfg.UpstreamTimeout,
		Signer: &auth.ServiceSigner{Name: "admin", Key: key},
	})
	if err != nil {
		return err
	}
	svc := service.New(
		service.Config{IdleTimeout: cfg.IdleTimeout, AbsoluteTimeout: cfg.AbsoluteTimeout},
		service.Deps{Upstream: up, Sessions: repository.NewMemorySessions(), Log: log},
	)
	h := api.New(api.Options{
		Service: svc, PublicOrigin: cfg.PublicOrigin, ClientIPHeader: cfg.ClientIPHeader, StaticDir: cfg.StaticDir,
		Ready: map[string]func(context.Context) error{"upstream": up.Ping},
		Log:   log,
	})
	srv := &http.Server{
		Addr: cfg.Listen, Handler: h.Routes(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go sweep(ctx, svc)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("admin listening", "addr", cfg.Listen)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// sweep drops dead sessions once a minute.
func sweep(ctx context.Context, svc *service.Service) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			svc.SweepExpired()
		}
	}
}

// loadKey reads the admin service-token signing key (a deploy secret, referenced by path).
func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read the service key file")
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("the service key file holds no PEM block")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		key, _ = k.(*ecdsa.PrivateKey)
	}
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("the service key must be an EC P-256 private key")
	}
	return key, nil
}
