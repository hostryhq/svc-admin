// Command admin-double serves the admin API double (package double) as a local process, for
// admin-web's development and tests. It is example-driven, keeps no data and needs no
// configuration beyond the flags below. It is never deployed.
//
//	go run ./cmd/admin-double -addr 127.0.0.1:8081 -static ../admin-web/dist
//
// Pre-authenticated session: cookie __Host-hostry-admin=double-seed-session (platform_admin),
// CSRF token csrf_example_token. Sign-in accounts: staff@example.invalid (support role) and
// platform@example.invalid (platform admin), password correct-horse-battery-staple, TOTP 123456.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hostryhq/svc-admin/api"
	"github.com/hostryhq/svc-admin/double"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8081", "listen address")
	origin := flag.String("origin", "", "the one accepted Origin (default: the request's own host)")
	static := flag.String("static", "", "admin-web build directory to serve at /")
	flag.Parse()

	opt := double.Options{Origin: *origin}
	if *static != "" {
		if _, err := os.Stat(*static); err != nil {
			fmt.Fprintln(os.Stderr, "admin-double: cannot read the static directory")
			os.Exit(1)
		}
		opt.StaticHandler = api.StaticHandler(*static)
	}
	srv := &http.Server{Addr: *addr, Handler: double.New(opt), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("admin-double listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
