# svc-admin

The platform admin backend (ADR-0013): vendor-staff sign-in, the browser session, organisation onboarding, support sessions and the vendor audit view. It is the only thing `admin-web` talks to. It has **no database**: sessions and the tokens held against them live in the memory of one instance, and a restart signs everyone out.

What it does, in one line each:

- **Browser side.** An opaque session id in a `__Host-hostry-admin` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`), a per-session CSRF token on every state-changing request plus a matching `Origin`, an idle timeout (default 30 minutes) and an absolute one (default 12 hours). CORS is off, a bearer token of any realm is refused, and **no token ever reaches the browser**.
- **Service side.** One named operation per panel need, built on generated `identity`, `tenancy` and `billing` clients (no pass-through). Every upstream call carries the `admin` service token and the staff member's vendor token (or, for support-view reads, the support token). The browser's `Idempotency-Key` is passed down; the owning services record each vendor action in their own transaction, so this service writes no audit record and cannot skip one.
- **Onboarding.** `createOrganisation` asks tenancy to create the organisation, then identity to create the owner invitation, with the same key. If identity fails the answer is `incomplete` (the organisation exists, harmless); replaying the request completes it. The owner's mobile number passes through memory only.
- **Approved actions.** Approving suspend, reinstate, close or a tax rule-set publication returns a single-use grant that stays in the approver's session in memory and goes to tenancy or billing in `Hostry-Vendor-Approval`; the approval executes in the same request, and the named operations with `approval_id` are the retry (409 `approval_not_executable` with a reason).
- **Answers.** Every answer is decoded into the admin contract's closed types and checked against a deny list (full mobile number, customer email, key material, tokens) before it is sent.

Contract: `api-specs/openapi/admin/v1`. Which operations exist and what they call: [`docs/operations-status.md`](docs/operations-status.md).

## Layout

```
cmd/admin/            wiring only
cmd/admin-double/     the double as a local process, for admin-web development
cmd/genspec/          extracts operations and examples from the bundled specs (make gen)
api/                  controller layer: cookie, CSRF, Origin, decoding, deny list, problems, static files
service/              rules: sessions, tokens, onboarding, support sessions, the allowlisted operations
repository/           in-memory session and idempotency stores (no database)
upstream/             the only way to reach identity and tenancy (generated clients + credentials + retry)
double/               the admin API double (importable; verified by the shared contract suite)
internal/gen/         generated from api-specs (committed): identity, tenancy, billing (client), admin (types, server)
internal/specdata/    operations and examples extracted from the specs (committed)
internal/fakeup/      in-process fakes of identity, tenancy and billing generated from their specs (tests)
internal/testenv/     the service wired to those fakes with real go-auth verification (tests)
contract/             the shared contract suite, run against the real service and against the double
```

## Run

Configuration is environment only; startup fails fast and lists every problem (values are never echoed).

| Variable | Meaning | Default |
|---|---|---|
| `ADMIN_PUBLIC_ORIGIN` | The one origin `admin-web` and the API share (https; http only for localhost) | required |
| `ADMIN_IDENTITY_URL`, `ADMIN_TENANCY_URL`, `ADMIN_BILLING_URL` | Base URLs of the services | required |
| `ADMIN_SERVICE_KEY_FILE` | PEM file with the ES256 key of the `admin` service token (a deploy secret, by reference) | required |
| `ADMIN_LISTEN` | Listen address | `:8080` |
| `ADMIN_STATIC_DIR` | `admin-web` build directory, served at `/` (same origin) | off |
| `ADMIN_CLIENT_IP_HEADER` | Trusted proxy header carrying the client address (last value is used) | remote address |
| `ADMIN_IDLE_TIMEOUT`, `ADMIN_ABSOLUTE_TIMEOUT` | Session limits | `30m`, `12h` |
| `ADMIN_UPSTREAM_TIMEOUT` | Timeout of each upstream call | `5s` |
| `ADMIN_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` |

There is no database setting. `/healthz` is liveness, `/readyz` checks that identity, tenancy and billing answer. No deployment exists in Phase 1 (AM12); everything runs as local processes and in CI.

## Test

```
make test                 # go test -race ./...
make vet && make lint     # make lint-tool installs the pinned golangci-lint
```

- Unit and API tests run the service against in-process fakes of identity, tenancy and billing that are generated from their OpenAPI documents (`internal/fakeup`). The fakes verify the real `go-auth` credentials, so a call without the service token or with the wrong token type is refused as the real service would.
- `contract/` runs the shared suite (`api-specs/contracttest`) against the real service and against `double/` (with the spec's examples required). A later integration step wires the real identity and tenancy doubles in place of the fakes.
- The double for `admin-web`: `go run ./cmd/admin-double -static ../admin-web/dist` (cookie `__Host-hostry-admin=double-seed-session`, CSRF `csrf_example_token`; accounts and failure injection in the package doc).

## Regenerate the clients

`make gen` bundles the specs from a checkout of `api-specs` (default `../api-specs`), regenerates `internal/gen` and `internal/specdata` with the pinned `oapi-codegen`, and records the api-specs commit in `internal/gen/API_SPECS_COMMIT`. Generated code is never edited by hand.

Private modules (`go-common`, `go-auth`, `api-specs`) need `GOPRIVATE` set to the hostryhq organisation's modules; for unmerged branches use an uncommitted `go.work` (git-ignored).
