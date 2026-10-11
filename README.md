# Traefik Gateway Plugin

Traefik middleware plugin for the FileConvert API gateway. Handles JWT authentication, rate limiting, admin access control, and service integrations.

## Features

- **JWT validation (dual-issuer)** — legacy HS256 tokens issued by identity-service (shared secret), plus Keycloak RS256 tokens (JWKS, per-`kid` key cache) for apps listed in `keycloakApps`; rejects expired/tampered tokens, fails closed
- **Policy authorization** (`authorizationMode: policy`, `authz.go`/`policy.go`) — the principal's Keycloak roles resolve through the registry snapshot's role bindings to policies; a request passes when a statement grants the endpoint's `required_permission` on the target application. The target application is a validated inbound `X-App-Id` (operator consoles) or the host's app. `X-Is-Admin` is derived from a literal `*` grant. `GET /api/_iam/me` is answered by the plugin. See "Policy authorization" below.
- **Admin access control (legacy engine)** — `authorizationMode: legacy` (default): endpoints marked `admin` in the registry require an admin role (`keycloakAdminRoles` for Keycloak tokens, identity-service for HS256); the policy verdict is still computed and logged as `shadow=`
- **Rate limiting** — fixed-window limiter backed by Redis, per-user or per-session, plan-aware limits from service-service snapshot
- **Registry snapshot** — polls service-service for endpoint metadata (access levels, rate limits per plan)
- **Plan resolution** — resolves user's plan tier via service-service customer rate-tier endpoint, scoped per `(app_id, user_id)`
- **App resolution (multi-app)** — derives a trusted `X-App-Id` from the request host via application-service's registry snapshot, strips any inbound client copy, and rejects unknown/inactive hosts (default `enforce` mode — see below). Plan/admin/rate-limit/endpoint lookups are app-scoped.
- **Downstream headers** — forwards `X-User-Id`, `X-User-Plan`, `X-Is-Admin`, `X-User-Roles`, `X-App-Id`, `X-Api-Key-Uid` to backend services, plus `X-User-Uid` (Keycloak `sub`, Keycloak path only). All seven are the configurable-name fields on `Config` (defaults set in `CreateConfig()`, `config.go`) and are **unconditionally stripped from the inbound request at `ServeHTTP` entry** (`plugin.go`, before any auth/routing logic runs) so a client-supplied copy can never survive — the plugin only ever re-stamps from data it validated itself. `X-Is-Admin` / `X-User-Roles` are stamped on **every JWT-authenticated request** (public endpoints included), so a backend can offer admin-only behaviour on a public route; on public endpoints the identity lookup fails soft (headers absent, request still forwarded, failure negatively cached for 10s). **The API-key auth path never sets `X-Is-Admin` / `X-User-Roles`** — see "API-key authentication" below.
- **Unregistered endpoints pass through untouched** — if the request doesn't match any endpoint in the service-service registry snapshot (scoped to the resolved app), the plugin does **zero** enforcement (no auth check, no rate limiting, no header stamping) and forwards straight to the next handler, leaving 404 handling to Traefik's own routing. This is open-by-default for any path the registry doesn't know about — only registered endpoints get gateway enforcement.

## Request Flow

```
Client → Nginx LB (TLS) → Traefik + Plugin → Backend Service
                                 │
        ┌──────────────┬─────────┼──────────────┬──────────────┐
        │              │         │              │              │
 application-service  service-service   identity-service     Redis
 (host→app_id)       (snapshot/plan)   (admin check)     (rate limits)
```

The plugin resolves `app_id` from the request host first (Step 1a): it unconditionally
strips any inbound `X-App-Id`, looks the host up in the cached registry snapshot, and on a
match stamps the trusted `X-App-Id`. CORS preflight is handled before this so it succeeds
even for unmapped hosts.

## Configuration

All options are configurable via the Traefik Middleware CRD (see `helm/middleware.yaml`).

| Key | Default | Description |
|-----|---------|-------------|
| `jwtSecret` | — | HMAC secret for JWT verification (legacy HS256 path — all apps not in `keycloakApps`) |
| `jwtIssuer` | `file-convert.online` | Expected JWT issuer (HS256 path) |
| `keycloakApps` | `[]` | app_ids validated on the Keycloak RS256/JWKS path (e.g. `[scantinel]`). Empty = Keycloak path disabled entirely |
| `keycloakJwksUrl` | — | Realm JWKS endpoint (or OIDC discovery URL; `jwks_uri` is followed). Required when `keycloakApps` is set |
| `keycloakIssuer` | — | Expected `iss`, byte-for-byte (realm public URL). Required when `keycloakApps` is set |
| `keycloakRealms` | `[]` | Per-app realms: list of `{appId, issuer, jwksUrl, acceptLegacy}`. Makes `appId` a Keycloak app validated against ITS realm (overrides the scalar realm for that app). `acceptLegacy: true` also accepts legacy HS256 identity-service tokens for that app (dispatch by token `alg`; each validator still pins its algorithm) — the migration window. Older plugin builds ignore this key |
| `userUidHeader` | `X-User-Uid` | Stamped with the Keycloak `sub` (UUID) on the Keycloak path only; always stripped inbound |
| `userEmailHeader` | _(empty = inert)_ | When set (e.g. `X-User-Email`): always stripped inbound; stamped only on the Keycloak path from `email` when `email_verified` is `true`. Enabled per env in the Middleware |
| `keycloakUserIdClaim` | `luid` | Claim stamped into `X-User-Id` (legacy_user_id mapper), falling back to `sub` |
| `keycloakAdminRoles` | `admin, owner` | **Legacy engine only.** Token roles (azp client roles + realm roles) implying `X-Is-Admin: true`. Ignored under `authorizationMode: policy` (admin is a `*` grant) |
| `operatorRealm` | _(none)_ | `{issuer, jwksUrl}` of the platform operators' realm (the console's `infra` realm). Accepted on EVERY application next to the app's own realm; what the token may do is decided by policy. Validator is picked by exact `iss` match |
| `authorizationMode` | `legacy` | `legacy` = today's engine (host-pinned app, `token.app_id == host app`, admin role list) plus a `shadow=allow|deny` log line with the policy verdict; `policy` = policy engine (requested app via `X-App-Id`, bindings → statements, derived `X-Is-Admin`, `/api/_iam/me`). Rollback is this one key |
| `keycloakClockSkewSeconds` | `30` | Leeway for exp/nbf/iat validation on the Keycloak path |
| `jwksRefreshInterval` | `10m` | Background JWKS refresh period |
| `jwksRefetchCooldown` | `30s` | Min interval between on-demand JWKS refetches triggered by unknown `kid`s |
| `sessionIdHeader` | `X-Session-Id` | Header for anonymous session identity |
| `deviceIdHeader` | `X-Device-Id` | FingerprintJS visitor id; preferred anonymous rate-limit key |
| `redisUrl` | `redis://127.0.0.1:6379/0` | Redis connection URL |
| `redisPrefix` | `gw:rl:` | Key prefix for rate limit counters |
| `serviceServiceUrl` | `http://service-service:8080` | Service registry URL |
| `applicationServiceUrl` | `http://application-service:8080` | Application registry URL (host→app_id snapshot) |
| `appSnapshotRefreshInterval` | `30s` | Periodic full refresh of the app registry snapshot |
| `appSnapshotVersionPollInterval` | `5s` | Cheap version poll interval for the app registry |
| `appIdHeader` | `X-App-Id` | Trusted, gateway-stamped app id header (inbound copies stripped) |
| `appResolutionMode` | `enforce` | `enforce` (**default**; unknown/inactive host → 403, cold registry → 503 — there are NO endpoints allowed without a resolved app_id), `permissive` (pass through, no stamp — local/debug only, do not use in production), or `disabled` (skip resolution — local single-app dev only) |
| `trustForwardedHost` | `false` | When true resolve from `X-Forwarded-Host`; otherwise from `req.Host` |
| `identityServiceUrl` | `http://identity-service:8080` | Identity service URL |
| `identityVerifyUrl` | `http://identity-service:8080/internal/v1/api-keys/verify` | Internal API-key verify endpoint (contract §4). Not registry-registered; full in-cluster path. Verify call is capped at ≤2s; identity unreachable → 503 for key traffic only |
| `apiKeyUidHeader` | `X-Api-Key-Uid` | Trusted, gateway-stamped API-key uid header (inbound copies stripped on every path) |
| `usageServiceUrl` | `http://usage-service:8080` | Usage service URL |
| `defaultRateLimitRequests` | `30` | Fallback rate limit |
| `defaultRateLimitDurationSeconds` | `60` | Fallback window |
| `defaultPlanName` | `free` | Plan for anonymous users |
| `adminAccessLevel` | `admin` | Legacy engine only: access level name implying `adminPermission`. The policy engine reads only `required_permission` (the registry resolves the fallback) |
| `httpTimeout` | `5s` | Timeout for upstream HTTP calls |
| `disableRateLimit` | `false` | Skip rate limiting (debug) |
| `disableAuth` | `false` | Skip JWT validation (debug) |
| `corsAllowedOrigins` | `[]` | Allowed CORS origins. Supports exact strings and `https://*.domain` wildcard subdomain patterns. Leave empty to disable plugin-level CORS (not recommended). |
| `corsAllowedMethods` | `GET POST PUT PATCH DELETE OPTIONS` | Comma-separated list of allowed HTTP methods |
| `corsAllowedHeaders` | `Origin Content-Type Accept Authorization X-Session-Id X-Device-Id X-App-Id` | Allowed request headers |
| `corsAllowCredentials` | `true` | Sets `Access-Control-Allow-Credentials` |
| `corsMaxAge` | `3600` | Preflight cache TTL in seconds |

## API-key authentication (`apikey.go`)

Requests may authenticate with a static API key instead of a JWT. Format:
`fc_<env>_<uid>_<secret>` (a fixed 4-part, underscore-delimited credential). The key is read
from the `X-Api-Key` header, or from `Authorization: Bearer` when its value starts with the
`fc_` prefix (`X-Api-Key` takes precedence). When a key is present, the plugin takes this path
**instead of** JWT parsing — it jumps straight to rate limiting, skipping JWT parsing,
cross-app JWT replay checks, and RBAC.

Verification is Redis cache-first (positive results cached 60s, negative 10s; only the key's
hash is cached, never the raw secret), falling back to a `POST` to identity-service's internal
`/internal/v1/api-keys/verify` endpoint with a hard ≤2s timeout. Any transport error **fails
closed** (503) — it is never treated as open/anonymous.

On success the plugin stamps `X-User-Id` and `X-Api-Key-Uid` (and `X-User-Plan` when the
verify response includes one) and rate-limits by key uid. **It never sets `X-Is-Admin` or
`X-User-Roles`** (explicit in-code comment at the stamping site: "Stamp trusted headers. NEVER
X-Is-Admin / X-User-Roles on this path.") — API keys carry no admin capability, and
permission-gated (RBAC) endpoints unconditionally deny API-key auth regardless of the key's
owner.

## Rate limiting (`ratelimit.go`)

The limiter is a **fixed-window counter**, not a sliding-window or token-bucket algorithm:
each check does a Redis `INCR` on the window's key followed by `EXPIRE` to seed the window
TTL on first hit. This means a client can burst up to 2x the configured limit across a window
boundary (e.g. near the end of one window and the start of the next) — a known fixed-window
trade-off, not a bug. Limits are sourced per-endpoint-per-plan from the service-service
registry snapshot, falling back to `defaultRateLimitRequests` / `defaultRateLimitDurationSeconds`
when the endpoint has no plan-specific limit configured.

## Policy authorization (`authorizationMode: policy`)

The registry snapshot carries `policies` (named lists of allow statements
`{actions, apps}`) and `bindings` (qualified role → policy). Statement grammar:

```
action  "*" | "<resource>.*" | "<resource>.<action>" | "authenticated"
app     "*" | "@home" (the application the token was issued for) | <app id>
role    "<azp client id>:<role>" for client roles, bare for realm roles
```

Per request:

1. **Target application** = validated inbound `X-App-Id` (must be an active app, else
   `403 unknown_app`), else the host's application. The header is re-stamped with the
   authorized value; a route registered for the host app but not exposed to the target is
   refused (`403`, `reason=endpoint_not_exposed`), never passed through.
2. **Credential**: HS256 only on non-Keycloak / `acceptLegacy` apps; RS256 validated by
   the realm whose `iss` the token carries, out of {target app's realm, `operatorRealm`}.
   Any other issuer → `401` (`reason=issuer_rejected`). No replay guard: scope is policy.
3. **Principal**: Keycloak subject, user id, `app_id` claim as home application, qualified
   roles → bound policies → statements. Legacy HS256 principals get a synthetic set from
   identity-service `/authz` (permissions on `@home`, `is_admin` ⇒ `*` on `@home`).
   API keys get `authenticated` on their bound application.
4. **Evaluation**: `required_permission` empty → open; no token → `401 reason=no_token`;
   no statement grants it on the target → `403 reason=no_matching_statement`.
   `authenticated` is granted only by `*` or the literal `authenticated`.
5. **Headers**: `X-App-Id` (target), `X-User-Id`, `X-User-Uid`, `X-User-Email` (if
   enabled), `X-User-Plan`, `X-User-Roles` (bound roles only), `X-Is-Admin: true` only for
   a literal `*` grant on the target application.
6. **Owner gate** on the derived admin header; **rate limit** keyed by the target
   application, `*` holders exempt there.
7. `GET /api/_iam/me` → `{subject, user_id, home_app, roles, policies,
   permissions_by_app}` for any authenticated principal (401 otherwise); never forwarded.

Every 401/403 logs one line with `reason=` (`no_token`, `issuer_rejected`,
`unknown_app`, `no_matching_statement`, `owner_mismatch`, `endpoint_not_exposed`).
Under `legacy` the same evaluation is logged as `shadow=allow|deny … unbound_role=[…]`
without affecting the verdict, so bindings can be verified before flipping the mode.

Cutover order: service-service with the policy API → seed bindings → Traefik image with
`authorizationMode: legacy` + `operatorRealm` → watch `shadow=` → flip to `policy`.
Rollback is `authorizationMode: legacy` (config only).

## Dual-issuer auth (Keycloak)

Per the Keycloak migration plan (`SecScanApp/plans/02-keycloak-auth-migration.md` §2), the
gateway supports two token issuers side by side. Dispatch happens **after** host→app_id
resolution:

- `app_id ∈ keycloakApps` (e.g. `scantinel`) → **RS256 + JWKS** validation: signature key
  selected by the token's `kid` from the cached realm JWKS, `iss` must equal
  `keycloakIssuer` exactly, exp/nbf/iat checked with `keycloakClockSkewSeconds` leeway.
  The `app_id` claim (hardcoded per-client protocol mapper) is REQUIRED and the existing
  cross-app replay check (`token.app_id == host app_id`) runs unchanged.
- every other app (fileconvert, …) → the **HS256 shared-secret** path, byte-for-byte
  unchanged.

Each path pins its algorithm (`WithValidMethods`), so an HS256 token can never validate on
the Keycloak path or vice versa (alg-confusion guard in both directions).

Downstream header contract is frozen: `X-User-Id` (claim `keycloakUserIdClaim`, default
`luid`, falling back to `sub`), `X-App-Id` (host registry, unchanged), `X-Is-Admin` /
`X-User-Roles` (from token roles: `resource_access[azp].roles` + `realm_access.roles` — no
identity-service round-trip for Keycloak tokens), `X-User-Plan` (service-service rate-tier,
unchanged).

JWKS handling: keys cached by `kid`; unknown `kid` triggers an on-demand refetch (rotation
pickup) rate-limited by `jwksRefetchCooldown`; a background refresh runs every
`jwksRefreshInterval`; on fetch failure the last-good key set keeps serving, so a Keycloak
outage does not invalidate existing sessions (only new logins/refreshes fail, at Keycloak).

**Yaegi note:** the JWKS client is hand-rolled on stdlib only (`net/http`,
`encoding/json`, `encoding/base64`, `math/big`, `crypto/rsa`) — no JOSE library — because
the plugin runs interpreted. RS256 verification itself is done by the already-vendored
`golang-jwt/jwt/v5`, whose full package (including `rsa.go`) is already interpreted by
Yaegi today for the HS256 path. Still, smoke-test on a dev cluster before relying on it.

### infra-gitops requirements (dev + prod middleware manifests)

```yaml
keycloakJwksUrl: "http://keycloak-service.keycloak.svc:8080/realms/platform/protocol/openid-connect/certs"
keycloakIssuer: "https://auth.internal.cloudfusion.tech/realms/platform"   # MUST match token `iss` exactly
keycloakApps: ["scantinel"]
keycloakUserIdClaim: "luid"
keycloakAdminRoles: ["admin", "owner"]   # legacy engine only
operatorRealm:
  issuer: "https://auth.internal.cloudfusion.tech/realms/infra"
  jwksUrl: "http://keycloak-service.keycloak.svc:8080/realms/infra/protocol/openid-connect/certs"
authorizationMode: "legacy"              # flip to "policy" after bindings are seeded
keycloakClockSkewSeconds: 30
jwksRefreshInterval: "10m"
jwksRefetchCooldown: "30s"
```

Also required in infra-gitops:

1. **NetworkPolicy**: traefik pods → `keycloak-service.keycloak.svc:8080` (JWKS fetch).
2. **Issuer/hostname coupling**: `keycloakIssuer` must equal the realm's public frontend
   URL. If/when the public auth hostname decision (plan §0 prerequisite) moves Keycloak to
   `auth.cloudfusion.tech`, update `keycloakIssuer` in the same change.
3. **Realm prerequisites** (plan Appendix A): `scantinel-web` client with the
   `oidc-hardcoded-claim-mapper` for `app_id=scantinel`, the `luid` user-attribute mapper,
   and client roles `admin`/`owner`.
4. Rollback: set `keycloakApps: []` (or drop the block) — the plugin reverts to
   HS256-only behaviour; no image change needed.

## Deployment

### Option A: Local plugin (volume mount)

Mount the plugin source at `/plugins-local/src/github.com/fileconvert/traefik-gateway-plugin/` and add:

```
--experimental.localplugins.gateway.modulename=github.com/fileconvert/traefik-gateway-plugin
```

### Option B: Custom Traefik image

```bash
docker build -t traefik-custom:latest .
```

## Testing

```bash
go test ./...
```

## Identity Service Requirement

The plugin expects a `GET /v1/user/:id/admin-status` endpoint on identity-service returning:

```json
{"status": "success", "data": {"is_admin": true}}
```

### X-User-Id for Keycloak principals

Every platform backend parses `X-User-Id` as a positive int64. For Keycloak-issued tokens the
plugin takes `keycloakUserIdClaim` (default `luid`) when it already is such an integer (migrated
fileconvert users) and otherwise derives a stable positive int64 from `sub`: FNV-1a 64 over the
UTF-8 bytes, top bit cleared, 0 → 1 (`deriveUserID` in `jwt.go`). **Cross-repo contract:**
`scantinel-website` performs the identical derivation when it calls its services in-cluster
(`src/lib/user-id.ts`); the shared vector is `00000000-0000-0000-0000-000000000000` →
`8950988243607919089`. Change both or neither.
