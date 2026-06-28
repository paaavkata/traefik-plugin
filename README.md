# Traefik Gateway Plugin

Traefik middleware plugin for the FileConvert API gateway. Handles JWT authentication, rate limiting, admin access control, and service integrations.

## Features

- **JWT validation** — decodes HS256 tokens issued by identity-service, rejects expired/tampered tokens
- **Admin access control** — endpoints marked `admin` in the registry require admin role (checked via identity-service)
- **Rate limiting** — fixed-window limiter backed by Redis, per-user or per-session, plan-aware limits from service-service snapshot
- **Registry snapshot** — polls service-service for endpoint metadata (access levels, rate limits per plan)
- **Plan resolution** — resolves user's plan tier via service-service customer rate-tier endpoint, scoped per `(app_id, user_id)`
- **App resolution (multi-app)** — derives a trusted `X-App-Id` from the request host via application-service's registry snapshot, strips any inbound client copy, and rejects unknown/inactive hosts (in `enforce` mode). Plan/admin/rate-limit/endpoint lookups are app-scoped.
- **Downstream headers** — forwards `X-User-Id`, `X-User-Plan`, `X-Is-Admin`, `X-App-Id` to backend services

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
| `jwtSecret` | — | HMAC secret for JWT verification |
| `jwtIssuer` | `file-convert.online` | Expected JWT issuer |
| `sessionIdHeader` | `X-Session-Id` | Header for anonymous session identity |
| `deviceIdHeader` | `X-Device-Id` | FingerprintJS visitor id; preferred anonymous rate-limit key |
| `redisUrl` | `redis://127.0.0.1:6379/0` | Redis connection URL |
| `redisPrefix` | `gw:rl:` | Key prefix for rate limit counters |
| `serviceServiceUrl` | `http://service-service:8080` | Service registry URL |
| `applicationServiceUrl` | `http://application-service:8080` | Application registry URL (host→app_id snapshot) |
| `appSnapshotRefreshInterval` | `30s` | Periodic full refresh of the app registry snapshot |
| `appSnapshotVersionPollInterval` | `5s` | Cheap version poll interval for the app registry |
| `appIdHeader` | `X-App-Id` | Trusted, gateway-stamped app id header (inbound copies stripped) |
| `appResolutionMode` | `permissive` | `enforce` (unknown/inactive host → 403, cold registry → 503), `permissive` (pass through, no stamp), or `disabled` (skip resolution) |
| `trustForwardedHost` | `false` | When true resolve from `X-Forwarded-Host`; otherwise from `req.Host` |
| `identityServiceUrl` | `http://identity-service:8080` | Identity service URL |
| `usageServiceUrl` | `http://usage-service:8080` | Usage service URL |
| `defaultRateLimitRequests` | `30` | Fallback rate limit |
| `defaultRateLimitDurationSeconds` | `60` | Fallback window |
| `defaultPlanName` | `free` | Plan for anonymous users |
| `adminAccessLevel` | `admin` | Access level name for admin endpoints |
| `httpTimeout` | `5s` | Timeout for upstream HTTP calls |
| `disableRateLimit` | `false` | Skip rate limiting (debug) |
| `disableAuth` | `false` | Skip JWT validation (debug) |
| `corsAllowedOrigins` | `[]` | Allowed CORS origins. Supports exact strings and `https://*.domain` wildcard subdomain patterns. Leave empty to disable plugin-level CORS (not recommended). |
| `corsAllowedMethods` | `GET POST PUT PATCH DELETE OPTIONS` | Comma-separated list of allowed HTTP methods |
| `corsAllowedHeaders` | `Origin Content-Type Accept Authorization X-Session-Id X-Device-Id X-App-Id` | Allowed request headers |
| `corsAllowCredentials` | `true` | Sets `Access-Control-Allow-Credentials` |
| `corsMaxAge` | `3600` | Preflight cache TTL in seconds |

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
