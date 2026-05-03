# Traefik Gateway Plugin

Traefik middleware plugin for the FileConvert API gateway. Handles JWT authentication, rate limiting, admin access control, and service integrations.

## Features

- **JWT validation** — decodes HS256 tokens issued by identity-service, rejects expired/tampered tokens
- **Admin access control** — endpoints marked `admin` in the registry require admin role (checked via identity-service)
- **Rate limiting** — fixed-window limiter backed by Redis, per-user or per-session, plan-aware limits from service-service snapshot
- **Registry snapshot** — polls service-service for endpoint metadata (access levels, rate limits per plan)
- **Plan resolution** — resolves user's plan tier via service-service customer rate-tier endpoint
- **Downstream headers** — forwards `X-User-Id`, `X-User-Plan`, `X-Is-Admin` to backend services

## Request Flow

```
Client → Nginx LB (TLS) → Traefik + Plugin → Backend Service
                                 │
                  ┌──────────────┼──────────────────┐
                  │              │                   │
          service-service   identity-service     Redis
          (snapshot/plan)   (admin check)     (rate limits)
```

## Configuration

All options are configurable via the Traefik Middleware CRD (see `helm/middleware.yaml`).

| Key | Default | Description |
|-----|---------|-------------|
| `jwtSecret` | — | HMAC secret for JWT verification |
| `jwtIssuer` | `file-convert.online` | Expected JWT issuer |
| `sessionIdHeader` | `X-Session-Id` | Header for anonymous rate-limit key |
| `redisUrl` | `redis://127.0.0.1:6379/0` | Redis connection URL |
| `redisPrefix` | `gw:rl:` | Key prefix for rate limit counters |
| `serviceServiceUrl` | `http://service-service:8080` | Service registry URL |
| `identityServiceUrl` | `http://identity-service:8080` | Identity service URL |
| `usageServiceUrl` | `http://usage-service:8080` | Usage service URL |
| `defaultRateLimitRequests` | `30` | Fallback rate limit |
| `defaultRateLimitDurationSeconds` | `60` | Fallback window |
| `defaultPlanName` | `free` | Plan for anonymous users |
| `adminAccessLevel` | `admin` | Access level name for admin endpoints |
| `httpTimeout` | `5s` | Timeout for upstream HTTP calls |
| `disableRateLimit` | `false` | Skip rate limiting (debug) |
| `disableAuth` | `false` | Skip JWT validation (debug) |

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
