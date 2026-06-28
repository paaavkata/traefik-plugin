# traefik-plugin — Multi-App (`app_id` from host) Implementation Plan

> **Status: PLAN ONLY.** No source under `traefik-plugin/` is modified by this document.
> Designed against `MULTI_APP_PLATFORM_GUIDE.md` §4 (trust model), §8 (locked decisions),
> §10 (PINNED contract — trusted header is exactly `X-App-Id`), §11 (registry API).
>
> Goal: make the gateway the trust boundary for `app_id`. Resolve `app_id` from the request
> **host** via the new `application-service` registry, **reject** unknown/inactive hosts, stamp a
> trusted `X-App-Id`, **strip** any inbound client copy — mirroring exactly how `X-User-Id` is
> stamped and how the session header is handled today (`plugin.go:187-190`). Then make plan
> resolution, access-level, and rate-limit lookups app-aware.
>
> NOTE (reconciliation): registry endpoint paths/shape are pinned in guide §11; where this doc's
> assumed `/v1/registry/apps/...` differs, **§11 wins** (isolated in `registry.go`).

## 0. Summary of current behaviour (what we are extending)

`ServeHTTP` (`plugin.go:93-236`) runs these steps in order:

0. **CORS** (`:96-112`) — preflight short-circuits with 204 before anything else; error responses inherit ACAO.
1. **Endpoint match** (`:114-121`) — `snapshot.matchEndpoint(method, path)`; **nil ⇒ pass-through** to `next`.
2. **JWT parse** (`:125-150`) — anonymous allowed (`claims == nil`).
3. **Admin check** (`:152-178`) — `identity.IsAdmin(ctx, userID)`; sets `X-Is-Admin`.
4. **Identity + plan** (`:180-204`) — authed: `planResolver.Resolve(ctx, userID, default)`, stamps `X-User-Id`/`X-User-Plan`, **deletes inbound session header** (`:190`). Anonymous: builds rate-limit key from device/session/IP.
5. **Rate limit** (`:206-232`) — `resolveRateLimit(ep, plan)` + `rateLimiter.Check(...)`.
6. **Forward** (`:235`).

Two lookups are **global** today and must become app-scoped: `PlanResolver.Resolve` (keyed on `userID`) and the endpoint snapshot (`matchEndpoint` + `RateLimits`/`AccessLevel`, global per endpoint).

## 1. Assumed `application-service` registry contract → see guide §11
Snapshot + version pair mirroring service-service's registry, so the existing `SnapshotCache`
design (shared poller, version poll + periodic refresh, serve-last-known-good) is reused near-verbatim.
Mapping is **host → app_id**, host **1:1 with an app** (§8.1). `status` must be `active` to resolve;
anything else ⇒ reject. Host normalization (lowercase, strip `:port`, strip trailing `.`) is plugin-side.
Wildcard hosts: prefer exact match; optional suffix-wildcard fallback only if registry confirms it.

## 2. PINNED-contract note: `X-App-Id` literal
The plugin is the authority that *stamps* the header and uses `"X-App-Id"` verbatim (§10). Note
`payment-service` declares `X-App-ID`; Go canonicalizes both to `X-App-Id`, so interop is correct.
Resolved: standardize the Go constant on `X-App-Id` (done in guide §10).

## 3. New config fields (`config.go`)
Add to `Config`:
```go
ApplicationServiceURL          string `json:"applicationServiceUrl" yaml:"applicationServiceUrl"`
AppSnapshotRefreshInterval     string `json:"appSnapshotRefreshInterval" yaml:"appSnapshotRefreshInterval"`
AppSnapshotVersionPollInterval string `json:"appSnapshotVersionPollInterval" yaml:"appSnapshotVersionPollInterval"`
AppIDHeader       string `json:"appIdHeader" yaml:"appIdHeader"`             // "X-App-Id"
AppResolutionMode string `json:"appResolutionMode" yaml:"appResolutionMode"` // "enforce" | "permissive" | "disabled"
```
Defaults: `ApplicationServiceURL: "http://application-service:8080"`, refresh `30s`, poll `5s`,
`AppIDHeader: "X-App-Id"`, `AppResolutionMode: "permissive"` (start safe; flip to `enforce` after registry is live).
Semantics: **enforce** — unknown/inactive host ⇒ 403, cold cache ⇒ 503. **permissive** — unknown host ⇒
do not stamp, log `TODO(trust)`, pass through (inbound strip still happens). **disabled** — skip host
resolution (local/debug; legacy single-app). Add `X-App-Id` to `CORSAllowedHeaders` and helm.

## 4. New file: `registry.go` — host→app_id snapshot client
Mirror `snapshot.go` (shared process-wide poller is essential — Traefik rebuilds middleware per
router/reload and would otherwise flood the registry; copy the `sharedCaches` pattern at `snapshot.go:90-111`).
DTOs `AppRegistryDTO{Version, GeneratedAt, Apps[]}`, `AppEntryDTO{AppID, Status, Hosts[]}`.
`AppRegistryCache{ byHost map[string]string; wildcards; version; client; baseURL; ... }`.
Functions 1:1 with snapshot.go: `newAppRegistryCache`, `getSharedAppRegistryCache` (keyed by URL),
`start`/`loop`/`checkVersion`/`refresh`; `refresh` rebuilds `byHost` from `active` apps only and serves
**last-known-good** on failure (never clear the map on a failed refresh).
`resolveHost(host) (appID string, known bool)` — read-locked, `normalizeHost` then map lookup, optional
suffix-wildcard fallback. `normalizeHost` lives in `helpers.go` + unit test.
Wire-up in `New()` after the snapshot cache (`:47`); add `appRegistry *AppRegistryCache` to `GatewayPlugin`.

## 5. `ServeHTTP` changes — exact placement & ordering
Insert **Step 1a (host → app_id)** between CORS (Step 0) and endpoint matching.
Ordering rationale: CORS stays first (preflight must complete even for unknown hosts); host resolution
before endpoint match (matching becomes app-scoped); **inbound strip is unconditional and earliest**
(`req.Header.Del(AppIDHeader)` before any branch can return — spoof-proof on all paths, same principle as
the session `Del` at `:190`).
```go
// 1a. Resolve app_id from host; strip any inbound client copy; stamp trusted header.
req.Header.Del(p.config.AppIDHeader) // ALWAYS strip inbound first
var appID string
if p.config.AppResolutionMode != "disabled" {
    id, known := p.appRegistry.resolveHost(req.Host)
    switch {
    case known:
        appID = id
        req.Header.Set(p.config.AppIDHeader, appID) // trusted stamp
    case p.config.AppResolutionMode == "enforce":
        if p.appRegistry.coldStart() { /* 503 registry_unavailable */ ; return }
        /* 403 unknown_app */ ; return
    default: // permissive
        p.log.warnf("TODO(trust): unmapped host=%q served without app_id (permissive)", req.Host)
    }
}
```
Then `matchEndpoint` becomes `matchEndpoint(appID, method, path)`. In permissive mode with unknown host,
`appID==""` and matching falls back to global/wildcard endpoints (legacy routing keeps working).
Subsequent steps carry `appID`: admin `IsAdmin(ctx, appID, userID)`; plan `Resolve(ctx, appID, userID, default)`;
rate-limit key prefixed `"app:"+appID+"|user:"+userID` (and into `anonymousRateLimitKey`).

## 6. Endpoint matching + access-level + rate-limit → per-`(app, endpoint)`
Per §8.3 the snapshot gains an app dimension (service-service plan: a top-level `apps[]` wrapper).
Plugin: resolve `apps[app_id]` then match method+path_regex within it. `matchEndpoint(appID, method, path)`
filters by app, with a two-pass match: **exact app match preferred over global (`""`/`"*"`)** so an app can
override a shared endpoint's policy. Once the app-correct `ep` is returned, existing `resolveRateLimit(ep, plan)`
and `ep.AccessLevel` are already per-app (the dimension is carried by *which* endpoint matched). Redis
counter isolation via per-app endpoint UIDs (+ app-prefixed key as defense-in-depth).

## 7. PlanResolver + IdentityClient → key on `(app_id, user_id)`
`PlanResolver.Resolve(ctx, appID, userID, default)`, cache key `appID+"\x00"+userID` (fixes the global-plan
bug in §4). Request carries the app (preferred: `X-App-Id` header on the rate-tier call; confirm shape with
service-service §4). `IdentityClient.IsAdmin(ctx, appID, userID)` — admin is per-app (§8.2), cache key
`appID+"\x00"+userID`, request carries `X-App-Id`. In permissive mode `appID==""` ⇒ behaves as today.

## 8. Test plan (`plugin_test.go`, `helpers_test.go`, new `registry_test.go`)
Harness: `setupTestAppRegistry()` with a pre-populated `byHost` map (bypass HTTP, mirror `setupTestSnapshot`);
add `appRegistry` to all `GatewayPlugin` literals; map `example.com` or set `req.Host="fileconvert.online"`
so existing tests stay green; add `AppID: "fileconvert"` to test snapshot endpoints; fix `matchEndpoint` call sites.
New tests: stamps `X-App-Id` on known host; strips inbound `X-App-Id` (matched + pass-through); unknown host
enforce ⇒ 403; permissive ⇒ 200 no header; cold registry enforce ⇒ 503; inactive app ⇒ 403; per-app endpoint
match (different access/limits); per-app plan resolution cache isolation; rate-limit key app isolation;
`registry_test.go` (normalizeHost, resolveHost hit/miss, last-known-good, version-change refresh); preflight
from unknown host still 204 with ACAO.

## 9. Rollout / back-compat (phased)
1. **Phase 0 (safe):** ship `registry.go` + plumbing with `AppResolutionMode: "permissive"`. No registry ⇒
   pass-through; inbound `X-App-Id` stripped (immediate security win); `appID==""` ⇒ everything behaves as today.
2. **Phase 1:** deploy application-service with fileconvert hosts; plugin starts stamping real `X-App-Id`.
3. **Phase 2:** service-service emits per-`(app,endpoint)` snapshot + app-scoped rate-tier/admin endpoints;
   PlanResolver/IdentityClient/matchEndpoint go fully app-keyed.
4. **Phase 3:** flip `AppResolutionMode: "enforce"`; unknown hosts ⇒ 403. Trust boundary fully closed.
5. Update `helm/middleware.yaml` + README config table + request-flow diagram. Each phase revertible via config.

## 10. Assumptions & risks
- **A1** registry shape (§11) — mismatch only touches `registry.go`. **A2** `req.Host` is the real client host
  behind CloudFlare→nginx(TLS)→Traefik — **verify nginx passes original Host / whether `X-Forwarded-Host` is
  needed** (add `trustForwardedHost` toggle if so; misconfig breaks all resolution — staging test). **A3** host
  1:1 app (§8.1). **A4** per-app endpoint UIDs give Redis isolation. **A5** `X-App-Id` vs `X-App-ID` (canonicalizes).
- **R1** cold-start + enforce + registry down ⇒ 503 (mitigate: last-known-good, stay permissive until proven,
  optional static fallback map for bootstrap). **R2** snapshot staleness ≤ poll interval (acceptable). **R3**
  reuse shared-poller or per-reload duplicate pollers (the bug `snapshot.go:81-94` prevents). **R4** two parallel
  snapshots (service-service + application-service) double poll load — lightweight, acceptable.

## CONTRACT CHANGE REQUESTED
None (stamps §10-pinned `X-App-Id` verbatim). Recorded the `payment-service` `X-App-ID` literal divergence for standardization (resolved in §10).
