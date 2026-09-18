package traefik_gateway_plugin

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GatewayPlugin is the Traefik middleware plugin.
type GatewayPlugin struct {
	next   http.Handler
	name   string
	config *Config
	log    *pluginLogger

	snapshot     *SnapshotCache
	appRegistry  *AppRegistryCache
	rateLimiter  *RateLimiter
	identity     *IdentityClient
	planResolver *PlanResolver
	apiKeys      *APIKeyVerifier

	// Dual-issuer (Keycloak) state. keycloakApps empty ⇒ every request takes the
	// legacy HS256 path exactly as before.
	jwks           *JWKSCache
	keycloakApps   map[string]bool
	keycloakLeeway time.Duration
}

// New creates a new plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	httpTimeout := parseDuration(config.HTTPTimeout, 5*time.Second)
	refreshInterval := parseDuration(config.SnapshotRefreshInterval, 30*time.Second)
	pollInterval := parseDuration(config.SnapshotVersionPollInterval, 5*time.Second)
	appRefreshInterval := parseDuration(config.AppSnapshotRefreshInterval, 30*time.Second)
	appPollInterval := parseDuration(config.AppSnapshotVersionPollInterval, 5*time.Second)

	plog := newPluginLogger(config.LogLevel)

	plugin := &GatewayPlugin{
		next:   next,
		name:   name,
		config: config,
		log:    plog,
	}

	// Snapshot cache — shared process-wide so that the many routers referencing this
	// middleware (and Traefik's per-reload rebuilds) reuse a single poller instead of
	// each spawning its own and flooding service-service.
	plugin.snapshot = getSharedSnapshotCache(config.ServiceServiceURL, httpTimeout, refreshInterval, pollInterval, plog)

	// Host→app_id registry cache — also shared process-wide for the same reason as the
	// endpoint snapshot. Started even in "disabled" mode is unnecessary, so skip it then.
	if config.AppResolutionMode != "disabled" {
		plugin.appRegistry = getSharedAppRegistryCache(config.ApplicationServiceURL, httpTimeout, appRefreshInterval, appPollInterval, plog)
	}

	// Rate limiter (Redis)
	if !config.DisableRateLimit {
		rl, err := newRateLimiter(config.RedisURL, config.RedisPassword, config.RedisPrefix, config.RedisDB, plog)
		if err != nil {
			return nil, fmt.Errorf("traefik-gateway-plugin: redis init failed: %w", err)
		}
		plugin.rateLimiter = rl
	}

	// Identity client
	plugin.identity = newIdentityClient(config.IdentityServiceURL, httpTimeout, plog)

	// Keycloak dual-issuer path (additive; inert when keycloakApps is empty).
	kcApps, err := buildKeycloakAppSet(config)
	if err != nil {
		return nil, err
	}
	plugin.keycloakApps = kcApps
	plugin.keycloakLeeway = time.Duration(config.KeycloakClockSkewSeconds) * time.Second
	if len(kcApps) > 0 {
		jwksRefresh := parseDuration(config.JWKSRefreshInterval, 10*time.Minute)
		jwksCooldown := parseDuration(config.JWKSRefetchCooldown, 30*time.Second)
		plugin.jwks = getSharedJWKSCache(config.KeycloakJWKSURL, httpTimeout, jwksRefresh, jwksCooldown, plog)
	}

	// Plan resolver
	plugin.planResolver = newPlanResolver(config.ServiceServiceURL, httpTimeout, plog)

	// API-key verifier (contract §4). Uses a dedicated Redis connection for its
	// positive/negative verify cache so it works independently of rate-limiting. A
	// Redis dial failure is non-fatal for the key path (cache disabled → every key
	// request hits identity-service directly); it only becomes fatal above when
	// rate-limiting itself needs Redis.
	var apiKeyCache *respRedis
	if config.RedisURL != "" {
		dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := dialRedis(dialCtx, config.RedisURL, config.RedisPassword, config.RedisDB, plog)
		cancel()
		if err != nil {
			plog.warnf("api-key cache redis init failed (cache disabled, verifying every request): %v", err)
		} else {
			apiKeyCache = c
		}
	}
	plugin.apiKeys = newAPIKeyVerifier(config.IdentityVerifyURL, httpTimeout, apiKeyCache, config.RedisPrefix, plog)

	return plugin, nil
}

// buildKeycloakAppSet validates the Keycloak config block and returns the set of
// app_ids that authenticate via Keycloak. Empty list ⇒ Keycloak path disabled.
func buildKeycloakAppSet(config *Config) (map[string]bool, error) {
	apps := make(map[string]bool, len(config.KeycloakApps))
	for _, a := range config.KeycloakApps {
		a = strings.TrimSpace(a)
		if a != "" {
			apps[a] = true
		}
	}
	if len(apps) > 0 {
		if config.KeycloakJWKSURL == "" {
			return nil, fmt.Errorf("traefik-gateway-plugin: keycloakApps is set but keycloakJwksUrl is empty")
		}
		if config.KeycloakIssuer == "" {
			return nil, fmt.Errorf("traefik-gateway-plugin: keycloakApps is set but keycloakIssuer is empty")
		}
	}
	return apps, nil
}

// isKeycloakApp reports whether the resolved app authenticates via Keycloak.
// Unresolved app_id ("" — permissive/disabled modes) always uses the legacy path.
func (p *GatewayPlugin) isKeycloakApp(appID string) bool {
	return appID != "" && p.keycloakApps[appID]
}

// parseKeycloakAuth validates a bearer token on the Keycloak RS256/JWKS path.
// Fails closed if the JWKS cache was never configured (misconfiguration must not
// silently fall back to the shared-secret path).
func (p *GatewayPlugin) parseKeycloakAuth(authHeader string) (*TokenClaims, error) {
	if authHeader == "" {
		return nil, nil // anonymous — same contract as parseJWT
	}
	if p.jwks == nil {
		return nil, fmt.Errorf("keycloak validation not configured")
	}
	return parseKeycloakJWT(authHeader, p.jwks, p.config.KeycloakIssuer, p.config.KeycloakUserIDClaim, p.keycloakLeeway, p.config.KeycloakAdminRoles)
}

// authzFromTokenRoles synthesizes a UserAuthz from Keycloak token roles without an
// identity-service round-trip (migration plan §2.3 Phase 1): admins get the
// wildcard permission — exactly the pre-RBAC fallback already coded in identity.go.
func authzFromTokenRoles(claims *TokenClaims) *UserAuthz {
	authz := &UserAuthz{Roles: claims.Roles, Permissions: []string{}, IsAdmin: claims.IsAdmin}
	if claims.IsAdmin {
		authz.Permissions = []string{"*"}
	}
	return authz
}

// stampAuthzHeaders sets the trusted X-Is-Admin / X-User-Roles headers from a
// resolved authorization view. Inbound copies were stripped at entry, so an
// absent header always means "not admin / no roles".
func (p *GatewayPlugin) stampAuthzHeaders(req *http.Request, authz *UserAuthz) {
	if authz == nil {
		return
	}
	if authz.IsAdmin {
		req.Header.Set(p.config.IsAdminHeader, "true")
	}
	if len(authz.Roles) > 0 {
		req.Header.Set(p.config.UserRolesHeader, strings.Join(authz.Roles, ","))
	}
}

// applyCORSHeaders sets Access-Control-* headers when the request Origin matches
// a configured allowed origin. Returns true if the origin was allowed.
func (p *GatewayPlugin) applyCORSHeaders(rw http.ResponseWriter, origin string) bool {
	for _, allowed := range p.config.CORSAllowedOrigins {
		matched := allowed == origin
		if !matched && strings.HasPrefix(allowed, "https://*.") {
			suffix := allowed[len("https://*"):]
			matched = strings.HasPrefix(origin, "https://") && strings.HasSuffix(origin, suffix)
		}
		if !matched && strings.HasPrefix(allowed, "http://*.") {
			suffix := allowed[len("http://*"):]
			matched = strings.HasPrefix(origin, "http://") && strings.HasSuffix(origin, suffix)
		}
		if matched {
			rw.Header().Set("Access-Control-Allow-Origin", origin)
			if p.config.CORSAllowCredentials {
				rw.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			rw.Header().Set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After")
			rw.Header().Add("Vary", "Origin")
			return true
		}
	}
	return false
}

func (p *GatewayPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// 0. CORS — must run before everything so that preflight bypasses auth/rate-limiting
	// and all plugin-generated error responses carry the correct CORS headers.
	if len(p.config.CORSAllowedOrigins) > 0 {
		origin := req.Header.Get("Origin")
		if origin != "" {
			p.applyCORSHeaders(rw, origin)
		}
		if req.Method == http.MethodOptions {
			rw.Header().Set("Access-Control-Allow-Methods", strings.Join(p.config.CORSAllowedMethods, ", "))
			rw.Header().Set("Access-Control-Allow-Headers", strings.Join(p.config.CORSAllowedHeaders, ", "))
			if p.config.CORSMaxAge > 0 {
				rw.Header().Set("Access-Control-Max-Age", strconv.Itoa(p.config.CORSMaxAge))
			}
			rw.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// Strip ALL gateway-owned trust headers unconditionally at entry. These are stamped
	// by THIS plugin only from validated data; any inbound client copy is a spoof and
	// must never survive to the backend on any path (passthrough, matched, error). The
	// only way any of these reaches a backend is if the plugin re-stamps a validated
	// value in a later step. (X-Session-Id / X-Device-Id are client-supplied identity
	// used for anonymous rate-limiting and are handled separately below — not blanket-
	// deleted here.)
	req.Header.Del(p.config.AppIDHeader)
	req.Header.Del(p.config.UserIDHeader)
	req.Header.Del(p.config.UserPlanHeader)
	req.Header.Del(p.config.IsAdminHeader)
	req.Header.Del(p.config.UserRolesHeader)
	req.Header.Del(p.config.ApiKeyUidHeader)

	// 1a. Resolve app_id from the request host; stamp the trusted header on success.
	var appID string
	if p.config.AppResolutionMode != "disabled" && p.appRegistry != nil {
		host := p.resolutionHost(req)
		id, known := p.appRegistry.resolveHost(host)
		switch {
		case known:
			appID = id
			req.Header.Set(p.config.AppIDHeader, appID)
			p.log.debugf("app resolved host=%q app_id=%s", host, appID)
		case p.config.AppResolutionMode == "enforce":
			if p.appRegistry.coldStart() {
				p.log.errorf("app registry unavailable (cold) host=%q path=%s (enforce)", host, req.URL.Path)
				writeJSON(rw, http.StatusServiceUnavailable, map[string]string{
					"error":   "registry_unavailable",
					"message": "application registry is not ready",
				})
				return
			}
			p.log.warnf("unknown/inactive app host=%q path=%s rejected (enforce)", host, req.URL.Path)
			writeJSON(rw, http.StatusForbidden, map[string]string{
				"error":   "unknown_app",
				"message": "host is not mapped to an active application",
			})
			return
		default: // permissive
			p.log.warnf("TODO(trust): unmapped host=%q served without app_id (permissive)", host)
		}
	}

	// 1. Match the request against the registry snapshot (scoped to the resolved app)
	ep := p.snapshot.matchEndpoint(appID, req.Method, req.URL.Path)
	if ep == nil {
		// Endpoint not registered — pass through (or deny depending on policy).
		// Default: pass through to let Traefik's own routing handle 404.
		p.next.ServeHTTP(rw, req)
		return
	}

	p.log.debugf("incoming request method=%s path=%s remote=%q headers=[%s]", req.Method, req.URL.Path, req.RemoteAddr, formatRequestHeaders(req))

	// 1b. API-key credential path (contract §4). If the client presents an fc_ key
	// (X-Api-Key or Authorization: Bearer fc_...), take the API-key path INSTEAD of
	// JWT parsing. On success this stamps X-User-Id / X-User-Plan / X-Api-Key-Uid and
	// jumps straight to rate limiting (skipping JWT, cross-app JWT replay, and RBAC —
	// API keys never carry admin and are denied on permission-gated endpoints in v1).
	if rawKey, isKey := extractAPIKeyCredential(req, p.config.JWTHeaderKey); isKey && !p.config.DisableAuth {
		p.serveAPIKey(rw, req, ep, appID, rawKey)
		return
	}

	// 2. Parse JWT (if present). Dual-issuer dispatch by the host-resolved app_id:
	// Keycloak apps → RS256 + JWKS + Keycloak issuer; everything else → the legacy
	// HS256 shared-secret path, byte-for-byte unchanged. Because each path pins its
	// algorithm (WithValidMethods), a token from one issuer can never validate on
	// the other's path (alg-confusion guard in both directions).
	var claims *TokenClaims
	if !p.config.DisableAuth {
		authHeader := req.Header.Get(p.config.JWTHeaderKey)
		var err error
		if p.isKeycloakApp(appID) {
			claims, err = p.parseKeycloakAuth(authHeader)
		} else {
			claims, err = parseJWT(authHeader, p.config.JWTSecret, p.config.JWTIssuer)
		}
		if err != nil {
			p.log.errorf("jwt auth failure path=%s error=%v", req.URL.Path, err)
			writeJSON(rw, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": err.Error(),
			})
			return
		}
		if claims != nil {
			// 2a. Cross-app token replay check (guide §8.5): a token minted for one
			// app must not be accepted on another app's host. Enforced only when both
			// sides are known — legacy tokens without the claim (claims.AppID == "")
			// and unresolved hosts (appID == "", permissive/disabled) pass through.
			if claims.AppID != "" && appID != "" && claims.AppID != appID {
				p.log.warnf("jwt app mismatch path=%s user_id=%s token_app_id=%s host_app_id=%s", req.URL.Path, claims.UserID, claims.AppID, appID)
				writeJSON(rw, http.StatusUnauthorized, map[string]string{
					"error":   "unauthorized",
					"message": "token was not issued for this application",
				})
				return
			}
			expStr := "none"
			if !claims.ExpiresAt.IsZero() {
				expStr = claims.ExpiresAt.Format(time.RFC3339)
			}
			p.log.infof("jwt auth success path=%s user_id=%s issuer=%s exp=%s", req.URL.Path, claims.UserID, claims.Issuer, expStr)
		} else {
			p.log.debugf("jwt anonymous path=%s (no bearer credentials)", req.URL.Path)
		}
	} else {
		p.log.debugf("jwt skipped path=%s (disableAuth=true)", req.URL.Path)
	}

	// 3. Permission check (RBAC v2, PERMISSIONS_STRATEGY.md). An endpoint may
	// require a permission tag from the snapshot; the legacy admin access level
	// implies config.AdminPermission. Fail closed: no claims → 401, identity
	// unavailable or permission missing → 403.
	requiredPermission := ep.RequiredPermission
	if requiredPermission == "" && ep.AccessLevel == p.config.AdminAccessLevel {
		requiredPermission = p.config.AdminPermission
	}
	// authzStamped records that the permission gate below already resolved and
	// stamped the caller's admin/roles headers, so step 4 does not repeat it.
	authzStamped := false
	if requiredPermission != "" {
		if claims == nil {
			p.log.warnf("permission-gated endpoint requires auth path=%s permission=%s", req.URL.Path, requiredPermission)
			writeJSON(rw, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "authentication required for this endpoint",
			})
			return
		}
		var authz *UserAuthz
		var err error
		if claims.Keycloak {
			// Keycloak tokens carry their roles; no identity-service round-trip
			// (migration plan §2.3 Phase 1 — admin ⇒ wildcard permission).
			authz = authzFromTokenRoles(claims)
		} else {
			authz, err = p.identity.Authz(ctx, appID, claims.UserID)
			if err != nil {
				p.log.warnf("identity authz check failed user_id=%s error=%v", claims.UserID, err)
			}
		}
		if err != nil || !authz.Has(requiredPermission) {
			if err == nil {
				p.log.warnf("permission denied user_id=%s path=%s required=%s roles=%v", claims.UserID, req.URL.Path, requiredPermission, authz.Roles)
			}
			writeJSON(rw, http.StatusForbidden, map[string]string{
				"error":   "forbidden",
				"message": "insufficient permissions",
			})
			return
		}
		p.log.infof("permission granted user_id=%s path=%s permission=%s", claims.UserID, req.URL.Path, requiredPermission)
		p.stampAuthzHeaders(req, authz)
		authzStamped = true
	}

	// 4. Determine rate-limit identity and plan
	var rateLimitKey string
	var planName string

	if claims != nil {
		rateLimitKey = "app:" + appID + "|user:" + claims.UserID
		planName = p.planResolver.Resolve(ctx, appID, claims.UserID, p.config.DefaultPlanName)
		req.Header.Set(p.config.UserIDHeader, claims.UserID)
		req.Header.Set(p.config.UserPlanHeader, planName)
		if claims.Keycloak {
			// Keycloak tokens carry admin/roles directly (frozen header contract:
			// same X-Is-Admin/X-User-Roles the identity-service path stamps).
			p.stampAuthzHeaders(req, authzFromTokenRoles(claims))
		} else if !authzStamped {
			// Legacy tokens: stamp the same admin/roles contract on EVERY
			// authenticated request, not only on permission-gated endpoints, so
			// a public endpoint can offer an admin-only behaviour (e.g. the
			// file-service download ignoring retention expiry for operators).
			// Fail-soft by design: identity unavailable ⇒ headers absent and the
			// caller is treated as a regular user; a public endpoint must never
			// turn into an error because of this lookup.
			if authz := p.identity.AuthzSoft(ctx, appID, claims.UserID); authz != nil {
				p.stampAuthzHeaders(req, authz)
			}
		}
		// Remove any client-supplied session header so backends can trust X-User-Id alone.
		req.Header.Del(p.config.SessionIDHeader)
	} else {
		sessionID := req.Header.Get(p.config.SessionIDHeader)
		deviceID := req.Header.Get(p.config.DeviceIDHeader)
		if sessionID != "" {
			// Forward the validated session ID so downstream services can use it for
			// credit metering (subject type = "session").
			req.Header.Set(p.config.SessionIDHeader, sessionID)
		}
		if deviceID != "" {
			req.Header.Set(p.config.DeviceIDHeader, deviceID)
		}
		rateLimitKey = "app:" + appID + "|" + anonymousRateLimitKey(deviceID, sessionID, clientIP(req))
		planName = p.config.DefaultPlanName
	}

	// 5. Rate limiting
	if !p.config.DisableRateLimit && p.rateLimiter != nil {
		limit, window := p.resolveRateLimit(ep, planName)
		if limit > 0 {
			result, err := p.rateLimiter.Check(ctx, rateLimitKey, ep.UID, limit, window)
			if err != nil {
				p.log.errorf("rate limit check failed endpoint_uid=%s plan=%s error=%v", ep.UID, planName, err)
			}
			if err == nil && !result.Allowed {
				p.log.warnf("rate limit exceeded endpoint_uid=%s plan=%s key=%s limit=%d window=%ds", ep.UID, planName, rateLimitKey, limit, window)
				rw.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				rw.Header().Set("X-RateLimit-Remaining", "0")
				rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
				rw.Header().Set("Retry-After", strconv.Itoa(int(time.Until(result.ResetAt).Seconds())))
				writeJSON(rw, http.StatusTooManyRequests, map[string]string{
					"error":   "rate_limit_exceeded",
					"message": "too many requests",
				})
				return
			}
			if err == nil {
				rw.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				rw.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
			}
		}
	}

	// 6. Forward to next handler
	p.next.ServeHTTP(rw, req)
}

// serveAPIKey handles the API-key credential path (contract §4). It parses the fc_
// token, verifies it (cache→identity), enforces app binding, denies permission-gated
// endpoints, stamps the trusted headers, buckets rate limiting by key_uid, and
// forwards. All error responses mirror the plugin's existing JSON error style.
//
// Precondition: the trust-header strip at ServeHTTP entry has already removed any
// inbound X-User-Id / X-User-Plan / X-Is-Admin / X-User-Roles / X-Api-Key-Uid copy,
// so a spoofed inbound value can never survive here.
func (p *GatewayPlugin) serveAPIKey(rw http.ResponseWriter, req *http.Request, ep *compiledEndpoint, appID, rawKey string) {
	ctx := req.Context()

	// Parse fc_<env>_<uid>_<secret>; malformed → 401.
	key, err := parseAPIKey(rawKey)
	if err != nil {
		p.log.warnf("api-key malformed path=%s error=%v", req.URL.Path, err)
		writeJSON(rw, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "malformed api key",
		})
		return
	}

	// Verify (cache first, then identity-service). Identity unreachable → 503
	// fail-closed for key traffic only.
	res, outcome := p.apiKeys.Verify(ctx, key)
	switch outcome {
	case apiKeyUnavailable:
		p.log.errorf("api-key verify unavailable path=%s uid=%s (fail-closed 503)", req.URL.Path, key.uid)
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{
			"error":   "identity_unavailable",
			"message": "key verification is temporarily unavailable",
		})
		return
	case apiKeyDenied:
		p.log.warnf("api-key denied path=%s uid=%s", req.URL.Path, key.uid)
		writeJSON(rw, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "invalid api key",
		})
		return
	}

	// App binding: verify response app_id must equal the host-resolved app_id
	// (mirror of the JWT cross-app check at plugin.go:274). Enforced only when both
	// sides are known — an unresolved host (appID == "") passes, matching the JWT path.
	if res.AppID != "" && appID != "" && res.AppID != appID {
		p.log.warnf("api-key app mismatch path=%s uid=%s key_app_id=%s host_app_id=%s", req.URL.Path, key.uid, res.AppID, appID)
		writeJSON(rw, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "key was not issued for this application",
		})
		return
	}

	// Permission gate: API-key auth has no permissions in v1, so any permission-gated
	// endpoint denies key auth (deny, not fall-through to anonymous).
	requiredPermission := ep.RequiredPermission
	if requiredPermission == "" && ep.AccessLevel == p.config.AdminAccessLevel {
		requiredPermission = p.config.AdminPermission
	}
	if requiredPermission != "" {
		p.log.warnf("api-key denied on permission-gated endpoint path=%s uid=%s required=%s", req.URL.Path, key.uid, requiredPermission)
		writeJSON(rw, http.StatusForbidden, map[string]string{
			"error":   "forbidden",
			"message": "api key authentication is not permitted for this endpoint",
		})
		return
	}

	// Stamp trusted headers. NEVER X-Is-Admin / X-User-Roles on this path.
	req.Header.Set(p.config.UserIDHeader, res.UserID)
	if res.Plan != "" {
		req.Header.Set(p.config.UserPlanHeader, res.Plan)
	}
	req.Header.Set(p.config.ApiKeyUidHeader, key.uid)
	// Remove any client-supplied session header so backends trust X-User-Id alone
	// (mirrors the authenticated JWT path).
	req.Header.Del(p.config.SessionIDHeader)

	p.log.infof("api-key auth success path=%s uid=%s user_id=%s plan=%s", req.URL.Path, key.uid, res.UserID, res.Plan)

	// Rate limiting: bucket by key_uid (not session/IP); resolved plan flows into
	// resolveRateLimit unchanged. Empty plan → DefaultPlanName (contract §3/§4).
	planName := res.Plan
	if planName == "" {
		planName = p.config.DefaultPlanName
	}
	rateLimitKey := "app:" + appID + "|key:" + key.uid

	if !p.config.DisableRateLimit && p.rateLimiter != nil {
		limit, window := p.resolveRateLimit(ep, planName)
		if limit > 0 {
			result, err := p.rateLimiter.Check(ctx, rateLimitKey, ep.UID, limit, window)
			if err != nil {
				p.log.errorf("rate limit check failed endpoint_uid=%s plan=%s error=%v", ep.UID, planName, err)
			}
			if err == nil && !result.Allowed {
				p.log.warnf("rate limit exceeded endpoint_uid=%s plan=%s key=%s limit=%d window=%ds", ep.UID, planName, rateLimitKey, limit, window)
				rw.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				rw.Header().Set("X-RateLimit-Remaining", "0")
				rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
				rw.Header().Set("Retry-After", strconv.Itoa(int(time.Until(result.ResetAt).Seconds())))
				writeJSON(rw, http.StatusTooManyRequests, map[string]string{
					"error":   "rate_limit_exceeded",
					"message": "too many requests",
				})
				return
			}
			if err == nil {
				rw.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				rw.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
			}
		}
	}

	// Forward to next handler.
	p.next.ServeHTTP(rw, req)
}

// resolutionHost returns the host used for app resolution. The prod path is
// CloudFlare→nginx→Traefik; whether the original Host survives or arrives as
// X-Forwarded-Host is unconfirmed, so the source is a config toggle defaulting to the
// safe req.Host. When TrustForwardedHost is set, X-Forwarded-Host wins if present.
func (p *GatewayPlugin) resolutionHost(req *http.Request) string {
	if p.config.TrustForwardedHost {
		if h := req.Header.Get("X-Forwarded-Host"); h != "" {
			// X-Forwarded-Host may be a comma-separated list; take the first (origin).
			if i := strings.IndexByte(h, ','); i >= 0 {
				h = h[:i]
			}
			return strings.TrimSpace(h)
		}
	}
	return req.Host
}

// resolveRateLimit determines the rate limit for the endpoint + plan combination.
func (p *GatewayPlugin) resolveRateLimit(ep *compiledEndpoint, planName string) (limit int, windowSeconds int) {
	if rl, ok := ep.RateLimits[planName]; ok {
		return rl.Requests, rl.DurationSeconds
	}
	return p.config.DefaultRateLimitRequests, p.config.DefaultRateLimitDurationSeconds
}
