package traefik_gateway_plugin

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// GatewayPlugin is the Traefik middleware plugin.
type GatewayPlugin struct {
	next     http.Handler
	name     string
	config   *Config

	snapshot     *SnapshotCache
	rateLimiter  *RateLimiter
	identity     *IdentityClient
	planResolver *PlanResolver
}

// New creates a new plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	httpTimeout := parseDuration(config.HTTPTimeout, 5*time.Second)
	refreshInterval := parseDuration(config.SnapshotRefreshInterval, 30*time.Second)
	pollInterval := parseDuration(config.SnapshotVersionPollInterval, 5*time.Second)

	plugin := &GatewayPlugin{
		next:   next,
		name:   name,
		config: config,
	}

	// Snapshot cache
	plugin.snapshot = newSnapshotCache(config.ServiceServiceURL, httpTimeout, refreshInterval, pollInterval)
	plugin.snapshot.start(ctx)

	// Rate limiter (Redis)
	if !config.DisableRateLimit {
		rl, err := newRateLimiter(config.RedisURL, config.RedisPassword, config.RedisPrefix, config.RedisDB)
		if err != nil {
			return nil, fmt.Errorf("traefik-gateway-plugin: redis init failed: %w", err)
		}
		plugin.rateLimiter = rl
	}

	// Identity client
	plugin.identity = newIdentityClient(config.IdentityServiceURL, httpTimeout)

	// Plan resolver
	plugin.planResolver = newPlanResolver(config.ServiceServiceURL, httpTimeout)

	return plugin, nil
}

func (p *GatewayPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// 1. Match the request against the registry snapshot
	ep := p.snapshot.matchEndpoint(req.Method, req.URL.Path)
	if ep == nil {
		// Endpoint not registered — pass through (or deny depending on policy).
		// Default: pass through to let Traefik's own routing handle 404.
		p.next.ServeHTTP(rw, req)
		return
	}

	// 2. Parse JWT (if present)
	var claims *TokenClaims
	if !p.config.DisableAuth {
		authHeader := req.Header.Get(p.config.JWTHeaderKey)
		var err error
		claims, err = parseJWT(authHeader, p.config.JWTSecret, p.config.JWTIssuer)
		if err != nil {
			writeJSON(rw, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": err.Error(),
			})
			return
		}
	}

	// 3. Admin access check
	if ep.AccessLevel == p.config.AdminAccessLevel {
		if claims == nil {
			writeJSON(rw, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "authentication required for admin endpoints",
			})
			return
		}
		isAdmin, err := p.identity.IsAdmin(ctx, claims.UserID)
		if err != nil || !isAdmin {
			writeJSON(rw, http.StatusForbidden, map[string]string{
				"error":   "forbidden",
				"message": "admin access required",
			})
			return
		}
		req.Header.Set(p.config.IsAdminHeader, "true")
	}

	// 4. Determine rate-limit identity and plan
	var rateLimitKey string
	var planName string

	if claims != nil {
		rateLimitKey = "user:" + claims.UserID
		planName = p.planResolver.Resolve(ctx, claims.UserID, p.config.DefaultPlanName)
		req.Header.Set(p.config.UserIDHeader, claims.UserID)
		req.Header.Set(p.config.UserPlanHeader, planName)
	} else {
		sessionID := req.Header.Get(p.config.SessionIDHeader)
		if sessionID == "" {
			sessionID = req.RemoteAddr
		}
		rateLimitKey = "session:" + sessionID
		planName = p.config.DefaultPlanName
	}

	// 5. Rate limiting
	if !p.config.DisableRateLimit && p.rateLimiter != nil {
		limit, window := p.resolveRateLimit(ep, planName)
		if limit > 0 {
			result, err := p.rateLimiter.Check(ctx, rateLimitKey, ep.UID, limit, window)
			if err == nil && !result.Allowed {
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

// resolveRateLimit determines the rate limit for the endpoint + plan combination.
func (p *GatewayPlugin) resolveRateLimit(ep *compiledEndpoint, planName string) (limit int, windowSeconds int) {
	if rl, ok := ep.RateLimits[planName]; ok {
		return rl.Requests, rl.DurationSeconds
	}
	return p.config.DefaultRateLimitRequests, p.config.DefaultRateLimitDurationSeconds
}
