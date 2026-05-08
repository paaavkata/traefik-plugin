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
	next   http.Handler
	name   string
	config *Config
	log    *pluginLogger

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

	plog := newPluginLogger(config.LogLevel)

	plugin := &GatewayPlugin{
		next:   next,
		name:   name,
		config: config,
		log:    plog,
	}

	// Snapshot cache
	plugin.snapshot = newSnapshotCache(config.ServiceServiceURL, httpTimeout, refreshInterval, pollInterval, plog)
	plugin.snapshot.start(ctx)

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

	// Plan resolver
	plugin.planResolver = newPlanResolver(config.ServiceServiceURL, httpTimeout, plog)

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

	p.log.debugf("incoming request method=%s path=%s remote=%q headers=[%s]", req.Method, req.URL.Path, req.RemoteAddr, formatRequestHeaders(req))

	// 2. Parse JWT (if present)
	var claims *TokenClaims
	if !p.config.DisableAuth {
		authHeader := req.Header.Get(p.config.JWTHeaderKey)
		var err error
		claims, err = parseJWT(authHeader, p.config.JWTSecret, p.config.JWTIssuer)
		if err != nil {
			p.log.errorf("jwt auth failure path=%s error=%v", req.URL.Path, err)
			writeJSON(rw, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": err.Error(),
			})
			return
		}
		if claims != nil {
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

	// 3. Admin access check
	if ep.AccessLevel == p.config.AdminAccessLevel {
		if claims == nil {
			p.log.warnf("admin endpoint requires auth path=%s", req.URL.Path)
			writeJSON(rw, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "authentication required for admin endpoints",
			})
			return
		}
		isAdmin, err := p.identity.IsAdmin(ctx, claims.UserID)
		if err != nil {
			p.log.warnf("identity admin check failed user_id=%s error=%v", claims.UserID, err)
		}
		if err != nil || !isAdmin {
			if err == nil && !isAdmin {
				p.log.warnf("admin access denied user_id=%s path=%s", claims.UserID, req.URL.Path)
			}
			writeJSON(rw, http.StatusForbidden, map[string]string{
				"error":   "forbidden",
				"message": "admin access required",
			})
			return
		}
		p.log.infof("admin access granted user_id=%s path=%s", claims.UserID, req.URL.Path)
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
			if err != nil {
				p.log.errorf("rate limit check failed endpoint_uid=%s plan=%s error=%v", ep.UID, planName, err)
			}
			if err == nil && !result.Allowed {
				p.log.warnf("rate limit exceeded endpoint_uid=%s plan=%s key=%s limit=%d window=%ds", ep.UID, planName, rateLimitKey, limit, window)
				rw.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				rw.Header().Set("X-RateLimit-Remaining", "0")
				rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
				rw.Header().Set("Retry-After", strconv.Itoa(int(time.Until(result.ResetAt).Seconds())))
				rw.Header().Set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After")
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
				rw.Header().Set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After")
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
