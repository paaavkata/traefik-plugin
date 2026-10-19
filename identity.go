package traefik_gateway_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// UserAuthz is the per-app authorization view derived from the token's roles
// (authzFromTokenRoles); the header-stamping contract (X-Is-Admin, X-User-Roles).
type UserAuthz struct {
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	IsAdmin     bool     `json:"is_admin"`
}

// Has reports whether the permission set grants the given tag ("*" = all).
func (a *UserAuthz) Has(permission string) bool {
	if a == nil {
		return false
	}
	for _, p := range a.Permissions {
		if p == "*" || p == permission {
			return true
		}
	}
	return false
}

// GetUserPlan resolves the user's plan from the service-service customer rate-tier endpoint.
type PlanResolver struct {
	baseURL string
	client  *http.Client
	log     *pluginLogger
	mu      sync.RWMutex
	cache   map[string]planCacheEntry
}

type planCacheEntry struct {
	plan      string
	expiresAt time.Time
}

const planCacheTTL = 30 * time.Second

func newPlanResolver(serviceServiceURL string, timeout time.Duration, log *pluginLogger) *PlanResolver {
	return &PlanResolver{
		baseURL: serviceServiceURL,
		client:  &http.Client{Timeout: timeout},
		log:     log,
		cache:   make(map[string]planCacheEntry),
	}
}

// Resolve returns the plan name for a customer scoped to an app (guide §4/§8.3:
// plans are per (app_id, user_id)). The cache key and request are app-scoped. When
// appID is non-empty the per-app rate-tier endpoint is used (guide §11); when empty
// (permissive/disabled resolution) the global endpoint is used. Falls back to defaultPlan on any error.
func (pr *PlanResolver) Resolve(ctx context.Context, appID, userID, defaultPlan string) string {
	cacheKey := appID + "\x00" + userID

	pr.mu.RLock()
	if entry, ok := pr.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		pr.mu.RUnlock()
		pr.log.debugf("plan resolver cache hit app_id=%s user_id=%s plan=%s", appID, userID, entry.plan)
		return entry.plan
	}
	pr.mu.RUnlock()

	var url string
	if appID != "" {
		url = fmt.Sprintf("%s/v1/apps/%s/customers/%s/rate-tier", pr.baseURL, appID, userID)
	} else {
		url = fmt.Sprintf("%s/v1/customers/%s/rate-tier", pr.baseURL, userID)
	}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		pr.log.warnf("plan resolver build request failed app_id=%s user_id=%s error=%v", appID, userID, err)
		return defaultPlan
	}
	if appID != "" {
		req.Header.Set("X-App-Id", appID)
	}

	resp, err := pr.client.Do(req)
	if err != nil {
		pr.log.warnf("plan resolver request failed user_id=%s duration=%s error=%v", userID, since(start), err)
		return defaultPlan
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	dur := since(start)
	if err != nil {
		pr.log.warnf("plan resolver read body failed user_id=%s duration=%s error=%v", userID, dur, err)
		return defaultPlan
	}
	bodyStr := string(body)
	pr.log.debugf("service-service rate-tier response user_id=%s status=%d duration=%s body=%s", userID, resp.StatusCode, dur, truncateForLog(bodyStr, maxLoggedHTTPBody))

	if resp.StatusCode != http.StatusOK {
		pr.log.debugf("plan resolver non-OK status, using default plan=%s user_id=%s", defaultPlan, userID)
		return defaultPlan
	}

	var result struct {
		PlanName string `json:"plan_name"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.PlanName == "" {
		if err != nil {
			pr.log.debugf("plan resolver json error user_id=%s err=%v body=%s", userID, err, truncateForLog(bodyStr, 512))
		}
		return defaultPlan
	}

	pr.mu.Lock()
	pr.cache[cacheKey] = planCacheEntry{
		plan:      result.PlanName,
		expiresAt: time.Now().Add(planCacheTTL),
	}
	pr.mu.Unlock()

	pr.log.infof("plan resolved app_id=%s user_id=%s plan=%s", appID, userID, result.PlanName)
	return result.PlanName
}
