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

// IdentityClient communicates with the identity-service to resolve user metadata.
type IdentityClient struct {
	baseURL string
	client  *http.Client
	log     *pluginLogger

	// Cache admin status / authz to avoid repeated calls per request burst.
	mu         sync.RWMutex
	adminCache map[string]adminCacheEntry
	authzCache map[string]authzCacheEntry
}

type adminCacheEntry struct {
	isAdmin   bool
	expiresAt time.Time
}

// UserAuthz is the per-app authorization view returned by identity's
// GET /v1/user/{id}/authz (RBAC v2, PERMISSIONS_STRATEGY.md).
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

type authzCacheEntry struct {
	authz     *UserAuthz
	expiresAt time.Time
}

const adminCacheTTL = 60 * time.Second
const authzCacheTTL = 60 * time.Second

func newIdentityClient(baseURL string, timeout time.Duration, log *pluginLogger) *IdentityClient {
	return &IdentityClient{
		baseURL:    baseURL,
		client:     &http.Client{Timeout: timeout},
		log:        log,
		adminCache: make(map[string]adminCacheEntry),
		authzCache: make(map[string]authzCacheEntry),
	}
}

// Authz resolves the user's per-app roles and permissions from
// GET /v1/user/:id/authz, caching per (appID, userID). If the endpoint is
// unavailable (older identity-service deploy or transient error) it falls back
// to the legacy admin-status check: admins synthesize a wildcard permission
// set, non-admins an empty one — preserving pre-RBAC behavior during rollout.
func (ic *IdentityClient) Authz(ctx context.Context, appID, userID string) (*UserAuthz, error) {
	cacheKey := appID + "\x00" + userID

	ic.mu.RLock()
	if entry, ok := ic.authzCache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		ic.mu.RUnlock()
		ic.log.debugf("identity Authz cache hit app_id=%s user_id=%s roles=%v", appID, userID, entry.authz.Roles)
		return entry.authz, nil
	}
	ic.mu.RUnlock()

	url := fmt.Sprintf("%s/v1/user/%s/authz", ic.baseURL, userID)
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if appID != "" {
		req.Header.Set("X-App-Id", appID)
	}

	authz, err := ic.fetchAuthz(req, userID, start)
	if err != nil {
		ic.log.warnf("identity authz unavailable, falling back to admin-status user_id=%s error=%v", userID, err)
		isAdmin, adminErr := ic.IsAdmin(ctx, appID, userID)
		if adminErr != nil {
			return nil, fmt.Errorf("authz fallback failed: %w", adminErr)
		}
		authz = &UserAuthz{Roles: []string{}, Permissions: []string{}, IsAdmin: isAdmin}
		if isAdmin {
			authz.Permissions = []string{"*"}
		}
	}

	ic.mu.Lock()
	ic.authzCache[cacheKey] = authzCacheEntry{authz: authz, expiresAt: time.Now().Add(authzCacheTTL)}
	ic.mu.Unlock()
	return authz, nil
}

func (ic *IdentityClient) fetchAuthz(req *http.Request, userID string, start time.Time) (*UserAuthz, error) {
	resp, err := ic.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity-service call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	dur := since(start)
	if err != nil {
		return nil, err
	}
	ic.log.debugf("identity authz response user_id=%s status=%d duration=%s body=%s", userID, resp.StatusCode, dur, truncateForLog(string(body), maxLoggedHTTPBody))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity-service returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Status string    `json:"status"`
		Data   UserAuthz `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if result.Data.Roles == nil {
		result.Data.Roles = []string{}
	}
	if result.Data.Permissions == nil {
		result.Data.Permissions = []string{}
	}
	// Admins keep legacy full access even if their role's policy links are
	// incomplete (is_admin derives from the Owner/Admin role name).
	if result.Data.IsAdmin && !result.Data.Has("*") {
		result.Data.Permissions = append(result.Data.Permissions, "*")
	}
	return &result.Data, nil
}

// IsAdmin checks if a user has admin privileges by calling
// GET /v1/user/:id and checking the role from identity-service. Admin is per-app
// (guide §8.2): the cache key and the forwarded X-App-Id header are scoped by appID.
// When appID is empty (permissive/legacy) it behaves as before.
func (ic *IdentityClient) IsAdmin(ctx context.Context, appID, userID string) (bool, error) {
	cacheKey := appID + "\x00" + userID

	ic.mu.RLock()
	if entry, ok := ic.adminCache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		ic.mu.RUnlock()
		ic.log.debugf("identity IsAdmin cache hit app_id=%s user_id=%s is_admin=%v", appID, userID, entry.isAdmin)
		return entry.isAdmin, nil
	}
	ic.mu.RUnlock()

	url := fmt.Sprintf("%s/v1/user/%s/admin-status", ic.baseURL, userID)
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	if appID != "" {
		req.Header.Set("X-App-Id", appID)
	}

	resp, err := ic.client.Do(req)
	if err != nil {
		ic.log.warnf("identity-service request failed user_id=%s duration=%s error=%v", userID, since(start), err)
		return false, fmt.Errorf("identity-service call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	dur := since(start)
	if err != nil {
		ic.log.warnf("identity-service read body failed user_id=%s duration=%s error=%v", userID, dur, err)
		return false, err
	}
	bodyStr := string(body)
	ic.log.debugf("identity-service response user_id=%s status=%d duration=%s body=%s", userID, resp.StatusCode, dur, truncateForLog(bodyStr, maxLoggedHTTPBody))

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("identity-service returned %d: %s", resp.StatusCode, bodyStr)
	}

	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Data    struct {
			IsAdmin bool `json:"is_admin"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	ic.mu.Lock()
	ic.adminCache[cacheKey] = adminCacheEntry{
		isAdmin:   result.Data.IsAdmin,
		expiresAt: time.Now().Add(adminCacheTTL),
	}
	ic.mu.Unlock()

	return result.Data.IsAdmin, nil
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
// (permissive/legacy single-app) the legacy global endpoint is used and behaviour
// matches today's. Falls back to defaultPlan on any error.
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
