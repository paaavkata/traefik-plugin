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

	// Cache admin status to avoid repeated calls per request burst.
	mu         sync.RWMutex
	adminCache map[string]adminCacheEntry
}

type adminCacheEntry struct {
	isAdmin   bool
	expiresAt time.Time
}

const adminCacheTTL = 60 * time.Second

func newIdentityClient(baseURL string, timeout time.Duration) *IdentityClient {
	return &IdentityClient{
		baseURL:    baseURL,
		client:     &http.Client{Timeout: timeout},
		adminCache: make(map[string]adminCacheEntry),
	}
}

// IsAdmin checks if a user has admin privileges by calling
// GET /v1/user/:id and checking the role from identity-service.
func (ic *IdentityClient) IsAdmin(ctx context.Context, userID string) (bool, error) {
	ic.mu.RLock()
	if entry, ok := ic.adminCache[userID]; ok && time.Now().Before(entry.expiresAt) {
		ic.mu.RUnlock()
		return entry.isAdmin, nil
	}
	ic.mu.RUnlock()

	url := fmt.Sprintf("%s/v1/user/%s/admin-status", ic.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	resp, err := ic.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("identity-service call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("identity-service returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Data    struct {
			IsAdmin bool `json:"is_admin"`
		} `json:"data"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	ic.mu.Lock()
	ic.adminCache[userID] = adminCacheEntry{
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
	mu      sync.RWMutex
	cache   map[string]planCacheEntry
}

type planCacheEntry struct {
	plan      string
	expiresAt time.Time
}

const planCacheTTL = 30 * time.Second

func newPlanResolver(serviceServiceURL string, timeout time.Duration) *PlanResolver {
	return &PlanResolver{
		baseURL: serviceServiceURL,
		client:  &http.Client{Timeout: timeout},
		cache:   make(map[string]planCacheEntry),
	}
}

// Resolve returns the plan name for a user (customer UID). Falls back to "free".
func (pr *PlanResolver) Resolve(ctx context.Context, userID, defaultPlan string) string {
	pr.mu.RLock()
	if entry, ok := pr.cache[userID]; ok && time.Now().Before(entry.expiresAt) {
		pr.mu.RUnlock()
		return entry.plan
	}
	pr.mu.RUnlock()

	url := fmt.Sprintf("%s/v1/customers/%s/rate-tier", pr.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return defaultPlan
	}

	resp, err := pr.client.Do(req)
	if err != nil {
		return defaultPlan
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return defaultPlan
	}

	var result struct {
		PlanName string `json:"plan_name"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil || result.PlanName == "" {
		return defaultPlan
	}

	pr.mu.Lock()
	pr.cache[userID] = planCacheEntry{
		plan:      result.PlanName,
		expiresAt: time.Now().Add(planCacheTTL),
	}
	pr.mu.Unlock()

	return result.PlanName
}
