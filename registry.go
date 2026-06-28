package traefik_gateway_plugin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AppRegistryDTO mirrors application-service's GET /v1/registry/snapshot response
// (guide §11). The gateway consumes the flat `hosts` map for the host→app_id hot path;
// `apps` is carried for completeness/debugging but not used for resolution.
type AppRegistryDTO struct {
	Version     string                `json:"version"`
	GeneratedAt time.Time             `json:"generated_at"`
	Hosts       map[string]AppHostDTO `json:"hosts"`
	Apps        []AppEntryDTO         `json:"apps"`
}

// AppHostDTO is a single entry of the flat hosts map: host → {app_id, status}.
type AppHostDTO struct {
	AppID  string `json:"app_id"`
	Status string `json:"status"`
}

// AppEntryDTO mirrors one element of the snapshot `apps[]` array.
type AppEntryDTO struct {
	AppID           string   `json:"app_id"`
	Status          string   `json:"status"`
	DisplayName     string   `json:"display_name"`
	DefaultPlanSlug string   `json:"default_plan_slug"`
	Hosts           []string `json:"hosts"`
	PrimaryHost     string   `json:"primary_host"`
}

// AppRegistryVersionDTO matches GET /v1/registry/version response.
type AppRegistryVersionDTO struct {
	Version string `json:"version"`
}

// wildcardHostEntry holds a suffix-wildcard host mapping (e.g. "*.example.com").
type wildcardHostEntry struct {
	suffix string // ".example.com" — matched via strings.HasSuffix
	appID  string
}

// AppRegistryCache polls application-service for the host→app_id registry snapshot
// and caches it. It mirrors SnapshotCache: a shared process-wide poller, cheap
// version polling with periodic full refresh, and serve-last-known-good on failure.
type AppRegistryCache struct {
	mu        sync.RWMutex
	byHost    map[string]string
	wildcards []wildcardHostEntry
	version   string
	loaded    bool // true once at least one snapshot has been successfully loaded

	client          *http.Client
	baseURL         string
	refreshInterval time.Duration
	pollInterval    time.Duration
	stopCh          chan struct{}
	log             *pluginLogger
}

func newAppRegistryCache(baseURL string, httpTimeout, refreshInterval, pollInterval time.Duration, log *pluginLogger) *AppRegistryCache {
	return &AppRegistryCache{
		byHost:          make(map[string]string),
		client:          &http.Client{Timeout: httpTimeout},
		baseURL:         baseURL,
		refreshInterval: refreshInterval,
		pollInterval:    pollInterval,
		stopCh:          make(chan struct{}),
		log:             log,
	}
}

// sharedAppCaches holds one running AppRegistryCache per applicationServiceUrl for
// the lifetime of the Traefik process — same rationale as sharedCaches in snapshot.go:
// Traefik rebuilds middleware per router and per reload, so without sharing each
// instance would spawn its own poller and flood application-service.
var (
	sharedAppCachesMu sync.Mutex
	sharedAppCaches   = make(map[string]*AppRegistryCache)
)

// getSharedAppRegistryCache returns the process-wide AppRegistryCache for baseURL,
// creating and starting it on first use.
func getSharedAppRegistryCache(baseURL string, httpTimeout, refreshInterval, pollInterval time.Duration, log *pluginLogger) *AppRegistryCache {
	sharedAppCachesMu.Lock()
	defer sharedAppCachesMu.Unlock()

	if c, ok := sharedAppCaches[baseURL]; ok {
		return c
	}

	c := newAppRegistryCache(baseURL, httpTimeout, refreshInterval, pollInterval, log)
	// Process-lifetime context; the shared poller is never torn down.
	c.start(context.Background())
	sharedAppCaches[baseURL] = c
	return c
}

func (c *AppRegistryCache) start(ctx context.Context) {
	c.refresh(ctx)
	go c.loop(ctx)
}

func (c *AppRegistryCache) stop() {
	close(c.stopCh)
}

func (c *AppRegistryCache) loop(ctx context.Context) {
	pollTicker := time.NewTicker(c.pollInterval)
	refreshTicker := time.NewTicker(c.refreshInterval)
	defer pollTicker.Stop()
	defer refreshTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-pollTicker.C:
			c.checkVersion()
		case <-refreshTicker.C:
			c.refresh(ctx)
		}
	}
}

func (c *AppRegistryCache) checkVersion() {
	start := time.Now()
	resp, err := c.client.Get(c.baseURL + "/v1/registry/version")
	if err != nil {
		c.log.warnf("app registry version poll failed duration=%s error=%v", since(start), err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	dur := since(start)
	if err != nil {
		c.log.warnf("app registry version read body failed duration=%s error=%v", dur, err)
		return
	}
	bodyStr := string(body)
	c.log.debugf("application-service registry/version response status=%d duration=%s body=%s", resp.StatusCode, dur, truncateForLog(bodyStr, maxLoggedHTTPBody))

	if resp.StatusCode != http.StatusOK {
		c.log.warnf("app registry version non-OK status=%d duration=%s", resp.StatusCode, dur)
		return
	}
	var v AppRegistryVersionDTO
	if err := json.Unmarshal(body, &v); err != nil {
		c.log.warnf("app registry version json error duration=%s err=%v body=%s", dur, err, truncateForLog(bodyStr, 512))
		return
	}

	c.mu.RLock()
	current := c.version
	c.mu.RUnlock()

	if v.Version != current {
		c.log.debugf("app registry version changed from %q to %q, refreshing snapshot", current, v.Version)
		c.refresh(context.Background())
	}
}

func (c *AppRegistryCache) refresh(ctx context.Context) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/registry/snapshot", nil)
	if err != nil {
		c.log.errorf("app registry snapshot build request failed error=%v", err)
		return
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.log.warnf("app registry snapshot request failed duration=%s error=%v", since(start), err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	dur := since(start)
	if err != nil {
		c.log.warnf("app registry snapshot read body failed duration=%s error=%v", dur, err)
		return
	}
	bodyStr := string(body)
	c.log.debugf("application-service registry/snapshot response status=%d duration=%s body=%s", resp.StatusCode, dur, truncateForLog(bodyStr, maxLoggedHTTPBody))

	if resp.StatusCode != http.StatusOK {
		// Serve last-known-good: do NOT clear the map on a failed refresh.
		c.log.warnf("app registry snapshot non-OK status=%d duration=%s (keeping last-known-good)", resp.StatusCode, dur)
		return
	}
	var snap AppRegistryDTO
	if err := json.Unmarshal(body, &snap); err != nil {
		c.log.warnf("app registry snapshot json error duration=%s err=%v body_prefix=%s (keeping last-known-good)", dur, err, truncateForLog(bodyStr, 512))
		return
	}

	byHost := make(map[string]string, len(snap.Hosts))
	wildcards := make([]wildcardHostEntry, 0)
	for host, entry := range snap.Hosts {
		if !strings.EqualFold(entry.Status, "active") {
			continue
		}
		nh := normalizeHost(host)
		if strings.HasPrefix(nh, "*.") {
			wildcards = append(wildcards, wildcardHostEntry{suffix: nh[1:], appID: entry.AppID})
			continue
		}
		byHost[nh] = entry.AppID
	}

	c.mu.Lock()
	c.byHost = byHost
	c.wildcards = wildcards
	c.version = snap.Version
	c.loaded = true
	c.mu.Unlock()

	c.log.debugf("app registry snapshot loaded version=%s hosts=%d wildcards=%d duration=%s", snap.Version, len(byHost), len(wildcards), dur)
}

// resolveHost maps a request host to an app_id. It returns (appID, true) only when
// the normalized host maps to an active app; otherwise ("", false). Read-locked.
func (c *AppRegistryCache) resolveHost(host string) (string, bool) {
	nh := normalizeHost(host)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if appID, ok := c.byHost[nh]; ok {
		return appID, true
	}
	// Optional suffix-wildcard fallback (e.g. "*.example.com").
	for _, w := range c.wildcards {
		if strings.HasSuffix(nh, w.suffix) {
			return w.appID, true
		}
	}
	return "", false
}

// coldStart reports whether the registry has never successfully loaded a snapshot.
// In enforce mode this distinguishes "registry unavailable" (503) from "unknown
// host" (403).
func (c *AppRegistryCache) coldStart() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.loaded
}
