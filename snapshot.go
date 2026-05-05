package traefik_gateway_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// SnapshotDTO mirrors service-service's GET /v1/registry/snapshot response.
type SnapshotDTO struct {
	Version     string               `json:"version"`
	GeneratedAt time.Time            `json:"generated_at"`
	Services    []SnapshotServiceDTO `json:"services"`
}

type SnapshotServiceDTO struct {
	UID       string                `json:"uid"`
	Slug      string                `json:"slug"`
	BasePath  string                `json:"base_path"`
	Endpoints []SnapshotEndpointDTO `json:"endpoints"`
}

type SnapshotEndpointDTO struct {
	UID         string                    `json:"uid"`
	Method      string                    `json:"method"`
	Path        string                    `json:"path"`
	FullPath    string                    `json:"full_path"`
	PathRegex   string                    `json:"path_regex"`
	AccessLevel string                    `json:"access_level"`
	Tags        []string                  `json:"tags"`
	RateLimits  map[string]RateLimitValue `json:"rate_limits"`
}

type RateLimitValue struct {
	Requests        int `json:"requests"`
	DurationSeconds int `json:"duration_seconds"`
}

// SnapshotVersionDTO matches GET /v1/registry/version response.
type SnapshotVersionDTO struct {
	Version string `json:"version"`
}

// compiledEndpoint holds a pre-compiled regex for fast matching.
type compiledEndpoint struct {
	SnapshotEndpointDTO
	regex *regexp.Regexp
}

// SnapshotCache polls service-service for the registry snapshot and caches it.
type SnapshotCache struct {
	mu              sync.RWMutex
	snapshot        *SnapshotDTO
	compiled        []compiledEndpoint
	version         string
	client          *http.Client
	baseURL         string
	refreshInterval time.Duration
	pollInterval    time.Duration
	stopCh          chan struct{}
	log             *pluginLogger
}

func newSnapshotCache(baseURL string, httpTimeout, refreshInterval, pollInterval time.Duration, log *pluginLogger) *SnapshotCache {
	sc := &SnapshotCache{
		client:          &http.Client{Timeout: httpTimeout},
		baseURL:         baseURL,
		refreshInterval: refreshInterval,
		pollInterval:    pollInterval,
		stopCh:          make(chan struct{}),
		log:             log,
	}
	return sc
}

func (sc *SnapshotCache) start(ctx context.Context) {
	sc.refresh(ctx)
	go sc.loop()
}

func (sc *SnapshotCache) stop() {
	close(sc.stopCh)
}

func (sc *SnapshotCache) loop() {
	pollTicker := time.NewTicker(sc.pollInterval)
	refreshTicker := time.NewTicker(sc.refreshInterval)
	defer pollTicker.Stop()
	defer refreshTicker.Stop()

	for {
		select {
		case <-sc.stopCh:
			return
		case <-pollTicker.C:
			sc.checkVersion()
		case <-refreshTicker.C:
			sc.refresh(context.Background())
		}
	}
}

func (sc *SnapshotCache) checkVersion() {
	start := time.Now()
	resp, err := sc.client.Get(sc.baseURL + "/v1/registry/version")
	if err != nil {
		sc.log.warnf("registry version poll failed duration=%s error=%v", since(start), err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	dur := since(start)
	if err != nil {
		sc.log.warnf("registry version read body failed duration=%s error=%v", dur, err)
		return
	}
	bodyStr := string(body)
	sc.log.debugf("service-service registry/version response status=%d duration=%s body=%s", resp.StatusCode, dur, truncateForLog(bodyStr, maxLoggedHTTPBody))

	if resp.StatusCode != http.StatusOK {
		sc.log.warnf("registry version non-OK status=%d duration=%s", resp.StatusCode, dur)
		return
	}
	var v SnapshotVersionDTO
	if err := json.Unmarshal(body, &v); err != nil {
		sc.log.warnf("registry version json error duration=%s err=%v body=%s", dur, err, truncateForLog(bodyStr, 512))
		return
	}

	sc.mu.RLock()
	current := sc.version
	sc.mu.RUnlock()

	if v.Version != current {
		sc.log.debugf("registry version changed from %q to %q, refreshing snapshot", current, v.Version)
		sc.refresh(context.Background())
	}
}

func (sc *SnapshotCache) refresh(ctx context.Context) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sc.baseURL+"/v1/registry/snapshot", nil)
	if err != nil {
		sc.log.errorf("registry snapshot build request failed error=%v", err)
		return
	}
	resp, err := sc.client.Do(req)
	if err != nil {
		sc.log.warnf("registry snapshot request failed duration=%s error=%v", since(start), err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	dur := since(start)
	if err != nil {
		sc.log.warnf("registry snapshot read body failed duration=%s error=%v", dur, err)
		return
	}
	bodyStr := string(body)
	sc.log.debugf("service-service registry/snapshot response status=%d duration=%s body=%s", resp.StatusCode, dur, truncateForLog(bodyStr, maxLoggedHTTPBody))

	if resp.StatusCode != http.StatusOK {
		sc.log.warnf("registry snapshot non-OK status=%d duration=%s", resp.StatusCode, dur)
		return
	}
	var snap SnapshotDTO
	if err := json.Unmarshal(body, &snap); err != nil {
		sc.log.warnf("registry snapshot json error duration=%s err=%v body_prefix=%s", dur, err, truncateForLog(bodyStr, 512))
		return
	}

	compiled := make([]compiledEndpoint, 0)
	for _, svc := range snap.Services {
		for _, ep := range svc.Endpoints {
			compiled = append(compiled, compiledEndpoint{
				SnapshotEndpointDTO: ep,
				regex:               compileRegex(ep.PathRegex, ep.FullPath, sc.log),
			})
		}
	}

	sc.mu.Lock()
	sc.snapshot = &snap
	sc.compiled = compiled
	sc.version = snap.Version
	sc.mu.Unlock()

	sc.log.debugf("registry snapshot loaded version=%s services=%d endpoints=%d duration=%s", snap.Version, len(snap.Services), len(compiled), dur)
}

func compileRegex(pathRegex, fullPath string, log *pluginLogger) *regexp.Regexp {
	re, err := regexp.Compile(pathRegex)
	if err != nil {
		re = regexp.MustCompile(fmt.Sprintf("^%s$", regexp.QuoteMeta(fullPath)))
	}
	log.debugf("compiled regex=%s fullPath=%s", re.String(), fullPath)
	return re
}

// matchEndpoint finds the endpoint matching the given method+path.
func (sc *SnapshotCache) matchEndpoint(method, path string) *compiledEndpoint {
	sc.log.debugf("matching endpoint method=%s path=%s", method, path)
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	for i := range sc.compiled {
		ep := &sc.compiled[i]
		if ep.Method != method {
			continue
		}
		if ep.regex.MatchString(path) {
			return ep
		}
	}
	return nil
}
