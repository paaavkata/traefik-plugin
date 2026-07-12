package traefik_gateway_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestSnapshot() *SnapshotCache {
	sc := &SnapshotCache{
		stopCh: make(chan struct{}),
	}
	sc.snapshot = &SnapshotDTO{
		Version: "1",
		Apps: []SnapshotAppDTO{
			{
				AppID: "fileconvert",
				Services: []SnapshotServiceDTO{
					{
						UID:      "svc1",
						Slug:     "conversion",
						BasePath: "/api/conversion",
						Endpoints: []SnapshotEndpointDTO{
							{
								UID:         "ep1",
								Method:      "POST",
								Path:        "/v1/convert",
								FullPath:    "/api/conversion/v1/convert",
								PathRegex:   `^/api/conversion/v1/convert$`,
								AccessLevel: "free",
								RateLimits: map[string]RateLimitValue{
									"free": {Requests: 10, DurationSeconds: 60},
									"pro":  {Requests: 100, DurationSeconds: 60},
								},
							},
							{
								UID:         "ep2",
								Method:      "GET",
								Path:        "/v1/admin/users",
								FullPath:    "/api/conversion/v1/admin/users",
								PathRegex:   `^/api/conversion/v1/admin/users$`,
								AccessLevel: "admin",
								RateLimits: map[string]RateLimitValue{
									"free": {Requests: 0, DurationSeconds: 60},
								},
							},
						},
					},
				},
			},
		},
	}

	compiled := make([]compiledEndpoint, 0)
	for _, app := range sc.snapshot.Apps {
		for _, svc := range app.Services {
			for _, ep := range svc.Endpoints {
				re := compileRegex(ep.PathRegex, ep.FullPath)
				compiled = append(compiled, compiledEndpoint{
					SnapshotEndpointDTO: ep,
					AppID:               app.AppID,
					regex:               re,
				})
			}
		}
	}
	sc.compiled = compiled
	return sc
}

// setupTestAppRegistry returns an AppRegistryCache pre-populated with a host→app_id
// map, bypassing HTTP (mirrors setupTestSnapshot). loaded=true so coldStart()==false.
func setupTestAppRegistry() *AppRegistryCache {
	return &AppRegistryCache{
		byHost: map[string]string{
			"fileconvert.online": "fileconvert",
			"cms.example.com":    "cms",
		},
		loaded: true,
		stopCh: make(chan struct{}),
	}
}

func TestPlugin_AnonymousRequest_FreeEndpoint(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
		identity: newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{
			cache: make(map[string]planCacheEntry),
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("X-Session-Id", "sess-abc123")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestPlugin_AdminEndpoint_NoAuth(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
		identity: newIdentityClient("http://localhost:9999", 1*time.Second, nil),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/conversion/v1/admin/users", nil)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for admin endpoint without auth, got %d", rr.Code)
	}
}

func TestPlugin_AdminEndpoint_NonAdminUser(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	// Mock identity service returns non-admin
	identityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "ok",
			"data":    map[string]bool{"is_admin": false},
		})
	}))
	defer identityServer.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
		identity: newIdentityClient(identityServer.URL, 5*time.Second, nil),
	}

	token := createTestToken("test-secret", 42, "file-convert.online", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/api/conversion/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin user, got %d", rr.Code)
	}
}

func TestPlugin_AdminEndpoint_AdminUser(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	identityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "ok",
			"data":    map[string]bool{"is_admin": true},
		})
	}))
	defer identityServer.Close()

	var capturedIsAdmin string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		capturedIsAdmin = req.Header.Get("X-Is-Admin")
		rw.WriteHeader(http.StatusOK)
	})

	// Mock service-service for plan resolution
	serviceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"plan_name": "free"})
	}))
	defer serviceServer.Close()

	plugin := &GatewayPlugin{
		next:         next,
		name:         "test",
		config:       config,
		snapshot:     setupTestSnapshot(),
		identity:     newIdentityClient(identityServer.URL, 5*time.Second, nil),
		planResolver: newPlanResolver(serviceServer.URL, 5*time.Second, nil),
	}

	token := createTestToken("test-secret", 42, "file-convert.online", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/api/conversion/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin user, got %d", rr.Code)
	}
	if capturedIsAdmin != "true" {
		t.Errorf("expected X-Is-Admin=true on forwarded request, got %q", capturedIsAdmin)
	}
}

func TestPlugin_InvalidJWT(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid JWT, got %d", rr.Code)
	}
}

func TestPlugin_ExpiredJWT(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
	}

	expiredClaims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		Issuer:    "file-convert.online",
		Subject:   fmt.Sprintf("%d", 1),
	}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims).SignedString([]byte("test-secret"))

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired JWT, got %d", rr.Code)
	}
}

func TestPlugin_UnregisteredEndpoint_PassThrough(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
	}

	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 pass-through for unregistered endpoint, got %d", rr.Code)
	}
}

// ── CORS tests ────────────────────────────────────────────────────────────────

func newCORSPlugin(t *testing.T) *GatewayPlugin {
	t.Helper()
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.CORSAllowedOrigins = []string{
		"https://file-convert.online",
		"https://*.file-convert.online",
		"http://localhost:3000",
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	return &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
		identity: newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{
			cache: make(map[string]planCacheEntry),
		},
	}
}

// OPTIONS preflight from an allowed exact origin → 204 + ACAO echoed back.
func TestPlugin_CORS_Preflight_AllowedExactOrigin(t *testing.T) {
	plugin := newCORSPlugin(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/conversion/v1/convert", nil)
	req.Header.Set("Origin", "https://file-convert.online")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for preflight, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://file-convert.online" {
		t.Errorf("expected ACAO=https://file-convert.online, got %q", got)
	}
}

// OPTIONS preflight from an allowed wildcard-subdomain origin → 204 + ACAO echoed back.
func TestPlugin_CORS_Preflight_AllowedWildcardSubdomain(t *testing.T) {
	plugin := newCORSPlugin(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/conversion/v1/convert", nil)
	req.Header.Set("Origin", "https://admin.file-convert.online")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for preflight, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://admin.file-convert.online" {
		t.Errorf("expected ACAO=https://admin.file-convert.online, got %q", got)
	}
	if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("expected Access-Control-Allow-Credentials=true")
	}
}

// OPTIONS preflight from a disallowed origin → 204 but NO ACAO header.
func TestPlugin_CORS_Preflight_DisallowedOrigin(t *testing.T) {
	plugin := newCORSPlugin(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/conversion/v1/convert", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no ACAO for disallowed origin, got %q", got)
	}
}

// Non-preflight GET from an allowed origin → ACAO is set on the forwarded response.
func TestPlugin_CORS_ActualRequest_SetsACАО(t *testing.T) {
	plugin := newCORSPlugin(t)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("X-Session-Id", "sess-1")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("expected ACAO=http://localhost:3000, got %q", got)
	}
}

// Admin endpoint with no token → plugin returns 401, and ACAO must still be present
// so the browser can read the error body instead of reporting a generic CORS failure.
func TestPlugin_CORS_AuthError_CarriesCORSHeader(t *testing.T) {
	plugin := newCORSPlugin(t)

	req := httptest.NewRequest(http.MethodGet, "/api/conversion/v1/admin/users", nil)
	req.Header.Set("Origin", "https://admin.file-convert.online")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://admin.file-convert.online" {
		t.Errorf("expected ACAO on 401 response, got %q", got)
	}
}

// No Origin header → plugin must not set any ACAO header (server-to-server calls).
func TestPlugin_CORS_NoOrigin_NoACАО(t *testing.T) {
	plugin := newCORSPlugin(t)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("X-Session-Id", "sess-2")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no ACAO when Origin is absent, got %q", got)
	}
}

// ── Existing tests ─────────────────────────────────────────────────────────────

func TestPlugin_AuthenticatedUser_SetsHeaders(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	var capturedUserID, capturedPlan string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		capturedUserID = req.Header.Get("X-User-Id")
		capturedPlan = req.Header.Get("X-User-Plan")
		rw.WriteHeader(http.StatusOK)
	})

	// Mock service-service for plan resolution
	serviceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"plan_name": "pro"})
	}))
	defer serviceServer.Close()

	plugin := &GatewayPlugin{
		next:         next,
		name:         "test",
		config:       config,
		snapshot:     setupTestSnapshot(),
		identity:     newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: newPlanResolver(serviceServer.URL, 5*time.Second, nil),
	}

	token := createTestToken("test-secret", 99, "file-convert.online", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if capturedUserID != "99" {
		t.Errorf("expected X-User-Id=99, got %s", capturedUserID)
	}
	if capturedPlan != "pro" {
		t.Errorf("expected X-User-Plan=pro, got %s", capturedPlan)
	}
}

// ── Multi-app (host → app_id) tests ──────────────────────────────────────────────

// Known host → trusted X-App-Id is stamped on the forwarded request.
func TestPlugin_AppResolution_KnownHost_StampsHeader(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	var capturedAppID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		capturedAppID = req.Header.Get("X-App-Id")
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
		identity:    newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{
			cache: make(map[string]planCacheEntry),
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-Session-Id", "sess-1")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if capturedAppID != "fileconvert" {
		t.Errorf("expected X-App-Id=fileconvert, got %q", capturedAppID)
	}
}

// Inbound client-supplied X-App-Id must be stripped and replaced with the trusted value.
func TestPlugin_AppResolution_StripsInboundHeader(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	var capturedAppID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		capturedAppID = req.Header.Get("X-App-Id")
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
		identity:    newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{
			cache: make(map[string]planCacheEntry),
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-App-Id", "evil-spoof")
	req.Header.Set("X-Session-Id", "sess-1")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if capturedAppID != "fileconvert" {
		t.Errorf("expected spoofed X-App-Id replaced with fileconvert, got %q", capturedAppID)
	}
}

// Inbound X-App-Id must be stripped even on the pass-through path (unregistered endpoint).
func TestPlugin_AppResolution_StripsInboundHeader_PassThrough(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	var seen bool
	var capturedAppID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seen = true
		capturedAppID = req.Header.Get("X-App-Id")
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
	}

	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-App-Id", "evil-spoof")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if !seen {
		t.Fatal("expected pass-through to next handler")
	}
	// Known host: trusted value stamped, spoof gone.
	if capturedAppID != "fileconvert" {
		t.Errorf("expected X-App-Id=fileconvert on pass-through, got %q", capturedAppID)
	}
}

// Enforce mode + unknown host → 403.
func TestPlugin_AppResolution_UnknownHost_Enforce_403(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "enforce"

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "not-a-known-host.com"
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown host in enforce mode, got %d", rr.Code)
	}
}

// Permissive mode + unknown host → 200, no X-App-Id stamped (legacy behaviour).
func TestPlugin_AppResolution_UnknownHost_Permissive_200(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "permissive" // local/debug-only mode (no longer the default)

	var capturedAppID string
	var seen bool
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seen = true
		capturedAppID = req.Header.Get("X-App-Id")
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
		identity:    newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{
			cache: make(map[string]planCacheEntry),
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "not-a-known-host.com"
	req.Header.Set("X-Session-Id", "sess-1")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 in permissive mode, got %d", rr.Code)
	}
	if !seen {
		t.Fatal("expected request forwarded to next")
	}
	if capturedAppID != "" {
		t.Errorf("expected no X-App-Id stamped for unknown host (permissive), got %q", capturedAppID)
	}
}

// Enforce mode + cold registry (never loaded) → 503.
func TestPlugin_AppResolution_ColdRegistry_Enforce_503(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "enforce"

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	coldRegistry := &AppRegistryCache{
		byHost: map[string]string{},
		loaded: false, // never refreshed successfully
		stopCh: make(chan struct{}),
	}

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: coldRegistry,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for cold registry in enforce mode, got %d", rr.Code)
	}
}

// Disabled mode → no resolution, no stamp, but inbound copy still stripped.
func TestPlugin_AppResolution_Disabled_StripsButNoStamp(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "disabled"

	var capturedAppID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		capturedAppID = req.Header.Get("X-App-Id")
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
		identity:    newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{
			cache: make(map[string]planCacheEntry),
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-App-Id", "evil-spoof")
	req.Header.Set("X-Session-Id", "sess-1")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if capturedAppID != "" {
		t.Errorf("expected no X-App-Id in disabled mode (inbound stripped, none stamped), got %q", capturedAppID)
	}
}

// Per-app endpoint match: an app-scoped endpoint wins over a shared one with the same path.
func TestPlugin_PerAppEndpoint_ExactMatchPreferred(t *testing.T) {
	sc := &SnapshotCache{stopCh: make(chan struct{})}
	// matchEndpoint operates on the compiled set; build it directly to unit-test the
	// two-pass match (exact-app preferred over a shared "" fallback). service-service's
	// apps[] snapshot emits concrete app_ids (shared services are duplicated per app),
	// so "" here models only the plugin's defensive fallback path.
	sc.compiled = []compiledEndpoint{
		{
			SnapshotEndpointDTO: SnapshotEndpointDTO{
				UID: "shared-ep", Method: "GET", Path: "/v1/thing",
				FullPath: "/api/x/v1/thing", PathRegex: `^/api/x/v1/thing$`, AccessLevel: "free",
			},
			AppID: "", // shared/global fallback
			regex: compileRegex(`^/api/x/v1/thing$`, "/api/x/v1/thing"),
		},
		{
			SnapshotEndpointDTO: SnapshotEndpointDTO{
				UID: "fc-ep", Method: "GET", Path: "/v1/thing",
				FullPath: "/api/x/v1/thing", PathRegex: `^/api/x/v1/thing$`, AccessLevel: "admin",
			},
			AppID: "fileconvert", // app-specific override
			regex: compileRegex(`^/api/x/v1/thing$`, "/api/x/v1/thing"),
		},
	}

	if ep := sc.matchEndpoint("fileconvert", "GET", "/api/x/v1/thing"); ep == nil || ep.UID != "fc-ep" {
		t.Errorf("expected exact-app endpoint fc-ep, got %+v", ep)
	}
	if ep := sc.matchEndpoint("cms", "GET", "/api/x/v1/thing"); ep == nil || ep.UID != "shared-ep" {
		t.Errorf("expected shared endpoint for other app, got %+v", ep)
	}
	if ep := sc.matchEndpoint("", "GET", "/api/x/v1/thing"); ep == nil || ep.UID != "shared-ep" {
		t.Errorf("expected shared endpoint for empty appID, got %+v", ep)
	}
}

// Per-app plan resolution: the same user on two apps must not share a cached plan.
func TestPlanResolver_AppScopedCache(t *testing.T) {
	var requestedURLs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURLs = append(requestedURLs, r.URL.Path)
		plan := "free"
		if r.URL.Path == "/v1/apps/fileconvert/customers/42/rate-tier" {
			plan = "pro"
		}
		json.NewEncoder(w).Encode(map[string]string{"plan_name": plan})
	}))
	defer server.Close()

	pr := newPlanResolver(server.URL, 5*time.Second, nil)

	if got := pr.Resolve(context.Background(), "fileconvert", "42", "free"); got != "pro" {
		t.Errorf("expected pro for fileconvert/42, got %q", got)
	}
	if got := pr.Resolve(context.Background(), "cms", "42", "free"); got != "free" {
		t.Errorf("expected free for cms/42 (separate cache key), got %q", got)
	}
	if len(requestedURLs) != 2 {
		t.Errorf("expected 2 upstream calls (no cross-app cache hit), got %d: %v", len(requestedURLs), requestedURLs)
	}
}

// ── Trust-header spoof stripping ─────────────────────────────────────────────────

// Client-supplied trust headers (X-User-Id, X-User-Plan, X-Is-Admin) must be stripped
// at entry and never forwarded on an anonymous request (nothing re-stamps them).
func TestPlugin_StripsSpoofedTrustHeaders_Anonymous(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "disabled"

	var gotUserID, gotPlan, gotIsAdmin, gotAppID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUserID = req.Header.Get("X-User-Id")
		gotPlan = req.Header.Get("X-User-Plan")
		gotIsAdmin = req.Header.Get("X-Is-Admin")
		gotAppID = req.Header.Get("X-App-Id")
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
		identity: newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{
			cache: make(map[string]planCacheEntry),
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("X-Session-Id", "sess-1")
	req.Header.Set("X-User-Id", "evil-spoof")
	req.Header.Set("X-User-Plan", "evil-spoof")
	req.Header.Set("X-Is-Admin", "true")
	req.Header.Set("X-App-Id", "evil-spoof")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotUserID != "" {
		t.Errorf("expected spoofed X-User-Id stripped, got %q", gotUserID)
	}
	if gotPlan != "" {
		t.Errorf("expected spoofed X-User-Plan stripped, got %q", gotPlan)
	}
	if gotIsAdmin != "" {
		t.Errorf("expected spoofed X-Is-Admin stripped, got %q", gotIsAdmin)
	}
	if gotAppID != "" {
		t.Errorf("expected spoofed X-App-Id stripped (disabled mode), got %q", gotAppID)
	}
}

// Spoofed trust headers must be stripped even on the pass-through (unmatched endpoint)
// path — the backend must never see a client-injected X-User-Id / X-Is-Admin.
func TestPlugin_StripsSpoofedTrustHeaders_PassThrough(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "disabled"

	var gotUserID, gotPlan, gotIsAdmin string
	var seen bool
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seen = true
		gotUserID = req.Header.Get("X-User-Id")
		gotPlan = req.Header.Get("X-User-Plan")
		gotIsAdmin = req.Header.Get("X-Is-Admin")
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
	}

	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	req.Header.Set("X-User-Id", "evil-spoof")
	req.Header.Set("X-User-Plan", "evil-spoof")
	req.Header.Set("X-Is-Admin", "true")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if !seen {
		t.Fatal("expected pass-through to next handler")
	}
	if gotUserID != "" || gotPlan != "" || gotIsAdmin != "" {
		t.Errorf("expected all spoofed trust headers stripped on pass-through, got user=%q plan=%q admin=%q", gotUserID, gotPlan, gotIsAdmin)
	}
}

// A spoofed X-Is-Admin on a non-admin matched endpoint (authenticated user) must be
// cleared — only an admin grant re-stamps it.
func TestPlugin_StripsSpoofedIsAdmin_AuthenticatedNonAdminEndpoint(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "disabled"

	var gotIsAdmin string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotIsAdmin = req.Header.Get("X-Is-Admin")
		rw.WriteHeader(http.StatusOK)
	})

	serviceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"plan_name": "free"})
	}))
	defer serviceServer.Close()

	plugin := &GatewayPlugin{
		next:         next,
		name:         "test",
		config:       config,
		snapshot:     setupTestSnapshot(),
		identity:     newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: newPlanResolver(serviceServer.URL, 5*time.Second, nil),
	}

	token := createTestToken("test-secret", 7, "file-convert.online", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Is-Admin", "true") // spoof
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if gotIsAdmin != "" {
		t.Errorf("expected spoofed X-Is-Admin cleared on non-admin endpoint, got %q", gotIsAdmin)
	}
}

// Unknown host in enforce mode → 403 and the request is NEVER forwarded.
func TestPlugin_UnknownHost_Enforce_NotForwarded(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "enforce"

	var forwarded bool
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		forwarded = true
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "not-a-known-host.com"
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown host in enforce mode, got %d", rr.Code)
	}
	if forwarded {
		t.Error("expected request NOT forwarded to backend on unknown host (enforce)")
	}
}

// Unauthenticated request to an admin endpoint → 401 and NOT forwarded.
func TestPlugin_AdminEndpoint_NoAuth_NotForwarded(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "disabled"

	var forwarded bool
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		forwarded = true
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:     next,
		name:     "test",
		config:   config,
		snapshot: setupTestSnapshot(),
		identity: newIdentityClient("http://localhost:9999", 1*time.Second, nil),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/conversion/v1/admin/users", nil)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for admin endpoint without auth, got %d", rr.Code)
	}
	if forwarded {
		t.Error("expected unauthenticated admin request NOT forwarded to backend")
	}
}

// Preflight from an unknown host still returns 204 with ACAO — CORS precedes resolution.
func TestPlugin_CORS_Preflight_UnknownHost_Enforce(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "enforce"
	config.CORSAllowedOrigins = []string{"https://file-convert.online"}

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	plugin := &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
	}

	req := httptest.NewRequest(http.MethodOptions, "/api/conversion/v1/convert", nil)
	req.Host = "totally-unknown.example"
	req.Header.Set("Origin", "https://file-convert.online")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 preflight even from unknown host, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://file-convert.online" {
		t.Errorf("expected ACAO on preflight, got %q", got)
	}
}
