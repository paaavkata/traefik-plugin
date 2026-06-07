package traefik_gateway_plugin

import (
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
	}

	compiled := make([]compiledEndpoint, 0)
	for _, svc := range sc.snapshot.Services {
		for _, ep := range svc.Endpoints {
			re := compileRegex(ep.PathRegex, ep.FullPath)
			compiled = append(compiled, compiledEndpoint{
				SnapshotEndpointDTO: ep,
				regex:               re,
			})
		}
	}
	sc.compiled = compiled
	return sc
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
