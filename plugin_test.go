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
			re := compileRegex(ep.PathRegex, ep.FullPath, nil)
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
