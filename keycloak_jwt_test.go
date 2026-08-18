package traefik_gateway_plugin

// Tests for the dual-issuer (Keycloak RS256/JWKS) path. A real RSA keypair is
// generated per test server; tokens are minted with golang-jwt and validated
// against an httptest JWKS endpoint — exercising the exact fetch/parse/verify
// code that runs under Yaegi in Traefik.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testKeycloakIssuer = "https://auth.test/realms/platform"

// --- JWKS test server -------------------------------------------------------

type testJWKSServer struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	pubs    map[string]*rsa.PublicKey // kid → public key currently published
	fetches int
	fail    bool // when true the endpoint returns 500
}

func newTestJWKSServer(t *testing.T) *testJWKSServer {
	ts := &testJWKSServer{t: t, pubs: map[string]*rsa.PublicKey{}}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		ts.fetches++
		if ts.fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		keys := []map[string]string{}
		for kid, pub := range ts.pubs {
			keys = append(keys, map[string]string{
				"kid": kid,
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

// newKey generates an RSA keypair and publishes its public half under kid.
func (ts *testJWKSServer) newKey(kid string) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		ts.t.Fatalf("rsa.GenerateKey: %v", err)
	}
	ts.mu.Lock()
	ts.pubs[kid] = &key.PublicKey
	ts.mu.Unlock()
	return key
}

func (ts *testJWKSServer) removeKey(kid string) {
	ts.mu.Lock()
	delete(ts.pubs, kid)
	ts.mu.Unlock()
}

func (ts *testJWKSServer) setFail(fail bool) {
	ts.mu.Lock()
	ts.fail = fail
	ts.mu.Unlock()
}

func (ts *testJWKSServer) fetchCount() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.fetches
}

// cache builds a warmed JWKSCache pointed at this server (not the shared map —
// tests need isolated instances).
func (ts *testJWKSServer) cache(refetchCooldown time.Duration) *JWKSCache {
	jc := newJWKSCache(ts.srv.URL, 2*time.Second, refetchCooldown, nil)
	if err := jc.refresh(); err != nil {
		ts.t.Fatalf("jwks warm fetch: %v", err)
	}
	return jc
}

// --- token minting ----------------------------------------------------------

// keycloakClaims returns the claim set a scantinel-web Keycloak access token carries.
func keycloakClaims(expiresAt time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":    testKeycloakIssuer,
		"sub":    "3f8e9a2c-0000-4000-8000-c0ffee000001",
		"exp":    jwt.NewNumericDate(expiresAt),
		"iat":    jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		"azp":    "scantinel-web",
		"app_id": "scantinel",
		"resource_access": map[string]interface{}{
			"scantinel-web": map[string]interface{}{
				"roles": []interface{}{"scanner"},
			},
		},
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"default-roles-platform"},
		},
	}
}

func mintKeycloakToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign RS256 token: %v", err)
	}
	return signed
}

func defaultAdminRoles() []string { return []string{"admin", "owner"} }

// --- parseKeycloakJWT unit tests -------------------------------------------

func TestParseKeycloakJWT_ValidToken_SubFallback(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	token := mintKeycloakToken(t, key, "kid-1", keycloakClaims(time.Now().Add(time.Hour)))
	claims, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claims.Keycloak {
		t.Error("expected Keycloak=true")
	}
	if claims.UserID != "3f8e9a2c-0000-4000-8000-c0ffee000001" {
		t.Errorf("expected UserID=sub (no luid claim), got %q", claims.UserID)
	}
	if claims.AppID != "scantinel" {
		t.Errorf("expected AppID=scantinel, got %q", claims.AppID)
	}
	if claims.IsAdmin {
		t.Error("expected IsAdmin=false")
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "scanner" {
		t.Errorf("expected roles [scanner default-roles-platform], got %v", claims.Roles)
	}
}

func TestParseKeycloakJWT_LuidClaimPreferredOverSub(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	c := keycloakClaims(time.Now().Add(time.Hour))
	c["luid"] = "12345" // legacy_user_id mapper — migrated numeric id
	token := mintKeycloakToken(t, key, "kid-1", c)

	claims, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != "12345" {
		t.Errorf("expected UserID=12345 from luid, got %q", claims.UserID)
	}
}

func TestParseKeycloakJWT_ClientAdminRole(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	c := keycloakClaims(time.Now().Add(time.Hour))
	c["resource_access"] = map[string]interface{}{
		"scantinel-web": map[string]interface{}{"roles": []interface{}{"admin", "scanner"}},
		// Roles of OTHER clients must not leak in.
		"fileconvert-web": map[string]interface{}{"roles": []interface{}{"owner"}},
	}
	token := mintKeycloakToken(t, key, "kid-1", c)

	claims, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claims.IsAdmin {
		t.Error("expected IsAdmin=true for client role 'admin'")
	}
	for _, r := range claims.Roles {
		if r == "owner" {
			t.Error("roles of a non-azp client leaked into claims.Roles")
		}
	}
}

func TestParseKeycloakJWT_ExpiredToken(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	token := mintKeycloakToken(t, key, "kid-1", keycloakClaims(time.Now().Add(-time.Hour)))
	_, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestParseKeycloakJWT_ExpiredWithinLeeway(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	// Expired 10s ago but leeway is 30s → clock-skew tolerance accepts it.
	token := mintKeycloakToken(t, key, "kid-1", keycloakClaims(time.Now().Add(-10*time.Second)))
	_, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err != nil {
		t.Fatalf("expected leeway to accept slightly-expired token, got %v", err)
	}
}

func TestParseKeycloakJWT_WrongIssuer(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	c := keycloakClaims(time.Now().Add(time.Hour))
	c["iss"] = "https://evil.example/realms/platform"
	token := mintKeycloakToken(t, key, "kid-1", c)

	_, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestParseKeycloakJWT_MissingAppIDClaim(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	c := keycloakClaims(time.Now().Add(time.Hour))
	delete(c, "app_id")
	token := mintKeycloakToken(t, key, "kid-1", c)

	_, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err == nil {
		t.Fatal("expected error for missing app_id claim (fail closed)")
	}
}

// Alg-confusion guard: an HS256 token (even a validly-signed legacy one) must
// never pass the Keycloak RS256 path.
func TestParseKeycloakJWT_HS256Rejected(t *testing.T) {
	ts := newTestJWKSServer(t)
	ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	token := createTestTokenWithApp("legacy-secret", 42, testKeycloakIssuer, "scantinel", time.Now().Add(time.Hour))
	_, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err == nil {
		t.Fatal("expected HS256 token to be rejected on the Keycloak path")
	}
}

func TestParseKeycloakJWT_WrongKeySignature(t *testing.T) {
	ts := newTestJWKSServer(t)
	ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	// Signed by an unrelated key but claiming the published kid.
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := mintKeycloakToken(t, rogue, "kid-1", keycloakClaims(time.Now().Add(time.Hour)))
	if _, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles()); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestParseKeycloakJWT_EmptyHeaderIsAnonymous(t *testing.T) {
	ts := newTestJWKSServer(t)
	jc := newJWKSCache(ts.srv.URL, time.Second, time.Second, nil)
	claims, err := parseKeycloakJWT("", jc, testKeycloakIssuer, "luid", 0, defaultAdminRoles())
	if err != nil || claims != nil {
		t.Fatalf("expected nil,nil for empty header, got %v, %v", claims, err)
	}
}

// --- JWKS cache behaviour ---------------------------------------------------

// Key rotation: a token signed by a newly-published kid triggers an on-demand
// refetch and then validates.
func TestJWKS_UnknownKidTriggersRefetch(t *testing.T) {
	ts := newTestJWKSServer(t)
	ts.newKey("kid-old")
	jc := ts.cache(0) // no cooldown — refetch immediately

	fetchesBefore := ts.fetchCount()

	// Rotate: new key published, old removed.
	newKey := ts.newKey("kid-new")
	ts.removeKey("kid-old")

	token := mintKeycloakToken(t, newKey, "kid-new", keycloakClaims(time.Now().Add(time.Hour)))
	claims, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err != nil {
		t.Fatalf("expected rotation pickup via refetch, got %v", err)
	}
	if claims.AppID != "scantinel" {
		t.Errorf("unexpected claims after rotation: %+v", claims)
	}
	if ts.fetchCount() <= fetchesBefore {
		t.Error("expected an on-demand JWKS refetch for the unknown kid")
	}

	// And the rotated-out kid no longer validates (cache was swapped, not merged).
	oldToken := mintKeycloakToken(t, newKey, "kid-old", keycloakClaims(time.Now().Add(time.Hour)))
	if _, err := parseKeycloakJWT("Bearer "+oldToken, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles()); err == nil {
		t.Fatal("expected rotated-out kid to be rejected")
	}
}

func TestJWKS_UnknownKidFailsClosed(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(0)

	token := mintKeycloakToken(t, key, "kid-bogus", keycloakClaims(time.Now().Add(time.Hour)))
	if _, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles()); err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

// Unknown-kid refetches are rate-limited by the cooldown (key-probe flood guard).
func TestJWKS_RefetchCooldown(t *testing.T) {
	ts := newTestJWKSServer(t)
	ts.newKey("kid-1")
	jc := ts.cache(time.Hour) // warm fetch just happened → cooldown active

	before := ts.fetchCount()
	for i := 0; i < 5; i++ {
		if _, err := jc.keyForKid("kid-bogus"); err == nil {
			t.Fatal("expected error for unknown kid")
		}
	}
	if got := ts.fetchCount(); got != before {
		t.Errorf("expected no refetches within cooldown, got %d extra", got-before)
	}
}

// Last-good fallback: when the JWKS endpoint goes down, previously cached keys
// keep validating (a Keycloak outage must not kill existing sessions).
func TestJWKS_LastGoodFallbackOnFetchFailure(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	jc := ts.cache(0)

	ts.setFail(true)

	// Background/on-demand refresh now fails…
	if err := jc.refresh(); err == nil {
		t.Fatal("expected refresh to fail while server is down")
	}
	// …but the cached key still serves.
	token := mintKeycloakToken(t, key, "kid-1", keycloakClaims(time.Now().Add(time.Hour)))
	if _, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles()); err != nil {
		t.Fatalf("expected last-good key to keep validating, got %v", err)
	}
}

// OIDC discovery URL support: the configured URL may serve a discovery document
// whose jwks_uri points at the real JWKS.
func TestJWKS_OIDCDiscoveryURL(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")

	disc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"jwks_uri": ts.srv.URL})
	}))
	defer disc.Close()

	jc := newJWKSCache(disc.URL, 2*time.Second, 0, nil)
	if err := jc.refresh(); err != nil {
		t.Fatalf("discovery refresh failed: %v", err)
	}
	token := mintKeycloakToken(t, key, "kid-1", keycloakClaims(time.Now().Add(time.Hour)))
	if _, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles()); err != nil {
		t.Fatalf("unexpected error via discovery URL: %v", err)
	}
}

// --- config validation ------------------------------------------------------

func TestBuildKeycloakAppSet(t *testing.T) {
	// Empty list ⇒ disabled, no validation demands.
	apps, err := buildKeycloakAppSet(&Config{})
	if err != nil || len(apps) != 0 {
		t.Fatalf("expected empty set, got %v, %v", apps, err)
	}

	// Apps without JWKS URL ⇒ hard config error (never silently fall back to HS256).
	if _, err := buildKeycloakAppSet(&Config{KeycloakApps: []string{"scantinel"}, KeycloakIssuer: testKeycloakIssuer}); err == nil {
		t.Fatal("expected error for missing keycloakJwksUrl")
	}
	if _, err := buildKeycloakAppSet(&Config{KeycloakApps: []string{"scantinel"}, KeycloakJWKSURL: "http://kc/certs"}); err == nil {
		t.Fatal("expected error for missing keycloakIssuer")
	}

	apps, err = buildKeycloakAppSet(&Config{
		KeycloakApps:    []string{" scantinel ", ""},
		KeycloakJWKSURL: "http://kc/certs",
		KeycloakIssuer:  testKeycloakIssuer,
	})
	if err != nil || !apps["scantinel"] || len(apps) != 1 {
		t.Fatalf("expected {scantinel}, got %v, %v", apps, err)
	}
}

// --- plugin-level dispatch tests -------------------------------------------

// setupDualAppSnapshot: fileconvert endpoints (as in setupTestSnapshot) plus a
// scantinel app with a free and an admin endpoint.
func setupDualAppSnapshot() *SnapshotCache {
	sc := setupTestSnapshot()
	scantinel := SnapshotAppDTO{
		AppID: "scantinel",
		Services: []SnapshotServiceDTO{
			{
				UID:      "svc-scan",
				Slug:     "scan",
				BasePath: "/api/scan",
				Endpoints: []SnapshotEndpointDTO{
					{
						UID:         "sep1",
						Method:      "POST",
						Path:        "/v1/scans",
						FullPath:    "/api/scan/v1/scans",
						PathRegex:   `^/api/scan/v1/scans$`,
						AccessLevel: "free",
					},
					{
						UID:         "sep2",
						Method:      "GET",
						Path:        "/v1/admin/findings",
						FullPath:    "/api/scan/v1/admin/findings",
						PathRegex:   `^/api/scan/v1/admin/findings$`,
						AccessLevel: "admin",
					},
				},
			},
		},
	}
	sc.snapshot.Apps = append(sc.snapshot.Apps, scantinel)
	for _, svc := range scantinel.Services {
		for _, ep := range svc.Endpoints {
			sc.compiled = append(sc.compiled, compiledEndpoint{
				SnapshotEndpointDTO: ep,
				AppID:               scantinel.AppID,
				regex:               compileRegex(ep.PathRegex, ep.FullPath),
			})
		}
	}
	return sc
}

func setupDualAppRegistry() *AppRegistryCache {
	return &AppRegistryCache{
		byHost: map[string]string{
			"fileconvert.online": "fileconvert",
			"scantinel.ai":       "scantinel",
		},
		loaded: true,
		stopCh: make(chan struct{}),
	}
}

// newDualIssuerPlugin builds a hand-wired plugin with both auth paths active.
func newDualIssuerPlugin(t *testing.T, ts *testJWKSServer, next http.Handler) *GatewayPlugin {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.KeycloakApps = []string{"scantinel"}
	config.KeycloakJWKSURL = ts.srv.URL
	config.KeycloakIssuer = testKeycloakIssuer

	kcApps, err := buildKeycloakAppSet(config)
	if err != nil {
		t.Fatalf("buildKeycloakAppSet: %v", err)
	}
	return &GatewayPlugin{
		next:           next,
		name:           "test",
		config:         config,
		snapshot:       setupDualAppSnapshot(),
		appRegistry:    setupDualAppRegistry(),
		identity:       newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver:   newPlanResolver("http://localhost:9999", 1*time.Second, nil),
		jwks:           ts.cache(0),
		keycloakApps:   kcApps,
		keycloakLeeway: time.Duration(config.KeycloakClockSkewSeconds) * time.Second,
	}
}

func TestPlugin_Keycloak_ScantinelToken_StampsHeaders(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")

	var gotUserID, gotAppID, gotIsAdmin, gotRoles string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUserID = req.Header.Get("X-User-Id")
		gotAppID = req.Header.Get("X-App-Id")
		gotIsAdmin = req.Header.Get("X-Is-Admin")
		gotRoles = req.Header.Get("X-User-Roles")
		rw.WriteHeader(http.StatusOK)
	})
	plugin := newDualIssuerPlugin(t, ts, next)

	c := keycloakClaims(time.Now().Add(time.Hour))
	c["luid"] = "777"
	c["resource_access"] = map[string]interface{}{
		"scantinel-web": map[string]interface{}{"roles": []interface{}{"admin", "scanner"}},
	}
	token := mintKeycloakToken(t, key, "kid-1", c)

	req := httptest.NewRequest(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Spoofed trust headers must be stripped/re-stamped.
	req.Header.Set("X-User-Id", "spoof")
	req.Header.Set("X-Is-Admin", "true")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "777" {
		t.Errorf("expected X-User-Id=777 (luid), got %q", gotUserID)
	}
	if gotAppID != "scantinel" {
		t.Errorf("expected X-App-Id=scantinel, got %q", gotAppID)
	}
	if gotIsAdmin != "true" {
		t.Errorf("expected X-Is-Admin=true from client role, got %q", gotIsAdmin)
	}
	if !strings.Contains(gotRoles, "scanner") {
		t.Errorf("expected X-User-Roles to contain scanner, got %q", gotRoles)
	}
}

// Replay check §8.5 survives verbatim: a Keycloak token whose app_id claim says
// fileconvert is rejected on the scantinel host.
func TestPlugin_Keycloak_AppIDMismatch_401(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newDualIssuerPlugin(t, ts, next)

	c := keycloakClaims(time.Now().Add(time.Hour))
	c["app_id"] = "fileconvert"
	token := mintKeycloakToken(t, key, "kid-1", c)

	req := httptest.NewRequest(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for cross-app token replay, got %d", rr.Code)
	}
}

func TestPlugin_Keycloak_ExpiredToken_401(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newDualIssuerPlugin(t, ts, next)

	token := mintKeycloakToken(t, key, "kid-1", keycloakClaims(time.Now().Add(-time.Hour)))
	req := httptest.NewRequest(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", rr.Code)
	}
}

// A legacy HS256 token presented on a Keycloak app's host must be rejected
// (dispatch is by app_id; the RS256 validator never accepts HS256).
func TestPlugin_Keycloak_HS256TokenOnScantinelHost_401(t *testing.T) {
	ts := newTestJWKSServer(t)
	ts.newKey("kid-1")
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newDualIssuerPlugin(t, ts, next)

	token := createTestTokenWithApp("test-secret", 42, "file-convert.online", "scantinel", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for HS256 token on Keycloak app, got %d", rr.Code)
	}
}

// Anonymous requests on a Keycloak app still pass free endpoints (contract parity
// with the legacy path).
func TestPlugin_Keycloak_AnonymousFreeEndpoint_OK(t *testing.T) {
	ts := newTestJWKSServer(t)
	ts.newKey("kid-1")
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newDualIssuerPlugin(t, ts, next)

	req := httptest.NewRequest(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", nil)
	req.Header.Set("X-Session-Id", "sess-anon-1")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for anonymous free endpoint, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Keycloak admin endpoint: token roles gate access without identity-service
// (which is unreachable in this test — proving no HTTP round-trip is needed).
func TestPlugin_Keycloak_AdminEndpoint_TokenRoles(t *testing.T) {
	ts := newTestJWKSServer(t)
	key := ts.newKey("kid-1")
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newDualIssuerPlugin(t, ts, next)

	// Non-admin → 403.
	token := mintKeycloakToken(t, key, "kid-1", keycloakClaims(time.Now().Add(time.Hour)))
	req := httptest.NewRequest(http.MethodGet, "http://scantinel.ai/api/scan/v1/admin/findings", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin Keycloak user, got %d", rr.Code)
	}

	// Admin client role → 200.
	c := keycloakClaims(time.Now().Add(time.Hour))
	c["resource_access"] = map[string]interface{}{
		"scantinel-web": map[string]interface{}{"roles": []interface{}{"admin"}},
	}
	token = mintKeycloakToken(t, key, "kid-1", c)
	req = httptest.NewRequest(http.MethodGet, "http://scantinel.ai/api/scan/v1/admin/findings", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for Keycloak admin, got %d: %s", rr.Code, rr.Body.String())
	}
}

// REGRESSION: with the Keycloak path fully configured, fileconvert HS256 tokens
// still validate and stamp headers exactly as before.
func TestPlugin_HS256Fileconvert_UnchangedWithKeycloakConfigured(t *testing.T) {
	ts := newTestJWKSServer(t)
	ts.newKey("kid-1")

	var gotUserID, gotAppID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUserID = req.Header.Get("X-User-Id")
		gotAppID = req.Header.Get("X-App-Id")
		rw.WriteHeader(http.StatusOK)
	})
	plugin := newDualIssuerPlugin(t, ts, next)

	token := createTestTokenWithApp("test-secret", 42, "file-convert.online", "fileconvert", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodPost, "http://fileconvert.online/api/conversion/v1/convert", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for legacy HS256 token, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "42" {
		t.Errorf("expected X-User-Id=42, got %q", gotUserID)
	}
	if gotAppID != "fileconvert" {
		t.Errorf("expected X-App-Id=fileconvert, got %q", gotAppID)
	}

	// And the reverse replay: an RS256 scantinel token on the fileconvert host
	// hits the HS256 validator and fails → 401.
	key := ts.newKey("kid-2")
	kcToken := mintKeycloakToken(t, key, "kid-2", keycloakClaims(time.Now().Add(time.Hour)))
	req = httptest.NewRequest(http.MethodPost, "http://fileconvert.online/api/conversion/v1/convert", nil)
	req.Header.Set("Authorization", "Bearer "+kcToken)
	rr = httptest.NewRecorder()
	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for RS256 token on HS256 app, got %d", rr.Code)
	}
}
