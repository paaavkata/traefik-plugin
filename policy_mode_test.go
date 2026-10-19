package traefik_gateway_plugin

// Policy engine (authorizationMode "policy") request-path tests. One test per
// gateway-authorization spec scenario, plus the both-modes matrix.

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testOperatorIssuer = "https://auth.test/realms/infra"

// policyFixtureSnapshot: the dual-app snapshot plus tagged routes and the
// policy registry. Tags are explicit (policy mode never reads access_level).
func policyFixtureSnapshot() *SnapshotCache {
	sc := setupDualAppSnapshot()
	add := func(appID, svcUID, base string, eps ...SnapshotEndpointDTO) {
		for i := range sc.snapshot.Apps {
			if sc.snapshot.Apps[i].AppID == appID {
				sc.snapshot.Apps[i].Services = append(sc.snapshot.Apps[i].Services, SnapshotServiceDTO{UID: svcUID, Slug: svcUID, BasePath: base, Endpoints: eps})
			}
		}
		for _, ep := range eps {
			sc.compiled = append(sc.compiled, compiledEndpoint{SnapshotEndpointDTO: ep, AppID: appID, regex: compileRegex(ep.PathRegex, ep.FullPath)})
		}
	}
	tagged := func(uid, method, path, perm, owner string) SnapshotEndpointDTO {
		return SnapshotEndpointDTO{UID: uid, Method: method, Path: path, FullPath: "/api/cms" + path,
			PathRegex:   "^" + strings.NewReplacer("{uid}", "[^/]+", "{id}", "(?P<id>[^/]+)").Replace("/api/cms"+path) + "$",
			AccessLevel: "authenticated", RequiredPermission: perm, OwnerParam: owner,
			RateLimits: map[string]RateLimitValue{"free": {Requests: 5, DurationSeconds: 60}}}
	}
	for _, app := range []string{"fileconvert", "scantinel"} {
		add(app, "cms-"+app, "/api/cms",
			tagged("pub-"+app, "POST", "/v1/content/{uid}/publish", "content.publish", ""),
			tagged("cust-"+app, "GET", "/v1/customers", "customers.read", ""),
			tagged("refund-"+app, "POST", "/v1/refund", "payments.refund", ""),
			tagged("me-"+app, "GET", "/v1/profile", "authenticated", ""),
			tagged("user-"+app, "GET", "/v1/users/{id}", "authenticated", "path:id"),
			tagged("open-"+app, "GET", "/v1/open", "", ""),
		)
	}
	sc.snapshot.Policies = []Policy{
		{Name: "platform-owner", Statements: []Statement{stmt([]string{"*"}, "*")}},
		{Name: "tenant-admin", Statements: []Statement{stmt([]string{"*"}, "@home")}},
		{Name: "tenant-user", Statements: []Statement{stmt([]string{"authenticated"}, "@home")}},
		{Name: "support", Statements: []Statement{stmt([]string{"support.*", "customers.read"}, "*")}},
		{Name: "moderator", Statements: []Statement{stmt([]string{"content.*", "authenticated"}, "@home")}},
	}
	sc.snapshot.Bindings = []Binding{
		{Role: "platform-admin:admin", Policy: "platform-owner"},
		{Role: "platform-admin:support", Policy: "support"},
		{Role: "scantinel-web:admin", Policy: "tenant-admin"},
		{Role: "scantinel-web:moderator", Policy: "moderator"},
		{Role: "default-roles-platform", Policy: "tenant-user"},
	}
	sc.policies = newPolicyIndex(sc.snapshot.Policies, sc.snapshot.Bindings)
	return sc
}

func policyRegistry() *AppRegistryCache {
	return &AppRegistryCache{
		byHost: map[string]string{"fileconvert.online": "fileconvert", "scantinel.ai": "scantinel", "admin.test": "platform-admin"},
		active: map[string]bool{"fileconvert": true, "scantinel": true, "platform-admin": true},
		loaded: true, stopCh: make(chan struct{}),
	}
}

type fakeLimiter struct{ calls int32 }

func (f *fakeLimiter) Check(_ context.Context, _, _ string, limit, _ int) (*RateLimitResult, error) {
	atomic.AddInt32(&f.calls, 1)
	return &RateLimitResult{Allowed: true, Remaining: limit - 1, Limit: limit, ResetAt: time.Now().Add(time.Minute)}, nil
}

type policyHarness struct {
	p                       *GatewayPlugin
	tenant                  *testJWKSServer // scantinel realm (testKeycloakIssuer)
	fc                      *testJWKSServer // fileconvert realm (testFCIssuer)
	operator                *testJWKSServer // infra realm
	tenantKey, fcKey, opKey *rsa.PrivateKey
	got                     http.Header
	nextHits                int32
	logs                    *bytes.Buffer
	limiter                 *fakeLimiter
}

func newPolicyHarness(t *testing.T, mode string) *policyHarness {
	t.Helper()
	h := &policyHarness{tenant: newTestJWKSServer(t), fc: newTestJWKSServer(t), operator: newTestJWKSServer(t), logs: &bytes.Buffer{}, limiter: &fakeLimiter{}}
	h.tenantKey = h.tenant.newKey("kid-s")
	h.fcKey = h.fc.newKey("kid-f")
	h.opKey = h.operator.newKey("kid-o")

	config := CreateConfig()
	config.DisableRateLimit = true
	config.AuthorizationMode = mode
	config.KeycloakApps = []string{"scantinel"}
	config.KeycloakJWKSURL = h.tenant.srv.URL
	config.KeycloakIssuer = testKeycloakIssuer
	config.KeycloakRealms = []KeycloakRealm{{AppID: "fileconvert", Issuer: testFCIssuer, JWKSURL: h.fc.srv.URL}}
	config.OperatorRealm = KeycloakRealm{Issuer: testOperatorIssuer, JWKSURL: h.operator.srv.URL}
	config.UserEmailHeader = "X-User-Email"

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&h.nextHits, 1)
		h.got = req.Header.Clone()
		rw.WriteHeader(http.StatusOK)
	})
	caches := map[string]rsaKeyProvider{h.tenant.srv.URL: h.tenant.cache(0), h.fc.srv.URL: h.fc.cache(0)}
	h.p = wirePlugin(t, config, next, caches)
	h.p.policyMode = mode == "policy"
	h.p.operatorRealm = &keycloakRealmRuntime{issuer: testOperatorIssuer, jwks: h.operator.cache(0)}
	h.p.snapshot = policyFixtureSnapshot()
	h.p.appRegistry = policyRegistry()
	h.p.log = &pluginLogger{level: levelInfo, out: log.New(h.logs, "", 0)}
	h.p.rateLimiter = h.limiter
	return h
}

func (h *policyHarness) operatorToken(t *testing.T, clientRoles ...string) string {
	c := keycloakClaims(time.Now().Add(time.Hour))
	c["iss"] = testOperatorIssuer
	c["azp"] = "platform-admin"
	c["app_id"] = "platform-admin"
	c["sub"] = "op-0000-0000-0000-000000000001"
	c["email"], c["email_verified"] = "op@example.test", true
	roles := []interface{}{}
	for _, r := range clientRoles {
		roles = append(roles, r)
	}
	c["resource_access"] = map[string]interface{}{"platform-admin": map[string]interface{}{"roles": roles}}
	c["realm_access"] = map[string]interface{}{"roles": []interface{}{"default-roles-infra"}}
	return mintKeycloakToken(t, h.opKey, "kid-o", c)
}

func (h *policyHarness) tenantToken(t *testing.T, clientRoles ...string) string {
	c := keycloakClaims(time.Now().Add(time.Hour)) // scantinel realm, azp scantinel-web, realm role default-roles-platform
	roles := []interface{}{"scanner"}
	for _, r := range clientRoles {
		roles = append(roles, r)
	}
	c["resource_access"] = map[string]interface{}{"scantinel-web": map[string]interface{}{"roles": roles}}
	return mintKeycloakToken(t, h.tenantKey, "kid-s", c)
}

func (h *policyHarness) fcToken(t *testing.T) string {
	return mintKeycloakToken(t, h.fcKey, "kid-f", fcClaims())
}

func (h *policyHarness) do(method, url, token string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.p.ServeHTTP(rr, req)
	return rr
}

func errCode(rr *httptest.ResponseRecorder) string {
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return body["error"]
}

// --- issuer set ------------------------------------------------------------

func TestPolicy_OperatorTokenOnTenantHost_Allowed(t *testing.T) {
	h := newPolicyHarness(t, "policy")
	rr := h.do(http.MethodPost, "http://scantinel.ai/api/cms/v1/refund", h.operatorToken(t, "admin"), map[string]string{"X-Is-Admin": "spoof", "X-User-Roles": "spoof"})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if h.got.Get("X-App-Id") != "scantinel" || h.got.Get("X-Is-Admin") != "true" || h.got.Get("X-User-Roles") != "platform-admin:admin" {
		t.Errorf("headers app=%q admin=%q roles=%q", h.got.Get("X-App-Id"), h.got.Get("X-Is-Admin"), h.got.Get("X-User-Roles"))
	}
	if h.got.Get("X-User-Uid") != "op-0000-0000-0000-000000000001" || h.got.Get("X-User-Email") != "op@example.test" {
		t.Errorf("uid=%q email=%q", h.got.Get("X-User-Uid"), h.got.Get("X-User-Email"))
	}
}

func TestPolicy_TenantTokenOnAnotherTenant_401(t *testing.T) {
	h := newPolicyHarness(t, "policy")
	rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/open", h.fcToken(t), nil)
	if rr.Code != http.StatusUnauthorized || errCode(rr) != "unauthorized" {
		t.Fatalf("expected 401 unauthorized, got %d %s", rr.Code, rr.Body.String())
	}
	if h.nextHits != 0 {
		t.Fatal("request reached the backend")
	}
	if !strings.Contains(h.logs.String(), "reason=issuer_rejected") {
		t.Errorf("missing reason code in logs:\n%s", h.logs.String())
	}
	// HS256 is not accepted anywhere.
	legacy := mintHS256Token("test-secret", 7, "file-convert.online", "scantinel", time.Now().Add(time.Hour))
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/open", legacy, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("HS256 on scantinel: expected 401, got %d", rr.Code)
	}
}

// --- requested application -------------------------------------------------

func TestPolicy_RequestedApp(t *testing.T) {
	h := newPolicyHarness(t, "policy")
	op := h.operatorToken(t, "admin")

	// Default to host.
	if rr := h.do(http.MethodGet, "http://fileconvert.online/api/cms/v1/customers", op, nil); rr.Code != http.StatusOK || h.got.Get("X-App-Id") != "fileconvert" {
		t.Fatalf("default-to-host: %d app=%q", rr.Code, h.got.Get("X-App-Id"))
	}
	// Operator targets a tenant from the admin host.
	if rr := h.do(http.MethodGet, "http://admin.test/api/cms/v1/customers", op, map[string]string{"X-App-Id": "scantinel"}); rr.Code != http.StatusOK || h.got.Get("X-App-Id") != "scantinel" {
		t.Fatalf("override: %d app=%q body=%s", rr.Code, h.got.Get("X-App-Id"), rr.Body.String())
	}
	// Unknown application.
	rr := h.do(http.MethodGet, "http://admin.test/api/cms/v1/customers", op, map[string]string{"X-App-Id": "nope"})
	if rr.Code != http.StatusForbidden || errCode(rr) != "unknown_app" {
		t.Fatalf("unknown app: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(h.logs.String(), "reason=unknown_app") {
		t.Error("missing reason=unknown_app")
	}
	// Support (customers.read on *) can read customers on scantinel but not refund.
	sup := h.operatorToken(t, "support")
	if rr := h.do(http.MethodGet, "http://admin.test/api/cms/v1/customers", sup, map[string]string{"X-App-Id": "scantinel"}); rr.Code != http.StatusOK || h.got.Get("X-Is-Admin") != "" {
		t.Fatalf("support customers: %d admin=%q", rr.Code, h.got.Get("X-Is-Admin"))
	}
	if rr := h.do(http.MethodPost, "http://admin.test/api/cms/v1/refund", sup, map[string]string{"X-App-Id": "scantinel"}); rr.Code != http.StatusForbidden {
		t.Fatalf("support refund: expected 403, got %d", rr.Code)
	}
	// A tenant user cannot widen scope by naming another app: its realm is not
	// in that application's issuer set (401), and even a shared-realm token
	// would hold no statement there (403).
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/profile", h.tenantToken(t), map[string]string{"X-App-Id": "fileconvert"}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("tenant user → fileconvert: expected 401, got %d", rr.Code)
	}
	if rr := h.do(http.MethodGet, "http://admin.test/api/cms/v1/profile", h.operatorToken(t, "unbound-role"), map[string]string{"X-App-Id": "scantinel"}); rr.Code != http.StatusForbidden {
		t.Fatalf("operator without binding → scantinel: expected 403, got %d", rr.Code)
	}
	// A route registered for the host app but not for the target is denied, not passed through.
	if rr := h.do(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", op, map[string]string{"X-App-Id": "fileconvert"}); rr.Code != http.StatusForbidden {
		t.Fatalf("not exposed: expected 403, got %d", rr.Code)
	}
}

// --- evaluation ------------------------------------------------------------

func TestPolicy_Evaluation(t *testing.T) {
	h := newPolicyHarness(t, "policy")

	rr := h.do(http.MethodPost, "http://scantinel.ai/api/cms/v1/content/abc/publish", "", nil)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(h.logs.String(), "reason=no_token") {
		t.Fatalf("anonymous on gated: %d\n%s", rr.Code, h.logs.String())
	}
	rr = h.do(http.MethodPost, "http://scantinel.ai/api/cms/v1/content/abc/publish", h.tenantToken(t), nil)
	if rr.Code != http.StatusForbidden || errCode(rr) != "forbidden" || !strings.Contains(h.logs.String(), "reason=no_matching_statement") {
		t.Fatalf("tenant user publish: %d %s", rr.Code, rr.Body.String())
	}
	// Prefix grant on the home application.
	if rr := h.do(http.MethodPost, "http://scantinel.ai/api/cms/v1/content/abc/publish", h.tenantToken(t, "moderator"), nil); rr.Code != http.StatusOK {
		t.Fatalf("moderator publish at home: %d %s", rr.Code, rr.Body.String())
	}
	if h.got.Get("X-Is-Admin") != "" || h.got.Get("X-User-Roles") != "scantinel-web:moderator,default-roles-platform" {
		t.Errorf("moderator headers admin=%q roles=%q", h.got.Get("X-Is-Admin"), h.got.Get("X-User-Roles"))
	}
	// Authenticated tier.
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/profile", h.tenantToken(t), nil); rr.Code != http.StatusOK {
		t.Fatalf("tenant user profile: %d", rr.Code)
	}
	// Token with no bound roles.
	c := keycloakClaims(time.Now().Add(time.Hour))
	c["realm_access"] = map[string]interface{}{"roles": []interface{}{"unbound"}}
	unbound := mintKeycloakToken(t, h.tenantKey, "kid-s", c)
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/profile", unbound, nil); rr.Code != http.StatusForbidden {
		t.Fatalf("unbound roles: expected 403, got %d", rr.Code)
	}
	// Tenant admin is wildcard at home only.
	if rr := h.do(http.MethodPost, "http://scantinel.ai/api/cms/v1/refund", h.tenantToken(t, "admin"), map[string]string{"X-Is-Admin": "true"}); rr.Code != http.StatusOK || h.got.Get("X-Is-Admin") != "true" {
		t.Fatalf("tenant admin at home: %d admin=%q", rr.Code, h.got.Get("X-Is-Admin"))
	}
	// Spoofed admin header without a wildcard grant never survives.
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/profile", h.tenantToken(t), map[string]string{"X-Is-Admin": "true"}); rr.Code != http.StatusOK || h.got.Get("X-Is-Admin") != "" {
		t.Fatalf("spoofed admin: %d admin=%q", rr.Code, h.got.Get("X-Is-Admin"))
	}
	// Untagged route stays open, headers still stamped.
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/open", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("open route anonymous: %d", rr.Code)
	}
}

func TestPolicy_OwnerGateUsesDerivedAdmin(t *testing.T) {
	h := newPolicyHarness(t, "policy")
	mod := h.tenantToken(t, "moderator")
	// Moderator addressing another user → 403 owner_mismatch; own sub → ok.
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/users/someone-else", mod, nil); rr.Code != http.StatusForbidden || !strings.Contains(h.logs.String(), "reason=owner_mismatch") {
		t.Fatalf("moderator other user: %d", rr.Code)
	}
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/users/3f8e9a2c-0000-4000-8000-c0ffee000001", mod, nil); rr.Code != http.StatusOK {
		t.Fatalf("moderator own user: %d", rr.Code)
	}
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/users/someone-else", h.operatorToken(t, "admin"), nil); rr.Code != http.StatusOK {
		t.Fatalf("operator any user: %d", rr.Code)
	}
}

func TestPolicy_RateLimitKeyedByTargetAndWildcardExempt(t *testing.T) {
	h := newPolicyHarness(t, "policy")
	h.p.config.DisableRateLimit = false
	if rr := h.do(http.MethodGet, "http://admin.test/api/cms/v1/customers", h.operatorToken(t, "admin"), map[string]string{"X-App-Id": "scantinel"}); rr.Code != http.StatusOK {
		t.Fatalf("operator: %d", rr.Code)
	}
	if h.limiter.calls != 0 {
		t.Fatalf("wildcard holder must skip the limiter, got %d checks", h.limiter.calls)
	}
	rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/profile", h.tenantToken(t), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("tenant user: %d", rr.Code)
	}
	if h.limiter.calls != 1 {
		t.Fatalf("tenant user must be checked once, got %d", h.limiter.calls)
	}
	if rr.Header().Get("X-RateLimit-Limit") != "5" {
		t.Errorf("rate-limit headers not stamped: %v", rr.Header())
	}
}

// --- legacy adapter --------------------------------------------------------

// --- API keys ----------------------------------------------------------------

func TestPolicy_APIKeyIsTenantUserOfItsApp(t *testing.T) {
	h := newPolicyHarness(t, "policy")
	srv, _ := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{"user_id": "77", "app_id": "fileconvert", "plan": "pro", "scopes": []string{}})
	defer srv.Close()
	h.p.apiKeys = newAPIKeyVerifier(srv.URL+"/internal/v1/api-keys/verify", 2*time.Second, nil, "gw:rl:", nil)
	key := validKey("abcdef123456", "supersecretvalue")

	if rr := h.do(http.MethodGet, "http://fileconvert.online/api/cms/v1/profile", "", map[string]string{"X-Api-Key": key}); rr.Code != http.StatusOK || h.got.Get("X-User-Id") != "77" || h.got.Get("X-Is-Admin") != "" {
		t.Fatalf("key on authenticated route: %d id=%q admin=%q", rr.Code, h.got.Get("X-User-Id"), h.got.Get("X-Is-Admin"))
	}
	if rr := h.do(http.MethodPost, "http://fileconvert.online/api/cms/v1/content/x/publish", "", map[string]string{"X-Api-Key": key}); rr.Code != http.StatusForbidden {
		t.Fatalf("key on content.publish: expected 403, got %d", rr.Code)
	}
	if rr := h.do(http.MethodGet, "http://scantinel.ai/api/cms/v1/profile", "", map[string]string{"X-Api-Key": key}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("key on another app: expected 401, got %d", rr.Code)
	}
}

// --- introspection ----------------------------------------------------------

func TestIAMMe(t *testing.T) {
	for _, mode := range []string{"legacy", "policy"} {
		t.Run(mode, func(t *testing.T) {
			h := newPolicyHarness(t, mode)
			rr := h.do(http.MethodGet, "http://admin.test/api/_iam/me", "", nil)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous: expected 401, got %d", rr.Code)
			}
			rr = h.do(http.MethodGet, "http://admin.test/api/_iam/me", h.operatorToken(t, "admin"), nil)
			if rr.Code != http.StatusOK {
				t.Fatalf("operator: %d %s", rr.Code, rr.Body.String())
			}
			var body struct {
				Subject  string              `json:"subject"`
				UserID   string              `json:"user_id"`
				HomeApp  string              `json:"home_app"`
				Roles    []string            `json:"roles"`
				Policies []string            `json:"policies"`
				Perms    map[string][]string `json:"permissions_by_app"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.HomeApp != "platform-admin" || body.Policies[0] != "platform-owner" || body.Subject == "" || body.UserID == "" {
				t.Errorf("body %+v", body)
			}
			for _, app := range []string{"fileconvert", "scantinel", "platform-admin"} {
				if got := body.Perms[app]; len(got) != 1 || got[0] != "*" {
					t.Errorf("permissions_by_app[%s]=%v", app, got)
				}
			}
			rr = h.do(http.MethodGet, "http://scantinel.ai/api/_iam/me", h.tenantToken(t), nil)
			body.Perms = nil
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK {
				t.Fatalf("tenant: %d %s", rr.Code, rr.Body.String())
			}
			if len(body.Perms) != 1 || body.Perms["scantinel"][0] != "authenticated" {
				t.Errorf("tenant permissions_by_app=%v", body.Perms)
			}
			if h.nextHits != 0 {
				t.Fatal("introspection must never reach a backend")
			}
		})
	}
}

// --- both modes ---------------------------------------------------------------

func TestBothModes_SharedBehaviour(t *testing.T) {
	for _, mode := range []string{"legacy", "policy"} {
		t.Run(mode, func(t *testing.T) {
			h := newPolicyHarness(t, mode)
			if rr := h.do(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", "", nil); rr.Code != http.StatusOK {
				t.Fatalf("anonymous free: %d", rr.Code)
			}
			if rr := h.do(http.MethodPost, "http://scantinel.ai/api/cms/v1/content/x/publish", "", nil); rr.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous gated: %d", rr.Code)
			}
			if rr := h.do(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", h.tenantToken(t), map[string]string{"X-Is-Admin": "true", "X-User-Id": "1"}); rr.Code != http.StatusOK || h.got.Get("X-Is-Admin") != "" || h.got.Get("X-App-Id") != "scantinel" {
				t.Fatalf("tenant user open route: %d admin=%q app=%q", rr.Code, h.got.Get("X-Is-Admin"), h.got.Get("X-App-Id"))
			}
			if rr := h.do(http.MethodGet, "http://nope.test/api/scan/v1/scans", "", nil); rr.Code != http.StatusForbidden {
				t.Fatalf("unknown host: %d", rr.Code)
			}
		})
	}
}

func TestLegacyMode_ShadowLogAndReplayGuardKept(t *testing.T) {
	h := newPolicyHarness(t, "legacy")
	// Legacy engine: the operator token is a foreign issuer on scantinel → 401 (replay guard / realm pin).
	if rr := h.do(http.MethodPost, "http://scantinel.ai/api/cms/v1/refund", h.operatorToken(t, "admin"), nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("legacy: operator on tenant host expected 401, got %d", rr.Code)
	}
	// Tenant admin (keycloakAdminRoles) passes the legacy gate; shadow line reports the policy verdict.
	if rr := h.do(http.MethodPost, "http://scantinel.ai/api/cms/v1/refund", h.tenantToken(t, "admin"), nil); rr.Code != http.StatusOK {
		t.Fatalf("legacy tenant admin: %d", rr.Code)
	}
	if !strings.Contains(h.logs.String(), "shadow=allow") {
		t.Errorf("missing shadow=allow line:\n%s", h.logs.String())
	}
	c := keycloakClaims(time.Now().Add(time.Hour))
	c["realm_access"] = map[string]interface{}{"roles": []interface{}{"unbound"}}
	h.do(http.MethodPost, "http://scantinel.ai/api/scan/v1/scans", mintKeycloakToken(t, h.tenantKey, "kid-s", c), nil)
	if !strings.Contains(h.logs.String(), "unbound_role=[scantinel-web:scanner unbound]") {
		t.Errorf("missing unbound_role line:\n%s", h.logs.String())
	}
}

func TestNew_ConfigValidation(t *testing.T) {
	bad := CreateConfig()
	bad.AuthorizationMode = "yolo"
	bad.DisableRateLimit = true
	if _, err := New(context.Background(), http.NotFoundHandler(), bad, "t"); err == nil {
		t.Fatal("bad authorizationMode accepted")
	}
	half := CreateConfig()
	half.DisableRateLimit = true
	half.OperatorRealm = KeycloakRealm{Issuer: "https://x"}
	if _, err := New(context.Background(), http.NotFoundHandler(), half, "t"); err == nil {
		t.Fatal("half operatorRealm accepted")
	}
	_ = jwt.MapClaims{}
}
