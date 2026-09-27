package traefik_gateway_plugin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractOwner(t *testing.T) {
	sc := setupTestSnapshot()
	cases := []struct{ method, url, want string }{
		{"GET", "/api/conversion/v1/user/42", "42"},
		{"GET", "/api/conversion/v1/owned?user_id=7", "7"},
		{"GET", "/api/conversion/v1/owned", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.url, nil)
		ep := sc.matchEndpoint("fileconvert", c.method, req.URL.Path)
		if ep == nil {
			t.Fatalf("%s: no endpoint", c.url)
		}
		if got := extractOwner(ep, req); got != c.want {
			t.Errorf("%s: got %q want %q", c.url, got, c.want)
		}
	}
	// malformed descriptor / unknown capture fail closed to "".
	ep := &compiledEndpoint{SnapshotEndpointDTO: SnapshotEndpointDTO{OwnerParam: "path:nope"}, regex: compileRegex(`^/u/(?P<id>[^/]+)$`, "")}
	if got := extractOwner(ep, httptest.NewRequest("GET", "/u/1", nil)); got != "" {
		t.Errorf("unknown capture: got %q", got)
	}
	ep.OwnerParam = "bogus"
	if got := extractOwner(ep, httptest.NewRequest("GET", "/u/1", nil)); got != "" {
		t.Errorf("malformed: got %q", got)
	}
}

func TestOwnerMatches(t *testing.T) {
	uid := "3f8e9a2c-0000-4000-8000-c0ffee000001"
	for _, c := range []struct {
		owner, id, uid string
		want           bool
	}{
		{"42", "42", "", true},
		{"43", "42", "", false},
		{uid, "42", uid, true},
		{"", "", "", false},
		{"", "42", "", false},
		{"x", "42", "", false},
	} {
		if got := ownerMatches(c.owner, c.id, c.uid); got != c.want {
			t.Errorf("ownerMatches(%q,%q,%q)=%v want %v", c.owner, c.id, c.uid, got, c.want)
		}
	}
}

// Legacy HS256 path: regular user own id / other id / admin any id / anonymous,
// spoofed X-Is-Admin, query form, and owner+admin gate interaction.
func TestPlugin_OwnerGate_Legacy(t *testing.T) {
	admin := newAuthzIdentityServer(t, []string{"Admin"}, []string{"*"}, true, http.StatusOK)
	defer admin.Close()
	user := newAuthzIdentityServer(t, []string{"User"}, []string{}, false, http.StatusOK)
	defer user.Close()
	plans := newPlanServer(t)
	defer plans.Close()

	newP := func(identityURL string, forwarded *bool) *GatewayPlugin {
		config := CreateConfig()
		config.JWTSecret = "test-secret"
		config.DisableRateLimit = true
		config.AppResolutionMode = "disabled"
		return &GatewayPlugin{
			next:         http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { *forwarded = true; rw.WriteHeader(http.StatusOK) }),
			name:         "test",
			config:       config,
			snapshot:     setupTestSnapshot(),
			identity:     newIdentityClient(identityURL, 5*time.Second, nil),
			planResolver: newPlanResolver(plans.URL, 5*time.Second, nil),
		}
	}
	tok42 := createTestToken("test-secret", 42, "file-convert.online", time.Now().Add(time.Hour))

	cases := []struct {
		name, identity, url, token string
		hdr                        map[string]string
		want                       int
	}{
		{"own id", user.URL, "/api/conversion/v1/user/42", tok42, nil, 200},
		{"other id", user.URL, "/api/conversion/v1/user/43", tok42, nil, 403},
		{"padded id", user.URL, "/api/conversion/v1/user/042", tok42, nil, 403},
		{"forged admin header", user.URL, "/api/conversion/v1/user/43", tok42, map[string]string{"X-Is-Admin": "true", "X-User-Roles": "admin"}, 403},
		{"admin any id", admin.URL, "/api/conversion/v1/user/43", tok42, nil, 200},
		{"anonymous", user.URL, "/api/conversion/v1/user/42", "", nil, 401},
		{"query own", user.URL, "/api/conversion/v1/owned?user_id=42", tok42, nil, 200},
		{"query other", user.URL, "/api/conversion/v1/owned?user_id=1", tok42, nil, 403},
		{"query absent", user.URL, "/api/conversion/v1/owned", tok42, nil, 403},
		{"admin+owner gate, non-admin own id", user.URL, "/api/conversion/v1/admin/user/42", tok42, nil, 403},
		{"admin+owner gate, admin other id", admin.URL, "/api/conversion/v1/admin/user/43", tok42, nil, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			forwarded := false
			p := newP(c.identity, &forwarded)
			req := httptest.NewRequest(http.MethodGet, c.url, nil)
			if c.token != "" {
				req.Header.Set("Authorization", "Bearer "+c.token)
			}
			for k, v := range c.hdr {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, req)
			if rr.Code != c.want {
				t.Fatalf("got %d want %d", rr.Code, c.want)
			}
			if forwarded != (c.want == 200) {
				t.Errorf("forwarded=%v for status %d", forwarded, c.want)
			}
		})
	}
}

// Identity down: admin cannot be confirmed ⇒ treated as non-admin ⇒ owner
// equality still enforced (fail-soft never widens access).
func TestPlugin_OwnerGate_IdentityDown_EnforcesOwner(t *testing.T) {
	down := newAuthzIdentityServer(t, nil, nil, false, http.StatusInternalServerError)
	down.Close() // unreachable
	plans := newPlanServer(t)
	defer plans.Close()
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "disabled"
	p := &GatewayPlugin{
		next:         http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) }),
		name:         "test",
		config:       config,
		snapshot:     setupTestSnapshot(),
		identity:     newIdentityClient(down.URL, time.Second, nil),
		planResolver: newPlanResolver(plans.URL, 5*time.Second, nil),
	}
	tok := createTestToken("test-secret", 42, "file-convert.online", time.Now().Add(time.Hour))
	for url, want := range map[string]int{"/api/conversion/v1/user/42": 200, "/api/conversion/v1/user/43": 403} {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("%s: got %d want %d", url, rr.Code, want)
		}
	}
}

// API keys: own id only, never an admin bypass.
func TestPlugin_OwnerGate_APIKey(t *testing.T) {
	srv, _ := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{
		"user_id": "77", "app_id": "fileconvert", "plan": "free", "scopes": []string{},
	})
	defer srv.Close()
	for url, want := range map[string]int{
		"/api/conversion/v1/user/77":          200,
		"/api/conversion/v1/user/78":          403,
		"/api/conversion/v1/owned?user_id=77": 200,
		"/api/conversion/v1/owned?user_id=78": 403,
		"/api/conversion/v1/admin/user/77":    403, // admin-gated: keys denied
	} {
		p := newAPIKeyPlugin(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) }), srv.URL+"/internal/v1/api-keys/verify", nil)
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Host = "fileconvert.online"
		req.Header.Set("X-Api-Key", validKey("ownerkey1234", "sekret"))
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("%s: got %d want %d", url, rr.Code, want)
		}
	}
}

// Keycloak path: own luid (X-User-Id) or own sub (X-User-Uid) pass; other ids
// 403 unless the token carries an admin realm role.
func TestPlugin_OwnerGate_Keycloak(t *testing.T) {
	ts1, ts2 := newTestJWKSServer(t), newTestJWKSServer(t)
	ts1.newKey("kid-s")
	k2 := ts2.newKey("kid-f")
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	p := newTwoRealmPlugin(t, ts1, ts2, false, next)

	userClaims := fcClaims()
	userClaims["realm_access"] = map[string]interface{}{"roles": []interface{}{"user"}}
	userTok := mintKeycloakToken(t, k2, "kid-f", userClaims)
	adminTok := mintKeycloakToken(t, k2, "kid-f", fcClaims())
	sub, _ := userClaims["sub"].(string)
	if sub == "" {
		t.Fatal("test token needs a sub")
	}

	get := func(url, tok string) int {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		return rr.Code
	}
	base := "http://fileconvert.online/api/conversion/v1/user/"
	for _, c := range []struct {
		url, tok string
		want     int
	}{
		{base + "42", userTok, 200},
		{base + sub, userTok, 200},
		{base + "43", userTok, 403},
		{base + "43", adminTok, 200},
	} {
		if got := get(c.url, c.tok); got != c.want {
			t.Errorf("%s: got %d want %d", c.url, got, c.want)
		}
	}
}
