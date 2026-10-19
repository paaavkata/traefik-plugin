package traefik_gateway_plugin

import (
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testCMSIssuer = "https://auth.test/realms/cms"

// testRealm is the RS256 realm the plugin-level tests authenticate against:
// one JWKS server (key kid-1) bound to apps "fileconvert" (testFCIssuer) and
// "cms" (testCMSIssuer), mirroring setupTestAppRegistry's hosts.
type testRealm struct {
	ts  *testJWKSServer
	key *rsa.PrivateKey
}

func newTestRealm(t *testing.T) *testRealm {
	t.Helper()
	ts := newTestJWKSServer(t)
	return &testRealm{ts: ts, key: ts.newKey("kid-1")}
}

// wire binds the realm to p and gives p an app registry when it has none, so
// a request with Host fileconvert.online resolves to app "fileconvert".
func (r *testRealm) wire(p *GatewayPlugin) *GatewayPlugin {
	jc := r.ts.cache(0)
	p.keycloakRealms = map[string]*keycloakRealmRuntime{
		"fileconvert": {issuer: testFCIssuer, jwks: jc},
		"cms":         {issuer: testCMSIssuer, jwks: jc},
	}
	p.keycloakLeeway = 30 * time.Second
	if p.appRegistry == nil {
		p.appRegistry = setupTestAppRegistry()
	}
	return p
}

// token mints a fileconvert-realm token for userID (luid) with realm role
// "member"; extra claims override (e.g. "exp", "app_id", "realm_access").
func (r *testRealm) token(t *testing.T, userID string, extra jwt.MapClaims) string {
	t.Helper()
	c := keycloakClaims(time.Now().Add(time.Hour))
	c["iss"] = testFCIssuer
	c["azp"] = "fileconvert-web"
	c["app_id"] = "fileconvert"
	c["luid"] = userID
	c["resource_access"] = map[string]interface{}{"fileconvert-web": map[string]interface{}{"roles": []interface{}{}}}
	c["realm_access"] = map[string]interface{}{"roles": []interface{}{"member"}}
	for k, v := range extra {
		c[k] = v
	}
	return mintKeycloakToken(t, r.key, "kid-1", c)
}

// admin mints a fileconvert-realm token carrying the realm role "admin".
func (r *testRealm) admin(t *testing.T, userID string) string {
	t.Helper()
	return r.token(t, userID, jwt.MapClaims{"realm_access": map[string]interface{}{"roles": []interface{}{"admin"}}})
}

// mintHS256Token builds a legacy identity-service style token. Only used to
// prove the gateway rejects HS256 everywhere.
func mintHS256Token(secret string, userID int, issuer, appID string, expiresAt time.Time) string {
	claims := jwt.MapClaims{
		"exp":    jwt.NewNumericDate(expiresAt),
		"iss":    issuer,
		"sub":    fmt.Sprintf("%d", userID),
		"app_id": appID,
	}
	signed, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	return signed
}
