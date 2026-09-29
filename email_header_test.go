package traefik_gateway_plugin

import (
	"net/http"
	"testing"
	"time"
)

// userEmailHeader: stripped on every path, stamped only from a verified
// Keycloak email claim; inert (untouched) when not configured.
func TestPlugin_UserEmailHeader(t *testing.T) {
	ts1, ts2 := newTestJWKSServer(t), newTestJWKSServer(t)
	k1 := ts1.newKey("kid-s")
	ts2.newKey("kid-f")
	var got http.Header
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		got = req.Header.Clone()
		rw.WriteHeader(http.StatusOK)
	})
	spoof := map[string]string{"X-User-Email": "victim@example.com"}
	claims := func(email string, verified interface{}) string {
		c := keycloakClaims(time.Now().Add(time.Hour))
		c["email"] = email
		c["email_verified"] = verified
		return mintKeycloakToken(t, k1, "kid-s", c)
	}
	legacy := createTestTokenWithApp("test-secret", 7, "file-convert.online", "fileconvert", time.Now().Add(time.Hour))

	on := newTwoRealmPlugin(t, ts1, ts2, true, next)
	on.config.UserEmailHeader = "X-User-Email"
	off := newTwoRealmPlugin(t, ts1, ts2, true, next)

	cases := []struct {
		name  string
		p     *GatewayPlugin
		url   string
		token string
		want  string
	}{
		{"verified claim stamped over spoof", on, scanURL, claims("me@example.com", true), "me@example.com"},
		{"unverified claim not stamped", on, scanURL, claims("me@example.com", false), ""},
		{"verified as string is not verified", on, scanURL, claims("me@example.com", "true"), ""},
		{"anonymous: spoof stripped", on, scanURL, "", ""},
		{"unregistered path: spoof stripped", on, "http://scantinel.ai/api/scan/v1/schedules", claims("me@example.com", true), ""},
		{"legacy HS256: spoof stripped", on, fcURL, legacy, ""},
		{"not configured: inert", off, scanURL, claims("me@example.com", true), "victim@example.com"},
	}
	for _, tc := range cases {
		got = nil
		if rr := serve(tc.p, tc.url, tc.token, spoof); rr.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", tc.name, rr.Code, rr.Body.String())
		}
		if v := got.Get("X-User-Email"); v != tc.want {
			t.Errorf("%s: X-User-Email=%q, want %q", tc.name, v, tc.want)
		}
	}
}
