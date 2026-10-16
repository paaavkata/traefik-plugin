package traefik_gateway_plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Regression tests for two behaviours that were correct when compiled but
// wrong under yaegi, Traefik's plugin interpreter (prod 500s, 2026-10-16).
// Natively they always passed; they document the contract the startup
// assertion in New() and the explicit keyfunc unpacking in parseKeycloakJWT
// enforce. The interpreter-level check lives in the ops notes (yaegi harness).

// An unknown kid must be a verification error, never a nil key handed to
// golang-jwt (which panics inside rsa.VerifyPKCS1v15).
func TestParseKeycloakJWT_UnknownKidIsError(t *testing.T) {
	ts := newTestJWKSServer(t)
	priv := ts.newKey("kid-1")
	jc := ts.cache(30 * time.Second)

	token := mintKeycloakToken(t, priv, "kid-unknown", keycloakClaims(time.Now().Add(time.Hour)))
	_, err := parseKeycloakJWT("Bearer "+token, jc, testKeycloakIssuer, "luid", 30*time.Second, defaultAdminRoles())
	if err == nil || !strings.Contains(err.Error(), "kid-unknown") {
		t.Fatalf("expected unknown-kid error naming the kid, got %v", err)
	}
}

// Every app must be bound to the JWKS cache of ITS realm, not a shared one.
func TestNew_RealmsBoundToOwnJWKS(t *testing.T) {
	dummy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer dummy.Close()

	cfg := CreateConfig()
	cfg.JWTSecret = "x"
	cfg.JWTIssuer = "file-convert.online"
	cfg.ServiceServiceURL = dummy.URL
	cfg.IdentityServiceURL = dummy.URL
	cfg.AppResolutionMode = "disabled"
	cfg.DisableRateLimit = true
	cfg.LogLevel = "error"
	cfg.KeycloakApps = []string{"scantinel"}
	cfg.KeycloakIssuer = "https://auth.scantinel.ai/realms/scantinel"
	cfg.KeycloakJWKSURL = dummy.URL + "/scantinel-jwks"
	cfg.KeycloakRealms = []KeycloakRealm{{
		AppID: "fileconvert", Issuer: "https://auth.file-convert.online/realms/fileconvert",
		JWKSURL: dummy.URL + "/fileconvert-jwks", AcceptLegacy: true,
	}}

	for i := 0; i < 20; i++ {
		h, err := New(context.Background(), http.NotFoundHandler(), cfg, "t")
		if err != nil {
			t.Fatal(err)
		}
		p := h.(*GatewayPlugin)
		for app, want := range map[string]string{"scantinel": cfg.KeycloakJWKSURL, "fileconvert": cfg.KeycloakRealms[0].JWKSURL} {
			jc, ok := p.keycloakRealms[app].jwks.(*JWKSCache)
			if !ok || jc.url != want {
				t.Fatalf("instance %d: app %s bound to %v, want %s", i, app, p.keycloakRealms[app].jwks, want)
			}
		}
	}
}
