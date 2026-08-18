package traefik_gateway_plugin

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func createTestToken(secret string, userID int, issuer string, expiresAt time.Time) string {
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Issuer:    issuer,
		Subject:   fmt.Sprintf("%d", userID),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(secret))
	return signed
}

// createTestTokenWithApp mints a token carrying the per-app "app_id" claim (§8.5).
func createTestTokenWithApp(secret string, userID int, issuer, appID string, expiresAt time.Time) string {
	claims := jwt.MapClaims{
		"exp":    jwt.NewNumericDate(expiresAt),
		"iss":    issuer,
		"sub":    fmt.Sprintf("%d", userID),
		"app_id": appID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(secret))
	return signed
}

func TestParseJWT_ValidToken(t *testing.T) {
	secret := "test-secret"
	token := createTestToken(secret, 42, "file-convert.online", time.Now().Add(time.Hour))

	claims, err := parseJWT("Bearer "+token, secret, "file-convert.online")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims == nil {
		t.Fatal("expected claims, got nil")
	}
	if claims.UserID != "42" {
		t.Errorf("expected UserID=42, got %s", claims.UserID)
	}
}

func TestParseJWT_EmptyHeader(t *testing.T) {
	claims, err := parseJWT("", "secret", "file-convert.online")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims != nil {
		t.Error("expected nil claims for empty header")
	}
}

func TestParseJWT_ExpiredToken(t *testing.T) {
	secret := "test-secret"
	token := createTestToken(secret, 1, "file-convert.online", time.Now().Add(-time.Hour))

	_, err := parseJWT("Bearer "+token, secret, "file-convert.online")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestParseJWT_WrongIssuer(t *testing.T) {
	secret := "test-secret"
	token := createTestToken(secret, 1, "wrong-issuer", time.Now().Add(time.Hour))

	_, err := parseJWT("Bearer "+token, secret, "file-convert.online")
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestParseJWT_WrongSecret(t *testing.T) {
	token := createTestToken("real-secret", 1, "file-convert.online", time.Now().Add(time.Hour))

	_, err := parseJWT("Bearer "+token, "wrong-secret", "file-convert.online")
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestParseJWT_MalformedHeader(t *testing.T) {
	_, err := parseJWT("Basic abc123", "secret", "file-convert.online")
	if err == nil {
		t.Fatal("expected error for non-Bearer header")
	}
}

// The "app_id" claim (§8.5) is surfaced on TokenClaims when present.
func TestParseJWT_AppIDClaim(t *testing.T) {
	secret := "test-secret"
	token := createTestTokenWithApp(secret, 42, "file-convert.online", "fileconvert", time.Now().Add(time.Hour))

	claims, err := parseJWT("Bearer "+token, secret, "file-convert.online")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.AppID != "fileconvert" {
		t.Errorf("expected AppID=fileconvert, got %q", claims.AppID)
	}
}

// Legacy tokens without the claim parse fine with an empty AppID.
func TestParseJWT_AppIDClaim_AbsentIsEmpty(t *testing.T) {
	secret := "test-secret"
	token := createTestToken(secret, 42, "file-convert.online", time.Now().Add(time.Hour))

	claims, err := parseJWT("Bearer "+token, secret, "file-convert.online")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.AppID != "" {
		t.Errorf("expected empty AppID for legacy token, got %q", claims.AppID)
	}
}
