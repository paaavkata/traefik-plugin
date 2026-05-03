package traefik_gateway_plugin

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenClaims holds the decoded JWT fields relevant to this plugin.
type TokenClaims struct {
	UserID    string
	Issuer    string
	ExpiresAt time.Time
}

// parseJWT extracts and validates a JWT from the Authorization header value.
// Returns nil claims (no error) if the header is empty (anonymous request).
func parseJWT(authHeader, secret, expectedIssuer string) (*TokenClaims, error) {
	if authHeader == "" {
		return nil, nil
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == authHeader {
		return nil, fmt.Errorf("malformed authorization header")
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("cannot parse claims")
	}

	iss, _ := claims.GetIssuer()
	if expectedIssuer != "" && iss != expectedIssuer {
		return nil, fmt.Errorf("issuer mismatch: got %q, want %q", iss, expectedIssuer)
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		return nil, fmt.Errorf("token missing subject")
	}

	exp, _ := claims.GetExpirationTime()
	if exp != nil && exp.Time.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	return &TokenClaims{
		UserID:    sub,
		Issuer:    iss,
		ExpiresAt: exp.Time,
	}, nil
}
