package traefik_gateway_plugin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenClaims holds the decoded JWT fields relevant to this plugin.
type TokenClaims struct {
	UserID string
	Issuer string
	// AppID is the optional "app_id" claim (guide §8.5). The gateway enforces that a
	// token minted for one app is not replayed against another. Empty for legacy
	// tokens issued before the claim existed (allowed during rollout).
	AppID     string
	ExpiresAt time.Time

	// Keycloak-only fields — populated by parseKeycloakJWT, zero for legacy HS256
	// tokens (whose admin/roles resolution stays on the identity-service HTTP path).
	Keycloak bool
	IsAdmin  bool
	Roles    []string
	Subject  string // Keycloak `sub` (UUID) → X-User-Uid
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

	expAt := time.Time{}
	if exp != nil {
		expAt = exp.Time
	}

	// Optional per-app claim (guide §8.5). identity-service mints it on every
	// access/refresh token; empty for legacy tokens issued before the claim existed.
	tokenAppID, _ := claims["app_id"].(string)

	return &TokenClaims{
		UserID:    sub,
		Issuer:    iss,
		AppID:     tokenAppID,
		ExpiresAt: expAt,
	}, nil
}

// parseKeycloakJWT extracts and validates a Keycloak RS256 access token from the
// Authorization header value. Returns nil claims (no error) if the header is empty
// (anonymous request). All validation failures return an error — the caller fails
// closed with 401.
//
// Guarantees:
//   - RS256 only (jwt.WithValidMethods) — an HS256 token can never pass here, and a
//     Keycloak-issued token can never pass the legacy HS256 path (alg-confusion guard
//     in both directions; dispatch is by app_id, validation by algorithm).
//   - `iss` must equal expectedIssuer byte-for-byte.
//   - signature key selected by `kid` via the JWKS cache (rotation-aware).
//   - exp/nbf/iat validated with `leeway` clock skew.
//   - `app_id` claim REQUIRED (the hardcoded per-client mapper always sets it);
//     the caller's replay check (token.app_id == host app_id) runs unchanged.
//   - X-User-Id source: claims[userIDClaim] (default "luid" = legacy_user_id
//     mapper, so migrated users keep their numeric id) falling back to `sub`.
//   - roles: client roles of the authorized party (resource_access[azp].roles)
//     plus realm roles (realm_access.roles); IsAdmin ⇔ intersection with adminRoles.
func parseKeycloakJWT(authHeader string, keys rsaKeyProvider, expectedIssuer, userIDClaim string, leeway time.Duration, adminRoles []string) (*TokenClaims, error) {
	if authHeader == "" {
		return nil, nil
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == authHeader {
		return nil, fmt.Errorf("malformed authorization header")
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token missing kid header")
		}
		return keys.keyForKid(kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithLeeway(leeway))

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
	if iss != expectedIssuer {
		return nil, fmt.Errorf("issuer mismatch: got %q, want %q", iss, expectedIssuer)
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		return nil, fmt.Errorf("token missing subject")
	}

	// Fail closed on a missing app_id: every app client carries the hardcoded-claim
	// mapper, so a Keycloak token without it was not minted by one of our clients.
	tokenAppID, _ := claims["app_id"].(string)
	if tokenAppID == "" {
		return nil, fmt.Errorf("token missing app_id claim")
	}

	userID := sub
	if userIDClaim != "" {
		if v, ok := claims[userIDClaim].(string); ok && v != "" {
			userID = v
		}
	}
	// Every platform backend parses X-User-Id as a positive int64. Migrated
	// fileconvert users carry that id in the claim; greenfield Keycloak users
	// (scantinel) only have UUIDs, so derive a stable positive int64 from `sub`.
	userID = numericUserID(userID, sub)

	expAt := time.Time{}
	if exp, _ := claims.GetExpirationTime(); exp != nil {
		expAt = exp.Time
	}

	roles := keycloakRoles(claims)
	isAdmin := false
	for _, r := range roles {
		for _, a := range adminRoles {
			if r == a {
				isAdmin = true
			}
		}
	}

	return &TokenClaims{
		UserID:    userID,
		Issuer:    iss,
		AppID:     tokenAppID,
		ExpiresAt: expAt,
		Keycloak:  true,
		IsAdmin:   isAdmin,
		Roles:     roles,
		Subject:   sub,
	}, nil
}

// keycloakRoles collects the app-scoped client roles of the authorized party
// (resource_access[azp].roles) and the realm roles (realm_access.roles), deduped,
// client roles first.
func keycloakRoles(claims jwt.MapClaims) []string {
	roles := []string{}
	seen := map[string]bool{}
	appendRoles := func(v interface{}) {
		arr, ok := v.([]interface{})
		if !ok {
			return
		}
		for _, item := range arr {
			if s, ok := item.(string); ok && s != "" && !seen[s] {
				seen[s] = true
				roles = append(roles, s)
			}
		}
	}

	if azp, _ := claims["azp"].(string); azp != "" {
		if ra, ok := claims["resource_access"].(map[string]interface{}); ok {
			if client, ok := ra[azp].(map[string]interface{}); ok {
				appendRoles(client["roles"])
			}
		}
	}
	if realm, ok := claims["realm_access"].(map[string]interface{}); ok {
		appendRoles(realm["roles"])
	}
	return roles
}

// numericUserID returns the value stamped into X-User-Id for a Keycloak
// principal. Backends (identity-service ids everywhere) require a positive
// int64, so a claim that already is one (the luid of a migrated fileconvert
// user) is used verbatim; anything else — the realm's `luid` mapper emits the
// Keycloak UUID for greenfield users — is replaced by deriveUserID(sub).
func numericUserID(claimValue, sub string) string {
	if isPositiveInt(claimValue) {
		return claimValue
	}
	return strconv.FormatUint(deriveUserID(sub), 10)
}

// isPositiveInt reports whether s is a base-10 integer in [1, MaxInt64].
func isPositiveInt(s string) bool {
	if s == "" || len(s) > 19 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return err == nil && v > 0
}

// deriveUserID maps a Keycloak subject (UUID string) to a stable positive
// int64: FNV-1a 64 of the UTF-8 bytes, top bit cleared, 0 mapped to 1.
// Implemented inline (no hash/fnv import) so it runs unchanged under Yaegi.
//
// CONTRACT: scantinel-website performs the identical derivation when it calls
// its services in-cluster with a self-stamped X-User-Id
// (services/scantinel-website/src/lib/user-id.ts). Change both or neither;
// the shared test vector is "00000000-0000-0000-0000-000000000000" →
// 8950988243607919089.
func deriveUserID(sub string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(sub); i++ {
		h ^= uint64(sub[i])
		h *= prime64
	}
	h &= 0x7fffffffffffffff
	if h == 0 {
		h = 1
	}
	return h
}

// tokenAlg returns the unverified `alg` of a bearer token's JOSE header ("" when
// unparseable). Used ONLY to pick a validator on acceptLegacy realms; each
// validator still pins its own algorithm, so a lying header just fails there.
func tokenAlg(authHeader string) string {
	tok := strings.TrimPrefix(authHeader, "Bearer ")
	i := strings.IndexByte(tok, '.')
	if i <= 0 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok[:i])
	if err != nil {
		return ""
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Alg
}
