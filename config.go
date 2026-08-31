package traefik_gateway_plugin

import "time"

// Config holds the plugin configuration set via Traefik static/dynamic config.
type Config struct {
	// JWT (legacy HS256 shared-secret path — identity-service tokens). This remains
	// the validator for every app NOT listed in KeycloakApps.
	JWTSecret    string `json:"jwtSecret" yaml:"jwtSecret"`
	JWTIssuer    string `json:"jwtIssuer" yaml:"jwtIssuer"`
	JWTHeaderKey string `json:"jwtHeaderKey" yaml:"jwtHeaderKey"`

	// --- Keycloak / dual-issuer (RS256 + JWKS) ---------------------------------
	// Apps listed in KeycloakApps authenticate against Keycloak; all other apps keep
	// the HS256 path above unchanged. Leaving KeycloakApps empty disables the
	// Keycloak path entirely (behaviour identical to before this feature existed).

	// KeycloakApps is the list of app_ids (as resolved from the request host via the
	// application registry) whose bearer tokens are validated on the Keycloak
	// RS256/JWKS path, e.g. ["scantinel"].
	KeycloakApps []string `json:"keycloakApps" yaml:"keycloakApps"`

	// KeycloakJWKSURL is the JWKS endpoint of the realm, e.g. (in-cluster)
	//   http://keycloak-service.keycloak.svc:8080/realms/platform/protocol/openid-connect/certs
	// An OIDC discovery URL (…/.well-known/openid-configuration) is also accepted;
	// the plugin follows its jwks_uri. Required when KeycloakApps is non-empty.
	KeycloakJWKSURL string `json:"keycloakJwksUrl" yaml:"keycloakJwksUrl"`

	// KeycloakIssuer is the expected `iss` claim, byte-for-byte, i.e. the realm's
	// PUBLIC frontend URL: https://<auth-host>/realms/platform. Required when
	// KeycloakApps is non-empty. Tokens with any other issuer are rejected (401).
	KeycloakIssuer string `json:"keycloakIssuer" yaml:"keycloakIssuer"`

	// KeycloakUserIDClaim is the claim stamped into X-User-Id when present on the
	// token, falling back to `sub`. Default "luid" — the legacy_user_id protocol
	// mapper — so migrated users keep their numeric platform user id.
	KeycloakUserIDClaim string `json:"keycloakUserIdClaim" yaml:"keycloakUserIdClaim"`

	// KeycloakAdminRoles: a token whose Keycloak roles (client roles of the azp
	// client, plus realm roles) intersect this list is stamped X-Is-Admin: true.
	KeycloakAdminRoles []string `json:"keycloakAdminRoles" yaml:"keycloakAdminRoles"`

	// KeycloakClockSkewSeconds is the leeway applied to exp/nbf/iat validation on
	// the Keycloak path (gateway and Keycloak clocks may drift). Default 30.
	KeycloakClockSkewSeconds int `json:"keycloakClockSkewSeconds" yaml:"keycloakClockSkewSeconds"`

	// JWKSRefreshInterval is the background JWKS re-fetch period (key rotation
	// pickup without traffic). Default "10m".
	JWKSRefreshInterval string `json:"jwksRefreshInterval" yaml:"jwksRefreshInterval"`

	// JWKSRefetchCooldown rate-limits on-demand re-fetches triggered by tokens with
	// an unknown `kid`, so attacker-minted kids cannot flood Keycloak. Default "30s".
	JWKSRefetchCooldown string `json:"jwksRefetchCooldown" yaml:"jwksRefetchCooldown"`

	// Session ID header for anonymous rate-limiting
	SessionIDHeader string `json:"sessionIdHeader" yaml:"sessionIdHeader"`

	// Device ID header for reset-resistant anonymous rate-limiting (FingerprintJS visitorId).
	DeviceIDHeader string `json:"deviceIdHeader" yaml:"deviceIdHeader"`

	// Redis
	RedisURL      string `json:"redisUrl" yaml:"redisUrl"`
	RedisPassword string `json:"redisPassword" yaml:"redisPassword"`
	RedisDB       int    `json:"redisDb" yaml:"redisDb"`
	RedisPrefix   string `json:"redisPrefix" yaml:"redisPrefix"`

	// Service-service (registry snapshot)
	ServiceServiceURL           string `json:"serviceServiceUrl" yaml:"serviceServiceUrl"`
	SnapshotRefreshInterval     string `json:"snapshotRefreshInterval" yaml:"snapshotRefreshInterval"`
	SnapshotVersionPollInterval string `json:"snapshotVersionPollInterval" yaml:"snapshotVersionPollInterval"`

	// Application-service (host→app_id registry snapshot)
	ApplicationServiceURL          string `json:"applicationServiceUrl" yaml:"applicationServiceUrl"`
	AppSnapshotRefreshInterval     string `json:"appSnapshotRefreshInterval" yaml:"appSnapshotRefreshInterval"`
	AppSnapshotVersionPollInterval string `json:"appSnapshotVersionPollInterval" yaml:"appSnapshotVersionPollInterval"`

	// AppIDHeader is the trusted, gateway-stamped header carrying the resolved app_id.
	// Canonical spelling is "X-App-Id" (guide §10). Any inbound client copy is stripped.
	AppIDHeader string `json:"appIdHeader" yaml:"appIdHeader"`

	// AppResolutionMode controls host→app_id resolution behaviour. There are NO
	// endpoints allowed without a resolved app_id, so "enforce" is the default/prod
	// path. Modes:
	//   "enforce"    — (DEFAULT) unknown/inactive host ⇒ 403, cold registry ⇒ 503.
	//                  A request with no resolvable app_id never reaches endpoint
	//                  matching or the backend.
	//   "permissive" — unknown host ⇒ pass through without app_id. LOCAL/DEBUG ONLY;
	//                  do not use in production (it lets requests through with no app_id).
	//   "disabled"   — skip host resolution entirely. LOCAL single-app dev only; the
	//                  app_id requirement is skipped and no X-App-Id is stamped.
	AppResolutionMode string `json:"appResolutionMode" yaml:"appResolutionMode"`

	// TrustForwardedHost selects the host source for app resolution. When true, the
	// X-Forwarded-Host header is used (when present); otherwise req.Host. Default false.
	// The prod path is CloudFlare→nginx→Traefik and it is not yet confirmed whether the
	// original Host survives, so this is a flag defaulting to the safe req.Host.
	TrustForwardedHost bool `json:"trustForwardedHost" yaml:"trustForwardedHost"`

	// Identity-service
	IdentityServiceURL string `json:"identityServiceUrl" yaml:"identityServiceUrl"`

	// IdentityVerifyURL is the in-cluster endpoint the gateway POSTs API-key
	// verification requests to (contract §4). It is NOT registered in the service
	// registry (internal service-to-service call), so it carries the full path.
	// Default: identity-service's /internal/v1/api-keys/verify. Same in-cluster URL
	// convention as IdentityServiceURL.
	IdentityVerifyURL string `json:"identityVerifyUrl" yaml:"identityVerifyUrl"`

	// ApiKeyUidHeader is the trusted, gateway-stamped header carrying the resolved
	// API key uid on the API-key auth path. Canonical spelling "X-Api-Key-Uid". Any
	// inbound client copy is stripped unconditionally (mirrors AppIDHeader).
	ApiKeyUidHeader string `json:"apiKeyUidHeader" yaml:"apiKeyUidHeader"`

	// Usage-service
	UsageServiceURL string `json:"usageServiceUrl" yaml:"usageServiceUrl"`

	// Default rate limit for anonymous/unregistered users (when no plan match)
	DefaultRateLimitRequests        int    `json:"defaultRateLimitRequests" yaml:"defaultRateLimitRequests"`
	DefaultRateLimitDurationSeconds int    `json:"defaultRateLimitDurationSeconds" yaml:"defaultRateLimitDurationSeconds"`
	DefaultPlanName                 string `json:"defaultPlanName" yaml:"defaultPlanName"`

	// Access level names
	AdminAccessLevel string `json:"adminAccessLevel" yaml:"adminAccessLevel"`
	FreeAccessLevel  string `json:"freeAccessLevel" yaml:"freeAccessLevel"`

	// AdminPermission is the RBAC v2 permission tag implied by the admin access
	// level; endpoints may also carry an explicit required_permission in the
	// snapshot (PERMISSIONS_STRATEGY.md).
	AdminPermission string `json:"adminPermission" yaml:"adminPermission"`

	// Headers forwarded downstream
	UserIDHeader    string `json:"userIdHeader" yaml:"userIdHeader"`
	UserPlanHeader  string `json:"userPlanHeader" yaml:"userPlanHeader"`
	IsAdminHeader   string `json:"isAdminHeader" yaml:"isAdminHeader"`
	UserRolesHeader string `json:"userRolesHeader" yaml:"userRolesHeader"`

	// Timeout for upstream service calls
	HTTPTimeout string `json:"httpTimeout" yaml:"httpTimeout"`

	// Log verbosity: error, warn, info, debug, or none/off/silent.
	LogLevel string `json:"logLevel" yaml:"logLevel"`

	// Whether to skip rate limiting entirely (for debugging)
	DisableRateLimit bool `json:"disableRateLimit" yaml:"disableRateLimit"`

	// Whether to skip JWT validation (for debugging/local)
	DisableAuth bool `json:"disableAuth" yaml:"disableAuth"`

	// CORS — leave CORSAllowedOrigins empty to disable CORS handling.
	// Supports exact origins ("https://file-convert.online") and wildcard
	// subdomain patterns ("https://*.file-convert.online").
	CORSAllowedOrigins   []string `json:"corsAllowedOrigins" yaml:"corsAllowedOrigins"`
	CORSAllowedMethods   []string `json:"corsAllowedMethods" yaml:"corsAllowedMethods"`
	CORSAllowedHeaders   []string `json:"corsAllowedHeaders" yaml:"corsAllowedHeaders"`
	CORSAllowCredentials bool     `json:"corsAllowCredentials" yaml:"corsAllowCredentials"`
	CORSMaxAge           int      `json:"corsMaxAge" yaml:"corsMaxAge"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		JWTIssuer:                       "file-convert.online",
		JWTHeaderKey:                    "Authorization",
		KeycloakUserIDClaim:             "luid",
		KeycloakAdminRoles:              []string{"admin", "owner"},
		KeycloakClockSkewSeconds:        30,
		JWKSRefreshInterval:             "10m",
		JWKSRefetchCooldown:             "30s",
		SessionIDHeader:                 "X-Session-Id",
		DeviceIDHeader:                  "X-Device-Id",
		RedisURL:                        "redis://127.0.0.1:6379/0",
		RedisPrefix:                     "gw:rl:",
		ServiceServiceURL:               "http://service-service:8080",
		SnapshotRefreshInterval:         "30s",
		SnapshotVersionPollInterval:     "5s",
		ApplicationServiceURL:           "http://application-service:8080",
		AppSnapshotRefreshInterval:      "30s",
		AppSnapshotVersionPollInterval:  "5s",
		AppIDHeader:                     "X-App-Id",
		AppResolutionMode:               "enforce",
		IdentityServiceURL:              "http://identity-service:8080",
		IdentityVerifyURL:               "http://identity-service:8080/internal/v1/api-keys/verify",
		ApiKeyUidHeader:                 "X-Api-Key-Uid",
		UsageServiceURL:                 "http://usage-service:8080",
		CORSAllowedMethods:              []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		CORSAllowedHeaders:              []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Session-Id", "X-Device-Id", "X-App-Id"},
		CORSAllowCredentials:            true,
		CORSMaxAge:                      3600,
		DefaultRateLimitRequests:        30,
		DefaultRateLimitDurationSeconds: 60,
		DefaultPlanName:                 "free",
		AdminAccessLevel:                "admin",
		FreeAccessLevel:                 "free",
		AdminPermission:                 "platform.admin",
		UserIDHeader:                    "X-User-Id",
		UserPlanHeader:                  "X-User-Plan",
		IsAdminHeader:                   "X-Is-Admin",
		UserRolesHeader:                 "X-User-Roles",
		HTTPTimeout:                     "5s",
		LogLevel:                        "info",
	}
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}
