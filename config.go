package traefik_gateway_plugin

import "time"

// Config holds the plugin configuration set via Traefik static/dynamic config.
type Config struct {
	// JWTHeaderKey is the header carrying the bearer token (default Authorization).
	JWTHeaderKey string `json:"jwtHeaderKey" yaml:"jwtHeaderKey"`

	// --- Keycloak (RS256 + JWKS) ----------------------------------------------
	// Bearer tokens are validated ONLY against the realm bound to the resolved
	// app (KeycloakApps + scalar realm, or KeycloakRealms) or the OperatorRealm.
	// An app with no realm rejects every bearer token (401); the HS256
	// shared-secret path (jwtSecret/jwtIssuer, identity-service tokens) was
	// removed in 2026-10 — those YAML keys are now ignored.

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

	// KeycloakRealms binds individual app_ids to their OWN realm (issuer + JWKS),
	// for apps that do not share the scalar keycloakIssuer/keycloakJwksUrl realm
	// (e.g. fileconvert next to scantinel). An app listed here is a Keycloak app
	// even when absent from KeycloakApps; an entry overrides the scalar realm for
	// its app. Unknown to plugin builds older than this field (ignored there), so
	// adding an entry is inert until the image carrying it is deployed.
	KeycloakRealms []KeycloakRealm `json:"keycloakRealms" yaml:"keycloakRealms"`

	// OperatorRealm is the realm of the platform operators (the console's
	// `infra` realm). Its tokens are accepted on EVERY application (next to the
	// application's own realm); what they may do there is decided by policy.
	// AppID is ignored. Empty issuer/jwksUrl = no operator realm.
	OperatorRealm KeycloakRealm `json:"operatorRealm" yaml:"operatorRealm"`

	// AuthorizationMode selects the authorization engine:
	//   "legacy" — (DEFAULT) today's path: keycloakAdminRoles from token roles,
	//              host-pinned app, token.app_id must equal the host app. The
	//              policy outcome is still computed and logged as `shadow=`.
	//   "policy" — gateway-iam-policies: principal roles → snapshot bindings →
	//              policy statements; requested application via X-App-Id;
	//              X-Is-Admin derived from a "*" grant; GET /api/_iam/me.
	AuthorizationMode string `json:"authorizationMode" yaml:"authorizationMode"`

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

	// UserUIDHeader carries the Keycloak `sub` (UUID) of the caller. Stamped ONLY
	// on the Keycloak path; stripped from every inbound request. Default "X-User-Uid".
	UserUIDHeader string `json:"userUidHeader" yaml:"userUidHeader"`

	// UserEmailHeader, when set (e.g. "X-User-Email"), is stripped from every
	// inbound request and re-stamped ONLY on the Keycloak path from a verified
	// token (`email` with `email_verified: true`). Empty (default) = inert, the
	// header is left untouched, so enabling it is a per-env Middleware change.
	UserEmailHeader string `json:"userEmailHeader" yaml:"userEmailHeader"`

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

// KeycloakRealm is one app_id -> realm binding (see Config.KeycloakRealms).
type KeycloakRealm struct {
	AppID   string `json:"appId" yaml:"appId"`
	Issuer  string `json:"issuer" yaml:"issuer"`   // exact expected `iss`
	JWKSURL string `json:"jwksUrl" yaml:"jwksUrl"` // JWKS or OIDC discovery URL
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		JWTHeaderKey:                    "Authorization",
		KeycloakUserIDClaim:             "luid",
		AuthorizationMode:               "legacy",
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
		UserUIDHeader:                   "X-User-Uid",
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
