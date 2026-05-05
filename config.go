package traefik_gateway_plugin

import "time"

// Config holds the plugin configuration set via Traefik static/dynamic config.
type Config struct {
	// JWT
	JWTSecret    string `json:"jwtSecret" yaml:"jwtSecret"`
	JWTIssuer    string `json:"jwtIssuer" yaml:"jwtIssuer"`
	JWTHeaderKey string `json:"jwtHeaderKey" yaml:"jwtHeaderKey"`

	// Session ID header for anonymous rate-limiting
	SessionIDHeader string `json:"sessionIdHeader" yaml:"sessionIdHeader"`

	// Redis
	RedisURL      string `json:"redisUrl" yaml:"redisUrl"`
	RedisPassword string `json:"redisPassword" yaml:"redisPassword"`
	RedisDB       int    `json:"redisDb" yaml:"redisDb"`
	RedisPrefix   string `json:"redisPrefix" yaml:"redisPrefix"`

	// Service-service (registry snapshot)
	ServiceServiceURL           string `json:"serviceServiceUrl" yaml:"serviceServiceUrl"`
	SnapshotRefreshInterval     string `json:"snapshotRefreshInterval" yaml:"snapshotRefreshInterval"`
	SnapshotVersionPollInterval string `json:"snapshotVersionPollInterval" yaml:"snapshotVersionPollInterval"`

	// Identity-service
	IdentityServiceURL string `json:"identityServiceUrl" yaml:"identityServiceUrl"`

	// Usage-service
	UsageServiceURL string `json:"usageServiceUrl" yaml:"usageServiceUrl"`

	// Default rate limit for anonymous/unregistered users (when no plan match)
	DefaultRateLimitRequests        int    `json:"defaultRateLimitRequests" yaml:"defaultRateLimitRequests"`
	DefaultRateLimitDurationSeconds int    `json:"defaultRateLimitDurationSeconds" yaml:"defaultRateLimitDurationSeconds"`
	DefaultPlanName                 string `json:"defaultPlanName" yaml:"defaultPlanName"`

	// Access level names
	AdminAccessLevel string `json:"adminAccessLevel" yaml:"adminAccessLevel"`
	FreeAccessLevel  string `json:"freeAccessLevel" yaml:"freeAccessLevel"`

	// Headers forwarded downstream
	UserIDHeader   string `json:"userIdHeader" yaml:"userIdHeader"`
	UserPlanHeader string `json:"userPlanHeader" yaml:"userPlanHeader"`
	IsAdminHeader  string `json:"isAdminHeader" yaml:"isAdminHeader"`

	// Timeout for upstream service calls
	HTTPTimeout string `json:"httpTimeout" yaml:"httpTimeout"`

	// Log verbosity: error, warn, info, debug, or none/off/silent.
	LogLevel string `json:"logLevel" yaml:"logLevel"`

	// Whether to skip rate limiting entirely (for debugging)
	DisableRateLimit bool `json:"disableRateLimit" yaml:"disableRateLimit"`

	// Whether to skip JWT validation (for debugging/local)
	DisableAuth bool `json:"disableAuth" yaml:"disableAuth"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		JWTIssuer:                       "file-convert.online",
		JWTHeaderKey:                    "Authorization",
		SessionIDHeader:                 "X-Session-Id",
		RedisURL:                        "redis://127.0.0.1:6379/0",
		RedisPrefix:                     "gw:rl:",
		ServiceServiceURL:               "http://service-service:8080",
		SnapshotRefreshInterval:         "30s",
		SnapshotVersionPollInterval:     "5s",
		IdentityServiceURL:              "http://identity-service:8080",
		UsageServiceURL:                 "http://usage-service:8080",
		DefaultRateLimitRequests:        30,
		DefaultRateLimitDurationSeconds: 60,
		DefaultPlanName:                 "free",
		AdminAccessLevel:                "admin",
		FreeAccessLevel:                 "free",
		UserIDHeader:                    "X-User-Id",
		UserPlanHeader:                  "X-User-Plan",
		IsAdminHeader:                   "X-Is-Admin",
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
