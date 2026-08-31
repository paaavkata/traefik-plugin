package traefik_gateway_plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// apiKeyPrefix is the mandatory token prefix. A credential (X-Api-Key value or the
// bearer value) beginning with this takes the API-key path instead of JWT parsing.
const apiKeyPrefix = "fc_"

// API-key verification cache TTLs (contract §4).
const (
	apiKeyCachePositiveTTL = 60 * time.Second
	apiKeyCacheNegativeTTL = 10 * time.Second
)

// apiKeyDenyMarker is the cache value stored for a denied key (negative cache),
// distinguishing a cached deny from a cached positive verify JSON.
const apiKeyDenyMarker = "__deny__"

// parsedAPIKey is the decomposed fc_<env>_<uid>_<secret> credential.
type parsedAPIKey struct {
	env    string
	uid    string
	secret string
}

// secretSHA256B64 returns the std-base64 encoding of SHA-256(secret) — the exact
// form used both as the verify request's secret_sha256 field and as the Redis cache
// key suffix (contract §3/§4).
func (k parsedAPIKey) secretSHA256B64() string {
	sum := sha256.Sum256([]byte(k.secret))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// cacheKey is the Redis cache key: apikey:<uid>:<base64(hash)>.
func (k parsedAPIKey) cacheKey() string {
	return "apikey:" + k.uid + ":" + k.secretSHA256B64()
}

// parseAPIKey decomposes fc_<env>_<uid>_<secret>. Only the fixed 4-part structure is
// validated here (non-empty env/uid/secret); cryptographic validity is decided by
// identity-service. Malformed input → error (the caller returns 401).
func parseAPIKey(token string) (parsedAPIKey, error) {
	if !strings.HasPrefix(token, apiKeyPrefix) {
		return parsedAPIKey{}, fmt.Errorf("not an api key")
	}
	// fc_<env>_<uid>_<secret> — exactly 4 underscore-delimited parts. The secret is
	// base64url (no '_'), the uid is [a-z0-9], and env has no '_', so SplitN(4) yields
	// the secret intact as the final field.
	parts := strings.SplitN(token, "_", 4)
	if len(parts) != 4 {
		return parsedAPIKey{}, fmt.Errorf("malformed api key: wrong segment count")
	}
	env, uid, secret := parts[1], parts[2], parts[3]
	if env == "" || uid == "" || secret == "" {
		return parsedAPIKey{}, fmt.Errorf("malformed api key: empty segment")
	}
	return parsedAPIKey{env: env, uid: uid, secret: secret}, nil
}

// extractAPIKeyCredential returns the raw credential string if the request carries an
// API key (X-Api-Key header, or an Authorization: Bearer value starting with fc_).
// X-Api-Key takes precedence. Returns ("", false) when no fc_ credential is present —
// the caller then stays on the untouched JWT path.
func extractAPIKeyCredential(req *http.Request, jwtHeaderKey string) (string, bool) {
	if v := strings.TrimSpace(req.Header.Get("X-Api-Key")); strings.HasPrefix(v, apiKeyPrefix) {
		return v, true
	}
	authHeader := req.Header.Get(jwtHeaderKey)
	if bearer := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")); bearer != authHeader {
		if strings.HasPrefix(bearer, apiKeyPrefix) {
			return bearer, true
		}
	}
	return "", false
}

// apiKeyVerifyResult is the identity-service verify response (contract §3), also the
// JSON cached on a positive result.
type apiKeyVerifyResult struct {
	UserID         string   `json:"user_id"`
	OrganizationID *int     `json:"organization_id"`
	AppID          string   `json:"app_id"`
	Plan           string   `json:"plan"`
	Scopes         []string `json:"scopes"`
}

// APIKeyVerifier verifies API keys against identity-service with a Redis-backed
// positive/negative cache. It fails closed for key traffic when identity is
// unreachable (the caller maps that to 503).
type APIKeyVerifier struct {
	verifyURL string
	client    *http.Client
	cache     *respRedis // may be nil (no Redis) — then every request hits identity
	prefix    string     // Redis key namespace prefix (shares the rate-limit prefix)
	log       *pluginLogger
}

func newAPIKeyVerifier(verifyURL string, timeout time.Duration, cache *respRedis, prefix string, log *pluginLogger) *APIKeyVerifier {
	return &APIKeyVerifier{
		verifyURL: verifyURL,
		// Hard-cap the verify call at ≤2s regardless of the shared HTTP timeout
		// (contract §4). identity unreachable within this budget → fail closed.
		client: &http.Client{Timeout: apiKeyVerifyTimeout(timeout)},
		cache:  cache,
		prefix: prefix,
		log:    log,
	}
}

// apiKeyVerifyTimeout clamps the verify timeout to the contract's ≤2s ceiling.
func apiKeyVerifyTimeout(configured time.Duration) time.Duration {
	const max = 2 * time.Second
	if configured <= 0 || configured > max {
		return max
	}
	return configured
}

// apiKeyOutcome is the resolved verification decision.
type apiKeyOutcome int

const (
	apiKeyValid       apiKeyOutcome = iota // key is valid; result populated
	apiKeyDenied                           // key is invalid/revoked/expired (401)
	apiKeyUnavailable                      // identity unreachable → fail closed (503)
)

// Verify resolves an API key: cache first, then identity-service on miss. The result
// is cached (positive 60s, negative 10s). Never caches the raw secret — only the hash
// (in the key) and the verify JSON / deny marker (in the value).
func (v *APIKeyVerifier) Verify(ctx context.Context, key parsedAPIKey) (*apiKeyVerifyResult, apiKeyOutcome) {
	redisKey := v.prefix + key.cacheKey()

	// 1. Cache lookup.
	if v.cache != nil {
		if raw, ok, err := v.cache.get(ctx, redisKey); err != nil {
			v.log.warnf("api-key cache read failed uid=%s error=%v", key.uid, err)
		} else if ok {
			if raw == apiKeyDenyMarker {
				v.log.debugf("api-key cache hit (deny) uid=%s", key.uid)
				return nil, apiKeyDenied
			}
			var res apiKeyVerifyResult
			if err := json.Unmarshal([]byte(raw), &res); err == nil {
				v.log.debugf("api-key cache hit (valid) uid=%s", key.uid)
				return &res, apiKeyValid
			}
			v.log.warnf("api-key cache hit but unparseable uid=%s (re-verifying)", key.uid)
		}
	}

	// 2. Miss → verify against identity-service.
	res, outcome := v.callIdentity(ctx, key)

	// 3. Cache the decision (never on unavailable — that must stay fail-open-to-retry).
	if v.cache != nil {
		switch outcome {
		case apiKeyValid:
			if payload, err := json.Marshal(res); err == nil {
				if err := v.cache.setEX(ctx, redisKey, string(payload), int(apiKeyCachePositiveTTL.Seconds())); err != nil {
					v.log.warnf("api-key cache write (valid) failed uid=%s error=%v", key.uid, err)
				}
			}
		case apiKeyDenied:
			if err := v.cache.setEX(ctx, redisKey, apiKeyDenyMarker, int(apiKeyCacheNegativeTTL.Seconds())); err != nil {
				v.log.warnf("api-key cache write (deny) failed uid=%s error=%v", key.uid, err)
			}
		}
	}
	return res, outcome
}

// callIdentity POSTs {key_uid, secret_sha256} to the internal verify endpoint.
// 200 → valid; 401 → denied; any transport error / other status → unavailable
// (fail closed for key traffic only).
func (v *APIKeyVerifier) callIdentity(ctx context.Context, key parsedAPIKey) (*apiKeyVerifyResult, apiKeyOutcome) {
	reqBody, err := json.Marshal(map[string]string{
		"key_uid":       key.uid,
		"secret_sha256": key.secretSHA256B64(),
	})
	if err != nil {
		v.log.errorf("api-key verify marshal failed uid=%s error=%v", key.uid, err)
		return nil, apiKeyUnavailable
	}

	start := time.Now()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, bytes.NewReader(reqBody))
	if err != nil {
		v.log.errorf("api-key verify build request failed uid=%s error=%v", key.uid, err)
		return nil, apiKeyUnavailable
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(httpReq)
	if err != nil {
		v.log.warnf("api-key verify request failed (fail-closed) uid=%s duration=%s error=%v", key.uid, since(start), err)
		return nil, apiKeyUnavailable
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	dur := since(start)
	if err != nil {
		v.log.warnf("api-key verify read body failed (fail-closed) uid=%s duration=%s error=%v", key.uid, dur, err)
		return nil, apiKeyUnavailable
	}
	v.log.debugf("api-key verify response uid=%s status=%d duration=%s", key.uid, resp.StatusCode, dur)

	switch resp.StatusCode {
	case http.StatusOK:
		var res apiKeyVerifyResult
		if err := json.Unmarshal(body, &res); err != nil {
			v.log.warnf("api-key verify json error uid=%s err=%v body=%s", key.uid, err, truncateForLog(string(body), 512))
			return nil, apiKeyUnavailable
		}
		return &res, apiKeyValid
	case http.StatusUnauthorized:
		return nil, apiKeyDenied
	default:
		v.log.warnf("api-key verify non-OK status uid=%s status=%d (fail-closed)", key.uid, resp.StatusCode)
		return nil, apiKeyUnavailable
	}
}
