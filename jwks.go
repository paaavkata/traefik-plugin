package traefik_gateway_plugin

// JWKS (RFC 7517) client for the Keycloak RS256 path. Hand-rolled on purpose:
// this plugin is Yaegi-interpreted inside Traefik, so third-party JOSE libraries
// (lestrrat-go/jwx, go-jose, keyfunc, …) are a compatibility risk. Everything here
// sticks to stdlib packages known to be in Yaegi's symbol table and already proven
// in this plugin or its vendored deps: net/http, encoding/json, encoding/base64,
// math/big, crypto/rsa (the latter already interpreted today via the vendored
// golang-jwt/jwt/v5 package). Deliberately avoids crypto/x509 (no x5c parsing —
// Keycloak always publishes n/e).
//
// Semantics:
//   - keys cached by `kid`; the cache is replaced only on a fully successful
//     fetch+parse ("last-good": a Keycloak outage never invalidates the keys
//     already cached, so existing sessions keep validating).
//   - unknown `kid` triggers an on-demand re-fetch (key rotation pickup) guarded
//     by a cooldown so attacker-supplied kids cannot flood Keycloak.
//   - a background loop re-fetches periodically so rotation is usually picked up
//     before the first token signed by the new key arrives.
//   - the configured URL may be either the JWKS endpoint itself or an OIDC
//     discovery document; in the latter case jwks_uri is followed.

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// rsaKeyProvider abstracts JWKS key lookup for parseKeycloakJWT (and tests).
type rsaKeyProvider interface {
	keyForKid(kid string) (*rsa.PublicKey, error)
}

// jwksDocument is the union of a JWKS response and an OIDC discovery document.
type jwksDocument struct {
	Keys    []jwksKeyJSON `json:"keys"`
	JWKSURI string        `json:"jwks_uri"`
}

type jwksKeyJSON struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

const maxJWKSBody = 1 << 20 // 1 MiB — a realm JWKS is a few KB; cap defensively.

// JWKSCache caches RSA public keys by kid for one JWKS URL.
type JWKSCache struct {
	url             string
	client          *http.Client
	log             *pluginLogger
	refetchCooldown time.Duration

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey // last-good set; replaced only on successful refresh
	lastAttempt time.Time                 // last fetch attempt (success or failure) — cooldown anchor

	stopCh chan struct{}
}

func newJWKSCache(url string, httpTimeout, refetchCooldown time.Duration, log *pluginLogger) *JWKSCache {
	return &JWKSCache{
		url:             url,
		client:          &http.Client{Timeout: httpTimeout},
		log:             log,
		refetchCooldown: refetchCooldown,
		keys:            make(map[string]*rsa.PublicKey),
		stopCh:          make(chan struct{}),
	}
}

// sharedJWKSCaches: one running cache per JWKS URL for the Traefik process
// lifetime — same rationale as sharedCaches in snapshot.go (Traefik rebuilds
// middleware instances per router and per config reload).
var (
	sharedJWKSCachesMu sync.Mutex
	sharedJWKSCaches   = make(map[string]*JWKSCache)
)

// getSharedJWKSCache returns the process-wide JWKSCache for url, creating and
// starting it (initial warm fetch + background refresh loop) on first use.
func getSharedJWKSCache(url string, httpTimeout, refreshInterval, refetchCooldown time.Duration, log *pluginLogger) *JWKSCache {
	sharedJWKSCachesMu.Lock()
	defer sharedJWKSCachesMu.Unlock()

	if jc, ok := sharedJWKSCaches[url]; ok {
		return jc
	}

	jc := newJWKSCache(url, httpTimeout, refetchCooldown, log)
	// Best-effort warm fetch; failure is not fatal (Keycloak may come up after
	// Traefik). Requests fail closed until keys are available.
	if err := jc.refresh(); err != nil {
		log.warnf("jwks initial fetch failed url=%s error=%v (will retry)", url, err)
	}
	go jc.loop(refreshInterval)
	sharedJWKSCaches[url] = jc
	return jc
}

func (jc *JWKSCache) loop(interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-jc.stopCh:
			return
		case <-ticker.C:
			if err := jc.refresh(); err != nil {
				jc.log.warnf("jwks background refresh failed url=%s error=%v (serving last-good keys)", jc.url, err)
			}
		}
	}
}

func (jc *JWKSCache) stop() { close(jc.stopCh) }

// keyForKid returns the cached RSA public key for kid. On a cache miss it
// re-fetches the JWKS once (rotation pickup), rate-limited by refetchCooldown.
// Unknown kid after refetch ⇒ error (caller fails closed with 401).
func (jc *JWKSCache) keyForKid(kid string) (*rsa.PublicKey, error) {
	jc.mu.RLock()
	key := jc.keys[kid]
	last := jc.lastAttempt
	jc.mu.RUnlock()
	if key != nil {
		return key, nil
	}

	if time.Since(last) >= jc.refetchCooldown {
		if err := jc.refresh(); err != nil {
			jc.log.warnf("jwks on-demand refresh failed url=%s kid=%s error=%v", jc.url, kid, err)
		}
		jc.mu.RLock()
		key = jc.keys[kid]
		jc.mu.RUnlock()
		if key != nil {
			jc.log.infof("jwks key rotation picked up kid=%s url=%s", kid, jc.url)
			return key, nil
		}
	}

	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

// refresh fetches and parses the JWKS, swapping in the new key set only on full
// success. Any failure leaves the previous (last-good) keys serving.
func (jc *JWKSCache) refresh() error {
	jc.mu.Lock()
	jc.lastAttempt = time.Now()
	jc.mu.Unlock()

	doc, err := jc.fetchDocument(jc.url)
	if err != nil {
		return err
	}
	// OIDC discovery document: follow jwks_uri.
	if len(doc.Keys) == 0 && doc.JWKSURI != "" {
		doc, err = jc.fetchDocument(doc.JWKSURI)
		if err != nil {
			return fmt.Errorf("jwks_uri fetch: %w", err)
		}
	}

	parsed := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" || k.Kty != "RSA" {
			continue
		}
		// Keycloak publishes an RSA-OAEP encryption key alongside the signing key;
		// only signature keys are usable here.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue
		}
		pub, err := parseRSAJWK(k)
		if err != nil {
			jc.log.warnf("jwks skipping unparseable key kid=%s error=%v", k.Kid, err)
			continue
		}
		parsed[k.Kid] = pub
	}
	if len(parsed) == 0 {
		return fmt.Errorf("JWKS at %s contained no usable RS256 signing keys", jc.url)
	}

	jc.mu.Lock()
	jc.keys = parsed
	jc.mu.Unlock()
	jc.log.debugf("jwks refreshed url=%s keys=%d", jc.url, len(parsed))
	return nil
}

func (jc *JWKSCache) fetchDocument(url string) (*jwksDocument, error) {
	resp, err := jc.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBody))
	if err != nil {
		return nil, fmt.Errorf("jwks read %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch %s: status %d: %s", url, resp.StatusCode, truncateForLog(string(body), 256))
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jwks parse %s: %w", url, err)
	}
	return &doc, nil
}

// parseRSAJWK builds an *rsa.PublicKey from base64url-encoded n/e (RFC 7518 §6.3).
func parseRSAJWK(k jwksKeyJSON) (*rsa.PublicKey, error) {
	if k.N == "" || k.E == "" {
		return nil, fmt.Errorf("missing n/e")
	}
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("bad modulus: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("bad exponent: %w", err)
	}
	if len(eb) == 0 || len(eb) > 4 {
		return nil, fmt.Errorf("exponent out of range (%d bytes)", len(eb))
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e < 3 || e%2 == 0 {
		return nil, fmt.Errorf("invalid public exponent %d", e)
	}
	n := new(big.Int).SetBytes(nb)
	if n.Sign() <= 0 || n.BitLen() < 1024 {
		return nil, fmt.Errorf("modulus too small (%d bits)", n.BitLen())
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
