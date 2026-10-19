package traefik_gateway_plugin

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Policy authorization engine (authorizationMode "policy").
//
// Stages after the shared ServeHTTP prelude (CORS, trust-header strip, host
// resolution, cold-snapshot check):
//
//  1. target application: validated inbound X-App-Id, else the host's app
//  2. endpoint match under the target app
//  3. credential: API key, or bearer token validated by the realm whose `iss`
//     it carries, out of {target app's realm, operator realm}
//  4. principal → bound roles → policy statements (authz.go)
//  5. required permission: no token → 401 no_token; no statement → 403
//  6. trusted headers stamped (X-Is-Admin only for a literal "*" grant)
//  7. owner gate, rate limit (wildcard holders exempt), forward

// iamMePath is served by the gateway itself; the registry rejects any service
// that tries to register a route under /_iam/.
const iamMePath = "/api/_iam/me"

// Denial reason codes (every 401/403 logs exactly one).
const (
	reasonNoToken             = "no_token"
	reasonIssuerRejected      = "issuer_rejected"
	reasonUnknownApp          = "unknown_app"
	reasonNoMatchingStatement = "no_matching_statement"
	reasonOwnerMismatch       = "owner_mismatch"
	reasonEndpointNotExposed  = "endpoint_not_exposed"
)

// deny logs a structured denial and writes the JSON error.
func (p *GatewayPlugin) deny(rw http.ResponseWriter, req *http.Request, status int, code, message, reason, target, userID, perm string) {
	p.log.warnf("denied status=%d reason=%s method=%s path=%s app_id=%s user_id=%s required=%s", status, reason, req.Method, req.URL.Path, target, userID, perm)
	writeJSON(rw, status, map[string]string{"error": code, "message": message})
}

// authenticate validates the bearer credential for a request targeting app.
// Returns (nil, "", nil) for an anonymous request; a reason code with the error.
func (p *GatewayPlugin) authenticate(app, authHeader string) (*TokenClaims, string, error) {
	if authHeader == "" || p.config.DisableAuth {
		return nil, "", nil
	}
	realm := p.keycloakRealmFor(app)
	iss := tokenIssuer(authHeader)
	var chosen *keycloakRealmRuntime
	if realm != nil && realm.issuer == iss {
		chosen = realm
	} else if p.operatorRealm != nil && p.operatorRealm.issuer == iss {
		chosen = p.operatorRealm
	}
	if chosen == nil {
		return nil, reasonIssuerRejected, errIssuerNotAccepted
	}
	claims, err := p.parseKeycloakAuth(chosen, authHeader)
	if err != nil {
		return nil, reasonIssuerRejected, err
	}
	return claims, "", nil
}

type authError string

func (e authError) Error() string { return string(e) }

const (
	errIssuerNotAccepted authError = "token issuer is not accepted for this application"
)

// principalFor builds the evaluator's view of a validated token: its roles
// resolve through the snapshot bindings; home = token app_id when present.
func (p *GatewayPlugin) principalFor(claims *TokenClaims) *principal {
	if claims == nil {
		return nil
	}
	pr := &principal{userID: claims.UserID, homeApp: claims.AppID, subject: claims.Subject, email: claims.Email}
	pr.roles = claims.QualifiedRoles
	pr.resolveStatements(p.snapshot.policyIndex())
	return pr
}

// servePolicy is the policy engine request path (stages 1–7 above).
func (p *GatewayPlugin) servePolicy(rw http.ResponseWriter, req *http.Request, hostApp, requestedApp string) {
	ctx := req.Context()

	// 1. Target application.
	target := hostApp
	if requestedApp != "" && p.appRegistry != nil {
		if !p.appRegistry.isActiveApp(requestedApp) {
			p.deny(rw, req, http.StatusForbidden, "unknown_app", "requested application is not an active application", reasonUnknownApp, requestedApp, "", "")
			return
		}
		target = requestedApp
	}
	if target != "" {
		req.Header.Set(p.config.AppIDHeader, target)
	}

	// 2. Endpoint match under the target app. An explicit override may only
	// address routes exposed to that application: a route that exists for the
	// host app but not for the target must not pass through un-gated.
	ep := p.snapshot.matchEndpoint(target, req.Method, req.URL.Path)
	if ep == nil {
		if target != hostApp && p.snapshot.matchEndpoint(hostApp, req.Method, req.URL.Path) != nil {
			p.deny(rw, req, http.StatusForbidden, "forbidden", "endpoint is not exposed to the requested application", reasonEndpointNotExposed, target, "", "")
			return
		}
		p.forward(rw, req)
		return
	}

	// 3. Credential.
	if rawKey, isKey := extractAPIKeyCredential(req, p.config.JWTHeaderKey); isKey && !p.config.DisableAuth {
		p.serveAPIKey(rw, req, ep, target, rawKey)
		return
	}
	claims, reason, err := p.authenticate(target, req.Header.Get(p.config.JWTHeaderKey))
	if err != nil {
		p.log.errorf("jwt auth failure path=%s app_id=%s reason=%s error=%v", req.URL.Path, target, reason, err)
		writeJSON(rw, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": err.Error()})
		return
	}

	// 4. Principal and statements.
	pr := p.principalFor(claims)
	userID := ""
	if claims != nil {
		userID = claims.UserID
		p.log.infof("jwt auth success path=%s user_id=%s issuer=%s home_app=%s target_app=%s roles=%v bound=%v", req.URL.Path, claims.UserID, claims.Issuer, pr.homeApp, target, pr.roles, pr.boundRoles)
	}

	// 5. Required permission.
	if perm := ep.RequiredPermission; perm != "" {
		if claims == nil {
			p.deny(rw, req, http.StatusUnauthorized, "unauthorized", "authentication required for this endpoint", reasonNoToken, target, "", perm)
			return
		}
		if !pr.granted(perm, target) {
			p.deny(rw, req, http.StatusForbidden, "forbidden", "insufficient permissions", reasonNoMatchingStatement, target, userID, perm)
			return
		}
	}

	// 6. Trusted headers and rate-limit identity.
	var rateLimitKey, planName string
	wildcard := false
	if claims != nil {
		wildcard = pr.isWildcard(target)
		rateLimitKey = "app:" + target + "|user:" + claims.UserID
		planName = p.planResolver.Resolve(ctx, target, claims.UserID, p.config.DefaultPlanName)
		req.Header.Set(p.config.UserIDHeader, claims.UserID)
		req.Header.Set(p.config.UserPlanHeader, planName)
		if claims.Keycloak {
			req.Header.Set(p.config.UserUIDHeader, claims.Subject)
			if p.config.UserEmailHeader != "" && claims.Email != "" {
				req.Header.Set(p.config.UserEmailHeader, claims.Email)
			}
		}
		if len(pr.boundRoles) > 0 {
			req.Header.Set(p.config.UserRolesHeader, strings.Join(pr.boundRoles, ","))
		}
		if wildcard {
			req.Header.Set(p.config.IsAdminHeader, "true")
		}
		req.Header.Del(p.config.SessionIDHeader)
	} else {
		sessionID := req.Header.Get(p.config.SessionIDHeader)
		deviceID := req.Header.Get(p.config.DeviceIDHeader)
		if sessionID != "" {
			req.Header.Set(p.config.SessionIDHeader, sessionID)
		}
		if deviceID != "" {
			req.Header.Set(p.config.DeviceIDHeader, deviceID)
		}
		rateLimitKey = "app:" + target + "|" + anonymousRateLimitKey(deviceID, sessionID, clientIP(req))
		planName = p.config.DefaultPlanName
	}

	// 7a. Owner gate on the derived admin header.
	if ep.OwnerParam != "" {
		if claims == nil {
			p.deny(rw, req, http.StatusUnauthorized, "unauthorized", "authentication required for this endpoint", reasonNoToken, target, "", ep.RequiredPermission)
			return
		}
		if !wildcard && !ownerMatches(extractOwner(ep, req), claims.UserID, claims.Subject) {
			p.deny(rw, req, http.StatusForbidden, "forbidden", "not allowed to access another user's resource", reasonOwnerMismatch, target, userID, ep.RequiredPermission)
			return
		}
	}

	// 7b. Rate limit keyed by the target app; "*" holders are exempt there.
	if !wildcard && !p.applyRateLimit(rw, req, ep, rateLimitKey, planName) {
		return
	}

	p.forward(rw, req)
}

// applyRateLimit runs the fixed-window check; false when the request was
// rejected with 429 (response already written).
func (p *GatewayPlugin) applyRateLimit(rw http.ResponseWriter, req *http.Request, ep *compiledEndpoint, rateLimitKey, planName string) bool {
	if p.config.DisableRateLimit || p.rateLimiter == nil {
		return true
	}
	limit, window := p.resolveRateLimit(ep, planName)
	if limit <= 0 {
		return true
	}
	result, err := p.rateLimiter.Check(req.Context(), rateLimitKey, ep.UID, limit, window)
	if err != nil {
		p.log.errorf("rate limit check failed endpoint_uid=%s plan=%s error=%v", ep.UID, planName, err)
		return true
	}
	if !result.Allowed {
		p.log.warnf("rate limit exceeded endpoint_uid=%s plan=%s key=%s limit=%d window=%ds", ep.UID, planName, rateLimitKey, limit, window)
		rw.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		rw.Header().Set("X-RateLimit-Remaining", "0")
		rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
		rw.Header().Set("Retry-After", strconv.Itoa(int(time.Until(result.ResetAt).Seconds())))
		writeJSON(rw, http.StatusTooManyRequests, map[string]string{"error": "rate_limit_exceeded", "message": "too many requests"})
		return false
	}
	rw.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
	rw.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
	rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
	return true
}

// serveIAMMe answers GET /api/_iam/me for any authenticated principal of the
// host application: who it is, its roles, bound policies and the action
// patterns it holds per active application. Never reaches a backend.
func (p *GatewayPlugin) serveIAMMe(rw http.ResponseWriter, req *http.Request, hostApp string) {
	if req.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed", "message": "GET only"})
		return
	}
	claims, reason, err := p.authenticate(hostApp, req.Header.Get(p.config.JWTHeaderKey))
	if err != nil {
		p.deny(rw, req, http.StatusUnauthorized, "unauthorized", err.Error(), reason, hostApp, "", "")
		return
	}
	if claims == nil {
		p.deny(rw, req, http.StatusUnauthorized, "unauthorized", "authentication required", reasonNoToken, hostApp, "", "")
		return
	}
	pr := p.principalFor(claims)
	var active []string
	if p.appRegistry != nil {
		active = p.appRegistry.activeAppIDs()
	}
	if len(active) == 0 && hostApp != "" {
		active = []string{hostApp}
	}
	roles, policies := pr.roles, pr.policies
	if roles == nil {
		roles = []string{}
	}
	if policies == nil {
		policies = []string{}
	}
	writeJSON(rw, http.StatusOK, map[string]interface{}{
		"subject":            pr.subject,
		"user_id":            pr.userID,
		"home_app":           pr.homeApp,
		"roles":              roles,
		"policies":           policies,
		"permissions_by_app": pr.permissionsByApp(active),
	})
}

// logShadow computes the policy-engine verdict for a request the legacy engine
// is serving and logs it, so bindings can be verified before cutover.
func (p *GatewayPlugin) logShadow(ctx context.Context, ep *compiledEndpoint, hostApp, target string, claims *TokenClaims) {
	if claims == nil || !p.log.enabled(levelInfo) {
		return
	}
	pr := p.principalFor(claims)
	perm := ep.RequiredPermission
	if perm == "" && ep.AccessLevel == p.config.AdminAccessLevel {
		perm = p.config.AdminPermission
	}
	verdict, reason := "allow", ""
	if perm != "" && !pr.granted(perm, target) {
		verdict, reason = "deny", reasonNoMatchingStatement
	}
	unbound := []string{}
	if claims.Keycloak && len(pr.boundRoles) == 0 && len(pr.roles) > 0 {
		unbound = pr.roles
	}
	p.log.infof("shadow=%s reason=%s path=%s app_id=%s user_id=%s required=%s bound=%v unbound_role=%v admin=%t", verdict, reason, ep.FullPath, target, claims.UserID, perm, pr.boundRoles, unbound, pr.isWildcard(target))
}
