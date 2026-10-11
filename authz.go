package traefik_gateway_plugin

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
)

// Access-policy evaluation (gateway-iam-policies).
//
// The registry snapshot carries policies (named lists of allow statements) and
// bindings (identity-provider role → policy). A principal's grant set is the
// union of the statements of every policy bound to one of its roles; a request
// is allowed when some statement grants the endpoint's required permission on
// the target application. There is no deny, so order never matters.
//
//	action  "*" | "<res>.*" | "<res>.<act>" | "authenticated"
//	app     "*" | "@home" (the principal's home application) | <app id>
//
// "authenticated" is granted only by "*" or the literal "authenticated": a
// "<res>.*" prefix never implies it.

const (
	permAuthenticated = "authenticated"
	appWildcard       = "*"
	appHome           = "@home"
)

// Statement is one allow rule of a policy.
type Statement struct {
	Actions []string `json:"actions"`
	Apps    []string `json:"apps"`
}

// Policy is a named list of statements, as published in the snapshot.
type Policy struct {
	Name       string      `json:"name"`
	Statements []Statement `json:"statements"`
}

// Binding maps one qualified role name to a policy name.
type Binding struct {
	Role   string `json:"role"`
	Policy string `json:"policy"`
}

// principal is the authenticated caller as seen by the evaluator.
type principal struct {
	subject string // Keycloak sub (empty for legacy / API-key principals)
	userID  string // X-User-Id value
	homeApp string // application the credential was issued for
	email   string
	roles   []string // qualified roles carried by the token ("<azp>:<role>" / "<realm role>")

	// Resolved from the snapshot (or synthesized for legacy / API-key principals).
	statements []Statement
	boundRoles []string // roles that resolved to a policy
	policies   []string // distinct bound policy names
}

// matchAction reports whether pattern grants perm.
func matchAction(pattern, perm string) bool {
	if pattern == "*" || pattern == perm {
		return true
	}
	if perm == permAuthenticated {
		return false
	}
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(perm, pattern[:len(pattern)-1])
	}
	return false
}

// matchApp reports whether the statement's app entry covers target for a
// principal whose home application is home.
func matchApp(entry, target, home string) bool {
	switch entry {
	case appWildcard:
		return true
	case appHome:
		return home != "" && target == home
	}
	return entry == target
}

// granted reports whether some statement grants perm on app.
func (p *principal) granted(perm, app string) bool {
	if p == nil || perm == "" {
		return perm == ""
	}
	for _, s := range p.statements {
		if !coversApp(s, app, p.homeApp) {
			continue
		}
		for _, a := range s.Actions {
			if matchAction(a, perm) {
				return true
			}
		}
	}
	return false
}

// isWildcard reports whether the principal holds a literal "*" action on app:
// the only thing that stamps X-Is-Admin and bypasses the owner gate and the
// per-plan rate limit.
func (p *principal) isWildcard(app string) bool {
	if p == nil {
		return false
	}
	for _, s := range p.statements {
		if !coversApp(s, app, p.homeApp) {
			continue
		}
		for _, a := range s.Actions {
			if a == "*" {
				return true
			}
		}
	}
	return false
}

func coversApp(s Statement, target, home string) bool {
	for _, e := range s.Apps {
		if matchApp(e, target, home) {
			return true
		}
	}
	return false
}

// permissionsByApp expands the principal's statements against the active
// application list: app → sorted distinct action patterns granted there.
// Applications with no grant are omitted.
func (p *principal) permissionsByApp(activeApps []string) map[string][]string {
	out := map[string][]string{}
	if p == nil {
		return out
	}
	for _, app := range activeApps {
		seen := map[string]bool{}
		for _, s := range p.statements {
			if !coversApp(s, app, p.homeApp) {
				continue
			}
			for _, a := range s.Actions {
				seen[a] = true
			}
		}
		if len(seen) == 0 {
			continue
		}
		list := make([]string, 0, len(seen))
		for a := range seen {
			list = append(list, a)
		}
		sort.Strings(list)
		out[app] = list
	}
	return out
}

// resolveStatements attaches the statements of every bound role, in role order.
func (p *principal) resolveStatements(idx *policyIndex) {
	p.statements = nil
	p.boundRoles = nil
	p.policies = nil
	if idx == nil {
		return
	}
	seenPolicy := map[string]bool{}
	for _, r := range p.roles {
		name, ok := idx.rolePolicy[r]
		if !ok {
			continue
		}
		p.boundRoles = append(p.boundRoles, r)
		if seenPolicy[name] {
			continue
		}
		seenPolicy[name] = true
		p.policies = append(p.policies, name)
		p.statements = append(p.statements, idx.policies[name]...)
	}
}

// legacyStatements synthesizes the statement set of a legacy (identity-service)
// principal: its reported permissions become actions on @home; is_admin adds
// "*" on @home. nil authz (identity unavailable) ⇒ no statements.
func legacyStatements(authz *UserAuthz) []Statement {
	if authz == nil {
		return nil
	}
	actions := []string{}
	for _, perm := range authz.Permissions {
		if perm == "*" {
			actions = append(actions, "*")
			continue
		}
		actions = append(actions, perm)
	}
	if authz.IsAdmin {
		actions = append(actions, "*")
	}
	// Every authenticated legacy user is at least a tenant user.
	actions = append(actions, permAuthenticated)
	return []Statement{{Actions: actions, Apps: []string{appHome}}}
}

// apiKeyStatements: an API key is a tenant user of its bound application.
func apiKeyStatements() []Statement {
	return []Statement{{Actions: []string{permAuthenticated}, Apps: []string{appHome}}}
}

// policyIndex is the compiled form of the snapshot's policies and bindings.
type policyIndex struct {
	policies   map[string][]Statement // policy name → statements
	rolePolicy map[string]string      // qualified role → policy name
}

func newPolicyIndex(policies []Policy, bindings []Binding) *policyIndex {
	idx := &policyIndex{
		policies:   make(map[string][]Statement, len(policies)),
		rolePolicy: make(map[string]string, len(bindings)),
	}
	for _, p := range policies {
		stmts := p.Statements
		if stmts == nil {
			stmts = []Statement{}
		}
		idx.policies[p.Name] = stmts
	}
	for _, b := range bindings {
		if _, ok := idx.policies[b.Policy]; !ok {
			continue // dangling binding: contributes nothing
		}
		idx.rolePolicy[b.Role] = b.Policy
	}
	return idx
}

// qualifyRoles builds the role names bindings reference: client roles of the
// authorized party as "<azp>:<role>", realm roles bare.
func qualifyRoles(azp string, clientRoles, realmRoles []string) []string {
	out := make([]string, 0, len(clientRoles)+len(realmRoles))
	seen := map[string]bool{}
	add := func(r string) {
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	if azp != "" {
		for _, r := range clientRoles {
			add(azp + ":" + r)
		}
	}
	for _, r := range realmRoles {
		add(r)
	}
	return out
}

// tokenIssuer returns the UNVERIFIED `iss` claim of a bearer token ("" when
// unparseable). Used only to pick which realm validates the token; the chosen
// validator still checks `iss` byte-for-byte after verifying the signature.
func tokenIssuer(authHeader string) string {
	tok := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	return c.Iss
}
