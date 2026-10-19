package traefik_gateway_plugin

import (
	"encoding/json"
	"reflect"
	"testing"
)

func stmt(actions []string, apps ...string) Statement { return Statement{Actions: actions, Apps: apps} }

// TestGranted is the evaluator's contract, one row per spec scenario.
func TestGranted(t *testing.T) {
	cases := []struct {
		name  string
		stmts []Statement
		home  string
		perm  string
		app   string
		want  bool
	}{
		{"wildcard grant", []Statement{stmt([]string{"*"}, "*")}, "platform-admin", "payments.refund", "fileconvert", true},
		{"prefix on home", []Statement{stmt([]string{"content.*"}, "@home")}, "scantinel", "content.publish", "scantinel", true},
		{"right action wrong app", []Statement{stmt([]string{"content.*"}, "scantinel")}, "scantinel", "content.publish", "fileconvert", false},
		{"@home does not cover another app", []Statement{stmt([]string{"*"}, "@home")}, "scantinel", "content.read", "fileconvert", false},
		{"authenticated by literal", []Statement{stmt([]string{"authenticated"}, "@home")}, "scantinel", "authenticated", "scantinel", true},
		{"authenticated by wildcard", []Statement{stmt([]string{"*"}, "*")}, "x", "authenticated", "scantinel", true},
		{"authenticated NOT implied by prefix", []Statement{stmt([]string{"content.*"}, "*")}, "x", "authenticated", "scantinel", false},
		{"exact action", []Statement{stmt([]string{"customers.read"}, "fileconvert", "scantinel")}, "x", "customers.read", "scantinel", true},
		{"prefix must respect the dot", []Statement{stmt([]string{"content.*"}, "*")}, "x", "contentious.read", "scantinel", false},
		{"no statements", nil, "scantinel", "authenticated", "scantinel", false},
		{"no permission required", nil, "scantinel", "", "scantinel", true},
		{"union across statements", []Statement{stmt([]string{"support.*"}, "*"), stmt([]string{"customers.read"}, "fileconvert")}, "x", "customers.read", "fileconvert", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pr := &principal{homeApp: c.home, statements: c.stmts}
			if got := pr.granted(c.perm, c.app); got != c.want {
				t.Fatalf("granted(%q,%q)=%v want %v", c.perm, c.app, got, c.want)
			}
		})
	}
	var nilP *principal
	if nilP.granted("x.y", "a") || !nilP.granted("", "a") {
		t.Fatal("nil principal: gated → false, ungated → true")
	}
}

func TestIsWildcard_OnlyLiteralStar(t *testing.T) {
	owner := &principal{homeApp: "platform-admin", statements: []Statement{stmt([]string{"*"}, "*")}}
	if !owner.isWildcard("scantinel") {
		t.Fatal("* on * is wildcard everywhere")
	}
	tenantAdmin := &principal{homeApp: "scantinel", statements: []Statement{stmt([]string{"*"}, "@home")}}
	if !tenantAdmin.isWildcard("scantinel") || tenantAdmin.isWildcard("fileconvert") {
		t.Fatal("* on @home is wildcard only at home")
	}
	moderator := &principal{homeApp: "scantinel", statements: []Statement{stmt([]string{"content.*", "customers.*"}, "*")}}
	if moderator.isWildcard("scantinel") {
		t.Fatal("prefix grants never make an admin")
	}
}

func TestResolveStatements_UnboundRolesIgnored(t *testing.T) {
	idx := newPolicyIndex(
		[]Policy{
			{Name: "platform-owner", Statements: []Statement{stmt([]string{"*"}, "*")}},
			{Name: "tenant-user", Statements: []Statement{stmt([]string{"authenticated"}, "@home")}},
		},
		[]Binding{
			{Role: "platform-admin:admin", Policy: "platform-owner"},
			{Role: "default-roles-scantinel", Policy: "tenant-user"},
			{Role: "ghost", Policy: "does-not-exist"},
		},
	)
	pr := &principal{roles: []string{"scantinel-web:scanner", "default-roles-scantinel", "ghost"}, homeApp: "scantinel"}
	pr.resolveStatements(idx)
	if !reflect.DeepEqual(pr.boundRoles, []string{"default-roles-scantinel"}) {
		t.Fatalf("bound roles %v", pr.boundRoles)
	}
	if !reflect.DeepEqual(pr.policies, []string{"tenant-user"}) {
		t.Fatalf("policies %v", pr.policies)
	}
	if !pr.granted("authenticated", "scantinel") || pr.granted("content.read", "scantinel") {
		t.Fatal("tenant-user grants authenticated at home only")
	}
	// Client vs realm collision: a client role "admin" of another client never
	// matches the platform-admin binding.
	other := &principal{roles: []string{"scantinel-web:admin", "admin"}, homeApp: "scantinel"}
	other.resolveStatements(idx)
	if len(other.boundRoles) != 0 {
		t.Fatalf("expected no binding, got %v", other.boundRoles)
	}
	none := &principal{roles: []string{"x"}}
	none.resolveStatements(nil)
	if len(none.statements) != 0 {
		t.Fatal("cold snapshot: nothing bound")
	}
}

func TestPermissionsByApp(t *testing.T) {
	owner := &principal{homeApp: "platform-admin", statements: []Statement{stmt([]string{"*"}, "*")}}
	got := owner.permissionsByApp([]string{"fileconvert", "scantinel", "platform-admin"})
	want := map[string][]string{"fileconvert": {"*"}, "scantinel": {"*"}, "platform-admin": {"*"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("owner: %v", got)
	}
	user := &principal{homeApp: "scantinel", statements: []Statement{stmt([]string{"authenticated"}, "@home")}}
	got = user.permissionsByApp([]string{"fileconvert", "scantinel"})
	if !reflect.DeepEqual(got, map[string][]string{"scantinel": {"authenticated"}}) {
		t.Fatalf("tenant user: %v", got)
	}
	support := &principal{homeApp: "platform-admin", statements: []Statement{stmt([]string{"support.*", "customers.read"}, "*"), stmt([]string{"customers.read"}, "scantinel")}}
	got = support.permissionsByApp([]string{"scantinel"})
	if !reflect.DeepEqual(got["scantinel"], []string{"customers.read", "support.*"}) {
		t.Fatalf("support dedupe/sort: %v", got)
	}
}

func TestAPIKeyAdapter(t *testing.T) {
	key := &principal{homeApp: "fileconvert", statements: apiKeyStatements()}
	if !key.granted("authenticated", "fileconvert") || key.granted("authenticated", "scantinel") || key.granted("content.read", "fileconvert") || key.isWildcard("fileconvert") {
		t.Fatal("api key: authenticated on its own app only")
	}
}

func TestQualifyRolesAndTokenIssuer(t *testing.T) {
	got := qualifyRoles("platform-admin", []string{"admin", "admin"}, []string{"default-roles-infra", ""})
	if !reflect.DeepEqual(got, []string{"platform-admin:admin", "default-roles-infra"}) {
		t.Fatalf("qualifyRoles: %v", got)
	}
	if got := qualifyRoles("", []string{"admin"}, nil); len(got) != 0 {
		t.Fatalf("client roles without azp are unaddressable: %v", got)
	}
	tok := "Bearer eyJhbGciOiJSUzI1NiJ9." + b64(`{"iss":"https://auth.test/realms/infra","sub":"x"}`) + ".sig"
	if iss := tokenIssuer(tok); iss != "https://auth.test/realms/infra" {
		t.Fatalf("tokenIssuer: %q", iss)
	}
	for _, bad := range []string{"", "Bearer x", "Bearer a.!!!.c"} {
		if tokenIssuer(bad) != "" {
			t.Errorf("tokenIssuer(%q) should be empty", bad)
		}
	}
}

func TestSnapshot_PoliciesParsedAndReplacedOnRefresh(t *testing.T) {
	raw := `{"version":"1","apps":[],"policies":[{"name":"p","statements":[{"actions":["content.*"],"apps":["@home"]}]}],"bindings":[{"role":"web:mod","policy":"p"}]}`
	var snap SnapshotDTO
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatal(err)
	}
	idx := newPolicyIndex(snap.Policies, snap.Bindings)
	if idx.rolePolicy["web:mod"] != "p" || len(idx.policies["p"]) != 1 {
		t.Fatalf("index: %+v", idx)
	}
	// Edited policy on the next refresh replaces the map.
	raw2 := `{"version":"2","apps":[],"policies":[{"name":"p","statements":[{"actions":["*"],"apps":["*"]}]}],"bindings":[]}`
	var snap2 SnapshotDTO
	_ = json.Unmarshal([]byte(raw2), &snap2)
	idx2 := newPolicyIndex(snap2.Policies, snap2.Bindings)
	if _, bound := idx2.rolePolicy["web:mod"]; bound || idx2.policies["p"][0].Actions[0] != "*" {
		t.Fatalf("refresh did not replace the index: %+v", idx2)
	}
	// Old service-service (no fields) and cold cache: nothing bound.
	var old SnapshotDTO
	_ = json.Unmarshal([]byte(`{"version":"3","apps":[]}`), &old)
	if idx := newPolicyIndex(old.Policies, old.Bindings); len(idx.rolePolicy) != 0 {
		t.Fatal("snapshot without policies must bind nothing")
	}
	cold := &SnapshotCache{stopCh: make(chan struct{})}
	if cold.policyIndex() != nil {
		t.Fatal("cold cache has no policy index")
	}
}
