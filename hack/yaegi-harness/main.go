// yaegi-harness runs the plugin under yaegi (Traefik's plugin interpreter) the
// way Traefik does and checks two behaviours that were correct when compiled
// but wrong when interpreted (prod 500s on 2026-10-16):
//
//  1. every app realm is bound to its OWN JWKS cache (New() range loop);
//  2. an unknown kid is a verification error, not a nil-key panic.
//
// Run:  cd hack/yaegi-harness && GOWORK=off go run . ../..   (own module, so vendor/ of
// the plugin stays untouched; the argument is the plugin repo root)
// It copies the package (with vendor/) into a temp GOPATH, appends a probe
// file, and exits non-zero on any failure. Not wired into CI yet.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

const importPath = "github.com/fileconvert/traefik-gateway-plugin"

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func main() {
	root := "../.."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	root, err := filepath.Abs(root)
	if err != nil {
		panic(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".traefik.yml")); err != nil {
		fmt.Fprintln(os.Stderr, "usage: go run . <plugin repo root> (dir with .traefik.yml)")
		os.Exit(2)
	}
	gopath, err := os.MkdirTemp("", "yaegi-harness-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(gopath)
	dst := filepath.Join(gopath, "src", filepath.FromSlash(importPath))
	if err := os.MkdirAll(dst, 0o755); err != nil {
		panic(err)
	}
	// Package sources + vendor, no tests, no hack/.
	cp := exec.Command("sh", "-c", `cp *.go go.mod go.sum "$0"/ && rm -f "$0"/*_test.go && cp -r vendor "$0"/`, dst)
	cp.Dir = root
	cp.Stderr = os.Stderr
	if err := cp.Run(); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "zz_yaegi_probe.go"), []byte(probeSrc), 0o644); err != nil {
		panic(err)
	}

	// JWKS server with one RS256 key, kid k1.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := map[string]interface{}{"keys": []map[string]string{{
		"kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig",
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/certs") {
			_ = json.NewEncoder(w).Encode(jwks)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	iss := "https://auth.example/realms/fileconvert"
	mint := func(kid string) string {
		hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
		pl, _ := json.Marshal(map[string]interface{}{"iss": iss, "sub": "u1", "app_id": "fileconvert", "luid": "4",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
		signing := b64(hdr) + "." + b64(pl)
		h := sha256.Sum256([]byte(signing))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		return signing + "." + b64(sig)
	}

	i := interp.New(interp.Options{GoPath: gopath, Unrestricted: true})
	if err := i.Use(stdlib.Symbols); err != nil {
		panic(err)
	}
	if _, err := i.Eval(`import "` + importPath + `"`); err != nil {
		panic(err)
	}
	pkg := strings.ReplaceAll(filepath.Base(importPath), "-", "_")
	eval := func(name string) interface{} {
		v, err := i.Eval(pkg + "." + name)
		if err != nil {
			panic(err)
		}
		return v.Interface()
	}
	failed := false
	check := func(name string, ok bool, detail string) {
		status := "ok  "
		if !ok {
			status = "FAIL"
			failed = true
		}
		fmt.Printf("%s %s: %s\n", status, name, detail)
	}

	realms := eval("YaegiProbeRealms").(func(string, string, string, int) string)
	r := realms(srv.URL+"/realms/scantinel/certs", srv.URL+"/realms/fileconvert/certs", srv.URL, 40)
	check("realm binding (40 instances)", r == "ok", r)

	eval("YaegiProbeInit").(func(string))(srv.URL + "/realms/fileconvert/certs")
	once := eval("YaegiProbeParse").(func(string, string) string)
	known := once(mint("k1"), iss)
	check("known kid verifies", known == "ok", known)
	unknown := once(mint("k-unknown"), iss)
	check("unknown kid is an error, not a panic", strings.HasPrefix(unknown, "err:") && strings.Contains(unknown, "k-unknown"), unknown)

	if failed {
		os.Exit(1)
	}
}

// probeSrc is appended to the package so the harness can reach unexported
// internals from interpreted code (same package, exported probe functions).
const probeSrc = `package traefik_gateway_plugin

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func YaegiProbeRealms(scantinelJWKS, fileconvertJWKS, dummyURL string, n int) string {
	for i := 0; i < n; i++ {
		cfg := CreateConfig()
		cfg.JWTSecret = "x"
		cfg.JWTIssuer = "file-convert.online"
		cfg.ServiceServiceURL = dummyURL
		cfg.IdentityServiceURL = dummyURL
		cfg.AppResolutionMode = "disabled"
		cfg.DisableRateLimit = true
		cfg.LogLevel = "error"
		cfg.KeycloakApps = []string{"scantinel"}
		cfg.KeycloakIssuer = "https://auth.scantinel.ai/realms/scantinel"
		cfg.KeycloakJWKSURL = scantinelJWKS
		cfg.KeycloakRealms = []KeycloakRealm{{AppID: "fileconvert", Issuer: "https://auth.file-convert.online/realms/fileconvert", JWKSURL: fileconvertJWKS, AcceptLegacy: true}}
		h, err := New(context.Background(), http.NotFoundHandler(), cfg, "probe")
		if err != nil {
			return "New: " + err.Error()
		}
		p := h.(*GatewayPlugin)
		for app, want := range map[string]string{"scantinel": scantinelJWKS, "fileconvert": fileconvertJWKS} {
			jc, _ := p.keycloakRealms[app].jwks.(*JWKSCache)
			if jc == nil || jc.url != want {
				return fmt.Sprintf("instance %d: app %s bound to %v, want %s", i, app, p.keycloakRealms[app].jwks, want)
			}
		}
	}
	return "ok"
}

var yaegiProbeCache *JWKSCache

func YaegiProbeInit(jwksURL string) {
	yaegiProbeCache = getSharedJWKSCache(jwksURL, 5*time.Second, time.Minute, 100*time.Millisecond, newPluginLogger("error"))
}

func YaegiProbeParse(token, issuer string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("panic: %v", r)
		}
	}()
	_, err := parseKeycloakJWT("Bearer "+token, yaegiProbeCache, issuer, "luid", 30*time.Second, []string{"admin"})
	if err != nil {
		return "err: " + err.Error()
	}
	return "ok"
}
`
