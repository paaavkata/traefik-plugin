package traefik_gateway_plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Test doubles ────────────────────────────────────────────────────────────────

// fakeRedisServer is a minimal in-process RESP2 server supporting the subset the
// api-key cache uses: PING, GET, SET key val EX seconds. It lets the cache tests run
// against the real respRedis client without an external Redis.
type fakeRedisServer struct {
	ln    net.Listener
	mu    sync.Mutex
	store map[string]string
}

func newFakeRedisServer(t *testing.T) *fakeRedisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake redis listen: %v", err)
	}
	s := &fakeRedisServer{ln: ln, store: make(map[string]string)}
	go s.serve()
	return s
}

func (s *fakeRedisServer) addr() string { return s.ln.Addr().String() }
func (s *fakeRedisServer) close()       { s.ln.Close() }

func (s *fakeRedisServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeRedisServer) handle(conn net.Conn) {
	defer conn.Close()
	rd := bufio.NewReader(conn)
	for {
		args, err := readRespCommand(rd)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		switch strings.ToUpper(args[0]) {
		case "PING":
			conn.Write([]byte("+PONG\r\n"))
		case "SET":
			// SET key value [EX seconds] — TTL ignored (tests are short-lived).
			if len(args) >= 3 {
				s.mu.Lock()
				s.store[args[1]] = args[2]
				s.mu.Unlock()
			}
			conn.Write([]byte("+OK\r\n"))
		case "GET":
			s.mu.Lock()
			v, ok := s.store[args[1]]
			s.mu.Unlock()
			if !ok {
				conn.Write([]byte("$-1\r\n"))
			} else {
				conn.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(v), v)))
			}
		default:
			conn.Write([]byte("+OK\r\n"))
		}
	}
}

// readRespCommand reads one RESP array-of-bulk-strings command.
func readRespCommand(rd *bufio.Reader) ([]string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("expected array header, got %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, fmt.Errorf("expected bulk header, got %q", hdr)
		}
		blen, err := strconv.Atoi(hdr[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, blen+2)
		if _, err := readFull(rd, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:blen]))
	}
	return args, nil
}

func readFull(rd *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := rd.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// validKey builds a well-formed fc_ token for tests.
func validKey(uid, secret string) string {
	return "fc_test_" + uid + "_" + secret
}

// ── parse tests ────────────────────────────────────────────────────────────────

func TestParseAPIKey_Valid(t *testing.T) {
	k, err := parseAPIKey("fc_test_a1b2c3d4e5f6_XoQ9secretpart")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.env != "test" || k.uid != "a1b2c3d4e5f6" || k.secret != "XoQ9secretpart" {
		t.Errorf("bad parse: %+v", k)
	}
}

func TestParseAPIKey_Malformed(t *testing.T) {
	for _, tok := range []string{
		"fc_test_onlythree",         // missing secret segment
		"fc_test__emptyuid",         // empty uid
		"fc_test_uid_",              // empty secret
		"fc__uid_secret",            // empty env
		"notakey",                   // no prefix
		"Bearer fc_test_uid_secret", // prefix not at start
	} {
		if _, err := parseAPIKey(tok); err == nil {
			t.Errorf("expected error for %q", tok)
		}
	}
}

func TestSecretHash_MatchesVerifyRequestForm(t *testing.T) {
	// Same secret must produce the same std-base64 SHA-256 used in cache key + request.
	k, _ := parseAPIKey("fc_test_uid123456789_abcDEFsecret")
	h1 := k.secretSHA256B64()
	if h1 == "" || strings.Contains(h1, "\n") {
		t.Fatalf("bad hash encoding %q", h1)
	}
	if !strings.HasPrefix(k.cacheKey(), "apikey:uid123456789:") {
		t.Errorf("unexpected cache key %q", k.cacheKey())
	}
}

// ── credential extraction ───────────────────────────────────────────────────────

func TestExtractAPIKeyCredential(t *testing.T) {
	// X-Api-Key wins.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Api-Key", "fc_test_uid_secret")
	if v, ok := extractAPIKeyCredential(r, "Authorization"); !ok || v != "fc_test_uid_secret" {
		t.Errorf("X-Api-Key: got %q ok=%v", v, ok)
	}

	// Authorization bearer fc_.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer fc_test_uid_secret")
	if v, ok := extractAPIKeyCredential(r, "Authorization"); !ok || v != "fc_test_uid_secret" {
		t.Errorf("bearer fc_: got %q ok=%v", v, ok)
	}

	// JWT bearer → not a key.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer eyJhbGci.jwt.token")
	if _, ok := extractAPIKeyCredential(r, "Authorization"); ok {
		t.Error("JWT bearer must not be treated as api key")
	}

	// No creds.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := extractAPIKeyCredential(r, "Authorization"); ok {
		t.Error("empty request must not yield a key")
	}
}

// ── plugin integration helpers ──────────────────────────────────────────────────

// mockIdentityVerify returns a verify server and a pointer to its call counter.
func mockIdentityVerify(t *testing.T, status int, body map[string]interface{}) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/internal/v1/api-keys/verify" {
			t.Errorf("unexpected verify path %q", r.URL.Path)
		}
		w.WriteHeader(status)
		if body != nil {
			json.NewEncoder(w).Encode(body)
		}
	}))
	return srv, &calls
}

func newAPIKeyPlugin(t *testing.T, next http.Handler, verifyURL string, cache *respRedis) *GatewayPlugin {
	t.Helper()
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.IdentityVerifyURL = verifyURL
	return &GatewayPlugin{
		next:        next,
		name:        "test",
		config:      config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
		identity:    newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{
			cache: make(map[string]planCacheEntry),
		},
		apiKeys: newAPIKeyVerifier(verifyURL, 2*time.Second, cache, "gw:rl:", nil),
	}
}

// ── happy path stamping ──────────────────────────────────────────────────────────

func TestPlugin_APIKey_HappyPath_StampsHeaders(t *testing.T) {
	srv, calls := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{
		"user_id": "77", "organization_id": nil, "app_id": "fileconvert", "plan": "pro", "scopes": []string{},
	})
	defer srv.Close()

	var gotUserID, gotPlan, gotUID, gotIsAdmin, gotRoles string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUserID = req.Header.Get("X-User-Id")
		gotPlan = req.Header.Get("X-User-Plan")
		gotUID = req.Header.Get("X-Api-Key-Uid")
		gotIsAdmin = req.Header.Get("X-Is-Admin")
		gotRoles = req.Header.Get("X-User-Roles")
		rw.WriteHeader(http.StatusOK)
	})
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-Api-Key", validKey("abcdef123456", "supersecretvalue"))
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotUserID != "77" {
		t.Errorf("X-User-Id=%q want 77", gotUserID)
	}
	if gotPlan != "pro" {
		t.Errorf("X-User-Plan=%q want pro", gotPlan)
	}
	if gotUID != "abcdef123456" {
		t.Errorf("X-Api-Key-Uid=%q want abcdef123456", gotUID)
	}
	if gotIsAdmin != "" || gotRoles != "" {
		t.Errorf("api-key path must never stamp admin/roles, got admin=%q roles=%q", gotIsAdmin, gotRoles)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Errorf("expected 1 identity call, got %d", *calls)
	}
}

// Bearer fc_ credential works identically to X-Api-Key.
func TestPlugin_APIKey_BearerCredential(t *testing.T) {
	srv, _ := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{
		"user_id": "5", "app_id": "fileconvert", "plan": "", "scopes": []string{},
	})
	defer srv.Close()

	var gotUserID, gotPlan string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUserID = req.Header.Get("X-User-Id")
		gotPlan = req.Header.Get("X-User-Plan")
		rw.WriteHeader(http.StatusOK)
	})
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("Authorization", "Bearer "+validKey("bearer123456", "sekret"))
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotUserID != "5" {
		t.Errorf("X-User-Id=%q want 5", gotUserID)
	}
	// Empty plan → header not stamped (contract §4).
	if gotPlan != "" {
		t.Errorf("empty plan must not stamp X-User-Plan, got %q", gotPlan)
	}
}

// ── spoofed X-Api-Key-Uid stripped on all paths ──────────────────────────────────

func TestPlugin_APIKey_StripsSpoofedUid_Matched(t *testing.T) {
	srv, _ := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{
		"user_id": "9", "app_id": "fileconvert", "plan": "free", "scopes": []string{},
	})
	defer srv.Close()

	var gotUID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUID = req.Header.Get("X-Api-Key-Uid")
		rw.WriteHeader(http.StatusOK)
	})
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-Api-Key-Uid", "spoofed-uid") // must be overwritten by trusted value
	req.Header.Set("X-Api-Key", validKey("realuid123456", "sekret"))
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if gotUID != "realuid123456" {
		t.Errorf("expected trusted uid realuid123456, got %q", gotUID)
	}
}

// Spoofed X-Api-Key-Uid on an anonymous matched request (no key) must be stripped.
func TestPlugin_APIKey_StripsSpoofedUid_Anonymous(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	var gotUID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUID = req.Header.Get("X-Api-Key-Uid")
		rw.WriteHeader(http.StatusOK)
	})
	plugin := &GatewayPlugin{
		next: next, name: "test", config: config,
		snapshot:     setupTestSnapshot(),
		identity:     newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: &PlanResolver{cache: make(map[string]planCacheEntry)},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Header.Set("X-Session-Id", "sess-1")
	req.Header.Set("X-Api-Key-Uid", "spoofed-uid")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if gotUID != "" {
		t.Errorf("expected spoofed X-Api-Key-Uid stripped on anonymous path, got %q", gotUID)
	}
}

// Spoofed X-Api-Key-Uid on the pass-through (unmatched) path must be stripped.
func TestPlugin_APIKey_StripsSpoofedUid_PassThrough(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true

	var gotUID string
	var seen bool
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seen = true
		gotUID = req.Header.Get("X-Api-Key-Uid")
		rw.WriteHeader(http.StatusOK)
	})
	plugin := &GatewayPlugin{next: next, name: "test", config: config, snapshot: setupTestSnapshot()}

	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	req.Header.Set("X-Api-Key-Uid", "spoofed-uid")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if !seen {
		t.Fatal("expected pass-through")
	}
	if gotUID != "" {
		t.Errorf("expected spoofed X-Api-Key-Uid stripped on pass-through, got %q", gotUID)
	}
}

// Spoofed X-Api-Key-Uid on an error path (unknown host enforce → 403) never reaches a backend.
func TestPlugin_APIKey_StripsSpoofedUid_ErrorPath(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "enforce"

	var forwarded bool
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		forwarded = true
		rw.WriteHeader(http.StatusOK)
	})
	plugin := &GatewayPlugin{
		next: next, name: "test", config: config,
		snapshot:    setupTestSnapshot(),
		appRegistry: setupTestAppRegistry(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "not-a-known-host.com"
	req.Header.Set("X-Api-Key-Uid", "spoofed-uid")
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 unknown host, got %d", rr.Code)
	}
	if forwarded {
		t.Error("request must not be forwarded on error path")
	}
}

// ── malformed key ────────────────────────────────────────────────────────────────

func TestPlugin_APIKey_Malformed_401(t *testing.T) {
	srv, calls := mockIdentityVerify(t, http.StatusOK, nil)
	defer srv.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-Api-Key", "fc_onlytwo") // malformed
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 malformed key, got %d", rr.Code)
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Errorf("malformed key must not reach identity, calls=%d", *calls)
	}
}

// ── app mismatch ─────────────────────────────────────────────────────────────────

func TestPlugin_APIKey_AppMismatch_401(t *testing.T) {
	srv, _ := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{
		"user_id": "1", "app_id": "cms", "plan": "free", "scopes": []string{}, // key bound to cms
	})
	defer srv.Close()

	var forwarded bool
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		forwarded = true
		rw.WriteHeader(http.StatusOK)
	})
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online" // resolves to fileconvert, key says cms
	req.Header.Set("X-Api-Key", validKey("mismatch1234", "sekret"))
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 app mismatch, got %d", rr.Code)
	}
	if forwarded {
		t.Error("app-mismatched key must not be forwarded")
	}
}

// ── identity down fail-closed ────────────────────────────────────────────────────

func TestPlugin_APIKey_IdentityDown_FailClosed_503(t *testing.T) {
	// Point at a closed port → transport error → unavailable → 503.
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newAPIKeyPlugin(t, next, "http://127.0.0.1:1/internal/v1/api-keys/verify", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-Api-Key", validKey("downkey12345", "sekret"))
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 fail-closed when identity down, got %d", rr.Code)
	}
}

func TestPlugin_APIKey_InvalidKey_401(t *testing.T) {
	srv, _ := mockIdentityVerify(t, http.StatusUnauthorized, map[string]interface{}{"error": "invalid_key"})
	defer srv.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-Api-Key", validKey("badkey123456", "sekret"))
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid key, got %d", rr.Code)
	}
}

// ── permission-gated endpoint denies key auth ────────────────────────────────────

func TestPlugin_APIKey_PermissionGated_Forbidden(t *testing.T) {
	srv, _ := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{
		"user_id": "3", "app_id": "fileconvert", "plan": "free", "scopes": []string{},
	})
	defer srv.Close()

	var forwarded bool
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		forwarded = true
		rw.WriteHeader(http.StatusOK)
	})
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", nil)

	// /v1/comments/hide requires content.moderate permission.
	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/comments/hide", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-Api-Key", validKey("permkey12345", "sekret"))
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 on permission-gated endpoint, got %d", rr.Code)
	}
	if forwarded {
		t.Error("permission-gated key request must not be forwarded")
	}
}

func TestPlugin_APIKey_AdminEndpoint_Forbidden(t *testing.T) {
	srv, _ := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{
		"user_id": "3", "app_id": "fileconvert", "plan": "free", "scopes": []string{},
	})
	defer srv.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/conversion/v1/admin/users", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("X-Api-Key", validKey("adminkey1234", "sekret"))
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 on admin endpoint via key auth, got %d", rr.Code)
	}
}

// ── cache hit / miss ─────────────────────────────────────────────────────────────

func TestPlugin_APIKey_CacheHitMiss(t *testing.T) {
	fake := newFakeRedisServer(t)
	defer fake.close()
	cache, err := dialRedis(context.Background(), fake.addr(), "", 0, nil)
	if err != nil {
		t.Fatalf("dial fake redis: %v", err)
	}
	defer cache.Close()

	srv, calls := mockIdentityVerify(t, http.StatusOK, map[string]interface{}{
		"user_id": "42", "app_id": "fileconvert", "plan": "pro", "scopes": []string{},
	})
	defer srv.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", cache)

	doReq := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
		req.Host = "fileconvert.online"
		req.Header.Set("X-Api-Key", validKey("cachekey1234", "sekret"))
		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)
		return rr.Code
	}

	// First request → cache miss → 1 identity call.
	if code := doReq(); code != http.StatusOK {
		t.Fatalf("first request expected 200, got %d", code)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Fatalf("after miss expected 1 identity call, got %d", *calls)
	}

	// Second request → cache hit → still 1 identity call.
	if code := doReq(); code != http.StatusOK {
		t.Fatalf("second request expected 200, got %d", code)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Errorf("after hit expected still 1 identity call, got %d", *calls)
	}
}

func TestPlugin_APIKey_NegativeCache(t *testing.T) {
	fake := newFakeRedisServer(t)
	defer fake.close()
	cache, err := dialRedis(context.Background(), fake.addr(), "", 0, nil)
	if err != nil {
		t.Fatalf("dial fake redis: %v", err)
	}
	defer cache.Close()

	srv, calls := mockIdentityVerify(t, http.StatusUnauthorized, map[string]interface{}{"error": "invalid_key"})
	defer srv.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := newAPIKeyPlugin(t, next, srv.URL+"/internal/v1/api-keys/verify", cache)

	doReq := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
		req.Host = "fileconvert.online"
		req.Header.Set("X-Api-Key", validKey("negkey123456", "sekret"))
		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := doReq(); code != http.StatusUnauthorized {
		t.Fatalf("first request expected 401, got %d", code)
	}
	if code := doReq(); code != http.StatusUnauthorized {
		t.Fatalf("second request expected 401 (cached deny), got %d", code)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Errorf("negative cache should collapse to 1 identity call, got %d", *calls)
	}
}

// ── JWT path unaffected when no fc_ credential present ────────────────────────────

func TestPlugin_APIKey_JWTPathUnaffected(t *testing.T) {
	// A normal JWT request must never touch the key verifier: point it at a closed
	// port so any accidental call would surface (503) instead of the JWT 200.
	serviceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"plan_name": "pro"})
	}))
	defer serviceServer.Close()

	var gotUserID, gotUID string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUserID = req.Header.Get("X-User-Id")
		gotUID = req.Header.Get("X-Api-Key-Uid")
		rw.WriteHeader(http.StatusOK)
	})

	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.IdentityVerifyURL = "http://127.0.0.1:1/internal/v1/api-keys/verify"
	plugin := &GatewayPlugin{
		next: next, name: "test", config: config,
		snapshot:     setupTestSnapshot(),
		appRegistry:  setupTestAppRegistry(),
		identity:     newIdentityClient("http://localhost:9999", 1*time.Second, nil),
		planResolver: newPlanResolver(serviceServer.URL, 5*time.Second, nil),
		apiKeys:      newAPIKeyVerifier("http://127.0.0.1:1/internal/v1/api-keys/verify", 2*time.Second, nil, "gw:rl:", nil),
	}

	token := createTestToken("test-secret", 99, "file-convert.online", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodPost, "/api/conversion/v1/convert", nil)
	req.Host = "fileconvert.online"
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	plugin.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("JWT request expected 200, got %d (key verifier must not run)", rr.Code)
	}
	if gotUserID != "99" {
		t.Errorf("expected JWT X-User-Id=99, got %q", gotUserID)
	}
	if gotUID != "" {
		t.Errorf("JWT path must not stamp X-Api-Key-Uid, got %q", gotUID)
	}
}
