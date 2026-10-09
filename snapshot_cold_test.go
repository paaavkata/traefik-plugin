package traefik_gateway_plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Gateway restarts while service-service is down: every refresh fails, the
// snapshot never loads, and in enforce mode requests must get 503 (never an
// un-gated pass-through). Once a refresh succeeds, matching resumes without a
// restart.
func TestPlugin_ColdSnapshot_EnforceFailsClosed(t *testing.T) {
	var healthy atomic.Bool
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(SnapshotDTO{Version: "v1", GeneratedAt: time.Now()})
	}))
	defer registry.Close()

	sc := newSnapshotCache(registry.URL, time.Second, time.Hour, time.Hour, newPluginLogger("error"))
	sc.refresh(context.Background()) // fails: 500
	if sc.Loaded() {
		t.Fatal("snapshot must not report loaded after a failed refresh")
	}

	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "enforce"

	passed := atomic.Int32{}
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		passed.Add(1)
		rw.WriteHeader(http.StatusOK)
	})
	plugin := &GatewayPlugin{next: next, name: "test", config: config, snapshot: sc, log: newPluginLogger("error")}

	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	rr := httptest.NewRecorder()
	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold snapshot in enforce mode: want 503, got %d", rr.Code)
	}
	if passed.Load() != 0 {
		t.Fatal("request reached the backend while the snapshot was cold")
	}

	// Registry recovers: the next refresh loads and requests flow again.
	healthy.Store(true)
	sc.refresh(context.Background())
	if !sc.Loaded() {
		t.Fatal("snapshot must report loaded after a successful refresh")
	}
	rr = httptest.NewRecorder()
	plugin.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || passed.Load() != 1 {
		t.Fatalf("after recovery: want 200 pass-through (unregistered path), got %d passed=%d", rr.Code, passed.Load())
	}

	// A later failed refresh keeps the last good snapshot.
	healthy.Store(false)
	sc.refresh(context.Background())
	if !sc.Loaded() {
		t.Fatal("a failed refresh after a successful load must keep Loaded() true")
	}
}

// Permissive mode keeps today's behaviour: a cold snapshot passes through.
func TestPlugin_ColdSnapshot_PermissivePassesThrough(t *testing.T) {
	config := CreateConfig()
	config.JWTSecret = "test-secret"
	config.DisableRateLimit = true
	config.AppResolutionMode = "permissive"
	sc := &SnapshotCache{stopCh: make(chan struct{})}
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusOK) })
	plugin := &GatewayPlugin{next: next, name: "test", config: config, snapshot: sc, log: newPluginLogger("error")}
	rr := httptest.NewRecorder()
	plugin.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("permissive cold snapshot: want 200, got %d", rr.Code)
	}
}
