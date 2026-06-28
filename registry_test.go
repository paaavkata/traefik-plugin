package traefik_gateway_plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Example.COM", "example.com"},
		{"example.com:8080", "example.com"},
		{"EXAMPLE.com.", "example.com"},
		{"  fileconvert.online  ", "fileconvert.online"},
		{"FileConvert.Online:443.", "fileconvert.online"},
		{"127.0.0.1:6000", "127.0.0.1"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeHost(c.in); got != c.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAppRegistry_ResolveHost_HitMiss(t *testing.T) {
	c := &AppRegistryCache{
		byHost: map[string]string{"fileconvert.online": "fileconvert"},
		loaded: true,
	}

	if id, ok := c.resolveHost("FileConvert.Online:443"); !ok || id != "fileconvert" {
		t.Errorf("expected (fileconvert,true), got (%q,%v)", id, ok)
	}
	if id, ok := c.resolveHost("unknown.example"); ok || id != "" {
		t.Errorf("expected miss, got (%q,%v)", id, ok)
	}
}

func TestAppRegistry_ResolveHost_Wildcard(t *testing.T) {
	c := &AppRegistryCache{
		byHost:    map[string]string{"app.example.com": "exact"},
		wildcards: []wildcardHostEntry{{suffix: ".example.com", appID: "wild"}},
		loaded:    true,
	}

	// Exact match takes precedence over wildcard.
	if id, ok := c.resolveHost("app.example.com"); !ok || id != "exact" {
		t.Errorf("expected exact, got (%q,%v)", id, ok)
	}
	// Falls back to wildcard.
	if id, ok := c.resolveHost("other.example.com"); !ok || id != "wild" {
		t.Errorf("expected wild, got (%q,%v)", id, ok)
	}
	if _, ok := c.resolveHost("nope.org"); ok {
		t.Error("expected miss for non-matching host")
	}
}

func TestAppRegistry_ColdStart(t *testing.T) {
	cold := &AppRegistryCache{byHost: map[string]string{}}
	if !cold.coldStart() {
		t.Error("expected coldStart true before first load")
	}
	warm := &AppRegistryCache{byHost: map[string]string{}, loaded: true}
	if warm.coldStart() {
		t.Error("expected coldStart false after load")
	}
}

// refresh parses the §11 snapshot, building byHost from the flat hosts map and
// including only active hosts.
func TestAppRegistry_Refresh_ActiveOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/registry/snapshot" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(AppRegistryDTO{
			Version: "7",
			Hosts: map[string]AppHostDTO{
				"fileconvert.online": {AppID: "fileconvert", Status: "active"},
				"suspended.example":  {AppID: "dead", Status: "suspended"},
			},
		})
	}))
	defer server.Close()

	c := newAppRegistryCache(server.URL, 2*time.Second, time.Minute, time.Minute, nil)
	c.refresh(context.Background())

	if c.coldStart() {
		t.Fatal("expected loaded after successful refresh")
	}
	if id, ok := c.resolveHost("fileconvert.online"); !ok || id != "fileconvert" {
		t.Errorf("expected active host resolved, got (%q,%v)", id, ok)
	}
	if _, ok := c.resolveHost("suspended.example"); ok {
		t.Error("expected suspended host NOT resolved")
	}
	if c.version != "7" {
		t.Errorf("expected version 7, got %q", c.version)
	}
}

// A failed refresh (non-OK / unreachable) must keep the last-known-good map.
func TestAppRegistry_Refresh_LastKnownGood(t *testing.T) {
	var fail bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(AppRegistryDTO{
			Version: "1",
			Hosts:   map[string]AppHostDTO{"fileconvert.online": {AppID: "fileconvert", Status: "active"}},
		})
	}))
	defer server.Close()

	c := newAppRegistryCache(server.URL, 2*time.Second, time.Minute, time.Minute, nil)
	c.refresh(context.Background())
	if id, _ := c.resolveHost("fileconvert.online"); id != "fileconvert" {
		t.Fatalf("setup: expected fileconvert, got %q", id)
	}

	// Now make the server fail and refresh again.
	fail = true
	c.refresh(context.Background())

	if id, ok := c.resolveHost("fileconvert.online"); !ok || id != "fileconvert" {
		t.Errorf("expected last-known-good preserved after failed refresh, got (%q,%v)", id, ok)
	}
}

// checkVersion triggers a refresh only when the version string changes.
func TestAppRegistry_CheckVersion_RefreshesOnChange(t *testing.T) {
	version := "1"
	var snapshotCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/registry/version":
			json.NewEncoder(w).Encode(AppRegistryVersionDTO{Version: version})
		case "/v1/registry/snapshot":
			snapshotCalls++
			json.NewEncoder(w).Encode(AppRegistryDTO{
				Version: version,
				Hosts:   map[string]AppHostDTO{"fileconvert.online": {AppID: "fileconvert", Status: "active"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := newAppRegistryCache(server.URL, 2*time.Second, time.Minute, time.Minute, nil)
	c.refresh(context.Background()) // initial load, version "1"
	if snapshotCalls != 1 {
		t.Fatalf("expected 1 snapshot call after initial refresh, got %d", snapshotCalls)
	}

	// Same version → no refresh.
	c.checkVersion()
	if snapshotCalls != 1 {
		t.Errorf("expected no refresh when version unchanged, got %d snapshot calls", snapshotCalls)
	}

	// Version bump → refresh.
	version = "2"
	c.checkVersion()
	if snapshotCalls != 2 {
		t.Errorf("expected refresh on version change, got %d snapshot calls", snapshotCalls)
	}
}
