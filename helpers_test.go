package traefik_gateway_plugin

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	if got := clientIP(req); got != "203.0.113.5" {
		t.Fatalf("clientIP() = %q, want 203.0.113.5", got)
	}
}

func TestAnonymousRateLimitKey(t *testing.T) {
	if got := anonymousRateLimitKey("dev-1", "sess-1", "1.2.3.4"); got != "device:dev-1" {
		t.Fatalf("got %q", got)
	}
	if got := anonymousRateLimitKey("", "sess-1", "1.2.3.4"); got != "session:sess-1" {
		t.Fatalf("got %q", got)
	}
	if got := anonymousRateLimitKey("", "", "1.2.3.4"); got != "ip:1.2.3.4" {
		t.Fatalf("got %q", got)
	}
}
