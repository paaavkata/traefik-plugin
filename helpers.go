package traefik_gateway_plugin

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

func writeJSON(rw http.ResponseWriter, statusCode int, data interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)
	json.NewEncoder(rw).Encode(data)
}

// clientIP returns the leftmost address from X-Forwarded-For (edge/client first),
// then X-Real-IP, then the connection remote address. Works behind Nginx → Traefik
// and future load balancers that prepend the client IP.
func clientIP(req *http.Request) string {
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			if ip := strings.TrimSpace(part); ip != "" {
				return ip
			}
		}
	}
	if rip := strings.TrimSpace(req.Header.Get("X-Real-IP")); rip != "" {
		return rip
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// anonymousRateLimitKey prefers device_id, then session_id, then client IP.
func anonymousRateLimitKey(deviceID, sessionID, ip string) string {
	if deviceID != "" {
		return "device:" + deviceID
	}
	if sessionID != "" {
		return "session:" + sessionID
	}
	if ip != "" {
		return "ip:" + ip
	}
	return "anon:unknown"
}
