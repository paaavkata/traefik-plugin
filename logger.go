package traefik_gateway_plugin

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type logLevel int

const levelNone logLevel = -1

const (
	levelError logLevel = iota
	levelWarn
	levelInfo
	levelDebug
)

func parseLogLevel(s string) logLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return levelError
	case "warn", "warning":
		return levelWarn
	case "", "info":
		return levelInfo
	case "debug":
		return levelDebug
	case "none", "off", "silent":
		return levelNone
	default:
		return levelInfo
	}
}

// pluginLogger writes to stderr with configurable verbosity. All methods are nil-safe.
type pluginLogger struct {
	level logLevel
	out   *log.Logger
}

func newPluginLogger(levelStr string) *pluginLogger {
	lvl := parseLogLevel(levelStr)
	return &pluginLogger{
		level: lvl,
		out:   log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds),
	}
}

func (l *pluginLogger) enabled(min logLevel) bool {
	if l == nil {
		return false
	}
	if l.level == levelNone {
		return false
	}
	return l.level >= min
}

func (l *pluginLogger) errorf(format string, args ...interface{}) {
	if !l.enabled(levelError) {
		return
	}
	l.out.Printf("[gateway-plugin][ERROR] "+format, args...)
}

func (l *pluginLogger) warnf(format string, args ...interface{}) {
	if !l.enabled(levelWarn) {
		return
	}
	l.out.Printf("[gateway-plugin][WARN] "+format, args...)
}

func (l *pluginLogger) infof(format string, args ...interface{}) {
	if !l.enabled(levelInfo) {
		return
	}
	l.out.Printf("[gateway-plugin][INFO] "+format, args...)
}

func (l *pluginLogger) debugf(format string, args ...interface{}) {
	if !l.enabled(levelDebug) {
		return
	}
	l.out.Printf("[gateway-plugin][DEBUG] "+format, args...)
}

const maxLoggedHTTPBody = 8192

func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf(" ... [truncated, total %d bytes]", len(s))
}

func redactAuthHeader(v string) string {
	if v == "" {
		return ""
	}
	low := strings.ToLower(strings.TrimSpace(v))
	if strings.HasPrefix(low, "bearer ") {
		return "Bearer ***"
	}
	return "***"
}

func formatRequestHeaders(req *http.Request) string {
	if req == nil {
		return ""
	}
	names := make([]string, 0, len(req.Header))
	for n := range req.Header {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteString("; ")
		}
		canonical := http.CanonicalHeaderKey(n)
		vals := req.Header[n]
		for j, v := range vals {
			if j > 0 {
				b.WriteString(", ")
			}
			if canonical == "Authorization" {
				v = redactAuthHeader(v)
			}
			fmt.Fprintf(&b, "%s: %q", n, v)
		}
	}
	return b.String()
}

func formatRedisCmd(args []string) string {
	if len(args) == 0 {
		return ""
	}
	cp := make([]string, len(args))
	copy(cp, args)
	if len(cp) > 0 && strings.EqualFold(cp[0], "AUTH") && len(cp) > 1 {
		cp[1] = "***"
	}
	return strings.Join(cp, " ")
}

func formatRedisResult(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "<nil>"
	case string:
		return truncateForLog(x, 256)
	case int64:
		return fmt.Sprintf("%d", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func since(start time.Time) time.Duration {
	return time.Since(start)
}
