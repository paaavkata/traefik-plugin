package traefik_gateway_plugin

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// respRedis is a tiny Redis RESP2 client (no unsafe / cgo), sufficient for rate limiting.
//
// The connection is established lazily and re-established after any I/O
// error, so a Redis restart never needs a Traefik reload: commands fail (the
// callers fail open) until Redis is back, then the next command reconnects.
type respRedis struct {
	addr   string
	useTLS bool
	pwd    string
	db     int

	conn net.Conn
	rd   *bufio.Reader
	bw   *bufio.Writer
	mu   sync.Mutex
	log  *pluginLogger

	// retryAt is the earliest time of the next dial after a failed one, so a
	// Redis outage costs one dial per backoff period, not one per request.
	retryAt time.Time
}

const (
	redisDialTimeout   = time.Second
	redisRedialBackoff = 2 * time.Second
)

// redisReplyError is an error reply from Redis ("-ERR ..."). The connection is
// still usable after it, unlike after an I/O or protocol error.
type redisReplyError string

func (e redisReplyError) Error() string { return "redis: " + string(e) }

// dialRedis returns a client for redisURL. Only an unusable URL is an error:
// an unreachable Redis is logged and retried on later commands, because
// failing here would make Traefik drop every route that uses the middleware.
func dialRedis(ctx context.Context, redisURL, password string, db int, log *pluginLogger) (*respRedis, error) {
	addr, useTLS, pwd, err := parseRedisURL(redisURL, password)
	if err != nil {
		return nil, err
	}
	r := &respRedis{addr: addr, useTLS: useTLS, pwd: pwd, db: db, log: log}

	r.mu.Lock()
	err = r.connect(ctx)
	r.mu.Unlock()
	if err != nil {
		log.warnf("redis unreachable at startup addr=%s (will retry on use): %v", addr, err)
	}
	return r, nil
}

// connect dials and runs the AUTH/SELECT/PING handshake. Caller holds r.mu.
func (r *respRedis) connect(ctx context.Context) error {
	if time.Now().Before(r.retryAt) {
		return fmt.Errorf("redis unavailable (next dial after %s)", r.retryAt.Format(time.RFC3339))
	}
	err := r.dialAndHandshake(ctx)
	if err != nil {
		r.dropConn()
		r.retryAt = time.Now().Add(redisRedialBackoff)
	}
	return err
}

func (r *respRedis) dialAndHandshake(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, redisDialTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", r.addr)
	if err != nil {
		return err
	}
	if r.useTLS {
		tconn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12})
		if err := tconn.HandshakeContext(dialCtx); err != nil {
			conn.Close()
			return err
		}
		conn = tconn
	}
	r.conn = conn
	r.rd = bufio.NewReader(conn)
	r.bw = bufio.NewWriter(conn)

	if r.pwd != "" {
		if _, err := r.roundTrip(dialCtx, "AUTH", r.pwd); err != nil {
			return err
		}
	}
	if r.db != 0 {
		if _, err := r.roundTrip(dialCtx, "SELECT", strconv.Itoa(r.db)); err != nil {
			return err
		}
	}
	_, err = r.roundTrip(dialCtx, "PING")
	return err
}

// dropConn closes the connection so the next command redials. Caller holds r.mu.
func (r *respRedis) dropConn() {
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
}

func parseRedisURL(redisURL, passwordOverride string) (addr string, useTLS bool, pwd string, err error) {
	pwd = passwordOverride
	if redisURL == "" {
		return "", false, "", fmt.Errorf("empty redis URL")
	}
	// Plain host:port (same fallback go-redis uses when ParseURL fails).
	if !strings.Contains(redisURL, "://") {
		return redisURL, false, pwd, nil
	}
	u, err := url.Parse(redisURL)
	if err != nil {
		return "", false, "", err
	}
	switch u.Scheme {
	case "redis", "rediss":
		useTLS = u.Scheme == "rediss"
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "6379"
		}
		if host == "" {
			return "", false, "", fmt.Errorf("redis URL missing host")
		}
		addr = net.JoinHostPort(host, port)
		if pwd == "" && u.User != nil {
			pwd, _ = u.User.Password()
		}
		return addr, useTLS, pwd, nil
	default:
		return "", false, "", fmt.Errorf("unsupported redis URL scheme %q", u.Scheme)
	}
}

func (r *respRedis) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropConn()
	return nil
}

func (r *respRedis) do(ctx context.Context, args ...string) (interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.conn == nil {
		if err := r.connect(ctx); err != nil {
			return nil, err
		}
		r.log.warnf("redis reconnected addr=%s", r.addr)
	}
	v, err := r.roundTrip(ctx, args...)
	if err != nil {
		if _, ok := err.(redisReplyError); !ok {
			r.dropConn()
		}
	}
	return v, err
}

// roundTrip sends one command and reads its reply. Caller holds r.mu.
func (r *respRedis) roundTrip(ctx context.Context, args ...string) (interface{}, error) {
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = r.conn.SetDeadline(deadline)

	cmdLogged := formatRedisCmd(args)
	start := time.Now()

	if err := writeRespArgs(r.bw, args); err != nil {
		r.log.debugf("redis write cmd=%q error=%v", cmdLogged, err)
		return nil, err
	}
	if err := r.bw.Flush(); err != nil {
		r.log.debugf("redis flush cmd=%q error=%v", cmdLogged, err)
		return nil, err
	}
	v, err := readRespReply(r.rd)
	if err != nil {
		r.log.debugf("redis cmd=%q duration=%s error=%v", cmdLogged, since(start), err)
		return nil, err
	}
	r.log.debugf("redis cmd=%q duration=%s result=%s", cmdLogged, since(start), formatRedisResult(v))
	return v, nil
}

func writeRespArgs(w *bufio.Writer, args []string) error {
	var sb strings.Builder
	sb.WriteByte('*')
	sb.WriteString(strconv.Itoa(len(args)))
	sb.WriteString("\r\n")
	for _, a := range args {
		sb.WriteByte('$')
		sb.WriteString(strconv.Itoa(len(a)))
		sb.WriteString("\r\n")
		sb.WriteString(a)
		sb.WriteString("\r\n")
	}
	_, err := w.WriteString(sb.String())
	return err
}

func readRespReply(rd *bufio.Reader) (interface{}, error) {
	c, err := rd.ReadByte()
	if err != nil {
		return nil, err
	}
	switch c {
	case '+', '-', ':':
		line, err := rd.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, fmt.Errorf("redis: malformed reply")
		}
		body := line[:len(line)-2]
		if c == '-' {
			return nil, redisReplyError(body)
		}
		if c == ':' {
			return strconv.ParseInt(string(body), 10, 64)
		}
		return string(body), nil
	case '$':
		line, err := rd.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, fmt.Errorf("redis: malformed bulk header")
		}
		n, err := strconv.Atoi(string(line[:len(line)-2]))
		if err != nil {
			return nil, err
		}
		if n == -1 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(rd, buf); err != nil {
			return nil, err
		}
		if buf[n] != '\r' || buf[n+1] != '\n' {
			return nil, fmt.Errorf("redis: malformed bulk payload")
		}
		return string(buf[:n]), nil
	default:
		return nil, fmt.Errorf("redis: unexpected reply type %q", c)
	}
}

func (r *respRedis) incr(ctx context.Context, key string) (int64, error) {
	v, err := r.do(ctx, "INCR", key)
	if err != nil {
		return 0, err
	}
	n, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("redis INCR: unexpected type %T", v)
	}
	return n, nil
}

func (r *respRedis) expire(ctx context.Context, key string, seconds int) error {
	v, err := r.do(ctx, "EXPIRE", key, strconv.Itoa(seconds))
	if err != nil {
		return err
	}
	if _, ok := v.(int64); !ok {
		return fmt.Errorf("redis EXPIRE: unexpected type %T", v)
	}
	return nil
}

// get returns the string value at key. A missing key yields ("", false, nil) —
// a nil bulk reply is a cache miss, not an error.
func (r *respRedis) get(ctx context.Context, key string) (string, bool, error) {
	v, err := r.do(ctx, "GET", key)
	if err != nil {
		return "", false, err
	}
	if v == nil {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", false, fmt.Errorf("redis GET: unexpected type %T", v)
	}
	return s, true, nil
}

// setEX writes key=value with a TTL in seconds (SET key value EX seconds).
func (r *respRedis) setEX(ctx context.Context, key, value string, seconds int) error {
	v, err := r.do(ctx, "SET", key, value, "EX", strconv.Itoa(seconds))
	if err != nil {
		return err
	}
	// SET replies +OK on success.
	if s, ok := v.(string); !ok || s != "OK" {
		return fmt.Errorf("redis SET: unexpected reply %v", v)
	}
	return nil
}
