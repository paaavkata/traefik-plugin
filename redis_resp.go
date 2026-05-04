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
type respRedis struct {
	conn net.Conn
	rd   *bufio.Reader
	bw   *bufio.Writer
	mu   sync.Mutex
}

func dialRedis(ctx context.Context, redisURL, password string, db int) (*respRedis, error) {
	addr, useTLS, pwd, err := parseRedisURL(redisURL, password)
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if useTLS {
		tconn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12})
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tconn
	}

	r := &respRedis{
		conn: conn,
		rd:   bufio.NewReader(conn),
		bw:   bufio.NewWriter(conn),
	}

	if pwd != "" {
		if _, err := r.do(ctx, "AUTH", pwd); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if db != 0 {
		if _, err := r.do(ctx, "SELECT", strconv.Itoa(db)); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if _, err := r.do(ctx, "PING"); err != nil {
		conn.Close()
		return nil, err
	}
	return r, nil
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
	return r.conn.Close()
}

func (r *respRedis) do(ctx context.Context, args ...string) (interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = r.conn.SetDeadline(deadline)

	if err := writeRespArgs(r.bw, args); err != nil {
		return nil, err
	}
	if err := r.bw.Flush(); err != nil {
		return nil, err
	}
	return readRespReply(r.rd)
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
			return nil, fmt.Errorf("redis: %s", body)
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
