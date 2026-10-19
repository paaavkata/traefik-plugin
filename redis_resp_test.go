package traefik_gateway_plugin

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
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
func TestRespRedis_DownAtStartThenReconnects(t *testing.T) {
	fake := newFakeRedisServer(t)
	addr := fake.addr()
	fake.close() // nothing listens on addr now

	r, err := dialRedis(context.Background(), addr, "", 0, nil)
	if err != nil {
		t.Fatalf("dialRedis must tolerate an unreachable Redis, got: %v", err)
	}
	defer r.Close()
	if _, _, err := r.get(context.Background(), "k"); err == nil {
		t.Fatal("expected an error while Redis is down")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not rebind %s: %v", addr, err)
	}
	back := &fakeRedisServer{ln: ln, store: map[string]string{"k": "v"}}
	go back.serve()
	defer back.close()

	deadline := time.Now().Add(redisRedialBackoff + 3*time.Second)
	for {
		v, ok, err := r.get(context.Background(), "k")
		if err == nil {
			if !ok || v != "v" {
				t.Fatalf("got %q ok=%v after reconnect", v, ok)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("client did not reconnect: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A connection that dies mid-life (Redis restart) is replaced on a later command.
func TestRespRedis_ReconnectsAfterConnectionLoss(t *testing.T) {
	fake := newFakeRedisServer(t)
	defer fake.close()
	r, err := dialRedis(context.Background(), fake.addr(), "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.setEX(context.Background(), "k", "v", 60); err != nil {
		t.Fatalf("set before loss: %v", err)
	}

	r.conn.Close() // simulate the server side going away

	if _, _, err := r.get(context.Background(), "k"); err == nil {
		t.Fatal("expected the first command on a dead connection to fail")
	}
	v, ok, err := r.get(context.Background(), "k")
	if err != nil || !ok || v != "v" {
		t.Fatalf("after reconnect: v=%q ok=%v err=%v", v, ok, err)
	}
}
